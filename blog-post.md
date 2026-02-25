# Building kpod-metrics: An eBPF-Based Pod Metrics Collector for Kubernetes

Kubernetes tells you *what* your pods requested. kpod-metrics tells you *what actually happened* at the kernel level.

Standard Kubernetes monitoring gives you CPU and memory usage from the metrics-server. But when a pod is slow, that's rarely enough. Was it stuck in the CPU run queue? Suffering TCP retransmissions? Hitting major page faults? Experiencing syscall latency? These questions require kernel-level visibility -- and that's where eBPF comes in.

kpod-metrics is a DaemonSet that attaches eBPF programs to Linux kernel tracepoints and exports per-pod performance metrics to Prometheus. It combines eBPF event tracing with cgroup filesystem reads to provide a complete picture of pod behavior, from scheduling latency to disk I/O.

## The Problem

Consider debugging a latency spike in production. Your Grafana dashboard shows CPU usage at 40% -- well under limits. Memory is fine. The application logs show nothing unusual. Yet p99 latency doubled.

The problem could be any of:
- **CPU run-queue contention**: Other pods on the node are consuming their time slices, making your pod wait
- **TCP retransmissions**: Network packets are being dropped and resent, adding 200ms+ per retransmit
- **Major page faults**: The kernel is paging memory from disk because of memory pressure on the node
- **Slow syscalls**: A filesystem `read()` is blocking on I/O, or `connect()` is timing out

None of these show up in standard Kubernetes metrics. You'd need to SSH into the node, run `perf`, `bpftrace`, or `strace`, and try to correlate output back to specific pods. kpod-metrics automates this entirely.

## Architecture

kpod-metrics deploys as a DaemonSet -- one pod per node. Each instance:

1. **Loads 4 eBPF programs** into the kernel via a JNI bridge to libbpf
2. **Watches pod lifecycle** through a node-scoped Kubernetes informer
3. **Collects metrics every 30 seconds** by batch-reading BPF maps and cgroup files
4. **Exports to Prometheus** on port 9090

```
┌──────────────────────────────────────────────┐
│  kpod-metrics pod (Spring Boot + JDK 21)     │
│                                               │
│  Collectors (parallel via virtual threads)    │
│  ├── eBPF: CPU, Network, Memory, Syscall     │
│  └── Cgroup: DiskIO, Interface, Filesystem   │
│                                               │
│  PodWatcher ──► CgroupResolver               │
│  (K8s informer)  (cgroup ID → pod metadata)  │
│                                               │
│  Prometheus :9090/actuator/prometheus         │
└────────────┬─────────────────────────────────┘
             │ JNI
┌────────────▼─────────────────────────────────┐
│  Linux Kernel                                 │
│  ├── cpu_sched.bpf.o  (sched_switch/wakeup)  │
│  ├── net.bpf.o        (tcp_sendmsg/recvmsg)  │
│  ├── mem.bpf.o        (oom_kill/mm_fault)     │
│  └── syscall.bpf.o    (sys_enter/sys_exit)    │
└───────────────────────────────────────────────┘
```

The tech stack is Kotlin 2.1 on Spring Boot 3.4 with Java 21 virtual threads. The eBPF programs are written in C, compiled once with CO-RE (Compile Once, Run Everywhere), and loaded at runtime via a JNI bridge to libbpf.

## What It Measures

### eBPF Metrics (kernel event tracing)

**CPU Scheduling** -- Attaches to `sched_wakeup` and `sched_switch` tracepoints. When a task wakes up, we record the timestamp. When it gets scheduled onto a CPU, we compute the delta. This gives us run-queue latency -- how long the pod waited for CPU time:

```c
SEC("tp/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    __u64 *tsp = bpf_map_lookup_elem(&wakeup_ts, &pid);
    if (tsp) {
        __u64 delta_ns = bpf_ktime_get_ns() - *tsp;
        // Record in histogram, keyed by cgroup_id
        __u32 slot = log2l(delta_ns);
        __sync_fetch_and_add(&hval->slots[slot], 1);
        __sync_fetch_and_add(&hval->sum_ns, delta_ns);
    }
}
```

Latency distributions are built in-kernel using log2 histogram buckets. Atomic `__sync_fetch_and_add` operations allow safe concurrent updates from multiple CPUs without locks.

**Network** -- Five attachment points cover the TCP lifecycle: `tcp_sendmsg` and `tcp_recvmsg` for throughput, `tcp_retransmit_skb` for retransmissions, `inet_sock_set_state` for connection tracking, and `tcp_probe` for RTT measurements.

**Memory** -- The `oom/mark_victim` tracepoint fires when the kernel selects an OOM kill victim. A kprobe on `handle_mm_fault` catches major page faults.

**Syscalls** -- Raw tracepoints on `sys_enter` and `sys_exit` measure per-syscall latency, error rates, and invocation counts. Only tracked syscalls (configurable, default 10) are measured to limit overhead.

### Cgroup Metrics (filesystem reads)

For disk I/O, network interface stats, and filesystem usage, eBPF is overkill. These are already exposed by the kernel through cgroup v2 controllers and `/proc`. kpod-metrics reads them directly:

- **Disk I/O** from `io.stat` -- read/write bytes and operations per device
- **Interface network** from `/proc/<pid>/net/dev` -- per-interface rx/tx bytes, packets, errors, drops
- **Filesystem** from `/proc/<pid>/mounts` + `statvfs` -- capacity, usage, available per mount

## Key Design Decisions

### Cgroup ID as the Universal Key

Every BPF map is keyed by `cgroup_id` -- the inode number of the pod's cgroup directory. When an eBPF program fires (say, on a `tcp_sendmsg` call), it calls `bpf_get_current_cgroup_id()` to get the cgroup of the process that triggered the event. This maps directly to a Kubernetes pod.

The `CgroupResolver` maintains a mapping from cgroup ID to pod metadata (namespace, pod name, container name). When PodWatcher discovers a new pod via the Kubernetes API, it scans `/proc` to find processes belonging to that pod's containers, resolves their cgroup path, and reads the directory's inode number:

```kotlin
val attrs = Files.readAttributes(cgroupPath, BasicFileAttributes::class.java)
val fileKey = attrs.fileKey()?.toString()  // "(dev=XXX,ino=YYY)"
val inode = Regex("ino=(\\d+)").find(fileKey)?.groupValues?.get(1)?.toLong()
// This inode IS the cgroup_id returned by bpf_get_current_cgroup_id()
```

### Snap-and-Reset with Batch Operations

Every collection cycle, we need to read all entries from a BPF map and reset them to zero. The naive approach -- iterate keys, lookup each value, delete each key -- requires 3N kernel crossings per map.

kpod-metrics uses `bpf_map_lookup_and_delete_batch`, a single syscall that atomically reads and deletes all entries:

```kotlin
fun mapBatchLookupAndDelete(
    mapFd: Int, keySize: Int, valueSize: Int, maxEntries: Int
): List<Pair<ByteArray, ByteArray>> {
    val keysArray = ByteArray(maxEntries * keySize)
    val valuesArray = ByteArray(maxEntries * valueSize)
    val count = nativeMapBatchLookupAndDelete(
        mapFd, keysArray, valuesArray, keySize, valueSize, maxEntries
    )
    if (count == -2) return legacyLookupAndDelete(mapFd, keySize, valueSize)
    // Parse results...
}
```

If the kernel doesn't support batch operations (pre-5.6), it falls back to the legacy iterate-lookup-delete path automatically.

### LRU Maps for Metrics

All seven metric maps use `BPF_MAP_TYPE_LRU_HASH` instead of `BPF_MAP_TYPE_HASH`. Standard hash maps silently fail when full -- `bpf_map_update_elem` returns an error, and you lose data with no indication. LRU maps auto-evict the least-recently-used entry to make room for new ones.

This is a pattern used across every major eBPF project we studied: Kepler, Tetragon, Inspektor Gadget, Beyla, and Coroot all use LRU for metric/cache maps.

Temporary per-task maps (like `wakeup_ts` which stores timestamps between `sched_wakeup` and `sched_switch`) stay as standard hash maps -- LRU would evict entries that are still needed.

### BPF Map Health Metrics

When a BPF map runs out of space, updates fail silently. To detect this before data loss, each BPF program tracks its own map health using per-CPU array counters:

```c
#define STATS_INC(map, idx) do { \
    __u32 _k = (idx); \
    __s64 *_v = bpf_map_lookup_elem(&map, &_k); \
    if (_v) __sync_fetch_and_add(_v, 1); \
} while(0)

int err = bpf_map_update_elem(&ctx_switches, &key, &val, BPF_ANY);
if (err) {
    STATS_INC(ctx_switches_stats, MAP_STAT_UPDATE_ERRORS);
} else {
    STATS_INC(ctx_switches_stats, MAP_STAT_ENTRIES);
}
```

These are exported as Prometheus metrics (`kpod.bpf.map.entries`, `kpod.bpf.map.update.errors.total`, `kpod.bpf.map.capacity`), letting operators set alerts when maps approach capacity.

### Deleted-Pod Grace Cache

When a pod is deleted, in-flight BPF events may still reference its cgroup ID. Without a grace period, those final metrics would be attributed to "unknown". The `CgroupResolver` moves deleted pods to a grace cache with a 5-second TTL:

```kotlin
fun onPodDeleted(cgroupId: Long) {
    val podInfo = cache.remove(cgroupId) ?: return
    graceCache[cgroupId] = GraceCacheEntry(podInfo, Instant.now())
}

fun resolve(cgroupId: Long): PodInfo? =
    cache[cgroupId] ?: graceCache[cgroupId]?.podInfo
```

The grace cache is capped at 10,000 entries with LRU eviction to prevent unbounded growth during mass rolling deployments.

### Virtual Threads for Parallel Collection

All collectors run in parallel using Java 21 virtual threads:

```kotlin
@Scheduled(fixedDelayString = "\${kpod.poll-interval:30000}")
fun collect() = runBlocking(vtDispatcher) {
    (bpfCollectors + cgroupCollectors).map { (name, collectFn) ->
        launch {
            collectFn()
        }
    }.joinAll()
}
```

Each collector blocks on JNI calls or file I/O, but virtual threads make this cheap -- no platform thread is tied up waiting. Collection cycle completes in 500-1000ms even with 100 pods on the node.

## CO-RE: Compile Once, Run Everywhere

The eBPF programs are compiled with Clang targeting the BPF bytecode format:

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
    -c cpu_sched.bpf.c -o cpu_sched.bpf.o
```

They include `vmlinux.h` -- a 180,000-line header generated from the kernel's BTF (BPF Type Format) data. The `preserve_access_index` attribute tells LLVM to record struct field access patterns rather than hard-coding offsets:

```c
#pragma clang attribute push (
    __attribute__((preserve_access_index)), apply_to = record)
```

At load time, libbpf reads the running kernel's BTF from `/sys/kernel/btf/vmlinux`, compares it against the compiled program's expectations, and patches the bytecode with correct field offsets. The same `.bpf.o` file works across kernel versions 5.8 through 6.x without recompilation.

## Configuration Profiles

Not every deployment needs every metric. Three profiles control the tradeoff between visibility and overhead:

| | minimal | standard | comprehensive |
|---|:---:|:---:|:---:|
| CPU scheduling | yes | yes | yes |
| Network TCP | - | yes | yes |
| Memory events | partial | yes | yes |
| Syscall tracing | - | - | yes |
| Disk I/O | yes | yes | yes |
| Interface network | - | yes | yes |
| Filesystem | - | yes | yes |
| **Time series per pod** | ~20 | ~39 | ~69 |

At 100 pods per node on `standard` profile, that's ~3,900 time series per node -- well within Prometheus's comfort zone.

## Scaling

kpod-metrics is designed for large clusters. Each DaemonSet pod operates independently:

- **BPF maps**: 10,240 entries per map (LRU), far more than the ~100-200 cgroup IDs on a typical node
- **API server**: Node-scoped informer (`spec.nodeName` field selector) -- one watch per node, not cluster-wide
- **Collection**: Batch JNI calls reduce kernel crossings to ~1 per map per cycle
- **Memory**: 256Mi request / 512Mi limit handles 100 pods comfortably
- **Kernel overhead**: ~15-20 MB per node for all BPF maps combined

We validated the architecture for **1,000 nodes with 100,000 pods**. The main constraint at that scale is Prometheus cardinality -- use `standard` profile (not `comprehensive`) to stay under 4 million time series.

## What We Learned from Open Source

The implementation incorporates patterns from six major eBPF projects:

- **Kepler** (CNCF): LRU hash maps, batch map operations
- **Tetragon** (Cilium): Per-map health metrics (`map_entries`, `map_errors`)
- **Inspektor Gadget**: Batch lookup-and-delete, 2-second grace cache for deleted pods
- **Beyla** (Grafana): LRU maps for metric aggregation
- **Pixie** (New Relic): In-kernel histogram aggregation
- **Coroot**: Cgroup-first pod attribution pattern

The biggest lesson: **instrument your BPF maps**. Before adding map stats, we had no way to know if a map was approaching capacity. Silent data loss is the worst failure mode in observability.

## Getting Started

Deploy with Helm:

```bash
helm install kpod-metrics ./helm/kpod-metrics \
    --namespace kpod-metrics --create-namespace
```

Verify metrics are flowing:

```bash
kubectl -n kpod-metrics port-forward ds/kpod-metrics 9090:9090
curl -s localhost:9090/actuator/prometheus | grep kpod
```

You'll see metrics like:

```
kpod_cpu_runqueue_latency_seconds_sum{namespace="default",pod="api-server-xyz",container="api",node="worker-1"} 0.0025
kpod_net_tcp_retransmits_total{namespace="default",pod="api-server-xyz",container="api",node="worker-1"} 3.0
kpod_mem_oom_kills_total{namespace="default",pod="cache-abc",container="redis",node="worker-1"} 1.0
```

Requirements: Linux kernel 5.8+ with BTF enabled, cgroup v2, Kubernetes 1.19+.

## What's Next

- **GPU metrics**: eBPF-based GPU utilization tracking (NVIDIA/AMD)
- **Grafana dashboards**: Pre-built dashboards for common debugging workflows
- **Alerting rules**: PrometheusRule templates for common failure patterns (OOM trending, retransmit spikes, run-queue saturation)
- **OpenTelemetry export**: OTLP push alongside Prometheus pull

The project is open source at [github.com/pjs7678/kpod-metrics](https://github.com/pjs7678/kpod-metrics).
