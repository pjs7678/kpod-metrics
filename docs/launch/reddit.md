# Reddit Posts

---

## r/kubernetes

### Title

```
I built an eBPF-based pod metrics collector where the BPF programs are written in Kotlin instead of C
```

### Body

I've been working on **kpod-metrics**, an open-source DaemonSet that uses eBPF
to collect per-pod kernel metrics and export them to Prometheus.

**Why I built it:** I needed deep kernel observability (CPU scheduling latency,
TCP retransmits, syscall errors) per pod, but existing tools were either too
heavy (Pixie at ~2Gi/node), network-only (Hubble), or required writing raw C
for every new metric.

**What makes it different:**

1. **eBPF programs defined in Kotlin** — A DSL generates both the kernel C code
   and type-safe Kotlin deserialization classes from a single definition. No more
   manually keeping structs in sync across C and JVM.

2. **Lightweight** — ~256 Mi per node. Tested up to 1,000 nodes / 100,000 pods.

3. **50+ metrics out of the box** — CPU runqueue latency, TCP bytes/RTT/drops,
   OOM kills, syscall latency, block I/O, page cache, IRQ latency, filesystem.

4. **L7 protocol detection** — Auto-detects HTTP, DNS, Redis, MySQL, Kafka,
   MongoDB with per-request latency.

5. **Zero-config service topology** — Auto-discovered from TCP peer data, with
   latency and protocol per edge.

6. **Kernel 4.18+** — Legacy mode for older kernels, CO-RE for 5.2+.

**Quick start:**

```bash
helm repo add kpod-metrics https://pjs7678.github.io/kpod-metrics
helm install kpod-metrics kpod-metrics/kpod-metrics \
  -n kpod-metrics --create-namespace
```

Includes Grafana dashboard (9 rows), Prometheus Operator ServiceMonitor with
18 alerting rules, and OTLP export.

- GitHub: https://github.com/pjs7678/kpod-metrics
- Docs: https://pjs7678.github.io/kpod-metrics
- Helm chart: https://pjs7678.github.io/kpod-metrics (ArtifactHub coming soon)

Would love feedback on what metrics or protocols to add next. Happy to answer
any questions about the eBPF DSL approach.

---

## r/devops

### Title

```
Open source: eBPF pod metrics for Kubernetes with auto service topology and L7 detection (256Mi/node)
```

### Body

Sharing **kpod-metrics** — an eBPF-based DaemonSet that gives you per-pod kernel
metrics in Prometheus without any application instrumentation.

**What it collects (per pod, per container):**
- CPU: runqueue latency, context switches
- Network: TCP bytes, RTT, retransmits, drops, connections
- Memory: OOM kills, page faults, cgroup usage
- Disk: block I/O latency, read/write throughput
- Syscalls: per-syscall count, errors, latency
- L7: HTTP, DNS, Redis, MySQL, Kafka, MongoDB request latency

**What I think is useful for ops teams:**
- **Service topology** auto-discovered from TCP connections — shows which
  services talk to which, with latency and protocol. No config, no sidecars.
- **18 alerting rules** included — high runqueue latency, TCP drops, OOM kills,
  filesystem full, crash loop detection, fork bomb detection, etc.
- **Three profiles** — `minimal` (~20 metrics/pod), `standard` (~39),
  `comprehensive` (~69) to control Prometheus cardinality.
- **~256 Mi per node** — runs alongside your existing monitoring stack.

Works with any Prometheus setup (ServiceMonitor or annotation-based scraping)
and supports OTLP export for Datadog/New Relic/Grafana Cloud.

```bash
helm repo add kpod-metrics https://pjs7678.github.io/kpod-metrics
helm install kpod-metrics kpod-metrics/kpod-metrics \
  -n kpod-metrics --create-namespace
```

GitHub: https://github.com/pjs7678/kpod-metrics

One interesting technical detail: the eBPF programs are defined in a Kotlin DSL
instead of C. The DSL generates both kernel-side C and JVM-side type-safe
deserializers. Happy to discuss the tradeoffs of this approach.

---

## r/ebpf

### Title

```
Kotlin DSL for writing eBPF programs — generates C code + type-safe JVM MapReaders from a single definition
```

### Body

I built a DSL in Kotlin for defining eBPF programs. Instead of writing raw C,
you define your BPF maps, structs, and tracepoint handlers in Kotlin:

```kotlin
val memProgram = ebpfProgram("mem") {
    val key = struct("counter_key") { u64("cgroup_id") }
    val oomKills = hashMap("oom_kills", key, BpfScalar.U64, maxEntries = 10240)

    tracepoint("oom", "mark_victim") {
        val cgId = getCurrentCgroupId()
        val ptr = mapLookupElem(oomKills, cgId)
        ifNonNull(ptr) { atomicIncrement(it) }
    }
}
```

**What it generates:**

1. **Kernel-side `.bpf.c`** — complete C program with struct definitions, map
   declarations, and SEC-annotated handler functions
2. **JVM-side `MapReader` classes** — type-safe Kotlin classes that deserialize
   BPF map entries without manual `ByteBuffer` parsing

**Why this matters:** In traditional eBPF development, you define structs in C,
then manually replicate the byte layout in your userspace code. One field
reorder or size change silently breaks deserialization. The DSL eliminates this
entire class of bugs.

**DSL features:**
- `struct()` / `hashMap()` / `lruHashMap()` — typed map declarations
- `tracepoint()` / `kprobe()` / `kretprobe()` — program attachment
- `mapLookupElem()` / `atomicIncrement()` — type-safe BPF helpers
- `preamble()` / `postamble()` / `raw()` — escape hatches for complex C
- Both CO-RE (5.2+) and legacy (4.18+) output

**Used in production** as part of kpod-metrics, a Kubernetes pod metrics
collector with 15+ eBPF programs covering CPU, network, memory, syscalls, disk,
and L7 protocol detection.

- DSL: https://github.com/pjs7678/kotlin-ebpf-dsl
- kpod-metrics: https://github.com/pjs7678/kpod-metrics

Curious what the eBPF community thinks about this approach. The main tradeoff
is that the DSL can't express everything (complex pointer chasing, nested loops),
which is why there's a `raw()` escape hatch for arbitrary C.
