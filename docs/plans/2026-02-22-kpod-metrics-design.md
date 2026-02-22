# kpod-metrics: eBPF Pod-Level Kernel Metrics for Kubernetes

**Date:** 2026-02-22
**Status:** Approved
**Distribution:** Internal tooling

## Problem

Platform/SRE teams need kernel-level visibility (CPU scheduling, network, memory, syscalls) at the pod level in Kubernetes. Existing tools are either CNI-locked (Hubble/Cilium), too heavy (Pixie, 2-8GB RAM), too narrow (Kepler = energy, Parca = profiling), or require eBPF expertise (Inspektor Gadget). There is no simple, declarative, low-overhead, Prometheus-native general kernel metrics collector.

## Goals

- Pod-level kernel metrics in Prometheus format with labels `{namespace, pod, container, node}`
- Easy configuration via `application.yml` with named presets (no eBPF knowledge required)
- Overhead: <1% CPU, <256MB RAM per node
- Deployable as a DaemonSet via Helm
- Minimum kernel: Linux 5.8+ (ring buffer, CAP_BPF)

## Non-Goals

- L7 protocol parsing (use Hubble/Pixie)
- Continuous profiling (use Parca)
- Energy/power metrics (use Kepler)
- Open-source distribution (internal tooling, may open-source later)

## Architecture

### Overview

Single Kotlin/Spring Boot process per node (DaemonSet) that loads eBPF programs via JNI calls to libbpf. The process handles eBPF lifecycle, metric aggregation, and Prometheus exposition.

```
┌─────────────────────────────────────────┐
│  Kotlin/Spring Boot (JDK 21)            │
│  Spring MVC + Virtual Threads           │
│  Kotlin Coroutines                      │
│  ┌──────────┐ ┌──────────┐ ┌─────────┐ │
│  │ Config   │ │ Metrics  │ │ /metrics│ │
│  │ (YAML)   │ │ Aggreg.  │ │ endpoint│ │
│  │ Profiles │ │ Coroutin.│ │ Actuator│ │
│  └────┬─────┘ └────▲─────┘ └─────────┘ │
│       │            │                     │
│  ┌────▼────────────┴─────┐              │
│  │   JNI Bridge Layer    │              │
│  │   (libbpf wrapper)   │              │
│  └────────────┬──────────┘              │
└───────────────┼──────────────────────────┘
                │ BPF syscalls
        ┌───────▼───────┐
        │  Linux Kernel  │
        │  eBPF programs │
        └───────────────┘
```

### Technology Stack

| Component | Technology |
|---|---|
| eBPF programs | C with CO-RE, compiled with clang |
| JNI bridge | C, linking libbpf statically |
| Application | Kotlin, Spring Boot 3.2+, Spring MVC |
| Concurrency | Virtual threads + Kotlin coroutines |
| Metrics | Micrometer with Prometheus registry |
| Runtime | JDK 21 (Temurin), standard JVM |
| Deployment | DaemonSet via Helm chart |

## eBPF Programs

Four eBPF program modules compiled with CO-RE (Compile Once, Run Everywhere) using BTF from `/sys/kernel/btf/vmlinux`.

### CPU Scheduling (`cpu_sched.bpf.c`)

- **Tracepoints:** `sched:sched_switch`, `sched:sched_wakeup`
- **Data:** Run queue latency (wakeup-to-switch delta), context switch count per cgroup
- **Map:** `BPF_MAP_TYPE_HASH` keyed by cgroup ID, value is log2 histogram buckets
- **Supplemental:** CPU throttle data from cgroup v2 `cpu.stat` (userspace polling)

### Network (`net.bpf.c`)

- **Tracepoints:** `sock:inet_sock_set_state`, `tcp:tcp_retransmit_skb`, `tcp_probe`
- **Kprobes:** `tcp_sendmsg`, `tcp_recvmsg`
- **Data:** TCP bytes sent/received, retransmit count, RTT, connection state transitions
- **Map:** `BPF_MAP_TYPE_HASH` keyed by cgroup ID + remote addr, aggregated to pod level in userspace

### Memory (`mem.bpf.c`)

- **Tracepoints:** `oom:oom_kill_process`
- **Kprobes:** `handle_mm_fault` (with `FAULT_FLAG_MAJOR`)
- **Supplemental:** RSS, working set, cache from cgroup v2 `memory.stat` and `memory.current` (userspace polling)

### Syscalls (`syscall.bpf.c`)

- **Tracepoints:** `raw_tracepoint/sys_enter`, `raw_tracepoint/sys_exit`
- **Data:** Per-cgroup syscall counts by type, error counts by errno, latency histograms
- **Map:** `BPF_MAP_TYPE_HASH` keyed by cgroup ID + syscall number
- **In-kernel aggregation:** All counting done in-kernel to avoid flooding userspace at high syscall rates

All programs use `BPF_MAP_TYPE_RINGBUF` (kernel 5.8+) for event delivery where needed.

## JNI Bridge Layer

A thin C library (`libkpod_bpf.so`) wrapping ~15 libbpf functions. Linked statically against libbpf.

### JNI Functions

```
// Lifecycle
openObject(path: String): Long          // bpf_object__open
loadObject(handle: Long): Int           // bpf_object__load
attachAll(handle: Long): Int            // bpf_program__attach (all)
destroyObject(handle: Long)             // bpf_object__close

// Map access
mapLookup(mapFd: Int, key: ByteArray): ByteArray?
mapGetNextKey(mapFd: Int, key: ByteArray?): ByteArray?
mapDelete(mapFd: Int, key: ByteArray)

// Ring buffer
ringBufferNew(mapFd: Int, callback: ...): Long
ringBufferPoll(rbHandle: Long, timeoutMs: Int): Int

// Utility
getCgroupId(path: String): Long
```

### Memory Management

- BPF object handles passed to Kotlin as `Long` (opaque native pointers)
- Handle registry with generation counters prevents use-after-free
- Map key/value exchange uses `byte[]` with `GetByteArrayRegion()` (no pinning)
- No persistent native references to JVM objects — every JNI call is stateless
- No `GetPrimitiveArrayCritical()` — avoids GC pauses

### Error Handling

- libbpf errors throw `BpfException` subclasses via `ThrowNew()` in JNI
- Exception hierarchy: `BpfException` (sealed) → `BpfLoadException`, `BpfMapException`
- Invalid handles validated against registry before native access
- Verifier log captured on program load failure
- Map lookup returning no key returns `null` (not an error)

### Thread Safety

- BPF map operations are inherently thread-safe (kernel RCU/spinlock protection)
- BPF program lifecycle (open/load/attach/destroy) is single-threaded at startup/shutdown
- Ring buffer polling is single-threaded per ring buffer (one collector per buffer)
- Handle registry uses `ConcurrentHashMap<Long, NativeHandle>`

### Native Crash Mitigation

JNI crash (SIGSEGV) kills the entire JVM with no recovery. Mitigation strategy:

**Prevention:**
- Handle registry with generation counters rejects stale pointers
- Defensive null/bounds checks in C before every libbpf call
- No pointer arithmetic — all access through libbpf APIs
- `-fsanitize=address` in dev, `valgrind` in CI

**Recovery:**
- DaemonSet `restartPolicy: Always` — K8s restarts the pod in 2-5 seconds
- Liveness probe on `/actuator/health` detects JVM hangs
- Prometheus handles scrape gaps and counter resets gracefully
- Fail-fast on startup: eBPF loaded during `ApplicationReadyEvent`

## Kotlin Application

### Concurrency Model

Spring MVC + virtual threads + Kotlin coroutines:

- **Spring MVC** handles HTTP on virtual threads (`spring.threads.virtual.enabled=true`)
- **Kotlin coroutines** provide structured concurrency for collectors
- **Virtual-thread-backed dispatcher** for blocking JNI calls
- Simpler than reactive/WebFlux — straightforward blocking Kotlin code

```kotlin
val VT = Executors.newVirtualThreadPerTaskExecutor().asCoroutineDispatcher()

@Component
class MetricsCollectorService(...) {
    @Scheduled(fixedDelayString = "\${kpod.poll-interval:15000}")
    fun collect() = runBlocking(VT) {
        listOf(
            launch { cpuCollector.collect() },
            launch { netCollector.collect() },
            launch { memCollector.collect() },
            launch { syscallCollector.collect() }
        ).joinAll()
    }
}
```

### Project Structure

```
kpod-metrics/
├── bpf/                              # C eBPF programs
│   ├── cpu_sched.bpf.c
│   ├── net.bpf.c
│   ├── mem.bpf.c
│   ├── syscall.bpf.c
│   └── vmlinux.h
├── jni/                              # JNI bridge (C)
│   ├── bpf_bridge.c
│   ├── bpf_bridge.h
│   └── CMakeLists.txt
├── src/main/kotlin/
│   └── com/internal/kpodmetrics/
│       ├── KpodMetricsApplication.kt
│       ├── config/
│       │   ├── MetricsProperties.kt          # @ConfigurationProperties
│       │   └── BpfAutoConfiguration.kt
│       ├── bpf/
│       │   ├── BpfBridge.kt                  # JNI declarations
│       │   ├── BpfProgramManager.kt          # Lifecycle management
│       │   └── CgroupResolver.kt             # cgroup ID → pod mapping
│       ├── collector/
│       │   ├── MetricsCollectorService.kt    # Coroutine orchestrator
│       │   ├── CpuSchedulingCollector.kt
│       │   ├── NetworkCollector.kt
│       │   ├── MemoryCollector.kt
│       │   └── SyscallCollector.kt
│       ├── metrics/
│       │   └── PrometheusExporter.kt         # Micrometer MeterBinder
│       └── k8s/
│           └── PodWatcher.kt                 # K8s API informer
├── src/main/resources/
│   └── application.yml
├── build.gradle.kts
├── Dockerfile
└── helm/
    └── kpod-metrics/
        ├── Chart.yaml
        ├── values.yaml
        └── templates/
            ├── daemonset.yaml
            └── serviceaccount.yaml
```

### Pod Attribution (CgroupResolver)

Maps cgroup inode IDs to pod metadata:

1. `bpf_get_current_cgroup_id()` returns cgroup v2 inode in eBPF programs
2. Userspace watches `/sys/fs/cgroup` via inotify for new cgroup directories
3. Container ID extracted from cgroup path (`.../pod<uid>/<container-id>/`)
4. CRI gRPC API maps container ID → pod UID
5. K8s informer (`PodWatcher`) resolves pod UID → name, namespace, labels

Maintains `ConcurrentHashMap<Long, PodInfo>` with TTL-based eviction for deleted pods.

## Metrics

### Label Set

All metrics include: `{namespace, pod, container, node}`

### Metric Inventory

**CPU Scheduling:**

| Metric | Type | Description |
|---|---|---|
| `kpod_cpu_runqueue_latency_seconds` | Histogram | Wakeup-to-scheduled latency |
| `kpod_cpu_context_switches_total` | Counter | Context switch count |
| `kpod_cpu_throttled_seconds_total` | Counter | CPU throttle time |
| `kpod_cpu_throttled_periods_total` | Counter | Throttled period count |

**Network:**

| Metric | Type | Description |
|---|---|---|
| `kpod_net_tcp_bytes_sent_total` | Counter | TCP bytes sent |
| `kpod_net_tcp_bytes_received_total` | Counter | TCP bytes received |
| `kpod_net_tcp_retransmits_total` | Counter | TCP retransmit count |
| `kpod_net_tcp_rtt_seconds` | Histogram | TCP smoothed RTT |
| `kpod_net_tcp_connections_total` | Counter | TCP connections by state |
| `kpod_net_tcp_connection_latency_seconds` | Histogram | SYN_SENT → ESTABLISHED time |

**Memory:**

| Metric | Type | Description |
|---|---|---|
| `kpod_mem_oom_kills_total` | Counter | OOM kill count |
| `kpod_mem_major_page_faults_total` | Counter | Major page fault count |
| `kpod_mem_rss_bytes` | Gauge | Resident set size |
| `kpod_mem_working_set_bytes` | Gauge | Working set size |
| `kpod_mem_cache_bytes` | Gauge | Page cache usage |

**Syscalls:**

| Metric | Type | Description |
|---|---|---|
| `kpod_syscall_count_total` | Counter | Syscall invocations `{syscall}` |
| `kpod_syscall_errors_total` | Counter | Failed syscalls `{syscall, errno}` |
| `kpod_syscall_latency_seconds` | Histogram | Syscall duration |

### Prometheus Exposition

- Micrometer `micrometer-registry-prometheus` via Spring Boot Actuator
- Endpoint: `GET /actuator/prometheus`
- Format: Prometheus text (`text/plain; version=0.0.4`)
- Custom `MeterBinder` per collector domain

## Configuration

### Metric Profiles

```yaml
kpod:
  profile: standard   # minimal | standard | comprehensive | custom
```

| Profile | CPU Sched | Network | Memory | Syscalls | Approx. Metrics |
|---|---|---|---|---|---|
| `minimal` | scheduling, throttling | - | oom, cgroup stats | - | ~6 |
| `standard` | scheduling, throttling | tcp | oom, page faults, cgroup stats | - | ~16 |
| `comprehensive` | all | all | all | default allowlist | ~22+ |
| `custom` | per-toggle | per-toggle | per-toggle | per-toggle | varies |

### Full Configuration Reference

```yaml
kpod:
  profile: standard
  poll-interval: 15s
  node-name: ${NODE_NAME}

  # Individual domain settings (used when profile: custom)
  cpu:
    enabled: true
    scheduling:
      enabled: true
      histogram-buckets: [0.000001, 0.00001, 0.0001, 0.001, 0.01, 0.1, 1.0]
    throttling:
      enabled: true

  network:
    enabled: true
    tcp:
      enabled: true
      rtt-histogram-buckets: [0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5]
      connection-latency-buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]

  memory:
    enabled: true
    oom: true
    page-faults: true
    cgroup-stats: true

  syscall:
    enabled: true
    tracked-syscalls:
      - read
      - write
      - openat
      - close
      - connect
      - accept4
      - sendto
      - recvfrom
      - epoll_wait
      - futex
    latency-histogram-buckets: [0.000001, 0.00001, 0.0001, 0.001, 0.01, 0.1]

  filter:
    namespaces: []
    exclude-namespaces:
      - kube-system
      - kube-public
    label-selector: ""

  bpf:
    program-dir: /app/bpf

spring:
  threads:
    virtual:
      enabled: true

server:
  port: 9090

management:
  endpoints:
    web:
      exposure:
        include: health, prometheus, info
  metrics:
    export:
      prometheus:
        enabled: true
```

## Deployment

### Dockerfile

```dockerfile
# Stage 1: Compile eBPF programs
FROM ubuntu:22.04 AS bpf-builder
RUN apt-get update && apt-get install -y clang llvm libbpf-dev linux-tools-common
COPY bpf/ /build/bpf/
RUN clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -c /build/bpf/cpu_sched.bpf.c -o /build/bpf/cpu_sched.bpf.o
# ... repeat for net.bpf.c, mem.bpf.c, syscall.bpf.c

# Stage 2: Build JNI native library
FROM ubuntu:22.04 AS jni-builder
RUN apt-get update && apt-get install -y cmake gcc libbpf-dev default-jdk
COPY jni/ /build/jni/
RUN cmake -B /build/jni/build /build/jni && cmake --build /build/jni/build

# Stage 3: Build Kotlin app
FROM gradle:8-jdk21 AS app-builder
COPY . /build
RUN gradle bootJar

# Stage 4: Runtime
FROM eclipse-temurin:21-jre
COPY --from=bpf-builder /build/bpf/*.bpf.o /app/bpf/
COPY --from=jni-builder /build/jni/build/libkpod_bpf.so /app/lib/
COPY --from=app-builder /build/build/libs/kpod-metrics.jar /app/
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75 -XX:+UseG1GC -Xss256k -Djava.library.path=/app/lib"
ENTRYPOINT ["java", "-jar", "/app/kpod-metrics.jar"]
```

### Helm Chart (values.yaml)

```yaml
image:
  repository: internal-registry/kpod-metrics
  tag: "0.1.0"

resources:
  requests:
    cpu: 50m
    memory: 128Mi
  limits:
    cpu: 200m
    memory: 256Mi

securityContext:
  privileged: false
  capabilities:
    add: [BPF, PERFMON, SYS_RESOURCE, NET_ADMIN]

volumes:
  - name: sys-kernel-btf
    hostPath: { path: /sys/kernel/btf }
  - name: sys-fs-cgroup
    hostPath: { path: /sys/fs/cgroup }
  - name: proc
    hostPath: { path: /proc, type: Directory }

podAnnotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "9090"
  prometheus.io/path: "/actuator/prometheus"

env:
  - name: NODE_NAME
    valueFrom:
      fieldRef:
        fieldPath: spec.nodeName

livenessProbe:
  httpGet: { path: /actuator/health/liveness, port: 9090 }
  initialDelaySeconds: 30
  periodSeconds: 10

readinessProbe:
  httpGet: { path: /actuator/health/readiness, port: 9090 }
  initialDelaySeconds: 15
  periodSeconds: 5

tolerations:
  - operator: Exists

config:
  profile: standard
```

DaemonSet requires `hostPID: true` for `/proc/<pid>/cgroup` access. ServiceAccount with RBAC for `list`/`watch` on pods.

## Testing Strategy

### Unit Tests (Kotlin)

- **Collectors:** Mock `BpfBridge` JNI calls, verify raw `ByteArray` parsing and Micrometer metric registration
- **CgroupResolver:** Test cgroup path parsing for systemd/cgroupfs drivers, QoS classes, edge cases
- **Configuration:** Verify `@ConfigurationProperties` binding for all profiles, invalid config rejection
- **Framework:** JUnit 5 + MockK

### Integration Tests (JNI Bridge)

- Linux CI runner with kernel 5.8+ and `CAP_BPF`
- Load a test BPF program, verify map read/write through JNI, verify cleanup
- Validate error paths: invalid `.bpf.o`, non-existent tracepoint, destroyed handle

### End-to-End Tests

- KIND cluster in CI
- Deploy Helm chart, generate workloads (CPU-intensive, network-heavy, OOM-triggering)
- Scrape `/actuator/prometheus`, assert metrics exist with correct labels and plausible values
- Validate exposition format with `promtool`

### Performance Tests

- Dedicated test node with `stress-ng` workload
- Measure baseline CPU/memory without kpod-metrics, then with
- Assert: delta CPU < 1%, total memory < 256MB
- 1-hour soak test to detect native memory leaks

## Overhead Budget

| Component | CPU | Memory |
|---|---|---|
| eBPF programs (in-kernel) | <0.1% | 10-50MB (maps) |
| JNI bridge + libbpf | <0.1% | ~5MB |
| JVM (Spring Boot + Micrometer) | <0.5% | 100-150MB |
| CgroupResolver + PodWatcher | <0.1% | ~20MB |
| **Total** | **<1%** | **<256MB** |

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| JNI native crash kills JVM | Low | High | Defensive coding, handle registry, K8s auto-restart |
| JNI + libbpf has few reference implementations | Medium | Medium | Spike/prototype the JNI bridge first, fallback to Go sidecar (Approach 2) |
| High syscall rate causes overhead spike | Medium | Medium | In-kernel aggregation, configurable syscall allowlist |
| Cgroup v1 clusters | Low | Medium | Require cgroup v2 (K8s 1.25+ default), document requirement |
| Virtual threads + JNI pinning | Low | Low | JNI calls are short-lived, no monitor contention |
