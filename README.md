# kpod-metrics

eBPF-based pod-level kernel metrics collector for Kubernetes. Runs as a DaemonSet, attaches eBPF programs to kernel tracepoints, and exports per-pod CPU, network, memory, syscall, disk I/O, and filesystem metrics to Prometheus.

## Architecture

```
Node (DaemonSet pod)
┌─────────────────────────────────────────────────┐
│  Spring Boot (JDK 21 + Virtual Threads)         │
│                                                  │
│  MetricsCollectorService (every 15-30s)         │
│  ├── eBPF Collectors ──► JNI ──► BPF Maps      │
│  │   ├── CpuSchedulingCollector                 │
│  │   ├── NetworkCollector                       │
│  │   ├── MemoryCollector                        │
│  │   ├── SyscallCollector                       │
│  │   └── BpfMapStatsCollector                   │
│  └── Cgroup Collectors ──► /sys/fs/cgroup       │
│      ├── DiskIOCollector                        │
│      ├── InterfaceNetworkCollector              │
│      └── FilesystemCollector                    │
│                                                  │
│  PodWatcher (K8s informer, node-scoped)         │
│  CgroupResolver (cgroup ID → pod metadata)      │
│  Prometheus exporter (:9090/actuator/prometheus) │
└─────────────────────────────────────────────────┘
         │ JNI (libkpod_bpf.so)
    ┌────▼────────────────────────┐
    │ Linux Kernel                │
    │ ├── cpu_sched.bpf.o        │
    │ ├── net.bpf.o              │
    │ ├── mem.bpf.o              │
    │ └── syscall.bpf.o          │
    │                             │
    │ Tracepoints: sched_switch,  │
    │ tcp_sendmsg, oom_kill,      │
    │ sys_enter/exit, ...         │
    └─────────────────────────────┘
```

eBPF programs are defined in Kotlin using [kotlin-ebpf-dsl](https://github.com/pjs7678/kotlin-ebpf-dsl), which generates both the C code for kernel-side programs and Kotlin `MapReader` classes for userspace deserialization. Programs are compiled once with CO-RE (Compile Once, Run Everywhere) using kernel BTF, so no per-kernel compilation is needed.

## Metrics

All metrics are labeled with `namespace`, `pod`, `container`, and `node`.

### eBPF Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `kpod.cpu.runqueue.latency` | DistributionSummary | Time spent waiting in the CPU run queue (seconds) |
| `kpod.cpu.context.switches` | Counter | Context switch count |
| `kpod.net.tcp.bytes.sent` | Counter | TCP bytes sent |
| `kpod.net.tcp.bytes.received` | Counter | TCP bytes received |
| `kpod.net.tcp.retransmits` | Counter | TCP retransmissions |
| `kpod.net.tcp.connections` | Counter | TCP connection count |
| `kpod.net.tcp.rtt` | DistributionSummary | TCP round-trip time (seconds) |
| `kpod.mem.oom.kills` | Counter | OOM kill events |
| `kpod.mem.major.page.faults` | Counter | Major page faults |
| `kpod.syscall.count` | Counter | Syscall invocations (+ `syscall` label) |
| `kpod.syscall.errors` | Counter | Syscall errors (+ `syscall` label) |
| `kpod.syscall.latency` | DistributionSummary | Syscall latency (+ `syscall` label) |

### Cgroup Metrics

| Metric | Type | Extra Labels | Description |
|--------|------|-------------|-------------|
| `kpod.disk.read.bytes` | Counter | `device` | Bytes read from disk |
| `kpod.disk.written.bytes` | Counter | `device` | Bytes written to disk |
| `kpod.disk.reads` | Counter | `device` | Read operation count |
| `kpod.disk.writes` | Counter | `device` | Write operation count |
| `kpod.net.iface.rx.bytes` | Counter | `interface` | Interface bytes received |
| `kpod.net.iface.tx.bytes` | Counter | `interface` | Interface bytes transmitted |
| `kpod.net.iface.rx.packets` | Counter | `interface` | Interface packets received |
| `kpod.net.iface.tx.packets` | Counter | `interface` | Interface packets transmitted |
| `kpod.net.iface.rx.errors` | Counter | `interface` | Interface receive errors |
| `kpod.net.iface.tx.errors` | Counter | `interface` | Interface transmit errors |
| `kpod.net.iface.rx.drops` | Counter | `interface` | Interface receive drops |
| `kpod.net.iface.tx.drops` | Counter | `interface` | Interface transmit drops |
| `kpod.fs.capacity.bytes` | Gauge | `mountpoint` | Filesystem total capacity |
| `kpod.fs.usage.bytes` | Gauge | `mountpoint` | Filesystem used bytes |
| `kpod.fs.available.bytes` | Gauge | `mountpoint` | Filesystem available bytes |

### BPF Map Diagnostics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kpod.bpf.map.entries` | Gauge | `map` | Current entry count in BPF map |
| `kpod.bpf.map.capacity` | Gauge | `map` | Max entries per map (10240) |
| `kpod.bpf.map.update.errors.total` | Counter | `map` | BPF map update failures |

## Profiles

Control which metrics are collected via the `kpod.profile` setting:

| Collector | minimal | standard | comprehensive |
|-----------|:-------:|:--------:|:-------------:|
| CPU scheduling | yes | yes | yes |
| Network TCP (eBPF) | - | yes | yes |
| Memory OOM | yes | yes | yes |
| Memory page faults | - | yes | yes |
| Syscall tracing | - | - | yes |
| Disk I/O (cgroup) | yes | yes | yes |
| Interface network (cgroup) | - | yes | yes |
| Filesystem (cgroup) | - | yes | yes |

**Estimated cardinality per pod**: minimal ~20, standard ~39, comprehensive ~69 time series.

## Prerequisites

- **Linux kernel 5.8+** with BTF enabled (`/sys/kernel/btf/vmlinux` must exist)
- **Cgroup v2** (default on Kubernetes 1.25+)
- **Kubernetes 1.19+**

Required kernel config (typically enabled by default on modern distros):

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_DEBUG_INFO_BTF=y
```

## Quick Start

### Deploy with Helm

```bash
helm install kpod-metrics ./helm/kpod-metrics \
  --namespace kpod-metrics --create-namespace
```

### Verify

```bash
# Check the DaemonSet is running
kubectl -n kpod-metrics get pods

# Check metrics are being exported
kubectl -n kpod-metrics port-forward ds/kpod-metrics 9090:9090
curl http://localhost:9090/actuator/prometheus | grep kpod
```

## Configuration

All settings are under the `kpod.*` prefix. Configure via Helm values or environment variables.

### Helm Values

```yaml
image:
  repository: internal-registry/kpod-metrics
  tag: "0.1.0"

resources:
  requests:
    cpu: 150m
    memory: 256Mi
  limits:
    cpu: 500m
    memory: 512Mi

config:
  profile: standard          # minimal | standard | comprehensive | custom
  pollInterval: 30000        # Collection interval in ms
  discovery:
    mode: informer           # informer (K8s API) or kubelet (Kubelet API)
    kubeletPollInterval: 30  # seconds, for kubelet mode
  cgroup:
    root: /sys/fs/cgroup
    procRoot: /host/proc
```

### Key Properties

| Property | Default | Description |
|----------|---------|-------------|
| `kpod.profile` | `standard` | Metric collection profile |
| `kpod.poll-interval` | `30000` | Collection interval (ms) |
| `kpod.discovery.mode` | `informer` | Pod discovery: `informer` or `kubelet` |
| `kpod.filter.exclude-namespaces` | `kube-system, kube-public` | Namespaces to skip |
| `kpod.filter.namespaces` | `[]` (all) | Namespaces to include (empty = all) |
| `kpod.filter.label-selector` | `""` | K8s label selector filter |
| `kpod.bpf.enabled` | `true` | Enable eBPF programs |
| `kpod.bpf.program-dir` | `/app/bpf` | Path to compiled BPF objects |
| `kpod.syscall.tracked-syscalls` | `read, write, openat, ...` | Syscalls to trace (comprehensive profile) |

## Building

### Docker (recommended)

The build context requires both this repo and [kotlin-ebpf-dsl](https://github.com/pjs7678/kotlin-ebpf-dsl) as a sibling directory:

```
parent/
├── kpod-metrics/
└── kotlin-ebpf-dsl/
```

```bash
docker build -f kpod-metrics/Dockerfile -t kpod-metrics:latest .
```

The 5-stage Dockerfile handles:

1. **Codegen** -- Gradle runs kotlin-ebpf-dsl to generate BPF C code and Kotlin MapReader classes
2. **BPF compile** -- clang compiles generated `.bpf.c` into CO-RE `.bpf.o` objects
3. **JNI build** -- CMake compiles the JNI bridge (`libkpod_bpf.so`) against libbpf
4. **App build** -- Gradle builds the Spring Boot executable JAR
5. **Runtime** -- Eclipse Temurin JRE 21, minimal image with compiled artifacts

### Local Development

Requires JDK 21 and kotlin-ebpf-dsl as a sibling directory:

```bash
./gradlew generateBpf  # Generate BPF C code + Kotlin MapReader classes
./gradlew build         # Compile + test (140 tests)
./gradlew bootJar       # Build executable JAR
```

BPF programs and JNI library must be cross-compiled in a Linux environment (the Dockerfile handles this).

## BPF Code Generation

eBPF programs are defined as Kotlin DSL in `src/bpfGenerator/kotlin/`:

```kotlin
val memProgram = ebpfProgram("mem") {
    val counterKey = struct("counter_key") { u64("cgroup_id") }
    val oomKills = hashMap("oom_kills", counterKey, BpfScalar.U64, maxEntries = 10240)

    tracepoint("oom", "mark_victim") {
        val cgId = getCurrentCgroupId()
        val ptr = mapLookupElem(oomKills, cgId)
        ifNonNull(ptr) { atomicIncrement(it) }
    }
}
```

Running `./gradlew generateBpf` produces:

- `build/generated/bpf/*.bpf.c` -- kernel-side C programs
- `build/generated/kotlin/*MapReader.kt` -- type-safe map deserialization

Collectors use generated `MapReader` layout classes instead of manual `ByteBuffer` parsing:

```kotlin
// Before (manual)
val cgroupId = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN).long

// After (generated)
val cgroupId = MemMapReader.CounterKeyLayout.decodeCgroupId(keyBytes)
```

## Testing

### Unit Tests

```bash
./gradlew test  # 140 tests
```

### Integration Test (minikube)

```bash
# Full test: minikube start, Docker build, Helm deploy, stress test, cleanup
./scripts/test-local-k8s.sh

# Reuse existing minikube and skip Docker build
./scripts/test-local-k8s.sh --skip-minikube --skip-build

# Cleanup only
./scripts/test-local-k8s.sh --teardown
```

The integration test validates: health endpoint, Prometheus metrics, cgroup collector output, pod stability under stress (zero restarts, <5s scrape latency, <10% error rate).

## Scaling

Tested for clusters up to **1,000 nodes / 100,000 pods**.

| Component | Capacity |
|-----------|----------|
| BPF map entries | 10,240 per map (LRU, auto-evicts) |
| API server load | 1 node-scoped watch per node |
| Batch JNI | Single syscall per map read |
| Kernel memory | ~15-20 MB per node |
| Collection cycle | ~500-1000ms per node |

For large clusters, use the `standard` profile (not `comprehensive`) to keep Prometheus cardinality under 4M time series.

## Project Structure

```
kpod-metrics/
├── bpf/
│   └── vmlinux.h               # Kernel BTF headers for CO-RE
├── jni/
│   ├── bpf_bridge.c            # JNI bridge (libbpf wrapper)
│   └── CMakeLists.txt
├── src/
│   ├── bpfGenerator/kotlin/    # eBPF program definitions (Kotlin DSL)
│   │   └── .../bpf/programs/
│   │       ├── Structs.kt      # Shared BPF struct definitions
│   │       ├── MemProgram.kt
│   │       ├── CpuSchedProgram.kt
│   │       ├── NetProgram.kt
│   │       ├── SyscallProgram.kt
│   │       └── GenerateBpf.kt  # Code generation entry point
│   ├── main/kotlin/
│   │   └── com/internal/kpodmetrics/
│   │       ├── bpf/            # BpfBridge, BpfProgramManager, CgroupResolver
│   │       ├── cgroup/         # CgroupReader, CgroupPathResolver
│   │       ├── collector/      # All metric collectors (eBPF + cgroup)
│   │       ├── config/         # MetricsProperties, profiles, auto-configuration
│   │       ├── discovery/      # PodProvider, PodCgroupMapper
│   │       ├── k8s/            # PodWatcher (K8s informer)
│   │       └── model/          # DTOs
│   └── test/kotlin/            # 140 unit tests
├── helm/kpod-metrics/          # Helm chart (DaemonSet, RBAC, ConfigMap)
├── scripts/
│   ├── test-local-k8s.sh       # Integration test (minikube)
│   └── stress-workload.yaml
├── Dockerfile                  # 5-stage build (codegen → BPF → JNI → app → runtime)
├── build.gradle.kts
└── settings.gradle.kts         # Composite build with kotlin-ebpf-dsl
```

## Tech Stack

- **Runtime**: Kotlin 2.1.10, Spring Boot 3.4.3, JDK 21 (virtual threads)
- **eBPF**: CO-RE programs generated by [kotlin-ebpf-dsl](https://github.com/pjs7678/kotlin-ebpf-dsl), compiled with clang, loaded via libbpf + JNI
- **Metrics**: Micrometer + Prometheus registry
- **K8s**: Fabric8 Kubernetes Client 7.1.0
- **Build**: Gradle 8.12 (composite build), multi-stage Docker
