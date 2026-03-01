# kpod-metrics

[![CI](https://github.com/pjs7678/kpod-metrics/actions/workflows/ci.yml/badge.svg)](https://github.com/pjs7678/kpod-metrics/actions/workflows/ci.yml)

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
│  │   ├── BiolatencyCollector                    │
│  │   ├── CachestatCollector                     │
│  │   ├── TcpdropCollector                       │
│  │   ├── HardirqsCollector                      │
│  │   ├── SoftirqsCollector                      │
│  │   ├── ExecsnoopCollector                     │
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
| `kpod.net.tcp.drops` | Counter | TCP packet drops |
| `kpod.disk.io.latency` | DistributionSummary | Block I/O latency (seconds) |
| `kpod.mem.cache.accesses` | Counter | Page cache accesses |
| `kpod.mem.cache.additions` | Counter | Page cache additions (misses) |
| `kpod.mem.cache.dirtied` | Counter | Page cache dirty pages |
| `kpod.mem.cache.buf.dirtied` | Counter | Buffer cache dirty pages |
| `kpod.irq.hw.latency` | DistributionSummary | Hardware interrupt latency (seconds) |
| `kpod.irq.hw.count` | Counter | Hardware interrupt count |
| `kpod.irq.sw.latency` | DistributionSummary | Software interrupt latency (seconds) |
| `kpod.proc.execs` | Counter | Process exec events |
| `kpod.proc.forks` | Counter | Process fork events |
| `kpod.proc.exits` | Counter | Process exit events |

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

### Memory Cgroup Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `kpod.mem.cgroup.usage.bytes` | Gauge | Current memory usage |
| `kpod.mem.cgroup.peak.bytes` | Gauge | Peak memory usage |
| `kpod.mem.cgroup.cache.bytes` | Gauge | Page cache usage |
| `kpod.mem.cgroup.swap.bytes` | Gauge | Swap usage |

### Pod Lifecycle Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kpod.container.restarts` | Gauge | `container` | Container restart count from K8s API |

### Self-Monitoring Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kpod.collection.cycle.duration` | Timer | — | Full collection cycle duration |
| `kpod.collector.duration` | Timer | `collector` | Per-collector execution time |
| `kpod.collector.errors.total` | Counter | `collector` | Per-collector failure count |
| `kpod.collection.timeouts.total` | Counter | — | Collection timeout count |
| `kpod.discovery.pods.total` | Gauge | — | Discovered pods per cycle |
| `kpod.cgroup.read.errors` | Counter | `collector` | Cgroup read failures |

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
| TCP drops (eBPF) | - | yes | yes |
| Memory OOM | yes | yes | yes |
| Memory page faults | - | yes | yes |
| Block I/O latency (eBPF) | - | yes | yes |
| Page cache stats (eBPF) | - | yes | yes |
| Hardware IRQ latency (eBPF) | - | - | yes |
| Software IRQ latency (eBPF) | - | - | yes |
| Process exec/fork/exit (eBPF) | - | - | yes |
| Syscall tracing | - | - | yes |
| Disk I/O (cgroup) | yes | yes | yes |
| Interface network (cgroup) | - | yes | yes |
| Filesystem (cgroup) | - | yes | yes |

**Estimated cardinality per pod**: minimal ~20, standard ~39, comprehensive ~69 time series.

## Prerequisites

- **Linux kernel 4.18+** (5.2+ recommended for CO-RE/BTF)
- **Cgroup v2** (default on Kubernetes 1.25+)
- **Kubernetes 1.19+**

The image ships two sets of compiled BPF programs. At startup, kpod-metrics checks for `/sys/kernel/btf/vmlinux` and automatically loads the appropriate set.

### Kernel Version Support

| Kernel | Mode | How it works |
|--------|------|--------------|
| **5.2+** | CO-RE (recommended) | Uses BTF for portable BPF loading. All features supported. Most distros since RHEL 8.2, Ubuntu 20.04, Debian 11. |
| **4.18–5.1** | Legacy | Uses pre-compiled BPF programs with fixed struct offsets. All features supported, but BPF objects are not relocatable across kernel builds with non-standard tracepoint layouts. |
| **< 4.18** | Not supported | Missing `bpf_get_current_cgroup_id()` helper required for per-pod attribution. |

**Limitations of legacy mode (4.18–5.1):**
- Tracepoint context struct layouts are assumed to match the stable kernel ABI. Custom or patched kernels that alter tracepoint format fields may cause incorrect data or load failures.
- No automatic struct relocation — if a field offset changes, the BPF program must be recompiled with an updated `compat_vmlinux.h`.

**How to verify your kernel supports kpod-metrics:**

```bash
# Check kernel version
uname -r

# Check if BTF is available (5.2+ with CONFIG_DEBUG_INFO_BTF=y)
ls /sys/kernel/btf/vmlinux

# Check cgroup v2
mount | grep cgroup2
```

Required kernel config (typically enabled by default on modern distros):

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_DEBUG_INFO_BTF=y  # Required only for CO-RE path; optional on 4.18+
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

### Grafana Dashboard

A ready-made Grafana dashboard is included with 9 rows covering all metric categories. It auto-provisions via the Grafana sidecar when deployed with Helm:

```yaml
grafana:
  dashboard:
    enabled: true   # default
    label: "1"      # matches Grafana sidecar default
```

For non-Helm setups, import `grafana/kpod-metrics-dashboard.json` directly via the Grafana UI.

### Prometheus Operator

For clusters running the [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator), enable the ServiceMonitor and PrometheusRule:

```yaml
serviceMonitor:
  enabled: true
  interval: 30s

prometheusRule:
  enabled: true
```

This provisions 15 alerting rules including: high runqueue latency, TCP retransmits/drops, syscall error rate, filesystem full, BPF map health, container restart rate, crash loop detection, and memory pressure. Plus 12 recording rules for precomputed p50/p99 aggregations.

## Configuration

All settings are under the `kpod.*` prefix. Configure via Helm values or environment variables.

### Helm Values

```yaml
image:
  repository: internal-registry/kpod-metrics
  tag: "1.3.0"

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

grafana:
  dashboard:
    enabled: true            # Deploy Grafana dashboard ConfigMap
    label: "1"               # Sidecar label selector value

serviceMonitor:
  enabled: false             # Requires Prometheus Operator CRDs
  interval: 30s
  scrapeTimeout: 10s

prometheusRule:
  enabled: false             # Requires Prometheus Operator CRDs
```

### Key Properties

| Property | Default | Description |
|----------|---------|-------------|
| `kpod.profile` | `standard` | Metric collection profile |
| `kpod.poll-interval` | `30000` | Base collection interval (ms) |
| `kpod.collection-timeout` | `20000` | Max time per collection cycle (ms) |
| `kpod.initial-delay` | `10000` | Delay before first collection (ms) |
| `kpod.node-name` | `${NODE_NAME}` | Node name for metric tags |
| `kpod.cluster-name` | `""` | Cluster name for multi-cluster tag |
| `kpod.discovery.mode` | `informer` | Pod discovery: `informer` or `kubelet` |
| `kpod.filter.namespaces` | `[]` (all) | Namespaces to include (empty = all) |
| `kpod.filter.exclude-namespaces` | `kube-system, kube-public` | Namespaces to skip |
| `kpod.filter.label-selector` | `""` | Label selector (`key=value`, `key!=value`, `key`) |
| `kpod.filter.include-labels` | `app, app.kubernetes.io/name, ...` | Pod labels to include as metric tags |
| `kpod.bpf.enabled` | `true` | Enable eBPF programs |

### Per-Collector Intervals

Heavy collectors can run less frequently than the base `poll-interval`. Set per-collector intervals in milliseconds:

```yaml
config:
  collectorIntervals:
    syscall: 60000      # every 60s instead of 30s
    biolatency: 60000
    hardirqs: 60000
    softirqs: 60000
```

Collectors without an explicit interval run every cycle. Use `config.collectors.<name>: false` to disable a collector entirely.
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
2. **BPF compile** -- clang compiles generated `.bpf.c` into both CO-RE (5.2+) and legacy (4.18+) `.bpf.o` objects
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

The integration test validates: health endpoint, Prometheus metrics, cgroup collector output, pod stability under stress (zero restarts, <5s scrape latency, <10% error rate). It also runs the E2E test (below) as a non-blocking sub-step.

### E2E Test (targeted workloads)

Deploys deterministic workload pods that generate specific kernel events, then asserts that kpod-metrics captures them as Prometheus metrics with correct pod labels.

```bash
# Full run: build, deploy, test, cleanup
./e2e/e2e-test.sh --cleanup

# Skip build, use existing image
./e2e/e2e-test.sh --skip-build --cleanup

# Test against an already-running deployment
./e2e/e2e-test.sh --skip-build --skip-deploy
```

| Flag | Description |
|------|-------------|
| `--skip-build` | Skip Docker image build (use existing image) |
| `--skip-deploy` | Skip helm install (use existing deployment) |
| `--cleanup` | Full teardown after test (helm uninstall + namespace delete) |
| `--wait=N` | Override metrics collection wait time in seconds (default: 25) |
| `--port=N` | Reuse an existing port-forward on this port |

**Workloads** (deployed to `e2e-test` namespace):

| Pod | Kernel Activity | Metrics Verified |
|-----|----------------|-----------------|
| `e2e-cpu-worker` | 4 busy-loop forks, 100m CPU limit | `kpod_cpu_context_switches_total` |
| `e2e-net-server` / `e2e-net-client` | TCP connect/send loop | `kpod_net_tcp_connections_total`, `kpod_net_iface_rx_bytes_total` |
| `e2e-syscall-worker` | Tight `cat /proc/self/status` loop | `kpod_syscall_count_total` |
| `e2e-mem-worker` | `dd` 10MB allocations | `kpod_fs_usage_bytes` |

eBPF-based assertions are **warn-only** (BPF programs may not load on minikube). Cgroup-based assertions are required to pass.

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
│   ├── vmlinux.h               # Kernel BTF headers for CO-RE
│   └── compat_vmlinux.h        # Minimal header for legacy (non-CO-RE) builds
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
├── grafana/
│   └── kpod-metrics-dashboard.json  # Standalone Grafana dashboard (importable via UI)
├── helm/kpod-metrics/          # Helm chart (DaemonSet, RBAC, ConfigMap)
│   ├── dashboards/
│   │   └── kpod-metrics.json   # Dashboard JSON for Helm-managed ConfigMap
│   └── templates/
│       ├── grafana-dashboard-cm.yaml   # Grafana sidecar ConfigMap
│       ├── servicemonitor.yaml         # Prometheus Operator ServiceMonitor
│       ├── prometheusrule.yaml         # Prometheus Operator alerting rules
│       └── service.yaml                # Headless Service for ServiceMonitor
├── e2e/
│   ├── e2e-test.sh             # E2E targeted workload test
│   └── workloads.yaml          # CPU, network, syscall, memory workload pods
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
- **CI/CD**: GitHub Actions — unit tests on PRs, image publish on merge to main

## CI/CD

GitHub Actions runs two workflows:

- **CI** (`ci.yml`) — Runs unit tests on every PR and push to `main`. Checks out the sibling [kotlin-ebpf-dsl](https://github.com/pjs7678/kotlin-ebpf-dsl) repo for the composite Gradle build.
- **Publish** (`publish.yml`) — On push to `main`, builds the Docker image and pushes to `ghcr.io/pjs7678/kpod-metrics` with `:latest` and `:<sha>` tags.

```bash
docker pull ghcr.io/pjs7678/kpod-metrics:latest
```
