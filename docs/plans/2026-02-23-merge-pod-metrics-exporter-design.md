# Design: Merge pod-metrics-exporter into kpod-metrics

**Date:** 2026-02-23
**Status:** Approved

## Goal

Merge pod-metrics-exporter into kpod-metrics to reduce operational overhead (single DaemonSet) and maintenance cost (single codebase). kpod-metrics serves as the base project.

## Decisions

- **Base project:** kpod-metrics
- **Project name:** kpod-metrics (unchanged)
- **Network metrics:** Keep both eBPF TCP-level and /proc interface-level (complementary)
- **Pod discovery:** Adopt dual mode from pod-metrics-exporter (K8s Informer primary + Kubelet polling fallback)
- **Cgroup support:** Both V1 and V2 with auto-detection
- **Metrics endpoint:** Micrometer + Actuator with background scheduled collection (15s)
- **Merge approach:** Incremental port, layer by layer

## Architecture

```
Spring Boot Application (Kotlin)
├── MetricsCollectorService (scheduled, 15s)
├── Micrometer + Actuator → /actuator/prometheus :9090
│
├── eBPF Collectors (existing)
│   ├── CpuSchedulingCollector
│   ├── NetworkCollector (TCP via eBPF)
│   ├── MemoryCollector
│   └── SyscallCollector
│
├── Cgroup/Proc Collectors (NEW from pod-metrics-exporter)
│   ├── DiskIOCollector (cgroup io.stat)
│   ├── InterfaceNetworkCollector (/proc/net/dev)
│   └── FilesystemCollector (mountinfo + statvfs)
│
├── BPF Layer (existing)
│   ├── BpfBridge (JNI)
│   └── BpfProgramManager
│
├── Cgroup Layer (NEW)
│   ├── CgroupVersionDetector (V1/V2 auto-detection)
│   ├── CgroupPathResolver (pod UID → cgroup path, V1+V2)
│   └── CgroupReader (parse cgroup/proc files)
│
└── Pod Discovery (ENHANCED)
    ├── PodProvider interface
    ├── K8sPodWatcher (informer, primary)
    ├── KubeletPodProvider (kubelet polling, fallback)
    ├── CgroupResolver (cgroup ID → pod, for eBPF)
    └── PodCgroupMapper (pod → cgroup path, for cgroup readers)
```

## Package Structure

```
com.internal.kpodmetrics/
├── KpodMetricsApplication.kt
├── bpf/
│   ├── BpfBridge.kt, BpfProgramManager.kt
│   ├── CgroupResolver.kt (cgroup ID → pod, for eBPF maps)
│   └── NativeHandle.kt
├── cgroup/ (NEW)
│   ├── CgroupVersionDetector.kt
│   ├── CgroupPathResolver.kt
│   └── CgroupReader.kt
├── collector/
│   ├── MetricsCollectorService.kt (updated to orchestrate all)
│   ├── CpuSchedulingCollector.kt, NetworkCollector.kt
│   ├── MemoryCollector.kt, SyscallCollector.kt
│   ├── DiskIOCollector.kt (NEW)
│   ├── InterfaceNetworkCollector.kt (NEW)
│   └── FilesystemCollector.kt (NEW)
├── discovery/ (NEW, replaces k8s/)
│   ├── PodProvider.kt (interface)
│   ├── K8sPodWatcher.kt (informer)
│   ├── KubeletPodProvider.kt (kubelet polling fallback)
│   └── PodCgroupMapper.kt
├── config/
│   ├── BpfAutoConfiguration.kt
│   └── MetricsProperties.kt (updated)
└── model/ (NEW)
    ├── PodInfo.kt
    └── PodCgroupTarget.kt
```

## Combined Metrics

### eBPF-sourced (existing)
| Metric | Type |
|--------|------|
| `kpod.cpu.runqueue.latency` | distribution |
| `kpod.cpu.context.switches` | counter |
| `kpod.net.tcp.bytes.sent` | counter |
| `kpod.net.tcp.bytes.received` | counter |
| `kpod.net.tcp.retransmits` | counter |
| `kpod.net.tcp.connections` | counter |
| `kpod.net.tcp.rtt` | distribution |
| `kpod.mem.oom.kills` | counter |
| `kpod.mem.major.page.faults` | counter |
| `kpod.syscall.count` | counter |
| `kpod.syscall.errors` | counter |
| `kpod.syscall.latency` | distribution |

### Cgroup/proc-sourced (NEW)
| Metric | Type |
|--------|------|
| `kpod.disk.read.bytes` | counter |
| `kpod.disk.written.bytes` | counter |
| `kpod.disk.reads` | counter |
| `kpod.disk.writes` | counter |
| `kpod.net.iface.rx.bytes` | counter |
| `kpod.net.iface.tx.bytes` | counter |
| `kpod.net.iface.rx.packets` | counter |
| `kpod.net.iface.tx.packets` | counter |
| `kpod.net.iface.rx.errors` | counter |
| `kpod.net.iface.tx.errors` | counter |
| `kpod.net.iface.rx.drops` | counter |
| `kpod.net.iface.tx.drops` | counter |
| `kpod.fs.capacity.bytes` | gauge |
| `kpod.fs.usage.bytes` | gauge |
| `kpod.fs.available.bytes` | gauge |

All metrics labeled with: `namespace`, `pod`, `container`, `node` (plus `device`, `interface`, or `mountpoint` where applicable).

## Configuration

```yaml
kpod:
  profile: standard  # minimal | standard | comprehensive | custom
  poll-interval: 15000
  node-name: ${NODE_NAME}
  discovery:
    mode: informer  # informer | kubelet | auto
    kubelet-poll-interval: 30
    node-ip: ${NODE_IP:}
  bpf:
    enabled: true
    program-dir: /app/bpf
  cgroup:
    root: /host/sys/fs/cgroup
    proc-root: /host/proc
  filter:
    namespaces: []
    excludeNamespaces: [kube-system, kube-public]
```

## Profile Mapping

| Profile | eBPF | Cgroup |
|---------|------|--------|
| minimal | CPU | Disk I/O |
| standard | CPU + TCP + Memory | Disk I/O + Interface Net + Filesystem |
| comprehensive | All (+ Syscall) | All |

## Implementation Approach

Incremental port in 4 phases:

1. **Cgroup infrastructure** - CgroupVersionDetector, CgroupPathResolver, CgroupReader (V1+V2)
2. **Pod discovery upgrade** - PodProvider interface, KubeletPodProvider fallback, PodCgroupMapper
3. **New collectors** - DiskIOCollector, InterfaceNetworkCollector, FilesystemCollector (using Micrometer)
4. **Integration** - Update MetricsCollectorService, config, Helm chart, Dockerfile
