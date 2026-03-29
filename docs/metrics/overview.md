# Metrics Overview

kpod-metrics exports 50+ metrics across 8 categories. All metrics are labeled with `namespace`, `pod`, `container`, and `node`.

## Metric Categories

| Category | Source | Key Metrics |
|----------|--------|-------------|
| [CPU](ebpf.md#cpu) | eBPF | Run queue latency, context switches |
| [Network](ebpf.md#network) | eBPF | TCP bytes, retransmits, drops, RTT, connections |
| [Memory](ebpf.md#memory) | eBPF + Cgroup | OOM kills, page faults, cache stats, cgroup usage |
| [Syscalls](ebpf.md#syscalls) | eBPF | Per-syscall count, errors, latency |
| [Disk I/O](ebpf.md#disk-io) | eBPF + Cgroup | Block I/O latency, read/write bytes |
| [L7 Protocols](l7.md) | eBPF | HTTP, DNS, Redis, MySQL, Kafka, MongoDB |
| [Interrupts](ebpf.md#interrupts) | eBPF | Hardware/software IRQ latency |
| [Process](ebpf.md#process) | eBPF | Exec, fork, exit events |

## Metric Naming

All metrics use the `kpod.` prefix (exported as `kpod_` in Prometheus format):

- `kpod.cpu.*` — CPU scheduling metrics
- `kpod.net.*` — Network metrics (TCP + interface)
- `kpod.mem.*` — Memory metrics (OOM, page faults, cache, cgroup)
- `kpod.syscall.*` — Syscall metrics
- `kpod.disk.*` — Disk I/O metrics
- `kpod.fs.*` — Filesystem metrics
- `kpod.irq.*` — Interrupt metrics
- `kpod.proc.*` — Process lifecycle metrics

## Labels

Every metric includes these standard labels:

| Label | Description |
|-------|-------------|
| `namespace` | Kubernetes namespace |
| `pod` | Pod name |
| `container` | Container name |
| `node` | Node name |

Some metrics include additional labels (e.g., `device`, `interface`, `syscall`, `mountpoint`). See individual metric pages for details.
