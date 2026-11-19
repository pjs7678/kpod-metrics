# eBPF Metrics

Metrics collected via eBPF programs attached to kernel tracepoints.

## CPU

| Metric | Type | Description |
|--------|------|-------------|
| `kpod.cpu.runqueue.latency` | Histogram | Time spent waiting in the CPU run queue, per event (seconds) |
| `kpod.cpu.context.switches` | Counter | Context switch count |

## Network

| Metric | Type | Description |
|--------|------|-------------|
| `kpod.net.tcp.bytes.sent` | Counter | TCP bytes sent |
| `kpod.net.tcp.bytes.received` | Counter | TCP bytes received |
| `kpod.net.tcp.retransmits` | Counter | TCP retransmissions |
| `kpod.net.tcp.connections` | Counter | TCP connection count |
| `kpod.net.tcp.rtt` | Histogram | Smoothed TCP round-trip time, per tcp_probe event (seconds) |
| `kpod.net.tcp.drops` | Counter | TCP packet drops |

## Memory

| Metric | Type | Description |
|--------|------|-------------|
| `kpod.mem.oom.kills` | Counter | OOM kill events |
| `kpod.mem.major.page.faults` | Counter | Major page faults |
| `kpod.mem.cache.accesses` | Counter | Page cache accesses |
| `kpod.mem.cache.additions` | Counter | Page cache additions (misses) |
| `kpod.mem.cache.dirtied` | Counter | Page cache dirty pages |
| `kpod.mem.cache.buf.dirtied` | Counter | Buffer cache dirty pages |

## Syscalls

| Metric | Type | Extra Labels | Description |
|--------|------|-------------|-------------|
| `kpod.syscall.count` | Counter | `syscall` | Syscall invocations |
| `kpod.syscall.errors` | Counter | `syscall` | Syscall errors |
| `kpod.syscall.latency` | Histogram | `syscall` | Syscall latency, per call |

## Disk I/O

| Metric | Type | Description |
|--------|------|-------------|
| `kpod.disk.io.latency` | Histogram | Block I/O latency, per request (seconds) |

## Interrupts

| Metric | Type | Description |
|--------|------|-------------|
| `kpod.irq.hw.latency` | DistributionSummary | Hardware interrupt latency (seconds) |
| `kpod.irq.hw.count` | Counter | Hardware interrupt count |
| `kpod.irq.sw.latency` | DistributionSummary | Software interrupt latency (seconds) |

## Process

| Metric | Type | Description |
|--------|------|-------------|
| `kpod.proc.execs` | Counter | Process exec events |
| `kpod.proc.forks` | Counter | Process fork events |
| `kpod.proc.exits` | Counter | Process exit events |
