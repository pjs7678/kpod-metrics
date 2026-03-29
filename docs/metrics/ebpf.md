# eBPF Metrics

Metrics collected via eBPF programs attached to kernel tracepoints.

## CPU

| Metric | Type | Description |
|--------|------|-------------|
| `kpod.cpu.runqueue.latency` | DistributionSummary | Time spent waiting in the CPU run queue (seconds) |
| `kpod.cpu.context.switches` | Counter | Context switch count |

## Network

| Metric | Type | Description |
|--------|------|-------------|
| `kpod.net.tcp.bytes.sent` | Counter | TCP bytes sent |
| `kpod.net.tcp.bytes.received` | Counter | TCP bytes received |
| `kpod.net.tcp.retransmits` | Counter | TCP retransmissions |
| `kpod.net.tcp.connections` | Counter | TCP connection count |
| `kpod.net.tcp.rtt` | DistributionSummary | TCP round-trip time (seconds) |
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
| `kpod.syscall.latency` | DistributionSummary | `syscall` | Syscall latency |

## Disk I/O

| Metric | Type | Description |
|--------|------|-------------|
| `kpod.disk.io.latency` | DistributionSummary | Block I/O latency (seconds) |

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
