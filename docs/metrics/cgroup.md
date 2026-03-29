# Cgroup Metrics

Metrics collected from cgroup v2 filesystem (`/sys/fs/cgroup`).

## Disk I/O

| Metric | Type | Extra Labels | Description |
|--------|------|-------------|-------------|
| `kpod.disk.read.bytes` | Counter | `device` | Bytes read from disk |
| `kpod.disk.written.bytes` | Counter | `device` | Bytes written to disk |
| `kpod.disk.reads` | Counter | `device` | Read operation count |
| `kpod.disk.writes` | Counter | `device` | Write operation count |

## Network Interface

| Metric | Type | Extra Labels | Description |
|--------|------|-------------|-------------|
| `kpod.net.iface.rx.bytes` | Counter | `interface` | Interface bytes received |
| `kpod.net.iface.tx.bytes` | Counter | `interface` | Interface bytes transmitted |
| `kpod.net.iface.rx.packets` | Counter | `interface` | Interface packets received |
| `kpod.net.iface.tx.packets` | Counter | `interface` | Interface packets transmitted |
| `kpod.net.iface.rx.errors` | Counter | `interface` | Interface receive errors |
| `kpod.net.iface.tx.errors` | Counter | `interface` | Interface transmit errors |
| `kpod.net.iface.rx.drops` | Counter | `interface` | Interface receive drops |
| `kpod.net.iface.tx.drops` | Counter | `interface` | Interface transmit drops |

## Filesystem

| Metric | Type | Extra Labels | Description |
|--------|------|-------------|-------------|
| `kpod.fs.capacity.bytes` | Gauge | `mountpoint` | Filesystem total capacity |
| `kpod.fs.usage.bytes` | Gauge | `mountpoint` | Filesystem used bytes |
| `kpod.fs.available.bytes` | Gauge | `mountpoint` | Filesystem available bytes |

## Memory Cgroup

| Metric | Type | Description |
|--------|------|-------------|
| `kpod.mem.cgroup.usage.bytes` | Gauge | Current memory usage |
| `kpod.mem.cgroup.peak.bytes` | Gauge | Peak memory usage |
| `kpod.mem.cgroup.cache.bytes` | Gauge | Page cache usage |
| `kpod.mem.cgroup.swap.bytes` | Gauge | Swap usage |

## Pod Lifecycle

| Metric | Type | Extra Labels | Description |
|--------|------|-------------|-------------|
| `kpod.container.restarts` | Gauge | `container` | Container restart count from K8s API |
