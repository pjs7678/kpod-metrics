# Self-Monitoring Metrics

kpod-metrics exports metrics about its own health and performance.

## Collection Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kpod.collection.cycle.duration` | Timer | — | Full collection cycle duration |
| `kpod.collector.duration` | Timer | `collector` | Per-collector execution time |
| `kpod.collector.errors.total` | Counter | `collector` | Per-collector failure count |
| `kpod.collector.skipped.total` | Counter | `collector` | Interval-based collector skips |
| `kpod.collection.timeouts.total` | Counter | — | Collection timeout count |
| `kpod.discovery.pods.total` | Gauge | — | Discovered pods per cycle |
| `kpod.cgroup.read.errors` | Counter | `collector` | Cgroup read failures |
| `kpod.bpf.program.load.duration` | Timer | `program` | BPF program load time at startup |

## BPF Map Diagnostics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kpod.bpf.map.entries` | Gauge | `map` | Current entry count in BPF map |
| `kpod.bpf.map.capacity` | Gauge | `map` | Max entries per map (10240) |
| `kpod.bpf.map.update.errors.total` | Counter | `map` | BPF map update failures |

## Health Endpoint

The `/actuator/health` endpoint reports component status:

```bash
curl http://localhost:9090/actuator/health | python3 -m json.tool
```

Components reported:

- `bpf` — BPF program load status (which programs loaded/failed)
- `diskSpace` — Available disk space
- `ping` — Basic liveness
