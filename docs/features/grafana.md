# Grafana Dashboard

A ready-made Grafana dashboard is included with 9 rows covering all metric categories.

## Auto-Provisioning via Helm

The dashboard auto-provisions via the Grafana sidecar when deployed with Helm:

```yaml
grafana:
  dashboard:
    enabled: true   # default
    label: "1"      # matches Grafana sidecar default
```

The Helm chart creates a ConfigMap with the dashboard JSON, labeled for automatic pickup by the Grafana sidecar.

## Manual Import

For non-Helm setups, import `grafana/kpod-metrics-dashboard.json` directly via the Grafana UI:

1. Open Grafana
2. Go to **Dashboards > Import**
3. Upload `grafana/kpod-metrics-dashboard.json`
4. Select your Prometheus data source

## Dashboard Rows

The dashboard includes 9 rows:

1. **Overview** — Pod count, collection cycle duration, collector health
2. **CPU** — Run queue latency (p50/p90/p99), context switches
3. **Network** — TCP bytes, connections, retransmits, RTT
4. **Memory** — OOM kills, page faults, cgroup usage
5. **Syscalls** — Per-syscall count, errors, latency
6. **Disk I/O** — Block I/O latency, read/write throughput
7. **Filesystem** — Capacity, usage, available space
8. **Interrupts** — Hardware/software IRQ latency
9. **Topology** — Service dependency Node Graph (requires Infinity plugin)

## Recording Rules

When [Prometheus Operator](prometheus-operator.md) is enabled, 17 recording rules are provisioned for precomputed p50/p90/p99 aggregations. The dashboard uses these recording rules for efficient rendering.
