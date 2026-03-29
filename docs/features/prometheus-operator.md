# Prometheus Operator

For clusters running the [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator), kpod-metrics provides a ServiceMonitor and PrometheusRule.

## Enable

```yaml
serviceMonitor:
  enabled: true
  interval: 30s

prometheusRule:
  enabled: true
```

## ServiceMonitor

When enabled, the Helm chart creates a ServiceMonitor that configures Prometheus to scrape kpod-metrics pods automatically. No manual scrape config needed.

Options:

```yaml
serviceMonitor:
  enabled: true
  interval: 30s        # scrape interval
  scrapeTimeout: 10s   # per-scrape timeout
  labels: {}           # extra labels for the ServiceMonitor
  annotations: {}      # extra annotations
```

## Alerting Rules

The PrometheusRule provisions **18 alerting rules**:

| Alert | Description |
|-------|-------------|
| High runqueue latency | CPU scheduling delays above threshold |
| TCP retransmit rate | Elevated retransmissions per pod |
| TCP drop rate | Packets being dropped |
| Syscall error rate | High syscall failure ratio |
| Filesystem full | Filesystem usage above 90% |
| BPF map near capacity | BPF map entries approaching limit |
| Container restart rate | Frequent container restarts |
| Crash loop detection | Containers in crash loop |
| Memory pressure | High memory usage relative to limits |
| Collector skip rate | Collectors being skipped too frequently |
| Fork/exec bomb | Abnormal process creation rate |
| OOM kills | OOM events detected |
| Collection timeout | Collection cycle exceeding timeout |
| High disk I/O latency | Block I/O latency above threshold |
| Network interface errors | Interface-level errors |
| IRQ latency spike | Interrupt handling delays |
| BPF program load failure | BPF program failed to load |
| High collector error rate | Collector failures above threshold |

## Recording Rules

**17 recording rules** for precomputed aggregations:

- p50/p90/p99 for CPU runqueue latency
- p50/p90/p99 for TCP RTT
- p50/p90/p99 for syscall latency
- p50/p90/p99 for disk I/O latency
- p50/p90/p99 for IRQ latency
- Rate aggregations for counters

These recording rules are used by the included Grafana dashboard for efficient rendering.
