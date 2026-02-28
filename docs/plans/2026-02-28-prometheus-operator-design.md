# Prometheus Operator Integration Design

## Context

kpod-metrics uses annotation-based Prometheus scraping. Clusters running the Prometheus Operator need ServiceMonitor and PrometheusRule CRDs for proper integration. Operators also need production alerting rules out of the box.

## Scope

- Headless Service (required target for ServiceMonitor)
- ServiceMonitor CRD template
- PrometheusRule CRD template with 8 production alerts
- All Helm-gated, disabled by default (requires Prometheus Operator)

## New Helm Templates

### service.yaml
Headless ClusterIP Service selecting kpod-metrics pods, exposing port 9090 (metrics).

### servicemonitor.yaml
ServiceMonitor targeting the headless Service with configurable interval, scrapeTimeout, labels.

### prometheusrule.yaml
PrometheusRule with 8 alerts:

| Alert | Severity | Condition |
|-------|----------|-----------|
| KpodHighRunqueueLatency | warning | p99 > 100ms for 5m |
| KpodHighTcpRetransmitRate | warning | rate > 10/s for 5m |
| KpodTcpDropsDetected | warning | drops > 0 for 5m |
| KpodHighSyscallErrorRate | warning | error rate > 5% for 10m |
| KpodFilesystemAlmostFull | critical | usage > 90% for 5m |
| KpodBpfMapNearCapacity | warning | utilization > 80% for 5m |
| KpodBpfMapUpdateErrors | critical | errors > 0 for 5m |
| KpodTargetDown | critical | target unreachable for 5m |

## values.yaml Additions

```yaml
serviceMonitor:
  enabled: false
  interval: 30s
  scrapeTimeout: 10s
  labels: {}
  annotations: {}

prometheusRule:
  enabled: false
  labels: {}
  annotations: {}
```
