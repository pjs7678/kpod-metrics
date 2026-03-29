# Configuration

All settings are under the `kpod.*` prefix. Configure via Helm values or environment variables.

## Helm Values

```yaml
image:
  repository: ghcr.io/pjs7678/kpod-metrics
  tag: "1.11.0"

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

## Key Properties

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
| `kpod.otlp.enabled` | `false` | Enable OTLP metrics export |
| `kpod.otlp.endpoint` | `http://localhost:4318/v1/metrics` | OTLP collector endpoint |
| `kpod.otlp.step` | `60000` | OTLP push interval (ms) |

## Per-Collector Intervals

Heavy collectors can run less frequently than the base `poll-interval`:

```yaml
config:
  collectorIntervals:
    syscall: 60000      # every 60s instead of 30s
    biolatency: 60000
    hardirqs: 60000
    softirqs: 60000
```

Collectors without an explicit interval run every cycle. Use `config.collectors.<name>: false` to disable a collector entirely.

## Namespace Filtering

By default, `kube-system` and `kube-public` are excluded. To monitor specific namespaces only:

```yaml
config:
  filter:
    namespaces:
      - production
      - staging
    excludeNamespaces: []
```

## Label Filtering

Include pod labels as metric tags:

```yaml
config:
  filter:
    labelSelector: "app=myservice"
    includeLabels:
      - app
      - version
      - team
```
