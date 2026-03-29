# Scaling

kpod-metrics is tested for clusters up to **1,000 nodes / 100,000 pods**.

## Resource Usage

| Component | Value |
|-----------|-------|
| BPF map entries | 10,240 per map (LRU, auto-evicts) |
| API server load | 1 node-scoped watch per node |
| Batch JNI | Single syscall per map read |
| Kernel memory | ~15–20 MB per node |
| Collection cycle | ~500–1000ms per node |

## Default Resource Requests

```yaml
resources:
  requests:
    cpu: 150m
    memory: 256Mi
  limits:
    cpu: 500m
    memory: 512Mi
```

## Cardinality Planning

| Cluster Size | Profile | Estimated Time Series |
|-------------|---------|----------------------|
| < 100 pods | comprehensive | ~7,000 |
| 100–1,000 pods | standard | ~39,000 |
| 1,000–10,000 pods | standard | ~390,000 |
| 10,000–100,000 pods | minimal or standard | ~2M–3.9M |

For large clusters, use the `standard` profile (not `comprehensive`) to keep Prometheus cardinality under 4M time series.

## Performance Tips

- Use [per-collector intervals](../getting-started/configuration.md#per-collector-intervals) to reduce overhead for heavy collectors (syscall, biolatency)
- Use [namespace filtering](../getting-started/configuration.md#namespace-filtering) to limit scope
- Use the `minimal` profile if you only need CPU and memory metrics
- BPF maps use LRU eviction — no manual cleanup needed
