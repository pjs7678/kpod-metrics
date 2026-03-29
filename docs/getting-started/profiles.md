# Collection Profiles

Control which metrics are collected via the `kpod.profile` setting.

## Profile Comparison

| Collector | minimal | standard | comprehensive |
|-----------|:-------:|:--------:|:-------------:|
| CPU scheduling | yes | yes | yes |
| Network TCP (eBPF) | - | yes | yes |
| TCP drops (eBPF) | - | yes | yes |
| Memory OOM | yes | yes | yes |
| Memory page faults | - | yes | yes |
| Block I/O latency (eBPF) | - | yes | yes |
| Page cache stats (eBPF) | - | yes | yes |
| Hardware IRQ latency (eBPF) | - | - | yes |
| Software IRQ latency (eBPF) | - | - | yes |
| Process exec/fork/exit (eBPF) | - | - | yes |
| Syscall tracing | - | - | yes |
| Disk I/O (cgroup) | yes | yes | yes |
| Interface network (cgroup) | - | yes | yes |
| Filesystem (cgroup) | - | yes | yes |

**Estimated cardinality per pod**: minimal ~20, standard ~39, comprehensive ~69 time series.

## Choosing a Profile

- **minimal** — Low overhead, essential metrics only. Good for large clusters where Prometheus cardinality is a concern.
- **standard** (default) — Balanced coverage. Recommended for most production clusters.
- **comprehensive** — Full observability including syscall tracing, IRQ latency, and process lifecycle. Higher cardinality.

## Setting the Profile

=== "Helm"

    ```yaml
    config:
      profile: standard
    ```

=== "Environment Variable"

    ```bash
    KPOD_PROFILE=comprehensive
    ```

## Custom Profile

Use `custom` profile with per-collector overrides:

```yaml
config:
  profile: custom
  collectors:
    cpu: true
    network: true
    syscall: false
    biolatency: true
    cachestat: false
    tcpdrop: true
    hardirqs: false
    softirqs: false
    execsnoop: true
    diskIO: true
    ifaceNet: true
    filesystem: true
```

## Cardinality Planning

For large clusters, use the `standard` profile to keep Prometheus cardinality under 4M time series:

| Cluster Size | Recommended Profile | Estimated Time Series |
|-------------|--------------------|-----------------------|
| < 100 pods | comprehensive | ~7,000 |
| 100–1,000 pods | standard | ~39,000 |
| 1,000–10,000 pods | standard | ~390,000 |
| 10,000–100,000 pods | minimal or standard | ~2M–3.9M |
