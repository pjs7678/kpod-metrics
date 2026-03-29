# Troubleshooting

## BPF Programs Failed to Load

**Symptom:** `/actuator/health` shows `bpf: DOWN` with failed programs.

**Check logs:**
```bash
kubectl logs ds/kpod-metrics | grep -i "failed to load"
```

**Common causes:**

| Cause | Fix |
|-------|-----|
| Kernel too old (< 4.18) | Upgrade to 4.18+ (legacy) or 5.2+ (CO-RE) |
| Missing BTF (kernel 5.2+ without `CONFIG_DEBUG_INFO_BTF`) | Legacy BPF is used automatically; check if `/sys/kernel/btf/vmlinux` exists |
| Missing capabilities | Ensure `BPF`, `PERFMON`, `SYS_RESOURCE`, `NET_ADMIN` capabilities are granted |
| Seccomp blocking BPF syscall | Use `RuntimeDefault` or add `bpf` to allowed syscalls |
| SELinux denying BPF access | Check `ausearch -m avc -ts recent` for BPF denials |

!!! tip
    kpod-metrics degrades gracefully — if a BPF program fails to load, other collectors continue working. Cgroup-based collectors never require BPF.

## No Metrics for Some Pods

**Check namespace filter:**
```bash
kubectl get configmap -n kpod-metrics kpod-metrics -o yaml | grep -A5 filter
```

By default, `kube-system` and `kube-public` are excluded.

**Check pod discovery:**
```bash
curl http://localhost:9090/actuator/prometheus | grep kpod_discovery_pods_total
```

If this is 0, the pod informer may not be watching the correct node.

## High Memory Usage

**Possible causes:**

- `comprehensive` profile with many pods — switch to `standard` or `minimal`
- Too many BPF map entries — check `kpod_bpf_map_entries` metric
- JVM heap — adjust with `JAVA_OPTS="-Xmx384m"` in `extraEnv`

## Collection Timeouts

**Symptom:** `kpod_collection_timeouts_total` is increasing.

**Causes:**

- Too many pods on a single node
- Slow cgroup filesystem reads (NFS-backed)
- Heavy syscall collector with many tracked syscalls

**Fix:** Increase `config.collectionTimeout` or use per-collector intervals:

```yaml
config:
  collectionTimeout: 30000
  collectorIntervals:
    syscall: 60000
    biolatency: 60000
```

## Kernel Compatibility Matrix

| Distro | Kernel | Mode | Status |
|--------|--------|------|--------|
| Ubuntu 22.04+ | 5.15+ | CO-RE | Fully supported |
| Ubuntu 20.04 | 5.4 | CO-RE | Fully supported |
| RHEL 8.2+ | 4.18 | Legacy | Fully supported |
| RHEL 9+ | 5.14+ | CO-RE | Fully supported |
| Debian 11+ | 5.10+ | CO-RE | Fully supported |
| Amazon Linux 2023 | 6.1+ | CO-RE | Fully supported |
| Bottlerocket | 5.10+ | CO-RE | Fully supported |

## Getting Help

- [GitHub Issues](https://github.com/pjs7678/kpod-metrics/issues) — Bug reports and feature requests
- [GitHub Discussions](https://github.com/pjs7678/kpod-metrics/discussions) — Questions and general discussion
