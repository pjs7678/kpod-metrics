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

**Verify kernel support:**
```bash
# On the node:
uname -r                              # Kernel version
ls /sys/kernel/btf/vmlinux 2>/dev/null && echo "BTF available" || echo "No BTF (legacy mode)"
cat /proc/config.gz | gunzip | grep CONFIG_BPF  # BPF config options
```

**Graceful degradation:** kpod-metrics loads BPF programs individually. If one program fails, others continue running. Cgroup-based collectors (disk I/O, filesystem, interface network) work without BPF.

## Metrics Missing for Specific Pods

**Symptom:** Some pods show metrics, others don't.

**Check pod discovery:**
```bash
# Verify the pod is on the same node as kpod-metrics
kubectl get pod <pod-name> -o wide
kubectl get pods -l app.kubernetes.io/name=kpod-metrics -o wide

# Check discovered pods count
curl -s http://localhost:9090/actuator/prometheus | grep kpod_discovery_pods_total
```

**Common causes:**

| Cause | Fix |
|-------|-----|
| Pod on different node | kpod-metrics is a DaemonSet; check node assignment |
| Namespace excluded | Check `kpod.filter.exclude-namespaces` (default: `kube-system, kube-public`) |
| Cgroup ID not resolved | Pod may use non-standard cgroup driver; check logs for "no cgroup IDs resolved" |
| Pod too new | Cgroup ID resolution happens on next collection cycle (up to `pollInterval`) |
| Pod deleted recently | Metrics are kept for 5 seconds in grace cache after deletion |

**Check cgroup resolution:**
```bash
kubectl logs ds/kpod-metrics | grep "cgroup" | tail -20
```

## High Collection Latency

**Symptom:** `kpod_collection_cycle_duration_seconds` is consistently high or `/actuator/health` shows collection as DOWN.

**Check cycle duration:**
```bash
curl -s http://localhost:9090/actuator/prometheus | grep kpod_collection_cycle_duration
```

**Common causes:**

| Cause | Fix |
|-------|-----|
| Too many pods on node | Reduce `pollInterval` or switch to `minimal` profile |
| Comprehensive profile enabled | Use `standard` profile unless syscall/IRQ metrics are needed |
| BPF map iteration slow | Maps auto-evict at 10,240 entries; check `kpod_bpf_map_entries` |
| CPU throttled | Increase CPU limit in Helm values |

**Per-collector breakdown:**
```bash
curl -s http://localhost:9090/actuator/prometheus | grep kpod_collector_duration_seconds
```

## Collector Errors

**Symptom:** `kpod_collector_errors_total` is incrementing.

**Check which collector is failing:**
```bash
curl -s http://localhost:9090/actuator/prometheus | grep kpod_collector_errors_total
kubectl logs ds/kpod-metrics | grep "Collector.*failed"
```

**Common causes:**

| Collector | Cause | Fix |
|-----------|-------|-----|
| cpu, network | BPF program not loaded | Check BPF health |
| diskIO | Cgroup v2 not mounted | Verify `/sys/fs/cgroup/io.stat` exists |
| filesystem | `/proc` not mounted | Check `hostPath` volume mount |
| syscall | Too many tracked syscalls | Reduce `kpod.syscall.tracked-syscalls` list |

## Health Check Failures

**`/actuator/health` returns DOWN:**

```bash
kubectl exec ds/kpod-metrics -- curl -s http://localhost:9090/actuator/health
```

| Component | DOWN Reason | Fix |
|-----------|-------------|-----|
| `bpf` | BPF programs failed to load | See "BPF Programs Failed to Load" |
| `collection` | No collection cycle in 3x poll interval | Check logs for errors, verify CPU/memory limits |

## Kernel Compatibility

| Kernel | BPF Mode | Features |
|--------|----------|----------|
| < 4.18 | Not supported | - |
| 4.18 - 5.1 | Legacy (no BTF) | All collectors work; no CO-RE relocations |
| 5.2+ with BTF | CO-RE | Full support with BTF-based struct relocation |
| 5.2+ without BTF | Legacy fallback | Auto-detected; works but no CO-RE benefits |

**Check which mode is active:**
```bash
kubectl logs ds/kpod-metrics | grep -E "CO-RE|legacy|BTF"
```

## Resource Sizing Guide

| Profile | Pods/Node | CPU Request | Memory Request |
|---------|-----------|-------------|----------------|
| minimal | < 50 | 100m | 128Mi |
| standard | < 100 | 150m | 256Mi |
| comprehensive | < 100 | 250m | 384Mi |
| comprehensive | 100+ | 500m | 512Mi |

These are starting points. Monitor `kpod_collection_cycle_duration_seconds` and adjust based on actual usage.
