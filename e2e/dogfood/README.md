# Dogfood harness

Runs kpod-metrics against workloads with known ground truth on a real cluster and checks the
exported metrics. `minikube`/`kind` hide the host cgroup tree (Docker-in-Docker), so use a real
node — e.g. a colima VM with k3s (`colima start --kubernetes`).

```bash
# Monitoring stack + kpod-metrics (comprehensive profile exercises every BPF program)
helm upgrade --install kps prometheus-community/kube-prometheus-stack -n monitoring --create-namespace \
  --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
  --set prometheus.prometheusSpec.ruleSelectorNilUsesHelmValues=false
helm upgrade --install kpod helm/kpod-metrics -n kpod-system --create-namespace \
  --set config.profile=comprehensive --set serviceMonitor.enabled=true --set prometheusRule.enabled=true
# If the API server endpoint is not on 443/6443:
#   --set networkPolicy.apiServerPorts='{443,<port>}'   (kubectl get endpointslices -l kubernetes.io/service-name=kubernetes)

kubectl apply -f e2e/dogfood/workloads.yaml
# wait ~3 collection cycles, then:
e2e/dogfood/verify.sh
```

| Workload | Ground truth | Signal checked |
|---|---|---|
| `cpu-throttled` | 2 spinners under a 100m quota | throttled periods > 50% |
| `cpu-hog` | 12 spinners, no network | run-queue data; **no** TCP metrics (attribution) |
| `mem-pressure` | ~100 MiB of a 128 MiB limit | memory, syscall (filter populated) |
| `disk-writer` | 4 × O_DIRECT writers, in place | disk IO latency |
| `web` / `client` | HTTP with 150 ms netem on client egress | TCP RTT > 67 ms (old ceiling), peer RTT ≈ 150 ms, bounded peer cardinality |

On Ubuntu/Debian nodes with `kernel.perf_event_paranoid` > 2 the non-privileged chart cannot attach
kprobes/tracepoints; the agent logs the fix (`sysctl kernel.perf_event_paranoid=2` or
`securityContext.privileged=true`).

Known gaps found here and not yet fixed: HTTP response status codes are not captured
(`status_code="0"` only); `tcpdrop` (kfree_skb, softirq) is still attributed to the interrupted
task; the BPF `*_stats` maps are never written, so `kpod_bpf_map_entries` stays 0.
