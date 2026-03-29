# Testing

## Unit Tests

```bash
./gradlew test  # 293 tests
```

## Integration Test (minikube)

```bash
# Full test: minikube start, Docker build, Helm deploy, stress test, cleanup
./scripts/test-local-k8s.sh

# Reuse existing minikube and skip Docker build
./scripts/test-local-k8s.sh --skip-minikube --skip-build

# Cleanup only
./scripts/test-local-k8s.sh --teardown
```

The integration test validates: health endpoint, Prometheus metrics, cgroup collector output, pod stability under stress (zero restarts, <5s scrape latency, <10% error rate).

## E2E Test (Targeted Workloads)

Deploys deterministic workload pods that generate specific kernel events, then asserts that kpod-metrics captures them as Prometheus metrics with correct pod labels.

```bash
# Full run: build, deploy, test, cleanup
./e2e/e2e-test.sh --cleanup

# Skip build, use existing image
./e2e/e2e-test.sh --skip-build --cleanup

# Test against an already-running deployment
./e2e/e2e-test.sh --skip-build --skip-deploy
```

### Flags

| Flag | Description |
|------|-------------|
| `--skip-build` | Skip Docker image build |
| `--skip-deploy` | Skip helm install |
| `--cleanup` | Full teardown after test |
| `--wait=N` | Override metrics collection wait time (seconds) |
| `--port=N` | Reuse an existing port-forward |

### Workloads

| Pod | Kernel Activity | Metrics Verified |
|-----|----------------|-----------------|
| `e2e-cpu-worker` | 4 busy-loop forks, 100m CPU limit | `kpod_cpu_context_switches_total` |
| `e2e-net-server/client` | TCP connect/send loop | `kpod_net_tcp_connections_total`, `kpod_net_iface_rx_bytes_total` |
| `e2e-syscall-worker` | Tight `cat /proc/self/status` loop | `kpod_syscall_count_total` |
| `e2e-mem-worker` | `dd` 10MB allocations | `kpod_fs_usage_bytes` |

!!! note
    eBPF-based assertions are **warn-only** (BPF programs may not load on minikube). Cgroup-based assertions are required to pass.
