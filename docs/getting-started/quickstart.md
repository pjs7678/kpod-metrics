# Quick Start

## Deploy with Helm

Add the Helm repository and install:

```bash
helm repo add kpod-metrics https://pjs7678.github.io/kpod-metrics
helm repo update
helm install kpod-metrics kpod-metrics/kpod-metrics \
  --namespace kpod-metrics --create-namespace
```

Or install from a local clone:

```bash
git clone https://github.com/pjs7678/kpod-metrics.git
helm install kpod-metrics ./kpod-metrics/helm/kpod-metrics \
  --namespace kpod-metrics --create-namespace
```

## Try It Locally (kind)

Spin up a local demo cluster with a single command:

```bash
git clone https://github.com/pjs7678/kpod-metrics.git
cd kpod-metrics
./scripts/quickstart.sh
```

This creates a `kind` cluster, installs kpod-metrics, and sets up port-forwarding so you can immediately view metrics. Run `./scripts/quickstart.sh --cleanup` to tear it down.

## Verify

### Check pods are running

```bash
kubectl -n kpod-metrics get pods
```

You should see a pod per node with `Running` status.

### Check health

```bash
kubectl -n kpod-metrics port-forward ds/kpod-metrics 9090:9090
curl http://localhost:9090/actuator/health | python3 -m json.tool
```

### Check metrics

```bash
curl http://localhost:9090/actuator/prometheus | grep kpod
```

You should see metrics like `kpod_cpu_context_switches_total`, `kpod_net_tcp_bytes_sent_total`, etc.

### View topology

```bash
curl http://localhost:9090/actuator/kpodTopology | python3 -m json.tool
```

## Next Steps

- [Configure collection profiles](profiles.md) to control which metrics are collected
- [Set up Grafana dashboards](../features/grafana.md) for visualization
- [Enable Prometheus Operator](../features/prometheus-operator.md) integration
- [Configure OTLP export](../features/otlp.md) for OpenTelemetry backends
