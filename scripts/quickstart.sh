#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="kpod-demo"
NAMESPACE="kpod-metrics"
IMAGE="ghcr.io/pjs7678/kpod-metrics:latest"
LOCAL_PORT=9090

# --- Cleanup mode ---
if [[ "${1:-}" == "--cleanup" ]]; then
  echo "Tearing down kpod-demo cluster..."
  kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
  echo "Done."
  exit 0
fi

# --- Check prerequisites ---
for cmd in kind kubectl helm docker; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: $cmd is required but not installed."
    exit 1
  fi
done

echo "==> Creating kind cluster '$CLUSTER_NAME'..."
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  echo "    Cluster already exists, reusing."
else
  kind create cluster --name "$CLUSTER_NAME" --wait 60s
fi

echo "==> Pulling and loading image into kind..."
docker pull "$IMAGE"
kind load docker-image "$IMAGE" --name "$CLUSTER_NAME"

echo "==> Installing kpod-metrics via Helm..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHART_DIR="$(cd "$SCRIPT_DIR/../helm/kpod-metrics" && pwd)"

helm upgrade --install kpod-metrics "$CHART_DIR" \
  --namespace "$NAMESPACE" --create-namespace \
  --set image.pullPolicy=Never \
  --set securityContext.privileged=true \
  --set securityContext.allowPrivilegeEscalation=true \
  --set networkPolicy.enabled=false \
  --wait --timeout 120s

echo "==> Waiting for DaemonSet rollout..."
kubectl -n "$NAMESPACE" rollout status daemonset/kpod-metrics --timeout=120s

echo ""
echo "==> kpod-metrics is running!"
echo ""
echo "    Port-forwarding to localhost:${LOCAL_PORT}..."
echo "    Metrics:  http://localhost:${LOCAL_PORT}/actuator/prometheus"
echo "    Health:   http://localhost:${LOCAL_PORT}/actuator/health"
echo "    Topology: http://localhost:${LOCAL_PORT}/actuator/kpodTopology"
echo ""
echo "    Press Ctrl+C to stop port-forwarding."
echo "    Run '$0 --cleanup' to delete the cluster."
echo ""

kubectl -n "$NAMESPACE" port-forward ds/kpod-metrics "${LOCAL_PORT}:9090"
