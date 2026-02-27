#!/usr/bin/env bash
# e2e-test.sh — End-to-end test verifying that targeted kernel events
# produce the expected Prometheus metrics in kpod-metrics.
#
# Usage:
#   ./e2e/e2e-test.sh [OPTIONS]
#
# Options:
#   --skip-build    Skip Docker image build (use existing image)
#   --skip-deploy   Skip helm install (use existing deployment)
#   --cleanup       Full teardown after test (helm uninstall + namespace delete)
#   --wait=N        Override wait time in seconds (default: 25)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Defaults ---
SKIP_BUILD=false
SKIP_DEPLOY=false
CLEANUP=false
WAIT_TIME=25
RELEASE_NAME="kpod-metrics"
DEPLOY_NS="default"
E2E_NS="e2e-test"
IMAGE_NAME="kpod-metrics"
IMAGE_TAG="local-test"
TIMEOUT_READY=120
LOCAL_PORT=19090

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }

FAILURES=0
WARNINGS=0
TOTAL=0
RESULTS=()

check_pass() {
    pass "$1"
    TOTAL=$((TOTAL + 1))
    RESULTS+=("PASS: $1")
}

check_fail() {
    fail "$1"
    FAILURES=$((FAILURES + 1))
    TOTAL=$((TOTAL + 1))
    RESULTS+=("FAIL: $1")
}

check_warn() {
    warn "$1"
    WARNINGS=$((WARNINGS + 1))
    TOTAL=$((TOTAL + 1))
    RESULTS+=("WARN: $1")
}

# ============================================================
# Parse flags
# ============================================================
for arg in "$@"; do
    case $arg in
        --skip-build)    SKIP_BUILD=true ;;
        --skip-deploy)   SKIP_DEPLOY=true ;;
        --cleanup)       CLEANUP=true ;;
        --wait=*)        WAIT_TIME="${arg#*=}" ;;
        *)               echo "Unknown flag: $arg"; exit 1 ;;
    esac
done

# ============================================================
# Cleanup handler
# ============================================================
PORT_FWD_PID=""

cleanup() {
    if [ -n "$PORT_FWD_PID" ]; then
        kill "$PORT_FWD_PID" 2>/dev/null && wait "$PORT_FWD_PID" 2>/dev/null || true
    fi
    info "Deleting e2e workloads namespace..."
    kubectl delete namespace "$E2E_NS" --ignore-not-found 2>/dev/null || true
    if $CLEANUP; then
        info "Uninstalling helm release..."
        helm uninstall "$RELEASE_NAME" -n "$DEPLOY_NS" 2>/dev/null || true
    fi
}

trap cleanup EXIT

# ============================================================
# Step 1: Setup — verify minikube, build image, deploy kpod-metrics
# ============================================================
info "=== Step 1: Setup ==="

# Verify minikube / cluster accessible
if ! kubectl cluster-info &>/dev/null; then
    fail "Cannot reach Kubernetes cluster. Is minikube running?"
    exit 1
fi
info "Kubernetes cluster is accessible."

# Create e2e-test namespace
kubectl create namespace "$E2E_NS" --dry-run=client -o yaml | kubectl apply -f - 2>/dev/null
info "Namespace $E2E_NS ready."

# Build Docker image
if ! $SKIP_BUILD; then
    info "Building Docker image inside minikube..."
    eval $(minikube docker-env)

    DSL_DIR="${DSL_DIR:-$(cd "$PROJECT_DIR/../../kotlin-ebpf-dsl" 2>/dev/null && pwd)}"
    if [ ! -d "$DSL_DIR" ]; then
        fail "kotlin-ebpf-dsl not found. Set DSL_DIR=/path/to/kotlin-ebpf-dsl"
        exit 1
    fi

    BUILD_CTX=$(mktemp -d)
    cp -a "$PROJECT_DIR" "$BUILD_CTX/kpod-metrics"
    cp -a "$DSL_DIR" "$BUILD_CTX/kotlin-ebpf-dsl"

    docker build -f "$BUILD_CTX/kpod-metrics/Dockerfile" -t "$IMAGE_NAME:$IMAGE_TAG" "$BUILD_CTX"
    rm -rf "$BUILD_CTX"
    info "Docker image built successfully."
else
    info "Skipping Docker build."
fi

# Deploy kpod-metrics via helm
if ! $SKIP_DEPLOY; then
    info "Deploying kpod-metrics via helm..."
    helm uninstall "$RELEASE_NAME" -n "$DEPLOY_NS" 2>/dev/null || true
    sleep 2

    helm install "$RELEASE_NAME" "$PROJECT_DIR/helm/kpod-metrics" \
        -n "$DEPLOY_NS" \
        --set image.repository="$IMAGE_NAME" \
        --set image.tag="$IMAGE_TAG" \
        --set image.pullPolicy=Never \
        --set securityContext.privileged=true \
        --set config.profile=comprehensive \
        --set config.pollInterval=10000 \
        --set resources.limits.memory=512Mi \
        --set resources.requests.memory=256Mi

    info "Waiting for kpod-metrics pod to become Ready (up to ${TIMEOUT_READY}s)..."
    POD_NAME=""
    WAITED=0
    while [ $WAITED -lt $TIMEOUT_READY ]; do
        POD_NAME=$(kubectl get pods -n "$DEPLOY_NS" -l "app.kubernetes.io/name=kpod-metrics" \
            -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
        if [ -n "$POD_NAME" ]; then
            PHASE=$(kubectl get pod "$POD_NAME" -n "$DEPLOY_NS" \
                -o jsonpath='{.status.phase}' 2>/dev/null || true)
            READY=$(kubectl get pod "$POD_NAME" -n "$DEPLOY_NS" \
                -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
            if [ "$PHASE" = "Running" ] && [ "$READY" = "True" ]; then
                break
            fi
        fi
        sleep 5
        WAITED=$((WAITED + 5))
        echo -n "."
    done
    echo ""

    if [ $WAITED -ge $TIMEOUT_READY ]; then
        fail "kpod-metrics pod did not become Ready within ${TIMEOUT_READY}s"
        kubectl describe pod "$POD_NAME" -n "$DEPLOY_NS" 2>/dev/null | tail -30
        kubectl logs "$POD_NAME" -n "$DEPLOY_NS" --tail=50 2>/dev/null || true
        exit 1
    fi
    info "kpod-metrics pod $POD_NAME is Ready (${WAITED}s)."
else
    info "Skipping helm deploy."
    POD_NAME=$(kubectl get pods -n "$DEPLOY_NS" -l "app.kubernetes.io/name=kpod-metrics" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    if [ -z "$POD_NAME" ]; then
        fail "No kpod-metrics pod found. Run without --skip-deploy."
        exit 1
    fi
    info "Using existing kpod-metrics pod: $POD_NAME"
fi

# ============================================================
# Step 2: Deploy targeted workloads
# ============================================================
info "=== Step 2: Deploy targeted workloads ==="
kubectl apply -f "$SCRIPT_DIR/workloads.yaml"

info "Waiting for e2e workload pods to be Running..."
E2E_PODS="e2e-cpu-worker e2e-net-server e2e-net-client e2e-syscall-worker e2e-mem-worker"
WAITED=0
while [ $WAITED -lt 60 ]; do
    ALL_RUNNING=true
    for pod in $E2E_PODS; do
        PHASE=$(kubectl get pod "$pod" -n "$E2E_NS" -o jsonpath='{.status.phase}' 2>/dev/null || true)
        if [ "$PHASE" != "Running" ]; then
            ALL_RUNNING=false
            break
        fi
    done
    if $ALL_RUNNING; then
        break
    fi
    sleep 5
    WAITED=$((WAITED + 5))
    echo -n "."
done
echo ""

for pod in $E2E_PODS; do
    PHASE=$(kubectl get pod "$pod" -n "$E2E_NS" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    if [ "$PHASE" = "Running" ]; then
        info "  $pod: Running"
    else
        warn "  $pod: $PHASE"
    fi
done

# ============================================================
# Step 3: Wait for metrics collection
# ============================================================
info "=== Step 3: Waiting ${WAIT_TIME}s for BPF maps to populate ==="
sleep "$WAIT_TIME"

# Start port-forward
info "Starting port-forward to $POD_NAME:9090 on localhost:$LOCAL_PORT..."
kubectl port-forward "$POD_NAME" -n "$DEPLOY_NS" ${LOCAL_PORT}:9090 &>/dev/null &
PORT_FWD_PID=$!
sleep 3

if ! kill -0 $PORT_FWD_PID 2>/dev/null; then
    fail "Port-forward failed to start"
    exit 1
fi
info "Port-forward active (PID: $PORT_FWD_PID)"

# Helper: curl via port-forward
local_curl() {
    curl -s -m 10 "$@" 2>/dev/null
}

# ============================================================
# Step 4: Assert metrics
# ============================================================
info "=== Step 4: Assert metrics ==="

PROM_RESPONSE=$(local_curl "http://localhost:${LOCAL_PORT}/actuator/prometheus" || true)
if [ -z "$PROM_RESPONSE" ]; then
    fail "Failed to scrape /actuator/prometheus"
    exit 1
fi
info "Scraped $(echo "$PROM_RESPONSE" | grep -c '^# TYPE' || true) metric families."

# Helper: check metric with pod filter, value > 0. Uses check_fail or check_warn.
assert_metric_gt_zero() {
    local metric_name="$1"
    local pod_filter="$2"
    local description="$3"
    local on_missing="${4:-fail}"  # "fail" or "warn"

    local matches
    matches=$(echo "$PROM_RESPONSE" | grep -v '^#' | grep "$metric_name" | grep "pod=\"$pod_filter\"" || true)

    if [ -z "$matches" ]; then
        if [ "$on_missing" = "warn" ]; then
            check_warn "$description — metric not found (eBPF may not be supported)"
        else
            check_fail "$description — metric not found"
        fi
        return
    fi

    local has_positive=false
    while IFS= read -r line; do
        local value
        value=$(echo "$line" | awk '{print $NF}')
        if [ -n "$value" ] && awk "BEGIN {exit !($value > 0)}" 2>/dev/null; then
            has_positive=true
            break
        fi
    done <<< "$matches"

    if $has_positive; then
        check_pass "$description"
    elif [ "$on_missing" = "warn" ]; then
        check_warn "$description — value is 0 (eBPF may not be supported)"
    else
        check_fail "$description — value is 0"
    fi
}

# Helper: check metric > 0 for pods matching a regex pattern
assert_metric_gt_zero_regex() {
    local metric_name="$1"
    local pod_pattern="$2"
    local description="$3"
    local on_missing="${4:-fail}"

    local matches
    matches=$(echo "$PROM_RESPONSE" | grep -v '^#' | grep "$metric_name" | grep -E "pod=\"${pod_pattern}" || true)

    if [ -z "$matches" ]; then
        if [ "$on_missing" = "warn" ]; then
            check_warn "$description — metric not found (eBPF may not be supported)"
        else
            check_fail "$description — metric not found"
        fi
        return
    fi

    local has_positive=false
    while IFS= read -r line; do
        local value
        value=$(echo "$line" | awk '{print $NF}')
        if [ -n "$value" ] && awk "BEGIN {exit !($value > 0)}" 2>/dev/null; then
            has_positive=true
            break
        fi
    done <<< "$matches"

    if $has_positive; then
        check_pass "$description"
    elif [ "$on_missing" = "warn" ]; then
        check_warn "$description — value is 0 (eBPF may not be supported)"
    else
        check_fail "$description — value is 0"
    fi
}

# --- eBPF metrics (warn-only — BPF programs may not load on minikube) ---
info "Checking eBPF-based metrics (warn-only on minikube)..."

assert_metric_gt_zero \
    "kpod_cpu_context_switches_total" \
    "e2e-cpu-worker" \
    "kpod_cpu_context_switches_total{pod=e2e-cpu-worker} > 0" \
    "warn"

assert_metric_gt_zero_regex \
    "kpod_net_tcp_connections_total" \
    "e2e-net" \
    "kpod_net_tcp_connections_total{pod=~e2e-net.*} > 0" \
    "warn"

assert_metric_gt_zero \
    "kpod_syscall_count_total" \
    "e2e-syscall-worker" \
    "kpod_syscall_count_total{pod=e2e-syscall-worker} > 0" \
    "warn"

# --- Cgroup metrics (must pass) ---
info "Checking cgroup-based metrics..."

FS_MATCHES=$(echo "$PROM_RESPONSE" | grep -v '^#' | grep "kpod_fs_usage_bytes" | grep -E 'pod="e2e-' || true)
if [ -n "$FS_MATCHES" ]; then
    check_pass "kpod_fs_usage_bytes{pod=~e2e-.*} exists"
else
    check_fail "kpod_fs_usage_bytes{pod=~e2e-.*} — metric not found"
fi

assert_metric_gt_zero_regex \
    "kpod_net_iface_rx_bytes_total" \
    "e2e-net" \
    "kpod_net_iface_rx_bytes_total{pod=~e2e-net.*} > 0" \
    "fail"

# ============================================================
# Step 5: Report + cleanup
# ============================================================
info ""
info "=========================================="
info "  E2E TEST RESULTS"
info "=========================================="
PASSED=$((TOTAL - FAILURES - WARNINGS))
for result in "${RESULTS[@]}"; do
    if [[ "$result" == PASS:* ]]; then
        echo -e "  ${GREEN}$result${NC}"
    elif [[ "$result" == WARN:* ]]; then
        echo -e "  ${YELLOW}$result${NC}"
    else
        echo -e "  ${RED}$result${NC}"
    fi
done
info "------------------------------------------"
info "  Total: $TOTAL  Passed: $PASSED  Warnings: $WARNINGS  Failed: $FAILURES"
info "=========================================="

if [ $FAILURES -gt 0 ]; then
    fail "E2E TESTS FAILED ($FAILURES failure(s), $WARNINGS warning(s))"
else
    pass "ALL E2E TESTS PASSED ($WARNINGS warning(s))"
fi

# Cleanup is handled by trap EXIT
exit $FAILURES
