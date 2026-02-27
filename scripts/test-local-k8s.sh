#!/usr/bin/env bash
# test-local-k8s.sh — Functional + stress testing for kpod-metrics on local minikube.
#
# Usage:
#   ./scripts/test-local-k8s.sh [OPTIONS]
#
# Options:
#   --skip-build        Skip Docker image build
#   --skip-minikube     Skip minikube start (assumes already running)
#   --teardown          Only run cleanup/teardown, then exit
#   --stress-duration=N Stress monitoring duration in seconds (default: 180)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Defaults ---
SKIP_BUILD=false
SKIP_MINIKUBE=false
TEARDOWN_ONLY=false
STRESS_DURATION=180
RELEASE_NAME="kpod-metrics"
NAMESPACE="default"
IMAGE_NAME="kpod-metrics"
IMAGE_TAG="local-test"
TIMEOUT_READY=120   # seconds to wait for pod ready

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

check_pass() {
    pass "$1"
}

check_fail() {
    fail "$1"
    FAILURES=$((FAILURES + 1))
}

check_warn() {
    warn "$1"
    WARNINGS=$((WARNINGS + 1))
}

# ============================================================
# Phase 0: Parse flags
# ============================================================
for arg in "$@"; do
    case $arg in
        --skip-build)       SKIP_BUILD=true ;;
        --skip-minikube)    SKIP_MINIKUBE=true ;;
        --teardown)         TEARDOWN_ONLY=true ;;
        --stress-duration=*)STRESS_DURATION="${arg#*=}" ;;
        *)                  echo "Unknown flag: $arg"; exit 1 ;;
    esac
done

# ============================================================
# Phase 7: Cleanup (also used for --teardown)
# ============================================================
cleanup() {
    info "=== Phase 7: Cleanup ==="
    # Kill port-forward if running (suppress termination message)
    if [ -n "${PORT_FWD_PID:-}" ]; then
        kill "$PORT_FWD_PID" 2>/dev/null && wait "$PORT_FWD_PID" 2>/dev/null || true
    fi
    kubectl delete -f "$SCRIPT_DIR/stress-workload.yaml" --ignore-not-found 2>/dev/null || true
    helm uninstall "$RELEASE_NAME" -n "$NAMESPACE" 2>/dev/null || true
    info "Cleanup complete."
}

if $TEARDOWN_ONLY; then
    cleanup
    info "Teardown complete. Minikube left running (stop manually with: minikube stop)"
    exit 0
fi

# ============================================================
# Phase 1: Start minikube
# ============================================================
if ! $SKIP_MINIKUBE; then
    info "=== Phase 1: Start minikube ==="
    if minikube status --format='{{.Host}}' 2>/dev/null | grep -q "Running"; then
        info "Minikube already running, skipping start."
    else
        info "Starting minikube (4 CPUs, 4GB RAM, docker driver)..."
        minikube start --cpus=4 --memory=4096 --driver=docker
    fi
else
    info "=== Phase 1: Skipping minikube start ==="
fi

# Verify minikube is accessible
if ! kubectl cluster-info &>/dev/null; then
    fail "Cannot reach Kubernetes cluster. Is minikube running?"
    exit 1
fi
info "Kubernetes cluster is accessible."

# ============================================================
# Phase 2: Build Docker image inside minikube
# ============================================================
if ! $SKIP_BUILD; then
    info "=== Phase 2: Build Docker image ==="
    info "Configuring Docker to use minikube's daemon..."
    eval $(minikube docker-env)

    # The Dockerfile expects both kpod-metrics/ and kotlin-ebpf-dsl/ in the build context.
    # Create a temp context directory with both repos.
    DSL_DIR="${DSL_DIR:-$(cd "$PROJECT_DIR/../../kotlin-ebpf-dsl" 2>/dev/null && pwd)}"
    if [ ! -d "$DSL_DIR" ]; then
        fail "kotlin-ebpf-dsl not found. Set DSL_DIR=/path/to/kotlin-ebpf-dsl"
        exit 1
    fi

    BUILD_CTX=$(mktemp -d)
    trap "rm -rf $BUILD_CTX" EXIT
    info "Creating build context at $BUILD_CTX..."
    cp -a "$PROJECT_DIR" "$BUILD_CTX/kpod-metrics"
    cp -a "$DSL_DIR" "$BUILD_CTX/kotlin-ebpf-dsl"

    info "Building $IMAGE_NAME:$IMAGE_TAG inside minikube..."
    docker build -f "$BUILD_CTX/kpod-metrics/Dockerfile" -t "$IMAGE_NAME:$IMAGE_TAG" "$BUILD_CTX"
    rm -rf "$BUILD_CTX"

    info "Docker image built successfully."
else
    info "=== Phase 2: Skipping Docker build ==="
fi

# ============================================================
# Phase 3: Helm deploy
# ============================================================
info "=== Phase 3: Helm deploy ==="

# Uninstall previous release if it exists
helm uninstall "$RELEASE_NAME" -n "$NAMESPACE" 2>/dev/null || true
sleep 2

info "Installing Helm chart..."
helm install "$RELEASE_NAME" "$PROJECT_DIR/helm/kpod-metrics" \
    -n "$NAMESPACE" \
    --set image.repository="$IMAGE_NAME" \
    --set image.tag="$IMAGE_TAG" \
    --set image.pullPolicy=Never \
    --set securityContext.privileged=true \
    --set resources.limits.memory=512Mi \
    --set resources.requests.memory=256Mi

info "Waiting for pod to become Ready (up to ${TIMEOUT_READY}s)..."
POD_NAME=""
WAITED=0
while [ $WAITED -lt $TIMEOUT_READY ]; do
    POD_NAME=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=kpod-metrics" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    if [ -n "$POD_NAME" ]; then
        PHASE=$(kubectl get pod "$POD_NAME" -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || true)
        READY=$(kubectl get pod "$POD_NAME" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
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
    check_fail "Pod did not become Ready within ${TIMEOUT_READY}s"
    info "Pod status:"
    kubectl describe pod "$POD_NAME" -n "$NAMESPACE" 2>/dev/null | tail -30
    info "Pod logs:"
    kubectl logs "$POD_NAME" -n "$NAMESPACE" --tail=50 2>/dev/null || true
    exit 1
fi
check_pass "Pod $POD_NAME is Running and Ready (${WAITED}s)"

# ============================================================
# Phase 4: Functional tests
# ============================================================
info "=== Phase 4: Functional tests ==="

# Set up port-forward for reliable access (avoids creating temp pods per request)
LOCAL_PORT=19090
info "Starting port-forward to $POD_NAME:9090 on localhost:$LOCAL_PORT..."
kubectl port-forward "$POD_NAME" -n "$NAMESPACE" ${LOCAL_PORT}:9090 &>/dev/null &
PORT_FWD_PID=$!
sleep 3

# Verify port-forward is working
if ! kill -0 $PORT_FWD_PID 2>/dev/null; then
    check_fail "Port-forward failed to start"
    exit 1
fi
info "Port-forward active (PID: $PORT_FWD_PID)"

# Helper: curl via port-forward
local_curl() {
    curl -s -m 10 "$@" 2>/dev/null
}

# Ensure port-forward is cleaned up on exit
cleanup_port_forward() {
    kill $PORT_FWD_PID 2>/dev/null || true
}
trap 'cleanup_port_forward' EXIT

# Test 1: Health endpoint
info "Testing /actuator/health..."
HEALTH_RESPONSE=$(local_curl "http://localhost:${LOCAL_PORT}/actuator/health" || true)
if grep -q '"status":"UP"' <<< "$HEALTH_RESPONSE"; then
    check_pass "/actuator/health returns UP"
else
    check_fail "/actuator/health did not return UP. Response: $HEALTH_RESPONSE"
fi

# Test 2: Prometheus endpoint returns data
info "Testing /actuator/prometheus..."
PROM_RESPONSE=$(local_curl "http://localhost:${LOCAL_PORT}/actuator/prometheus" || true)
if [ -n "$PROM_RESPONSE" ] && grep -q "^# HELP\|^# TYPE" <<< "$PROM_RESPONSE"; then
    check_pass "/actuator/prometheus returns valid metrics data"
else
    check_fail "/actuator/prometheus did not return valid data"
fi

# Give collectors time to produce initial metrics
info "Waiting 30s for metric collectors to gather data..."
sleep 30

# Re-scrape after waiting
PROM_RESPONSE=$(local_curl "http://localhost:${LOCAL_PORT}/actuator/prometheus" || true)

# Test 3: Cgroup filesystem metrics
if grep -q "kpod_fs_" <<< "$PROM_RESPONSE"; then
    check_pass "kpod_fs_* gauges present"
    # Verify pod labels on filesystem metrics
    if grep "kpod_fs_" <<< "$PROM_RESPONSE" | grep -q "pod="; then
        check_pass "kpod_fs_* metrics have pod labels"
    else
        check_fail "kpod_fs_* metrics missing pod labels"
    fi
else
    check_fail "kpod_fs_* gauges not found"
fi

# Test 4: Cgroup network interface metrics
if grep -q "kpod_net_iface_" <<< "$PROM_RESPONSE"; then
    check_pass "kpod_net_iface_* counters present"
else
    check_fail "kpod_net_iface_* counters not found"
fi

# Test 5: Cgroup disk I/O metrics
if grep -q "kpod_disk_" <<< "$PROM_RESPONSE"; then
    check_pass "kpod_disk_* counters present"
else
    check_fail "kpod_disk_* counters not found"
fi

# Test 6: eBPF metrics (warn-only — may not work on minikube)
for metric in kpod_cpu_ kpod_net_tcp_ kpod_mem_ kpod_syscall_; do
    if grep -q "$metric" <<< "$PROM_RESPONSE"; then
        check_pass "${metric}* metrics present (eBPF)"
    else
        check_warn "${metric}* metrics not found (eBPF may not be supported on minikube)"
    fi
done

# Test 7: No FATAL errors in logs
POD_LOGS=$(kubectl logs "$POD_NAME" -n "$NAMESPACE" 2>/dev/null || true)
if grep -qi "FATAL\|Exception.*FATAL" <<< "$POD_LOGS"; then
    check_fail "FATAL errors found in pod logs"
    grep -i "FATAL" <<< "$POD_LOGS" | head -5
else
    check_pass "No FATAL errors in pod logs"
fi

info "--- Functional test summary: $FAILURES failures, $WARNINGS warnings ---"

if [ $FAILURES -gt 0 ]; then
    fail "Functional tests failed. Aborting before stress tests."
    cleanup
    exit 1
fi

# Optional: Run E2E targeted workload tests
E2E_SCRIPT="$PROJECT_DIR/e2e/e2e-test.sh"
if [ -x "$E2E_SCRIPT" ]; then
    info "Running E2E targeted workload tests..."
    if "$E2E_SCRIPT" --skip-build --skip-deploy --wait=25; then
        check_pass "E2E targeted workload tests passed"
    else
        check_warn "E2E targeted workload tests failed (non-blocking)"
    fi
fi

# ============================================================
# Phase 5: Deploy stress workloads
# ============================================================
info "=== Phase 5: Deploy stress workloads ==="
kubectl apply -f "$SCRIPT_DIR/stress-workload.yaml"

info "Waiting 30s for stress pods to start..."
sleep 30

for pod in stress-cpu-mem stress-disk-io stress-net-server stress-net-client stress-mixed; do
    PHASE=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    if [ "$PHASE" = "Running" ]; then
        info "  $pod: Running"
    elif [ "$PHASE" = "Succeeded" ]; then
        info "  $pod: Succeeded (already completed)"
    else
        warn "  $pod: $PHASE (may still be starting)"
    fi
done

# ============================================================
# Phase 6: Stress monitoring
# ============================================================
info "=== Phase 6: Stress monitoring (${STRESS_DURATION}s) ==="

SCRAPE_ERRORS=0
SCRAPE_TOTAL=0
MAX_LATENCY=0
INTERVAL=15
ELAPSED=0

while [ $ELAPSED -lt $STRESS_DURATION ]; do
    SCRAPE_TOTAL=$((SCRAPE_TOTAL + 1))
    START_MS=$(date +%s%N | cut -b1-13)

    SCRAPE_RESULT=$(local_curl "http://localhost:${LOCAL_PORT}/actuator/prometheus" || true)

    END_MS=$(date +%s%N | cut -b1-13)
    LATENCY_MS=$((END_MS - START_MS))

    if [ -z "$SCRAPE_RESULT" ] || ! grep -q "^# " <<< "$SCRAPE_RESULT"; then
        SCRAPE_ERRORS=$((SCRAPE_ERRORS + 1))
        warn "Scrape #$SCRAPE_TOTAL failed (latency: ${LATENCY_MS}ms)"
    else
        # Count distinct metric families
        METRIC_COUNT=$(grep -c "^# TYPE" <<< "$SCRAPE_RESULT" || true)
        info "Scrape #$SCRAPE_TOTAL OK — ${LATENCY_MS}ms — $METRIC_COUNT metric families"
    fi

    if [ $LATENCY_MS -gt $MAX_LATENCY ]; then
        MAX_LATENCY=$LATENCY_MS
    fi

    # Check JVM heap via metrics (sum all heap areas, handle scientific notation)
    JVM_HEAP_TOTAL=$(grep -v '^#' <<< "$SCRAPE_RESULT" | grep 'jvm_memory_used_bytes{.*area="heap"' | awk '{sum += $NF} END {if (NR>0) printf "%.0f", sum}' || true)
    if [ -n "$JVM_HEAP_TOTAL" ] && [ "$JVM_HEAP_TOTAL" != "0" ]; then
        JVM_HEAP_MB=$(awk "BEGIN {printf \"%.1f\", $JVM_HEAP_TOTAL/1048576}")
        info "  JVM heap: ${JVM_HEAP_MB}MB"
    fi

    # Check process CPU (exclude comment lines)
    PROCESS_CPU=$(grep -v '^#' <<< "$SCRAPE_RESULT" | grep 'process_cpu_usage' | head -1 | awk '{print $NF}' || true)
    if [ -n "$PROCESS_CPU" ]; then
        CPU_PCT=$(awk "BEGIN {printf \"%.1f\", $PROCESS_CPU*100}")
        info "  Process CPU: ${CPU_PCT}%"
    fi

    sleep $INTERVAL
    ELAPSED=$((ELAPSED + INTERVAL))
done

# --- Stress pass/fail criteria ---
info "=== Stress test results ==="

# Check kpod-metrics pod is still Running
PHASE=$(kubectl get pod "$POD_NAME" -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || true)
if [ "$PHASE" = "Running" ]; then
    check_pass "kpod-metrics pod still Running after stress"
else
    check_fail "kpod-metrics pod is $PHASE (expected Running)"
fi

# Check zero restarts
RESTARTS=$(kubectl get pod "$POD_NAME" -n "$NAMESPACE" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || true)
if [ "${RESTARTS:-0}" -eq 0 ]; then
    check_pass "Zero restarts (no OOM kills)"
else
    check_fail "Pod restarted $RESTARTS time(s) — possible OOM"
fi

# Scrape latency check
if [ $MAX_LATENCY -lt 5000 ]; then
    check_pass "Max scrape latency: ${MAX_LATENCY}ms (< 5000ms)"
else
    check_fail "Max scrape latency: ${MAX_LATENCY}ms (>= 5000ms threshold)"
fi

# Scrape error rate
if [ $SCRAPE_TOTAL -gt 0 ]; then
    ERROR_RATE=$((SCRAPE_ERRORS * 100 / SCRAPE_TOTAL))
    if [ $ERROR_RATE -lt 10 ]; then
        check_pass "Scrape error rate: ${ERROR_RATE}% ($SCRAPE_ERRORS/$SCRAPE_TOTAL) (< 10%)"
    else
        check_fail "Scrape error rate: ${ERROR_RATE}% ($SCRAPE_ERRORS/$SCRAPE_TOTAL) (>= 10%)"
    fi
fi

# ============================================================
# Final summary
# ============================================================
echo ""
info "=========================================="
info "  FINAL RESULTS"
info "=========================================="
info "  Failures:  $FAILURES"
info "  Warnings:  $WARNINGS"
info "=========================================="

if [ $FAILURES -gt 0 ]; then
    fail "TEST SUITE FAILED ($FAILURES failure(s))"
else
    pass "ALL TESTS PASSED ($WARNINGS warning(s))"
fi

# Cleanup
cleanup

exit $FAILURES
