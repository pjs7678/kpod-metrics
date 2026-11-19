#!/usr/bin/env bash
# verify.sh — checks kpod-metrics against the ground truth of e2e/dogfood/workloads.yaml.
#
# Needs a real (non-nested) cluster running kpod-metrics with the comprehensive profile and the
# dogfood workloads for at least ~3 collection cycles. Every check below is a regression test for
# a bug found while dogfooding; the comment names what it guards.
#
# Usage: e2e/dogfood/verify.sh [kpod-namespace]   (default: kpod-system)
set -uo pipefail
NS=${1:-kpod-system}
DOG=kpod-dogfood
fails=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fails=$((fails + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

POD=$(kubectl -n "$NS" get pod -l app.kubernetes.io/name=kpod-metrics -o jsonpath='{.items[0].metadata.name}')
[ -n "$POD" ] || { echo "no kpod-metrics pod in $NS"; exit 1; }
SCRAPE=$(mktemp); trap 'rm -f "$SCRAPE"' EXIT
kubectl get --raw "/api/v1/namespaces/$NS/pods/$POD:9090/proxy/actuator/prometheus" > "$SCRAPE"
val() { awk -v m="$1" '$0 ~ "^"m"[{ ]" {print $NF; exit}' "$SCRAPE"; }
has() { grep -qE "$1" "$SCRAPE"; }
count() { grep -cE "$1" "$SCRAPE"; }
# histogram_quantile over one pod's buckets (sums across other labels)
quantile() { # metric pod-prefix q
  python3 - "$SCRAPE" "$1" "$2" "$3" <<'PY'
import sys, re, collections
path, metric, pod, q = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
b = collections.Counter()
for l in open(path):
    m = re.match(rf'{metric}_bucket\{{(.*)\}} (\S+)', l)
    if m and re.search(rf'pod="{pod}', m[1]):
        le = re.search(r'le="([^"]+)"', m[1])[1]
        b[float('inf') if le == '+Inf' else float(le)] += float(m[2])
if not b: print('nan'); sys.exit()
e = sorted(b.items()); tot = e[-1][1]; r = q * tot; prev = (0.0, 0.0)
for le, c in e:
    if c >= r:
        if le == float('inf'): print(e[-2][0]); break
        lo, lc = prev; print(lo + (le - lo) * ((r - lc) / (c - lc) if c > lc else 0)); break
    prev = (le, c)
PY
}
gt() { python3 -c "import sys; sys.exit(0 if float('$1') > float('$2') else 1)" 2>/dev/null; }
lt() { python3 -c "import sys; sys.exit(0 if float('$1') < float('$2') else 1)" 2>/dev/null; }

echo "== agent health ($POD)"
check "no restarts (OOMKill: JVM sized from host RAM, heap+BPF maps over limit)" \
  '[ "$(kubectl -n "$NS" get pod "$POD" -o jsonpath="{.status.containerStatuses[0].restartCount}")" = 0 ]'
check "all BPF programs loaded (perf_event_paranoid, span_event layout, stack size)" '[ "$(val kpod_bpf_programs_failed)" = "0.0" ]'
check "pods discovered (NetworkPolicy API port, gauge on boxed Int)" 'gt "$(val kpod_discovery_pods)" 0'
check "no collection timeouts (API calls on the collection path)" '[ "$(val kpod_collection_timeouts_total)" = "0.0" ]'
check "peer resolver populated (informers, services RBAC)" 'gt "$(val kpod_peer_resolver_entries)" 0'

echo "== BPF data reaches pods (cgroup id resolution, batch drain out_batch)"
for m in kpod_cpu_context_switches_total kpod_cpu_runqueue_latency_seconds_bucket kpod_net_tcp_rtt_seconds_bucket \
         kpod_syscall_latency_seconds_bucket kpod_disk_io_latency_seconds_bucket; do
  check "$m has $DOG series" "has '^$m\\{.*namespace=\"$DOG\"'"
done
check "syscall filter populated (trk_syscalls was never written)" "has '^kpod_syscall_latency_seconds_count\\{.*pod=\"mem-pressure'"

echo "== attribution (softirq events used the interrupted task's cgroup)"
check "no TCP RTT on CPU-only pods" "! has '^kpod_net_tcp_rtt_seconds_count\\{.*pod=\"(cpu-hog|cpu-throttled)'"
check "no peer RTT on CPU-only pods" "! has '^kpod_net_tcp_peer_rtt_seconds_count\\{.*pod=\"(cpu-hog|cpu-throttled)'"
check "client has TCP RTT" "has '^kpod_net_tcp_rtt_seconds_count\\{.*pod=\"client'"

echo "== latency above the old 67 ms ceiling (150 ms netem on client egress)"
p=$(quantile kpod_net_tcp_rtt_seconds web 0.5);  check "web TCP RTT p50 > 100 ms (got ${p}s)" 'gt "$p" 0.1'
c=$(awk '/^kpod_net_tcp_peer_rtt_seconds_count\{.*pod="client.*remote_service="web"/ {s+=$NF} END {print s+0}' "$SCRAPE")
s=$(awk '/^kpod_net_tcp_peer_rtt_seconds_sum\{.*pod="client.*remote_service="web"/ {s+=$NF} END {print s+0}' "$SCRAPE")
m=$(python3 -c "print($s/$c if $c else 'nan')")
check "client->web peer RTT mean 120..300 ms, not 8x (got ${m}s)" 'gt "$m" 0.12 && lt "$m" 0.3'

echo "== cardinality bounded (remote_ip garbage + ephemeral remote_port)"
n=$(count "^kpod_net_tcp_peer_rtt_seconds_count\\{.*namespace=\"$DOG\"")
check "peer RTT series for $DOG < 20 (got $n)" '[ "$n" -lt 20 ]'
check "no peer series keyed by ephemeral server-side ports" \
  "! grep -E '^kpod_net_tcp_peer_connections_total\\{.*direction=\"server\"' \"$SCRAPE\" | grep -vq 'remote_port=\"0\"'"

echo "== HTTP status codes (payload clamp read 0 bytes; recv re-read an advanced iterator)"
http() { awk -v pod="$1" -v st="$2" '$0 ~ "^kpod_http_requests_total\\{" && $0 ~ "pod=\""pod && $0 ~ "status_code=\""st"\"" {s+=$NF} END {print s+0}' "$SCRAPE"; }
for side in client web; do
  req=$(http "$side" 0); ok=$(http "$side" 200); err=$(http "$side" 503)
  check "$side: every request matched to a response ($ok+$err of $req)" '[ "$req" != 0 ] && gt "$(python3 -c "print(($ok+$err)/$req)")" 0.9'
  check "$side: 503 share near the workload's 25% (got $err/$req)" 'gt "$(python3 -c "print($err/$req if $req else 0)")" 0.15 && lt "$(python3 -c "print($err/$req if $req else 1)")" 0.35'
done

echo "== cgroup signals"
t=$(awk '/^kpod_cpu_throttled_periods_total\{.*pod="cpu-throttled/ {print $NF; exit}' "$SCRAPE")
a=$(awk '/^kpod_cpu_periods_total\{.*pod="cpu-throttled/ {print $NF; exit}' "$SCRAPE")
check "cpu-throttled is throttled in >50% of periods" 'gt "$(python3 -c "print($t/$a if $a else 0)")" 0.5'
check "label tag keys consistent (meters were rejected per pod)" \
  '! kubectl -n "$NS" logs "$POD" | grep -q "Prometheus requires that all meters with the same name have the same set of tag keys"'

echo
if [ "$fails" -eq 0 ]; then echo "all checks passed"; else echo "$fails check(s) failed"; exit 1; fi
