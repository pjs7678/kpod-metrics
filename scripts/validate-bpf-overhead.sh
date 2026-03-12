#!/usr/bin/env bash
# validate-bpf-overhead.sh — Quick BPF overhead check using bpftool
#
# Usage:
#   scripts/validate-bpf-overhead.sh              # snapshot
#   scripts/validate-bpf-overhead.sh --watch 10   # sample every 10s, show delta
#
# Requires: bpftool, jq, root/CAP_BPF

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
pass()  { echo -e "${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }

# Check prerequisites
for cmd in bpftool jq; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd not found. Install it first." >&2
        exit 1
    fi
done

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root (bpftool requires CAP_BPF)." >&2
    exit 1
fi

# Enable run_time tracking if available (kernel 5.1+)
if [ -f /proc/sys/kernel/bpf_stats_enabled ]; then
    if [ "$(cat /proc/sys/kernel/bpf_stats_enabled)" != "1" ]; then
        echo 1 > /proc/sys/kernel/bpf_stats_enabled
        info "Enabled BPF stats (/proc/sys/kernel/bpf_stats_enabled=1)"
    fi
fi

snapshot_progs() {
    bpftool prog show -j 2>/dev/null | jq -c '
        [.[] | select(.name != null and .name != "") |
         {id, name, run_time_ns: (.run_time_ns // 0), run_cnt: (.run_cnt // 0)}]
    '
}

snapshot_maps() {
    bpftool map show -j 2>/dev/null | jq -c '
        [.[] | select(.name != null and .name != "") |
         {id, name, type: .type, max_entries: .max_entries,
          bytes_memlock: (.bytes_memlock // 0)}]
    '
}

print_prog_snapshot() {
    local progs="$1"
    echo ""
    echo "=== BPF Program Stats ==="
    printf "%-30s %12s %15s %12s\n" "PROGRAM" "RUN_COUNT" "CPU_TIME_NS" "AVG_NS/CALL"
    printf "%-30s %12s %15s %12s\n" "-------" "---------" "-----------" "-----------"
    echo "$progs" | jq -r '.[] | [.name, .run_cnt, .run_time_ns,
        (if .run_cnt > 0 then (.run_time_ns / .run_cnt | floor) else 0 end)] |
        @tsv' | while IFS=$'\t' read -r name cnt time avg; do
        printf "%-30s %12s %15s %12s\n" "$name" "$cnt" "$time" "$avg"
    done

    # Total CPU time
    local total_ns
    total_ns=$(echo "$progs" | jq '[.[].run_time_ns] | add // 0')
    local total_ms=$((total_ns / 1000000))
    echo ""
    info "Total BPF CPU time: ${total_ms}ms (${total_ns}ns)"
}

print_map_snapshot() {
    local maps="$1"
    echo ""
    echo "=== BPF Map Memory ==="
    printf "%-30s %-22s %12s %15s\n" "MAP" "TYPE" "MAX_ENTRIES" "MEMORY_BYTES"
    printf "%-30s %-22s %12s %15s\n" "---" "----" "-----------" "------------"
    echo "$maps" | jq -r '.[] | [.name, .type, .max_entries, .bytes_memlock] | @tsv' |
        sort -t$'\t' -k4 -rn | while IFS=$'\t' read -r name type maxe mem; do
        printf "%-30s %-22s %12s %15s\n" "$name" "$type" "$maxe" "$mem"
    done

    # Total memory
    local total_bytes
    total_bytes=$(echo "$maps" | jq '[.[].bytes_memlock] | add // 0')
    local total_kb=$((total_bytes / 1024))
    local total_mb=$((total_bytes / 1048576))
    echo ""
    info "Total BPF map memory: ${total_kb}KB (${total_mb}MB)"

    # Threshold check
    if [ "$total_mb" -gt 100 ]; then
        fail "BPF map memory exceeds 100MB threshold"
    elif [ "$total_mb" -gt 50 ]; then
        warn "BPF map memory above 50MB"
    else
        pass "BPF map memory within limits (${total_mb}MB)"
    fi
}

print_delta() {
    local before="$1" after="$2" seconds="$3"
    echo ""
    echo "=== BPF Program Delta (${seconds}s interval) ==="
    printf "%-30s %12s %15s %10s\n" "PROGRAM" "CALLS/s" "CPU_NS/s" "AVG_NS"
    printf "%-30s %12s %15s %10s\n" "-------" "-------" "--------" "------"

    # Join before and after by name, compute delta
    jq -n --argjson b "$before" --argjson a "$after" --arg s "$seconds" '
        ($b | map({(.name): .}) | add) as $bm |
        ($a | map({(.name): .}) | add) as $am |
        ($s | tonumber) as $sec |
        [$am | to_entries[] | {
            name: .key,
            calls_s: (((.value.run_cnt - ($bm[.key].run_cnt // 0)) / $sec) | floor),
            cpu_s: (((.value.run_time_ns - ($bm[.key].run_time_ns // 0)) / $sec) | floor),
            avg: (if (.value.run_cnt - ($bm[.key].run_cnt // 0)) > 0
                  then ((.value.run_time_ns - ($bm[.key].run_time_ns // 0)) /
                        (.value.run_cnt - ($bm[.key].run_cnt // 0))) | floor
                  else 0 end)
        }] | sort_by(-.cpu_s)[] |
        [.name, .calls_s, .cpu_s, .avg] | @tsv
    ' | while IFS=$'\t' read -r name calls cpu avg; do
        printf "%-30s %12s %15s %10s\n" "$name" "$calls" "$cpu" "$avg"
    done

    # Total CPU usage as percentage
    local total_delta_ns
    total_delta_ns=$(jq -n --argjson b "$before" --argjson a "$after" '
        ([$a[].run_time_ns] | add // 0) - ([$b[].run_time_ns] | add // 0)')
    local num_cpus
    num_cpus=$(nproc)
    local wall_ns=$((seconds * 1000000000 * num_cpus))
    if [ "$wall_ns" -gt 0 ]; then
        local pct
        pct=$(echo "scale=4; $total_delta_ns * 100 / $wall_ns" | bc 2>/dev/null || echo "N/A")
        echo ""
        info "Total BPF CPU overhead: ${pct}% of ${num_cpus} CPUs over ${seconds}s"
        # Check threshold (1% is generous for BPF)
        local pct_int=${pct%%.*}
        if [ "${pct_int:-0}" -gt 5 ]; then
            fail "BPF CPU overhead exceeds 5%"
        elif [ "${pct_int:-0}" -gt 1 ]; then
            warn "BPF CPU overhead above 1%"
        else
            pass "BPF CPU overhead within limits (${pct}%)"
        fi
    fi
}

# Main
if [ "${1:-}" = "--watch" ]; then
    interval="${2:-10}"
    info "Watching BPF overhead (sampling every ${interval}s). Ctrl+C to stop."
    before=$(snapshot_progs)
    print_prog_snapshot "$before"
    print_map_snapshot "$(snapshot_maps)"
    while true; do
        sleep "$interval"
        after=$(snapshot_progs)
        print_delta "$before" "$after" "$interval"
        before="$after"
    done
else
    progs=$(snapshot_progs)
    maps=$(snapshot_maps)
    print_prog_snapshot "$progs"
    print_map_snapshot "$maps"
    echo ""
    info "Run with --watch <seconds> to see per-second rates"
fi
