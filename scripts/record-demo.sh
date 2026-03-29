#!/usr/bin/env bash
set -euo pipefail

# Demo recording script for kpod-metrics
# Records a simulated terminal session showing install → metrics → topology
#
# Prerequisites:
#   brew install asciinema    # macOS
#   pip install asciinema     # or pip
#
# Usage:
#   ./scripts/record-demo.sh              # Record to docs/demo.cast
#   ./scripts/record-demo.sh --play       # Play existing recording
#
# Convert to GIF:
#   npm install -g svg-term-cli
#   svg-term --in docs/demo.cast --out docs/demo.svg --window --width 80 --height 24
#
#   # Or use agg (asciinema gif generator):
#   cargo install --git https://github.com/asciinema/agg
#   agg docs/demo.cast docs/demo.gif --cols 80 --rows 24

CAST_FILE="docs/demo.cast"

if [[ "${1:-}" == "--play" ]]; then
  exec asciinema play "$CAST_FILE"
fi

# --- Simulated demo (no real cluster needed) ---

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEMO_SCRIPT=$(mktemp)

cat > "$DEMO_SCRIPT" << 'DEMO'
#!/usr/bin/env bash

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
GRAY='\033[0;90m'
BOLD='\033[1m'
NC='\033[0m'

type_cmd() {
  printf "${BOLD}\$ ${NC}"
  for ((i=0; i<${#1}; i++)); do
    printf "%s" "${1:$i:1}"
    sleep 0.04
  done
  echo
  sleep 0.3
}

section() {
  echo
  printf "${YELLOW}━━━ %s ━━━${NC}\n" "$1"
  sleep 0.8
}

clear
printf "${GREEN}${BOLD}"
cat << 'BANNER'

  ┬┌─┌─┐┌─┐┌┬┐   ┌┬┐┌─┐┌┬┐┬─┐┬┌─┐┌─┐
  ├┴┐├─┘│ │ ││───│││├┤  │ ├┬┘││  └─┐
  ┴ ┴┴  └─┘─┴┘   ┴ ┴└─┘ ┴ ┴└─┴└─┘└─┘

  eBPF-powered pod metrics for Kubernetes

BANNER
printf "${NC}"
sleep 1.5

section "Step 1: Add Helm repository"

type_cmd "helm repo add kpod-metrics https://pjs7678.github.io/kpod-metrics"
printf "${GRAY}\"kpod-metrics\" has been added to your repositories${NC}\n"
sleep 0.5

type_cmd "helm repo update"
printf "${GRAY}Hang tight while we grab the latest from your chart repositories...\n"
printf "...Successfully got an update from the \"kpod-metrics\" chart repository\n"
printf "Update Complete. ⎈Happy Helming!⎈${NC}\n"
sleep 1

section "Step 2: Install kpod-metrics"

type_cmd "helm install kpod-metrics kpod-metrics/kpod-metrics -n kpod-metrics --create-namespace"
printf "${GRAY}NAME: kpod-metrics\n"
printf "LAST DEPLOYED: Sat Mar 29 2026\n"
printf "NAMESPACE: kpod-metrics\n"
printf "STATUS: deployed\n"
printf "REVISION: 1${NC}\n"
sleep 1.5

section "Step 3: Check pods"

type_cmd "kubectl -n kpod-metrics get pods"
printf "NAME                    READY   STATUS    RESTARTS   AGE\n"
printf "kpod-metrics-${CYAN}xk9p2${NC}   1/1     ${GREEN}Running${NC}   0          45s\n"
sleep 1.5

section "Step 4: View metrics"

type_cmd "kubectl -n kpod-metrics port-forward ds/kpod-metrics 9090:9090 &"
printf "${GRAY}Forwarding from 127.0.0.1:9090 -> 9090${NC}\n"
sleep 0.5

type_cmd "curl -s localhost:9090/actuator/prometheus | grep kpod | head -15"
echo
printf "# HELP kpod_cpu_context_switches_total Context switch count\n"
printf "kpod_cpu_context_switches_total{namespace=\"default\",pod=\"api-server-7b4d9\",container=\"api\",node=\"node-1\"} ${CYAN}284751${NC}\n"
printf "kpod_cpu_context_switches_total{namespace=\"default\",pod=\"worker-5c8f2\",container=\"worker\",node=\"node-1\"} ${CYAN}157302${NC}\n"
echo
printf "# HELP kpod_net_tcp_bytes_sent_total TCP bytes sent\n"
printf "kpod_net_tcp_bytes_sent_total{namespace=\"default\",pod=\"api-server-7b4d9\",container=\"api\",node=\"node-1\"} ${CYAN}1.048576e+08${NC}\n"
echo
printf "# HELP kpod_net_tcp_rtt_seconds TCP round-trip time\n"
printf "kpod_net_tcp_rtt_seconds{namespace=\"default\",pod=\"api-server-7b4d9\",quantile=\"0.5\"} ${CYAN}0.000842${NC}\n"
printf "kpod_net_tcp_rtt_seconds{namespace=\"default\",pod=\"api-server-7b4d9\",quantile=\"0.9\"} ${CYAN}0.002150${NC}\n"
printf "kpod_net_tcp_rtt_seconds{namespace=\"default\",pod=\"api-server-7b4d9\",quantile=\"0.99\"} ${CYAN}0.008431${NC}\n"
echo
printf "# HELP kpod_mem_cgroup_usage_bytes Current memory usage\n"
printf "kpod_mem_cgroup_usage_bytes{namespace=\"default\",pod=\"api-server-7b4d9\",container=\"api\",node=\"node-1\"} ${CYAN}1.34217728e+08${NC}\n"
echo
printf "# HELP kpod_syscall_count_total Syscall invocations\n"
printf "kpod_syscall_count_total{namespace=\"default\",pod=\"api-server-7b4d9\",syscall=\"read\",node=\"node-1\"} ${CYAN}892451${NC}\n"
printf "kpod_syscall_count_total{namespace=\"default\",pod=\"api-server-7b4d9\",syscall=\"write\",node=\"node-1\"} ${CYAN}541203${NC}\n"
sleep 2

section "Step 5: Service topology"

type_cmd "curl -s localhost:9090/actuator/kpodTopology | python3 -m json.tool | head -25"
printf "${GRAY}{\n"
printf "    \"nodes\": [\n"
printf "        {\n"
printf "            \"id\": \"default/api-server\",\n"
printf "            \"title\": \"api-server\",\n"
printf "            \"mainStat\": \"1,247 req/s\",\n"
printf "            \"arc__http\": 0.85,\n"
printf "            \"arc__redis\": 0.15\n"
printf "        },\n"
printf "        {\n"
printf "            \"id\": \"default/postgres\",\n"
printf "            \"title\": \"postgres\",\n"
printf "            \"mainStat\": \"523 req/s\"\n"
printf "        }\n"
printf "    ],\n"
printf "    \"edges\": [\n"
printf "        {\n"
printf "            \"source\": \"default/api-server\",\n"
printf "            \"target\": \"default/postgres\",\n"
printf "            \"mainStat\": \"2.1ms avg\",\n"
printf "            \"secondaryStat\": \"8.4ms p99\",\n"
printf "            \"detail__protocol\": \"mysql\"\n"
printf "        }\n"
printf "    ]\n"
printf "}${NC}\n"
sleep 2

echo
printf "${GREEN}${BOLD}✓ kpod-metrics is collecting per-pod kernel metrics!${NC}\n"
echo
printf "  Docs:   ${CYAN}https://pjs7678.github.io/kpod-metrics${NC}\n"
printf "  GitHub: ${CYAN}https://github.com/pjs7678/kpod-metrics${NC}\n"
echo
sleep 2
DEMO

chmod +x "$DEMO_SCRIPT"

# Check for asciinema
if command -v asciinema &>/dev/null; then
  echo "Recording demo to $CAST_FILE..."
  asciinema rec "$CAST_FILE" \
    --cols 90 --rows 30 \
    --title "kpod-metrics Demo" \
    --command "$DEMO_SCRIPT" \
    --overwrite
  rm -f "$DEMO_SCRIPT"
  echo ""
  echo "Recording saved to $CAST_FILE"
  echo ""
  echo "Convert to SVG:"
  echo "  npm install -g svg-term-cli"
  echo "  svg-term --in $CAST_FILE --out docs/demo.svg --window --width 90 --height 30"
  echo ""
  echo "Convert to GIF:"
  echo "  cargo install --git https://github.com/asciinema/agg"
  echo "  agg $CAST_FILE docs/demo.gif --cols 90 --rows 30"
  echo ""
  echo "Play back:"
  echo "  asciinema play $CAST_FILE"
else
  echo "asciinema not found. Running demo directly..."
  echo ""
  bash "$DEMO_SCRIPT"
  rm -f "$DEMO_SCRIPT"
  echo ""
  echo "Install asciinema to record:"
  echo "  brew install asciinema    # macOS"
  echo "  pip install asciinema     # pip"
fi
