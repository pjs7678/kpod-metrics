# AI Assistant (MCP)

An [MCP](https://modelcontextprotocol.io) server that lets AI assistants (Claude Code, Claude Desktop,
Cursor, VS Code, …) explore and diagnose your cluster with kpod-metrics data. Ask questions in plain
language: _"why is checkout slow?"_, _"which pods are CPU-throttled?"_, _"what does payments depend on?"_

It runs **on your machine** and uses your existing kubeconfig, so there is nothing to deploy and your
RBAC applies. Prometheus is reached through the Kubernetes API proxy (auto-discovered), so no
port-forward is needed either.

## Install

Requires [uv](https://docs.astral.sh/uv/) and `kubectl` pointing at the cluster.

**Claude Code**

```bash
claude mcp add kpod -- uvx --from "git+https://github.com/pjs7678/kpod-metrics#subdirectory=mcp" kpod-mcp
```

**Claude Desktop / Cursor / other clients** (`mcpServers` JSON):

```json
{
  "mcpServers": {
    "kpod": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/pjs7678/kpod-metrics#subdirectory=mcp", "kpod-mcp"],
      "env": { "KPOD_KUBE_CONTEXT": "prod-eu" }
    }
  }
}
```

Check connectivity first:

```bash
uvx --from "git+https://github.com/pjs7678/kpod-metrics#subdirectory=mcp" kpod-mcp doctor
```

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `KPOD_PROMETHEUS_URL` | – | Direct Prometheus URL (e.g. `http://localhost:9090`, Thanos, Mimir `/prometheus`). Skips kubectl. |
| `KPOD_PROMETHEUS_BEARER_TOKEN` | – | Bearer token for `KPOD_PROMETHEUS_URL`. |
| `KPOD_PROMETHEUS_SERVICE` | auto-discovered | `<namespace>/<service>:<port>` reached via the API server proxy. |
| `KPOD_KUBE_CONTEXT` | current context | kubectl context. |
| `KPOD_NAMESPACE` | all namespaces | Namespace of the kpod-metrics DaemonSet (for `kpod_agent_status`). |
| `KPOD_SELECTOR` | `app.kubernetes.io/name=kpod-metrics` | Label selector of the agent pods. |

Auto-discovery looks for the usual Prometheus services: `kube-prometheus-stack-prometheus`, `prometheus-k8s`,
`prometheus-server`, `prometheus`, `prometheus-operated`.

## Tools

| Tool | What it answers |
|---|---|
| `kpod_overview` | What is unhealthy right now? Pods over threshold on throttling, PSI, memory/limit, retransmits, error ratios, restarts — sorted by severity. |
| `kpod_pod_report` | Everything about one pod, per container, with sparkline trends and an optional comparison (`compare="1d"`). |
| `kpod_top` | Rank pods by one of ~30 pre-built signals (`cpu_throttling`, `memory_limit_utilization`, `http_latency`, …). |
| `kpod_dependencies` | Service dependency graph (Mermaid) from eBPF TCP data, with connection rate and RTT. |
| `kpod_query` | Arbitrary read-only PromQL, results summarised. |
| `kpod_metrics_catalog` | Exact metric names, labels and semantics, so the assistant writes correct PromQL. |
| `kpod_agent_status` | Health of the agents: BPF load failures, collector errors, silent programs. |

Prompts (slash commands in Claude Code, e.g. `/mcp__kpod__diagnose_pod`): `diagnose_pod`, `cluster_health`,
`rightsize`.

## Terminal use (no AI client)

The same reports print as Markdown:

```bash
kpod-mcp overview -n shop
kpod-mcp report shop/checkout-7d9f8b6c5-x2x9p -w 6h -c 1d
kpod-mcp top cpu_throttling -n shop
kpod-mcp deps -n shop
kpod-mcp agents
```

## Design notes

- **Read-only.** Every tool is a Prometheus query or an actuator `GET`; tools carry `readOnlyHint`.
  Namespace/pod arguments are validated as DNS-1123 names before being placed in PromQL.
- **Pre-judged output.** Tools return thresholds and flags with the numbers, so the model does not
  have to know what "normal" throttling looks like — and is told which metrics are means, not percentiles.
- **Label rename handling.** If Prometheus Operator renamed `pod` to `exported_pod`, it is detected and
  queries adapt.
- **Privacy.** Metrics go to whichever AI client you connect. Pod names, namespaces and DNS names
  will be part of the conversation.

## Development

```bash
cd mcp
uv sync
uv run pytest
uv run kpod-mcp doctor
```
