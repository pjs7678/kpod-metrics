"""MCP server exposing kpod-metrics to AI assistants."""

from __future__ import annotations

import functools
from typing import Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from . import analysis
from .backend import Agents, BackendError, Kubectl, Prometheus, Settings
from .catalog import SIGNALS

INSTRUCTIONS = """\
kpod-metrics is an eBPF + cgroup per-pod metrics agent (CPU throttling/PSI, memory, TCP, HTTP/DNS/Redis/
MySQL/Kafka/Mongo, service dependencies). These tools read its data from Prometheus and from the agents.

Workflow:
1. kpod_overview — what is unhealthy right now (start here when the question is vague).
2. kpod_pod_report — everything about one pod, with trends; pass compare="1d" to compare with yesterday.
3. kpod_top — rank pods by one signal; kpod_dependencies — who talks to whom (Mermaid graph).
4. kpod_query — arbitrary PromQL; call kpod_metrics_catalog first for exact names and semantics.
5. kpod_agent_status — when data is missing (BPF load failures, collector errors).

Interpretation rules:
- Throttling with low average CPU = bursty workload hitting its CFS quota: raise/remove the CPU limit.
- PSI (pressure) is the most direct "slowed down by resource contention" evidence; prefer it over utilisation.
- Memory: judge OOM risk on RSS/limit, not usage (usage includes reclaimable page cache).
- Percentiles exist only for runqueue, TCP RTT, syscall and disk IO latency (kernel histograms; a value at the
  top edge — runqueue 4.3 s, TCP RTT 8.6 s, syscall/disk 34 s — means "at least that"). HTTP/DNS/DB latencies are means — never present them as percentiles.
- Report concrete values and the pod/container they came from. Never invent metrics not returned by a tool.
"""

RO = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True)

SignalName = Literal[tuple(SIGNALS)]  # type: ignore[valid-type]


def _user_errors(fn):
    """mcp 2.x hides the text of unexpected exceptions from the client. Validation and backend
    failures are expected and actionable (bad pod name, Prometheus unreachable), so surface them."""

    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        try:
            return await fn(*args, **kwargs)
        except (BackendError, ValueError) as e:
            raise ToolError(str(e)) from e

    return wrapper


def build(settings: Settings | None = None, ctx: analysis.Ctx | None = None) -> MCPServer:
    if ctx is None:
        settings = settings or Settings.from_env()
        kubectl = Kubectl(settings)
        ctx = analysis.Ctx(prom=Prometheus(settings, kubectl), agents=Agents(settings, kubectl))
    mcp = MCPServer("kpod-metrics", instructions=INSTRUCTIONS)

    @mcp.tool(annotations=RO)
    @_user_errors
    async def kpod_overview(namespace: str | None = None, window: str = "15m", limit: int = 5) -> str:
        """Cluster (or namespace) health summary: every pod/container whose CPU throttling, PSI stall,
        memory-vs-limit, TCP retransmits/drops, HTTP/DB error ratio, latency or restarts exceed a
        threshold, sorted by severity. Start here.

        Args:
            namespace: Limit to one namespace (default: all monitored namespaces).
            window: PromQL range window, e.g. 5m, 15m, 1h.
            limit: Max flagged pods per signal.
        """
        return await analysis.overview(ctx, namespace, window, limit)

    @mcp.tool(annotations=RO)
    @_user_errors
    async def kpod_pod_report(namespace: str, pod: str, window: str = "1h", compare: str | None = None) -> str:
        """Deep-dive into one pod: per-container CPU/limit/throttling/PSI, memory RSS/limit, disk, network,
        TCP health, HTTP/DNS/DB metrics, detected application, outbound dependencies and trend sparklines.

        Args:
            namespace: Pod namespace.
            pod: Exact pod name (if unknown, the response lists pods with data in the namespace).
            window: Range window for rates and trends, e.g. 15m, 1h, 6h.
            compare: Optional offset to compare against, e.g. 1d (same time yesterday) or 1h.
        """
        return await analysis.pod_report(ctx, namespace, pod, window, compare)

    @mcp.tool(annotations=RO)
    @_user_errors
    async def kpod_top(signal: SignalName, namespace: str | None = None, window: str = "15m",
                       limit: int = 10, lowest: bool = False) -> str:
        """Rank pods/containers by one pre-built signal (e.g. cpu_throttling, memory_limit_utilization,
        tcp_retransmits, http_latency, cpu_pressure). Flags values above the signal's threshold.

        Args:
            signal: Signal name; see kpod_metrics_catalog for descriptions and thresholds.
            namespace: Optional namespace filter.
            window: Range window, e.g. 5m, 1h.
            limit: Number of rows.
            lowest: Return the lowest values instead (e.g. least-utilised pods for right-sizing).
        """
        return await analysis.top(ctx, signal, namespace, window, limit, lowest)

    @mcp.tool(annotations=RO)
    @_user_errors
    async def kpod_dependencies(namespace: str | None = None, pod: str | None = None, window: str = "15m",
                                group_by: Literal["workload", "pod"] = "workload", max_edges: int = 40) -> str:
        """Service dependency graph from eBPF-observed outbound TCP connections, as a Mermaid diagram plus a
        table with connection rate and RTT per edge. Pods are grouped into workloads by default.

        Args:
            namespace: Only edges originating in this namespace.
            pod: Only edges originating from this pod (requires namespace for precision).
            window: Range window.
            group_by: 'workload' (strip ReplicaSet/DaemonSet suffixes) or 'pod'.
            max_edges: Keep the busiest N edges.
        """
        return await analysis.dependencies(ctx, namespace, pod, window, group_by, max_edges)

    @mcp.tool(annotations=RO)
    @_user_errors
    async def kpod_query(promql: str, range_window: str | None = None, step: str | None = None,
                         max_series: int = 30) -> str:
        """Run a read-only PromQL query against the Prometheus that scrapes kpod-metrics.
        Instant query by default; set range_window (e.g. 1h) for a range query summarised as sparklines.
        Call kpod_metrics_catalog first for exact metric names — they differ from Micrometer names.

        Args:
            promql: PromQL expression.
            range_window: Look-back for a range query (e.g. 30m, 6h). Omit for an instant query.
            step: Range resolution (e.g. 1m). Default: range/60.
            max_series: Truncate output to this many series.
        """
        return await analysis.query(ctx, promql, range_window, step, max_series)

    @mcp.tool(annotations=RO)
    @_user_errors
    async def kpod_metrics_catalog(search: str | None = None) -> str:
        """List kpod-metrics' Prometheus metric names, labels and semantics, plus the pre-built signals
        usable with kpod_top. Use before writing PromQL.

        Args:
            search: Optional case-insensitive filter, e.g. "tcp", "pressure", "redis".
        """
        return analysis.catalog(search)

    @mcp.tool(annotations=RO)
    @_user_errors
    async def kpod_agent_status() -> str:
        """Health of the kpod-metrics DaemonSet itself, per node: BPF programs loaded/failed, collector
        errors, programs producing no data, monitored pod count. Use when expected data is missing.
        Reads /actuator/kpodDiagnostics through the Kubernetes API pod proxy (needs pods/proxy RBAC).
        """
        return await analysis.agent_status(ctx)

    @mcp.prompt(title="Diagnose a pod")
    def diagnose_pod(namespace: str, pod: str) -> str:
        """Systematic root-cause analysis of one pod using kpod-metrics."""
        return f"""Diagnose pod `{namespace}/{pod}` using the kpod tools.

1. Call kpod_pod_report(namespace="{namespace}", pod="{pod}", window="1h", compare="1d").
2. Walk the resource chain and state, with numbers, which links are healthy or not:
   CPU (limit utilisation → throttling → PSI cpu → runqueue wait) → memory (RSS/limit, PSI memory)
   → disk (PSI io) → network (retransmits, drops, RTT) → protocols (error ratio, latency) → restarts.
3. For each unhealthy outbound dependency, call kpod_pod_report on that peer if it is a pod in the cluster.
4. If data is missing, call kpod_agent_status before concluding anything.
5. Conclude with: most likely cause, supporting evidence (metric = value), what would falsify it, and
   concrete remediation (e.g. resource limit changes with suggested values derived from observed usage).
"""

    @mcp.prompt(title="Cluster health check")
    def cluster_health(namespace: str = "") -> str:
        """Triage everything kpod-metrics flags as unhealthy."""
        scope = f'namespace="{namespace}"' if namespace else "no namespace filter"
        return f"""Run a health check with the kpod tools ({scope}).

1. Call kpod_overview(window="15m"{', namespace="' + namespace + '"' if namespace else ''}).
2. Group the findings by root cause rather than by signal (e.g. one noisy node, one overloaded
   dependency, systematically too-low CPU limits).
3. For the top 3 groups, confirm with kpod_pod_report or kpod_top and rank by user impact.
4. Output a short table: issue, affected pods, evidence, suggested fix, urgency.
"""

    @mcp.prompt(title="Right-size resources")
    def rightsize(namespace: str) -> str:
        """Suggest CPU/memory requests and limits from observed usage."""
        return f"""Suggest resource settings for workloads in namespace `{namespace}` using the kpod tools.

1. kpod_top(signal="cpu_throttling", namespace="{namespace}", window="1d") and
   kpod_top(signal="memory_limit_utilization", namespace="{namespace}", window="1d").
2. For candidates, use kpod_query with max_over_time / quantile_over_time over 7d on
   rate(kpod_cpu_usage_seconds_total[5m]) and kpod_mem_cgroup_rss_bytes to get p95/max usage.
3. Recommend per container: CPU request ≈ p95 usage, CPU limit removed or ≥ 2× p95 if throttled,
   memory limit ≈ max RSS × 1.3. Show current vs suggested and the evidence.
"""

    return mcp
