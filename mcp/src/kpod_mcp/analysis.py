"""Analyses behind the MCP tools. Each returns Markdown: dense enough for an LLM to reason
over in one tool call, readable enough to show a human as-is."""

from __future__ import annotations

import asyncio
import math
from collections import defaultdict
from dataclasses import dataclass

from . import format as fmt
from .backend import Agents, BackendError, Labels, Prometheus, Sample, now
from .catalog import (
    METRICS, OVERVIEW_SIGNALS, POD_REPORT_GROUPS, SIGNALS, TREND_SIGNALS, COMMON,
    duration, duration_seconds, k8s_name, selector,
)


@dataclass
class Ctx:
    prom: Prometheus
    agents: Agents


def _label_note(labels: Labels) -> str:
    if labels.pod == "exported_pod":
        return (
            "\n> Note: Prometheus renamed kpod's `pod`/`namespace` labels to `exported_*` "
            "(ServiceMonitor without `honorLabels: true`). Queries below already account for it.\n"
        )
    return ""


def _who(labels: Labels, s: Sample) -> tuple[str, str, str]:
    return (
        s.labels.get(labels.namespace, ""),
        s.labels.get(labels.pod, ""),
        s.labels.get(labels.container, ""),
    )


async def _gather(coros: dict[str, object]) -> dict[str, list[Sample] | Exception]:
    keys = list(coros)
    results = await asyncio.gather(*coros.values(), return_exceptions=True)
    return dict(zip(keys, results))


# ---------------------------------------------------------------------------
# Cluster overview
# ---------------------------------------------------------------------------


async def overview(ctx: Ctx, namespace: str | None, window: str, limit: int) -> str:
    duration(window)
    labels = await ctx.prom.labels()
    sel = selector(labels, namespace)
    signals = [SIGNALS[n] for n in OVERVIEW_SIGNALS]
    res = await _gather({
        s.name: ctx.prom.instant(f"topk({max(limit, 1) * 3}, {s.promql(labels, sel, window)})") for s in signals
    } | {
        "_pods": ctx.prom.instant(f"count(count by ({labels.by_pod}) (kpod_mem_cgroup_usage_bytes{{{sel}}}))"),
        "_nodes": ctx.prom.instant(f"count(count by (node) (kpod_mem_cgroup_usage_bytes{{{sel}}}))"),
    })

    # A failing coverage query means Prometheus itself is unusable — say so instead of "no data".
    if isinstance(res["_pods"], Exception):
        raise res["_pods"]

    def scalar(key: str) -> int:
        r = res.get(key)
        return int(r[0].value) if isinstance(r, list) and r else 0

    findings: list[tuple[float, list[str]]] = []
    healthy, no_data, failed = [], [], []
    for s in signals:
        r = res[s.name]
        if isinstance(r, Exception):
            failed.append(f"{s.title}: {r}")
            continue
        if not r:
            no_data.append(f"{s.title} ({s.requires})")
            continue
        flagged = [x for x in r if not math.isnan(x.value) and s.threshold is not None and x.value >= s.threshold]
        if not flagged:
            healthy.append(s.title)
        for x in sorted(flagged, key=lambda x: -x.value)[:limit]:
            ns, pod, ctr = _who(labels, x)
            findings.append((x.value / s.threshold, [
                s.title, f"{ns}/{pod}", ctr, fmt.value(x.value, s.unit), fmt.value(s.threshold, s.unit),
            ]))

    scope = f"namespace `{namespace}`" if namespace else "all namespaces"
    out = [
        f"# kpod-metrics overview — {scope}, last {window}",
        f"Monitoring **{scalar('_pods')} pods** on **{scalar('_nodes')} nodes**.",
        _label_note(labels),
    ]
    if scalar("_pods") == 0:
        out.append(
            "No kpod data found. Check that kpod-metrics is scraped by this Prometheus "
            "(`kpod_agent_status`, `up`), and that the namespace is not excluded "
            "(kube-system/kube-public are excluded by default)."
        )
        return "\n".join(out)

    if findings:
        findings.sort(key=lambda f: -f[0])
        out += [f"## ⚠ Findings ({len(findings)})", "Sorted by how far each value exceeds its threshold.", ""]
        out.append(fmt.table(["Signal", "Pod", "Container", "Value", "Threshold"], [f[1] for f in findings]))
    else:
        out.append("## ✓ No signal above threshold")
    if healthy:
        out += ["", "**Within thresholds:** " + ", ".join(healthy)]
    if no_data:
        out += ["", "**No data** (collector disabled for the profile, or no such traffic): " + "; ".join(no_data)]
    if failed:
        out += ["", "**Query errors:** " + "; ".join(failed)]
    out += ["", "_Next: `kpod_pod_report` for a flagged pod, or `kpod_top` for a ranking of any signal._"]
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Top-N ranking for one signal
# ---------------------------------------------------------------------------


async def top(ctx: Ctx, signal: str, namespace: str | None, window: str, limit: int, lowest: bool) -> str:
    duration(window)
    if signal not in SIGNALS:
        raise ValueError(f"Unknown signal '{signal}'. Valid: {', '.join(SIGNALS)}")
    s = SIGNALS[signal]
    labels = await ctx.prom.labels()
    fn = "bottomk" if lowest else "topk"
    rows = await ctx.prom.instant(f"{fn}({limit}, {s.promql(labels, selector(labels, namespace), window)})")
    rows.sort(key=lambda x: x.value, reverse=not lowest)
    out = [f"# {'Lowest' if lowest else 'Top'} {limit} by {s.title} — last {window}", s.help, _label_note(labels)]
    if not rows:
        out.append(f"No data. Requires: {s.requires}.")
        return "\n".join(out)
    out.append(fmt.table(
        ["#", "Namespace", "Pod", "Container", "Value", "Flag"],
        [
            [str(i + 1), *_who(labels, x), fmt.value(x.value, s.unit),
             "⚠" if s.threshold is not None and x.value >= s.threshold else ""]
            for i, x in enumerate(rows)
        ],
    ))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Single pod deep-dive
# ---------------------------------------------------------------------------


async def _suggest_pods(ctx: Ctx, labels: Labels, namespace: str, pod: str) -> list[str]:
    try:
        r = await ctx.prom.instant(
            f'group by ({labels.pod}) (kpod_mem_cgroup_usage_bytes{{{labels.namespace}="{namespace}"}})'
        )
    except BackendError:
        return []
    names = sorted({x.labels.get(labels.pod, "") for x in r})
    stem = fmt.workload(pod)
    return [n for n in names if stem in n or pod in n][:10] or names[:10]


async def pod_report(ctx: Ctx, namespace: str, pod: str, window: str, compare: str | None) -> str:
    k8s_name(namespace, "namespace")
    k8s_name(pod, "pod")
    duration(window)
    labels = await ctx.prom.labels()
    sel = selector(labels, namespace, pod)
    t_now = now()
    t_then = t_now - duration_seconds(compare) if compare else None

    names = [n for _, group in POD_REPORT_GROUPS for n in group]
    queries: dict[str, object] = {n: ctx.prom.instant(SIGNALS[n].promql(labels, sel, window), t_now) for n in names}
    if t_then is not None:
        queries |= {f"then:{n}": ctx.prom.instant(SIGNALS[n].promql(labels, sel, window), t_then) for n in names}
    peer_by = f"{labels.container}, remote_service, remote_pod, remote_ip, remote_port"
    queries |= {
        "_app": ctx.prom.instant(f"kpod_container_application{{{sel}}}", t_now),
        "_peers": ctx.prom.instant(
            f"topk(15, sum by ({peer_by}) (rate(kpod_net_tcp_peer_connections_total{{{sel}}}[{window}])) > 0)", t_now),
        "_peer_rtt": ctx.prom.instant(
            f"sum by ({peer_by}) (rate(kpod_net_tcp_peer_rtt_seconds_sum{{{sel}}}[{window}])) / "
            f"sum by ({peer_by}) (rate(kpod_net_tcp_peer_rtt_seconds_count{{{sel}}}[{window}]))", t_now),
        "_http": ctx.prom.instant(
            f"sum by (method, status_code, direction) (rate(kpod_http_requests_total{{{sel}}}[{window}])) > 0", t_now),
        "_dns": ctx.prom.instant(
            f"topk(5, sum by (domain) (rate(kpod_dns_top_domains_total{{{sel}}}[{window}])) > 0)", t_now),
    }
    res = await _gather(queries)
    errors = [r for r in res.values() if isinstance(r, Exception)]
    if errors and len(errors) == len(res):
        raise errors[0]

    # container -> signal -> value
    values: dict[str, dict[str, float]] = defaultdict(dict)
    before: dict[str, dict[str, float]] = defaultdict(dict)
    for key, r in res.items():
        if key.startswith("_") or isinstance(r, Exception):
            continue
        target = before if key.startswith("then:") else values
        sig = key.removeprefix("then:")
        for x in r:
            target[x.labels.get(labels.container, "")][sig] = x.value

    if not values:
        hint = await _suggest_pods(ctx, labels, namespace, pod)
        msg = f"No kpod data for `{namespace}/{pod}` in the last {window}."
        if hint:
            msg += " Pods with data in this namespace: " + ", ".join(f"`{h}`" for h in hint)
        else:
            msg += " The namespace may be excluded (kube-system/kube-public by default) or not scraped."
        return msg

    apps = defaultdict(list)
    if isinstance(res["_app"], list):
        for x in res["_app"]:
            apps[x.labels.get(labels.container, "")].append(x.labels.get("application", "?"))

    out = [f"# Pod report — `{namespace}/{pod}`, last {window}" + (f" (vs {compare} ago)" if compare else ""),
           _label_note(labels)]

    flagged: list[str] = []
    for ctr in sorted(values):
        v = values[ctr]
        app = f" — detected: {', '.join(sorted(apps[ctr]))}" if apps.get(ctr) else ""
        out.append(f"## Container `{ctr}`{app}")
        for group, sigs in POD_REPORT_GROUPS:
            present = [n for n in sigs if n in v]
            if not present:
                continue
            rows = []
            for n in present:
                s = SIGNALS[n]
                bad = s.threshold is not None and v[n] >= s.threshold
                if bad:
                    flagged.append(f"`{ctr}`: **{s.title}** = {fmt.value(v[n], s.unit)} "
                                   f"(threshold {fmt.value(s.threshold, s.unit)}) — {s.help}")
                row = [s.title, fmt.value(v[n], s.unit), "⚠" if bad else ""]
                if compare:
                    b = before.get(ctr, {}).get(n)
                    row.insert(2, fmt.value(b, s.unit) if b is not None else "–")
                rows.append(row)
            headers = ["Signal", "Now"] + ([f"{compare} ago"] if compare else []) + [""]
            out += [f"**{group}**", fmt.table(headers, rows), ""]

    # Trends
    span = duration_seconds(window)
    step = max(span / 30, 15)
    rate_w = f"{int(max(step * 2, 60))}s"
    trend_q = {n: ctx.prom.range(SIGNALS[n].promql(labels, sel, rate_w), t_now - span, t_now, step)
               for n in TREND_SIGNALS}
    trends = await _gather(trend_q)
    trend_rows = []
    for n, series in trends.items():
        if isinstance(series, Exception) or not series:
            continue
        s = SIGNALS[n]
        for ser in series:
            vals = [v for _, v in ser.values]
            if not vals:
                continue
            trend_rows.append([s.title, ser.labels.get(labels.container, ""), fmt.sparkline(vals),
                               fmt.value(min(vals), s.unit), fmt.value(max(vals), s.unit)])
    if trend_rows:
        out += [f"## Trends (last {window})",
                fmt.table(["Signal", "Container", "Trend", "Min", "Max"], trend_rows), ""]

    # HTTP breakdown
    if isinstance(res["_http"], list) and res["_http"]:
        rows = sorted(res["_http"], key=lambda x: -x.value)[:15]
        out += ["## HTTP breakdown", fmt.table(
            ["Direction", "Method", "Status", "Rate"],
            [[x.labels.get("direction", ""), x.labels.get("method", ""), x.labels.get("status_code", ""),
              fmt.value(x.value, "per_s")] for x in rows]), ""]

    # Dependencies
    if isinstance(res["_peers"], list) and res["_peers"]:
        rtt = {}
        if isinstance(res["_peer_rtt"], list):
            rtt = {tuple(sorted(x.labels.items())): x.value for x in res["_peer_rtt"]}
        rows = []
        for x in sorted(res["_peers"], key=lambda x: -x.value):
            lab = x.labels
            peer = lab.get("remote_service") or fmt.workload(lab.get("remote_pod", "")) or lab.get("remote_ip", "?")
            rows.append([lab.get(labels.container, ""), peer, lab.get("remote_port", ""),
                         fmt.value(x.value, "per_s"), fmt.value(rtt.get(tuple(sorted(lab.items())), math.nan), "seconds")])
        out += ["## Outbound dependencies (TCP)", fmt.table(["Container", "Peer", "Port", "Conn rate", "RTT"], rows), ""]

    if isinstance(res["_dns"], list) and res["_dns"]:
        out += ["## Top DNS names", ", ".join(
            f"`{x.labels.get('domain', '?')}` ({fmt.value(x.value, 'per_s')})"
            for x in sorted(res["_dns"], key=lambda x: -x.value))]

    out += ["", "## Flags"]
    out += [f"- {f}" for f in flagged] if flagged else ["- None above threshold."]
    missing = sorted({SIGNALS[n].requires for n in names if not any(n in v for v in values.values())})
    if missing:
        out += ["", "_Signals without data (collector off or no traffic): " + "; ".join(missing) + "._"]
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Service dependency graph
# ---------------------------------------------------------------------------


async def dependencies(ctx: Ctx, namespace: str | None, pod: str | None, window: str, group_by: str,
                       max_edges: int) -> str:
    duration(window)
    if group_by not in ("workload", "pod"):
        raise ValueError("group_by must be 'workload' or 'pod'")
    labels = await ctx.prom.labels()
    sel = selector(labels, namespace, pod)
    by = f"{labels.namespace}, {labels.pod}, remote_service, remote_pod, remote_ip, remote_port"
    res = await _gather({
        "conn": ctx.prom.instant(f"sum by ({by}) (rate(kpod_net_tcp_peer_connections_total{{{sel}}}[{window}])) > 0"),
        "rtt_sum": ctx.prom.instant(f"sum by ({by}) (rate(kpod_net_tcp_peer_rtt_seconds_sum{{{sel}}}[{window}]))"),
        "rtt_cnt": ctx.prom.instant(f"sum by ({by}) (rate(kpod_net_tcp_peer_rtt_seconds_count{{{sel}}}[{window}]))"),
    })
    if isinstance(res["conn"], Exception):
        raise res["conn"]

    def key(x: Sample) -> tuple:
        return tuple(sorted(x.labels.items()))

    rtt_sum = {key(x): x.value for x in res["rtt_sum"]} if isinstance(res["rtt_sum"], list) else {}
    rtt_cnt = {key(x): x.value for x in res["rtt_cnt"]} if isinstance(res["rtt_cnt"], list) else {}

    def name(ns: str, p: str) -> str:
        return f"{ns}/{fmt.workload(p) if group_by == 'workload' else p}"

    edges: dict[tuple[str, str, str], list[float]] = defaultdict(lambda: [0.0, 0.0, 0.0])  # rate, rtt_sum, rtt_cnt
    for x in res["conn"]:
        lab = x.labels
        src = name(lab.get(labels.namespace, ""), lab.get(labels.pod, ""))
        if lab.get("remote_service"):
            dst = lab["remote_service"]
        elif lab.get("remote_pod"):
            dst = fmt.workload(lab["remote_pod"]) if group_by == "workload" else lab["remote_pod"]
        else:
            dst = f"external:{lab.get('remote_ip', '?')}"
        e = edges[(src, dst, lab.get("remote_port", ""))]
        e[0] += x.value
        e[1] += rtt_sum.get(key(x), 0.0)
        e[2] += rtt_cnt.get(key(x), 0.0)

    if not edges:
        return f"No TCP peer data in the last {window}. Requires the tcpPeer collector (standard profile)."

    ranked = sorted(edges.items(), key=lambda kv: -kv[1][0])[:max_edges]
    lines = ["```mermaid", "graph LR"]
    for (src, dst, port), (rate, rs, rc) in ranked:
        rtt = fmt.value(rs / rc, "seconds") if rc > 0 else ""
        label = f"{port} · {fmt.value(rate, 'per_s')}" + (f" · {rtt}" if rtt else "")
        lines.append(f'  {fmt.mermaid_id(src)}["{src}"] -->|"{label}"| {fmt.mermaid_id(dst)}["{dst}"]')
    lines.append("```")

    rows = [[src, dst, port, fmt.value(rate, "per_s"), fmt.value(rs / rc, "seconds") if rc > 0 else "–"]
            for (src, dst, port), (rate, rs, rc) in ranked]
    scope = f"{namespace or 'all namespaces'}{'/' + pod if pod else ''}"
    out = [f"# Service dependencies — {scope}, last {window}", _label_note(labels),
           "Edges are outbound TCP connections observed by eBPF (connection rate, mean RTT).", "",
           *lines, "", fmt.table(["From", "To", "Port", "Conn rate", "RTT"], rows)]
    if len(edges) > max_edges:
        out.append(f"\n_{len(edges) - max_edges} smaller edges omitted._")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Raw PromQL and catalog
# ---------------------------------------------------------------------------


async def query(ctx: Ctx, promql: str, range_: str | None, step: str | None, max_series: int) -> str:
    if range_:
        span = duration_seconds(range_)
        step_s = duration_seconds(step) if step else max(span / 60, 15)
        t = now()
        series = await ctx.prom.range(promql, t - span, t, step_s)
        rows = []
        for s in series[:max_series]:
            vals = [v for _, v in s.values]
            rows.append([_fmt_labels(s.labels), fmt.sparkline(vals), f"{min(vals):.4g}", f"{max(vals):.4g}",
                         f"{vals[-1]:.4g}" if vals else "–"])
        out = fmt.table(["Series", "Trend", "Min", "Max", "Last"], rows)
        total = len(series)
    else:
        samples = await ctx.prom.instant(promql)
        samples.sort(key=lambda x: -x.value if not math.isnan(x.value) else math.inf)
        out = fmt.table(["Series", "Value"], [[_fmt_labels(s.labels), f"{s.value:.6g}"] for s in samples[:max_series]])
        total = len(samples)
    if total == 0:
        return "Empty result. Check the metric name with `kpod_metrics_catalog`."
    if total > max_series:
        out += f"\n\n_{total - max_series} more series truncated; aggregate with sum by (...) or topk()._"
    return out


def _fmt_labels(labels: dict[str, str]) -> str:
    name = labels.get("__name__", "")
    rest = ", ".join(f'{k}="{v}"' for k, v in sorted(labels.items()) if k != "__name__" and not k.startswith("label_"))
    return f"{name}{{{rest}}}" if rest or name else "{}"


def catalog(search: str | None) -> str:
    rows = [list(m) for m in METRICS if not search or search.lower() in " ".join(m).lower()]
    sigs = [[s.name, s.title, s.unit, fmt.value(s.threshold, s.unit) if s.threshold is not None else "–"]
            for s in SIGNALS.values() if not search or search.lower() in (s.name + s.title + s.help).lower()]
    out = [
        "# kpod-metrics catalog",
        f"Common labels on every pod metric: `{COMMON}`. Prometheus Operator without `honorLabels` renames "
        "namespace/pod/container to `exported_*`.",
        "Latency summaries have **no histogram buckets**: use `rate(x_sum)/rate(x_count)` for a mean; "
        "`histogram_quantile` will return nothing.",
        "",
        "## Metrics",
        fmt.table(["Name", "Type", "Extra labels", "Meaning"], rows) if rows else "_No metric matches._",
        "",
        "## Pre-built signals (for `kpod_top`)",
        fmt.table(["Signal", "Title", "Unit", "Threshold"], sigs) if sigs else "_No signal matches._",
    ]
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Agent health
# ---------------------------------------------------------------------------


async def agent_status(ctx: Ctx) -> str:
    agents = await ctx.agents.list()
    if not agents:
        return (f"No kpod-metrics pods found with selector `{ctx.agents.settings.kpod_selector}`"
                f"{' in ' + ctx.agents.settings.kpod_namespace if ctx.agents.settings.kpod_namespace else ''}.")
    sem = asyncio.Semaphore(8)

    async def diag(a):
        async with sem:
            return await ctx.agents.actuator(a, "kpodDiagnostics")

    results = await asyncio.gather(*(diag(a) for a in agents), return_exceptions=True)
    rows, problems, recs = [], [], set()
    for a, d in sorted(zip(agents, results), key=lambda p: p[0].node):
        if isinstance(d, Exception):
            rows.append([a.node, a.name, "✓" if a.ready else "✗", "–", "–", "–", "–", "unreachable"])
            problems.append(f"`{a.node}`: diagnostics unreachable — {d}")
            continue
        bpf = d.get("bpf", {})
        failed = bpf.get("failedPrograms") or []
        errors = d.get("lastCollectorErrors") or {}
        silent = (d.get("metricHealth") or {}).get("silentPrograms") or []
        rows.append([
            a.node, a.name, "✓" if a.ready else "✗", d.get("uptime", "?"),
            str(d.get("monitoredPods", "?")),
            f"{len(bpf.get('loadedPrograms') or [])} ok / {len(failed)} failed" if bpf.get("available") else "BPF off",
            str(len(errors)), ", ".join(silent) or "–",
        ])
        if failed:
            problems.append(f"`{a.node}`: BPF programs failed to load: {', '.join(map(str, failed))}")
        for c, e in errors.items():
            problems.append(f"`{a.node}`: collector `{c}` — {e}")
        recs.update(d.get("recommendations") or [])
    out = [f"# kpod-metrics agents ({len(agents)})",
           fmt.table(["Node", "Pod", "Ready", "Uptime", "Pods", "BPF", "Collector errors", "Silent programs"], rows)]
    if problems:
        out += ["", "## Problems", *[f"- {p}" for p in problems]]
    if recs:
        out += ["", "## Agent recommendations", *[f"- {r}" for r in sorted(recs)]]
    return "\n".join(out)
