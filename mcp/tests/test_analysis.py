from conftest import FakeProm, s

from kpod_mcp import analysis
from kpod_mcp.analysis import Ctx
from kpod_mcp.backend import EXPORTED_LABELS, Sample


async def test_overview_flags_sorted_by_severity_and_lists_missing_collectors(ctx, prom):
    prom.on(r"^count\(count by \(namespace, pod\)", [Sample({}, 12)])
    prom.on(r"^count\(count by \(node\)", [Sample({}, 3)])
    prom.on(r"kpod_cpu_throttled_periods_total", [s(0.5), s(0.1, pod="cart-5f6d7c8b9-abcd1")])
    prom.on(r"kpod_mem_cgroup_rss_bytes", [s(0.95, pod="cart-5f6d7c8b9-abcd1")])
    prom.on(r"kpod_net_tcp_retransmits_total", [s(0.2)])

    out = await analysis.overview(ctx, "shop", "15m", 5)

    assert "**12 pods** on **3 nodes**" in out
    findings = out.split("## ⚠ Findings")[1].split("**")[0]
    # throttling 0.5/0.25 = 2.0x ranks above memory 0.95/0.85 = 1.1x; 10% throttling is not flagged
    assert findings.index("CPU throttled") < findings.index("Memory RSS / limit")
    assert "10.0%" not in findings
    assert "TCP retransmits" in out.split("**Within thresholds:**")[1]
    assert "Redis error ratio (redis collector)" in out  # no data → named with its collector
    assert all('namespace="shop"' in q for q, _ in prom.queries)


async def test_overview_without_data_explains_why(ctx):
    out = await analysis.overview(ctx, None, "15m", 5)
    assert "No kpod data found" in out


async def test_overview_uses_exported_labels_when_renamed():
    prom = FakeProm(EXPORTED_LABELS)
    ctx = Ctx(prom=prom, agents=None)
    await analysis.overview(ctx, "shop", "5m", 3)
    q = next(q for q, _ in prom.queries if "throttled" in q)
    assert "by (exported_namespace, exported_pod, exported_container)" in q
    assert 'exported_namespace="shop"' in q


async def test_pod_report_sections_flags_and_compare(ctx, prom):
    prom.on(r"kpod_cpu_throttled_periods_total", [s(0.4)])
    prom.on(r"rate\(kpod_cpu_usage_seconds_total\{[^}]*\}\[1h\]\)\)$", [s(0.25)])
    prom.on(r"kpod_mem_cgroup_rss_bytes\{[^}]*\}\)$", [s(800 * 2**20)])
    prom.on(r"kpod_container_application", [s(1, application="java")])
    prom.on(r"kpod_net_tcp_peer_connections_total", [s(3.0, remote_service="cart", remote_port="8080")])
    prom.on(r"kpod_net_tcp_peer_rtt_seconds_sum", [s(0.002, remote_service="cart", remote_port="8080")])
    prom.on(r"kpod_http_requests_total\{[^}]*\}\[1h\]\)\) > 0$",
            [Sample({"method": "GET", "status_code": "500", "direction": "server"}, 2.0)])

    out = await analysis.pod_report(ctx, "shop", "checkout-7d9f8b6c5-x2x9p", "1h", "1d")

    assert "## Container `app` — detected: java" in out
    assert "| 1d ago |" in out
    assert "CPU throttled periods** = 40.0%" in out
    assert "| app | cart | 8080 | 3.00/s | 2.0ms |" in out
    assert "| server | GET | 500 | 2.00/s |" in out
    assert "## Trends" in out
    # comparison queries are evaluated one day earlier, not re-written with offset
    times = sorted({t for _, t in prom.queries if t is not None})
    assert len(times) == 2 and abs((times[1] - times[0]) - 86400) < 1


async def test_pod_report_unknown_pod_suggests_names(ctx, prom):
    prom.on(r"^group by \(pod\)", [Sample({"pod": "checkout-7d9f8b6c5-aaaa1"}, 1), Sample({"pod": "cart-1"}, 1)])
    out = await analysis.pod_report(ctx, "shop", "checkout-7d9f8b6c5-x2x9p", "1h", None)
    assert "No kpod data" in out and "`checkout-7d9f8b6c5-aaaa1`" in out and "cart-1" not in out


async def test_dependencies_group_into_workloads_with_mermaid(ctx, prom):
    prom.on(r"peer_connections_total", [
        s(2.0, pod="checkout-7d9f8b6c5-x2x9p", remote_service="cart", remote_port="8080"),
        s(1.0, pod="checkout-7d9f8b6c5-zzzz9", remote_service="cart", remote_port="8080"),
        s(0.5, pod="checkout-7d9f8b6c5-x2x9p", remote_pod="", remote_ip="10.0.0.9", remote_port="443"),
    ])
    out = await analysis.dependencies(ctx, "shop", None, "15m", "workload", 40)
    assert "```mermaid" in out
    assert '| shop/checkout | cart | 8080 | 3.00/s |' in out  # two replicas merged
    assert "external:10.0.0.9" in out


async def test_top_rejects_unknown_signal(ctx):
    import pytest
    with pytest.raises(ValueError, match="Unknown signal"):
        await analysis.top(ctx, "nope", None, "5m", 10, False)


def test_catalog_search():
    out = analysis.catalog("pressure")
    assert "kpod_pressure_stall_seconds_total" in out and "kpod_redis" not in out
    assert "histogram_quantile` will return nothing" in out


async def test_prometheus_outage_is_not_reported_as_missing_data(ctx, prom):
    import pytest
    from kpod_mcp.backend import BackendError

    async def boom(*a, **k):
        raise BackendError("Prometheus unreachable")
    prom.instant = boom
    with pytest.raises(BackendError):
        await analysis.overview(ctx, None, "15m", 5)
    with pytest.raises(BackendError):
        await analysis.pod_report(ctx, "shop", "web-1", "1h", None)
