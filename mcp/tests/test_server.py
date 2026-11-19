import os
import shutil

from conftest import s
from mcp import Client, StdioServerParameters

from kpod_mcp.backend import BackendError
from kpod_mcp.server import build


async def test_tools_are_read_only_and_signal_is_an_enum(ctx):
    m = build(ctx=ctx)
    tools = {t.name: t for t in await m.list_tools()}
    assert set(tools) == {"kpod_overview", "kpod_pod_report", "kpod_top", "kpod_dependencies",
                          "kpod_query", "kpod_metrics_catalog", "kpod_agent_status"}
    assert all(t.annotations.read_only_hint for t in tools.values())
    sig = tools["kpod_top"].input_schema["properties"]["signal"]
    assert "cpu_throttling" in sig["enum"]


async def test_call_tool_end_to_end(ctx, prom):
    prom.on(r"kpod_cpu_throttled_periods_total", [s(0.6)])
    m = build(ctx=ctx)
    r = await m.call_tool("kpod_top", {"signal": "cpu_throttling", "namespace": "shop"})
    assert not r.is_error
    assert "60.0%" in r.content[0].text and "⚠" in r.content[0].text


async def test_invalid_input_reaches_the_model_as_readable_tool_error(ctx, prom):
    # Through the real protocol path (in-memory client), not just the Python API.
    async with Client(build(ctx=ctx)) as client:
        r = await client.call_tool("kpod_pod_report", {"namespace": "shop", "pod": 'x"} or vector(1)'})
        assert r.is_error
        assert "DNS-1123" in r.content[0].text
        assert not any("or vector" in q for q, _ in prom.queries)  # rejected before reaching Prometheus

        r = await client.call_tool("kpod_top", {"signal": "not_a_signal"})
        assert r.is_error  # schema enum rejects it


async def test_backend_failure_is_actionable_not_generic(ctx, prom):
    async def boom(*a, **k):
        raise BackendError("Prometheus unreachable at http://p:9090")
    prom.instant = boom
    async with Client(build(ctx=ctx)) as client:
        r = await client.call_tool("kpod_overview", {})
        assert r.is_error and "Prometheus unreachable" in r.content[0].text


async def test_stdio_entrypoint_smoke():
    """Launch the real console script over stdio, as Claude Code / Desktop would."""
    exe = shutil.which("kpod-mcp")
    assert exe, "console script not installed (run uv sync)"
    env = {**os.environ, "KPOD_PROMETHEUS_URL": "http://127.0.0.1:9"}  # nothing listens on port 9
    async with Client(StdioServerParameters(command=exe, args=[], env=env)) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert "kpod_overview" in names
        r = await client.call_tool("kpod_metrics_catalog", {"search": "throttled"})
        assert not r.is_error and "kpod_cpu_throttled_periods_total" in r.content[0].text
        r = await client.call_tool("kpod_overview", {})
        assert r.is_error and "unreachable" in r.content[0].text


async def test_prompts_render(ctx):
    m = build(ctx=ctx)
    p = await m.get_prompt("diagnose_pod", {"namespace": "shop", "pod": "web-1"})
    assert 'kpod_pod_report(namespace="shop", pod="web-1"' in p.messages[0].content.text
