"""`kpod-mcp` entry point: MCP server (default) or the same analyses printed to the terminal."""

from __future__ import annotations

import argparse
import asyncio
import shutil
import sys

from . import __version__, analysis
from .backend import Agents, BackendError, Kubectl, Prometheus, Settings


def _ctx(settings: Settings) -> analysis.Ctx:
    k = Kubectl(settings)
    return analysis.Ctx(prom=Prometheus(settings, k), agents=Agents(settings, k))


async def _doctor(settings: Settings) -> int:
    ok = True

    def line(good: bool, msg: str) -> None:
        nonlocal ok
        ok &= good
        print(("✓ " if good else "✗ ") + msg)

    line(shutil.which("kubectl") is not None or bool(settings.prometheus_url),
         "kubectl on PATH" if shutil.which("kubectl") else "kubectl missing (fine if KPOD_PROMETHEUS_URL is set)")
    ctx = _ctx(settings)
    try:
        print(f"  Prometheus: {await ctx.prom.describe()}")
        n = await ctx.prom.instant('count(count by (__name__) ({__name__=~"kpod_.+"}))')
        count = int(n[0].value) if n else 0
        line(count > 0, f"{count} kpod metric names in Prometheus")
        labels = await ctx.prom.labels()
        line(labels.pod == "pod", f"pod label: `{labels.pod}`" + (
            "" if labels.pod == "pod" else " — set serviceMonitor honorLabels: true (handled automatically)"))
    except BackendError as e:
        line(False, f"Prometheus: {e}")
    try:
        agents = await ctx.agents.list()
        line(bool(agents), f"{len(agents)} kpod-metrics agent pods ({sum(a.ready for a in agents)} ready)")
    except BackendError as e:
        line(False, f"agents: {e}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="kpod-mcp", description="AI/MCP access to kpod-metrics.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("serve", help="Run the MCP server on stdio (default)")
    sub.add_parser("doctor", help="Check connectivity to Prometheus and the agents")
    o = sub.add_parser("overview", help="Print the health overview")
    o.add_argument("-n", "--namespace")
    o.add_argument("-w", "--window", default="15m")
    r = sub.add_parser("report", help="Print a pod report: report <namespace>/<pod>")
    r.add_argument("target")
    r.add_argument("-w", "--window", default="1h")
    r.add_argument("-c", "--compare")
    t = sub.add_parser("top", help="Rank pods by a signal")
    t.add_argument("signal")
    t.add_argument("-n", "--namespace")
    t.add_argument("-w", "--window", default="15m")
    t.add_argument("-k", "--limit", type=int, default=10)
    d = sub.add_parser("deps", help="Print the dependency graph")
    d.add_argument("-n", "--namespace")
    d.add_argument("-w", "--window", default="15m")
    sub.add_parser("agents", help="Print agent status")
    args = p.parse_args(argv)

    settings = Settings.from_env()
    if args.cmd in (None, "serve"):
        from .server import build
        build(settings).run("stdio")
        return

    ctx = _ctx(settings)
    try:
        match args.cmd:
            case "doctor":
                sys.exit(asyncio.run(_doctor(settings)))
            case "overview":
                out = asyncio.run(analysis.overview(ctx, args.namespace, args.window, 5))
            case "report":
                ns, _, pod = args.target.partition("/")
                if not pod:
                    p.error("target must be <namespace>/<pod>")
                out = asyncio.run(analysis.pod_report(ctx, ns, pod, args.window, args.compare))
            case "top":
                out = asyncio.run(analysis.top(ctx, args.signal, args.namespace, args.window, args.limit, False))
            case "deps":
                out = asyncio.run(analysis.dependencies(ctx, args.namespace, None, args.window, "workload", 40))
            case "agents":
                out = asyncio.run(analysis.agent_status(ctx))
    except (BackendError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    print(out)


if __name__ == "__main__":
    main()
