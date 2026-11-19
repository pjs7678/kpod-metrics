"""Compact, LLM- and human-readable rendering."""

from __future__ import annotations

import math
import re

_SPARK = "▁▂▃▄▅▆▇█"


def value(v: float, unit: str) -> str:
    if v is None or math.isnan(v):
        return "–"
    if math.isinf(v):
        return "∞"
    match unit:
        case "ratio":
            return f"{v * 100:.1f}%"
        case "cores":
            return f"{v:.3f} cores" if v < 10 else f"{v:.1f} cores"
        case "bytes":
            return _si(v, 1024, ["B", "KiB", "MiB", "GiB", "TiB"])
        case "Bps":
            return _si(v, 1024, ["B/s", "KiB/s", "MiB/s", "GiB/s"])
        case "per_s":
            return f"{v:.2f}/s" if v < 100 else f"{v:,.0f}/s"
        case "seconds":
            if v < 1e-3:
                return f"{v * 1e6:.0f}µs"
            if v < 1:
                return f"{v * 1e3:.1f}ms"
            return f"{v:.2f}s"
        case "s_per_s":
            return f"{v:.3f}s/s"
        case "count":
            return f"{v:.0f}"
    return f"{v:.4g}"


def _si(v: float, base: int, units: list[str]) -> str:
    i = 0
    while abs(v) >= base and i < len(units) - 1:
        v /= base
        i += 1
    return f"{v:.0f} {units[i]}" if i == 0 else f"{v:.1f} {units[i]}"


def sparkline(values: list[float]) -> str:
    vals = [v for v in values if not math.isnan(v)]
    if not vals:
        return ""
    lo, hi = min(vals), max(vals)
    if hi == lo:
        return _SPARK[0] * len(values)
    return "".join(
        " " if math.isnan(v) else _SPARK[min(len(_SPARK) - 1, int((v - lo) / (hi - lo) * (len(_SPARK) - 1) + 0.5))]
        for v in values
    )


def table(headers: list[str], rows: list[list[str]]) -> str:
    def esc(c: str) -> str:
        return str(c).replace("|", "\\|").replace("\n", " ")

    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


# ReplicaSet pods: <deployment>-<pod-template-hash 6-10>-<5>, DaemonSet/Job pods: <name>-<5>.
# StatefulSet ordinals (-0, -1) are kept: each replica is a distinct identity.
_RS_SUFFIX = re.compile(r"-[a-z0-9]{6,10}-[a-z0-9]{5}$")
_SHORT_SUFFIX = re.compile(r"-[a-z0-9]{5}$")


def workload(pod: str) -> str:
    if not pod:
        return pod
    # Generated suffixes almost always contain a digit; requiring one keeps hand-written
    # names such as "cart-service-redis" or "my-redis" intact (false merges are worse than misses).
    for pattern in (_RS_SUFFIX, _SHORT_SUFFIX):
        m = pattern.search(pod)
        if m and any(ch.isdigit() for ch in m.group()):
            return pod[: m.start()]
    return pod


def mermaid_id(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", name) or "_"
