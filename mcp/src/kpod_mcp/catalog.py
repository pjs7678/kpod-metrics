"""What kpod-metrics exports, as PromQL the assistant can rely on.

Names here are the *Prometheus exposition* names (Micrometer appends `_seconds` for
summaries with a time base unit and `_total` for counters). They were verified against
Micrometer's PrometheusMeterRegistry output, not guessed from the Kotlin meter names.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from string import Template

from .backend import Labels

# ---------------------------------------------------------------------------
# Input validation — everything interpolated into PromQL goes through these.
# ---------------------------------------------------------------------------

_K8S_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
_DURATION = re.compile(r"^\d+[smhdw]$")
_DURATION_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def k8s_name(value: str, what: str) -> str:
    if not _K8S_NAME.match(value):
        raise ValueError(f"Invalid {what} '{value}': must be a Kubernetes DNS-1123 name.")
    return value


def duration(value: str) -> str:
    if not _DURATION.match(value):
        raise ValueError(f"Invalid duration '{value}': use e.g. 5m, 1h, 2d.")
    return value


def duration_seconds(value: str) -> int:
    duration(value)
    return int(value[:-1]) * _DURATION_SECONDS[value[-1]]


def selector(labels: Labels, namespace: str | None = None, pod: str | None = None) -> str:
    """Label matchers (without braces). Always non-empty so templates can append `,x="y"`."""
    parts = [f'{labels.pod}!=""']
    if namespace:
        parts.append(f'{labels.namespace}="{k8s_name(namespace, "namespace")}"')
    if pod:
        parts.append(f'{labels.pod}="{k8s_name(pod, "pod")}"')
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# Signals: named, pre-built queries with a unit and an "unhealthy" threshold.
# Template vars: $sel (matchers), $w (range window), $by (namespace,pod,container labels)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Signal:
    name: str
    title: str
    template: str
    unit: str  # cores | ratio | bytes | Bps | per_s | seconds | s_per_s | count
    threshold: float | None  # value at/above which it is flagged; None = informational
    help: str
    requires: str = ""  # collector/profile note shown when the signal has no data

    def promql(self, labels: Labels, sel: str, window: str) -> str:
        return Template(self.template).substitute(sel=sel, w=window, by=labels.by)


def _ratio(num: str, den: str) -> str:
    return f"(sum by ($by) ({num}) / sum by ($by) ({den}))"


def _avg(metric: str, extra: str = "") -> str:
    m = f"{metric}{{$sel{extra}}}"
    return _ratio(f"rate({m.replace('{', '_sum{', 1)}[$w])", f"rate({m.replace('{', '_count{', 1)}[$w])")


_L7 = {
    "redis": "Redis",
    "mysql": "MySQL",
    "kafka": "Kafka",
    "mongo": "MongoDB",
}

SIGNALS: dict[str, Signal] = {
    s.name: s
    for s in [
        Signal(
            "cpu_usage", "CPU usage",
            "sum by ($by) (rate(kpod_cpu_usage_seconds_total{$sel}[$w]))",
            "cores", None, "CPU cores consumed (cgroup cpu.stat).", "cpuCgroup collector",
        ),
        Signal(
            "cpu_limit_utilization", "CPU usage / limit",
            "(sum by ($by) (rate(kpod_cpu_usage_seconds_total{$sel}[$w])) / max by ($by) (kpod_cpu_limit_cores{$sel}))",
            "ratio", 0.8, "Fraction of the CPU limit used. Containers without a limit are absent.",
            "cpuCgroup collector",
        ),
        Signal(
            "cpu_throttling", "CPU throttled periods",
            "(" + _ratio("rate(kpod_cpu_throttled_periods_total{$sel}[$w])", "rate(kpod_cpu_periods_total{$sel}[$w])") + " > 0)",
            "ratio", 0.25,
            "Fraction of CFS periods in which the container hit its quota. >25% usually means added latency "
            "even when average CPU looks low (bursty workloads).",
            "cpuCgroup collector",
        ),
        Signal(
            "cpu_pressure", "CPU stall (PSI some)",
            'sum by ($by) (rate(kpod_pressure_stall_seconds_total{$sel, resource="cpu", kind="some"}[$w]))',
            "ratio", 0.2, "Fraction of wall time some task waited for CPU (runqueue or throttling).",
            "pressure collector, cgroup v2",
        ),
        Signal(
            "memory_pressure", "Memory stall (PSI some)",
            'sum by ($by) (rate(kpod_pressure_stall_seconds_total{$sel, resource="memory", kind="some"}[$w]))',
            "ratio", 0.05, "Fraction of wall time stalled on memory reclaim/swap/refault. Precedes OOM.",
            "pressure collector, cgroup v2",
        ),
        Signal(
            "io_pressure", "IO stall (PSI some)",
            'sum by ($by) (rate(kpod_pressure_stall_seconds_total{$sel, resource="io", kind="some"}[$w]))',
            "ratio", 0.1, "Fraction of wall time stalled on block IO.", "pressure collector, cgroup v2",
        ),
        Signal(
            "runqueue_wait", "Runqueue wait",
            "sum by ($by) (rate(kpod_cpu_runqueue_latency_seconds_sum{$sel}[$w]))",
            "s_per_s", 0.1,
            "Seconds spent runnable-but-not-running per second (eBPF sched_switch). Approximates CPU contention "
            "from noisy neighbours.",
            "cpu (eBPF) collector",
        ),
        Signal(
            "memory_rss", "Memory RSS",
            "max by ($by) (kpod_mem_cgroup_rss_bytes{$sel})",
            "bytes", None, "Anonymous (non-reclaimable) memory.", "memory collector",
        ),
        Signal(
            "memory_limit_utilization", "Memory RSS / limit",
            "(max by ($by) (kpod_mem_cgroup_rss_bytes{$sel}) / max by ($by) (kpod_mem_cgroup_limit_bytes{$sel}))",
            "ratio", 0.85, "OOM risk: RSS cannot be reclaimed, so at 100% the container is OOM-killed.",
            "memory collector",
        ),
        Signal(
            "memory_usage", "Memory usage (incl. cache)",
            "max by ($by) (kpod_mem_cgroup_usage_bytes{$sel})",
            "bytes", None, "memory.current — includes reclaimable page cache.", "memory collector",
        ),
        Signal(
            "tcp_retransmits", "TCP retransmits",
            "sum by ($by) (rate(kpod_net_tcp_retransmits_total{$sel}[$w]))",
            "per_s", 1.0, "Retransmitted segments/s — packet loss or congestion on the path.", "network collector",
        ),
        Signal(
            "tcp_drops", "TCP drops",
            "sum by ($by) (rate(kpod_net_tcp_drops_total{$sel}[$w]))",
            "per_s", 0.5, "Packets dropped by the kernel TCP stack (backlog full, memory, policy).",
            "tcpdrop collector",
        ),
        Signal(
            "tcp_rtt", "TCP RTT (avg)",
            _avg("kpod_net_tcp_rtt_seconds"),
            "seconds", 0.05, "Smoothed RTT averaged across connections.", "network collector",
        ),
        Signal(
            "net_rx", "Network RX",
            "sum by ($by) (rate(kpod_net_iface_rx_bytes_total{$sel}[$w]))",
            "Bps", None, "Pod network namespace receive bytes/s (same for all containers of a pod).",
            "ifaceNet collector",
        ),
        Signal(
            "net_tx", "Network TX",
            "sum by ($by) (rate(kpod_net_iface_tx_bytes_total{$sel}[$w]))",
            "Bps", None, "Pod network namespace transmit bytes/s.", "ifaceNet collector",
        ),
        Signal(
            "disk_read", "Disk read",
            "sum by ($by) (rate(kpod_disk_read_bytes_total{$sel}[$w]))",
            "Bps", None, "Block device read bytes/s (cgroup io.stat).", "diskIO collector",
        ),
        Signal(
            "disk_write", "Disk write",
            "sum by ($by) (rate(kpod_disk_written_bytes_total{$sel}[$w]))",
            "Bps", None, "Block device write bytes/s.", "diskIO collector",
        ),
        Signal(
            "http_rps", "HTTP requests",
            "sum by ($by) (rate(kpod_http_requests_total{$sel}[$w]))",
            "per_s", None, "HTTP/1.x requests/s seen by eBPF (client + server).", "http collector",
        ),
        Signal(
            "http_error_ratio", "HTTP 5xx ratio",
            "(" + _ratio('rate(kpod_http_requests_total{$sel, status_code=~"5.."}[$w])',
                         "rate(kpod_http_requests_total{$sel}[$w])") + " > 0)",
            "ratio", 0.01, "Share of HTTP responses with status 5xx.", "http collector",
        ),
        Signal(
            "http_latency", "HTTP latency (avg)",
            _avg("kpod_http_request_duration_seconds"),
            "seconds", 0.5, "Average HTTP latency (eBPF, request→response).", "http collector",
        ),
        Signal(
            "dns_errors", "DNS errors",
            "sum by ($by) (rate(kpod_dns_errors_total{$sel}[$w]))",
            "per_s", 0.1, "DNS responses with an error rcode (NXDOMAIN, SERVFAIL, ...).", "dns collector",
        ),
        Signal(
            "dns_latency", "DNS latency (avg)",
            _avg("kpod_dns_latency_seconds"),
            "seconds", 0.1, "Average DNS resolution latency.", "dns collector",
        ),
        *[
            s
            for proto, title in _L7.items()
            for s in (
                Signal(
                    f"{proto}_error_ratio", f"{title} error ratio",
                    "(" + _ratio(f"rate(kpod_{proto}_errors_total{{$sel}}[$w])",
                                 f"rate(kpod_{proto}_requests_total{{$sel}}[$w])") + " > 0)",
                    "ratio", 0.01, f"Share of {title} requests that returned an error.", f"{proto} collector",
                ),
                Signal(
                    f"{proto}_latency", f"{title} latency (avg)",
                    _avg(f"kpod_{proto}_request_duration_seconds"),
                    "seconds", 0.1, f"Average {title} request latency.", f"{proto} collector",
                ),
            )
        ],
        Signal(
            "restarts", "Container restarts",
            "max by ($by) (increase(kpod_container_restarts{$sel}[$w]))",
            "count", 1.0, "Restarts within the window (from the Kubernetes API).", "always on",
        ),
    ]
}

# Signals shown in the cluster overview: the ones with a meaningful "unhealthy" threshold.
OVERVIEW_SIGNALS = [
    "cpu_throttling", "cpu_pressure", "cpu_limit_utilization", "runqueue_wait",
    "memory_limit_utilization", "memory_pressure", "io_pressure",
    "tcp_retransmits", "tcp_drops", "http_error_ratio", "http_latency",
    "dns_errors", "redis_error_ratio", "mysql_error_ratio", "kafka_error_ratio", "mongo_error_ratio",
    "restarts",
]

# Signals in a single-pod report, grouped.
POD_REPORT_GROUPS: list[tuple[str, list[str]]] = [
    ("CPU", ["cpu_usage", "cpu_limit_utilization", "cpu_throttling", "cpu_pressure", "runqueue_wait"]),
    ("Memory", ["memory_rss", "memory_usage", "memory_limit_utilization", "memory_pressure"]),
    ("Disk", ["disk_read", "disk_write", "io_pressure"]),
    ("Network", ["net_rx", "net_tx", "tcp_retransmits", "tcp_drops", "tcp_rtt"]),
    ("Protocols", [
        "http_rps", "http_error_ratio", "http_latency", "dns_errors", "dns_latency",
        "redis_error_ratio", "redis_latency", "mysql_error_ratio", "mysql_latency",
        "kafka_error_ratio", "kafka_latency", "mongo_error_ratio", "mongo_latency",
    ]),
    ("Lifecycle", ["restarts"]),
]

# Plotted as sparklines in the pod report.
TREND_SIGNALS = ["cpu_usage", "cpu_throttling", "memory_rss", "tcp_retransmits", "http_rps", "http_latency"]


# ---------------------------------------------------------------------------
# Metric catalog (for the assistant writing its own PromQL)
# ---------------------------------------------------------------------------

COMMON = "namespace, pod, container, node, label_<pod label>"

METRICS: list[tuple[str, str, str, str]] = [
    # name, type, extra labels, description
    ("kpod_cpu_usage_seconds_total", "counter", "", "CPU time (cgroup). rate() = cores."),
    ("kpod_cpu_throttled_seconds_total", "counter", "", "Time throttled by CFS quota."),
    ("kpod_cpu_throttled_periods_total", "counter", "", "CFS periods throttled."),
    ("kpod_cpu_periods_total", "counter", "", "CFS periods elapsed."),
    ("kpod_cpu_limit_cores", "gauge", "", "CPU limit; absent if unlimited."),
    ("kpod_cpu_runqueue_latency_seconds_{sum,count,max}", "summary", "",
     "eBPF runqueue wait. Each sample = total wait of one collection cycle, so rate(_sum) = wait s/s; "
     "_sum/_count is NOT per-event latency. No _bucket series."),
    ("kpod_cpu_context_switches_total", "counter", "", "Context switches."),
    ("kpod_pressure_stall_seconds_total", "counter", "resource=cpu|memory|io, kind=some|full",
     "PSI stall time. rate() = stalled fraction of wall time."),
    ("kpod_mem_cgroup_usage_bytes", "gauge", "", "memory.current (includes page cache)."),
    ("kpod_mem_cgroup_rss_bytes", "gauge", "", "Anonymous memory."),
    ("kpod_mem_cgroup_limit_bytes", "gauge", "", "Memory limit; absent if unlimited."),
    ("kpod_mem_cgroup_{peak,cache,swap}_bytes", "gauge", "", "Peak / page cache / swap."),
    ("kpod_disk_{read,written}_bytes_total, kpod_disk_{reads,writes}_total", "counter", "device", "cgroup io.stat."),
    ("kpod_disk_io_latency_seconds_{sum,count,max}", "summary", "", "eBPF block IO latency (comprehensive profile)."),
    ("kpod_net_iface_{rx,tx}_{bytes,packets,errors,drops}_total", "counter", "interface", "Pod netns /proc/net/dev."),
    ("kpod_net_tcp_{retransmits,connections,drops}_total", "counter", "", "eBPF TCP events."),
    ("kpod_net_tcp_rtt_seconds_{sum,count,max}", "summary", "", "Per-cycle average smoothed RTT."),
    ("kpod_net_tcp_peer_connections_total", "counter", "remote_ip, remote_port, remote_pod, remote_service",
     "Outbound connections per peer — the service dependency graph."),
    ("kpod_net_tcp_peer_rtt_seconds_{sum,count,max}", "summary", "remote_*", "RTT per peer."),
    ("kpod_http_requests_total", "counter", "method, status_code, direction", "eBPF HTTP/1.x."),
    ("kpod_http_request_duration_seconds_{sum,count,max}", "summary", "method, direction",
     "Per-cycle average latency; _sum/_count = mean of averages."),
    ("kpod_{redis,mysql,kafka,mongo}_requests_total", "counter", "command/op labels vary", "L7 request counts."),
    ("kpod_{redis,mysql,kafka,mongo}_errors_total", "counter", "", "L7 error counts."),
    ("kpod_{redis,mysql,kafka,mongo}_request_duration_seconds_{sum,count,max}", "summary", "", "L7 latency."),
    ("kpod_dns_requests_total", "counter", "qtype", "DNS queries."),
    ("kpod_dns_errors_total", "counter", "", "DNS error responses."),
    ("kpod_dns_latency_seconds_{sum,count,max}", "summary", "", "DNS latency."),
    ("kpod_dns_top_domains_total", "counter", "domain", "Queried domains (capped)."),
    ("kpod_syscall_{count,errors}_total", "counter", "syscall", "Comprehensive profile."),
    ("kpod_proc_{execs,forks,exits}_total", "counter", "", "Process lifecycle (eBPF)."),
    ("kpod_container_restarts", "gauge", "", "Restart count from the Kubernetes API."),
    ("kpod_container_application", "gauge (=1)", "application", "Detected software (postgres, redis, java, ...)."),
    ("kpod_fs_{capacity,usage,available}_bytes", "gauge", "mountpoint", "Container filesystems."),
    ("kpod_collector_errors_total, kpod_collector_duration_seconds", "self", "collector", "Agent health."),
]
