import pytest

from kpod_mcp.backend import EXPORTED_LABELS, Labels
from kpod_mcp.catalog import SIGNALS, duration, duration_seconds, k8s_name, selector


def _balanced(q: str) -> bool:
    pairs = {")": "(", "]": "[", "}": "{"}
    stack = []
    in_str = False
    for ch in q:
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch in "([{":
            stack.append(ch)
        elif ch in pairs:
            if not stack or stack.pop() != pairs[ch]:
                return False
    return not stack and not in_str


@pytest.mark.parametrize("name", list(SIGNALS))
@pytest.mark.parametrize("labels", [Labels(), EXPORTED_LABELS])
def test_every_signal_renders_structurally_valid_promql(name, labels):
    q = SIGNALS[name].promql(labels, selector(labels, "shop", "web-1"), "5m")
    assert "$" not in q, q
    assert _balanced(q), q
    assert "{," not in q and ",}" not in q, q
    assert "[5m]" in q or "kpod_mem" in q or "kpod_container" in q, q
    # every metric selector carries the pod filter
    assert q.count(f'{labels.pod}="web-1"') >= q.count("kpod_"), q
    # aggregations keep pod identity so results can be attributed
    assert labels.pod in q.split("by (", 1)[1] if "by (" in q else True


def test_metric_names_use_prometheus_exposition_names():
    # Verified against Micrometer PrometheusMeterRegistry: seconds-unit summaries get _seconds, counters _total.
    q = SIGNALS["http_latency"].promql(Labels(), selector(Labels()), "5m")
    assert "kpod_http_request_duration_seconds_sum" in q and "kpod_http_request_duration_seconds_count" in q
    assert "kpod_cpu_runqueue_latency_seconds_sum" in SIGNALS["runqueue_wait"].template
    # Quantiles only over the four kernel histograms; protocol latencies are summaries without buckets.
    bucketed = {n for n, s in SIGNALS.items() if "_bucket" in s.template}
    assert bucketed == {"runqueue_p99", "tcp_rtt_p99", "disk_io_p99"}
    for n in bucketed:
        assert "sum by (" in SIGNALS[n].template and ", le)" in SIGNALS[n].template


@pytest.mark.parametrize("bad", ['web"}) or vector(1', "Web", "a b", "x" * 300, "-x"])
def test_names_are_validated_before_entering_promql(bad):
    with pytest.raises(ValueError):
        selector(Labels(), namespace="ok", pod=bad)


def test_durations():
    assert duration_seconds("15m") == 900
    assert duration_seconds("2d") == 172800
    for bad in ["15", "1h30m", "5m]) or vector(1", "-1m"]:
        with pytest.raises(ValueError):
            duration(bad)


def test_selector_always_non_empty():
    assert selector(Labels()) == 'pod!=""'
    assert selector(EXPORTED_LABELS, "shop") == 'exported_pod!="", exported_namespace="shop"'
    assert k8s_name("a.b-c", "x") == "a.b-c"
