import math

import pytest

from kpod_mcp import format as fmt


@pytest.mark.parametrize("pod,expected", [
    ("checkout-7d9f8b6c5-x2x9p", "checkout"),
    ("fluent-bit-4k2xq", "fluent-bit"),
    ("redis-0", "redis-0"),                     # StatefulSet ordinal kept
    ("my-redis", "my-redis"),                   # no generated suffix
    ("cart-service-redis", "cart-service-redis"),  # word suffix, no digit → untouched
    ("api-abcdef-ghijk", "api-abcdef-ghijk"),   # looks generated but no digit → untouched
    ("", ""),
])
def test_workload(pod, expected):
    assert fmt.workload(pod) == expected


def test_values():
    assert fmt.value(0.256, "ratio") == "25.6%"
    assert fmt.value(1536 * 1024 * 1024, "bytes") == "1.5 GiB"
    assert fmt.value(0.0042, "seconds") == "4.2ms"
    assert fmt.value(0.0000042, "seconds") == "4µs"
    assert fmt.value(math.nan, "ratio") == "–"
    assert fmt.value(12345, "per_s") == "12,345/s"


def test_sparkline():
    assert fmt.sparkline([0, 1, 2, 3, 4, 5, 6, 7]) == "▁▂▃▄▅▆▇█"
    assert fmt.sparkline([3, 3, 3]) == "▁▁▁"
    assert fmt.sparkline([]) == ""


def test_table_escapes_pipes():
    assert "a\\|b" in fmt.table(["x"], [["a|b"]])
