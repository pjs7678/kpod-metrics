from __future__ import annotations

import re
from typing import Callable

import pytest

from kpod_mcp.analysis import Ctx
from kpod_mcp.backend import Agents, Kubectl, Labels, Prometheus, Sample, Series, Settings

Handler = Callable[[str], list[Sample] | None]


class FakeProm(Prometheus):
    """Answers queries by regex rules; records every query so tests can assert on PromQL."""

    def __init__(self, labels: Labels = Labels()):
        super().__init__(Settings(), Kubectl(Settings()))
        self._fixed_labels = labels
        self.rules: list[tuple[re.Pattern, list[Sample]]] = []
        self.queries: list[tuple[str, float | None]] = []
        self.range_queries: list[str] = []

    def on(self, pattern: str, samples: list[Sample]) -> "FakeProm":
        self.rules.append((re.compile(pattern), samples))
        return self

    async def labels(self) -> Labels:
        return self._fixed_labels

    async def instant(self, query: str, at: float | None = None) -> list[Sample]:
        self.queries.append((query, at))
        for pat, samples in self.rules:
            if pat.search(query):
                return samples
        return []

    async def range(self, query: str, start: float, end: float, step_s: float) -> list[Series]:
        self.range_queries.append(query)
        for pat, samples in self.rules:
            if pat.search(query):
                return [Series(s.labels, [(start + i * step_s, s.value * (1 + i / 10)) for i in range(10)])
                        for s in samples]
        return []


def s(value: float, ns: str = "shop", pod: str = "checkout-7d9f8b6c5-x2x9p", container: str = "app", **extra) -> Sample:
    return Sample({"namespace": ns, "pod": pod, "container": container, **extra}, value)


@pytest.fixture
def prom() -> FakeProm:
    return FakeProm()


@pytest.fixture
def ctx(prom: FakeProm) -> Ctx:
    return Ctx(prom=prom, agents=Agents(Settings(), Kubectl(Settings())))
