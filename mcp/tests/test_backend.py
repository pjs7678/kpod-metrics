import json

import pytest

from kpod_mcp.backend import Agents, BackendError, Kubectl, Prometheus, Settings


class FakeKubectl(Kubectl):
    def __init__(self, responses: dict[str, str]):
        super().__init__(Settings())
        self.responses = responses
        self.calls: list[tuple[str, ...]] = []

    def available(self) -> bool:
        return True

    async def run(self, *args: str) -> str:
        self.calls.append(args)
        for key, val in self.responses.items():
            if key in " ".join(args):
                return val
        raise BackendError(f"unexpected kubectl {args}")


def _svc(ns, name, ports):
    return {"metadata": {"namespace": ns, "name": name}, "spec": {"ports": ports}}


async def test_discovers_preferred_prometheus_and_queries_via_api_proxy():
    services = {"items": [
        _svc("monitoring", "prometheus-operated", [{"name": "web", "port": 9090}]),
        _svc("monitoring", "kube-prometheus-stack-prometheus", [{"name": "reloader", "port": 8080},
                                                                {"name": "http-web", "port": 9090}]),
    ]}
    k = FakeKubectl({
        "get services": json.dumps(services),
        "/api/v1/query?": json.dumps({"status": "success", "data": {"resultType": "vector", "result": [
            {"metric": {"pod": "a"}, "value": [1, "0.5"]}]}}),
    })
    p = Prometheus(Settings(), k)
    r = await p.instant('up{job="x"}')
    assert r[0].labels == {"pod": "a"} and r[0].value == 0.5
    raw = next(c for c in k.calls if c[:2] == ("get", "--raw"))[2]
    assert raw.startswith("/api/v1/namespaces/monitoring/services/kube-prometheus-stack-prometheus:9090/proxy/api/v1/query?")
    assert "query=up%7Bjob%3D%22x%22%7D" in raw


async def test_explicit_service_and_error_surface():
    k = FakeKubectl({"--raw": json.dumps({"status": "error", "errorType": "bad_data", "error": "parse error"})})
    p = Prometheus(Settings(prometheus_service="mon/prom:9090"), k)
    with pytest.raises(BackendError, match="parse error"):
        await p.instant("((")
    assert await p.describe() == "kubectl API proxy: /api/v1/namespaces/mon/services/prom:9090/proxy"


async def test_bad_service_spec():
    with pytest.raises(BackendError, match="namespace>/<service>:<port>"):
        await Prometheus(Settings(prometheus_service="prom"), FakeKubectl({})).instant("up")


async def test_no_prometheus_found_gives_actionable_error():
    p = Prometheus(Settings(), FakeKubectl({"get services": json.dumps({"items": []})}))
    with pytest.raises(BackendError, match="KPOD_PROMETHEUS_URL"):
        await p.instant("up")


async def test_label_mode_detection():
    vector = lambda v: json.dumps({"status": "success", "data": {"resultType": "vector",
                                   "result": [{"metric": {}, "value": [1, v]}] if v else []}})
    p = Prometheus(Settings(prometheus_service="m/p:1"), FakeKubectl({"--raw": vector("4")}))
    assert (await p.labels()).pod == "exported_pod"
    p = Prometheus(Settings(prometheus_service="m/p:1"), FakeKubectl({"--raw": vector(None)}))
    assert (await p.labels()).pod == "pod"


async def test_agents_listing_and_actuator_path():
    pods = {"items": [{"metadata": {"name": "kpod-abc", "namespace": "kpod"}, "spec": {"nodeName": "n1"},
                       "status": {"conditions": [{"type": "Ready", "status": "True"}]}}]}
    k = FakeKubectl({"get pods": json.dumps(pods), "/proxy/actuator/kpodDiagnostics": json.dumps({"uptime": "1h"})})
    a = Agents(Settings(kpod_namespace="kpod"), k)
    [pod] = await a.list()
    assert pod.ready and pod.node == "n1"
    assert (await a.actuator(pod, "kpodDiagnostics"))["uptime"] == "1h"
    assert ("get", "pods", "-n", "kpod", "-l", "app.kubernetes.io/name=kpod-metrics", "-o", "json") in k.calls


def test_settings_from_env():
    st = Settings.from_env({"KPOD_PROMETHEUS_URL": "http://p:9090/", "KPOD_PROMETHEUS_BEARER_TOKEN": "t"})
    assert st.prometheus_url == "http://p:9090"
    assert st.prometheus_headers == {"Authorization": "Bearer t"}
