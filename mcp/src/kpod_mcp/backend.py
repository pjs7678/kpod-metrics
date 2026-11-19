"""Data access: Prometheus (cluster-wide history) and kpod-metrics agents (live, per node).

Both are reachable either directly by URL or through the Kubernetes API server proxy
using the developer's own kubeconfig, so no port-forward is needed and the developer's
RBAC applies.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import httpx


class BackendError(RuntimeError):
    """A data source is unreachable or returned an error. Message is shown to the user/LLM."""


@dataclass
class Settings:
    prometheus_url: str | None = None
    # "<namespace>/<service>:<port>", reached through the API server service proxy
    prometheus_service: str | None = None
    kube_context: str | None = None
    kpod_namespace: str | None = None  # None = search all namespaces
    kpod_selector: str = "app.kubernetes.io/name=kpod-metrics"
    kpod_port: int = 9090
    timeout_s: float = 20.0
    prometheus_headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Settings":
        e = os.environ if env is None else env
        headers = {}
        if token := e.get("KPOD_PROMETHEUS_BEARER_TOKEN"):
            headers["Authorization"] = f"Bearer {token}"
        return cls(
            prometheus_url=(e.get("KPOD_PROMETHEUS_URL") or "").rstrip("/") or None,
            prometheus_service=e.get("KPOD_PROMETHEUS_SERVICE") or None,
            kube_context=e.get("KPOD_KUBE_CONTEXT") or None,
            kpod_namespace=e.get("KPOD_NAMESPACE") or None,
            kpod_selector=e.get("KPOD_SELECTOR", "app.kubernetes.io/name=kpod-metrics"),
            kpod_port=int(e.get("KPOD_PORT", "9090")),
            timeout_s=float(e.get("KPOD_TIMEOUT_S", "20")),
            prometheus_headers=headers,
        )


class Kubectl:
    def __init__(self, settings: Settings):
        self.settings = settings

    def available(self) -> bool:
        return shutil.which("kubectl") is not None

    async def run(self, *args: str) -> str:
        if not self.available():
            raise BackendError("kubectl not found on PATH (needed for in-cluster access).")
        cmd = ["kubectl"]
        if self.settings.kube_context:
            cmd += ["--context", self.settings.kube_context]
        cmd += list(args)
        # argv list, no shell: arguments are never interpreted by a shell.
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), self.settings.timeout_s)
        except asyncio.TimeoutError:
            proc.kill()
            raise BackendError(f"kubectl timed out after {self.settings.timeout_s:.0f}s: {' '.join(args[:3])}")
        if proc.returncode != 0:
            # client-go repeats retry noise; the last line is the most specific error.
            lines = [ln.strip() for ln in err.decode().splitlines() if ln.strip()]
            raise BackendError(f"kubectl {' '.join(args[:2])} failed: {(lines[-1] if lines else '')[:400]}")
        return out.decode()

    async def get_json(self, *args: str) -> Any:
        return json.loads(await self.run(*args, "-o", "json"))

    async def get_raw(self, path: str) -> str:
        return await self.run("get", "--raw", path)


# Ordered by preference. prometheus-operated is headless, so prefer the ClusterIP services.
KNOWN_PROMETHEUS_SERVICES = (
    "kube-prometheus-stack-prometheus",
    "prometheus-k8s",
    "prometheus-server",
    "prometheus",
    "prometheus-operated",
)


@dataclass(frozen=True)
class Labels:
    """Label names for pod identity. Prometheus Operator without honorLabels renames
    the exporter's namespace/pod/container to exported_* (target labels win)."""

    namespace: str = "namespace"
    pod: str = "pod"
    container: str = "container"

    @property
    def by(self) -> str:
        return f"{self.namespace}, {self.pod}, {self.container}"

    @property
    def by_pod(self) -> str:
        return f"{self.namespace}, {self.pod}"


EXPORTED_LABELS = Labels("exported_namespace", "exported_pod", "exported_container")


@dataclass
class Sample:
    labels: dict[str, str]
    value: float


@dataclass
class Series:
    labels: dict[str, str]
    values: list[tuple[float, float]]


class Prometheus:
    def __init__(self, settings: Settings, kubectl: Kubectl):
        self.settings = settings
        self.kubectl = kubectl
        self._proxy_base: str | None = None
        self._labels: Labels | None = None
        self._lock = asyncio.Lock()

    async def describe(self) -> str:
        if self.settings.prometheus_url:
            return f"direct: {self.settings.prometheus_url}"
        return f"kubectl API proxy: {await self._resolve_proxy()}"

    async def _resolve_proxy(self) -> str:
        if self._proxy_base:
            return self._proxy_base
        async with self._lock:
            if self._proxy_base:
                return self._proxy_base
            if spec := self.settings.prometheus_service:
                try:
                    ns, rest = spec.split("/", 1)
                    name, port = rest.rsplit(":", 1)
                except ValueError:
                    raise BackendError(
                        f"KPOD_PROMETHEUS_SERVICE must be '<namespace>/<service>:<port>', got '{spec}'"
                    )
            else:
                ns, name, port = await self._discover()
            self._proxy_base = f"/api/v1/namespaces/{ns}/services/{name}:{port}/proxy"
            return self._proxy_base

    async def _discover(self) -> tuple[str, str, str]:
        svcs = (await self.kubectl.get_json("get", "services", "--all-namespaces")).get("items", [])
        by_name: dict[str, dict] = {}
        for s in svcs:
            by_name.setdefault(s["metadata"]["name"], s)
        for name in KNOWN_PROMETHEUS_SERVICES:
            if s := by_name.get(name):
                ports = s["spec"].get("ports", [])
                port = next(
                    (p["port"] for p in ports if p.get("name") in ("http-web", "web", "http")),
                    ports[0]["port"] if ports else 9090,
                )
                return s["metadata"]["namespace"], name, str(port)
        raise BackendError(
            "Could not find Prometheus. Set KPOD_PROMETHEUS_URL (e.g. http://localhost:9090) "
            "or KPOD_PROMETHEUS_SERVICE (e.g. monitoring/prometheus-k8s:9090)."
        )

    async def _api(self, path: str, params: dict[str, Any]) -> Any:
        if self.settings.prometheus_url:
            try:
                async with httpx.AsyncClient(timeout=self.settings.timeout_s) as client:
                    r = await client.get(
                        f"{self.settings.prometheus_url}{path}",
                        params=params,
                        headers=self.settings.prometheus_headers,
                    )
            except httpx.HTTPError as e:
                raise BackendError(f"Prometheus unreachable at {self.settings.prometheus_url}: {e}")
            text = r.text
        else:
            base = await self._resolve_proxy()
            text = await self.kubectl.get_raw(f"{base}{path}?{urlencode(params)}")
        try:
            body = json.loads(text)
        except json.JSONDecodeError:
            raise BackendError(f"Prometheus returned non-JSON: {text[:200]}")
        if body.get("status") != "success":
            raise BackendError(f"Prometheus error: {body.get('errorType', '')} {body.get('error', text[:300])}")
        return body["data"]

    async def instant(self, query: str, at: float | None = None) -> list[Sample]:
        params: dict[str, Any] = {"query": query}
        if at is not None:
            params["time"] = f"{at:.3f}"
        data = await self._api("/api/v1/query", params)
        if data["resultType"] == "scalar":
            return [Sample({}, float(data["result"][1]))]
        if data["resultType"] != "vector":
            raise BackendError(f"Expected an instant vector, got {data['resultType']}")
        return [Sample(r["metric"], float(r["value"][1])) for r in data["result"]]

    async def range(self, query: str, start: float, end: float, step_s: float) -> list[Series]:
        data = await self._api(
            "/api/v1/query_range",
            {"query": query, "start": f"{start:.3f}", "end": f"{end:.3f}", "step": f"{max(step_s, 1):.0f}s"},
        )
        return [Series(r["metric"], [(float(t), float(v)) for t, v in r["values"]]) for r in data["result"]]

    async def labels(self) -> Labels:
        """Detect whether kpod's pod labels survived scraping or were renamed to exported_*."""
        if self._labels is None:
            exported = await self.instant('count({__name__=~"kpod_.+", exported_pod!=""})')
            self._labels = EXPORTED_LABELS if exported and exported[0].value > 0 else Labels()
        return self._labels


@dataclass
class AgentPod:
    name: str
    namespace: str
    node: str
    ready: bool


class Agents:
    """kpod-metrics DaemonSet pods, reached through the API server pod proxy."""

    def __init__(self, settings: Settings, kubectl: Kubectl):
        self.settings = settings
        self.kubectl = kubectl

    async def list(self) -> list[AgentPod]:
        scope = ["-n", self.settings.kpod_namespace] if self.settings.kpod_namespace else ["--all-namespaces"]
        data = await self.kubectl.get_json("get", "pods", *scope, "-l", self.settings.kpod_selector)
        pods = []
        for p in data.get("items", []):
            conds = {c["type"]: c["status"] for c in p.get("status", {}).get("conditions", [])}
            pods.append(
                AgentPod(
                    name=p["metadata"]["name"],
                    namespace=p["metadata"]["namespace"],
                    node=p.get("spec", {}).get("nodeName", "?"),
                    ready=conds.get("Ready") == "True",
                )
            )
        return pods

    async def actuator(self, pod: AgentPod, endpoint: str) -> Any:
        path = f"/api/v1/namespaces/{pod.namespace}/pods/{pod.name}:{self.settings.kpod_port}/proxy/actuator/{endpoint}"
        return json.loads(await self.kubectl.get_raw(path))


def now() -> float:
    return time.time()
