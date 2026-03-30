# kpod-metrics

**eBPF-based pod-level kernel metrics collector for Kubernetes.**

kpod-metrics runs as a DaemonSet on each node, attaches eBPF programs to kernel tracepoints, and exports per-pod CPU, network, memory, syscall, disk I/O, and filesystem metrics to Prometheus.

## Demo

<p align="center">
  <img src="demo.svg" alt="kpod-metrics demo" style="max-width:100%; border-radius:8px;">
</p>

<div class="grid cards" markdown>

- :zap: **Zero Instrumentation**

    ---

    eBPF attaches to kernel tracepoints automatically. No code changes, no sidecars, no agents inside your pods.

- :bar_chart: **Per-Pod Granularity**

    ---

    Every metric is labeled with `namespace`, `pod`, `container`, and `node`. Drill down from cluster to individual container.

- :globe_with_meridians: **L7 Protocol Detection**

    ---

    Auto-detect HTTP, DNS, Redis, MySQL, Kafka, and MongoDB traffic with per-request latency and error tracking.

- :chart_with_upwards_trend: **Prometheus-Native**

    ---

    Metrics exported directly to Prometheus. Works with Grafana dashboards (included), ServiceMonitor, and OTLP export.

</div>

## Quick Install

```bash
helm repo add kpod-metrics https://pjs7678.github.io/kpod-metrics
helm repo update
helm install kpod-metrics kpod-metrics/kpod-metrics \
  --namespace kpod-metrics --create-namespace
```

See the [Quick Start guide](getting-started/quickstart.md) for detailed setup instructions.

## Key Features

- **50+ metrics** across CPU, network, memory, syscalls, disk I/O, filesystem, and interrupts
- **Auto-discovered service topology** from TCP peer data — no configuration needed
- **L7 protocol detection** for HTTP, DNS, Redis, MySQL, Kafka, MongoDB
- **Grafana dashboards** included with 9 metric rows
- **Prometheus Operator** support with ServiceMonitor and 18 alerting rules
- **OTLP export** for OpenTelemetry-compatible backends
- **Three profiles** (minimal, standard, comprehensive) to control overhead
- **Kotlin eBPF DSL** — BPF programs defined in type-safe Kotlin, not raw C
- **Broad kernel support** — 4.18+ (legacy) and 5.2+ (CO-RE)
- **Tested at scale** — 1,000 nodes / 100,000 pods

## Architecture

```
Node (DaemonSet pod)
┌─────────────────────────────────────────────────┐
│  Spring Boot (JDK 21 + Virtual Threads)         │
│                                                  │
│  MetricsCollectorService (every 30s default)    │
│  ├── eBPF Collectors ──► JNI ──► BPF Maps      │
│  └── Cgroup Collectors ──► /sys/fs/cgroup       │
│                                                  │
│  Prometheus exporter (:9090/actuator/prometheus) │
└─────────────────────────────────────────────────┘
         │ JNI (libkpod_bpf.so)
    ┌────▼────────────────────────┐
    │ Linux Kernel                │
    │ eBPF programs on            │
    │ tracepoints: sched_switch,  │
    │ tcp_sendmsg, oom_kill, ...  │
    └─────────────────────────────┘
```

Learn more in the [Architecture overview](architecture/overview.md).
