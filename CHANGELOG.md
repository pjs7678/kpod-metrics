# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - 2026-02-28

### Added
- Multi-arch Docker image builds (linux/amd64 + linux/arm64) via buildx
- Container image vulnerability scanning with Trivy (CRITICAL/HIGH)
- Automated release workflow triggered on version tag push
- Helm chart linting in CI pipeline

### Changed
- Dockerfile now auto-detects target architecture from buildx TARGETARCH
- Publish workflow uses docker/build-push-action with multi-platform support
- Trivy scan results uploaded to GitHub Security tab (SARIF format)

## [0.2.0] - 2026-02-28

### Added
- Grafana dashboard with 9 rows and 29 panels covering all kpod-metrics collectors
  - Auto-provisioned via Grafana sidecar ConfigMap (Helm-managed)
  - Standalone JSON available at `grafana/kpod-metrics-dashboard.json`
- Prometheus Operator integration (ServiceMonitor + PrometheusRule)
  - Headless Service for ServiceMonitor pod discovery
  - 8 production alerting rules (runqueue latency, TCP retransmits/drops, syscall errors, filesystem usage, BPF map capacity/errors, target down)
- BCC tool collectors: BiolatencyCollector, CachestatCollector, TcpdropCollector, HardirqsCollector, SoftirqsCollector, ExecsnoopCollector

### Fixed
- Dockerfile compatibility with legacy Docker builder (non-BuildKit)

## [0.1.0] - 2026-02-27

### Added
- Core eBPF collectors: CPU scheduling, network, memory, syscall
- Cgroup collectors: disk I/O, interface network, filesystem
- BPF map diagnostics collector
- Dual kernel support: CO-RE (5.2+ with BTF) and legacy (4.18-5.1)
- JNI bridge wrapping libbpf for BPF program lifecycle
- Kotlin DSL code generation for eBPF programs (via kotlin-ebpf-dsl)
- Spring Boot application with virtual threads and Micrometer/Prometheus export
- Pod discovery via K8s informer or Kubelet API
- Profile system: minimal, standard, comprehensive, custom
- Helm chart with DaemonSet, RBAC, ConfigMap, PDB
- Multi-stage Dockerfile (codegen, BPF compile, JNI build, app build, runtime)
- GitHub Actions CI/CD (unit tests, image publish)
- E2E and integration test scripts (minikube)
