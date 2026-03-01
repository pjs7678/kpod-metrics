# Changelog

All notable changes to this project will be documented in this file.

## [1.6.0] - 2026-03-01

### Added
- README: OTLP export documentation with full configuration example
- README: `kpod.collector.skipped.total` and `kpod.bpf.program.load.duration` in Self-Monitoring metrics table
- README: OTLP properties (`kpod.otlp.*`) in Key Properties table
- Grafana dashboard: Collector Skip Rate panel (time series, ID 104)
- Grafana dashboard: BPF Program Load Duration panel (stat, ID 105)
- PrometheusRule: `kpod:collector_skip_rate:5m` recording rule
- PrometheusRule: `KpodHighCollectorSkipRate` alert (> 10% skip rate for 10m)
- `kpod.initial-delay` exposed as `initialDelay` property in MetricsProperties

### Changed
- Fixed `poll-interval` default mismatch: `application.yml` now defaults to 30000ms (was 15000ms), matching MetricsProperties and Helm values
- README: updated test count (140 → 201), image tag (1.3.0 → 1.6.0), architecture diagram
- README: added MemoryCgroupCollector to architecture diagram
- README: updated PrometheusRule counts (17 alerts + 13 recording rules)
- Grafana dashboard synced between standalone and Helm copies (49 panels total)

## [1.5.0] - 2026-03-01

### Added
- `kpod.collector.skipped.total` counter — tracks interval-based collector skips per collector
- `kpod.bpf.program.load.duration` timer — measures BPF program load time per program
- `lastCollectorErrors` in DiagnosticsEndpoint — shows last error message per collector
- `enabledCollectorCount` in DiagnosticsEndpoint — runtime count of active collectors
- Helm probe customization: `probes.startup`, `probes.liveness`, `probes.readiness` in values.yaml
  - Configurable `periodSeconds`, `failureThreshold`, `initialDelaySeconds`

### Changed
- `MetricsCollectorService` tracks last error per collector for diagnostics
- `BpfProgramManager.tryLoadProgram` records load duration via Micrometer timer
- DaemonSet template uses `{{ .Values.probes.* }}` instead of hardcoded probe intervals

## [1.4.0] - 2026-03-01

### Added
- OpenTelemetry/OTLP metrics export via `micrometer-registry-otlp`
  - Configurable via `kpod.otlp.enabled`, `kpod.otlp.endpoint`, `kpod.otlp.headers`, `kpod.otlp.step`
  - Push metrics to any OTLP-compatible collector alongside Prometheus scraping
- `CollectorConfigHealthIndicator`: health check reports DOWN when all collectors are disabled
  - `getEnabledCollectorCount()` on MetricsCollectorService for runtime inspection
- Enhanced Helm NOTES.txt: shows active profile, poll/timeout settings, conditional sections for
  ServiceMonitor, PrometheusRule, Grafana dashboard, and OTLP export
- Helm values: `otlp.enabled`, `otlp.endpoint`, `otlp.headers`, `otlp.step`

### Changed
- `BpfAutoConfiguration` conditionally creates `OtlpMeterRegistry` bean when `kpod.otlp.enabled=true`
- Helm ConfigMap renders OTLP configuration under `kpod.otlp` when enabled

## [1.3.0] - 2026-03-01

### Added
- Per-collector interval configuration (`kpod.collector-intervals.<name>`)
  - Heavy collectors (syscall, biolatency, hardirqs) can run at longer intervals
  - Default: all collectors run every cycle (backward compatible)
  - Tracks per-collector last-run timestamps; skips when interval hasn't elapsed
- PrometheusRule alerts: `KpodHighRestartRate` (> 3 restarts/15min) and `KpodPodCrashLooping` (> 5 restarts/30min)
- Helm DaemonSet: `affinity` and `topologySpreadConstraints` support
- README: comprehensive configuration reference (40+ properties documented)
- README: memory cgroup, pod lifecycle, and self-monitoring metric tables

### Changed
- `MetricsCollectorService` accepts `CollectorIntervals` for per-collector scheduling
- `BpfAutoConfiguration` passes `collectorIntervals` and `basePollInterval` to service
- Helm ConfigMap renders `collector-intervals` when configured
- README Prometheus Operator section updated to reflect 15 alert rules + 12 recording rules

## [1.2.0] - 2026-03-01

### Added
- Container restart tracking: `kpod.container.restarts` gauge per pod/container
  - Automatically updated from K8s container status `restartCount`
  - Cleaned up on pod deletion to prevent cardinality growth
- Grafana dashboard: Container Restarts panel in Process Activity row
- KubeletPodProvider now captures container restart counts

### Changed
- Dashboard histogram queries optimized to use precomputed recording rules
  - 6 queries replaced: runqueue latency p50/p99, TCP RTT p50/p99, syscall latency p99
  - Reduces Prometheus query load on large clusters
- Helm dashboard ConfigMap synced with standalone dashboard (fixes v1.1.0 panel gap)
- PodWatcher now accepts optional `MeterRegistry` for restart gauge registration

### Fixed
- Helm dashboards copy missing 5 panels added in v1.1.0 (interface errors/drops/packets, buffer dirty, fs available)

## [1.1.0] - 2026-03-01

### Added
- Service always created (decoupled from ServiceMonitor) — standalone Prometheus can now scrape without Operator
- DaemonSet `updateStrategy` with configurable `maxUnavailable` (default: 1) for controlled rollouts
- `extraEnv` support in Helm values for JVM tuning, proxy settings, etc.
- Grafana dashboard: Interface Errors, Interface Drops, Interface Packets panels (Network row)
- Grafana dashboard: Buffer Dirty Rate panel (Memory & Cache row)
- Grafana dashboard: Filesystem Available panel (Disk & Filesystem row)
- 12 Prometheus recording rules for precomputed aggregations (p50/p99 latencies, error ratios, rates)
- Chart.yaml metadata: home, sources, keywords, maintainers for chart discoverability

### Changed
- PrometheusRule now has two rule groups: `kpod-metrics.recording` and `kpod-metrics` (alerting)
- Helm chart version and appVersion bumped to 1.1.0

## [1.0.0] - 2026-03-01

### Added
- Spring graceful shutdown (`server.shutdown=graceful`, 30s timeout) for clean request draining
- `DiscoveryHealthIndicator`: readiness check that reports DOWN if no pods discovered after 60s grace period
- Initial collection delay (`kpod.initial-delay`, default 10s) to allow PodWatcher to discover pods before first cycle
- Collection overlap guard: skips cycle with warning if previous cycle is still running
- Helm test pod (`helm test`) for health endpoint validation
- Dockerfile `HEALTHCHECK` for non-Kubernetes environments

### Changed
- `MetricsCollectorService.collect()` uses `compareAndSet` for atomic overlap detection
- Helm ConfigMap includes graceful shutdown configuration
- `build.gradle.kts` version set to `1.0.0`

## [0.9.0] - 2026-03-01

### Added
- Pod label propagation to metrics: configurable `kpod.filter.include-labels` whitelist
  - Pod labels (e.g., `app=nginx`) appear as `label_app="nginx"` metric tags
  - Labels filtered at PodCgroupMapper level to control cardinality
- Metric staleness cleanup: Micrometer meters for deleted pods are automatically removed
  - Prevents cardinality growth from pod churn in long-running clusters
  - Cleans gauge stores in FilesystemCollector and MemoryCgroupCollector
- Label selector filtering: `kpod.filter.label-selector` now functional
  - Supports `key=value`, `key!=value`, and `key` (exists) selectors
  - Comma-separated for multiple terms (AND logic)
- `PodCgroupTarget.tags()` helper for consistent tag construction across cgroup collectors

### Changed
- `PodCgroupMapper` now accepts `includeLabels` to filter pod labels at discovery time
- `PodWatcher.shouldWatch()` now evaluates label selectors alongside namespace filters
- Cgroup collectors use `target.tags()` instead of manual tag construction
- Helm ConfigMap renders filter config (namespaces, excludeNamespaces, labelSelector, includeLabels)

## [0.8.0] - 2026-03-01

### Added
- Memory cgroup collector: `kpod.mem.cgroup.usage.bytes`, `kpod.mem.cgroup.peak.bytes`,
  `kpod.mem.cgroup.cache.bytes`, `kpod.mem.cgroup.swap.bytes` — supports cgroup v1 and v2
- Multi-cluster label injection via `kpod.cluster-name` — adds `cluster` common tag to all metrics
- `node` common tag automatically applied to all metrics via `MeterRegistryCustomizer`
- Grafana dashboard: Memory (Cgroup) row with usage, peak, cache, swap panels
- Grafana dashboard: Operational row with cgroup read error rate and collection timeout panels
- PrometheusRule alerts: `KpodCgroupReadErrors`, `KpodCollectionTimeouts`, `KpodMemoryPressure`

### Changed
- Helm values: added `config.clusterName` option
- Helm ConfigMap: renders `cluster-name` when set

## [0.7.0] - 2026-03-01

### Added
- Per-target error handling in cgroup collectors (DiskIO, InterfaceNetwork, Filesystem)
  - `kpod.cgroup.read.errors` counter per collector — one pod's failure no longer blocks others
- Graceful shutdown with drain timeout — waits for in-flight collection cycle to complete
- `/actuator/kpodDiagnostics` endpoint: uptime, collector states, BPF program status, profile summary
- Startup cardinality estimation with configurable warning threshold
  - Logs estimated metric series count per profile at boot
  - Warns if estimate exceeds 100k (configurable)

### Changed
- `MetricsCollectorService.close()` now drains in-flight cycles before shutting down executor
- Cgroup collector tests updated for error counter registration at construction

## [0.6.0] - 2026-03-01

### Added
- Collection cycle timeout (`kpod.collection-timeout`) with `kpod.collection.timeouts.total` counter
- Per-collector enable/disable overrides (`kpod.collectors.*`) on top of profiles
- E2E test CI workflow (`.github/workflows/e2e.yml`) with minikube, weekly schedule + manual dispatch

### Changed
- Collection cycle now wrapped in `withTimeoutOrNull` for bounded execution
- Helm ConfigMap template renders `collection-timeout` and `collectors` config
- Added `kotlin("test")` dependency for test assertions

## [0.5.0] - 2026-03-01

### Added
- Helm chart: `imagePullSecrets` support for private registries
- Helm chart: `priorityClassName` support for guaranteed scheduling
- Helm chart: `allowPrivilegeEscalation: false` and `drop: ALL` capabilities hardening
- Helm chart: optional `seccompProfile` configuration
- Helm chart: NetworkPolicy template (`networkPolicy.enabled`)
- Enhanced NOTES.txt with health check verification and feature status
- Troubleshooting guide (`docs/troubleshooting.md`)
- CONTRIBUTING.md with development setup and PR process
- SECURITY.md with security model and vulnerability reporting

## [0.4.0] - 2026-03-01

### Added
- Self-monitoring metrics for collection pipeline health:
  - `kpod.collection.cycle.duration` — timer for full collection cycle
  - `kpod.collector.duration` — timer per collector (tagged by collector name)
  - `kpod.collector.errors.total` — counter per collector for failure tracking
  - `kpod.discovery.pods.total` — gauge of discovered pods per cycle
  - `kpod.bpf.programs.loaded` / `kpod.bpf.programs.failed` — BPF program load status
- Custom Spring Boot health indicators for Kubernetes probes:
  - `BpfHealthIndicator` — reports DOWN when BPF programs fail to load
  - `CollectionHealthIndicator` — reports DOWN when collection is stale (3x poll interval)
- Per-program graceful BPF load failures (partial degradation instead of full failure)
- Grafana dashboard Row 10: Collection Health (7 panels)
- PrometheusRule alerts: KpodCollectorErrors, KpodNoBpfPrograms

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
