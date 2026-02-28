# CI/CD Hardening Design

## Context

kpod-metrics CI/CD currently has basic unit test gating and single-arch (x86_64) Docker publishing. Production Kubernetes clusters run mixed architectures (AMD64 + ARM64), the publish workflow has no container scanning, and releases are manual.

## Scope

- Multi-arch Docker builds (linux/amd64 + linux/arm64)
- Container image scanning (Trivy)
- Automated release workflow (tag push triggers build + release)
- Helm chart linting in CI

## Changes

### Dockerfile Update

Add automatic `TARGETARCH` → `TARGET_ARCH` mapping for buildx compatibility:
- Docker buildx provides `TARGETARCH` (amd64/arm64)
- BPF clang needs `TARGET_ARCH` (x86_64/arm64)
- Map `amd64` → `x86_64`, keep `arm64` as-is

### ci.yml — Add Helm Lint

New `helm-lint` job running in parallel with existing `test` job. Uses `helm lint helm/kpod-metrics`.

### publish.yml — Multi-Arch + Scanning

Replace `docker build/push` with `docker buildx` multi-platform:
- Setup QEMU for cross-compilation
- Setup Docker Buildx
- Build + push `linux/amd64,linux/arm64` manifest
- Tags: `latest` + short SHA
- Add Trivy vulnerability scan (CRITICAL/HIGH severity, fail on findings)

### release.yml — Automated Release

Triggered on `v*` tag push:
- Build multi-arch image with version tag (e.g., `v0.3.0`)
- Trivy scan
- Create GitHub Release with auto-generated release notes
- Tags: version + `latest`

## Values Not Changed

- `values.yaml` image repository stays as `internal-registry/kpod-metrics` (user overrides for their registry)
- Existing test job structure unchanged
- Dependabot config unchanged
