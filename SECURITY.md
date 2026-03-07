# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it by opening a private security advisory on GitHub:

https://github.com/pjs7678/kpod-metrics/security/advisories/new

Do not open a public issue for security vulnerabilities.

## Security Model

kpod-metrics requires elevated Linux capabilities to load and run eBPF programs. Understanding the security implications is important for production deployments.

### Required Capabilities

| Capability | Purpose |
|------------|---------|
| `BPF` | Load and manage eBPF programs |
| `PERFMON` | Attach to kernel tracepoints |
| `SYS_RESOURCE` | Increase BPF map memory limits |
| `NET_ADMIN` | Attach network-related BPF programs |

### Recommended Security Configuration

```yaml
securityContext:
  privileged: false
  allowPrivilegeEscalation: false
  capabilities:
    add: [BPF, PERFMON, SYS_RESOURCE, NET_ADMIN]
    drop: [ALL]
  seccompProfile:
    type: RuntimeDefault
```

### Why Root Is Required

kpod-metrics runs as `uid 0` because eBPF program loading (`bpf()` syscall) and reading host paths (`/sys/fs/cgroup`, `/proc`) require root even when Linux capabilities are granted. Running as non-root is not supported.

### What kpod-metrics Accesses

- **Read-only host paths:** `/sys/kernel/btf`, `/sys/fs/cgroup`, `/sys/kernel/tracing`, `/sys/kernel/debug`, `/proc`
- **Writable paths:** `/tmp` (emptyDir, tmpfs, 64Mi limit) for JVM temporary files
- **BPF subsystem:** Loads eBPF programs, creates BPF maps, reads BPF map data
- **Kubernetes API:** List/watch pods on the local node (scoped by RBAC)
- **Optional network egress:** OTLP collector (4317/4318) and Pyroscope (4040) when enabled

### Network Policy

Enable `networkPolicy.enabled: true` in Helm values to restrict network access. The policy allows:
- **Ingress:** Port 9090 (Prometheus scraping)
- **Egress:** DNS (53), Kubernetes API (443/6443), plus OTLP and Pyroscope ports when those features are enabled

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.4.x+ | Yes |
| < 0.4.0 | No (missing health checks) |
