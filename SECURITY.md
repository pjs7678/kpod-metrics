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

### What kpod-metrics Accesses

- **Read-only host paths:** `/sys/kernel/btf`, `/sys/fs/cgroup`, `/sys/kernel/tracing`, `/sys/kernel/debug`, `/proc`
- **BPF subsystem:** Loads eBPF programs, creates BPF maps, reads BPF map data
- **Kubernetes API:** List/watch pods on the local node (scoped by RBAC)
- **No network egress** beyond Kubernetes API (no external calls, no data exfiltration)

### Network Policy

Enable `networkPolicy.enabled: true` in Helm values to restrict network access. The policy allows:
- **Ingress:** Port 9090 (Prometheus scraping)
- **Egress:** DNS (53) and Kubernetes API (443/6443)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.4.x+ | Yes |
| < 0.4.0 | No (missing health checks) |
