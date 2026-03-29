# Security

## Security Model

kpod-metrics runs as a privileged DaemonSet with access to kernel-level data. Understanding its security model is important for production deployment.

## Required Capabilities

| Capability | Why |
|-----------|-----|
| `BPF` | Load and interact with BPF programs |
| `PERFMON` | Attach BPF programs to tracepoints |
| `SYS_RESOURCE` | Lock memory for BPF maps |
| `NET_ADMIN` | Access network-related BPF features |

## What It Accesses

| Resource | Access | Purpose |
|----------|--------|---------|
| `/sys/kernel/btf/vmlinux` | Read | BTF type information for CO-RE |
| `/sys/fs/cgroup` | Read | Cgroup metrics (CPU, memory, disk, network) |
| `/proc` | Read | Process-to-cgroup mapping |
| Kubernetes API | Read (node-scoped) | Pod metadata via informer |
| BPF subsystem | Read/Write | Load programs, read maps |

## What It Does NOT Access

- No access to pod filesystems or volumes
- No access to container processes or namespaces
- No network traffic content (only metadata: byte counts, connection info)
- No secrets or configmaps from other namespaces
- No write access to the Kubernetes API

## Network Policy

The Helm chart includes a NetworkPolicy that restricts egress:

```yaml
networkPolicy:
  enabled: true  # default
```

Allowed egress:

- Kubernetes API server (for pod informer)
- DNS (port 53)
- OTLP endpoint (if configured)
- Pyroscope endpoint (if configured)

## Reporting a Vulnerability

Report security vulnerabilities via GitHub private security advisory:

[https://github.com/pjs7678/kpod-metrics/security/advisories/new](https://github.com/pjs7678/kpod-metrics/security/advisories/new)

Do not open a public issue for security vulnerabilities.
