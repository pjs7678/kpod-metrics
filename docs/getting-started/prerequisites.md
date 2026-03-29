# Prerequisites

## Requirements

- **Linux kernel 4.18+** (5.2+ recommended for CO-RE/BTF)
- **Cgroup v2** (default on Kubernetes 1.25+)
- **Kubernetes 1.19+**

The image ships two sets of compiled BPF programs. At startup, kpod-metrics checks for `/sys/kernel/btf/vmlinux` and automatically loads the appropriate set.

## Kernel Version Support

| Kernel | Mode | How it works |
|--------|------|--------------|
| **5.2+** | CO-RE (recommended) | Uses BTF for portable BPF loading. All features supported. Most distros since RHEL 8.2, Ubuntu 20.04, Debian 11. |
| **4.18–5.1** | Legacy | Uses pre-compiled BPF programs with fixed struct offsets. All features supported, but BPF objects are not relocatable across kernel builds with non-standard tracepoint layouts. |
| **< 4.18** | Not supported | Missing `bpf_get_current_cgroup_id()` helper required for per-pod attribution. |

### Limitations of Legacy Mode (4.18–5.1)

- Tracepoint context struct layouts are assumed to match the stable kernel ABI. Custom or patched kernels that alter tracepoint format fields may cause incorrect data or load failures.
- No automatic struct relocation — if a field offset changes, the BPF program must be recompiled with an updated `compat_vmlinux.h`.

## How to Verify Your Kernel

```bash
# Check kernel version
uname -r

# Check if BTF is available (5.2+ with CONFIG_DEBUG_INFO_BTF=y)
ls /sys/kernel/btf/vmlinux

# Check cgroup v2
mount | grep cgroup2
```

### Required Kernel Config

Typically enabled by default on modern distros:

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_DEBUG_INFO_BTF=y  # Required only for CO-RE path; optional on 4.18+
```

## Required Capabilities

kpod-metrics needs the following Linux capabilities:

| Capability | Why |
|-----------|-----|
| `BPF` | Load and interact with BPF programs |
| `PERFMON` | Attach BPF programs to tracepoints |
| `SYS_RESOURCE` | Lock memory for BPF maps |
| `NET_ADMIN` | Access network-related BPF features |

These are configured automatically by the Helm chart.
