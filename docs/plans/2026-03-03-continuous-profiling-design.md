# Continuous Profiling for kpod-metrics

## Overview

Add eBPF-based CPU profiling to kpod-metrics DaemonSet with Pyroscope as the storage/visualization backend. Java workloads get async-profiler level visibility via Pyroscope's existing Java agent (sidecar).

## Requirements

- **Targets**: Go + Java services
- **Backend**: Pyroscope server (self-hosted or Grafana Cloud)
- **Profile types**: CPU (eBPF for Go/native/kernel), CPU + Allocations (JFR/async-profiler for Java)
- **Java accuracy**: async-profiler level (inlined methods, interpreted frames, no safepoint bias)

## Architecture

```
Node
├── kpod-metrics DaemonSet (existing + new profiling collector)
│   ├── BPF: perf_event_open (CPU sampling, 99Hz per CPU)
│   ├── BPF_MAP_TYPE_STACK_TRACE (kernel + user stacks)
│   ├── LRU_HASH: (cgroup_id, tgid, kern_stack, user_stack) → count
│   ├── Drain every 29s → resolve symbols → pprof
│   └── Push pprof → Pyroscope ingest API
│
└── Per Java pod (opt-in sidecar)
    ├── Pyroscope Java agent (bundles async-profiler)
    ├── CPU: AsyncGetCallTrace (no safepoint bias, inlined methods)
    ├── Allocations: jdk.ObjectAllocationInNewTLAB
    └── Push pprof → Pyroscope ingest API
```

**Why two tiers:**
- eBPF gives system-wide CPU visibility (Go, native, kernel) with zero application instrumentation
- async-profiler (via Pyroscope Java agent) gives Java-specific accuracy that eBPF cannot match: inlined methods, interpreted frames, JIT symbol resolution via JVMTI

## eBPF CPU Profiler

### BPF Program

Attached to `perf_event` (PERF_TYPE_SOFTWARE / PERF_COUNT_SW_CPU_CLOCK) at 99Hz on each CPU.

```c
// Pseudocode
SEC("perf_event")
int cpu_profile(struct bpf_perf_event_data *ctx) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    u64 tgid_pid  = bpf_get_current_pid_tgid();
    u32 tgid      = tgid_pid >> 32;

    int kern_stack = bpf_get_stackid(ctx, &stack_traces, 0);
    int user_stack = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);

    struct profile_key key = { cgroup_id, tgid, kern_stack, user_stack };
    u64 *count = bpf_map_lookup_elem(&profile_counts, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        u64 one = 1;
        bpf_map_update_elem(&profile_counts, &key, &one, BPF_NOEXIST);
    }
    return 0;
}
```

### BPF Maps

| Map | Type | Key | Value | Max Entries |
|-----|------|-----|-------|-------------|
| `stack_traces` | `STACK_TRACE` | stack_id (u32) | u64[128] instruction pointers | 32,768 |
| `profile_counts` | `LRU_HASH` | `{cgroup_id(u64), tgid(u32), kern_stack_id(i32), user_stack_id(i32)}` = 20 bytes | count (u64) | 65,536 |

### Drain & Symbol Resolution Pipeline

```
Every 29s (MetricsCollectorService cycle):

1. Batch drain profile_counts map
   → List<(cgroupId, tgid, kernStackId, userStackId, count)>

2. Read stack_traces map for each unique stack ID
   → Map<stackId, LongArray>  (instruction pointers)

3. Group entries by (cgroupId → PodInfo)
   → Map<PodInfo, List<StackSample>>

4. For each pod, resolve symbols:
   ├── Kernel IPs:  /proc/kallsyms → function names
   ├── User IPs:    /proc/<tgid>/maps → find ELF binary
   │                ELF .symtab/.dynsym → function name
   │                .gosymtab → Go function name (if Go binary)
   │                /tmp/perf-<tgid>.map → JIT symbols
   └── Cache: (binary_path, buildId, offset) → symbol

5. Build pprof Profile protobuf per pod
   → cpu profile_type, 29s duration, sample values = counts

6. Push to Pyroscope ingest API
   POST /ingest?name=kpod.cpu{namespace=X,pod=Y,node=Z}
```

### Symbol Resolution Strategy

| Binary Type | Detection | Resolution Method |
|-------------|-----------|-------------------|
| Go | ELF `.note.go.buildid` | `.gosymtab` (full qualified names) |
| Native C/C++ | Default | ELF `.symtab` / `.dynsym` |
| Java JIT | `/tmp/perf-<pid>.map` exists | Parse perf-map file |
| Kernel | Stack from kernel space | `/proc/kallsyms` |
| Unknown | No symbols found | `[unknown] 0x<addr>` |

Symbol cache: `ConcurrentHashMap<(binaryPath, buildId, offset), String>` — survives across drain cycles, invalidated when binary mtime changes.

## New Components

| Component | Location | Purpose |
|-----------|----------|---------|
| `cpu_profile.bpf.c` | Generated via kotlin-ebpf-dsl | BPF program for perf_event sampling |
| `CpuProfileCollector.kt` | `collector/` | Drains maps, drives symbol resolution, builds pprof |
| `SymbolResolver.kt` | `profiling/` | Resolves instruction pointers → function names |
| `PprofBuilder.kt` | `profiling/` | Constructs pprof protobuf from resolved stacks |
| `PyroscopePusher.kt` | `profiling/` | HTTP client pushing pprof to Pyroscope ingest API |

### JNI Additions (BpfBridge)

```kotlin
// Read a single stack trace by ID from STACK_TRACE map
fun mapLookupStack(mapFd: Int, stackId: Int, maxDepth: Int): LongArray?

// Attach BPF program to perf_event on all CPUs
fun perfEventOpenAndAttach(handle: Long, progName: String, sampleFreq: Int): IntArray
```

## Pyroscope Push Protocol

```
POST /ingest
  ?name=kpod.cpu{namespace=default,pod=myapp-xyz,node=worker-1}
  &sampleRate=99
  &from=<epoch_seconds>
  &until=<epoch_seconds>
  &format=pprof
Content-Type: application/x-protobuf
Body: <gzip-compressed pprof Profile protobuf>
```

## Configuration

```yaml
kpod:
  profiling:
    enabled: false                          # opt-in
    cpu:
      enabled: true
      frequency: 99                         # Hz
      stackDepth: 128                       # max frames per stack
    pyroscope:
      endpoint: "http://pyroscope:4040"
      tenantId: ""                          # X-Scope-OrgID for multi-tenant
      authToken: ""                         # Bearer token (Grafana Cloud)
    symbolCache:
      maxEntries: 50000
```

## Phased Delivery

### Phase 1 — BPF program + map drain (foundation)
- New BPF program: `cpu_profile.bpf.c` via kotlin-ebpf-dsl
- JNI additions: `perfEventOpenAndAttach()`, `mapLookupStack()`
- `CpuProfileCollector.kt`: drains maps, groups by cgroup, raw IP addresses
- No symbol resolution yet — log raw stacks for validation
- **Deliverable**: BPF program loads, attaches to perf_event, collects stacks per pod

### Phase 2 — Symbol resolution
- `SymbolResolver.kt`: `/proc/kallsyms`, ELF symtab, `.gosymtab`, perf-map files
- Symbol cache with build-ID invalidation
- **Deliverable**: Human-readable stack traces in logs

### Phase 3 — pprof + Pyroscope push
- `PprofBuilder.kt`: Construct pprof protobuf from resolved stacks
- `PyroscopePusher.kt`: HTTP push to Pyroscope with gzip compression
- Pyroscope config properties + Helm wiring
- **Deliverable**: Flamegraphs visible in Grafana/Pyroscope

### Phase 4 — Java agent integration
- Helm templates for Pyroscope Java agent sidecar injection
- Documentation for `JAVA_TOOL_OPTIONS` setup
- Example annotations for workload opt-in
- **Deliverable**: Java allocation + CPU flamegraphs alongside eBPF profiles
