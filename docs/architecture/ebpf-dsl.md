# Kotlin eBPF DSL

kpod-metrics uses [kotlin-ebpf-dsl](https://github.com/pjs7678/kotlin-ebpf-dsl) to define eBPF programs in type-safe Kotlin instead of writing raw C.

## Why a DSL?

Traditional eBPF development requires writing C code with manual struct definitions, map declarations, and `ByteBuffer` parsing in userspace. This is error-prone:

- Struct field offsets can mismatch between kernel and userspace
- Map key/value types must be kept in sync manually
- No compile-time type safety for map operations

The Kotlin eBPF DSL eliminates these issues by generating both sides from a single definition.

## Example

=== "Kotlin DSL (what you write)"

    ```kotlin
    val memProgram = ebpfProgram("mem") {
        val counterKey = struct("counter_key") {
            u64("cgroup_id")
        }
        val oomKills = hashMap(
            "oom_kills", counterKey,
            BpfScalar.U64, maxEntries = 10240
        )

        tracepoint("oom", "mark_victim") {
            val cgId = getCurrentCgroupId()
            val ptr = mapLookupElem(oomKills, cgId)
            ifNonNull(ptr) { atomicIncrement(it) }
        }
    }
    ```

=== "Generated C (runs in kernel)"

    ```c
    struct counter_key {
        __u64 cgroup_id;
    };

    struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 10240);
        __type(key, struct counter_key);
        __type(value, __u64);
    } oom_kills SEC(".maps");

    SEC("tp/oom/mark_victim")
    int handle_mark_victim(void *ctx) {
        struct counter_key key = {};
        key.cgroup_id = bpf_get_current_cgroup_id();
        __u64 *val = bpf_map_lookup_elem(&oom_kills, &key);
        if (val) __sync_fetch_and_add(val, 1);
        return 0;
    }
    ```

=== "Generated Kotlin MapReader"

    ```kotlin
    // Type-safe deserialization — no manual ByteBuffer parsing
    val cgroupId = MemMapReader.CounterKeyLayout.decodeCgroupId(keyBytes)
    ```

## DSL Features

| Feature | Description |
|---------|-------------|
| `struct()` | Define BPF map key/value structs |
| `hashMap()` / `lruHashMap()` | Declare BPF maps with typed keys and values |
| `tracepoint()` | Attach to kernel tracepoints |
| `kprobe()` / `kretprobe()` | Attach to kernel functions |
| `mapLookupElem()` | Type-safe map lookup |
| `atomicIncrement()` | Atomic counter operations |
| `getCurrentCgroupId()` | Get current cgroup ID for pod attribution |
| `preamble()` / `postamble()` | Inject raw C for complex logic |
| `raw()` | Escape hatch for C that the DSL can't express |

## File Organization

eBPF programs are defined in `src/bpfGenerator/kotlin/.../bpf/programs/`:

```
bpf/programs/
├── Structs.kt          # Shared BPF struct definitions
├── MemProgram.kt       # Memory (OOM, page faults, cache)
├── CpuSchedProgram.kt  # CPU scheduling
├── NetProgram.kt       # Network (TCP)
├── SyscallProgram.kt   # Syscall tracing
└── GenerateBpf.kt      # Code generation entry point
```
