package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

// ── CPU profile structs ─────────────────────────────────────────────

object ProfileKey : BpfStruct("profile_key") {
    val cgroupId by u64()
    val tgid by u32()
    val kernStackId by s32()
    val userStackId by s32()
}

// ── CPU profile preamble ────────────────────────────────────────────
// Both maps are defined in the preamble because:
// - stack_traces: STACK_TRACE maps need key_size/value_size (not __type)
// - profile_counts: uses struct key + scalar value (not supported by DSL map builders)

private val CPU_PROFILE_PREAMBLE = """
#define MAX_STACK_DEPTH 128
#define MAX_PROFILE_ENTRIES 65536
#define MAX_STACK_ENTRIES 32768
""".trimIndent()

private val CPU_PROFILE_POSTAMBLE = """
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, MAX_STACK_ENTRIES);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_PROFILE_ENTRIES);
    __type(key, struct profile_key);
    __type(value, __u64);
} profile_counts SEC(".maps");

static __always_inline void inc_profile(void *map, void *key)
{
    __u64 *count = bpf_map_lookup_elem(map, key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(map, key, &one, BPF_NOEXIST);
    }
}
""".trimIndent()

// ── CPU profile program ─────────────────────────────────────────────

@Suppress("DEPRECATION")
val cpuProfileProgram = ebpf("cpu_profile") {
    license("GPL")
    targetKernel("5.5")

    preamble(CPU_PROFILE_PREAMBLE)
    postamble(CPU_PROFILE_POSTAMBLE)

    // perf_event program — attached to CPU perf events for profiling
    perfEvent("cpu_profile") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val tgidPid = declareVar("tgid_pid", raw("bpf_get_current_pid_tgid()", BpfScalar.U64))
        val tgid = declareVar("tgid", raw("tgid_pid >> 32", BpfScalar.U32))
        val kernStackId = declareVar("kern_stack_id",
            raw("bpf_get_stackid(ctx, &stack_traces, 0)", BpfScalar.S32))
        val userStackId = declareVar("user_stack_id",
            raw("bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK)", BpfScalar.S32))

        val key = stackVar(ProfileKey) {
            it[ProfileKey.cgroupId] = cgroupId
            it[ProfileKey.tgid] = tgid
            it[ProfileKey.kernStackId] = kernStackId
            it[ProfileKey.userStackId] = userStackId
        }

        declareVar("_inc", raw(
            "(inc_profile(&profile_counts, &${(key.expr as BpfExpr.VarRef).variable.name}), (__s32)0)",
            BpfScalar.S32
        ))

        returnValue(literal(0, BpfScalar.S32))
    }
}
