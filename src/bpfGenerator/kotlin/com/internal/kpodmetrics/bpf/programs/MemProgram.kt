package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar

/**
 * DSL definition for the mem BPF program.
 *
 * This generates C code structurally equivalent to the hand-written `bpf/mem.bpf.c`.
 * It defines two LRU_HASH maps (oom_kills, major_faults) and two programs:
 *   - tp/oom/mark_victim: counts OOM kills per cgroup
 *   - kprobe/handle_mm_fault: counts major page faults per cgroup
 *
 * Note: Stats tracking (STATS_INC/STATS_DEC) in the else branch is omitted from
 * the DSL logic. The DEFINE_STATS_MAP macros are included in the preamble so the
 * stats maps are still created (for compatibility), but are not written to by
 * the generated program body. Stats tracking can be added later if needed.
 */
val memProgram = ebpf("mem") {
    license("GPL")
    targetKernel("5.3")

    preamble(COMMON_PREAMBLE + "\n\nDEFINE_STATS_MAP(oom_kills)\nDEFINE_STATS_MAP(major_faults)")

    val oomKills by lruHashMap(CounterKey, CounterValue, maxEntries = 10240)
    val majorFaults by lruHashMap(CounterKey, CounterValue, maxEntries = 10240)

    tracepoint("oom", "mark_victim") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CounterKey) {
            it[CounterKey.cgroupId] = cgroupId
        }
        val entry = oomKills.lookup(key)
        ifNonNull(entry) { e ->
            e[CounterValue.count].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(CounterValue) {
                it[CounterValue.count] = literal(1u, BpfScalar.U64)
            }
            oomKills.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    kprobe("handle_mm_fault") {
        // Access 3rd argument (flags) via raw PT_REGS to check FAULT_FLAG_MAJOR (0x4)
        val flags = declareVar("flags", raw("(unsigned int)PT_REGS_PARM3(ctx)", BpfScalar.U32))
        // If not a major fault, return early
        ifThen(flags and literal(0x4, BpfScalar.U32) eq literal(0, BpfScalar.U32)) {
            returnValue(literal(0, BpfScalar.S32))
        }

        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CounterKey) {
            it[CounterKey.cgroupId] = cgroupId
        }
        val entry = majorFaults.lookup(key)
        ifNonNull(entry) { e ->
            e[CounterValue.count].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(CounterValue) {
                it[CounterValue.count] = literal(1u, BpfScalar.U64)
            }
            majorFaults.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
