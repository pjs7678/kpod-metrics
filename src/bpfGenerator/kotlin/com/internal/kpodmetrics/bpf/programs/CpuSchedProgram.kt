package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar

/**
 * DSL definition for the cpu_sched BPF program.
 *
 * This generates C code structurally equivalent to the hand-written `bpf/cpu_sched.bpf.c`.
 * It defines three maps and two tracepoint programs:
 *
 * Maps:
 *   - wakeup_ts:    HASH (scalar), key=__u32 (PID), value=__u64 (timestamp)
 *   - runq_latency: LRU_HASH, key=hist_key, value=hist_value (27-slot histogram)
 *   - ctx_switches: LRU_HASH, key=counter_key, value=counter_value
 *
 * Programs:
 *   - tp/sched/sched_wakeup:  records wakeup timestamp per PID
 *   - tp/sched/sched_switch:  counts context switches and computes run-queue latency histogram
 *
 * Note: Stats tracking (STATS_INC/STATS_DEC) in the else branches is omitted from
 * the DSL logic. The DEFINE_STATS_MAP macros are included in the preamble so the
 * stats maps are still created (for compatibility), but are not written to by the
 * generated program body.
 */
val cpuSchedProgram = ebpf("cpu_sched") {
    license("GPL")

    preamble(
        COMMON_PREAMBLE +
            "\n\nDEFINE_STATS_MAP(runq_latency)\nDEFINE_STATS_MAP(ctx_switches)"
    )

    // ── Maps ────────────────────────────────────────────────────────────
    val wakeupTs by scalarHashMap(BpfScalar.U32, BpfScalar.U64, maxEntries = 10240)
    val runqLatency by lruHashMap(HistKey, HistValue, maxEntries = 10240)
    val ctxSwitches by lruHashMap(CounterKey, CounterValue, maxEntries = 10240)

    // ── Program 1: tp/sched/sched_wakeup ────────────────────────────────
    tracepoint("sched", "sched_wakeup") {
        val pid = declareVar(
            "pid",
            raw("((struct trace_event_raw_sched_wakeup_template *)ctx)->pid", BpfScalar.U32)
        )
        val ts = declareVar("ts", ktimeGetNs())
        wakeupTs.update(pid, ts, flags = BPF_ANY)
        returnValue(literal(0, BpfScalar.S32))
    }

    // ── Program 2: tp/sched/sched_switch ────────────────────────────────
    tracepoint("sched", "sched_switch") {
        val nextPid = declareVar(
            "next_pid",
            raw("((struct trace_event_raw_sched_switch *)ctx)->next_pid", BpfScalar.U32)
        )
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())

        // ── Part 1: Count context switches (lookup-or-insert) ───────────
        val ckey = stackVar(CounterKey) {
            it[CounterKey.cgroupId] = cgroupId
        }
        val cval = ctxSwitches.lookup(ckey)
        ifNonNull(cval) { e ->
            e[CounterValue.count].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(CounterValue) {
                it[CounterValue.count] = literal(1u, BpfScalar.U64)
            }
            ctxSwitches.update(ckey, newVal, flags = BPF_NOEXIST)
        }

        // ── Part 2: Look up wakeup timestamp for next_pid ───────────────
        val tsp = wakeupTs.lookup(nextPid)
        ifNonNull(tsp) { e ->
            // Dereference the pointer to get the timestamp value
            val tspVarName = (e.expr as BpfExpr.VarRef).variable.name
            val deltaNs = declareVar(
                "delta_ns",
                ktimeGetNs() - raw("*$tspVarName", BpfScalar.U64)
            )
            wakeupTs.delete(nextPid)

            // ── Part 3: Compute run-queue latency histogram ─────────────
            val hkey = stackVar(HistKey) {
                it[HistKey.cgroupId] = cgroupId
            }
            val hval = runqLatency.lookup(hkey)
            ifNonNull(hval) { he ->
                val slot = declareVar(
                    "slot",
                    raw("log2l(delta_ns) >= MAX_SLOTS ? MAX_SLOTS - 1 : log2l(delta_ns)", BpfScalar.U32)
                )
                he[HistValue.slots].at(slot).atomicAdd(literal(1u, BpfScalar.U64))
                he[HistValue.count].atomicAdd(literal(1u, BpfScalar.U64))
                he[HistValue.sumNs].atomicAdd(deltaNs)
            }.elseThen {
                val slot2 = declareVar(
                    "slot2",
                    raw("log2l(delta_ns) >= MAX_SLOTS ? MAX_SLOTS - 1 : log2l(delta_ns)", BpfScalar.U32)
                )
                val newHval = stackVar(HistValue) {
                    it[HistValue.count] = literal(1u, BpfScalar.U64)
                    it[HistValue.sumNs] = deltaNs
                }
                // Array assignment for slots[slot2] = 1 using raw C via declareVar
                val newHvalName = (newHval.expr as BpfExpr.VarRef).variable.name
                declareVar(
                    "_arr_set",
                    raw("($newHvalName.slots[slot2] = 1ULL, (__s32)0)", BpfScalar.S32)
                )
                runqLatency.update(hkey, newHval, flags = BPF_NOEXIST)
            }
        }

        returnValue(literal(0, BpfScalar.S32))
    }
}
