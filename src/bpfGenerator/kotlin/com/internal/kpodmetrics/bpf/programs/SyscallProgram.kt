package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

/**
 * syscall_key struct — defined here (not in Structs.kt) because it is specific
 * to the syscall program. Composite key with cgroup_id + syscall number.
 */
object SyscallKey : BpfStruct("syscall_key") {
    val cgroupId by u64()
    val syscallNr by u32()
    val pad by u32(cName = "_pad")  // explicit padding
}

/**
 * syscall_stats struct — per-syscall statistics including count, error count,
 * latency sum, and a 27-slot log2 histogram of latencies.
 */
object SyscallStats : BpfStruct("syscall_stats") {
    val count by u64()
    val errorCount by u64()
    val latencySumNs by u64()
    val latencySlots by array(BpfScalar.U64, 27)
}

/**
 * DSL definition for the syscall BPF program.
 *
 * This generates C code structurally equivalent to the hand-written `bpf/syscall.bpf.c`.
 * It defines five maps and two raw tracepoint programs:
 *
 * Maps:
 *   - syscall_start:    HASH (scalar), key=__u64 (pid_tgid), value=__u64 (timestamp)
 *   - syscall_nr_map:   HASH (scalar), key=__u64 (pid_tgid), value=__u32 (syscall number)
 *   - syscall_stats:    LRU_HASH, key=syscall_key, value=syscall_stats
 *   - tracked_syscalls: HASH (scalar), key=__u32, value=__u8
 *
 * Programs:
 *   - raw_tp/sys_enter: checks tracked_syscalls, records timestamp and syscall number
 *   - raw_tp/sys_exit:  computes latency, updates per-syscall stats with histogram
 *
 * Note: Stats tracking (STATS_INC/STATS_DEC) in the else branches is omitted from
 * the DSL logic. The DEFINE_STATS_MAP macros are included in the preamble so the
 * stats maps are still created (for compatibility), but are not written to by the
 * generated program body.
 */
val syscallProgram = ebpf("syscall") {
    license("GPL")

    preamble(
        COMMON_PREAMBLE +
            "\n\nDEFINE_STATS_MAP(syscall_stats_map)"
    )

    // ── Maps ────────────────────────────────────────────────────────────
    val syscallStart by scalarHashMap(BpfScalar.U64, BpfScalar.U64, maxEntries = 10240)
    val syscallNrMap by scalarHashMap(BpfScalar.U64, BpfScalar.U32, maxEntries = 10240)
    val syscallStatsMap by lruHashMap(SyscallKey, SyscallStats, maxEntries = 10240, mapName = "syscall_stats")
    // shortened from "tracked_syscalls" (16 chars) for 15-char BPF map name limit
    val trackedSyscalls by scalarHashMap(BpfScalar.U32, BpfScalar.U8, maxEntries = 64, mapName = "trk_syscalls")

    // ── Program 1: raw_tp/sys_enter ──────────────────────────────────────
    rawTracepoint("sys_enter") {
        val syscallNr = declareVar("syscall_nr", raw("(__u32)ctx->args[1]", BpfScalar.U32))

        // Check if this syscall is tracked — if not tracked, skip everything
        val tracked = trackedSyscalls.lookup(syscallNr)
        ifNonNull(tracked) {
            val pidTgid = declareVar("pid_tgid", getCurrentPidTgid())
            val ts = declareVar("ts", ktimeGetNs())
            syscallStart.update(pidTgid, ts, flags = BPF_ANY)
            syscallNrMap.update(pidTgid, syscallNr, flags = BPF_ANY)
        }

        returnValue(literal(0, BpfScalar.S32))
    }

    // ── Program 2: raw_tp/sys_exit ───────────────────────────────────────
    rawTracepoint("sys_exit") {
        val pidTgid = declareVar("pid_tgid", getCurrentPidTgid())
        val ret = declareVar("ret", raw("(long)ctx->args[1]", BpfScalar.S64))

        // Lookup timestamp — if not found, this wasn't a tracked syscall
        val tsp = syscallStart.lookup(pidTgid)
        ifNonNull(tsp) { tspEntry ->
            // Lookup syscall number
            val nr = syscallNrMap.lookup(pidTgid)
            ifNonNull(nr) { nrEntry ->
                // Dereference scalar pointers to get values
                val tspVarName = (tspEntry.expr as BpfExpr.VarRef).variable.name
                val nrVarName = (nrEntry.expr as BpfExpr.VarRef).variable.name

                val deltaNs = declareVar(
                    "delta_ns",
                    ktimeGetNs() - raw("*$tspVarName", BpfScalar.U64)
                )
                val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())

                // Build composite key
                val key = stackVar(SyscallKey) {
                    it[SyscallKey.cgroupId] = cgroupId
                    it[SyscallKey.syscallNr] = raw("*$nrVarName", BpfScalar.U32)
                }

                // Lookup existing stats
                val stats = syscallStatsMap.lookup(key)
                ifNonNull(stats) { se ->
                    // Atomically update count
                    se[SyscallStats.count].atomicAdd(literal(1u, BpfScalar.U64))

                    // Conditionally increment error_count if ret < 0
                    ifThen(ret lt literal(0L, BpfScalar.S64)) {
                        se[SyscallStats.errorCount].atomicAdd(literal(1u, BpfScalar.U64))
                    }

                    // Atomically update latency sum
                    se[SyscallStats.latencySumNs].atomicAdd(deltaNs)

                    // Compute histogram slot and atomically update
                    val slot = declareVar(
                        "slot",
                        raw("log2l(delta_ns) >= MAX_SLOTS ? MAX_SLOTS - 1 : log2l(delta_ns)", BpfScalar.U32)
                    )
                    se[SyscallStats.latencySlots].at(slot).atomicAdd(literal(1u, BpfScalar.U64))
                }.elseThen {
                    // Build new stats entry
                    val newStats = stackVar(SyscallStats) {
                        it[SyscallStats.count] = literal(1u, BpfScalar.U64)
                        it[SyscallStats.errorCount] = raw("(ret < 0) ? 1ULL : 0ULL", BpfScalar.U64)
                        it[SyscallStats.latencySumNs] = deltaNs
                    }

                    // Compute slot and set latency_slots[slot] = 1
                    val slot2 = declareVar(
                        "slot2",
                        raw("log2l(delta_ns) >= MAX_SLOTS ? MAX_SLOTS - 1 : log2l(delta_ns)", BpfScalar.U32)
                    )
                    val newStatsName = (newStats.expr as BpfExpr.VarRef).variable.name
                    declareVar(
                        "_arr_set",
                        raw("($newStatsName.latency_slots[slot2] = 1ULL, (__s32)0)", BpfScalar.S32)
                    )
                    syscallStatsMap.update(key, newStats, flags = BPF_NOEXIST)
                }

                // Delete from both maps
                syscallStart.delete(pidTgid)
                syscallNrMap.delete(pidTgid)
            }.elseThen {
                // nr not found — just clean up syscall_start
                syscallStart.delete(pidTgid)
            }
        }

        returnValue(literal(0, BpfScalar.S32))
    }
}
