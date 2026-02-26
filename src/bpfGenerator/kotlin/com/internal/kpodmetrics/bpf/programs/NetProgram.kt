package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

/**
 * tcp_stats struct — defined here (not in Structs.kt) because it is specific
 * to the net program. It has 6 u64 fields matching the hand-written C struct.
 */
object TcpStats : BpfStruct("tcp_stats") {
    val bytesSent by u64()
    val bytesReceived by u64()
    val retransmits by u64()
    val connections by u64()
    val rttSumUs by u64()
    val rttCount by u64()
}

/**
 * DSL definition for the net BPF program.
 *
 * This generates C code structurally equivalent to the hand-written `bpf/net.bpf.c`.
 * It defines two LRU_HASH maps and five programs:
 *
 * Maps:
 *   - tcp_stats_map: LRU_HASH, key=counter_key, value=tcp_stats
 *   - rtt_hist:      LRU_HASH, key=hist_key, value=hist_value
 *
 * Programs:
 *   - kprobe/tcp_sendmsg:           atomicAdd bytes_sent by size (3rd arg)
 *   - kprobe/tcp_recvmsg:           atomicAdd bytes_received by len (3rd arg)
 *   - tp/tcp/tcp_retransmit_skb:    atomicAdd retransmits by 1
 *   - tp/sock/inet_sock_set_state:  if newstate==1 (TCP_ESTABLISHED), atomicAdd connections by 1
 *   - tp/tcp/tcp_probe:             atomicAdd rtt_sum_us and rtt_count; histogram update on rtt_hist
 *
 * Note: Stats tracking (STATS_INC/STATS_DEC) in the else branches is omitted from
 * the DSL logic. The DEFINE_STATS_MAP macros are included in the preamble so the
 * stats maps are still created (for compatibility), but are not written to by the
 * generated program body.
 */
val netProgram = ebpf("net") {
    license("GPL")
    targetKernel("5.3")

    preamble(
        COMMON_PREAMBLE +
            "\n\nDEFINE_STATS_MAP(tcp_stats_map)\nDEFINE_STATS_MAP(rtt_hist)"
    )

    // ── Maps ────────────────────────────────────────────────────────────
    val tcpStatsMap by lruHashMap(CounterKey, TcpStats, maxEntries = 10240)
    val rttHist by lruHashMap(HistKey, HistValue, maxEntries = 10240)

    // ── Program 1: kprobe/tcp_sendmsg ───────────────────────────────────
    kprobe("tcp_sendmsg") {
        val size = declareVar("size", raw("(size_t)PT_REGS_PARM3(ctx)", BpfScalar.U64))
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CounterKey) {
            it[CounterKey.cgroupId] = cgroupId
        }
        val entry = tcpStatsMap.lookup(key)
        ifNonNull(entry) { e ->
            e[TcpStats.bytesSent].atomicAdd(size)
        }.elseThen {
            val newVal = stackVar(TcpStats) {
                it[TcpStats.bytesSent] = size
            }
            tcpStatsMap.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    // ── Program 2: kprobe/tcp_recvmsg ───────────────────────────────────
    kprobe("tcp_recvmsg") {
        val len = declareVar("len", raw("(size_t)PT_REGS_PARM3(ctx)", BpfScalar.U64))
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CounterKey) {
            it[CounterKey.cgroupId] = cgroupId
        }
        val entry = tcpStatsMap.lookup(key)
        ifNonNull(entry) { e ->
            e[TcpStats.bytesReceived].atomicAdd(len)
        }.elseThen {
            val newVal = stackVar(TcpStats) {
                it[TcpStats.bytesReceived] = len
            }
            tcpStatsMap.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    // ── Program 3: tp/tcp/tcp_retransmit_skb ────────────────────────────
    tracepoint("tcp", "tcp_retransmit_skb") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CounterKey) {
            it[CounterKey.cgroupId] = cgroupId
        }
        val entry = tcpStatsMap.lookup(key)
        ifNonNull(entry) { e ->
            e[TcpStats.retransmits].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(TcpStats) {
                it[TcpStats.retransmits] = literal(1u, BpfScalar.U64)
            }
            tcpStatsMap.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    // ── Program 4: tp/sock/inet_sock_set_state ──────────────────────────
    tracepoint("sock", "inet_sock_set_state") {
        val newstate = declareVar(
            "newstate",
            raw("((struct trace_event_raw_inet_sock_set_state *)ctx)->newstate", BpfScalar.S32)
        )
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())

        // Only count when newstate == 1 (TCP_ESTABLISHED)
        ifThen(newstate eq literal(1, BpfScalar.S32)) {
            val key = stackVar(CounterKey) {
                it[CounterKey.cgroupId] = cgroupId
            }
            val entry = tcpStatsMap.lookup(key)
            ifNonNull(entry) { e ->
                e[TcpStats.connections].atomicAdd(literal(1u, BpfScalar.U64))
            }.elseThen {
                val newVal = stackVar(TcpStats) {
                    it[TcpStats.connections] = literal(1u, BpfScalar.U64)
                }
                tcpStatsMap.update(key, newVal, flags = BPF_NOEXIST)
            }
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    // ── Program 5: tp/tcp/tcp_probe ─────────────────────────────────────
    tracepoint("tcp", "tcp_probe") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val srttUs = declareVar(
            "srtt_us",
            raw("((struct trace_event_raw_tcp_probe *)ctx)->srtt", BpfScalar.U32)
        )

        // ── Part 1: Update tcp_stats (rtt_sum_us, rtt_count) ────────────
        val key = stackVar(CounterKey) {
            it[CounterKey.cgroupId] = cgroupId
        }
        val stats = tcpStatsMap.lookup(key)
        ifNonNull(stats) { e ->
            e[TcpStats.rttSumUs].atomicAdd(srttUs)
            e[TcpStats.rttCount].atomicAdd(literal(1u, BpfScalar.U64))
        }

        // ── Part 2: Update rtt_hist histogram ───────────────────────────
        val rttNs = declareVar("rtt_ns", raw("(__u64)srtt_us * 1000", BpfScalar.U64))
        val hkey = stackVar(HistKey) {
            it[HistKey.cgroupId] = cgroupId
        }
        val hval = rttHist.lookup(hkey)
        ifNonNull(hval) { he ->
            val slot = declareVar(
                "slot",
                raw("log2l(rtt_ns) >= MAX_SLOTS ? MAX_SLOTS - 1 : log2l(rtt_ns)", BpfScalar.U32)
            )
            he[HistValue.slots].at(slot).atomicAdd(literal(1u, BpfScalar.U64))
            he[HistValue.count].atomicAdd(literal(1u, BpfScalar.U64))
            he[HistValue.sumNs].atomicAdd(rttNs)
        }.elseThen {
            val slot2 = declareVar(
                "slot2",
                raw("log2l(rtt_ns) >= MAX_SLOTS ? MAX_SLOTS - 1 : log2l(rtt_ns)", BpfScalar.U32)
            )
            val newHval = stackVar(HistValue) {
                it[HistValue.count] = literal(1u, BpfScalar.U64)
                it[HistValue.sumNs] = rttNs
            }
            // Array assignment for slots[slot2] = 1 using raw C via declareVar
            val newHvalName = (newHval.expr as BpfExpr.VarRef).variable.name
            declareVar(
                "_arr_set",
                raw("($newHvalName.slots[slot2] = 1ULL, (__s32)0)", BpfScalar.S32)
            )
            rttHist.update(hkey, newHval, flags = BPF_NOEXIST)
        }

        returnValue(literal(0, BpfScalar.S32))
    }
}
