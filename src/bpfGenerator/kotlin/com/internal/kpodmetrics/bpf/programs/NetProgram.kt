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

/** IPv4 TCP 4-tuple from the local side: addresses as stored by the kernel, ports host-order. */
object FlowKey : BpfStruct("flow_key") {
    val saddr by u32()
    val daddr by u32()
    val sport by u16()
    val dport by u16()
}

object SockOwnerVal : BpfStruct("sock_owner_val") {
    val cgroupId by u64()
}

/**
 * Socket-owner attribution. tcp_probe, tcp_retransmit_skb and most inet_sock_set_state events
 * run in softirq context, where bpf_get_current_cgroup_id() is whatever task the interrupt
 * landed on — on a busy node usually a CPU-heavy pod that never touched the socket. Dogfooding
 * showed TCP RTT on pods with no network activity and none on the pod actually talking.
 *
 * The owner is recorded in process context (connect, accept, send/recv — the last also covers
 * connections that predate the agent) keyed by 4-tuple, which every relevant tracepoint carries
 * on every kernel (tcp_probe dropped skaddr in newer kernels). Softirq-side events look the
 * owner up; unknown flows are skipped rather than misattributed. IPv4 only.
 */
internal val NET_OWNER_POSTAMBLE = SOCK_FLOW_HELPERS + """

/* Local flavor: the legacy header lacks this struct; CO-RE relocates fields by name. */
struct trace_event_raw_tcp_event_sk_skb___kpod {
    struct trace_entry ent;
    const void *skbaddr;
    const void *skaddr;
    int state;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 saddr[4];
    __u8 daddr[4];
} __attribute__((preserve_access_index));

/* Process context only: the current task owns the socket. Writes only when the owner changed. */
static __always_inline void kpod_record_owner(struct sock *sk)
{
    struct flow_key k = {};
    if (!sk || kpod_flow_from_sk(sk, &k) < 0) return;
    __u64 cg = bpf_get_current_cgroup_id();
    struct sock_owner_val *o = bpf_map_lookup_elem(&sock_owner, &k);
    if (o && o->cgroup_id == cg) return;
    struct sock_owner_val v = { .cgroup_id = cg };
    bpf_map_update_elem(&sock_owner, &k, &v, BPF_ANY);
}

static __always_inline __u64 kpod_owner_lookup(struct flow_key *k)
{
    struct sock_owner_val *o = bpf_map_lookup_elem(&sock_owner, k);
    return o ? o->cgroup_id : 0;
}

static __always_inline int kpod_flow_from_state(void *ctx, struct flow_key *k)
{
    struct trace_event_raw_inet_sock_set_state *tp = ctx;
    /* saddr/daddr hold inet_saddr/inet_daddr for AF_INET and IPv4-mapped AF_INET6 alike */
    bpf_probe_read(&k->saddr, 4, tp->saddr);
    bpf_probe_read(&k->daddr, 4, tp->daddr);
    k->sport = tp->sport;
    k->dport = tp->dport;
    return (k->saddr && k->daddr) ? 0 : -1;
}

static __always_inline __u64 kpod_owner_state(void *ctx)
{
    struct flow_key k = {};
    if (kpod_flow_from_state(ctx, &k) < 0) return 0;
    return kpod_owner_lookup(&k);
}

static __always_inline void kpod_forget_flow(void *ctx)
{
    struct flow_key k = {};
    if (kpod_flow_from_state(ctx, &k) < 0) return;
    bpf_map_delete_elem(&sock_owner, &k);
}

static __always_inline __u64 kpod_owner_sk_skb(void *ctx)
{
    struct trace_event_raw_tcp_event_sk_skb___kpod *tp = ctx;
    struct flow_key k = {};
    bpf_probe_read(&k.saddr, 4, tp->saddr);
    bpf_probe_read(&k.daddr, 4, tp->daddr);
    k.sport = tp->sport;
    k.dport = tp->dport;
    if (!k.saddr || !k.daddr) return 0;
    return kpod_owner_lookup(&k);
}

/* tcp_probe carries sockaddr_in/in6 (28 bytes), not raw addresses. */
static __always_inline __u64 kpod_owner_tcp_probe(void *ctx)
{
    struct trace_event_raw_tcp_probe *tp = ctx;
    struct flow_key k = {};
    if (kpod_sockaddr_v4(tp->saddr, &k.saddr) < 0 || kpod_sockaddr_v4(tp->daddr, &k.daddr) < 0) return 0;
    k.sport = tp->sport;
    k.dport = tp->dport;
    return kpod_owner_lookup(&k);
}
"""

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
    // 32768 x (12 B key + 8 B value + LRU overhead) ~ 3 MiB of kernel memory charged to the agent
    @Suppress("UNUSED_VARIABLE")
    val sockOwner by lruHashMap(FlowKey, SockOwnerVal, maxEntries = 32768)

    postamble(NET_OWNER_POSTAMBLE)

    // ── Program 1: kprobe/tcp_sendmsg ───────────────────────────────────
    kprobe("tcp_sendmsg") {
        declareVar("_own", raw("(kpod_record_owner((struct sock *)PT_REGS_PARM1(ctx)), (__s32)0)", BpfScalar.S32))
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
        declareVar("_own", raw("(kpod_record_owner((struct sock *)PT_REGS_PARM1(ctx)), (__s32)0)", BpfScalar.S32))
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

    // ── Owner recording at connection setup (process context) ──────────
    kprobe("tcp_connect") {
        declareVar("_own", raw("(kpod_record_owner((struct sock *)PT_REGS_PARM1(ctx)), (__s32)0)", BpfScalar.S32))
        returnValue(literal(0, BpfScalar.S32))
    }

    // Passive open: the accepting task owns the new socket; count the connection here.
    kretprobe("inet_csk_accept") {
        val sk = declareVar("sk", raw("(__u64)PT_REGS_RC(ctx)", BpfScalar.U64))
        ifThen(sk eq literal(0u, BpfScalar.U64)) { returnValue(literal(0, BpfScalar.S32)) }
        declareVar("_own", raw("(kpod_record_owner((struct sock *)sk), (__s32)0)", BpfScalar.S32))
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
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
        returnValue(literal(0, BpfScalar.S32))
    }

    // ── Program 3: tp/tcp/tcp_retransmit_skb ────────────────────────────
    tracepoint("tcp", "tcp_retransmit_skb") {
        // softirq/timer context: attribute to the socket's owner, not the interrupted task
        val cgroupId = declareVar("cgroup_id", raw("kpod_owner_sk_skb(ctx)", BpfScalar.U64))
        ifThen(cgroupId eq literal(0u, BpfScalar.U64)) { returnValue(literal(0, BpfScalar.S32)) }
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
        val oldstate = declareVar(
            "oldstate",
            raw("((struct trace_event_raw_inet_sock_set_state *)ctx)->oldstate", BpfScalar.S32)
        )
        // TCP_CLOSE (7): drop the owner entry so a reused 4-tuple starts clean
        ifThen(newstate eq literal(7, BpfScalar.S32)) {
            declareVar("_fg", raw("(kpod_forget_flow(ctx), (__s32)0)", BpfScalar.S32))
            returnValue(literal(0, BpfScalar.S32))
        }
        // Count active opens here (SYN_SENT -> ESTABLISHED runs in softirq, so use the owner
        // recorded at tcp_connect); passive opens are counted at inet_csk_accept return.
        val cgroupId = declareVar("cgroup_id", raw("kpod_owner_state(ctx)", BpfScalar.U64))
        ifThen((newstate eq literal(1, BpfScalar.S32)) and (oldstate eq literal(2, BpfScalar.S32)) and
            (cgroupId ne literal(0u, BpfScalar.U64))) {
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
        // softirq context (ACK processing): attribute to the socket's owner
        val cgroupId = declareVar("cgroup_id", raw("kpod_owner_tcp_probe(ctx)", BpfScalar.U64))
        ifThen(cgroupId eq literal(0u, BpfScalar.U64)) { returnValue(literal(0, BpfScalar.S32)) }
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
                histSlot(histUnits(rttNs), 27)
            )
            he[HistValue.slots].at(slot).atomicAdd(literal(1u, BpfScalar.U64))
            he[HistValue.count].atomicAdd(literal(1u, BpfScalar.U64))
            he[HistValue.sumNs].atomicAdd(rttNs)
        }.elseThen {
            val slot2 = declareVar(
                "slot2",
                histSlot(histUnits(rttNs), 27)
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
