package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

// ── TCP peer structs ────────────────────────────────────────────────

object TcpPeerConnKey : BpfStruct("tcp_peer_conn_key") {
    val cgroupId by u64()
    val remoteIp4 by u32()
    val remotePort by u16()
    val direction by u8()
    val pad by u8()
}

object TcpPeerRttKey : BpfStruct("tcp_peer_rtt_key") {
    val cgroupId by u64()
    val remoteIp4 by u32()
    val remotePort by u16()
    val pad by u16()
}

// Re-use hist_value but with sum_us instead of sum_ns.
// Since the C struct field name comes from the BpfStruct definition,
// we define a separate struct for tcp_peer RTT histograms.
object TcpPeerHistValue : BpfStruct("tcp_peer_hist_value") {
    val slots by array(BpfScalar.U64, 27)
    val count by u64()
    val sumUs by u64()
}

// ── TCP peer preamble ───────────────────────────────────────────────

private val TCP_PEER_PREAMBLE = """
#define HIST_SLOTS 27
#define DIR_CLIENT 0
#define DIR_SERVER 1
#define LOOPBACK_IP4 0x0100007F

$COMMON_PREAMBLE
""".trimIndent()

private val TCP_PEER_POSTAMBLE = """
static __always_inline void inc_counter(void *map, void *key)
{
    struct counter_value *val = bpf_map_lookup_elem(map, key);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
    } else {
        struct counter_value one = { .count = 1 };
        bpf_map_update_elem(map, key, &one, BPF_NOEXIST);
    }
}
""".trimIndent()

// ── TCP peer program ────────────────────────────────────────────────

@Suppress("DEPRECATION")
val tcpPeerProgram = ebpf("tcp_peer") {
    license("GPL")
    targetKernel("5.5")

    preamble(TCP_PEER_PREAMBLE)
    postamble(TCP_PEER_POSTAMBLE)

    // ── Maps ─────────────────────────────────────────────────────────
    val tcpPeerConns by lruHashMap(TcpPeerConnKey, CounterValue, maxEntries = 10240)
    val tcpPeerRtt by lruHashMap(TcpPeerRttKey, TcpPeerHistValue, maxEntries = 10240)

    // ── kprobe/tcp_connect ───────────────────────────────────────────
    kprobe("tcp_connect") {
        declareVar("_tcp_connect", raw("""({
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    __u32 daddr;
    if (bpf_probe_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr) < 0)
        return 0;
    if (daddr == 0 || daddr == LOOPBACK_IP4)
        return 0;
    __u16 dport_be;
    if (bpf_probe_read(&dport_be, sizeof(dport_be), &sk->__sk_common.skc_dport) < 0)
        return 0;
    __u16 dport = __builtin_bswap16(dport_be);
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tcp_peer_conn_key key = {
        .cgroup_id = cgroup_id,
        .remote_ip4 = daddr,
        .remote_port = dport,
        .direction = DIR_CLIENT,
    };
    inc_counter(&tcp_peer_conns, &key);
    (__s32)0;
})""", BpfScalar.S32))
        returnValue(literal(0, BpfScalar.S32))
    }

    // ── kretprobe/inet_csk_accept ────────────────────────────────────
    kretprobe("inet_csk_accept") {
        declareVar("_tcp_accept", raw("""({
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!sk) return 0;
    __u32 daddr;
    if (bpf_probe_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr) < 0)
        return 0;
    if (daddr == 0 || daddr == LOOPBACK_IP4)
        return 0;
    __u16 dport_be;
    if (bpf_probe_read(&dport_be, sizeof(dport_be), &sk->__sk_common.skc_dport) < 0)
        return 0;
    __u16 dport = __builtin_bswap16(dport_be);
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tcp_peer_conn_key key = {
        .cgroup_id = cgroup_id,
        .remote_ip4 = daddr,
        .remote_port = dport,
        .direction = DIR_SERVER,
    };
    inc_counter(&tcp_peer_conns, &key);
    (__s32)0;
})""", BpfScalar.S32))
        returnValue(literal(0, BpfScalar.S32))
    }

    // ── tp/tcp/tcp_probe (RTT histogram) ─────────────────────────────
    tracepoint("tcp", "tcp_probe") {
        declareVar("_tcp_rtt", raw("""({
    struct trace_event_raw_tcp_probe *tp =
        (struct trace_event_raw_tcp_probe *)ctx;
    __u32 srtt = tp->srtt;
    if (srtt == 0) return 0;
    __u64 rtt_us = (__u64)srtt * 8;
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u16 dport = tp->dport;
    __u32 daddr;
    bpf_probe_read_kernel(&daddr, sizeof(daddr), tp->daddr);
    if (daddr == 0 || daddr == LOOPBACK_IP4) return 0;
    struct tcp_peer_rtt_key key = {
        .cgroup_id = cgroup_id,
        .remote_ip4 = daddr,
        .remote_port = dport,
    };
    struct tcp_peer_hist_value *hist = bpf_map_lookup_elem(&tcp_peer_rtt, &key);
    if (hist) {
        __u32 slot = log2l(rtt_us);
        if (slot >= HIST_SLOTS) slot = HIST_SLOTS - 1;
        __sync_fetch_and_add(&hist->slots[slot], 1);
        __sync_fetch_and_add(&hist->count, 1);
        __sync_fetch_and_add(&hist->sum_us, rtt_us);
    } else {
        struct tcp_peer_hist_value new_hist = {};
        __u32 slot = log2l(rtt_us);
        if (slot >= HIST_SLOTS) slot = HIST_SLOTS - 1;
        new_hist.slots[slot] = 1;
        new_hist.count = 1;
        new_hist.sum_us = rtt_us;
        bpf_map_update_elem(&tcp_peer_rtt, &key, &new_hist, BPF_NOEXIST);
    }
    (__s32)0;
})""", BpfScalar.S32))
        returnValue(literal(0, BpfScalar.S32))
    }
}
