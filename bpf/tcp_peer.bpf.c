// bpf/tcp_peer.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define HIST_SLOTS 27
#define DIR_CLIENT 0
#define DIR_SERVER 1

/* Loopback 127.0.0.1 in network byte order */
#define LOOPBACK_IP4 0x0100007F

static __always_inline __u32 log2l(__u64 v)
{
    __u32 r = 0;
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if (v <= 1) break;
        v >>= 1;
        r++;
    }
    return r;
}

/* ── Map key/value structs ────────────────────────────────── */

struct tcp_peer_conn_key {
    __u64 cgroup_id;
    __u32 remote_ip4;
    __u16 remote_port;
    __u8  direction;
    __u8  _pad;
};

struct counter_value {
    __u64 count;
};

struct tcp_peer_rtt_key {
    __u64 cgroup_id;
    __u32 remote_ip4;
    __u16 remote_port;
    __u16 _pad;
};

struct hist_value {
    __u64 slots[HIST_SLOTS];
    __u64 count;
    __u64 sum_us;
};

/* ── Maps ─────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct tcp_peer_conn_key);
    __type(value, struct counter_value);
} tcp_peer_conns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct tcp_peer_rtt_key);
    __type(value, struct hist_value);
} tcp_peer_rtt SEC(".maps");

/* ── Helpers ──────────────────────────────────────────────── */

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

/* ── kprobe/tcp_connect ───────────────────────────────────── */

SEC("kprobe/tcp_connect")
int tcp_peer_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    __u32 daddr;
    if (bpf_probe_read(&daddr, sizeof(daddr),
                              &sk->__sk_common.skc_daddr) < 0)
        return 0;

    /* Skip if remote IP is 0 or loopback */
    if (daddr == 0 || daddr == LOOPBACK_IP4)
        return 0;

    __u16 dport_be;
    if (bpf_probe_read(&dport_be, sizeof(dport_be),
                              &sk->__sk_common.skc_dport) < 0)
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

    return 0;
}

/* ── kretprobe/inet_csk_accept ────────────────────────────── */

SEC("kretprobe/inet_csk_accept")
int tcp_peer_accept(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!sk)
        return 0;

    __u32 daddr;
    if (bpf_probe_read(&daddr, sizeof(daddr),
                              &sk->__sk_common.skc_daddr) < 0)
        return 0;

    /* Skip if remote IP is 0 or loopback */
    if (daddr == 0 || daddr == LOOPBACK_IP4)
        return 0;

    __u16 dport_be;
    if (bpf_probe_read(&dport_be, sizeof(dport_be),
                              &sk->__sk_common.skc_dport) < 0)
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

    return 0;
}

/* ── tp/tcp/tcp_probe ─────────────────────────────────────── */

SEC("tp/tcp/tcp_probe")
int tcp_peer_rtt_probe(void *ctx)
{
    struct trace_event_raw_tcp_probe *tp =
        (struct trace_event_raw_tcp_probe *)ctx;

    __u32 srtt = tp->srtt;
    if (srtt == 0)
        return 0;

    /* srtt is in microseconds >> 3, convert to actual microseconds */
    __u64 rtt_us = (__u64)srtt * 8;

    __u64 cgroup_id = bpf_get_current_cgroup_id();

    /* Extract remote IP and port from tracepoint fields.
       daddr is a __u8[28] sockaddr storage; for IPv4, first 4 bytes
       hold the 32-bit address in network byte order. */
    __u16 dport = tp->dport;
    __u32 daddr;
    bpf_probe_read_kernel(&daddr, sizeof(daddr), tp->daddr);

    if (daddr == 0 || daddr == LOOPBACK_IP4)
        return 0;

    struct tcp_peer_rtt_key key = {
        .cgroup_id = cgroup_id,
        .remote_ip4 = daddr,
        .remote_port = dport,
    };

    struct hist_value *hist = bpf_map_lookup_elem(&tcp_peer_rtt, &key);
    if (hist) {
        __u32 slot = log2l(rtt_us);
        if (slot >= HIST_SLOTS)
            slot = HIST_SLOTS - 1;
        __sync_fetch_and_add(&hist->slots[slot], 1);
        __sync_fetch_and_add(&hist->count, 1);
        __sync_fetch_and_add(&hist->sum_us, rtt_us);
    } else {
        struct hist_value new_hist = {};
        __u32 slot = log2l(rtt_us);
        if (slot >= HIST_SLOTS)
            slot = HIST_SLOTS - 1;
        new_hist.slots[slot] = 1;
        new_hist.count = 1;
        new_hist.sum_us = rtt_us;
        bpf_map_update_elem(&tcp_peer_rtt, &key, &new_hist, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
