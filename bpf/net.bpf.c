#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

struct tcp_stats {
    __u64 bytes_sent;
    __u64 bytes_received;
    __u64 retransmits;
    __u64 connections;
    __u64 rtt_sum_us;
    __u64 rtt_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct counter_key);
    __type(value, struct tcp_stats);
} tcp_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, __u64);
} conn_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct hist_key);
    __type(value, struct hist_value);
} conn_latency SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct hist_key);
    __type(value, struct hist_value);
} rtt_hist SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(handle_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct counter_key key = { .cgroup_id = cgroup_id };
    struct tcp_stats *stats = bpf_map_lookup_elem(&tcp_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->bytes_sent, size);
    } else {
        struct tcp_stats new_stats = { .bytes_sent = size };
        bpf_map_update_elem(&tcp_stats_map, &key, &new_stats, BPF_NOEXIST);
    }
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(handle_tcp_recvmsg, struct sock *sk, struct msghdr *msg,
               size_t len, int flags, int *addr_len) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct counter_key key = { .cgroup_id = cgroup_id };
    struct tcp_stats *stats = bpf_map_lookup_elem(&tcp_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->bytes_received, len);
    } else {
        struct tcp_stats new_stats = { .bytes_received = len };
        bpf_map_update_elem(&tcp_stats_map, &key, &new_stats, BPF_NOEXIST);
    }
    return 0;
}

SEC("tp/tcp/tcp_retransmit_skb")
int handle_tcp_retransmit(struct trace_event_raw_tcp_event_sk_skb *ctx) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct counter_key key = { .cgroup_id = cgroup_id };
    struct tcp_stats *stats = bpf_map_lookup_elem(&tcp_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->retransmits, 1);
    } else {
        struct tcp_stats new_stats = { .retransmits = 1 };
        bpf_map_update_elem(&tcp_stats_map, &key, &new_stats, BPF_NOEXIST);
    }
    return 0;
}

SEC("tp/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    int newstate = ctx->newstate;
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (newstate == 1) {
        struct counter_key key = { .cgroup_id = cgroup_id };
        struct tcp_stats *stats = bpf_map_lookup_elem(&tcp_stats_map, &key);
        if (stats) {
            __sync_fetch_and_add(&stats->connections, 1);
        } else {
            struct tcp_stats new_stats = { .connections = 1 };
            bpf_map_update_elem(&tcp_stats_map, &key, &new_stats, BPF_NOEXIST);
        }
    }
    return 0;
}

SEC("tp/tcp/tcp_probe")
int handle_tcp_probe(struct trace_event_raw_tcp_probe *ctx) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u32 srtt_us = ctx->srtt;
    struct counter_key key = { .cgroup_id = cgroup_id };
    struct tcp_stats *stats = bpf_map_lookup_elem(&tcp_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->rtt_sum_us, srtt_us);
        __sync_fetch_and_add(&stats->rtt_count, 1);
    }
    struct hist_key hkey = { .cgroup_id = cgroup_id };
    __u64 rtt_ns = (__u64)srtt_us * 1000;
    struct hist_value *hval = bpf_map_lookup_elem(&rtt_hist, &hkey);
    if (hval) {
        __u32 slot = log2l(rtt_ns);
        if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
        __sync_fetch_and_add(&hval->slots[slot], 1);
        __sync_fetch_and_add(&hval->count, 1);
        __sync_fetch_and_add(&hval->sum_ns, rtt_ns);
    } else {
        struct hist_value new_val = {};
        __u32 slot = log2l(rtt_ns);
        if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
        new_val.slots[slot] = 1;
        new_val.count = 1;
        new_val.sum_ns = rtt_ns;
        bpf_map_update_elem(&rtt_hist, &hkey, &new_val, BPF_NOEXIST);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
