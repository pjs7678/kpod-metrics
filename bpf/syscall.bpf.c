#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

#define MAX_TRACKED_SYSCALLS 64

struct syscall_key {
    __u64 cgroup_id;
    __u32 syscall_nr;
    __u32 _pad;
};

struct syscall_stats {
    __u64 count;
    __u64 error_count;
    __u64 latency_sum_ns;
    __u64 latency_slots[MAX_SLOTS];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, __u64);
} syscall_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, __u32);
} syscall_nr_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct syscall_key);
    __type(value, struct syscall_stats);
} syscall_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TRACKED_SYSCALLS);
    __type(key, __u32);
    __type(value, __u8);
} tracked_syscalls SEC(".maps");

DEFINE_STATS_MAP(syscall_stats_map)

SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    __u32 syscall_nr = (__u32)ctx->args[1];
    __u8 *tracked = bpf_map_lookup_elem(&tracked_syscalls, &syscall_nr);
    if (!tracked) return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&syscall_start, &pid_tgid, &ts, BPF_ANY);
    bpf_map_update_elem(&syscall_nr_map, &pid_tgid, &syscall_nr, BPF_ANY);
    return 0;
}

SEC("raw_tracepoint/sys_exit")
int handle_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    long ret = (long)ctx->args[1];
    __u64 *tsp = bpf_map_lookup_elem(&syscall_start, &pid_tgid);
    if (!tsp) return 0;
    __u32 *nr = bpf_map_lookup_elem(&syscall_nr_map, &pid_tgid);
    if (!nr) {
        bpf_map_delete_elem(&syscall_start, &pid_tgid);
        return 0;
    }
    __u64 delta_ns = bpf_ktime_get_ns() - *tsp;
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct syscall_key key = {
        .cgroup_id = cgroup_id,
        .syscall_nr = *nr,
    };
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->count, 1);
        if (ret < 0) {
            __sync_fetch_and_add(&stats->error_count, 1);
        }
        __sync_fetch_and_add(&stats->latency_sum_ns, delta_ns);
        __u32 slot = log2l(delta_ns);
        if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
        __sync_fetch_and_add(&stats->latency_slots[slot], 1);
    } else {
        struct syscall_stats new_stats = {
            .count = 1,
            .error_count = (ret < 0) ? 1 : 0,
            .latency_sum_ns = delta_ns,
        };
        __u32 slot = log2l(delta_ns);
        if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
        new_stats.latency_slots[slot] = 1;
        int err = bpf_map_update_elem(&syscall_stats_map, &key, &new_stats, BPF_NOEXIST);
        if (err)
            STATS_INC(syscall_stats_map_stats, MAP_STAT_UPDATE_ERRORS);
        else
            STATS_INC(syscall_stats_map_stats, MAP_STAT_ENTRIES);
    }
    bpf_map_delete_elem(&syscall_start, &pid_tgid);
    bpf_map_delete_elem(&syscall_nr_map, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
