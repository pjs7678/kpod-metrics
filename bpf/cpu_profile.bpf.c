// bpf/cpu_profile.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_STACK_DEPTH 128
#define MAX_PROFILE_ENTRIES 65536
#define MAX_STACK_ENTRIES 32768

struct profile_key {
    __u64 cgroup_id;
    __u32 tgid;
    __s32 kern_stack_id;
    __s32 user_stack_id;
} __attribute__((packed));

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

SEC("perf_event")
int cpu_profile(struct bpf_perf_event_data *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u64 tgid_pid = bpf_get_current_pid_tgid();
    __u32 tgid = tgid_pid >> 32;

    __s32 kern_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
    __s32 user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);

    struct profile_key key = {
        .cgroup_id = cgroup_id,
        .tgid = tgid,
        .kern_stack_id = kern_stack_id,
        .user_stack_id = user_stack_id,
    };

    __u64 *count = bpf_map_lookup_elem(&profile_counts, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&profile_counts, &key, &one, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
