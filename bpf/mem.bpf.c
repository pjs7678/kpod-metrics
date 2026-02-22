#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct counter_key);
    __type(value, struct counter_value);
} oom_kills SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct counter_key);
    __type(value, struct counter_value);
} major_faults SEC(".maps");

SEC("tp/oom/mark_victim")
int handle_oom_kill(struct trace_event_raw_mark_victim *ctx) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct counter_key key = { .cgroup_id = cgroup_id };
    struct counter_value *val = bpf_map_lookup_elem(&oom_kills, &key);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
    } else {
        struct counter_value new_val = { .count = 1 };
        bpf_map_update_elem(&oom_kills, &key, &new_val, BPF_NOEXIST);
    }
    return 0;
}

SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(handle_page_fault, struct vm_area_struct *vma,
               unsigned long address, unsigned int flags) {
    if (!(flags & 0x4))
        return 0;
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct counter_key key = { .cgroup_id = cgroup_id };
    struct counter_value *val = bpf_map_lookup_elem(&major_faults, &key);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
    } else {
        struct counter_value new_val = { .count = 1 };
        bpf_map_update_elem(&major_faults, &key, &new_val, BPF_NOEXIST);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
