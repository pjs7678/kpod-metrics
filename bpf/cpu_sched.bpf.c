#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} wakeup_ts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct hist_key);
    __type(value, struct hist_value);
} runq_latency SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct counter_key);
    __type(value, struct counter_value);
} ctx_switches SEC(".maps");

SEC("tp/sched/sched_wakeup")
int handle_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx) {
    __u32 pid = ctx->pid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&wakeup_ts, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("tp/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    __u32 next_pid = ctx->next_pid;
    /*
     * bpf_get_current_cgroup_id() returns the cgroup of the outgoing task
     * (i.e. the task being switched OUT), not the incoming task (next_pid).
     *
     * For ctx_switches this is semantically correct: the outgoing task is
     * the one performing the context switch.
     *
     * TODO: For runq_latency below, the latency value is correct (time
     * next_pid spent waiting in the run queue), but it is attributed to the
     * outgoing task's cgroup rather than next_pid's cgroup. Properly
     * resolving the incoming task's cgroup requires reading from the
     * task_struct via bpf_get_current_task_btf() or maintaining a separate
     * pid-to-cgroup map, which adds significant complexity. This is a known
     * limitation -- the cgroup attribution for runq_latency may be wrong
     * when the incoming and outgoing tasks belong to different cgroups.
     */
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    struct counter_key ckey = { .cgroup_id = cgroup_id };
    struct counter_value *cval = bpf_map_lookup_elem(&ctx_switches, &ckey);
    if (cval) {
        __sync_fetch_and_add(&cval->count, 1);
    } else {
        struct counter_value new_val = { .count = 1 };
        bpf_map_update_elem(&ctx_switches, &ckey, &new_val, BPF_NOEXIST);
    }

    __u64 *tsp = bpf_map_lookup_elem(&wakeup_ts, &next_pid);
    if (!tsp) return 0;

    __u64 delta_ns = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&wakeup_ts, &next_pid);

    struct hist_key hkey = { .cgroup_id = cgroup_id };
    struct hist_value *hval = bpf_map_lookup_elem(&runq_latency, &hkey);
    if (hval) {
        __u32 slot = log2l(delta_ns);
        if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
        __sync_fetch_and_add(&hval->slots[slot], 1);
        __sync_fetch_and_add(&hval->count, 1);
        __sync_fetch_and_add(&hval->sum_ns, delta_ns);
    } else {
        struct hist_value new_val = {};
        __u32 slot = log2l(delta_ns);
        if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
        new_val.slots[slot] = 1;
        new_val.count = 1;
        new_val.sum_ns = delta_ns;
        bpf_map_update_elem(&runq_latency, &hkey, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
