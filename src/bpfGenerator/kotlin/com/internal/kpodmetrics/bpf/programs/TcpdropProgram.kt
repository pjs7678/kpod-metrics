package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.tools.CgroupKey
import dev.ebpf.dsl.tools.Counter
import dev.ebpf.dsl.types.BpfScalar

/**
 * Custom tcpdrop program that handles `tcp_drop` being inlined on newer kernels.
 *
 * On kernel 6.x, `tcp_drop()` is inlined by GCC and cannot be kprobed.
 * We use `#ifdef LEGACY_IOVEC` to select the correct attachment:
 *   - Legacy build (4.18): kprobe/tcp_drop (function exists)
 *   - Core build (5.17+): tracepoint/skb/kfree_skb with reason filtering
 *
 * The kfree_skb tracepoint fires for ALL skb frees. We filter by
 * reason >= SKB_DROP_REASON_NOT_SPECIFIED (2) to only count actual drops.
 */
val tcpdropProgram = ebpf("tcpdrop") {
    license("GPL")
    targetKernel("5.3")

    preamble("#define SKB_DROP_REASON_NOT_SPECIFIED 2")

    // Emit entire program as conditional raw C
    postamble("""
#ifdef LEGACY_IOVEC
SEC("kprobe/tcp_drop")
int kprobe_tcp_drop(struct pt_regs *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct cgroup_key key = { .cgroup_id = cgroup_id };
    struct counter *e = bpf_map_lookup_elem(&tcp_drops, &key);
    if (e) {
        __sync_fetch_and_add(&e->count, 1ULL);
    } else {
        struct counter v = { .count = 1ULL };
        bpf_map_update_elem(&tcp_drops, &key, &v, 1);
    }
    return 0;
}
#else
/* kfree_skb tracepoint context layout (from /sys/kernel/tracing/events/skb/kfree_skb/format) */
struct kfree_skb_args {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    int common_pid;
    void *skbaddr;
    void *location;
    __u16 protocol;
    __u16 __pad;
    __u32 reason;
};

SEC("tracepoint/skb/kfree_skb")
int tp_kfree_skb(struct kfree_skb_args *ctx)
{
    if (ctx->reason < SKB_DROP_REASON_NOT_SPECIFIED) return 0;
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct cgroup_key key = { .cgroup_id = cgroup_id };
    struct counter *e = bpf_map_lookup_elem(&tcp_drops, &key);
    if (e) {
        __sync_fetch_and_add(&e->count, 1ULL);
    } else {
        struct counter v = { .count = 1ULL };
        bpf_map_update_elem(&tcp_drops, &key, &v, 1);
    }
    return 0;
}
#endif
""".trimIndent())

    // Map declaration only — program logic is in postamble
    val tcpDrops by lruHashMap(CgroupKey, Counter, maxEntries = 10240)
}
