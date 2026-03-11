package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.tools.CacheStats
import dev.ebpf.dsl.tools.CgroupKey
import dev.ebpf.dsl.types.BpfScalar

/**
 * Custom cachestat program that handles the kernel 5.16+ folio rename.
 *
 * `account_page_dirtied` was removed in 5.16+ (replaced by `folio_account_dirtied`).
 * We use `#ifdef LEGACY_IOVEC` to select the correct kprobe target:
 *   - Legacy build (4.18): kprobe/account_page_dirtied
 *   - Core build (5.16+): kprobe/folio_account_dirtied
 *
 * The other three probes (mark_page_accessed, add_to_page_cache_lru, mark_buffer_dirty)
 * are stable across all supported kernels.
 */
val cachestatProgram = ebpf("cachestat") {
    license("GPL")
    targetKernel("5.3")

    // Emit the conditional dirtied probe as raw C after struct/map definitions
    postamble("""
#ifdef LEGACY_IOVEC
SEC("kprobe/account_page_dirtied")
int kprobe_account_page_dirtied(struct pt_regs *ctx)
#else
SEC("kprobe/folio_account_dirtied")
int kprobe_folio_account_dirtied(struct pt_regs *ctx)
#endif
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct cgroup_key key = { .cgroup_id = cgroup_id };
    struct cache_stats *e = bpf_map_lookup_elem(&cache_stats, &key);
    if (e) {
        __sync_fetch_and_add(&e->dirtied, 1ULL);
    } else {
        struct cache_stats v = { .dirtied = 1ULL };
        bpf_map_update_elem(&cache_stats, &key, &v, 1);
    }
    return 0;
}
""".trimIndent())

    val cacheStats by lruHashMap(CgroupKey, CacheStats, maxEntries = 10240)

    kprobe("mark_page_accessed") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = cacheStats.lookup(key)
        ifNonNull(entry) { e ->
            e[CacheStats.accesses].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(CacheStats) { it[CacheStats.accesses] = literal(1u, BpfScalar.U64) }
            cacheStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    kprobe("add_to_page_cache_lru") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = cacheStats.lookup(key)
        ifNonNull(entry) { e ->
            e[CacheStats.additions].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(CacheStats) { it[CacheStats.additions] = literal(1u, BpfScalar.U64) }
            cacheStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    // account_page_dirtied / folio_account_dirtied is handled by postamble above

    kprobe("mark_buffer_dirty") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = cacheStats.lookup(key)
        ifNonNull(entry) { e ->
            e[CacheStats.bufDirtied].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(CacheStats) { it[CacheStats.bufDirtied] = literal(1u, BpfScalar.U64) }
            cacheStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
