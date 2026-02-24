#ifndef KPOD_COMMON_H
#define KPOD_COMMON_H

#define MAX_ENTRIES 10240
#define MAX_SLOTS 27

struct hist_key {
    __u64 cgroup_id;
};

struct hist_value {
    __u64 slots[MAX_SLOTS];
    __u64 count;
    __u64 sum_ns;
};

struct counter_key {
    __u64 cgroup_id;
};

struct counter_value {
    __u64 count;
};

/* --- Map stats infrastructure --- */

enum map_stat_idx {
    MAP_STAT_ENTRIES = 0,
    MAP_STAT_UPDATE_ERRORS = 1,
    MAP_STAT_MAX = 2,
};

#define DEFINE_STATS_MAP(name) \
struct { \
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); \
    __uint(max_entries, MAP_STAT_MAX); \
    __type(key, __u32); \
    __type(value, __s64); \
} name##_stats SEC(".maps");

#define STATS_INC(map, idx) do { \
    __u32 _k = (idx); \
    __s64 *_v = bpf_map_lookup_elem(&map, &_k); \
    if (_v) __sync_fetch_and_add(_v, 1); \
} while(0)

#define STATS_DEC(map, idx) do { \
    __u32 _k = (idx); \
    __s64 *_v = bpf_map_lookup_elem(&map, &_k); \
    if (_v) __sync_fetch_and_add(_v, -1); \
} while(0)

static __always_inline __u32 log2l(__u64 v) {
    __u32 r = 0;
    while (v > 1) {
        v >>= 1;
        r++;
    }
    return r;
}

#endif
