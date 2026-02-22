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

static __always_inline __u32 log2l(__u64 v) {
    __u32 r = 0;
    while (v > 1) {
        v >>= 1;
        r++;
    }
    return r;
}

#endif
