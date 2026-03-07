// bpf/dns.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_DNS_PACKET 44
#define MAX_DOMAIN_LEN 32
#define MAX_LABELS 16
#define MAX_LABEL_LEN 63
#define HIST_SLOTS 27

static __always_inline __u32 log2l(__u64 v)
{
    __u32 r = 0;
    while (v > 1) {
        v >>= 1;
        r++;
    }
    return r;
}

/* ── Map key/value structs ────────────────────────────────── */

struct dns_port_key {
    __u16 port;
    __u16 _pad1;
    __u32 _pad2;
};

struct dns_port_val {
    __u8 enabled;
    __u8 _pad[7];
};

struct dns_req_key {
    __u64 cgroup_id;
    __u16 qtype;
    __u16 _pad1;
    __u32 _pad2;
};

struct counter_value {
    __u64 count;
};

struct hist_key {
    __u64 cgroup_id;
};

struct hist_value {
    __u64 slots[HIST_SLOTS];
    __u64 count;
    __u64 sum_ns;
};

struct dns_err_key {
    __u64 cgroup_id;
    __u8  rcode;
    __u8  _pad[7];
};

struct dns_domain_key {
    __u64 cgroup_id;
    __u8  domain[MAX_DOMAIN_LEN];
};

struct dns_txid_key {
    __u64 cgroup_id;
    __u16 txid;
    __u16 _pad1;
    __u32 _pad2;
};

struct ts_value {
    __u64 ts;
};

struct recv_stash {
    __u64 msghdr_ptr;
    __u64 cgroup_id;
};

/* ── Maps ─────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, struct dns_port_key);
    __type(value, struct dns_port_val);
} dns_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct dns_req_key);
    __type(value, struct counter_value);
} dns_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct hist_key);
    __type(value, struct hist_value);
} dns_latency SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct dns_err_key);
    __type(value, struct counter_value);
} dns_errors SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct dns_domain_key);
    __type(value, struct counter_value);
} dns_domains SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct dns_txid_key);
    __type(value, struct ts_value);
} dns_inflight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct recv_stash);
} recv_stash_map SEC(".maps");

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

/* ── kprobe/udp_sendmsg ───────────────────────────────────── */

SEC("kprobe/udp_sendmsg")
int dns_send(struct pt_regs *ctx)
{
    /* arg2 = struct msghdr *msg */
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

    /* Read msg_name pointer (sockaddr) */
    void *msg_name;
    if (bpf_probe_read_user(&msg_name, sizeof(msg_name), &msg->msg_name) < 0)
        return 0;

    /* Read dest port from sockaddr_in.sin_port (offset 2) */
    __u16 dport_be;
    if (bpf_probe_read_user(&dport_be, sizeof(dport_be),
                            (char *)msg_name + 2) < 0)
        return 0;
    __u16 dport = __builtin_bswap16(dport_be);

    /* Check if this port is a DNS port */
    struct dns_port_key port_key = { .port = dport };
    if (!bpf_map_lookup_elem(&dns_ports, &port_key))
        return 0;

    /* Read msg_iov pointer */
    struct iovec *msg_iov;
    if (bpf_probe_read_user(&msg_iov, sizeof(msg_iov), &msg->msg_iov) < 0)
        return 0;

    /* Read first iov entry */
    struct iovec iov0;
    if (bpf_probe_read_user(&iov0, sizeof(iov0), msg_iov) < 0)
        return 0;

    if (iov0.iov_len < 17)
        return 0;

    /* Read first MAX_DNS_PACKET bytes of DNS packet */
    __u8 pkt[MAX_DNS_PACKET];
    __builtin_memset(pkt, 0, sizeof(pkt));
    if (bpf_probe_read_user(pkt, sizeof(pkt), iov0.iov_base) < 0)
        return 0;

    /* Parse DNS header: bytes 0-1 = txid, bytes 2-3 = flags */
    __u16 txid = ((__u16)pkt[0] << 8) | pkt[1];
    __u16 flags = ((__u16)pkt[2] << 8) | pkt[3];

    /* QR bit is bit 15 of flags; skip if this is a response */
    if (flags & 0x8000)
        return 0;

    __u64 cgroup_id = bpf_get_current_cgroup_id();

    /* Decode QNAME starting at byte 12 into domain[32] */
    __u8 domain[MAX_DOMAIN_LEN];
    __builtin_memset(domain, 0, sizeof(domain));
    __u32 pkt_off = 12;   /* offset into pkt[] */
    __u32 dom_off = 0;    /* offset into domain[] */

    #pragma unroll
    for (int label = 0; label < MAX_LABELS; label++) {
        if (pkt_off >= MAX_DNS_PACKET)
            break;

        __u8 label_len = pkt[pkt_off];
        if (label_len == 0)
            break;
        if (label_len > MAX_LABEL_LEN)
            break;

        /* Add dot separator between labels */
        if (dom_off > 0 && dom_off < MAX_DOMAIN_LEN) {
            domain[dom_off] = '.';
            dom_off++;
        }

        pkt_off++;

        #pragma unroll
        for (int c = 0; c < MAX_LABEL_LEN; c++) {
            if (c >= label_len)
                break;
            if (pkt_off >= MAX_DNS_PACKET)
                break;
            if (dom_off >= MAX_DOMAIN_LEN)
                break;
            domain[dom_off] = pkt[pkt_off];
            dom_off++;
            pkt_off++;
        }
    }

    /* Extract qtype: 2 bytes after QNAME null terminator */
    __u16 qtype = 0;
    __u32 qtype_off = pkt_off + 1; /* skip null terminator */
    if (qtype_off + 1 < MAX_DNS_PACKET)
        qtype = ((__u16)pkt[qtype_off] << 8) | pkt[qtype_off + 1];

    /* Store timestamp in dns_inflight for latency tracking */
    struct dns_txid_key txid_key = {
        .cgroup_id = cgroup_id,
        .txid = txid,
    };
    struct ts_value ts_val = { .ts = bpf_ktime_get_ns() };
    bpf_map_update_elem(&dns_inflight, &txid_key, &ts_val, BPF_NOEXIST);

    /* Increment dns_requests[cgroup_id + qtype] */
    struct dns_req_key req_key = {
        .cgroup_id = cgroup_id,
        .qtype = qtype,
    };
    inc_counter(&dns_requests, &req_key);

    /* Increment dns_domains[cgroup_id + domain] */
    struct dns_domain_key dom_key = { .cgroup_id = cgroup_id };
    __builtin_memcpy(dom_key.domain, domain, MAX_DOMAIN_LEN);
    inc_counter(&dns_domains, &dom_key);

    return 0;
}

/* ── kprobe/udp_recvmsg ───────────────────────────────────── */

SEC("kprobe/udp_recvmsg")
int dns_recv_enter(struct pt_regs *ctx)
{
    __u32 zero = 0;
    struct recv_stash *stash = bpf_map_lookup_elem(&recv_stash_map, &zero);
    if (!stash)
        return 0;

    stash->msghdr_ptr = (__u64)PT_REGS_PARM2(ctx);
    stash->cgroup_id = bpf_get_current_cgroup_id();

    return 0;
}

/* ── kretprobe/udp_recvmsg ────────────────────────────────── */

SEC("kretprobe/udp_recvmsg")
int dns_recv_exit(struct pt_regs *ctx)
{
    long ret = (long)PT_REGS_RC(ctx);
    if (ret < 12)
        return 0;

    /* Retrieve stashed data */
    __u32 zero = 0;
    struct recv_stash *stash = bpf_map_lookup_elem(&recv_stash_map, &zero);
    if (!stash)
        return 0;

    struct msghdr *msg = (struct msghdr *)stash->msghdr_ptr;
    __u64 cgroup_id = stash->cgroup_id;

    /* Extract source port from msg_name (sockaddr_in.sin_port) */
    void *msg_name;
    if (bpf_probe_read_user(&msg_name, sizeof(msg_name), &msg->msg_name) < 0)
        return 0;

    __u16 sport_be;
    if (bpf_probe_read_user(&sport_be, sizeof(sport_be),
                            (char *)msg_name + 2) < 0)
        return 0;
    __u16 sport = __builtin_bswap16(sport_be);

    /* Check if this port is a DNS port */
    struct dns_port_key port_key = { .port = sport };
    if (!bpf_map_lookup_elem(&dns_ports, &port_key))
        return 0;

    /* Read first iov to get DNS header */
    struct iovec *msg_iov;
    if (bpf_probe_read_user(&msg_iov, sizeof(msg_iov), &msg->msg_iov) < 0)
        return 0;

    struct iovec iov0;
    if (bpf_probe_read_user(&iov0, sizeof(iov0), msg_iov) < 0)
        return 0;

    __u8 hdr[12];
    if (bpf_probe_read_user(hdr, sizeof(hdr), iov0.iov_base) < 0)
        return 0;

    /* Parse DNS header */
    __u16 txid = ((__u16)hdr[0] << 8) | hdr[1];
    __u16 flags = ((__u16)hdr[2] << 8) | hdr[3];

    /* QR bit must be 1 (response) */
    if (!(flags & 0x8000))
        return 0;

    /* Lookup inflight request and compute latency */
    struct dns_txid_key txid_key = {
        .cgroup_id = cgroup_id,
        .txid = txid,
    };

    struct ts_value *ts_val = bpf_map_lookup_elem(&dns_inflight, &txid_key);
    if (ts_val) {
        __u64 now = bpf_ktime_get_ns();
        __u64 latency_ns = now - ts_val->ts;

        /* Update latency histogram */
        struct hist_key h_key = { .cgroup_id = cgroup_id };
        struct hist_value *hist = bpf_map_lookup_elem(&dns_latency, &h_key);
        if (hist) {
            __u32 slot = log2l(latency_ns);
            if (slot >= HIST_SLOTS)
                slot = HIST_SLOTS - 1;
            __sync_fetch_and_add(&hist->slots[slot], 1);
            __sync_fetch_and_add(&hist->count, 1);
            __sync_fetch_and_add(&hist->sum_ns, latency_ns);
        } else {
            struct hist_value new_hist = {};
            __u32 slot = log2l(latency_ns);
            if (slot >= HIST_SLOTS)
                slot = HIST_SLOTS - 1;
            new_hist.slots[slot] = 1;
            new_hist.count = 1;
            new_hist.sum_ns = latency_ns;
            bpf_map_update_elem(&dns_latency, &h_key, &new_hist, BPF_NOEXIST);
        }

        /* Delete inflight entry */
        bpf_map_delete_elem(&dns_inflight, &txid_key);
    }

    /* If rcode != 0, increment error counter */
    __u8 rcode = flags & 0x000F;
    if (rcode != 0) {
        struct dns_err_key err_key = {
            .cgroup_id = cgroup_id,
            .rcode = rcode,
        };
        inc_counter(&dns_errors, &err_key);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
