// bpf/http.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_PAYLOAD   128
#define MAX_PATH_LEN  64
#define HIST_SLOTS    27

static __always_inline __u32 log2l(__u64 v)
{
    __u32 r = 0;
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if (v <= 1) break;
        v >>= 1;
        r++;
    }
    return r;
}

/* ── HTTP method enum ────────────────────────────────────── */

#define METHOD_UNKNOWN 0
#define METHOD_GET     1
#define METHOD_POST    2
#define METHOD_PUT     3
#define METHOD_DELETE  4
#define METHOD_PATCH   5
#define METHOD_HEAD    6

/* ── Direction defines ───────────────────────────────────── */

#define DIR_REQUEST_OUT 0   /* client sending request */
#define DIR_REQUEST_IN  1   /* server receiving request */

/* ── Map key/value structs ───────────────────────────────── */

struct http_port_key {
    __u16 port;
    __u16 _pad1;
    __u32 _pad2;
};

struct http_port_val {
    __u8 enabled;
    __u8 _pad[7];
};

struct http_event_key {
    __u64 cgroup_id;
    __u8  method;
    __u8  direction;
    __u16 status_code;
    __u32 _pad;
};

struct http_event_val {
    __u64 count;
};

struct http_latency_key {
    __u64 cgroup_id;
    __u8  method;
    __u8  direction;
    __u16 _pad1;
    __u32 _pad2;
};

struct hist_value {
    __u64 slots[HIST_SLOTS];
    __u64 count;
    __u64 sum_ns;
};

struct http_path_key {
    __u64 cgroup_id;
    __u8  path[MAX_PATH_LEN];
};

struct counter_value {
    __u64 count;
};

struct http_inflight_key {
    __u64 cgroup_id;
    __u64 sock_cookie;
};

struct http_inflight_val {
    __u64 ts;
    __u8  method;
    __u8  direction;
    __u16 _pad1;
    __u32 _pad2;
};

struct recv_stash {
    __u64 sock_ptr;
    __u64 msghdr_ptr;
    __u64 cgroup_id;
    __u64 sock_cookie;
};

/* ── Maps ────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, struct http_port_key);
    __type(value, struct http_port_val);
} http_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct http_event_key);
    __type(value, struct http_event_val);
} http_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct http_latency_key);
    __type(value, struct hist_value);
} http_latency SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct http_path_key);
    __type(value, struct counter_value);
} http_top_paths SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct http_inflight_key);
    __type(value, struct http_inflight_val);
} http_inflight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct recv_stash);
} http_recv_stash SEC(".maps");

/* ── Helpers ─────────────────────────────────────────────── */

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

static __always_inline void update_hist(void *map, void *key, __u64 val_ns)
{
    struct hist_value *hist = bpf_map_lookup_elem(map, key);
    if (hist) {
        __u32 slot = log2l(val_ns);
        if (slot >= HIST_SLOTS)
            slot = HIST_SLOTS - 1;
        __sync_fetch_and_add(&hist->slots[slot], 1);
        __sync_fetch_and_add(&hist->count, 1);
        __sync_fetch_and_add(&hist->sum_ns, val_ns);
    } else {
        struct hist_value new_hist = {};
        __u32 slot = log2l(val_ns);
        if (slot >= HIST_SLOTS)
            slot = HIST_SLOTS - 1;
        new_hist.slots[slot] = 1;
        new_hist.count = 1;
        new_hist.sum_ns = val_ns;
        bpf_map_update_elem(map, key, &new_hist, BPF_NOEXIST);
    }
}

static __always_inline __u8 detect_method(const __u8 *buf, __u32 len)
{
    if (len >= 4 && buf[0] == 'G' && buf[1] == 'E' &&
        buf[2] == 'T' && buf[3] == ' ')
        return METHOD_GET;
    if (len >= 5 && buf[0] == 'P' && buf[1] == 'O' &&
        buf[2] == 'S' && buf[3] == 'T' && buf[4] == ' ')
        return METHOD_POST;
    if (len >= 4 && buf[0] == 'P' && buf[1] == 'U' &&
        buf[2] == 'T' && buf[3] == ' ')
        return METHOD_PUT;
    if (len >= 7 && buf[0] == 'D' && buf[1] == 'E' &&
        buf[2] == 'L' && buf[3] == 'E' && buf[4] == 'T' &&
        buf[5] == 'E' && buf[6] == ' ')
        return METHOD_DELETE;
    if (len >= 6 && buf[0] == 'P' && buf[1] == 'A' &&
        buf[2] == 'T' && buf[3] == 'C' && buf[4] == 'H' &&
        buf[5] == ' ')
        return METHOD_PATCH;
    if (len >= 5 && buf[0] == 'H' && buf[1] == 'E' &&
        buf[2] == 'A' && buf[3] == 'D' && buf[4] == ' ')
        return METHOD_HEAD;

    return METHOD_UNKNOWN;
}

/* Returns status code (e.g. 200) if buf starts with "HTTP/1.", else 0 */
static __always_inline __u16 detect_response(const __u8 *buf, __u32 len)
{
    if (len < 12)
        return 0;
    if (buf[0] != 'H' || buf[1] != 'T' || buf[2] != 'T' ||
        buf[3] != 'P' || buf[4] != '/' || buf[5] != '1' ||
        buf[6] != '.')
        return 0;

    /* "HTTP/1.X SSS" — status code at offset 9..11 */
    if (buf[8] != ' ')
        return 0;

    __u16 code = 0;
    if (buf[9] >= '0' && buf[9] <= '9')
        code += (buf[9] - '0') * 100;
    else
        return 0;
    if (buf[10] >= '0' && buf[10] <= '9')
        code += (buf[10] - '0') * 10;
    else
        return 0;
    if (buf[11] >= '0' && buf[11] <= '9')
        code += (buf[11] - '0');
    else
        return 0;

    return code;
}

/* Extracts the path from a request line: "METHOD /path HTTP/1.x" */
static __always_inline void extract_path(__u8 *dst, const __u8 *buf,
                                         __u32 len, __u8 method)
{
    __u32 start = 0;
    switch (method) {
    case METHOD_GET:    start = 4; break;
    case METHOD_POST:   start = 5; break;
    case METHOD_PUT:    start = 4; break;
    case METHOD_DELETE: start = 7; break;
    case METHOD_PATCH:  start = 6; break;
    case METHOD_HEAD:   start = 5; break;
    default:            return;
    }

    __u32 path_len = 0;
    #pragma unroll
    for (int i = 0; i < MAX_PATH_LEN; i++) {
        __u32 off = start + i;
        if (off >= len)
            break;
        if (buf[off] == ' ' || buf[off] == '?' || buf[off] == '\r')
            break;
        dst[i] = buf[off];
        path_len++;
    }
}

static __always_inline void read_sock_addr(struct sock *sk,
                                           __u16 *dport, __u16 *sport)
{
    __u16 dport_be;
    bpf_probe_read(&dport_be, sizeof(dport_be),
                          &sk->__sk_common.skc_dport);
    *dport = __builtin_bswap16(dport_be);

    __u16 sport_be;
    bpf_probe_read(&sport_be, sizeof(sport_be),
                          &sk->__sk_common.skc_num);
    *sport = sport_be;   /* skc_num is host order */
}

static __always_inline int is_http_port(__u16 port)
{
    struct http_port_key pk = { .port = port };
    return bpf_map_lookup_elem(&http_ports, &pk) != 0;
}

/* ── kprobe/tcp_sendmsg ──────────────────────────────────── */

SEC("kprobe/tcp_sendmsg")
int http_send(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

    __u16 dport, sport;
    read_sock_addr(sk, &dport, &sport);

    /* At least one side must be an HTTP port */
    int dport_http = is_http_port(dport);
    int sport_http = is_http_port(sport);
    if (!dport_http && !sport_http)
        return 0;

    /* Read first iov */
    struct iovec *msg_iov;
    if (bpf_probe_read(&msg_iov, sizeof(msg_iov), &msg->msg_iter.__iov) < 0)
        return 0;

    struct iovec iov0;
    if (bpf_probe_read(&iov0, sizeof(iov0), msg_iov) < 0)
        return 0;

    if (iov0.iov_len < 8)
        return 0;

    __u8 buf[MAX_PAYLOAD];
    __builtin_memset(buf, 0, sizeof(buf));
    __u32 to_read = iov0.iov_len;
    if (to_read > MAX_PAYLOAD)
        to_read = MAX_PAYLOAD;
    if (bpf_probe_read(buf, to_read, iov0.iov_base) < 0)
        return 0;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u64 sock_cookie = bpf_get_socket_cookie(ctx);

    struct http_inflight_key inf_key = {
        .cgroup_id = cgroup_id,
        .sock_cookie = sock_cookie,
    };

    /* Try to detect HTTP request */
    __u8 method = detect_method(buf, to_read);
    if (method != METHOD_UNKNOWN) {
        /* Sending a request = client outbound (DIR_REQUEST_OUT)
           Sending a request on a server port = not typical, but
           we use dport to decide: if dport is HTTP, we're the client. */
        __u8 direction = dport_http ? DIR_REQUEST_OUT : DIR_REQUEST_IN;

        /* Record event */
        struct http_event_key ev_key = {
            .cgroup_id = cgroup_id,
            .method = method,
            .direction = direction,
            .status_code = 0,
        };
        struct http_event_val *ev = bpf_map_lookup_elem(&http_events, &ev_key);
        if (ev) {
            __sync_fetch_and_add(&ev->count, 1);
        } else {
            struct http_event_val one = { .count = 1 };
            bpf_map_update_elem(&http_events, &ev_key, &one, BPF_NOEXIST);
        }

        /* Extract and record path */
        struct http_path_key path_key = { .cgroup_id = cgroup_id };
        __builtin_memset(path_key.path, 0, MAX_PATH_LEN);
        extract_path(path_key.path, buf, to_read, method);
        inc_counter(&http_top_paths, &path_key);

        /* Create inflight entry for latency tracking */
        struct http_inflight_val inf_val = {
            .ts = bpf_ktime_get_ns(),
            .method = method,
            .direction = direction,
        };
        bpf_map_update_elem(&http_inflight, &inf_key, &inf_val, BPF_NOEXIST);

        return 0;
    }

    /* Try to detect HTTP response */
    __u16 status = detect_response(buf, to_read);
    if (status == 0)
        return 0;

    /* Sending a response = server completing a request */
    struct http_inflight_val *inf = bpf_map_lookup_elem(&http_inflight, &inf_key);
    if (!inf)
        return 0;

    __u64 latency_ns = bpf_ktime_get_ns() - inf->ts;
    __u8 req_method = inf->method;
    __u8 req_dir = inf->direction;

    /* Record event with status code */
    struct http_event_key ev_key = {
        .cgroup_id = cgroup_id,
        .method = req_method,
        .direction = req_dir,
        .status_code = status,
    };
    struct http_event_val *ev = bpf_map_lookup_elem(&http_events, &ev_key);
    if (ev) {
        __sync_fetch_and_add(&ev->count, 1);
    } else {
        struct http_event_val one = { .count = 1 };
        bpf_map_update_elem(&http_events, &ev_key, &one, BPF_NOEXIST);
    }

    /* Update latency histogram */
    struct http_latency_key lat_key = {
        .cgroup_id = cgroup_id,
        .method = req_method,
        .direction = req_dir,
    };
    update_hist(&http_latency, &lat_key, latency_ns);

    /* Delete inflight entry */
    bpf_map_delete_elem(&http_inflight, &inf_key);

    return 0;
}

/* ── kprobe/tcp_recvmsg ──────────────────────────────────── */

SEC("kprobe/tcp_recvmsg")
int http_recv_enter(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    __u16 dport, sport;
    read_sock_addr(sk, &dport, &sport);

    /* At least one side must be an HTTP port */
    if (!is_http_port(dport) && !is_http_port(sport))
        return 0;

    __u32 zero = 0;
    struct recv_stash *stash = bpf_map_lookup_elem(&http_recv_stash, &zero);
    if (!stash)
        return 0;

    stash->sock_ptr = (__u64)sk;
    stash->msghdr_ptr = (__u64)PT_REGS_PARM2(ctx);
    stash->cgroup_id = bpf_get_current_cgroup_id();
    stash->sock_cookie = bpf_get_socket_cookie(ctx);

    return 0;
}

/* ── kretprobe/tcp_recvmsg ───────────────────────────────── */

SEC("kretprobe/tcp_recvmsg")
int http_recv_exit(struct pt_regs *ctx)
{
    long ret = (long)PT_REGS_RC(ctx);
    if (ret < 8)
        return 0;

    __u32 zero = 0;
    struct recv_stash *stash = bpf_map_lookup_elem(&http_recv_stash, &zero);
    if (!stash)
        return 0;

    struct msghdr *msg = (struct msghdr *)stash->msghdr_ptr;
    __u64 cgroup_id = stash->cgroup_id;
    __u64 sock_cookie = stash->sock_cookie;
    struct sock *sk = (struct sock *)stash->sock_ptr;

    if (!msg || !sk)
        return 0;

    /* Determine ports for direction */
    __u16 dport, sport;
    read_sock_addr(sk, &dport, &sport);

    int dport_http = is_http_port(dport);
    int sport_http = is_http_port(sport);

    /* Read first iov from msghdr */
    struct iovec *msg_iov;
    if (bpf_probe_read(&msg_iov, sizeof(msg_iov), &msg->msg_iter.__iov) < 0)
        return 0;

    struct iovec iov0;
    if (bpf_probe_read(&iov0, sizeof(iov0), msg_iov) < 0)
        return 0;

    __u8 buf[MAX_PAYLOAD];
    __builtin_memset(buf, 0, sizeof(buf));
    __u32 to_read = (__u32)ret;
    if (to_read > MAX_PAYLOAD)
        to_read = MAX_PAYLOAD;
    if (bpf_probe_read_user(buf, to_read, iov0.iov_base) < 0)
        return 0;

    struct http_inflight_key inf_key = {
        .cgroup_id = cgroup_id,
        .sock_cookie = sock_cookie,
    };

    /* Try to detect HTTP request (server receiving = DIR_REQUEST_IN) */
    __u8 method = detect_method(buf, to_read);
    if (method != METHOD_UNKNOWN) {
        __u8 direction = sport_http ? DIR_REQUEST_IN : DIR_REQUEST_OUT;

        /* Record event */
        struct http_event_key ev_key = {
            .cgroup_id = cgroup_id,
            .method = method,
            .direction = direction,
            .status_code = 0,
        };
        struct http_event_val *ev = bpf_map_lookup_elem(&http_events, &ev_key);
        if (ev) {
            __sync_fetch_and_add(&ev->count, 1);
        } else {
            struct http_event_val one = { .count = 1 };
            bpf_map_update_elem(&http_events, &ev_key, &one, BPF_NOEXIST);
        }

        /* Extract and record path */
        struct http_path_key path_key = { .cgroup_id = cgroup_id };
        __builtin_memset(path_key.path, 0, MAX_PATH_LEN);
        extract_path(path_key.path, buf, to_read, method);
        inc_counter(&http_top_paths, &path_key);

        /* Create inflight entry for latency tracking */
        struct http_inflight_val inf_val = {
            .ts = bpf_ktime_get_ns(),
            .method = method,
            .direction = direction,
        };
        bpf_map_update_elem(&http_inflight, &inf_key, &inf_val, BPF_NOEXIST);

        return 0;
    }

    /* Try to detect HTTP response (client receiving) */
    __u16 status = detect_response(buf, to_read);
    if (status == 0)
        return 0;

    /* Receiving a response = completing a client request */
    struct http_inflight_val *inf = bpf_map_lookup_elem(&http_inflight, &inf_key);
    if (!inf)
        return 0;

    __u64 latency_ns = bpf_ktime_get_ns() - inf->ts;
    __u8 req_method = inf->method;
    __u8 req_dir = inf->direction;

    /* Record event with status code */
    struct http_event_key ev_key = {
        .cgroup_id = cgroup_id,
        .method = req_method,
        .direction = req_dir,
        .status_code = status,
    };
    struct http_event_val *ev = bpf_map_lookup_elem(&http_events, &ev_key);
    if (ev) {
        __sync_fetch_and_add(&ev->count, 1);
    } else {
        struct http_event_val one = { .count = 1 };
        bpf_map_update_elem(&http_events, &ev_key, &one, BPF_NOEXIST);
    }

    /* Update latency histogram */
    struct http_latency_key lat_key = {
        .cgroup_id = cgroup_id,
        .method = req_method,
        .direction = req_dir,
    };
    update_hist(&http_latency, &lat_key, latency_ns);

    /* Delete inflight entry */
    bpf_map_delete_elem(&http_inflight, &inf_key);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
