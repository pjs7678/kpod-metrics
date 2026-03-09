package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

// ── HTTP-specific structs ────────────────────────────────────────────

object HttpPortKey : BpfStruct("http_port_key") {
    val port by u16()
    val pad1 by u16()
    val pad2 by u32()
}

object HttpPortVal : BpfStruct("http_port_val") {
    val enabled by u8()
    val pad by array(BpfScalar.U8, 7)
}

object HttpEventKey : BpfStruct("http_event_key") {
    val cgroupId by u64()
    val method by u8()
    val direction by u8()
    val statusCode by u16()
    val pad by u32()
}

object HttpEventVal : BpfStruct("http_event_val") {
    val count by u64()
}

object HttpLatKey : BpfStruct("http_latency_key") {
    val cgroupId by u64()
    val method by u8()
    val direction by u8()
    val pad1 by u16()
    val pad2 by u32()
}

object HttpInflightKey : BpfStruct("http_inflight_key") {
    val cgroupId by u64()
    val sockCookie by u64()
}

object HttpInflightVal : BpfStruct("http_inflight_val") {
    val ts by u64()
    val method by u8()
    val direction by u8()
    val pad1 by u16()
    val pad2 by u32()
}

object HttpRecvStash : BpfStruct("http_recv_stash") {
    val sockPtr by u64()
    val msghdrPtr by u64()
    val cgroupId by u64()
    val sockCookie by u64()
}

// ── HTTP preamble ────────────────────────────────────────────────────

private val HTTP_PREAMBLE = """
#define MAX_PAYLOAD 128

$COMMON_PREAMBLE

DEFINE_STATS_MAP(http_ports)
DEFINE_STATS_MAP(http_events)
DEFINE_STATS_MAP(http_latency)
DEFINE_STATS_MAP(http_inflight)
DEFINE_STATS_MAP(http_recv_stash)

#define METHOD_UNKNOWN 0
#define METHOD_GET     1
#define METHOD_POST    2
#define METHOD_PUT     3
#define METHOD_DELETE  4
#define METHOD_PATCH   5
#define METHOD_HEAD    6

#define DIR_REQUEST_OUT 0
#define DIR_REQUEST_IN  1

static __always_inline __u8 detect_method(const __u8 *buf, __u32 len)
{
    if (len >= 4 && buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T' && buf[3] == ' ')
        return METHOD_GET;
    if (len >= 5 && buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T' && buf[4] == ' ')
        return METHOD_POST;
    if (len >= 4 && buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T' && buf[3] == ' ')
        return METHOD_PUT;
    if (len >= 7 && buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'E' && buf[4] == 'T' && buf[5] == 'E' && buf[6] == ' ')
        return METHOD_DELETE;
    if (len >= 6 && buf[0] == 'P' && buf[1] == 'A' && buf[2] == 'T' && buf[3] == 'C' && buf[4] == 'H' && buf[5] == ' ')
        return METHOD_PATCH;
    if (len >= 5 && buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D' && buf[4] == ' ')
        return METHOD_HEAD;
    return METHOD_UNKNOWN;
}

static __always_inline __u16 detect_response(const __u8 *buf, __u32 len)
{
    if (len < 12) return 0;
    if (buf[0] != 'H' || buf[1] != 'T' || buf[2] != 'T' || buf[3] != 'P' ||
        buf[4] != '/' || buf[5] != '1' || buf[6] != '.') return 0;
    if (buf[8] != ' ') return 0;
    __u16 code = 0;
    if (buf[9] >= '0' && buf[9] <= '9') code += (buf[9] - '0') * 100; else return 0;
    if (buf[10] >= '0' && buf[10] <= '9') code += (buf[10] - '0') * 10; else return 0;
    if (buf[11] >= '0' && buf[11] <= '9') code += (buf[11] - '0'); else return 0;
    return code;
}

static __always_inline int read_first_iov(struct msghdr *msg, struct iovec *out)
{
    __u8 iter_type;
    if (bpf_probe_read(&iter_type, sizeof(iter_type), &msg->msg_iter.iter_type) < 0)
        return -1;
    if (iter_type == 0 /* ITER_UBUF */) {
        if (bpf_probe_read(out, sizeof(*out), &msg->msg_iter.__ubuf_iovec) < 0)
            return -1;
        return 0;
    }
    struct iovec *msg_iov;
    if (bpf_probe_read(&msg_iov, sizeof(msg_iov), &msg->msg_iter.__iov) < 0)
        return -1;
    if (!msg_iov) return -1;
    if (bpf_probe_read(out, sizeof(*out), msg_iov) < 0)
        return -1;
    return 0;
}

static __always_inline void read_sock_addr(struct sock *sk, __u16 *dport, __u16 *sport)
{
    __u16 dport_be;
    bpf_probe_read(&dport_be, sizeof(dport_be), &sk->__sk_common.skc_dport);
    *dport = __builtin_bswap16(dport_be);
    __u16 sport_be;
    bpf_probe_read(&sport_be, sizeof(sport_be), &sk->__sk_common.skc_num);
    *sport = sport_be;
}

""".trimIndent()

private val HTTP_POSTAMBLE = """
static __always_inline void update_hist(void *map, void *key, __u64 val_ns)
{
    struct hist_value *hist = bpf_map_lookup_elem(map, key);
    if (!hist) {
        struct hist_value new_hist = {};
        bpf_map_update_elem(map, key, &new_hist, BPF_NOEXIST);
        hist = bpf_map_lookup_elem(map, key);
        if (!hist) return;
    }
    __u32 slot = log2l(val_ns);
    if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
    __sync_fetch_and_add(&hist->slots[slot], 1);
    __sync_fetch_and_add(&hist->count, 1);
    __sync_fetch_and_add(&hist->sum_ns, val_ns);
}

static __always_inline int check_http_port(struct sock *sk)
{
    __u16 dport, sport;
    read_sock_addr(sk, &dport, &sport);
    struct http_port_key pk = { .port = dport };
    if (bpf_map_lookup_elem(&http_ports, &pk)) return 1;
    pk.port = sport;
    __builtin_memset(&pk.pad1, 0, sizeof(pk.pad1) + sizeof(pk.pad2));
    if (bpf_map_lookup_elem(&http_ports, &pk)) return 1;
    return 0;
}

static __always_inline void inc_http_event(void *map, void *key)
{
    struct http_event_val *ev = bpf_map_lookup_elem(map, key);
    if (ev) {
        __sync_fetch_and_add(&ev->count, 1);
    } else {
        struct http_event_val one = { .count = 1 };
        bpf_map_update_elem(map, key, &one, BPF_NOEXIST);
    }
}
""".trimIndent()

// ── HTTP program ─────────────────────────────────────────────────────

@Suppress("DEPRECATION")
val httpProgram = ebpf("http") {
    license("GPL")
    targetKernel("5.5")

    preamble(HTTP_PREAMBLE)
    postamble(HTTP_POSTAMBLE)

    // ── Maps ─────────────────────────────────────────────────────────
    val httpPorts by hashMap(HttpPortKey, HttpPortVal, maxEntries = 8)
    val httpEvents by lruHashMap(HttpEventKey, HttpEventVal, maxEntries = 10240)
    val httpLatency by lruHashMap(HttpLatKey, HistValue, maxEntries = 10240)
    val httpInflight by lruHashMap(HttpInflightKey, HttpInflightVal, maxEntries = 8192)
    val httpRecvStash by percpuArray(HttpRecvStash, maxEntries = 1)

    // ── kprobe/tcp_sendmsg ───────────────────────────────────────────
    kprobe("tcp_sendmsg") {
        // The send path: detect HTTP request or response, update maps
        // Uses preamble helpers for method/response detection + iov reading
        declareVar("_http_send", raw("""({
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

    if (!check_http_port(sk)) return 0;

    struct iovec iov0;
    if (read_first_iov(msg, &iov0) < 0) return 0;
    if (iov0.iov_len < 8) return 0;

    __u8 buf[MAX_PAYLOAD];
    __builtin_memset(buf, 0, sizeof(buf));
    __u32 to_read = iov0.iov_len;
    if (to_read > MAX_PAYLOAD) to_read = MAX_PAYLOAD;
    if (bpf_probe_read_user(buf, to_read, iov0.iov_base) < 0) return 0;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u64 sock_cookie = (__u64)sk;

    struct http_inflight_key inf_key = {
        .cgroup_id = cgroup_id,
        .sock_cookie = sock_cookie,
    };

    __u8 method = detect_method(buf, to_read);
    if (method != METHOD_UNKNOWN) {
        __u8 direction = DIR_REQUEST_OUT;
        struct http_event_key ev_key = {
            .cgroup_id = cgroup_id,
            .method = method,
            .direction = direction,
            .status_code = 0,
        };
        inc_http_event(&http_events, &ev_key);
        struct http_inflight_val inf_val = {
            .ts = bpf_ktime_get_ns(),
            .method = method,
            .direction = direction,
        };
        bpf_map_update_elem(&http_inflight, &inf_key, &inf_val, BPF_NOEXIST);
        return 0;
    }

    __u16 status = detect_response(buf, to_read);
    if (status == 0) return 0;

    struct http_inflight_val *inf = bpf_map_lookup_elem(&http_inflight, &inf_key);
    if (!inf) return 0;

    __u64 latency_ns = bpf_ktime_get_ns() - inf->ts;
    __u8 req_method = inf->method;
    __u8 req_dir = inf->direction;

    struct http_event_key ev_key = {
        .cgroup_id = cgroup_id,
        .method = req_method,
        .direction = req_dir,
        .status_code = status,
    };
    inc_http_event(&http_events, &ev_key);

    struct http_latency_key lat_key = {
        .cgroup_id = cgroup_id,
        .method = req_method,
        .direction = req_dir,
    };
    update_hist(&http_latency, &lat_key, latency_ns);
    bpf_map_delete_elem(&http_inflight, &inf_key);
    (__s32)0;
})""", BpfScalar.S32))
        returnValue(literal(0, BpfScalar.S32))
    }

    // ── kprobe/tcp_recvmsg ───────────────────────────────────────────
    kprobe("tcp_recvmsg") {
        declareVar("_http_recv", raw("""({
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!check_http_port(sk)) return 0;

    __u32 zero = 0;
    struct http_recv_stash *stash = bpf_map_lookup_elem(&http_recv_stash, &zero);
    if (!stash) return 0;

    stash->sock_ptr = (__u64)sk;
    stash->msghdr_ptr = (__u64)PT_REGS_PARM2(ctx);
    stash->cgroup_id = bpf_get_current_cgroup_id();
    stash->sock_cookie = (__u64)sk;
    (__s32)0;
})""", BpfScalar.S32))
        returnValue(literal(0, BpfScalar.S32))
    }

    // ── kretprobe/tcp_recvmsg ────────────────────────────────────────
    kretprobe("tcp_recvmsg") {
        declareVar("_http_recv_exit", raw("""({
    long ret = (long)PT_REGS_RC(ctx);
    if (ret < 8) return 0;

    __u32 zero = 0;
    struct http_recv_stash *stash = bpf_map_lookup_elem(&http_recv_stash, &zero);
    if (!stash) return 0;

    struct msghdr *msg = (struct msghdr *)stash->msghdr_ptr;
    __u64 cgroup_id = stash->cgroup_id;
    __u64 sock_cookie = stash->sock_cookie;
    struct sock *sk = (struct sock *)stash->sock_ptr;
    if (!msg || !sk) return 0;

    __u16 dport, sport;
    read_sock_addr(sk, &dport, &sport);
    struct http_port_key pk = { .port = sport };
    int sport_http = 0;
    if (bpf_map_lookup_elem(&http_ports, &pk)) sport_http = 1;

    struct iovec iov0;
    if (read_first_iov(msg, &iov0) < 0) return 0;

    __u8 buf[MAX_PAYLOAD];
    __builtin_memset(buf, 0, sizeof(buf));
    __u32 to_read = (__u32)ret;
    if (to_read > MAX_PAYLOAD) to_read = MAX_PAYLOAD;
    if (bpf_probe_read_user(buf, to_read, iov0.iov_base) < 0) return 0;

    struct http_inflight_key inf_key = {
        .cgroup_id = cgroup_id,
        .sock_cookie = sock_cookie,
    };

    __u8 method = detect_method(buf, to_read);
    if (method != METHOD_UNKNOWN) {
        __u8 direction = DIR_REQUEST_OUT;
        if (sport_http) direction = DIR_REQUEST_IN;
        struct http_event_key ev_key = {
            .cgroup_id = cgroup_id,
            .method = method,
            .direction = direction,
            .status_code = 0,
        };
        inc_http_event(&http_events, &ev_key);
        struct http_inflight_val inf_val = {
            .ts = bpf_ktime_get_ns(),
            .method = method,
            .direction = direction,
        };
        bpf_map_update_elem(&http_inflight, &inf_key, &inf_val, BPF_NOEXIST);
        return 0;
    }

    __u16 status = detect_response(buf, to_read);
    if (status == 0) return 0;

    struct http_inflight_val *inf = bpf_map_lookup_elem(&http_inflight, &inf_key);
    if (!inf) return 0;

    __u64 latency_ns = bpf_ktime_get_ns() - inf->ts;
    __u8 req_method = inf->method;
    __u8 req_dir = inf->direction;

    struct http_event_key ev_key = {
        .cgroup_id = cgroup_id,
        .method = req_method,
        .direction = req_dir,
        .status_code = status,
    };
    inc_http_event(&http_events, &ev_key);

    struct http_latency_key lat_key = {
        .cgroup_id = cgroup_id,
        .method = req_method,
        .direction = req_dir,
    };
    update_hist(&http_latency, &lat_key, latency_ns);
    bpf_map_delete_elem(&http_inflight, &inf_key);
    (__s32)0;
})""", BpfScalar.S32))
        returnValue(literal(0, BpfScalar.S32))
    }
}
