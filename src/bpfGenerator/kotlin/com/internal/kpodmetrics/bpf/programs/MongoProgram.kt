package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

// ── MongoDB-specific structs ────────────────────────────────────────

object MongoPortKey : BpfStruct("mongo_port_key") {
    val port by u16()
    val pad1 by u16()
    val pad2 by u32()
}

object MongoPortVal : BpfStruct("mongo_port_val") {
    val enabled by u8()
    val pad by array(BpfScalar.U8, 7)
}

object MongoEventKey : BpfStruct("mongo_event_key") {
    val cgroupId by u64()
    val command by u8()   // CMD_FIND=1, CMD_INSERT=2, etc.
    val pad1 by u8()
    val pad2 by u16()
    val pad3 by u32()
}

object MongoLatKey : BpfStruct("mongo_latency_key") {
    val cgroupId by u64()
    val command by u8()
    val pad1 by u8()
    val pad2 by u16()
    val pad3 by u32()
}

object MongoInflightKey : BpfStruct("mongo_inflight_key") {
    val cgroupId by u64()
    val sockCookie by u64()
}

object MongoInflightVal : BpfStruct("mongo_inflight_val") {
    val ts by u64()
    val requestId by u32()
    val command by u8()
    val pad1 by u8()
    val pad2 by u16()
}

object MongoErrKey : BpfStruct("mongo_err_key") {
    val cgroupId by u64()
    val errType by u8()   // 1 = command failure (ok:0)
    val pad by array(BpfScalar.U8, 7)
}

object MongoRecvStash : BpfStruct("mongo_rcv_stash") {
    val sockPtr by u64()
    val msghdrPtr by u64()
    val cgroupId by u64()
    val sockCookie by u64()
}

// ── MongoDB preamble ────────────────────────────────────────────────

private val MONGO_PREAMBLE = """
#define MAX_PAYLOAD 64

$COMMON_PREAMBLE

DEFINE_STATS_MAP(mongo_ports)
DEFINE_STATS_MAP(mongo_events)
DEFINE_STATS_MAP(mongo_latency)
DEFINE_STATS_MAP(mongo_inflight)
DEFINE_STATS_MAP(mongo_errors)
DEFINE_STATS_MAP(mongo_rcv_stash)

/* MongoDB commands */
#define MCMD_UNKNOWN   0
#define MCMD_FIND      1
#define MCMD_INSERT    2
#define MCMD_UPDATE    3
#define MCMD_DELETE     4
#define MCMD_AGGREGATE 5
#define MCMD_GETMORE   6
#define MCMD_COUNT     7
#define MCMD_DISTINCT  8
#define MCMD_OTHER     9

/* MongoDB OP_MSG opcode */
#define OP_MSG 2013

/* Error type */
#define MERR_CMD_FAILURE 1

#define PROTO_HTTP  1
#define PROTO_REDIS 2
#define PROTO_MYSQL 3
#define PROTO_KAFKA 4
#define PROTO_MONGO 5

/*
 * MongoDB wire protocol (OP_MSG):
 *   MsgHeader (16 bytes):
 *     [0..3]   messageLength  (int32 little-endian, includes itself)
 *     [4..7]   requestId      (int32 little-endian)
 *     [8..11]  responseTo     (int32 little-endian)
 *     [12..15] opCode         (int32 little-endian)
 *
 *   OP_MSG body:
 *     [16..19] flagBits       (uint32 little-endian)
 *     [20]     section kind   (0 = body)
 *     [21..24] BSON doc size  (int32 little-endian)
 *     [25..]   BSON document  (first element: type(1) + key + value)
 *
 * Request detection:  opCode == OP_MSG && responseTo == 0
 * Response detection: opCode == OP_MSG && responseTo != 0
 *
 * Command extraction: first BSON key starts at offset 25.
 *   BSON element: type(1 byte) + cstring key + value
 *   For command name: type == 0x02 (string), key is the command name.
 *
 * Error detection in response: look for "ok" field with double value 0.0
 */

/*
 * Extract command name from first BSON key at offset 25.
 * BSON element format: type(1B) + key_cstring + value
 * The first key in a command document is the command name itself.
 */
static __always_inline __u8 classify_mongo_cmd(const __u8 *buf, __u32 len)
{
    /* First BSON key starts at offset 25 (16 hdr + 4 flags + 1 kind + 4 bson_size) */
    if (len < 30) return MCMD_UNKNOWN;

    /* Skip type byte at offset 25, key starts at 26 */
    __u32 off = 26;
    if (off + 4 > len) return MCMD_UNKNOWN;

    __u8 c0 = buf[off];
    __u8 c1 = (off + 1 < len) ? buf[off + 1] : 0;
    __u8 c2 = (off + 2 < len) ? buf[off + 2] : 0;
    __u8 c3 = (off + 3 < len) ? buf[off + 3] : 0;
    __u8 c4 = (off + 4 < len) ? buf[off + 4] : 0;
    __u8 c5 = (off + 5 < len) ? buf[off + 5] : 0;
    __u8 c6 = (off + 6 < len) ? buf[off + 6] : 0;
    __u8 c7 = (off + 7 < len) ? buf[off + 7] : 0;
    __u8 c8 = (off + 8 < len) ? buf[off + 8] : 0;

    /* "find\0" */
    if (c0 == 'f' && c1 == 'i' && c2 == 'n' && c3 == 'd' && c4 == 0)
        return MCMD_FIND;
    /* "insert\0" */
    if (c0 == 'i' && c1 == 'n' && c2 == 's' && c3 == 'e' && c4 == 'r' && c5 == 't' && c6 == 0)
        return MCMD_INSERT;
    /* "update\0" */
    if (c0 == 'u' && c1 == 'p' && c2 == 'd' && c3 == 'a' && c4 == 't' && c5 == 'e' && c6 == 0)
        return MCMD_UPDATE;
    /* "delete\0" */
    if (c0 == 'd' && c1 == 'e' && c2 == 'l' && c3 == 'e' && c4 == 't' && c5 == 'e' && c6 == 0)
        return MCMD_DELETE;
    /* "aggregate\0" */
    if (c0 == 'a' && c1 == 'g' && c2 == 'g' && c3 == 'r' && c4 == 'e' && c5 == 'g' && c6 == 'a' && c7 == 't' && c8 == 'e')
        return MCMD_AGGREGATE;
    /* "getMore\0" */
    if (c0 == 'g' && c1 == 'e' && c2 == 't' && c3 == 'M' && c4 == 'o' && c5 == 'r' && c6 == 'e' && c7 == 0)
        return MCMD_GETMORE;
    /* "count\0" */
    if (c0 == 'c' && c1 == 'o' && c2 == 'u' && c3 == 'n' && c4 == 't' && c5 == 0)
        return MCMD_COUNT;
    /* "distinct\0" */
    if (c0 == 'd' && c1 == 'i' && c2 == 's' && c3 == 't' && c4 == 'i' && c5 == 'n' && c6 == 'c' && c7 == 't' && c8 == 0)
        return MCMD_DISTINCT;

    return MCMD_OTHER;
}

/*
 * Check if buffer is a MongoDB OP_MSG request.
 * Request: opCode == OP_MSG (2013) and responseTo == 0.
 */
static __always_inline int is_mongo_request(const __u8 *buf, __u32 len, __u32 *out_request_id)
{
    if (len < 21) return 0;

    /* messageLength (LE int32) — sanity check */
    __u32 msg_len = (__u32)buf[0] | ((__u32)buf[1] << 8) |
                    ((__u32)buf[2] << 16) | ((__u32)buf[3] << 24);
    if (msg_len < 21 || msg_len > 48 * 1024 * 1024) return 0; /* < min or > 48MB */

    /* requestId (LE int32) */
    __u32 request_id = (__u32)buf[4] | ((__u32)buf[5] << 8) |
                       ((__u32)buf[6] << 16) | ((__u32)buf[7] << 24);

    /* responseTo (LE int32) — must be 0 for request */
    __u32 response_to = (__u32)buf[8] | ((__u32)buf[9] << 8) |
                        ((__u32)buf[10] << 16) | ((__u32)buf[11] << 24);
    if (response_to != 0) return 0;

    /* opCode (LE int32) — must be OP_MSG (2013) */
    __u32 opcode = (__u32)buf[12] | ((__u32)buf[13] << 8) |
                   ((__u32)buf[14] << 16) | ((__u32)buf[15] << 24);
    if (opcode != OP_MSG) return 0;

    *out_request_id = request_id;
    return 1;
}

/*
 * Check if buffer is a MongoDB OP_MSG response.
 * Response: opCode == OP_MSG (2013) and responseTo != 0.
 */
static __always_inline int is_mongo_response(const __u8 *buf, __u32 len, __u32 *out_response_to)
{
    if (len < 21) return 0;

    __u32 msg_len = (__u32)buf[0] | ((__u32)buf[1] << 8) |
                    ((__u32)buf[2] << 16) | ((__u32)buf[3] << 24);
    if (msg_len < 21 || msg_len > 48 * 1024 * 1024) return 0;

    __u32 response_to = (__u32)buf[8] | ((__u32)buf[9] << 8) |
                        ((__u32)buf[10] << 16) | ((__u32)buf[11] << 24);
    if (response_to == 0) return 0;

    __u32 opcode = (__u32)buf[12] | ((__u32)buf[13] << 8) |
                   ((__u32)buf[14] << 16) | ((__u32)buf[15] << 24);
    if (opcode != OP_MSG) return 0;

    *out_response_to = response_to;
    return 1;
}

/*
 * Detect command failure in MongoDB response.
 * Looks for "ok" field with BSON double type (0x01) and value 0.0.
 * Scans from offset 25 (start of BSON body) up to MAX_PAYLOAD.
 * Returns MERR_CMD_FAILURE if ok:0.0 found, else 0.
 */
static __always_inline __u8 detect_mongo_error(const __u8 *buf, __u32 len)
{
    /* Scan for "ok\0" field in BSON body starting after header+flags+kind+bsonsize */
    if (len < 35) return 0;

    /* Simple scan: look for type=0x01 followed by "ok\0" then 8 bytes of double 0.0 */
    #pragma unroll
    for (int i = 25; i < 55; i++) {
        if (i + 12 > len) break;
        if (i + 12 > MAX_PAYLOAD) break;
        if (buf[i] == 0x01 && buf[i+1] == 'o' && buf[i+2] == 'k' && buf[i+3] == 0) {
            /* Next 8 bytes are the double value (LE). 0.0 is all zeros. */
            __u64 val = 0;
            __builtin_memcpy(&val, &buf[i+4], 8);
            if (val == 0) return MERR_CMD_FAILURE;
        }
    }
    return 0;
}

static __always_inline int read_first_iov(struct msghdr *msg, struct iovec *out)
{
#ifdef LEGACY_IOVEC
    struct iovec *msg_iov;
    if (bpf_probe_read(&msg_iov, sizeof(msg_iov), &msg->msg_iter.__iov) < 0)
        return -1;
    if (!msg_iov) return -1;
    if (bpf_probe_read(out, sizeof(*out), msg_iov) < 0)
        return -1;
    return 0;
#else
    __u8 iter_type;
    if (bpf_probe_read(&iter_type, sizeof(iter_type), &msg->msg_iter.iter_type) < 0)
        return -1;
    if (iter_type == 0) {
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
#endif
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

private val MONGO_POSTAMBLE = """
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

static __always_inline int check_mongo_port(struct sock *sk)
{
    __u16 dport, sport;
    read_sock_addr(sk, &dport, &sport);
    struct mongo_port_key pk = { .port = dport };
    if (bpf_map_lookup_elem(&mongo_ports, &pk)) return 1;
    pk.port = sport;
    __builtin_memset(&pk.pad1, 0, sizeof(pk.pad1) + sizeof(pk.pad2));
    if (bpf_map_lookup_elem(&mongo_ports, &pk)) return 1;
    return 0;
}

static __always_inline void inc_mongo_event(void *map, void *key)
{
    struct counter_value *ev = bpf_map_lookup_elem(map, key);
    if (ev) {
        __sync_fetch_and_add(&ev->count, 1);
    } else {
        struct counter_value one = { .count = 1 };
        bpf_map_update_elem(map, key, &one, BPF_NOEXIST);
    }
}

static __always_inline void maybe_emit_span(
    void *rb, void *cfg_map,
    __u64 start_ts, __u64 latency_ns, __u64 cgroup_id,
    __u32 dst_ip, __u16 dst_port, __u16 src_port,
    __u8 protocol, __u8 method, __u16 status_code, __u8 direction,
    const __u8 *buf, __u32 buf_len)
{
    __u32 zero = 0;
    struct tracing_config *cfg = bpf_map_lookup_elem(cfg_map, &zero);
    if (!cfg || !cfg->enabled || latency_ns <= cfg->threshold_ns)
        return;

    struct span_event *evt = bpf_ringbuf_reserve(rb, sizeof(*evt), 0);
    if (!evt)
        return;

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->ts_ns = start_ts;
    evt->latency_ns = latency_ns;
    evt->cgroup_id = cgroup_id;
    evt->dst_ip = dst_ip;
    evt->dst_port = dst_port;
    evt->src_port = src_port;
    evt->protocol = protocol;
    evt->method = method;
    evt->status_code = status_code;
    evt->direction = direction;

    bpf_ringbuf_submit(evt, 0);
}
""".trimIndent()

// ── MongoDB program ─────────────────────────────────────────────────

@Suppress("DEPRECATION")
val mongoProgram = ebpf("mongo") {
    license("GPL")
    targetKernel("5.8")

    preamble(MONGO_PREAMBLE)
    postamble(MONGO_POSTAMBLE)

    // ── Maps ─────────────────────────────────────────────────────────
    val mongoPorts by hashMap(MongoPortKey, MongoPortVal, maxEntries = 8)
    val mongoEvents by lruHashMap(MongoEventKey, CounterValue, maxEntries = 10240)
    val mongoLatency by lruHashMap(MongoLatKey, HistValue, maxEntries = 10240)
    val mongoInflight by lruHashMap(MongoInflightKey, MongoInflightVal, maxEntries = 8192)
    val mongoErrors by lruHashMap(MongoErrKey, CounterValue, maxEntries = 10240)
    val mongoRcvStash by percpuArray(MongoRecvStash, maxEntries = 1)
    val tracingConfig by array(TracingConfig, maxEntries = 1)
    val spanEvents by ringBuf(maxEntries = 262144) // 256KB

    // ── kprobe/tcp_sendmsg ───────────────────────────────────────────
    kprobe("tcp_sendmsg") {
        declareVar("_mongo_send", raw("""({
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

    if (!check_mongo_port(sk)) return 0;

    struct iovec iov0;
    if (read_first_iov(msg, &iov0) < 0) return 0;
    if (iov0.iov_len < 21) return 0;

    __u8 buf[MAX_PAYLOAD];
    __builtin_memset(buf, 0, sizeof(buf));
    __u32 to_read = iov0.iov_len;
    if (to_read > MAX_PAYLOAD) to_read = MAX_PAYLOAD;
    to_read &= (MAX_PAYLOAD - 1);  /* provable bound for older verifiers */
    if (bpf_probe_read_user(buf, to_read, iov0.iov_base) < 0) return 0;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u64 sock_cookie = (__u64)sk;

    struct mongo_inflight_key inf_key = {
        .cgroup_id = cgroup_id,
        .sock_cookie = sock_cookie,
    };

    /* Check if this is a MongoDB request (OP_MSG, responseTo == 0) */
    __u32 request_id = 0;
    if (is_mongo_request(buf, to_read, &request_id)) {
        __u8 command = classify_mongo_cmd(buf, to_read);
        struct mongo_event_key ev_key = {
            .cgroup_id = cgroup_id,
            .command = command,
        };
        inc_mongo_event(&mongo_events, &ev_key);
        struct mongo_inflight_val inf_val = {
            .ts = bpf_ktime_get_ns(),
            .request_id = request_id,
            .command = command,
        };
        bpf_map_update_elem(&mongo_inflight, &inf_key, &inf_val, BPF_NOEXIST);
        return 0;
    }

    /* Check if this is a MongoDB response (OP_MSG, responseTo != 0) */
    __u32 response_to = 0;
    if (is_mongo_response(buf, to_read, &response_to)) {
        struct mongo_inflight_val *inf = bpf_map_lookup_elem(&mongo_inflight, &inf_key);
        if (!inf) return 0;

        __u64 latency_ns = bpf_ktime_get_ns() - inf->ts;
        __u8 req_cmd = inf->command;

        struct mongo_latency_key lat_key = {
            .cgroup_id = cgroup_id,
            .command = req_cmd,
        };
        update_hist(&mongo_latency, &lat_key, latency_ns);

        __u8 err = detect_mongo_error(buf, to_read);
        if (err) {
            struct mongo_err_key ek = { .cgroup_id = cgroup_id, .err_type = err };
            inc_mongo_event(&mongo_errors, &ek);
        }
        {
            __u32 dst_ip = 0;
            bpf_probe_read(&dst_ip, sizeof(dst_ip), &sk->__sk_common.skc_daddr);
            __u16 dport, sport;
            read_sock_addr(sk, &dport, &sport);
            maybe_emit_span(&span_events, &tracing_config,
                inf->ts, latency_ns, cgroup_id,
                dst_ip, dport, sport,
                PROTO_MONGO, req_cmd, err ? 1 : 0, 0,
                NULL, 0);
        }

        bpf_map_delete_elem(&mongo_inflight, &inf_key);
    }
    (__s32)0;
})""", BpfScalar.S32))
        returnValue(literal(0, BpfScalar.S32))
    }

    // ── kprobe/tcp_recvmsg ───────────────────────────────────────────
    kprobe("tcp_recvmsg") {
        declareVar("_mongo_recv", raw("""({
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!check_mongo_port(sk)) return 0;

    __u32 zero = 0;
    struct mongo_rcv_stash *stash = bpf_map_lookup_elem(&mongo_rcv_stash, &zero);
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
        declareVar("_mongo_recv_exit", raw("""({
    long ret = (long)PT_REGS_RC(ctx);
    if (ret < 21) return 0;

    __u32 zero = 0;
    struct mongo_rcv_stash *stash = bpf_map_lookup_elem(&mongo_rcv_stash, &zero);
    if (!stash) return 0;

    struct msghdr *msg = (struct msghdr *)stash->msghdr_ptr;
    __u64 cgroup_id = stash->cgroup_id;
    __u64 sock_cookie = stash->sock_cookie;
    struct sock *sk = (struct sock *)stash->sock_ptr;
    if (!msg || !sk) return 0;

    struct iovec iov0;
    if (read_first_iov(msg, &iov0) < 0) return 0;

    __u8 buf[MAX_PAYLOAD];
    __builtin_memset(buf, 0, sizeof(buf));
    __u32 to_read = (__u32)ret;
    if (to_read > MAX_PAYLOAD) to_read = MAX_PAYLOAD;
    to_read &= (MAX_PAYLOAD - 1);  /* provable bound for older verifiers */
    if (bpf_probe_read_user(buf, to_read, iov0.iov_base) < 0) return 0;

    struct mongo_inflight_key inf_key = {
        .cgroup_id = cgroup_id,
        .sock_cookie = sock_cookie,
    };

    /* Check for inbound MongoDB request */
    __u32 request_id = 0;
    if (is_mongo_request(buf, to_read, &request_id)) {
        __u8 command = classify_mongo_cmd(buf, to_read);
        struct mongo_event_key ev_key = {
            .cgroup_id = cgroup_id,
            .command = command,
        };
        inc_mongo_event(&mongo_events, &ev_key);
        struct mongo_inflight_val inf_val = {
            .ts = bpf_ktime_get_ns(),
            .request_id = request_id,
            .command = command,
        };
        bpf_map_update_elem(&mongo_inflight, &inf_key, &inf_val, BPF_NOEXIST);
        return 0;
    }

    /* Check for inbound MongoDB response */
    __u32 response_to = 0;
    if (is_mongo_response(buf, to_read, &response_to)) {
        struct mongo_inflight_val *inf = bpf_map_lookup_elem(&mongo_inflight, &inf_key);
        if (!inf) return 0;

        __u64 latency_ns = bpf_ktime_get_ns() - inf->ts;
        __u8 req_cmd = inf->command;

        struct mongo_latency_key lat_key = {
            .cgroup_id = cgroup_id,
            .command = req_cmd,
        };
        update_hist(&mongo_latency, &lat_key, latency_ns);

        __u8 err = detect_mongo_error(buf, to_read);
        if (err) {
            struct mongo_err_key ek = { .cgroup_id = cgroup_id, .err_type = err };
            inc_mongo_event(&mongo_errors, &ek);
        }
        {
            __u32 dst_ip = 0;
            bpf_probe_read(&dst_ip, sizeof(dst_ip), &sk->__sk_common.skc_daddr);
            __u16 dport, sport;
            read_sock_addr(sk, &dport, &sport);
            maybe_emit_span(&span_events, &tracing_config,
                inf->ts, latency_ns, cgroup_id,
                dst_ip, dport, sport,
                PROTO_MONGO, req_cmd, err ? 1 : 0, 0,
                NULL, 0);
        }

        bpf_map_delete_elem(&mongo_inflight, &inf_key);
    }
    (__s32)0;
})""", BpfScalar.S32))
        returnValue(literal(0, BpfScalar.S32))
    }
}
