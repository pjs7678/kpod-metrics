package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

// ── Kafka-specific structs ───────────────────────────────────────────

object KafkaPortKey : BpfStruct("kafka_port_key") {
    val port by u16()
    val pad1 by u16()
    val pad2 by u32()
}

object KafkaPortVal : BpfStruct("kafka_port_val") {
    val enabled by u8()
    val pad by array(BpfScalar.U8, 7)
}

object KafkaEventKey : BpfStruct("kafka_event_key") {
    val cgroupId by u64()
    val apiKey by u16()   // Produce=0, Fetch=1, etc.
    val direction by u8() // DIR_CLIENT=0, DIR_SERVER=1
    val pad1 by u8()
    val pad2 by u32()
}

object KafkaLatKey : BpfStruct("kafka_latency_key") {
    val cgroupId by u64()
    val apiKey by u16()
    val direction by u8()
    val pad1 by u8()
    val pad2 by u32()
}

object KafkaInflightKey : BpfStruct("kafka_inflight_key") {
    val cgroupId by u64()
    val sockCookie by u64()
}

object KafkaInflightVal : BpfStruct("kafka_inflight_val") {
    val ts by u64()
    val apiKey by u16()
    val direction by u8()
    val pad1 by u8()
    val pad2 by u32()
}

object KafkaErrKey : BpfStruct("kafka_err_key") {
    val cgroupId by u64()
    val errCode by u16()  // Kafka error code from response
    val pad1 by u16()
    val pad2 by u32()
}

object KafkaRecvStash : BpfStruct("kafka_rcv_stash") {
    val sockPtr by u64()
    val msghdrPtr by u64()
    val cgroupId by u64()
    val sockCookie by u64()
}

// ── Kafka preamble ───────────────────────────────────────────────────

private val KAFKA_PREAMBLE = """
#define MAX_PAYLOAD 64

$COMMON_PREAMBLE

DEFINE_STATS_MAP(kafka_ports)
DEFINE_STATS_MAP(kafka_events)
DEFINE_STATS_MAP(kafka_latency)
DEFINE_STATS_MAP(kafka_inflight)
DEFINE_STATS_MAP(kafka_errors)
DEFINE_STATS_MAP(kafka_rcv_stash)

/* Kafka API keys we track */
#define KAFKA_PRODUCE          0
#define KAFKA_FETCH            1
#define KAFKA_LIST_OFFSETS     2
#define KAFKA_METADATA         3
#define KAFKA_OFFSET_COMMIT    8
#define KAFKA_OFFSET_FETCH     9
#define KAFKA_FIND_COORDINATOR 10
#define KAFKA_JOIN_GROUP       11
#define KAFKA_HEARTBEAT        12
#define KAFKA_LEAVE_GROUP      13
#define KAFKA_SYNC_GROUP       14
#define KAFKA_API_VERSIONS     18
#define KAFKA_CREATE_TOPICS    19
#define KAFKA_DELETE_TOPICS    20
#define KAFKA_API_OTHER        0xFFFF

/* Direction */
#define DIR_CLIENT 0
#define DIR_SERVER 1

#define PROTO_HTTP  1
#define PROTO_REDIS 2
#define PROTO_MYSQL 3
#define PROTO_KAFKA 4

/*
 * Kafka wire protocol (request):
 *   [0..3]  message_size (int32 big-endian, excludes itself)
 *   [4..5]  api_key     (int16 big-endian)
 *   [6..7]  api_version (int16 big-endian)
 *   [8..11] correlation_id (int32 big-endian)
 *
 * Kafka wire protocol (response):
 *   [0..3]  message_size (int32 big-endian, excludes itself)
 *   [4..7]  correlation_id (int32 big-endian)
 *   (no api_key in response — matched by correlation_id at higher layer)
 *
 * We detect requests by checking:
 *   - message_size > 0 and reasonable (< 100MB)
 *   - api_key in known range (0..67)
 *   - api_version in sane range (0..15)
 *
 * We detect responses by:
 *   - having an inflight entry for this socket
 *   - message_size > 0 and reasonable
 */

static __always_inline int is_kafka_request(const __u8 *buf, __u32 len, __u16 *out_api_key)
{
    if (len < 12) return 0;

    /* message_size (big-endian int32) */
    __u32 msg_size = ((__u32)buf[0] << 24) | ((__u32)buf[1] << 16) |
                     ((__u32)buf[2] << 8)  | (__u32)buf[3];
    if (msg_size == 0 || msg_size > 104857600) return 0; /* 0 or > 100MB */

    /* api_key (big-endian int16) */
    __u16 api_key = ((__u16)buf[4] << 8) | (__u16)buf[5];
    if (api_key > 67) return 0; /* max known Kafka API key */

    /* api_version (big-endian int16) */
    __u16 api_ver = ((__u16)buf[6] << 8) | (__u16)buf[7];
    if (api_ver > 15) return 0; /* sanity check */

    *out_api_key = api_key;
    return 1;
}

static __always_inline __u16 classify_api_key(__u16 api_key)
{
    switch (api_key) {
    case KAFKA_PRODUCE:
    case KAFKA_FETCH:
    case KAFKA_LIST_OFFSETS:
    case KAFKA_METADATA:
    case KAFKA_OFFSET_COMMIT:
    case KAFKA_OFFSET_FETCH:
    case KAFKA_FIND_COORDINATOR:
    case KAFKA_JOIN_GROUP:
    case KAFKA_HEARTBEAT:
    case KAFKA_LEAVE_GROUP:
    case KAFKA_SYNC_GROUP:
    case KAFKA_API_VERSIONS:
    case KAFKA_CREATE_TOPICS:
    case KAFKA_DELETE_TOPICS:
        return api_key;
    default:
        return KAFKA_API_OTHER;
    }
}

/*
 * Detect a Kafka response. Responses lack api_key, so we just check
 * that message_size is reasonable (the caller must have an inflight entry).
 */
static __always_inline int is_kafka_response(const __u8 *buf, __u32 len)
{
    if (len < 8) return 0;
    __u32 msg_size = ((__u32)buf[0] << 24) | ((__u32)buf[1] << 16) |
                     ((__u32)buf[2] << 8)  | (__u32)buf[3];
    if (msg_size == 0 || msg_size > 104857600) return 0;
    /* correlation_id at [4..7] — any value is valid */
    return 1;
}

/*
 * Extract Kafka error code from response.
 * For Produce/Fetch responses, the error code position varies by API version.
 * For simplicity, check the "top-level" error code at offset 8..9 (present
 * in many response types like Metadata, FindCoordinator, etc.).
 * Returns 0 (NONE) if no error or if we can't parse.
 */
static __always_inline __u16 extract_kafka_error(const __u8 *buf, __u32 len, __u16 api_key)
{
    /* Most responses have error_code at bytes 8-9 (after correlation_id) */
    if (len < 10) return 0;
    __u16 err = ((__u16)buf[8] << 8) | (__u16)buf[9];
    return err;
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

private val KAFKA_POSTAMBLE = """
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

static __always_inline int check_kafka_port(struct sock *sk)
{
    __u16 dport, sport;
    read_sock_addr(sk, &dport, &sport);
    struct kafka_port_key pk = { .port = dport };
    if (bpf_map_lookup_elem(&kafka_ports, &pk)) return 1;
    pk.port = sport;
    __builtin_memset(&pk.pad1, 0, sizeof(pk.pad1) + sizeof(pk.pad2));
    if (bpf_map_lookup_elem(&kafka_ports, &pk)) return 1;
    return 0;
}

static __always_inline void inc_kafka_event(void *map, void *key)
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

// ── Kafka program ────────────────────────────────────────────────────

@Suppress("DEPRECATION")
val kafkaProgram = ebpf("kafka") {
    license("GPL")
    targetKernel("5.8")

    preamble(KAFKA_PREAMBLE)
    postamble(KAFKA_POSTAMBLE)

    // ── Maps ─────────────────────────────────────────────────────────
    val kafkaPorts by hashMap(KafkaPortKey, KafkaPortVal, maxEntries = 8)
    val kafkaEvents by lruHashMap(KafkaEventKey, CounterValue, maxEntries = 10240)
    val kafkaLatency by lruHashMap(KafkaLatKey, HistValue, maxEntries = 10240)
    val kafkaInflight by lruHashMap(KafkaInflightKey, KafkaInflightVal, maxEntries = 8192)
    val kafkaErrors by lruHashMap(KafkaErrKey, CounterValue, maxEntries = 10240)
    val kafkaRcvStash by percpuArray(KafkaRecvStash, maxEntries = 1)
    val tracingConfig by array(TracingConfig, maxEntries = 1)
    val spanEvents by ringBuf(maxEntries = 262144) // 256KB

    // ── kprobe/tcp_sendmsg ───────────────────────────────────────────
    kprobe("tcp_sendmsg") {
        declareVar("_kafka_send", raw("""({
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

    if (!check_kafka_port(sk)) return 0;

    struct iovec iov0;
    if (read_first_iov(msg, &iov0) < 0) return 0;
    if (iov0.iov_len < 12) return 0;

    __u8 buf[MAX_PAYLOAD];
    __builtin_memset(buf, 0, sizeof(buf));
    __u32 to_read = iov0.iov_len;
    if (to_read > MAX_PAYLOAD) to_read = MAX_PAYLOAD;
    to_read &= (MAX_PAYLOAD - 1);  /* provable bound for older verifiers */
    if (bpf_probe_read_user(buf, to_read, iov0.iov_base) < 0) return 0;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u64 sock_cookie = (__u64)sk;

    struct kafka_inflight_key inf_key = {
        .cgroup_id = cgroup_id,
        .sock_cookie = sock_cookie,
    };

    /* Check if this is a Kafka request */
    __u16 api_key_raw = 0;
    if (is_kafka_request(buf, to_read, &api_key_raw)) {
        __u16 api_key = classify_api_key(api_key_raw);
        __u8 direction = DIR_CLIENT;
        struct kafka_event_key ev_key = {
            .cgroup_id = cgroup_id,
            .api_key = api_key,
            .direction = direction,
        };
        inc_kafka_event(&kafka_events, &ev_key);
        struct kafka_inflight_val inf_val = {
            .ts = bpf_ktime_get_ns(),
            .api_key = api_key,
            .direction = direction,
        };
        bpf_map_update_elem(&kafka_inflight, &inf_key, &inf_val, BPF_NOEXIST);
        return 0;
    }

    /* Check if this is a Kafka response (we're the broker sending a reply) */
    if (is_kafka_response(buf, to_read)) {
        struct kafka_inflight_val *inf = bpf_map_lookup_elem(&kafka_inflight, &inf_key);
        if (!inf) return 0;

        __u64 latency_ns = bpf_ktime_get_ns() - inf->ts;
        __u16 req_api_key = inf->api_key;
        __u8 req_dir = inf->direction;

        struct kafka_latency_key lat_key = {
            .cgroup_id = cgroup_id,
            .api_key = req_api_key,
            .direction = req_dir,
        };
        update_hist(&kafka_latency, &lat_key, latency_ns);

        __u16 err_code = extract_kafka_error(buf, to_read, req_api_key);
        if (err_code != 0) {
            struct kafka_err_key ek = { .cgroup_id = cgroup_id, .err_code = err_code };
            inc_kafka_event(&kafka_errors, &ek);
        }
        {
            __u32 dst_ip = 0;
            bpf_probe_read(&dst_ip, sizeof(dst_ip), &sk->__sk_common.skc_daddr);
            __u16 dport, sport;
            read_sock_addr(sk, &dport, &sport);
            maybe_emit_span(&span_events, &tracing_config,
                inf->ts, latency_ns, cgroup_id,
                dst_ip, dport, sport,
                PROTO_KAFKA, (__u8)(req_api_key & 0xFF), err_code, req_dir,
                NULL, 0);
        }

        bpf_map_delete_elem(&kafka_inflight, &inf_key);
    }
    (__s32)0;
})""", BpfScalar.S32))
        returnValue(literal(0, BpfScalar.S32))
    }

    // ── kprobe/tcp_recvmsg ───────────────────────────────────────────
    kprobe("tcp_recvmsg") {
        declareVar("_kafka_recv", raw("""({
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!check_kafka_port(sk)) return 0;

    __u32 zero = 0;
    struct kafka_rcv_stash *stash = bpf_map_lookup_elem(&kafka_rcv_stash, &zero);
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
        declareVar("_kafka_recv_exit", raw("""({
    long ret = (long)PT_REGS_RC(ctx);
    if (ret < 12) return 0;

    __u32 zero = 0;
    struct kafka_rcv_stash *stash = bpf_map_lookup_elem(&kafka_rcv_stash, &zero);
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

    struct kafka_inflight_key inf_key = {
        .cgroup_id = cgroup_id,
        .sock_cookie = sock_cookie,
    };

    /* Check for inbound Kafka request (we're the broker) */
    __u16 api_key_raw = 0;
    if (is_kafka_request(buf, to_read, &api_key_raw)) {
        __u16 api_key = classify_api_key(api_key_raw);
        __u8 direction = DIR_SERVER;
        struct kafka_event_key ev_key = {
            .cgroup_id = cgroup_id,
            .api_key = api_key,
            .direction = direction,
        };
        inc_kafka_event(&kafka_events, &ev_key);
        struct kafka_inflight_val inf_val = {
            .ts = bpf_ktime_get_ns(),
            .api_key = api_key,
            .direction = direction,
        };
        bpf_map_update_elem(&kafka_inflight, &inf_key, &inf_val, BPF_NOEXIST);
        return 0;
    }

    /* Check for inbound Kafka response (we're the client) */
    if (is_kafka_response(buf, to_read)) {
        struct kafka_inflight_val *inf = bpf_map_lookup_elem(&kafka_inflight, &inf_key);
        if (!inf) return 0;

        __u64 latency_ns = bpf_ktime_get_ns() - inf->ts;
        __u16 req_api_key = inf->api_key;
        __u8 req_dir = inf->direction;

        struct kafka_latency_key lat_key = {
            .cgroup_id = cgroup_id,
            .api_key = req_api_key,
            .direction = req_dir,
        };
        update_hist(&kafka_latency, &lat_key, latency_ns);

        __u16 err_code = extract_kafka_error(buf, to_read, req_api_key);
        if (err_code != 0) {
            struct kafka_err_key ek = { .cgroup_id = cgroup_id, .err_code = err_code };
            inc_kafka_event(&kafka_errors, &ek);
        }
        {
            __u32 dst_ip = 0;
            bpf_probe_read(&dst_ip, sizeof(dst_ip), &sk->__sk_common.skc_daddr);
            __u16 dport, sport;
            read_sock_addr(sk, &dport, &sport);
            maybe_emit_span(&span_events, &tracing_config,
                inf->ts, latency_ns, cgroup_id,
                dst_ip, dport, sport,
                PROTO_KAFKA, (__u8)(req_api_key & 0xFF), err_code, req_dir,
                NULL, 0);
        }

        bpf_map_delete_elem(&kafka_inflight, &inf_key);
    }
    (__s32)0;
})""", BpfScalar.S32))
        returnValue(literal(0, BpfScalar.S32))
    }
}
