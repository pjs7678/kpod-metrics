package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

// ── Redis-specific structs ───────────────────────────────────────────

object RedisPortKey : BpfStruct("redis_port_key") {
    val port by u16()
    val pad1 by u16()
    val pad2 by u32()
}

object RedisPortVal : BpfStruct("redis_port_val") {
    val enabled by u8()
    val pad by array(BpfScalar.U8, 7)
}

object RedisEventKey : BpfStruct("redis_event_key") {
    val cgroupId by u64()
    val command by u8()    // CMD_GET=1, CMD_SET=2, etc.
    val direction by u8()  // DIR_CLIENT=0, DIR_SERVER=1
    val pad1 by u16()
    val pad2 by u32()
}

object RedisLatKey : BpfStruct("redis_latency_key") {
    val cgroupId by u64()
    val command by u8()
    val direction by u8()
    val pad1 by u16()
    val pad2 by u32()
}

object RedisInflightKey : BpfStruct("redis_inflight_key") {
    val cgroupId by u64()
    val sockCookie by u64()
}

object RedisInflightVal : BpfStruct("redis_inflight_val") {
    val ts by u64()
    val command by u8()
    val direction by u8()
    val pad1 by u16()
    val pad2 by u32()
}

object RedisErrKey : BpfStruct("redis_err_key") {
    val cgroupId by u64()
    val errType by u8()    // ERR_GENERIC=1, ERR_WRONGTYPE=2, ERR_MOVED=3, ERR_OTHER=4
    val pad by array(BpfScalar.U8, 7)
}

object RedisRecvStash : BpfStruct("redis_rcv_stash") {
    val sockPtr by u64()
    val msghdrPtr by u64()
    val cgroupId by u64()
    val sockCookie by u64()
}

// ── Redis preamble ───────────────────────────────────────────────────

private val REDIS_PREAMBLE = """
#define MAX_PAYLOAD 64

$COMMON_PREAMBLE

DEFINE_STATS_MAP(redis_ports)
DEFINE_STATS_MAP(redis_events)
DEFINE_STATS_MAP(redis_latency)
DEFINE_STATS_MAP(redis_inflight)
DEFINE_STATS_MAP(redis_errors)
DEFINE_STATS_MAP(redis_rcv_stash)

/* Redis commands we track individually */
#define CMD_UNKNOWN  0
#define CMD_GET      1
#define CMD_SET      2
#define CMD_DEL      3
#define CMD_HGET     4
#define CMD_HSET     5
#define CMD_LPUSH    6
#define CMD_RPUSH    7
#define CMD_SADD     8
#define CMD_ZADD     9
#define CMD_EXPIRE  10
#define CMD_INCR    11
#define CMD_OTHER   12

/* Direction */
#define DIR_CLIENT 0
#define DIR_SERVER 1

/* Redis error types */
#define RERR_GENERIC   1
#define RERR_WRONGTYPE 2
#define RERR_MOVED     3
#define RERR_OTHER     4

/* RESP type bytes */
#define RESP_SIMPLE_STRING '+'
#define RESP_ERROR         '-'
#define RESP_INTEGER       ':'
#define RESP_BULK_STRING   '$'
#define RESP_ARRAY         '*'

/*
 * Parse RESP array to extract command name.
 * RESP request format: *<count>\r\n$<len>\r\n<COMMAND>\r\n...
 *
 * Use fixed offsets for the common case (single-digit array count and
 * command length) to avoid variable-offset loops that explode verifier state.
 * Common case: command at offset 8 (single-digit array count + cmd length)
 * Less common: command at offset 9 (2-digit count or length)
 */
static __always_inline __u8 match_redis_cmd(const __u8 *buf, __u32 off, __u32 len)
{
    if (off + 3 > len) return CMD_UNKNOWN;
    __u8 c0 = buf[off] | 0x20;
    __u8 c1 = buf[off + 1] | 0x20;
    __u8 c2 = buf[off + 2] | 0x20;
    __u8 c3 = (off + 3 < len) ? (buf[off + 3] | 0x20) : 0;

    if (c0 == 'g' && c1 == 'e' && c2 == 't') return CMD_GET;
    if (c0 == 's' && c1 == 'e' && c2 == 't') return CMD_SET;
    if (c0 == 'd' && c1 == 'e' && c2 == 'l') return CMD_DEL;
    if (c0 == 'h' && c1 == 'g' && c2 == 'e' && c3 == 't') return CMD_HGET;
    if (c0 == 'h' && c1 == 's' && c2 == 'e' && c3 == 't') return CMD_HSET;
    if (c0 == 'l' && c1 == 'p' && c2 == 'u') return CMD_LPUSH;
    if (c0 == 'r' && c1 == 'p' && c2 == 'u') return CMD_RPUSH;
    if (c0 == 's' && c1 == 'a' && c2 == 'd') return CMD_SADD;
    if (c0 == 'z' && c1 == 'a' && c2 == 'd') return CMD_ZADD;
    if (c0 == 'e' && c1 == 'x' && c2 == 'p') return CMD_EXPIRE;
    if (c0 == 'i' && c1 == 'n' && c2 == 'c') return CMD_INCR;
    return CMD_OTHER;
}

static __always_inline __u8 detect_redis_command(const __u8 *buf, __u32 len)
{
    if (len < 8 || buf[0] != '*') return CMD_UNKNOWN;

    /* Most common: *N\r\n then bulk string header \r\n -> cmd at 8 */
    if (buf[2] == '\r' && buf[4] == '${'$'}' && buf[6] == '\r') {
        return match_redis_cmd(buf, 8, len);
    }
    /* 2-digit cmd length: cmd at 9 */
    if (buf[2] == '\r' && buf[4] == '${'$'}' && buf[7] == '\r') {
        return match_redis_cmd(buf, 9, len);
    }
    /* 2-digit array count: cmd at 9 */
    if (buf[3] == '\r' && buf[5] == '${'$'}' && buf[7] == '\r') {
        return match_redis_cmd(buf, 9, len);
    }
    return CMD_UNKNOWN;
}

/*
 * Detect RESP response type and check for error.
 * Returns: first byte of RESP response ('+', '-', ':', '${'$'}', '*')
 * Error classification only when first byte is '-'.
 */
static __always_inline __u8 detect_redis_error(const __u8 *buf, __u32 len)
{
    if (len < 4 || buf[0] != '-') return 0;
    /* -ERR ..., -WRONGTYPE ..., -MOVED ..., etc. */
    if (len >= 5 && buf[1] == 'E' && buf[2] == 'R' && buf[3] == 'R')
        return RERR_GENERIC;
    if (len >= 10 && buf[1] == 'W' && buf[2] == 'R' && buf[3] == 'O')
        return RERR_WRONGTYPE;
    if (len >= 7 && buf[1] == 'M' && buf[2] == 'O' && buf[3] == 'V')
        return RERR_MOVED;
    return RERR_OTHER;
}

static __always_inline int is_redis_response(const __u8 *buf, __u32 len)
{
    if (len < 1) return 0;
    return (buf[0] == '+' || buf[0] == '-' || buf[0] == ':' ||
            buf[0] == '$' || buf[0] == '*');
}

static __always_inline int read_first_iov(struct msghdr *msg, struct iovec *out)
{
#ifdef LEGACY_IOVEC
    /* 4.18: iov_iter.type is ITER_IOVEC=0, __iov is always a pointer */
    struct iovec *msg_iov;
    if (bpf_probe_read(&msg_iov, sizeof(msg_iov), &msg->msg_iter.__iov) < 0)
        return -1;
    if (!msg_iov) return -1;
    if (bpf_probe_read(out, sizeof(*out), msg_iov) < 0)
        return -1;
    return 0;
#else
    /* 6.x: iter_type (u8); ITER_UBUF=0 stores iovec inline, ITER_IOVEC=1 uses pointer */
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

private val REDIS_POSTAMBLE = """
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

static __always_inline int check_redis_port(struct sock *sk)
{
    __u16 dport, sport;
    read_sock_addr(sk, &dport, &sport);
    struct redis_port_key pk = { .port = dport };
    if (bpf_map_lookup_elem(&redis_ports, &pk)) return 1;
    pk.port = sport;
    __builtin_memset(&pk.pad1, 0, sizeof(pk.pad1) + sizeof(pk.pad2));
    if (bpf_map_lookup_elem(&redis_ports, &pk)) return 1;
    return 0;
}

static __always_inline int is_redis_sport(struct sock *sk)
{
    __u16 dport, sport;
    read_sock_addr(sk, &dport, &sport);
    struct redis_port_key pk = { .port = sport };
    return bpf_map_lookup_elem(&redis_ports, &pk) ? 1 : 0;
}

static __always_inline void inc_redis_event(void *map, void *key)
{
    struct counter_value *ev = bpf_map_lookup_elem(map, key);
    if (ev) {
        __sync_fetch_and_add(&ev->count, 1);
    } else {
        struct counter_value one = { .count = 1 };
        bpf_map_update_elem(map, key, &one, BPF_NOEXIST);
    }
}
""".trimIndent()

// ── Redis program ────────────────────────────────────────────────────

@Suppress("DEPRECATION")
val redisProgram = ebpf("redis") {
    license("GPL")
    targetKernel("5.5")

    preamble(REDIS_PREAMBLE)
    postamble(REDIS_POSTAMBLE)

    // ── Maps ─────────────────────────────────────────────────────────
    val redisPorts by hashMap(RedisPortKey, RedisPortVal, maxEntries = 8)
    val redisEvents by lruHashMap(RedisEventKey, CounterValue, maxEntries = 10240)
    val redisLatency by lruHashMap(RedisLatKey, HistValue, maxEntries = 10240)
    val redisInflight by lruHashMap(RedisInflightKey, RedisInflightVal, maxEntries = 8192)
    val redisErrors by lruHashMap(RedisErrKey, CounterValue, maxEntries = 10240)
    val redisRcvStash by percpuArray(RedisRecvStash, maxEntries = 1)

    // ── kprobe/tcp_sendmsg ───────────────────────────────────────────
    kprobe("tcp_sendmsg") {
        declareVar("_redis_send", raw("""({
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

    if (!check_redis_port(sk)) return 0;

    struct iovec iov0;
    if (read_first_iov(msg, &iov0) < 0) return 0;
    if (iov0.iov_len < 4) return 0;

    __u8 buf[MAX_PAYLOAD];
    __builtin_memset(buf, 0, sizeof(buf));
    __u32 to_read = iov0.iov_len;
    if (to_read > MAX_PAYLOAD) to_read = MAX_PAYLOAD;
    to_read &= (MAX_PAYLOAD - 1);  /* provable bound for older verifiers */
    if (bpf_probe_read_user(buf, to_read, iov0.iov_base) < 0) return 0;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u64 sock_cookie = (__u64)sk;

    struct redis_inflight_key inf_key = {
        .cgroup_id = cgroup_id,
        .sock_cookie = sock_cookie,
    };

    /* Try to detect a RESP command (request) */
    __u8 cmd = detect_redis_command(buf, to_read);
    if (cmd != CMD_UNKNOWN) {
        /* This is a request being sent out (client) */
        __u8 direction = DIR_CLIENT;
        struct redis_event_key ev_key = {
            .cgroup_id = cgroup_id,
            .command = cmd,
            .direction = direction,
        };
        inc_redis_event(&redis_events, &ev_key);
        struct redis_inflight_val inf_val = {
            .ts = bpf_ktime_get_ns(),
            .command = cmd,
            .direction = direction,
        };
        bpf_map_update_elem(&redis_inflight, &inf_key, &inf_val, BPF_NOEXIST);
        return 0;
    }

    /* Try to detect a RESP response (we're the server sending a reply) */
    if (is_redis_response(buf, to_read)) {
        struct redis_inflight_val *inf = bpf_map_lookup_elem(&redis_inflight, &inf_key);
        if (!inf) return 0;

        __u64 latency_ns = bpf_ktime_get_ns() - inf->ts;
        __u8 req_cmd = inf->command;
        __u8 req_dir = inf->direction;

        struct redis_latency_key lat_key = {
            .cgroup_id = cgroup_id,
            .command = req_cmd,
            .direction = req_dir,
        };
        update_hist(&redis_latency, &lat_key, latency_ns);

        /* Check for error response */
        __u8 err = detect_redis_error(buf, to_read);
        if (err) {
            struct redis_err_key ek = { .cgroup_id = cgroup_id, .err_type = err };
            inc_redis_event(&redis_errors, &ek);
        }

        bpf_map_delete_elem(&redis_inflight, &inf_key);
    }
    (__s32)0;
})""", BpfScalar.S32))
        returnValue(literal(0, BpfScalar.S32))
    }

    // ── kprobe/tcp_recvmsg ───────────────────────────────────────────
    kprobe("tcp_recvmsg") {
        declareVar("_redis_recv", raw("""({
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!check_redis_port(sk)) return 0;

    __u32 zero = 0;
    struct redis_rcv_stash *stash = bpf_map_lookup_elem(&redis_rcv_stash, &zero);
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
        declareVar("_redis_recv_exit", raw("""({
    long ret = (long)PT_REGS_RC(ctx);
    if (ret < 3) return 0;

    __u32 zero = 0;
    struct redis_rcv_stash *stash = bpf_map_lookup_elem(&redis_rcv_stash, &zero);
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

    struct redis_inflight_key inf_key = {
        .cgroup_id = cgroup_id,
        .sock_cookie = sock_cookie,
    };

    /* Check for inbound RESP command (we're the server receiving a request) */
    __u8 cmd = detect_redis_command(buf, to_read);
    if (cmd != CMD_UNKNOWN) {
        __u8 direction = DIR_SERVER;
        struct redis_event_key ev_key = {
            .cgroup_id = cgroup_id,
            .command = cmd,
            .direction = direction,
        };
        inc_redis_event(&redis_events, &ev_key);
        struct redis_inflight_val inf_val = {
            .ts = bpf_ktime_get_ns(),
            .command = cmd,
            .direction = direction,
        };
        bpf_map_update_elem(&redis_inflight, &inf_key, &inf_val, BPF_NOEXIST);
        return 0;
    }

    /* Check for inbound RESP response (we're the client receiving a reply) */
    if (is_redis_response(buf, to_read)) {
        struct redis_inflight_val *inf = bpf_map_lookup_elem(&redis_inflight, &inf_key);
        if (!inf) return 0;

        __u64 latency_ns = bpf_ktime_get_ns() - inf->ts;
        __u8 req_cmd = inf->command;
        __u8 req_dir = inf->direction;

        struct redis_latency_key lat_key = {
            .cgroup_id = cgroup_id,
            .command = req_cmd,
            .direction = req_dir,
        };
        update_hist(&redis_latency, &lat_key, latency_ns);

        /* Check for error response */
        __u8 err = detect_redis_error(buf, to_read);
        if (err) {
            struct redis_err_key ek = { .cgroup_id = cgroup_id, .err_type = err };
            inc_redis_event(&redis_errors, &ek);
        }

        bpf_map_delete_elem(&redis_inflight, &inf_key);
    }
    (__s32)0;
})""", BpfScalar.S32))
        returnValue(literal(0, BpfScalar.S32))
    }
}
