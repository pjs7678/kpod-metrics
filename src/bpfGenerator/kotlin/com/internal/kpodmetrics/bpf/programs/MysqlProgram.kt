package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

// ── MySQL-specific structs ───────────────────────────────────────────

object MysqlPortKey : BpfStruct("mysql_port_key") {
    val port by u16()
    val pad1 by u16()
    val pad2 by u32()
}

object MysqlPortVal : BpfStruct("mysql_port_val") {
    val enabled by u8()
    val pad by array(BpfScalar.U8, 7)
}

object MysqlEventKey : BpfStruct("mysql_event_key") {
    val cgroupId by u64()
    val command by u8()    // COM_QUERY=0x03, COM_STMT_PREPARE=0x16, etc.
    val stmtType by u8()  // STMT_SELECT=1, STMT_INSERT=2, etc.
    val direction by u8()  // DIR_CLIENT=0, DIR_SERVER=1
    val pad1 by u8()
    val pad2 by u32()
}

object MysqlLatKey : BpfStruct("mysql_latency_key") {
    val cgroupId by u64()
    val command by u8()
    val stmtType by u8()
    val direction by u8()
    val pad1 by u8()
    val pad2 by u32()
}

object MysqlInflightKey : BpfStruct("mysql_inflight_key") {
    val cgroupId by u64()
    val sockCookie by u64()
}

object MysqlInflightVal : BpfStruct("mysql_inflight_val") {
    val ts by u64()
    val command by u8()
    val stmtType by u8()
    val direction by u8()
    val pad1 by u8()
    val pad2 by u32()
}

object MysqlErrKey : BpfStruct("mysql_err_key") {
    val cgroupId by u64()
    val errCode by u16()
    val pad1 by u16()
    val pad2 by u32()
}

object MysqlRecvStash : BpfStruct("mysql_rcv_stash") {
    val sockPtr by u64()
    val msghdrPtr by u64()
    val cgroupId by u64()
    val sockCookie by u64()
}

// ── MySQL preamble ───────────────────────────────────────────────────

private val MYSQL_PREAMBLE = """
#define MAX_PAYLOAD 64

$COMMON_PREAMBLE

DEFINE_STATS_MAP(mysql_ports)
DEFINE_STATS_MAP(mysql_events)
DEFINE_STATS_MAP(mysql_latency)
DEFINE_STATS_MAP(mysql_inflight)
DEFINE_STATS_MAP(mysql_errors)
DEFINE_STATS_MAP(mysql_rcv_stash)

/* MySQL command types (from mysql_com.h) */
#define COM_QUERY          0x03
#define COM_STMT_PREPARE   0x16
#define COM_STMT_EXECUTE   0x17
#define COM_PING           0x0e
#define COM_QUIT           0x01
#define COM_INIT_DB        0x02

/* Statement types (for COM_QUERY) */
#define STMT_UNKNOWN  0
#define STMT_SELECT   1
#define STMT_INSERT   2
#define STMT_UPDATE   3
#define STMT_DELETE   4
#define STMT_BEGIN    5
#define STMT_COMMIT   6
#define STMT_OTHER    7

/* Direction */
#define DIR_CLIENT 0
#define DIR_SERVER 1

/* MySQL response types (first byte after header) */
#define MYSQL_OK     0x00
#define MYSQL_ERR    0xFF
#define MYSQL_EOF    0xFE

/*
 * MySQL wire protocol: 4-byte header (3-byte length LE + 1-byte seq)
 * followed by command byte at offset 4.
 *
 * For COM_QUERY, SQL text starts at offset 5.
 * Parse first keyword to determine statement type.
 */
static __always_inline __u8 detect_mysql_command(const __u8 *buf, __u32 len)
{
    /* Need at least 5 bytes: 4-byte header + 1-byte command */
    if (len < 5) return 0;
    return buf[4];
}

static __always_inline __u8 detect_stmt_type(const __u8 *buf, __u32 len)
{
    /* SQL starts at offset 5. Match first keyword. */
    if (len < 11) return STMT_UNKNOWN;
    __u32 off = 5;
    /* Skip leading whitespace */
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (off >= len) return STMT_UNKNOWN;
        if (buf[off] != ' ' && buf[off] != '\t' && buf[off] != '\n') break;
        off++;
    }
    if (off + 3 > len) return STMT_UNKNOWN;

    __u8 c0 = buf[off] | 0x20;
    __u8 c1 = (off + 1 < len) ? (buf[off + 1] | 0x20) : 0;
    __u8 c2 = (off + 2 < len) ? (buf[off + 2] | 0x20) : 0;
    __u8 c3 = (off + 3 < len) ? (buf[off + 3] | 0x20) : 0;
    __u8 c4 = (off + 4 < len) ? (buf[off + 4] | 0x20) : 0;
    __u8 c5 = (off + 5 < len) ? (buf[off + 5] | 0x20) : 0;

    /* SELECT */
    if (c0 == 's' && c1 == 'e' && c2 == 'l' && c3 == 'e' && c4 == 'c' && c5 == 't')
        return STMT_SELECT;
    /* INSERT */
    if (c0 == 'i' && c1 == 'n' && c2 == 's' && c3 == 'e' && c4 == 'r' && c5 == 't')
        return STMT_INSERT;
    /* UPDATE */
    if (c0 == 'u' && c1 == 'p' && c2 == 'd' && c3 == 'a' && c4 == 't' && c5 == 'e')
        return STMT_UPDATE;
    /* DELETE */
    if (c0 == 'd' && c1 == 'e' && c2 == 'l' && c3 == 'e' && c4 == 't' && c5 == 'e')
        return STMT_DELETE;
    /* BEGIN */
    if (c0 == 'b' && c1 == 'e' && c2 == 'g' && c3 == 'i' && c4 == 'n')
        return STMT_BEGIN;
    /* COMMIT */
    if (c0 == 'c' && c1 == 'o' && c2 == 'm' && c3 == 'm' && c4 == 'i' && c5 == 't')
        return STMT_COMMIT;

    return STMT_OTHER;
}

/*
 * Detect MySQL response packet.
 * Returns: 0 = not a valid response, MYSQL_OK/MYSQL_ERR/MYSQL_EOF/other.
 * For MYSQL_ERR, error code is at bytes 5-6 (LE u16).
 */
static __always_inline __u8 detect_mysql_response(const __u8 *buf, __u32 len)
{
    if (len < 5) return 0;
    /* Validate header: length field (3 bytes LE) should be > 0 and seq should be reasonable */
    __u32 pkt_len = buf[0] | (buf[1] << 8) | (buf[2] << 16);
    if (pkt_len == 0 || pkt_len > 0xFFFFFF) return 0;
    return buf[4];
}

static __always_inline __u16 extract_mysql_error_code(const __u8 *buf, __u32 len)
{
    if (len < 7 || buf[4] != MYSQL_ERR) return 0;
    return (__u16)(buf[5]) | ((__u16)(buf[6]) << 8);
}

/*
 * Check if a packet looks like a MySQL command (not a response).
 * MySQL commands: seq_id is typically 0 for new commands from client.
 */
static __always_inline int is_mysql_command(const __u8 *buf, __u32 len)
{
    if (len < 5) return 0;
    __u8 seq = buf[3];
    __u8 cmd = buf[4];
    /* Client commands typically have seq_id = 0 */
    if (seq != 0) return 0;
    /* Valid command range */
    if (cmd == COM_QUERY || cmd == COM_STMT_PREPARE || cmd == COM_STMT_EXECUTE ||
        cmd == COM_PING || cmd == COM_QUIT || cmd == COM_INIT_DB)
        return 1;
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

private val MYSQL_POSTAMBLE = """
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

static __always_inline int check_mysql_port(struct sock *sk)
{
    __u16 dport, sport;
    read_sock_addr(sk, &dport, &sport);
    struct mysql_port_key pk = { .port = dport };
    if (bpf_map_lookup_elem(&mysql_ports, &pk)) return 1;
    pk.port = sport;
    __builtin_memset(&pk.pad1, 0, sizeof(pk.pad1) + sizeof(pk.pad2));
    if (bpf_map_lookup_elem(&mysql_ports, &pk)) return 1;
    return 0;
}

static __always_inline void inc_mysql_event(void *map, void *key)
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

// ── MySQL program ────────────────────────────────────────────────────

@Suppress("DEPRECATION")
val mysqlProgram = ebpf("mysql") {
    license("GPL")
    targetKernel("5.5")

    preamble(MYSQL_PREAMBLE)
    postamble(MYSQL_POSTAMBLE)

    // ── Maps ─────────────────────────────────────────────────────────
    val mysqlPorts by hashMap(MysqlPortKey, MysqlPortVal, maxEntries = 8)
    val mysqlEvents by lruHashMap(MysqlEventKey, CounterValue, maxEntries = 10240)
    val mysqlLatency by lruHashMap(MysqlLatKey, HistValue, maxEntries = 10240)
    val mysqlInflight by lruHashMap(MysqlInflightKey, MysqlInflightVal, maxEntries = 8192)
    val mysqlErrors by lruHashMap(MysqlErrKey, CounterValue, maxEntries = 10240)
    val mysqlRcvStash by percpuArray(MysqlRecvStash, maxEntries = 1)

    // ── kprobe/tcp_sendmsg ───────────────────────────────────────────
    kprobe("tcp_sendmsg") {
        declareVar("_mysql_send", raw("""({
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

    if (!check_mysql_port(sk)) return 0;

    struct iovec iov0;
    if (read_first_iov(msg, &iov0) < 0) return 0;
    if (iov0.iov_len < 5) return 0;

    __u8 buf[MAX_PAYLOAD];
    __builtin_memset(buf, 0, sizeof(buf));
    __u32 to_read = iov0.iov_len;
    if (to_read > MAX_PAYLOAD) to_read = MAX_PAYLOAD;
    to_read &= (MAX_PAYLOAD - 1);  /* provable bound for older verifiers */
    if (bpf_probe_read_user(buf, to_read, iov0.iov_base) < 0) return 0;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u64 sock_cookie = (__u64)sk;

    struct mysql_inflight_key inf_key = {
        .cgroup_id = cgroup_id,
        .sock_cookie = sock_cookie,
    };

    /* Check if this is a MySQL command (client request) */
    if (is_mysql_command(buf, to_read)) {
        __u8 cmd = buf[4];
        __u8 stmt_type = STMT_UNKNOWN;
        if (cmd == COM_QUERY) stmt_type = detect_stmt_type(buf, to_read);

        __u8 direction = DIR_CLIENT;
        struct mysql_event_key ev_key = {
            .cgroup_id = cgroup_id,
            .command = cmd,
            .stmt_type = stmt_type,
            .direction = direction,
        };
        inc_mysql_event(&mysql_events, &ev_key);
        struct mysql_inflight_val inf_val = {
            .ts = bpf_ktime_get_ns(),
            .command = cmd,
            .stmt_type = stmt_type,
            .direction = direction,
        };
        bpf_map_update_elem(&mysql_inflight, &inf_key, &inf_val, BPF_NOEXIST);
        return 0;
    }

    /* Check if this is a MySQL response (server reply) */
    __u8 resp = detect_mysql_response(buf, to_read);
    if (resp == MYSQL_OK || resp == MYSQL_ERR || resp == MYSQL_EOF) {
        struct mysql_inflight_val *inf = bpf_map_lookup_elem(&mysql_inflight, &inf_key);
        if (!inf) return 0;

        __u64 latency_ns = bpf_ktime_get_ns() - inf->ts;
        __u8 req_cmd = inf->command;
        __u8 req_stmt = inf->stmt_type;
        __u8 req_dir = inf->direction;

        struct mysql_latency_key lat_key = {
            .cgroup_id = cgroup_id,
            .command = req_cmd,
            .stmt_type = req_stmt,
            .direction = req_dir,
        };
        update_hist(&mysql_latency, &lat_key, latency_ns);

        if (resp == MYSQL_ERR) {
            __u16 err_code = extract_mysql_error_code(buf, to_read);
            struct mysql_err_key ek = { .cgroup_id = cgroup_id, .err_code = err_code };
            inc_mysql_event(&mysql_errors, &ek);
        }

        bpf_map_delete_elem(&mysql_inflight, &inf_key);
    }
    (__s32)0;
})""", BpfScalar.S32))
        returnValue(literal(0, BpfScalar.S32))
    }

    // ── kprobe/tcp_recvmsg ───────────────────────────────────────────
    kprobe("tcp_recvmsg") {
        declareVar("_mysql_recv", raw("""({
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!check_mysql_port(sk)) return 0;

    __u32 zero = 0;
    struct mysql_rcv_stash *stash = bpf_map_lookup_elem(&mysql_rcv_stash, &zero);
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
        declareVar("_mysql_recv_exit", raw("""({
    long ret = (long)PT_REGS_RC(ctx);
    if (ret < 5) return 0;

    __u32 zero = 0;
    struct mysql_rcv_stash *stash = bpf_map_lookup_elem(&mysql_rcv_stash, &zero);
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

    struct mysql_inflight_key inf_key = {
        .cgroup_id = cgroup_id,
        .sock_cookie = sock_cookie,
    };

    /* Check for inbound MySQL command (we're the server) */
    if (is_mysql_command(buf, to_read)) {
        __u8 cmd = buf[4];
        __u8 stmt_type = STMT_UNKNOWN;
        if (cmd == COM_QUERY) stmt_type = detect_stmt_type(buf, to_read);

        __u8 direction = DIR_SERVER;
        struct mysql_event_key ev_key = {
            .cgroup_id = cgroup_id,
            .command = cmd,
            .stmt_type = stmt_type,
            .direction = direction,
        };
        inc_mysql_event(&mysql_events, &ev_key);
        struct mysql_inflight_val inf_val = {
            .ts = bpf_ktime_get_ns(),
            .command = cmd,
            .stmt_type = stmt_type,
            .direction = direction,
        };
        bpf_map_update_elem(&mysql_inflight, &inf_key, &inf_val, BPF_NOEXIST);
        return 0;
    }

    /* Check for inbound MySQL response (we're the client) */
    __u8 resp = detect_mysql_response(buf, to_read);
    if (resp == MYSQL_OK || resp == MYSQL_ERR || resp == MYSQL_EOF) {
        struct mysql_inflight_val *inf = bpf_map_lookup_elem(&mysql_inflight, &inf_key);
        if (!inf) return 0;

        __u64 latency_ns = bpf_ktime_get_ns() - inf->ts;
        __u8 req_cmd = inf->command;
        __u8 req_stmt = inf->stmt_type;
        __u8 req_dir = inf->direction;

        struct mysql_latency_key lat_key = {
            .cgroup_id = cgroup_id,
            .command = req_cmd,
            .stmt_type = req_stmt,
            .direction = req_dir,
        };
        update_hist(&mysql_latency, &lat_key, latency_ns);

        if (resp == MYSQL_ERR) {
            __u16 err_code = extract_mysql_error_code(buf, to_read);
            struct mysql_err_key ek = { .cgroup_id = cgroup_id, .err_code = err_code };
            inc_mysql_event(&mysql_errors, &ek);
        }

        bpf_map_delete_elem(&mysql_inflight, &inf_key);
    }
    (__s32)0;
})""", BpfScalar.S32))
        returnValue(literal(0, BpfScalar.S32))
    }
}
