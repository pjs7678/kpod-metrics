# Redis & MySQL L7 Protocol Detection Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add BPF-based Redis and MySQL protocol detection with request/response latency tracking to distinguish slow backend vs slow client-side.

**Architecture:** Two new BPF programs (redis, mysql) defined in kotlin-ebpf-dsl, hooking tcp_sendmsg/tcp_recvmsg to parse protocol headers and match request-response pairs via inflight maps. Each has a dedicated Kotlin collector that reads BPF maps via JNI bridge and exports Prometheus metrics.

**Tech Stack:** kotlin-ebpf-dsl (BPF program DSL), Spring Boot (collector beans), Micrometer (Prometheus metrics), JNI bridge (BPF map reads)

---

### Task 1: Add Redis and MySQL to ExtendedProperties and profiles

**Files:**
- Modify: `src/main/kotlin/com/internal/kpodmetrics/config/MetricsProperties.kt`

**Step 1: Add properties to ExtendedProperties**

In `MetricsProperties.kt`, add Redis and MySQL fields to `ExtendedProperties`:

```kotlin
data class ExtendedProperties(
    val biolatency: Boolean = false,
    val cachestat: Boolean = false,
    val tcpdrop: Boolean = false,
    val hardirqs: Boolean = false,
    val softirqs: Boolean = false,
    val execsnoop: Boolean = false,
    val dns: Boolean = false,
    val dnsPorts: List<Int> = listOf(53),
    val tcpPeer: Boolean = false,
    val http: Boolean = false,
    val httpPorts: List<Int> = listOf(80, 8080, 8443),
    val redis: Boolean = false,
    val redisPorts: List<Int> = listOf(6379),
    val mysql: Boolean = false,
    val mysqlPorts: List<Int> = listOf(3306)
)
```

**Step 2: Add to standard and comprehensive profiles**

In `resolveProfile()`, add `redis = true, mysql = true` to both `"standard"` and `"comprehensive"` `ExtendedProperties` blocks. Example for standard:

```kotlin
"standard" -> ResolvedConfig(
    // ... existing ...
    extended = ExtendedProperties(
        tcpdrop = true, execsnoop = true, dns = true, tcpPeer = true, http = true,
        redis = true, mysql = true
    ),
    // ...
)
```

Do the same for `"comprehensive"`.

**Step 3: Add collector intervals and overrides**

In `CollectorIntervals`, add:
```kotlin
val redis: Long? = null,
val mysql: Long? = null
```

In `CollectorOverrides`, add:
```kotlin
val redis: Boolean? = null,
val mysql: Boolean? = null
```

**Step 4: Run tests**

Run: `JAVA_HOME=/opt/homebrew/Cellar/openjdk@21/21.0.10/libexec/openjdk.jdk/Contents/Home ./gradlew -PebpfDslPath=/Users/jongsu/kotlin-ebpf-dsl test`
Expected: All tests pass (config changes are additive, existing tests unaffected).

**Step 5: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/config/MetricsProperties.kt
git commit -m "feat: add redis and mysql config properties to ExtendedProperties and profiles"
```

---

### Task 2: Create Redis BPF program DSL definition

**Files:**
- Create: `src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/RedisProgram.kt`
- Modify: `src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/GenerateBpf.kt`

**Step 1: Create RedisProgram.kt**

Create the file at `src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/RedisProgram.kt`:

```kotlin
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

object RedisRecvStash : BpfStruct("redis_recv_stash") {
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
DEFINE_STATS_MAP(redis_recv_stash)

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
 * We look for the command starting after the second \n.
 */
static __always_inline __u8 detect_redis_command(const __u8 *buf, __u32 len)
{
    if (len < 8 || buf[0] != '*') return CMD_UNKNOWN;

    /* Find the command: skip *<N>\r\n$<N>\r\n to get to the command bytes */
    __u32 off = 1;
    /* Skip array count digits + \r\n */
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (off >= len) return CMD_UNKNOWN;
        if (buf[off] == '\r') { off += 2; break; }
        off++;
    }
    /* Expect '$' for bulk string length */
    if (off >= len || buf[off] != '$') return CMD_UNKNOWN;
    off++;
    /* Skip length digits + \r\n */
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (off >= len) return CMD_UNKNOWN;
        if (buf[off] == '\r') { off += 2; break; }
        off++;
    }
    /* Now at command bytes — match common commands (case-insensitive first char) */
    if (off + 3 > len) return CMD_UNKNOWN;

    __u8 c0 = buf[off] | 0x20;  /* tolower */
    __u8 c1 = (off + 1 < len) ? (buf[off + 1] | 0x20) : 0;
    __u8 c2 = (off + 2 < len) ? (buf[off + 2] | 0x20) : 0;
    __u8 c3 = (off + 3 < len) ? (buf[off + 3] | 0x20) : 0;
    __u8 c4 = (off + 4 < len) ? (buf[off + 4] | 0x20) : 0;

    /* GET */
    if (c0 == 'g' && c1 == 'e' && c2 == 't' && (off + 3 >= len || buf[off + 3] == '\r'))
        return CMD_GET;
    /* SET */
    if (c0 == 's' && c1 == 'e' && c2 == 't' && (off + 3 >= len || buf[off + 3] == '\r'))
        return CMD_SET;
    /* DEL */
    if (c0 == 'd' && c1 == 'e' && c2 == 'l' && (off + 3 >= len || buf[off + 3] == '\r'))
        return CMD_DEL;
    /* HGET */
    if (c0 == 'h' && c1 == 'g' && c2 == 'e' && c3 == 't')
        return CMD_HGET;
    /* HSET */
    if (c0 == 'h' && c1 == 's' && c2 == 'e' && c3 == 't')
        return CMD_HSET;
    /* LPUSH */
    if (c0 == 'l' && c1 == 'p' && c2 == 'u' && c3 == 's')
        return CMD_LPUSH;
    /* RPUSH */
    if (c0 == 'r' && c1 == 'p' && c2 == 'u' && c3 == 's')
        return CMD_RPUSH;
    /* SADD */
    if (c0 == 's' && c1 == 'a' && c2 == 'd' && c3 == 'd')
        return CMD_SADD;
    /* ZADD */
    if (c0 == 'z' && c1 == 'a' && c2 == 'd' && c3 == 'd')
        return CMD_ZADD;
    /* EXPIRE */
    if (c0 == 'e' && c1 == 'x' && c2 == 'p')
        return CMD_EXPIRE;
    /* INCR */
    if (c0 == 'i' && c1 == 'n' && c2 == 'c' && c3 == 'r')
        return CMD_INCR;

    return CMD_OTHER;
}

/*
 * Detect RESP response type and check for error.
 * Returns: first byte of RESP response ('+', '-', ':', '$', '*')
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
    val redisRecvStash by percpuArray(RedisRecvStash, maxEntries = 1)

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
    struct redis_recv_stash *stash = bpf_map_lookup_elem(&redis_recv_stash, &zero);
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
    struct redis_recv_stash *stash = bpf_map_lookup_elem(&redis_recv_stash, &zero);
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
```

**Step 2: Add to GenerateBpf.kt**

In `GenerateBpf.kt`, add `redisProgram` to the programs list and `"redis"` to `cOnlyPrograms`:

```kotlin
val programs = listOf(
    // Custom programs
    cpuSchedProgram, netProgram, syscallProgram, dnsProgram, httpProgram,
    cpuProfileProgram, tcpPeerProgram, redisProgram,
    // BCC-style tools from kotlin-ebpf-dsl
    biolatency(), cachestat(), tcpdrop(),
    hardirqs(), softirqs(), execsnoop()
)
// ...
val cOnlyPrograms = setOf("dns", "http", "cpu_profile", "tcp_peer", "redis")
```

**Step 3: Run code generation to verify it compiles**

Run: `JAVA_HOME=/opt/homebrew/Cellar/openjdk@21/21.0.10/libexec/openjdk.jdk/Contents/Home ./gradlew -PebpfDslPath=/Users/jongsu/kotlin-ebpf-dsl generateBpf`
Expected: `Generated N BPF programs` with `redis` in the list.

**Step 4: Run tests**

Run: `JAVA_HOME=/opt/homebrew/Cellar/openjdk@21/21.0.10/libexec/openjdk.jdk/Contents/Home ./gradlew -PebpfDslPath=/Users/jongsu/kotlin-ebpf-dsl test`
Expected: All tests pass.

**Step 5: Commit**

```bash
git add src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/RedisProgram.kt \
        src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/GenerateBpf.kt
git commit -m "feat: add Redis BPF program with RESP protocol detection"
```

---

### Task 3: Create MySQL BPF program DSL definition

**Files:**
- Create: `src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/MysqlProgram.kt`
- Modify: `src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/GenerateBpf.kt`

**Step 1: Create MysqlProgram.kt**

Create the file at `src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/MysqlProgram.kt`:

```kotlin
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
    val pad by u8()
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

object MysqlRecvStash : BpfStruct("mysql_recv_stash") {
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
DEFINE_STATS_MAP(mysql_recv_stash)

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
    val mysqlRecvStash by percpuArray(MysqlRecvStash, maxEntries = 1)

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
    struct mysql_recv_stash *stash = bpf_map_lookup_elem(&mysql_recv_stash, &zero);
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
    struct mysql_recv_stash *stash = bpf_map_lookup_elem(&mysql_recv_stash, &zero);
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
```

**Step 2: Add to GenerateBpf.kt**

Add `mysqlProgram` to the programs list and `"mysql"` to `cOnlyPrograms`:

```kotlin
val programs = listOf(
    // Custom programs
    cpuSchedProgram, netProgram, syscallProgram, dnsProgram, httpProgram,
    cpuProfileProgram, tcpPeerProgram, redisProgram, mysqlProgram,
    // BCC-style tools from kotlin-ebpf-dsl
    biolatency(), cachestat(), tcpdrop(),
    hardirqs(), softirqs(), execsnoop()
)
// ...
val cOnlyPrograms = setOf("dns", "http", "cpu_profile", "tcp_peer", "redis", "mysql")
```

**Step 3: Run code generation**

Run: `JAVA_HOME=/opt/homebrew/Cellar/openjdk@21/21.0.10/libexec/openjdk.jdk/Contents/Home ./gradlew -PebpfDslPath=/Users/jongsu/kotlin-ebpf-dsl generateBpf`
Expected: `Generated N BPF programs` with `mysql` in the list.

**Step 4: Run tests**

Run: `JAVA_HOME=/opt/homebrew/Cellar/openjdk@21/21.0.10/libexec/openjdk.jdk/Contents/Home ./gradlew -PebpfDslPath=/Users/jongsu/kotlin-ebpf-dsl test`
Expected: All tests pass.

**Step 5: Commit**

```bash
git add src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/MysqlProgram.kt \
        src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/GenerateBpf.kt
git commit -m "feat: add MySQL BPF program with wire protocol detection"
```

---

### Task 4: Create RedisCollector

**Files:**
- Create: `src/main/kotlin/com/internal/kpodmetrics/collector/RedisCollector.kt`

**Step 1: Create RedisCollector.kt**

Follow the exact same pattern as `HttpCollector.kt`. Create `src/main/kotlin/com/internal/kpodmetrics/collector/RedisCollector.kt`:

```kotlin
package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.DistributionSummary
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

class RedisCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(RedisCollector::class.java)

    companion object {
        // redis_event_key: u64(cgroup_id) + u8(command) + u8(direction) + u16(pad1) + u32(pad2) = 16
        private const val EVENT_KEY_SIZE = 16
        // counter_value: u64(count) = 8
        private const val EVENT_VALUE_SIZE = 8
        // redis_latency_key: u64(cgroup_id) + u8(command) + u8(direction) + u16(pad1) + u32(pad2) = 16
        private const val LATENCY_KEY_SIZE = 16
        // hist_value: u64[27](slots) + u64(count) + u64(sum_ns) = 232
        private const val HIST_VALUE_SIZE = 232
        // redis_err_key: u64(cgroup_id) + u8(err_type) + u8[7](pad) = 16
        private const val ERROR_KEY_SIZE = 16
        private const val ERROR_VALUE_SIZE = 8

        private val COMMAND_NAMES = arrayOf(
            "UNKNOWN", "GET", "SET", "DEL", "HGET", "HSET",
            "LPUSH", "RPUSH", "SADD", "ZADD", "EXPIRE", "INCR", "OTHER"
        )

        private val ERROR_NAMES = arrayOf(
            "UNKNOWN", "ERR", "WRONGTYPE", "MOVED", "OTHER"
        )

        fun commandName(cmd: Int): String =
            if (cmd in COMMAND_NAMES.indices) COMMAND_NAMES[cmd] else "UNKNOWN"

        fun errorName(err: Int): String =
            if (err in ERROR_NAMES.indices) ERROR_NAMES[err] else "UNKNOWN"

        fun directionLabel(direction: Int): String = when (direction) {
            0 -> "client"
            1 -> "server"
            else -> "unknown"
        }
    }

    fun collect() {
        if (!config.extended.redis) return
        if (!programManager.isProgramLoaded("redis")) return
        collectEvents()
        collectLatency()
        collectErrors()
    }

    private fun mapIterateAndDelete(mapFd: Int, keySize: Int, valueSize: Int): List<Pair<ByteArray, ByteArray>> {
        val keys = mutableListOf<ByteArray>()
        var prevKey: ByteArray? = null
        while (true) {
            val nextKey = bridge.mapGetNextKey(mapFd, prevKey, keySize) ?: break
            keys.add(nextKey)
            prevKey = nextKey
        }
        val results = mutableListOf<Pair<ByteArray, ByteArray>>()
        for (k in keys) {
            val value = bridge.mapLookup(mapFd, k, valueSize)
            if (value != null) results.add(k to value)
            bridge.mapDelete(mapFd, k)
        }
        return results
    }

    private fun collectEvents() {
        val mapFd = programManager.getMapFd("redis", "redis_events")
        val entries = mapIterateAndDelete(mapFd, EVENT_KEY_SIZE, EVENT_VALUE_SIZE)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long
            val command = buf.get().toInt() and 0xFF
            val direction = buf.get().toInt() and 0xFF

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue

            val valBuf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            val count = valBuf.long

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "command", commandName(command),
                "direction", directionLabel(direction)
            )
            registry.counter("kpod.redis.requests", tags).increment(count.toDouble())
        }
    }

    private fun collectLatency() {
        val mapFd = programManager.getMapFd("redis", "redis_latency")
        val entries = mapIterateAndDelete(mapFd, LATENCY_KEY_SIZE, HIST_VALUE_SIZE)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long
            val command = buf.get().toInt() and 0xFF
            val direction = buf.get().toInt() and 0xFF

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue

            val valBuf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            valBuf.position(27 * 8) // Skip histogram slots
            val count = valBuf.long
            val sumNs = valBuf.long

            if (count <= 0 || sumNs <= 0) continue

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "command", commandName(command),
                "direction", directionLabel(direction)
            )
            val avgLatencySeconds = (sumNs.toDouble() / count.toDouble()) / 1_000_000_000.0
            DistributionSummary.builder("kpod.redis.request.duration")
                .tags(tags)
                .baseUnit("seconds")
                .register(registry)
                .record(avgLatencySeconds)
        }
    }

    private fun collectErrors() {
        val mapFd = programManager.getMapFd("redis", "redis_errors")
        val entries = mapIterateAndDelete(mapFd, ERROR_KEY_SIZE, ERROR_VALUE_SIZE)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long
            val errType = buf.get().toInt() and 0xFF

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue

            val valBuf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            val count = valBuf.long

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "error_type", errorName(errType)
            )
            registry.counter("kpod.redis.errors", tags).increment(count.toDouble())
        }
    }
}
```

**Step 2: Run tests**

Run: `JAVA_HOME=/opt/homebrew/Cellar/openjdk@21/21.0.10/libexec/openjdk.jdk/Contents/Home ./gradlew -PebpfDslPath=/Users/jongsu/kotlin-ebpf-dsl test`
Expected: All tests pass.

**Step 3: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/collector/RedisCollector.kt
git commit -m "feat: add RedisCollector for RESP protocol metrics"
```

---

### Task 5: Create MysqlCollector

**Files:**
- Create: `src/main/kotlin/com/internal/kpodmetrics/collector/MysqlCollector.kt`

**Step 1: Create MysqlCollector.kt**

Create `src/main/kotlin/com/internal/kpodmetrics/collector/MysqlCollector.kt`:

```kotlin
package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.DistributionSummary
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

class MysqlCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(MysqlCollector::class.java)

    companion object {
        // mysql_event_key: u64(cgroup_id) + u8(command) + u8(stmt_type) + u8(direction) + u8(pad) = 12
        // Note: struct size rounds to alignment — u64 + 4*u8 = 12, but compiler may pad to 16.
        // Actually: u64(8) + u8+u8+u8+u8(4) = 12 bytes. No padding needed since last field fits.
        // But BPF struct alignment typically pads to 8-byte boundary → 16 bytes.
        private const val EVENT_KEY_SIZE = 16
        // counter_value: u64(count) = 8
        private const val EVENT_VALUE_SIZE = 8
        // mysql_latency_key: u64(cgroup_id) + u8(command) + u8(stmt_type) + u8(direction) + u8(pad1) + u32(pad2) = 16
        private const val LATENCY_KEY_SIZE = 16
        // hist_value: u64[27](slots) + u64(count) + u64(sum_ns) = 232
        private const val HIST_VALUE_SIZE = 232
        // mysql_err_key: u64(cgroup_id) + u16(err_code) + u16(pad1) + u32(pad2) = 16
        private const val ERROR_KEY_SIZE = 16
        private const val ERROR_VALUE_SIZE = 8

        private val COMMAND_NAMES = mapOf(
            0x03 to "COM_QUERY",
            0x16 to "COM_STMT_PREPARE",
            0x17 to "COM_STMT_EXECUTE",
            0x0e to "COM_PING",
            0x01 to "COM_QUIT",
            0x02 to "COM_INIT_DB"
        )

        private val STMT_NAMES = arrayOf(
            "UNKNOWN", "SELECT", "INSERT", "UPDATE", "DELETE", "BEGIN", "COMMIT", "OTHER"
        )

        fun commandName(cmd: Int): String = COMMAND_NAMES[cmd] ?: "COM_UNKNOWN"

        fun stmtName(stmt: Int): String =
            if (stmt in STMT_NAMES.indices) STMT_NAMES[stmt] else "UNKNOWN"

        fun directionLabel(direction: Int): String = when (direction) {
            0 -> "client"
            1 -> "server"
            else -> "unknown"
        }
    }

    fun collect() {
        if (!config.extended.mysql) return
        if (!programManager.isProgramLoaded("mysql")) return
        collectEvents()
        collectLatency()
        collectErrors()
    }

    private fun mapIterateAndDelete(mapFd: Int, keySize: Int, valueSize: Int): List<Pair<ByteArray, ByteArray>> {
        val keys = mutableListOf<ByteArray>()
        var prevKey: ByteArray? = null
        while (true) {
            val nextKey = bridge.mapGetNextKey(mapFd, prevKey, keySize) ?: break
            keys.add(nextKey)
            prevKey = nextKey
        }
        val results = mutableListOf<Pair<ByteArray, ByteArray>>()
        for (k in keys) {
            val value = bridge.mapLookup(mapFd, k, valueSize)
            if (value != null) results.add(k to value)
            bridge.mapDelete(mapFd, k)
        }
        return results
    }

    private fun collectEvents() {
        val mapFd = programManager.getMapFd("mysql", "mysql_events")
        val entries = mapIterateAndDelete(mapFd, EVENT_KEY_SIZE, EVENT_VALUE_SIZE)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long
            val command = buf.get().toInt() and 0xFF
            val stmtType = buf.get().toInt() and 0xFF
            val direction = buf.get().toInt() and 0xFF

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue

            val valBuf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            val count = valBuf.long

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "command", commandName(command),
                "stmt_type", stmtName(stmtType),
                "direction", directionLabel(direction)
            )
            registry.counter("kpod.mysql.requests", tags).increment(count.toDouble())
        }
    }

    private fun collectLatency() {
        val mapFd = programManager.getMapFd("mysql", "mysql_latency")
        val entries = mapIterateAndDelete(mapFd, LATENCY_KEY_SIZE, HIST_VALUE_SIZE)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long
            val command = buf.get().toInt() and 0xFF
            val stmtType = buf.get().toInt() and 0xFF
            val direction = buf.get().toInt() and 0xFF

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue

            val valBuf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            valBuf.position(27 * 8) // Skip histogram slots
            val count = valBuf.long
            val sumNs = valBuf.long

            if (count <= 0 || sumNs <= 0) continue

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "command", commandName(command),
                "stmt_type", stmtName(stmtType),
                "direction", directionLabel(direction)
            )
            val avgLatencySeconds = (sumNs.toDouble() / count.toDouble()) / 1_000_000_000.0
            DistributionSummary.builder("kpod.mysql.request.duration")
                .tags(tags)
                .baseUnit("seconds")
                .register(registry)
                .record(avgLatencySeconds)
        }
    }

    private fun collectErrors() {
        val mapFd = programManager.getMapFd("mysql", "mysql_errors")
        val entries = mapIterateAndDelete(mapFd, ERROR_KEY_SIZE, ERROR_VALUE_SIZE)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long
            val errCode = buf.short.toInt() and 0xFFFF

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue

            val valBuf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            val count = valBuf.long

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "error_code", errCode.toString()
            )
            registry.counter("kpod.mysql.errors", tags).increment(count.toDouble())
        }
    }
}
```

**Step 2: Run tests**

Run: `JAVA_HOME=/opt/homebrew/Cellar/openjdk@21/21.0.10/libexec/openjdk.jdk/Contents/Home ./gradlew -PebpfDslPath=/Users/jongsu/kotlin-ebpf-dsl test`
Expected: All tests pass.

**Step 3: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/collector/MysqlCollector.kt
git commit -m "feat: add MysqlCollector for MySQL wire protocol metrics"
```

---

### Task 6: Wire Redis and MySQL into BpfProgramManager

**Files:**
- Modify: `src/main/kotlin/com/internal/kpodmetrics/bpf/BpfProgramManager.kt`

**Step 1: Add loading in loadAll()**

After the `if (ext.http) tryLoadProgram("http")` line, add:

```kotlin
if (ext.redis) tryLoadProgram("redis")
if (ext.mysql) tryLoadProgram("mysql")
```

**Step 2: Add configureRedisPorts() method**

After `configureHttpPorts()`, add:

```kotlin
fun configureRedisPorts(ports: List<Int>) {
    if (!isProgramLoaded("redis")) return
    val mapFd = getMapFd("redis", "redis_ports")
    for (port in ports) {
        val keyBytes = java.nio.ByteBuffer.allocate(8)
            .order(java.nio.ByteOrder.LITTLE_ENDIAN)
            .putShort(port.toShort())
            .putShort(0)  // _pad1
            .putInt(0)    // _pad2
            .array()
        val valueBytes = java.nio.ByteBuffer.allocate(8)
            .order(java.nio.ByteOrder.LITTLE_ENDIAN)
            .put(1.toByte())  // enabled
            .put(ByteArray(7))  // _pad
            .array()
        bridge.mapUpdate(mapFd, keyBytes, valueBytes)
    }
    log.info("Redis port filter configured: {}", ports)
}
```

**Step 3: Add configureMysqlPorts() method**

```kotlin
fun configureMysqlPorts(ports: List<Int>) {
    if (!isProgramLoaded("mysql")) return
    val mapFd = getMapFd("mysql", "mysql_ports")
    for (port in ports) {
        val keyBytes = java.nio.ByteBuffer.allocate(8)
            .order(java.nio.ByteOrder.LITTLE_ENDIAN)
            .putShort(port.toShort())
            .putShort(0)  // _pad1
            .putInt(0)    // _pad2
            .array()
        val valueBytes = java.nio.ByteBuffer.allocate(8)
            .order(java.nio.ByteOrder.LITTLE_ENDIAN)
            .put(1.toByte())  // enabled
            .put(ByteArray(7))  // _pad
            .array()
        bridge.mapUpdate(mapFd, keyBytes, valueBytes)
    }
    log.info("MySQL port filter configured: {}", ports)
}
```

**Step 4: Run tests**

Run: `JAVA_HOME=/opt/homebrew/Cellar/openjdk@21/21.0.10/libexec/openjdk.jdk/Contents/Home ./gradlew -PebpfDslPath=/Users/jongsu/kotlin-ebpf-dsl test`
Expected: All tests pass.

**Step 5: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/bpf/BpfProgramManager.kt
git commit -m "feat: add Redis and MySQL program loading and port configuration"
```

---

### Task 7: Wire into BpfAutoConfiguration and MetricsCollectorService

**Files:**
- Modify: `src/main/kotlin/com/internal/kpodmetrics/config/BpfAutoConfiguration.kt`
- Modify: `src/main/kotlin/com/internal/kpodmetrics/collector/MetricsCollectorService.kt`

**Step 1: Add collector beans in BpfAutoConfiguration.kt**

After the `httpCollector` bean definition, add:

```kotlin
@Bean
@ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
fun redisCollector(
    bridge: BpfBridge,
    manager: BpfProgramManager,
    resolver: CgroupResolver,
    registry: MeterRegistry,
    config: ResolvedConfig
) = RedisCollector(bridge, manager, resolver, registry, config, props.nodeName)

@Bean
@ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
fun mysqlCollector(
    bridge: BpfBridge,
    manager: BpfProgramManager,
    resolver: CgroupResolver,
    registry: MeterRegistry,
    config: ResolvedConfig
) = MysqlCollector(bridge, manager, resolver, registry, config, props.nodeName)
```

**Step 2: Add port configuration in onStartup()**

After the `configureHttpPorts` block, add:

```kotlin
if (resolvedCfg.extended.redis) {
    it.configureRedisPorts(resolvedCfg.extended.redisPorts)
}
if (resolvedCfg.extended.mysql) {
    it.configureMysqlPorts(resolvedCfg.extended.mysqlPorts)
}
```

**Step 3: Add to metricsCollectorService() bean**

Add `redisCollector: RedisCollector` and `mysqlCollector: MysqlCollector` as parameters to the `metricsCollectorService` bean. Pass them to the `MetricsCollectorService` constructor.

**Step 4: Update MetricsCollectorService constructor**

Add the new collector parameters after `httpCollector`:

```kotlin
private val redisCollector: RedisCollector,
private val mysqlCollector: MysqlCollector,
```

Add to the `collectors` map (in the `init` or wherever collectors are registered):

```kotlin
"redis" to redisCollector::collect,
"mysql" to mysqlCollector::collect,
```

Add to `collectorIntervals` map:

```kotlin
"redis" to collectorIntervals.redis,
"mysql" to collectorIntervals.mysql,
```

Add to `collectorOverrides` map:

```kotlin
"redis" to collectorOverrides.redis,
"mysql" to collectorOverrides.mysql,
```

Add "redis" and "mysql" to the `count` line for enabled collectors.

**Step 5: Run tests**

Run: `JAVA_HOME=/opt/homebrew/Cellar/openjdk@21/21.0.10/libexec/openjdk.jdk/Contents/Home ./gradlew -PebpfDslPath=/Users/jongsu/kotlin-ebpf-dsl test`
Expected: All tests pass.

**Step 6: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/config/BpfAutoConfiguration.kt \
        src/main/kotlin/com/internal/kpodmetrics/collector/MetricsCollectorService.kt
git commit -m "feat: wire Redis and MySQL collectors into Spring context and scheduler"
```

---

### Task 8: Docker build verification

**Step 1: Run full tests locally**

Run: `JAVA_HOME=/opt/homebrew/Cellar/openjdk@21/21.0.10/libexec/openjdk.jdk/Contents/Home ./gradlew -PebpfDslPath=/Users/jongsu/kotlin-ebpf-dsl test`
Expected: `BUILD SUCCESSFUL`

**Step 2: Verify Docker build**

The worktree needs to be rsynced to a temp directory for Docker build (worktree symlinks break Docker COPY). Follow the same process used for the DNS/HTTP migration:

```bash
TMPDIR=$(mktemp -d)
rsync -a --delete /Users/jongsu/dev/kpod-metrics/.worktrees/migrate-bpf/ "$TMPDIR/kpod-metrics/"
rsync -a --delete /Users/jongsu/kotlin-ebpf-dsl/ "$TMPDIR/kotlin-ebpf-dsl/"
docker build -f "$TMPDIR/kpod-metrics/Dockerfile" -t kpod-metrics:l7-redis-mysql "$TMPDIR"
```

Expected: Build succeeds. Check that all 15 BPF programs compile (13 existing + redis + mysql) in both core and legacy.

**Step 3: Verify BPF objects exist in image**

```bash
docker run --rm kpod-metrics:l7-redis-mysql ls -la /app/bpf/core/ /app/bpf/legacy/ | grep -E "redis|mysql"
```

Expected: `redis.bpf.o` and `mysql.bpf.o` in both `core/` and `legacy/`.

**Step 4: Commit (if any fixes needed)**

If no fixes needed, skip. Otherwise fix and commit.

---

### Task 9: Push and create PR

**Step 1: Push branch**

```bash
git push origin feature/migrate-remaining-bpf
```

**Step 2: Create PR**

```bash
gh pr create --title "feat: add Redis and MySQL L7 protocol detection" --body "..."
```

Include summary: BPF-based latency tracking for Redis (RESP) and MySQL (wire protocol). Distinguishes slow backend vs slow client-side. 15 BPF programs total, all DSL-generated.
