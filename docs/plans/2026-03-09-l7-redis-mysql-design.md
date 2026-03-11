# Redis & MySQL L7 Protocol Detection Design

**Goal:** Add BPF-based latency tracking for Redis and MySQL to distinguish slow backend (external) vs slow client-side processing.

**Architecture:** Two separate BPF programs (`redis`, `mysql`) following the HTTP/DNS pattern — hook tcp_sendmsg/tcp_recvmsg, parse protocol headers from IOV buffers, match requests to responses via inflight maps, record latency histograms. Both defined in kotlin-ebpf-dsl with C-only emission; collectors use raw JNI bridge.

---

## Redis Program

### Protocol: RESP

Requests start with `*` (RESP array): `*<count>\r\n$<len>\r\n<COMMAND>\r\n...`
Responses start with `+` (simple string), `-` (error), `:` (integer), `$` (bulk), `*` (array).

### Detection Strategy

- **Request**: Read first ~64 bytes. Parse RESP array to extract command name.
- **Response**: Match first byte for type. `-` prefix = error; extract error type (ERR, WRONGTYPE, MOVED, etc).
- **Matching**: `(cgroup_id, sock_cookie)` inflight key — one outstanding request per socket direction.

### Tracked Commands

GET, SET, DEL, HGET, HSET, LPUSH, RPUSH, SADD, ZADD, EXPIRE, INCR. Everything else bucketed as OTHER.

### BPF Maps

| Map | Type | Key | Value |
|-----|------|-----|-------|
| `redis_ports` | HASH | `__u16 port` | `__u8` (1) |
| `redis_inflight` | LRU_HASH | `(cgroup_id, sock_cookie)` | `(timestamp, command, direction)` |
| `redis_events` | LRU_HASH | `(cgroup_id, command, direction)` | `counter_value` |
| `redis_latency` | LRU_HASH | `(cgroup_id, command, direction)` | `hist_value` (27-slot log2 + count + sum_ns) |
| `redis_errors` | LRU_HASH | `(cgroup_id, error_type)` | `counter_value` |

### Prometheus Metrics

- `kpod.redis.requests{command, direction}` — counter
- `kpod.redis.request.duration{command, direction}` — distribution summary (ns)
- `kpod.redis.errors{error_type}` — counter

---

## MySQL Program

### Protocol: MySQL Wire Protocol

4-byte packet header (3-byte length + 1-byte sequence ID) followed by payload. Command byte at offset 4.

### Detection Strategy

- **Request**: Read first ~64 bytes. Check command byte at offset 4:
  - `0x03` COM_QUERY: parse first SQL keyword at offset 5 (SELECT, INSERT, UPDATE, DELETE, BEGIN, COMMIT → stmt_type). Bucket rest as OTHER.
  - `0x16` COM_STMT_PREPARE, `0x17` COM_STMT_EXECUTE, `0x0e` COM_PING: track by command type.
- **Response**: First byte after 4-byte header:
  - `0x00` = OK packet
  - `0xFF` = ERR packet (error code at bytes 5-6, little-endian)
  - `0xFE` = EOF
  - Other = column count (result set)
- **Matching**: `(cgroup_id, sock_cookie)` inflight key — same as Redis/HTTP.

### BPF Maps

| Map | Type | Key | Value |
|-----|------|-----|-------|
| `mysql_ports` | HASH | `__u16 port` | `__u8` (1) |
| `mysql_inflight` | LRU_HASH | `(cgroup_id, sock_cookie)` | `(timestamp, command, stmt_type, direction)` |
| `mysql_events` | LRU_HASH | `(cgroup_id, command, stmt_type, direction)` | `counter_value` |
| `mysql_latency` | LRU_HASH | `(cgroup_id, command, stmt_type, direction)` | `hist_value` (27-slot log2 + count + sum_ns) |
| `mysql_errors` | LRU_HASH | `(cgroup_id, error_code)` | `counter_value` |

### Prometheus Metrics

- `kpod.mysql.requests{command, stmt_type, direction}` — counter
- `kpod.mysql.request.duration{command, stmt_type, direction}` — distribution summary (ns)
- `kpod.mysql.errors{error_code}` — counter

---

## Direction Semantics

Same as HTTP:
- **client** (outbound request, inbound response): app calling Redis/MySQL. Latency = backend slowness.
- **server** (inbound request, outbound response): app proxying. Latency = app processing time.

This is the core of distinguishing "slow external" vs "slow client-side."

---

## Hook Points

Both programs use the same hooks as HTTP:

| Hook | Purpose |
|------|---------|
| `kprobe/tcp_sendmsg` | Parse outbound requests/responses |
| `kprobe/tcp_recvmsg` | Stash msghdr + sock to per-CPU array |
| `kretprobe/tcp_recvmsg` | Parse inbound requests/responses from stashed buffer |

Port filter checked early (before payload read) for fast rejection.

---

## Integration

- **DSL**: `RedisProgram.kt`, `MysqlProgram.kt` in `src/bpfGenerator/kotlin/.../bpf/programs/`
- **GenerateBpf.kt**: Add to programs list + `cOnlyPrograms` set
- **Collectors**: `RedisCollector.kt`, `MysqlCollector.kt` following `HttpCollector` pattern
- **BpfProgramManager**: Add `configureRedisPorts()`, `configureMysqlPorts()`
- **MetricsProperties**: Add to `standard` profile, add port config properties
- **Default ports**: Redis 6379, MySQL 3306 (configurable via properties)

---

## Kernel Requirements

- Minimum kernel: 5.5 (same as HTTP/DNS — needs `bpf_probe_read_kernel`)
- Uses: `bpf_get_current_cgroup_id` (5.3+), `bpf_get_socket_cookie`, `bpf_ktime_get_ns`
