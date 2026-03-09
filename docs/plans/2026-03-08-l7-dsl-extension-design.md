# L7 Protocol DSL Extension Design

> Extend kotlin-ebpf-dsl with buffer read/byte match primitives, then migrate hand-written DNS and HTTP BPF programs to the Kotlin DSL.

## Problem

The existing DNS (`bpf/dns.bpf.c`, 389 lines) and HTTP (`bpf/http.bpf.c`, 530 lines) BPF programs are hand-written C because the kotlin-ebpf-dsl lacks primitives for:

- Reading byte buffers from kernel pointers (`bpf_probe_read` into stack arrays)
- Byte-level access and pattern matching on payload data
- Multi-byte reads with endianness control
- kretprobe program type (needed for recv-side latency tracking)
- Per-CPU arrays for kprobe↔kretprobe data passing
- `bpf_get_socket_cookie()` helper

This means every new L7 protocol requires 300-500 lines of hand-written C. By extending the DSL, future protocols (MySQL, Redis, PostgreSQL, gRPC) become ~50-100 line Kotlin files.

## New DSL Primitives

### 1. `probeReadBuf(ptr, size)` — Stack buffer read

Reads `size` bytes from a kernel pointer into a stack-allocated buffer.

```kotlin
val buf = probeReadBuf(ptr, 64)
```

Generates:
```c
char __buf_0[64];
__builtin_memset(&__buf_0, 0, sizeof(__buf_0));
bpf_probe_read_kernel(&__buf_0, 64, (void *)ptr);
```

Returns a `BufferHandle` (new type) that supports byte/multi-byte access.

### 2. `BufferHandle.byte(index)` — Single byte access

```kotlin
val methodByte = buf.byte(0)
```

Generates:
```c
((__u8)__buf_0[0])
```

Returns `ExprHandle` with type `BpfScalar.U8`.

### 3. `BufferHandle.u16be(offset)` / `u16le(offset)` / `u32be(offset)` / `u32le(offset)` — Multi-byte read

```kotlin
val port = buf.u16be(0)   // network byte order
val txid = buf.u16be(0)   // DNS transaction ID
val len = buf.u32le(4)    // little-endian length
```

Generates:
```c
__bpf_ntohs(*(__u16 *)&__buf_0[0])   // u16be
(*(__u16 *)&__buf_0[0])               // u16le
__bpf_ntohl(*(__u32 *)&__buf_0[0])    // u32be
(*(__u32 *)&__buf_0[4])               // u32le
```

### 4. `kretprobe(name)` — Return probe program type

```kotlin
kretprobe("udp_recvmsg") {
    val retval = returnValue()  // PT_REGS_RC(ctx)
    // ...
}
```

Generates:
```c
SEC("kretprobe/udp_recvmsg")
int kretprobe_udp_recvmsg(struct pt_regs *ctx) {
    int retval = (int)PT_REGS_RC(ctx);
    // ...
}
```

### 5. `perCpuArray(valueType, maxEntries)` — Per-CPU array map

```kotlin
val stash by perCpuArray(RecvStash, maxEntries = 1)
```

Generates:
```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct recv_stash);
} stash SEC(".maps");
```

Used for kprobe→kretprobe data passing with zero-key lookup.

### 6. `getSocketCookie()` — Socket cookie helper

```kotlin
val cookie = getSocketCookie()
```

Generates:
```c
__u64 cookie = bpf_get_socket_cookie(ctx);
```

Returns `ExprHandle` with type `BpfScalar.U64`.

## Additional DSL Enhancements

### `probeReadUser(ptr, size)` — User-space buffer read

Same as `probeReadBuf` but uses `bpf_probe_read_user` instead of `bpf_probe_read_kernel`. Needed for reading iovec data from user-space buffers.

```kotlin
val payload = probeReadUser(iovBase, 64)
```

### `BufferHandle.slice(offset, size)` — Sub-buffer

For passing a portion of a buffer to further parsing.

```kotlin
val dnsHeader = buf.slice(0, 12)
val qname = buf.slice(12, 32)
```

## Migration: DNS Program

The hand-written `bpf/dns.bpf.c` (389 lines) becomes `DnsProgram.kt`:

### Maps (same as current)

| Map | Type | Key | Value | Max |
|-----|------|-----|-------|-----|
| dns_ports | HASH | PortKey (u16) | PortVal (u8) | 8 |
| dns_requests | LRU_HASH | DnsReqKey (cgroup+qtype) | Counter (u64) | 10240 |
| dns_latency | LRU_HASH | CgroupKey (u64) | HistValue (232B) | 10240 |
| dns_errors | LRU_HASH | DnsErrKey (cgroup+rcode) | Counter (u64) | 10240 |
| dns_domains | LRU_HASH | DnsDomainKey (cgroup+domain[32]) | Counter (u64) | 1024 |
| dns_inflight | LRU_HASH | DnsInflightKey (cgroup+txid) | Timestamp (u64) | 4096 |
| recv_stash | PERCPU_ARRAY | u32 (zero) | RecvStash | 1 |

### Programs

1. **`kprobe/udp_sendmsg`** — Intercept outgoing DNS queries
   - Read destination port from msghdr→msg_name
   - Check port in dns_ports filter
   - Read first 44 bytes of payload via iovec
   - Parse DNS header (txid, flags)
   - Decode QNAME, extract QTYPE
   - Update dns_requests, dns_domains counters
   - Store timestamp in dns_inflight

2. **`kprobe/udp_recvmsg`** — Stash msghdr pointer
   - Save msghdr pointer + cgroup_id in recv_stash per-CPU array

3. **`kretprobe/udp_recvmsg`** — Process DNS responses
   - Read stash, extract source port
   - Read DNS response header
   - Check QR bit (response flag)
   - Lookup dns_inflight by txid for latency
   - Update dns_latency histogram, dns_errors if rcode != 0

## Migration: HTTP Program

The hand-written `bpf/http.bpf.c` (530 lines) becomes `HttpProgram.kt`:

### Maps (same as current)

| Map | Type | Key | Value | Max |
|-----|------|-----|-------|-----|
| http_ports | HASH | PortKey | PortVal | 8 |
| http_events | LRU_HASH | HttpEventKey (cgroup+method+direction+status) | Counter | 10240 |
| http_latency | LRU_HASH | HttpLatKey (cgroup+method+direction) | HistValue | 10240 |
| http_inflight | LRU_HASH | HttpInflightKey (cgroup+cookie) | HttpInflightVal | 8192 |
| http_recv_stash | PERCPU_ARRAY | u32 | RecvStash | 1 |

### Programs

1. **`kprobe/tcp_sendmsg`** — Detect HTTP requests and responses
   - Extract source/dest port from socket
   - Check ports in http_ports filter
   - Read first 16 bytes of payload via iovec (handles ITER_UBUF and ITER_IOVEC)
   - Pattern match HTTP methods (GET, POST, PUT, DELETE, PATCH, HEAD)
   - Pattern match HTTP responses (HTTP/1.x status code)
   - Track inflight requests via socket cookie
   - Update http_events counter, http_latency histogram

2. **`kprobe/tcp_recvmsg`** — Stash for response tracking
3. **`kretprobe/tcp_recvmsg`** — Process received HTTP data

### Kernel Compatibility: ITER_UBUF

HTTP needs to handle two iovec layouts:
- Kernel 6.0+: `ITER_UBUF` — iov embedded in `__ubuf_iovec` union
- Kernel < 6.0: `ITER_IOVEC` — `__iov` is pointer to iovec array

The DSL should support this via conditional compilation or runtime detection. The current hand-written code uses `#ifdef` based on iter_type field.

## Validation Strategy

### Step 1: Structural comparison
- Generate C from DSL programs
- Diff against hand-written C for equivalent logic (maps, programs, control flow)
- Not byte-identical, but functionally equivalent

### Step 2: Unit tests
- Run existing DnsCollector/HttpCollector tests against DSL-generated `.bpf.o`
- All existing tests must pass unchanged

### Step 3: E2E test
- Build Docker image with DSL-generated BPF programs
- Run `e2e/e2e-test.sh` on minikube
- Verify DNS and HTTP metrics appear in Prometheus

## Implementation Order

1. **kotlin-ebpf-dsl**: Add 6+2 primitives (probeReadBuf, probeReadUser, BufferHandle, kretprobe, perCpuArray, getSocketCookie)
2. **kotlin-ebpf-dsl**: Unit tests for code generation of new primitives
3. **kpod-metrics**: Write `DnsProgram.kt` in bpfGenerator
4. **kpod-metrics**: Validate generated C matches dns.bpf.c behavior
5. **kpod-metrics**: Write `HttpProgram.kt` in bpfGenerator
6. **kpod-metrics**: Validate generated C matches http.bpf.c behavior
7. **kpod-metrics**: Update Dockerfile to compile DSL-generated DNS/HTTP
8. **kpod-metrics**: Remove hand-written bpf/dns.bpf.c and bpf/http.bpf.c
9. **kpod-metrics**: E2E verification

## Future Protocols (enabled by this work)

Once the DSL supports buffer reads and byte matching, adding new protocols becomes a Kotlin-only task:

| Protocol | Detection | Key bytes | Complexity |
|----------|-----------|-----------|------------|
| MySQL | COM_* command byte at offset 4 | 1 byte | Low |
| Redis | RESP prefix: `*`, `$`, `+`, `-`, `:` | 1 byte | Low |
| PostgreSQL | Message type byte + 4-byte length | 5 bytes | Low |
| gRPC | HTTP/2 frame header (9 bytes) + `:path` header | Complex | High |
