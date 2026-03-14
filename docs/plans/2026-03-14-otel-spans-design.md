# OpenTelemetry Span Generation from eBPF L7 Events — Design

## Goal

Add runtime-toggleable, sampled OTel span export for HTTP, Redis, and MySQL requests captured by eBPF. Spans are emitted only for slow requests exceeding per-protocol latency thresholds, exported via OTLP, and linked to existing Prometheus metrics via exemplars.

## Decisions

- **Sampled slow-request spans** — not every request, only those exceeding configurable latency thresholds
- **Runtime toggle** — enabled/disabled without redeployment via ConfigMap hot-reload + REST API override
- **Ring buffer** (BPF_MAP_TYPE_RINGBUF, kernel 5.8+) — per-event streaming from BPF to userspace
- **OTLP export + Prometheus exemplars** — spans exported to Tempo/Jaeger, trace_id attached as exemplar to Prometheus histograms
- **HTTP URL path capture** — parsed from existing 128B request line buffer (no increase needed)
- **Per-protocol default thresholds** — HTTP: 200ms, Redis: 10ms, MySQL: 200ms
- **No traceparent extraction** (future follow-up) — spans get kpod-generated trace/span IDs

## Architecture

### Data Flow

```
BPF (kernel)
  tcp_sendmsg / tcp_recvmsg
       │
       ▼
  Request-response matched (existing inflight logic)
       │
       ▼
  Read tracing_config map [0]  ──► disabled? → return (zero overhead)
       │
       ▼ enabled
  latency > threshold?  ──► no → return
       │
       ▼ yes
  Write SpanEvent to ring buffer
       │
       ▼ ring buffer
  JNI Bridge: nativeRingBufPoll()
       │
       ▼
  Kotlin SpanCollector
  - Resolves cgroup_id → pod/namespace
  - Creates OTel Span with attributes
  - Attaches trace_id as exemplar to Prometheus metrics
  - Batches and exports via OTLP
       │
       ▼
  Tempo / Jaeger / OTel Collector
```

### When Tracing is Off (Default)

- BPF: one map lookup returns `enabled=0`, returns immediately (~10ns)
- Kotlin: ring buffer reader thread not started, OTel SDK not initialized
- Zero overhead beyond the config map existing in the BPF object

## BPF Changes

### New Shared Struct: SpanEvent (48 bytes)

```c
struct span_event {
    __u64 ts_ns;          // request start timestamp
    __u64 latency_ns;     // response - request time
    __u64 cgroup_id;      // pod attribution
    __u32 dst_ip;         // destination IPv4
    __u16 dst_port;       // destination port
    __u16 src_port;       // source port
    __u8  protocol;       // 1=HTTP, 2=Redis, 3=MySQL
    __u8  method;         // HTTP method / Redis cmd / MySQL stmt type
    __u16 status_code;    // HTTP status / MySQL error code
    __u8  direction;      // 0=outbound, 1=inbound
    __u8  pad[3];         // alignment
    char  url_path[64];   // HTTP only: first 64 chars of URL path
};
```

### New Config Map: TracingConfig (16 bytes)

```c
struct tracing_config {
    __u32 enabled;        // 0=off, 1=on
    __u32 pad;
    __u64 threshold_ns;   // latency threshold in nanoseconds
};
```

Array map, 1 entry. Written by Kotlin, read by BPF.

### Per L7 Program Changes

Each program (HTTP, Redis, MySQL) gets:

1. `tracing_config` — ARRAY map (1 entry)
2. `span_events` — RINGBUF map (256KB)
3. Span emission logic inserted after existing latency calculation:

```c
struct tracing_config *cfg = bpf_map_lookup_elem(&tracing_config, &zero);
if (cfg && cfg->enabled && latency_ns > cfg->threshold_ns) {
    struct span_event *evt = bpf_ringbuf_reserve(&span_events, sizeof(*evt), 0);
    if (evt) {
        evt->ts_ns = start_ts;
        evt->latency_ns = latency_ns;
        evt->cgroup_id = cgroup_id;
        evt->dst_ip = dst_ip;
        evt->dst_port = dst_port;
        evt->src_port = src_port;
        evt->protocol = PROTO_HTTP; // or PROTO_REDIS, PROTO_MYSQL
        evt->method = method;
        evt->status_code = status_code;
        evt->direction = direction;
        // URL path: HTTP only, parsed from request line
        bpf_ringbuf_submit(evt, 0);
    }
}
```

### HTTP URL Path Extraction

The request line (`GET /api/users HTTP/1.1\r\n`) is already in the 128B capture buffer. Parse: find first space (after method), copy up to 64 chars until next space or `\r`. No buffer size increase needed.

## JNI Bridge Changes

New native functions wrapping libbpf ring buffer API:

```c
// Create ring buffer reader for a map fd
nativeRingBufNew(int mapFd) → long

// Poll ring buffer, return up to maxEvents as byte array (non-blocking)
nativeRingBufPoll(long ringBufPtr, int maxEvents, int eventSize) → byte[]

// Free ring buffer reader
nativeRingBufFree(long ringBufPtr)
```

Wraps `ring_buffer__new()`, `ring_buffer__poll()`, `ring_buffer__free()`.

## Kotlin Components

### SpanCollector

- Dedicated virtual thread, lazy-started on first enable
- Polls ring buffers for HTTP/Redis/MySQL (3 fds)
- Deserializes SpanEvent bytes
- Resolves cgroup_id → pod/namespace via CgroupResolver
- Creates OTel Span:
  - `service.name` = pod name
  - `k8s.namespace.name`, `k8s.pod.name`
  - `http.request.method`, `url.path`, `http.response.status_code` (HTTP)
  - `db.system` = "redis"/"mysql", `db.operation.name` (Redis/MySQL)
  - `network.peer.address`, `network.peer.port`
  - `server.address` or `client.address` based on direction
- Generates random span_id and trace_id (no traceparent extraction)
- Attaches trace_id as exemplar to Prometheus histogram metrics

### TracingConfigManager

- Holds current tracing state per protocol
- Writes tracing_config BPF array map on enable/disable
- Config sources:
  - **REST API**: `POST /actuator/kpodTracing` — immediate, takes precedence
  - **ConfigMap watch**: Spring `@ConfigurationProperties` refresh
- API override resets on pod restart

### TracingProperties

```kotlin
data class TracingProperties(
    val enabled: Boolean = false,
    val http: ProtocolTracingConfig = ProtocolTracingConfig(thresholdMs = 200),
    val redis: ProtocolTracingConfig = ProtocolTracingConfig(thresholdMs = 10),
    val mysql: ProtocolTracingConfig = ProtocolTracingConfig(thresholdMs = 200),
    val otlpEndpoint: String = "",  // empty = reuse otlp.endpoint
    val ringBufferSizeKb: Int = 256
)

data class ProtocolTracingConfig(
    val enabled: Boolean = true,
    val thresholdMs: Long = 100
)
```

## API

```
GET  /actuator/kpodTracing    → current tracing state + source
POST /actuator/kpodTracing    → partial update (e.g., {"enabled": true})
```

Response includes `"source": "configmap" | "api"` to show config origin.

## Helm values.yaml Additions

```yaml
tracing:
  enabled: false
  otlpEndpoint: ""
  ringBufferSizeKb: 256
  http:
    enabled: true
    thresholdMs: 200
  redis:
    enabled: true
    thresholdMs: 10
  mysql:
    enabled: true
    thresholdMs: 200
```

## Kernel Requirements

- Ring buffer requires kernel 5.8+
- Legacy path (4.18-5.7): tracing feature unavailable, metrics still work
- BpfProgramManager detects kernel version and skips ring buffer map creation on older kernels

## Testing

**Unit tests:**
- TracingConfigManager: enable/disable writes correct bytes, API override precedence
- SpanCollector: mock ring buffer → verify OTel span attributes, cgroup resolution
- TracingProperties: config parsing, defaults, partial updates

**E2E test (optional Step 6):**
1. Enable tracing via API
2. Generate slow HTTP traffic exceeding threshold
3. Verify tracing active via GET endpoint
4. Disable via API, verify disabled
5. Span export verification skipped (requires OTel backend)

**BPF overhead:**
- Existing pre-push hook validates overhead
- With tracing disabled, ring buffer write count = 0

## Future Follow-ups

- **traceparent header extraction**: Increase HTTP buffer to 512B, parse W3C trace context, link to existing traces
- **Percentage sampling**: Sample N% of below-threshold requests for baseline visibility
- **gRPC/HTTP2 support**: Multiplexed streams require different correlation strategy
