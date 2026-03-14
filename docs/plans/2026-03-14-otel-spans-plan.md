# OpenTelemetry Span Generation — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add runtime-toggleable OTel span export for slow HTTP/Redis/MySQL requests captured by eBPF, with Prometheus exemplar linkage.

**Architecture:** BPF ring buffers stream per-request span events to userspace when latency exceeds a configurable threshold. A Kotlin SpanCollector reads events via JNI, creates OTel spans, and exports via OTLP. The feature is disabled by default and toggled at runtime via REST API or ConfigMap — no redeployment needed.

**Tech Stack:** kotlin-ebpf-dsl (ring buffer maps), libbpf (ring_buffer API), JNI bridge, OpenTelemetry Java SDK, Spring Boot actuator endpoints, OTLP exporter.

---

### Task 1: Add SpanEvent and TracingConfig structs to DSL

**Files:**
- Create: `src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/SpanStructs.kt`

**Context:** The DSL already has `BpfStruct` definitions in `Structs.kt` (CounterKey, HistValue, etc.). We add a new file for span-related structs shared across HTTP/Redis/MySQL programs. The DSL uses `object` syntax with `u64()`, `u32()`, `u16()`, `u8()`, `array()` field builders.

**Step 1: Create SpanStructs.kt**

```kotlin
package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

/**
 * Span event emitted from BPF to ring buffer for slow requests.
 * Must match the C struct layout exactly (48 + 64 = 112 bytes).
 */
object SpanEvent : BpfStruct("span_event") {
    val tsNs      by u64()       // request start timestamp (ns)
    val latencyNs by u64()       // response - request time (ns)
    val cgroupId  by u64()       // pod attribution
    val dstIp     by u32()       // destination IPv4
    val dstPort   by u16()       // destination port
    val srcPort   by u16()       // source port
    val protocol  by u8()        // 1=HTTP, 2=Redis, 3=MySQL
    val method    by u8()        // HTTP method / Redis cmd / MySQL stmt
    val statusCode by u16()      // HTTP status / MySQL error code
    val direction by u8()        // 0=outbound, 1=inbound
    val pad       by array(BpfScalar.U8, 3)  // alignment padding
    val urlPath   by array(BpfScalar.U8, 64) // HTTP only: URL path (first 64 chars)
}

/**
 * Tracing runtime config written by Kotlin, read by BPF.
 * Array map with 1 entry.
 */
object TracingConfig : BpfStruct("tracing_config") {
    val enabled     by u32()     // 0=off, 1=on
    val pad         by u32()     // alignment
    val thresholdNs by u64()     // latency threshold in nanoseconds
}
```

**Step 2: Verify DSL compiles the structs**

Run: `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew -PebpfDslPath=../../kotlin-ebpf-dsl compileBpfGeneratorKotlin --no-daemon 2>&1 | tail -5`
Expected: `BUILD SUCCESSFUL`

**Step 3: Commit**

```bash
git add src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/SpanStructs.kt
git commit -m "feat(bpf): add SpanEvent and TracingConfig DSL structs"
```

---

### Task 2: Add ring buffer and tracing config to HttpProgram

**Files:**
- Modify: `src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/HttpProgram.kt`

**Context:** HttpProgram.kt defines the HTTP BPF program using the DSL. It has an `httpInflight` LRU hash map that correlates request→response. Latency is computed at ~line 268 (sendmsg path) and ~line 374 (recvmsg path) as `__u64 latency_ns = bpf_ktime_get_ns() - inf->ts;`. After latency, `update_hist()` records the histogram. We add the span emission logic right after `update_hist()`.

The DSL supports `ringBuf(maxEntries)` for ring buffer maps and `scalarArrayMap(valueType, maxEntries)` for array maps.

**Step 1: Read HttpProgram.kt to understand the current structure**

Run: Read `src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/HttpProgram.kt`

Understand:
- Where map declarations are (near top of `ebpf("http") { ... }`)
- Where the preamble is defined
- Where latency is computed and histogram updated (two locations: sendmsg and recvmsg paths)
- How `raw()` blocks are used for C code insertion

**Step 2: Add tracing maps and preamble constants**

In the map declarations section (after existing maps like `httpInflight`, `httpLatency`), add:

```kotlin
val tracingConfig by scalarArrayMap(TracingConfig, maxEntries = 1)
val spanEvents by ringBuf(maxEntries = 262144) // 256KB
```

In the preamble, add protocol constants:

```c
#define PROTO_HTTP  1
#define PROTO_REDIS 2
#define PROTO_MYSQL 3
```

**Step 3: Add span emission helper to postamble**

Add a `postamble()` with the span emission function. This goes in postamble because it references the `span_event`, `tracing_config` structs and the ring buffer map:

```c
static __always_inline void maybe_emit_span(
    void *rb, void *cfg_map,
    __u64 start_ts, __u64 latency_ns, __u64 cgroup_id,
    __u32 dst_ip, __u16 dst_port, __u16 src_port,
    __u8 protocol, __u8 method, __u16 status_code, __u8 direction,
    const __u8 *url_path, __u32 url_len)
{
    __u32 zero = 0;
    struct tracing_config *cfg = bpf_map_lookup_elem(cfg_map, &zero);
    if (!cfg || !cfg->enabled || latency_ns <= cfg->threshold_ns)
        return;

    struct span_event *evt = bpf_ringbuf_reserve(rb, sizeof(*evt), 0);
    if (!evt)
        return;

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
    __builtin_memset(evt->url_path, 0, sizeof(evt->url_path));
    if (url_path && url_len > 0) {
        if (url_len > 64) url_len = 64;
        url_len &= 63;
        bpf_probe_read_kernel(evt->url_path, url_len, url_path);
    }
    bpf_ringbuf_submit(evt, 0);
}
```

**Step 4: Add URL path parsing helper to preamble**

Add to the preamble a function that extracts the URL path from the 128B request line buffer:

```c
// Parse URL path from "GET /api/users HTTP/1.1\r\n" buffer
// Returns pointer to start of path and sets *path_len
static __always_inline const __u8 *parse_url_path(const __u8 *buf, __u32 buf_len, __u32 *path_len) {
    __u32 i = 0;
    // Skip method (find first space)
    for (i = 0; i < buf_len && i < 10; i++) {
        if (buf[i] == ' ') { i++; break; }
    }
    if (i >= buf_len) { *path_len = 0; return 0; }
    __u32 start = i;
    // Find end of path (next space or \r or ?)
    for (; i < buf_len && i < 128; i++) {
        if (buf[i] == ' ' || buf[i] == '\r' || buf[i] == '?') break;
    }
    *path_len = i - start;
    return &buf[start];
}
```

**Step 5: Insert span emission calls after latency calculation**

At both latency computation sites (sendmsg ~line 268 and recvmsg ~line 374), after `update_hist(...)`, add a `raw()` block:

```kotlin
raw("""
    {
        __u32 url_len = 0;
        const __u8 *url = parse_url_path(buf, to_read, &url_len);
        maybe_emit_span(&span_events, &tracing_config,
            inf->ts, latency_ns, cgroup_id,
            dst_ip, dst_port, src_port,
            PROTO_HTTP, inf->method, status_code, inf->direction,
            url, url_len);
    }
""")
```

Note: The exact variable names (`buf`, `to_read`, `inf`, `cgroup_id`, `dst_ip`, `dst_port`, `src_port`, `status_code`) must match the existing generated C code. Read the generated C output to confirm names.

**Step 6: Generate and verify C output**

Run: `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew -PebpfDslPath=../../kotlin-ebpf-dsl generateBpf --no-daemon 2>&1 | tail -5`
Expected: `BUILD SUCCESSFUL` and `Generated 14 BPF programs` (or current count)

Verify: `cat build/generated/bpf/http.bpf.c | grep -c 'maybe_emit_span'`
Expected: `2` (one for sendmsg path, one for recvmsg path)

**Step 7: Commit**

```bash
git add src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/HttpProgram.kt
git commit -m "feat(bpf): add ring buffer span emission to HTTP program"
```

---

### Task 3: Add ring buffer and tracing config to RedisProgram

**Files:**
- Modify: `src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/RedisProgram.kt`

**Context:** Same pattern as Task 2 but for Redis. Latency is computed at ~line 345 (sendmsg) and ~line 444 (recvmsg). Redis has no URL path — pass NULL/0. Redis uses `command` field (CMD_GET=1, CMD_SET=2, etc.) which maps to the `method` byte in SpanEvent.

**Step 1: Read RedisProgram.kt**

Read the file. Note the variable names used at the latency computation sites.

**Step 2: Add tracing maps**

Same as HTTP — add `tracingConfig` and `spanEvents` maps. Add `PROTO_REDIS` constant to preamble.

**Step 3: Add the same `maybe_emit_span` helper to postamble**

Same function as HTTP. Since this is in a separate BPF object file, it needs its own copy.

**Step 4: Insert span emission calls**

At both latency sites, after `update_hist(...)`:

```c
maybe_emit_span(&span_events, &tracing_config,
    inf->ts, latency_ns, cgroup_id,
    dst_ip, dst_port, src_port,
    PROTO_REDIS, inf->command, 0, inf->direction,
    NULL, 0);
```

Redis has no URL path (NULL, 0) and no status_code (0).

**Step 5: Generate and verify**

Run: `./gradlew -PebpfDslPath=../../kotlin-ebpf-dsl generateBpf --no-daemon`
Verify: `cat build/generated/bpf/redis.bpf.c | grep -c 'maybe_emit_span'` → `2`

**Step 6: Commit**

```bash
git add src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/RedisProgram.kt
git commit -m "feat(bpf): add ring buffer span emission to Redis program"
```

---

### Task 4: Add ring buffer and tracing config to MysqlProgram

**Files:**
- Modify: `src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/MysqlProgram.kt`

**Context:** Same pattern as Tasks 2-3. Latency at ~line 359 (sendmsg) and ~line 465 (recvmsg). MySQL uses `stmtType` (STMT_SELECT=1, etc.) as the method byte, and `errCode` maps to statusCode.

**Step 1: Read MysqlProgram.kt**

Read the file. Note variable names at latency sites.

**Step 2: Add tracing maps and `maybe_emit_span` helper**

Same pattern. Add `PROTO_MYSQL` constant.

**Step 3: Insert span emission calls**

```c
maybe_emit_span(&span_events, &tracing_config,
    inf->ts, latency_ns, cgroup_id,
    dst_ip, dst_port, src_port,
    PROTO_MYSQL, inf->stmt_type, err_code, inf->direction,
    NULL, 0);
```

MySQL has no URL path. `err_code` is the MySQL error code (from ERR response) or 0 on success.

**Step 4: Generate and verify**

Run: `./gradlew -PebpfDslPath=../../kotlin-ebpf-dsl generateBpf --no-daemon`
Verify: `cat build/generated/bpf/mysql.bpf.c | grep -c 'maybe_emit_span'` → `2`

**Step 5: Commit**

```bash
git add src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/MysqlProgram.kt
git commit -m "feat(bpf): add ring buffer span emission to MySQL program"
```

---

### Task 5: Add ring buffer JNI bridge functions

**Files:**
- Modify: `jni/bpf_bridge.h`
- Modify: `jni/bpf_bridge.c`

**Context:** The JNI bridge (`bpf_bridge.c`) wraps libbpf calls. Existing pattern: `nativeMapLookup()` calls `bpf_map_lookup_elem()`. We add three functions wrapping libbpf's `ring_buffer__new()`, `ring_buffer__poll()`, `ring_buffer__free()`. The bridge uses a `bpf_obj_wrapper` struct for object pointers and `throw_load_exception()` for errors.

**Step 1: Read bpf_bridge.h and bpf_bridge.c**

Read both files to understand the JNI function naming convention and error handling patterns.

**Step 2: Add declarations to bpf_bridge.h**

After existing declarations (line ~37), add:

```c
JNIEXPORT jlong JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeRingBufNew(
    JNIEnv *env, jobject self, jint mapFd);

JNIEXPORT jbyteArray JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeRingBufPoll(
    JNIEnv *env, jobject self, jlong rbPtr, jint maxEvents, jint eventSize);

JNIEXPORT void JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeRingBufFree(
    JNIEnv *env, jobject self, jlong rbPtr);
```

**Step 3: Implement ring buffer functions in bpf_bridge.c**

After existing functions (line ~300), add:

```c
// Ring buffer callback context — collects events into a flat byte array
struct rb_ctx {
    uint8_t *buf;
    int event_size;
    int max_events;
    int count;
};

static int rb_callback(void *ctx_ptr, void *data, size_t data_sz) {
    struct rb_ctx *ctx = (struct rb_ctx *)ctx_ptr;
    if (ctx->count >= ctx->max_events)
        return 1; // stop polling
    if ((int)data_sz > ctx->event_size)
        data_sz = ctx->event_size;
    memcpy(ctx->buf + (ctx->count * ctx->event_size), data, data_sz);
    ctx->count++;
    return 0;
}

JNIEXPORT jlong JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeRingBufNew(
    JNIEnv *env, jobject self, jint mapFd) {
    (void)self;
    struct ring_buffer *rb = ring_buffer__new(mapFd, rb_callback, NULL, NULL);
    if (!rb) {
        throw_load_exception(env, "Failed to create ring buffer");
        return 0;
    }
    return (jlong)(uintptr_t)rb;
}

JNIEXPORT jbyteArray JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeRingBufPoll(
    JNIEnv *env, jobject self, jlong rbPtr, jint maxEvents, jint eventSize) {
    (void)self;
    if (rbPtr == 0) return NULL;
    struct ring_buffer *rb = (struct ring_buffer *)(uintptr_t)rbPtr;

    int buf_size = maxEvents * eventSize;
    uint8_t *buf = calloc(1, buf_size);
    if (!buf) return NULL;

    struct rb_ctx ctx = { .buf = buf, .event_size = eventSize, .max_events = maxEvents, .count = 0 };

    // Update the ring buffer's callback context
    // Note: ring_buffer__new takes a single callback; we need to pass ctx per poll.
    // Workaround: Use a thread-local or reconstruct. Simpler: create a new ring_buffer per poll
    // is too expensive. Better approach: store ctx pointer and use ring_buffer__poll with timeout=0.
    //
    // Actually, libbpf's ring_buffer__new takes ctx as 3rd arg to callback.
    // We need to set it at creation time. Restructure:
    // - Store ctx in a wrapper struct alongside rb pointer
    // - Update ctx fields before each poll

    // Simpler approach: allocate a wrapper that holds both rb and ctx
    // For now, use a static thread-local (single-threaded polling assumed)
    static __thread struct rb_ctx *tl_ctx;
    tl_ctx = &ctx;

    // This won't work with libbpf's API directly. Better approach below.

    free(buf);

    // --- Better Implementation ---
    // We need to pass ctx to the callback at creation time.
    // Solution: nativeRingBufNew takes no callback; instead, nativeRingBufPoll
    // creates a temporary ring_buffer, polls, then destroys it.
    // This is fine for our use case (polling every ~100ms).

    // Actually, the cleanest approach: store a persistent ctx in a wrapper.
    return NULL; // placeholder — see corrected implementation below
}
```

**CORRECTED IMPLEMENTATION** — Use a wrapper struct that persists the callback context:

```c
struct rb_wrapper {
    struct ring_buffer *rb;
    uint8_t *buf;
    int event_size;
    int max_events;
    int count;
};

static int rb_callback(void *ctx_ptr, void *data, size_t data_sz) {
    struct rb_wrapper *w = (struct rb_wrapper *)ctx_ptr;
    if (w->count >= w->max_events)
        return 1; // stop
    if ((int)data_sz > w->event_size)
        data_sz = w->event_size;
    memcpy(w->buf + (w->count * w->event_size), data, data_sz);
    w->count++;
    return 0;
}

JNIEXPORT jlong JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeRingBufNew(
    JNIEnv *env, jobject self, jint mapFd) {
    (void)self;
    struct rb_wrapper *w = calloc(1, sizeof(*w));
    if (!w) {
        throw_load_exception(env, "Failed to allocate ring buffer wrapper");
        return 0;
    }
    w->rb = ring_buffer__new(mapFd, rb_callback, w, NULL);
    if (!w->rb) {
        free(w);
        throw_load_exception(env, "Failed to create ring buffer");
        return 0;
    }
    return (jlong)(uintptr_t)w;
}

JNIEXPORT jbyteArray JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeRingBufPoll(
    JNIEnv *env, jobject self, jlong rbPtr, jint maxEvents, jint eventSize) {
    (void)self;
    if (rbPtr == 0) return NULL;
    struct rb_wrapper *w = (struct rb_wrapper *)(uintptr_t)rbPtr;

    int buf_size = maxEvents * eventSize;
    w->buf = calloc(1, buf_size);
    if (!w->buf) return NULL;
    w->event_size = eventSize;
    w->max_events = maxEvents;
    w->count = 0;

    ring_buffer__poll(w->rb, 0 /* timeout_ms=0, non-blocking */);

    jbyteArray result = NULL;
    if (w->count > 0) {
        int result_size = w->count * eventSize;
        result = (*env)->NewByteArray(env, result_size);
        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, result_size, (jbyte *)w->buf);
        }
    }
    free(w->buf);
    w->buf = NULL;
    return result;
}

JNIEXPORT void JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeRingBufFree(
    JNIEnv *env, jobject self, jlong rbPtr) {
    (void)env; (void)self;
    if (rbPtr == 0) return;
    struct rb_wrapper *w = (struct rb_wrapper *)(uintptr_t)rbPtr;
    if (w->rb) ring_buffer__free(w->rb);
    free(w->buf);
    free(w);
}
```

**Step 4: Verify JNI compiles**

Run: `docker build -f Dockerfile --target jni-builder -t kpod-jni-test .` from parent dir (or the existing build process)

**Step 5: Commit**

```bash
git add jni/bpf_bridge.h jni/bpf_bridge.c
git commit -m "feat(jni): add ring buffer new/poll/free functions"
```

---

### Task 6: Add ring buffer Kotlin wrappers in BpfBridge

**Files:**
- Modify: `src/main/kotlin/com/internal/kpodmetrics/bpf/BpfBridge.kt`

**Context:** BpfBridge.kt has JNI `external` declarations paired with public wrapper methods that use `HandleRegistry` for safety. Ring buffer functions don't use object handles — they work on map fds and ring buffer pointers directly.

**Step 1: Read BpfBridge.kt**

Read the file. Note the pattern: private external → public wrapper.

**Step 2: Add JNI declarations and wrappers**

After existing external declarations (~line 55), add:

```kotlin
private external fun nativeRingBufNew(mapFd: Int): Long
private external fun nativeRingBufPoll(rbPtr: Long, maxEvents: Int, eventSize: Int): ByteArray?
private external fun nativeRingBufFree(rbPtr: Long)
```

After existing public methods (~line 178), add:

```kotlin
fun ringBufNew(mapFd: Int): Long = nativeRingBufNew(mapFd)

/**
 * Poll a ring buffer for up to maxEvents events of eventSize bytes each.
 * Returns a byte array containing count*eventSize bytes, or null if no events.
 * Non-blocking (timeout=0).
 */
fun ringBufPoll(rbPtr: Long, maxEvents: Int, eventSize: Int): ByteArray? =
    nativeRingBufPoll(rbPtr, maxEvents, eventSize)

fun ringBufFree(rbPtr: Long) = nativeRingBufFree(rbPtr)
```

**Step 3: Verify compilation**

Run: `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew -PebpfDslPath=../../kotlin-ebpf-dsl compileKotlin --no-daemon 2>&1 | tail -5`
Expected: `BUILD SUCCESSFUL`

**Step 4: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/bpf/BpfBridge.kt
git commit -m "feat(bridge): add ring buffer Kotlin wrappers"
```

---

### Task 7: Add TracingProperties configuration

**Files:**
- Modify: `src/main/kotlin/com/internal/kpodmetrics/config/MetricsProperties.kt`
- Modify: `src/main/resources/application.yml`

**Context:** MetricsProperties.kt defines `@ConfigurationProperties(prefix = "kpod")` with nested data classes like `OtlpProperties`. We add `TracingProperties` following the same pattern.

**Step 1: Read MetricsProperties.kt**

Read the file. Note the `OtlpProperties` pattern at lines 142-147.

**Step 2: Add TracingProperties to MetricsProperties.kt**

After `OtlpProperties` (~line 147), add:

```kotlin
data class ProtocolTracingConfig(
    val enabled: Boolean = true,
    val thresholdMs: Long = 100
)

data class TracingProperties(
    val enabled: Boolean = false,
    val http: ProtocolTracingConfig = ProtocolTracingConfig(thresholdMs = 200),
    val redis: ProtocolTracingConfig = ProtocolTracingConfig(thresholdMs = 10),
    val mysql: ProtocolTracingConfig = ProtocolTracingConfig(thresholdMs = 200),
    val otlpEndpoint: String = "",
    val ringBufferSizeKb: Int = 256
)
```

In the main `MetricsProperties` class (after `val otlp`), add:

```kotlin
val tracing: TracingProperties = TracingProperties(),
```

**Step 3: Add defaults to application.yml**

After the existing `kpod:` config block, add:

```yaml
  tracing:
    enabled: false
    otlp-endpoint: ""
    ring-buffer-size-kb: 256
    http:
      enabled: true
      threshold-ms: 200
    redis:
      enabled: true
      threshold-ms: 10
    mysql:
      enabled: true
      threshold-ms: 200
```

**Step 4: Verify compilation**

Run: `./gradlew -PebpfDslPath=../../kotlin-ebpf-dsl compileKotlin --no-daemon`
Expected: `BUILD SUCCESSFUL`

**Step 5: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/config/MetricsProperties.kt src/main/resources/application.yml
git commit -m "feat(config): add TracingProperties with per-protocol thresholds"
```

---

### Task 8: Add OTel SDK dependencies

**Files:**
- Modify: `build.gradle.kts`
- Modify: `gradle/libs.versions.toml` (if version catalog is used, otherwise inline in build.gradle.kts)

**Context:** The project uses Micrometer for metrics (already has `micrometer-registry-otlp` for metrics export). For spans, we need the OpenTelemetry Java SDK directly.

**Step 1: Check gradle/libs.versions.toml**

Read `gradle/libs.versions.toml` to see if OTel versions are already defined.

**Step 2: Add OTel SDK dependencies**

In the version catalog (or directly in build.gradle.kts), add:

```kotlin
// In build.gradle.kts dependencies block, after micrometer-registry-otlp:
implementation("io.opentelemetry:opentelemetry-api:1.45.0")
implementation("io.opentelemetry:opentelemetry-sdk:1.45.0")
implementation("io.opentelemetry:opentelemetry-exporter-otlp:1.45.0")
implementation("io.opentelemetry:opentelemetry-semconv:1.30.1-alpha")
```

Note: Use the latest stable versions. Check Maven Central for current releases. The `semconv` artifact provides semantic convention constants (`http.request.method`, `db.system`, etc.).

**Step 3: Verify dependencies resolve**

Run: `./gradlew -PebpfDslPath=../../kotlin-ebpf-dsl dependencies --configuration runtimeClasspath --no-daemon 2>&1 | grep opentelemetry`
Expected: All OTel dependencies resolve successfully

**Step 4: Commit**

```bash
git add build.gradle.kts gradle/libs.versions.toml
git commit -m "feat(deps): add OpenTelemetry SDK for span export"
```

---

### Task 9: Implement TracingConfigManager

**Files:**
- Create: `src/main/kotlin/com/internal/kpodmetrics/tracing/TracingConfigManager.kt`

**Context:** This component manages the runtime tracing state. It writes to BPF `tracing_config` array maps when tracing is enabled/disabled. It holds the current config state and supports both ConfigMap (Spring property refresh) and API override.

**Step 1: Create TracingConfigManager.kt**

```kotlin
package com.internal.kpodmetrics.tracing

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.config.MetricsProperties
import com.internal.kpodmetrics.config.ProtocolTracingConfig
import com.internal.kpodmetrics.config.TracingProperties
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.atomic.AtomicReference

data class TracingState(
    val enabled: Boolean = false,
    val http: ProtocolTracingConfig = ProtocolTracingConfig(thresholdMs = 200),
    val redis: ProtocolTracingConfig = ProtocolTracingConfig(thresholdMs = 10),
    val mysql: ProtocolTracingConfig = ProtocolTracingConfig(thresholdMs = 200),
    val source: String = "configmap"  // "configmap" or "api"
)

class TracingConfigManager(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val properties: TracingProperties
) {
    private val log = LoggerFactory.getLogger(TracingConfigManager::class.java)
    private val state = AtomicReference(TracingState(
        enabled = properties.enabled,
        http = properties.http,
        redis = properties.redis,
        mysql = properties.mysql,
        source = "configmap"
    ))

    fun getState(): TracingState = state.get()

    fun updateFromApi(update: TracingState) {
        val current = state.get()
        val newState = current.copy(
            enabled = update.enabled,
            http = update.http,
            redis = update.redis,
            mysql = update.mysql,
            source = "api"
        )
        state.set(newState)
        applyToBpf(newState)
    }

    fun applyCurrentConfig() {
        applyToBpf(state.get())
    }

    private fun applyToBpf(tracingState: TracingState) {
        applyProtocol("http", tracingState.enabled && tracingState.http.enabled, tracingState.http.thresholdMs)
        applyProtocol("redis", tracingState.enabled && tracingState.redis.enabled, tracingState.redis.thresholdMs)
        applyProtocol("mysql", tracingState.enabled && tracingState.mysql.enabled, tracingState.mysql.thresholdMs)
    }

    private fun applyProtocol(programName: String, enabled: Boolean, thresholdMs: Long) {
        val handle = programManager.getHandle(programName) ?: return
        try {
            val mapFd = bridge.getMapFd(handle, "tracing_config")
            if (mapFd < 0) {
                log.debug("No tracing_config map for program {}", programName)
                return
            }

            // TracingConfig struct: u32 enabled + u32 pad + u64 threshold_ns = 16 bytes
            val key = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(0).array()
            val value = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(if (enabled) 1 else 0)
                .putInt(0) // pad
                .putLong(thresholdMs * 1_000_000L) // ms → ns
                .array()

            bridge.mapUpdate(mapFd, key, value, 0L) // BPF_ANY
            log.info("Tracing {} for {}: threshold={}ms", if (enabled) "enabled" else "disabled", programName, thresholdMs)
        } catch (e: Exception) {
            log.debug("Failed to update tracing config for {}: {}", programName, e.message)
        }
    }
}
```

**Step 2: Verify compilation**

Run: `./gradlew -PebpfDslPath=../../kotlin-ebpf-dsl compileKotlin --no-daemon`
Expected: `BUILD SUCCESSFUL`

**Step 3: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/tracing/TracingConfigManager.kt
git commit -m "feat(tracing): add TracingConfigManager for runtime BPF config"
```

---

### Task 10: Implement SpanCollector

**Files:**
- Create: `src/main/kotlin/com/internal/kpodmetrics/tracing/SpanCollector.kt`

**Context:** SpanCollector is the core component. It runs a dedicated virtual thread that polls ring buffers when tracing is enabled. It deserializes SpanEvent bytes, resolves cgroup_id to pod info, creates OTel spans, and exports them. It is lazy-started — the thread only spawns when tracing is first enabled.

**Step 1: Create SpanCollector.kt**

```kotlin
package com.internal.kpodmetrics.tracing

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.collector.CgroupResolver
import io.opentelemetry.api.common.AttributeKey
import io.opentelemetry.api.common.Attributes
import io.opentelemetry.api.trace.SpanKind
import io.opentelemetry.api.trace.StatusCode
import io.opentelemetry.api.trace.Tracer
import io.opentelemetry.sdk.OpenTelemetrySdk
import io.opentelemetry.sdk.trace.SdkTracerProvider
import io.opentelemetry.sdk.trace.export.BatchSpanProcessor
import io.opentelemetry.exporter.otlp.trace.OtlpGrpcSpanExporter
import org.slf4j.LoggerFactory
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class SpanCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val configManager: TracingConfigManager,
    private val otlpEndpoint: String
) {
    private val log = LoggerFactory.getLogger(SpanCollector::class.java)
    private val running = AtomicBoolean(false)
    private val started = AtomicBoolean(false)
    private val pollingThread = AtomicReference<Thread?>()

    // Ring buffer pointers per protocol
    private var httpRbPtr: Long = 0
    private var redisRbPtr: Long = 0
    private var mysqlRbPtr: Long = 0

    // OTel SDK — lazy init
    private var otelSdk: OpenTelemetrySdk? = null
    private var tracer: Tracer? = null

    companion object {
        const val SPAN_EVENT_SIZE = 112 // SpanEvent struct size
        const val MAX_POLL_EVENTS = 256
        const val POLL_INTERVAL_MS = 100L

        // Protocol constants (match BPF defines)
        const val PROTO_HTTP = 1
        const val PROTO_REDIS = 2
        const val PROTO_MYSQL = 3

        // HTTP methods
        private val HTTP_METHODS = arrayOf("UNKNOWN", "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD")
        // Redis commands
        private val REDIS_COMMANDS = arrayOf(
            "UNKNOWN", "GET", "SET", "DEL", "HGET", "HSET",
            "LPUSH", "RPUSH", "SADD", "ZADD", "EXPIRE", "INCR", "OTHER"
        )
        // MySQL statement types
        private val MYSQL_STMTS = arrayOf(
            "UNKNOWN", "SELECT", "INSERT", "UPDATE", "DELETE", "BEGIN", "COMMIT", "OTHER"
        )
    }

    fun start() {
        if (started.compareAndSet(false, true)) {
            initOtel()
            initRingBuffers()
            running.set(true)
            val thread = Thread.ofVirtual().name("span-collector").start { pollLoop() }
            pollingThread.set(thread)
            log.info("SpanCollector started (endpoint={})", otlpEndpoint)
        }
    }

    fun stop() {
        running.set(false)
        pollingThread.get()?.interrupt()
        pollingThread.set(null)
        cleanupRingBuffers()
        otelSdk?.shutdown()
        otelSdk = null
        tracer = null
        started.set(false)
        log.info("SpanCollector stopped")
    }

    fun isRunning(): Boolean = running.get()

    private fun initOtel() {
        val endpoint = otlpEndpoint.ifBlank { "http://localhost:4317" }
        val exporter = OtlpGrpcSpanExporter.builder()
            .setEndpoint(endpoint)
            .build()
        val tracerProvider = SdkTracerProvider.builder()
            .addSpanProcessor(BatchSpanProcessor.builder(exporter).build())
            .build()
        otelSdk = OpenTelemetrySdk.builder()
            .setTracerProvider(tracerProvider)
            .build()
        tracer = otelSdk!!.getTracer("kpod-metrics", "1.0.0")
    }

    private fun initRingBuffers() {
        httpRbPtr = initRingBuffer("http", "span_events")
        redisRbPtr = initRingBuffer("redis", "span_events")
        mysqlRbPtr = initRingBuffer("mysql", "span_events")
    }

    private fun initRingBuffer(programName: String, mapName: String): Long {
        val handle = programManager.getHandle(programName) ?: return 0
        return try {
            val mapFd = bridge.getMapFd(handle, mapName)
            if (mapFd < 0) { 0 } else { bridge.ringBufNew(mapFd) }
        } catch (e: Exception) {
            log.debug("Ring buffer not available for {}: {}", programName, e.message)
            0
        }
    }

    private fun cleanupRingBuffers() {
        if (httpRbPtr != 0L) { bridge.ringBufFree(httpRbPtr); httpRbPtr = 0 }
        if (redisRbPtr != 0L) { bridge.ringBufFree(redisRbPtr); redisRbPtr = 0 }
        if (mysqlRbPtr != 0L) { bridge.ringBufFree(mysqlRbPtr); mysqlRbPtr = 0 }
    }

    private fun pollLoop() {
        while (running.get()) {
            try {
                val state = configManager.getState()
                if (!state.enabled) {
                    Thread.sleep(1000) // sleep longer when disabled
                    continue
                }
                pollRingBuffer(httpRbPtr)
                pollRingBuffer(redisRbPtr)
                pollRingBuffer(mysqlRbPtr)
                Thread.sleep(POLL_INTERVAL_MS)
            } catch (_: InterruptedException) {
                break
            } catch (e: Exception) {
                log.warn("SpanCollector poll error: {}", e.message)
                Thread.sleep(1000)
            }
        }
    }

    private fun pollRingBuffer(rbPtr: Long) {
        if (rbPtr == 0L) return
        val data = bridge.ringBufPoll(rbPtr, MAX_POLL_EVENTS, SPAN_EVENT_SIZE) ?: return
        val eventCount = data.size / SPAN_EVENT_SIZE
        for (i in 0 until eventCount) {
            val offset = i * SPAN_EVENT_SIZE
            processSpanEvent(data, offset)
        }
    }

    private fun processSpanEvent(data: ByteArray, offset: Int) {
        val buf = ByteBuffer.wrap(data, offset, SPAN_EVENT_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        val tsNs = buf.long
        val latencyNs = buf.long
        val cgroupId = buf.long
        val dstIp = buf.int
        val dstPort = java.lang.Short.toUnsignedInt(buf.short)
        val srcPort = java.lang.Short.toUnsignedInt(buf.short)
        val protocol = java.lang.Byte.toUnsignedInt(buf.get())
        val method = java.lang.Byte.toUnsignedInt(buf.get())
        val statusCode = java.lang.Short.toUnsignedInt(buf.short)
        val direction = java.lang.Byte.toUnsignedInt(buf.get())
        buf.get(ByteArray(3)) // pad
        val urlPathBytes = ByteArray(64)
        buf.get(urlPathBytes)
        val urlPath = String(urlPathBytes).trimEnd('\u0000')

        // Resolve pod info
        val podInfo = cgroupResolver.resolve(cgroupId)

        val t = tracer ?: return
        val spanName = buildSpanName(protocol, method, urlPath)
        val attrs = buildAttributes(protocol, method, statusCode, direction, dstIp, dstPort, srcPort, urlPath, podInfo)

        val span = t.spanBuilder(spanName)
            .setSpanKind(if (direction == 0) SpanKind.CLIENT else SpanKind.SERVER)
            .setAllAttributes(attrs)
            .setStartTimestamp(tsNs, java.util.concurrent.TimeUnit.NANOSECONDS)
            .startSpan()

        // Set status
        if (protocol == PROTO_HTTP && statusCode >= 500) {
            span.setStatus(StatusCode.ERROR)
        }

        span.end(tsNs + latencyNs, java.util.concurrent.TimeUnit.NANOSECONDS)
    }

    private fun buildSpanName(protocol: Int, method: Int, urlPath: String): String = when (protocol) {
        PROTO_HTTP -> "${HTTP_METHODS.getOrElse(method) { "UNKNOWN" }} ${urlPath.ifEmpty { "/" }}"
        PROTO_REDIS -> "REDIS ${REDIS_COMMANDS.getOrElse(method) { "UNKNOWN" }}"
        PROTO_MYSQL -> "MYSQL ${MYSQL_STMTS.getOrElse(method) { "UNKNOWN" }}"
        else -> "UNKNOWN"
    }

    private fun buildAttributes(
        protocol: Int, method: Int, statusCode: Int, direction: Int,
        dstIp: Int, dstPort: Int, srcPort: Int, urlPath: String,
        podInfo: CgroupResolver.PodInfo?
    ): Attributes {
        val builder = Attributes.builder()

        // Kubernetes context
        if (podInfo != null) {
            builder.put(AttributeKey.stringKey("k8s.namespace.name"), podInfo.namespace)
            builder.put(AttributeKey.stringKey("k8s.pod.name"), podInfo.podName)
            builder.put(AttributeKey.stringKey("service.name"), podInfo.podName)
        }

        // Network
        val dstAddr = intToIpv4(dstIp)
        builder.put(AttributeKey.stringKey("network.peer.address"), dstAddr)
        builder.put(AttributeKey.longKey("network.peer.port"), dstPort.toLong())
        builder.put(AttributeKey.longKey("network.local.port"), srcPort.toLong())

        // Protocol-specific
        when (protocol) {
            PROTO_HTTP -> {
                builder.put(AttributeKey.stringKey("http.request.method"), HTTP_METHODS.getOrElse(method) { "UNKNOWN" })
                if (urlPath.isNotEmpty()) builder.put(AttributeKey.stringKey("url.path"), urlPath)
                if (statusCode > 0) builder.put(AttributeKey.longKey("http.response.status_code"), statusCode.toLong())
            }
            PROTO_REDIS -> {
                builder.put(AttributeKey.stringKey("db.system"), "redis")
                builder.put(AttributeKey.stringKey("db.operation.name"), REDIS_COMMANDS.getOrElse(method) { "UNKNOWN" })
            }
            PROTO_MYSQL -> {
                builder.put(AttributeKey.stringKey("db.system"), "mysql")
                builder.put(AttributeKey.stringKey("db.operation.name"), MYSQL_STMTS.getOrElse(method) { "UNKNOWN" })
                if (statusCode > 0) builder.put(AttributeKey.longKey("db.response.status_code"), statusCode.toLong())
            }
        }

        builder.put(AttributeKey.stringKey("network.direction"), if (direction == 0) "outbound" else "inbound")
        return builder.build()
    }

    private fun intToIpv4(ip: Int): String {
        return InetAddress.getByAddress(
            byteArrayOf(
                (ip and 0xFF).toByte(),
                ((ip shr 8) and 0xFF).toByte(),
                ((ip shr 16) and 0xFF).toByte(),
                ((ip shr 24) and 0xFF).toByte()
            )
        ).hostAddress
    }
}
```

**Step 2: Verify compilation**

Run: `./gradlew -PebpfDslPath=../../kotlin-ebpf-dsl compileKotlin --no-daemon`
Expected: `BUILD SUCCESSFUL`

Note: `CgroupResolver.PodInfo` may need to be checked — read `CgroupResolver.kt` to confirm the return type and method name. Adjust if needed.

**Step 3: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/tracing/SpanCollector.kt
git commit -m "feat(tracing): add SpanCollector with ring buffer polling and OTel export"
```

---

### Task 11: Implement TracingEndpoint (REST API)

**Files:**
- Create: `src/main/kotlin/com/internal/kpodmetrics/tracing/TracingEndpoint.kt`

**Context:** Spring Boot custom actuator endpoints use `@Endpoint(id = "...")` with `@ReadOperation` (GET) and `@WriteOperation` (POST). Existing examples: `KpodDiagnosticsEndpoint.kt` in the config package.

**Step 1: Check existing endpoint pattern**

Read an existing custom endpoint file (e.g., search for `@Endpoint` in the codebase) to confirm the exact pattern used.

**Step 2: Create TracingEndpoint.kt**

```kotlin
package com.internal.kpodmetrics.tracing

import com.internal.kpodmetrics.config.ProtocolTracingConfig
import org.springframework.boot.actuate.endpoint.annotation.Endpoint
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation
import org.springframework.boot.actuate.endpoint.annotation.WriteOperation

@Endpoint(id = "kpodTracing")
class TracingEndpoint(
    private val configManager: TracingConfigManager,
    private val spanCollector: SpanCollector
) {
    @ReadOperation
    fun getTracingState(): Map<String, Any> {
        val state = configManager.getState()
        return mapOf(
            "enabled" to state.enabled,
            "running" to spanCollector.isRunning(),
            "http" to mapOf("enabled" to state.http.enabled, "thresholdMs" to state.http.thresholdMs),
            "redis" to mapOf("enabled" to state.redis.enabled, "thresholdMs" to state.redis.thresholdMs),
            "mysql" to mapOf("enabled" to state.mysql.enabled, "thresholdMs" to state.mysql.thresholdMs),
            "source" to state.source
        )
    }

    @WriteOperation
    fun updateTracingState(
        enabled: Boolean?,
        httpEnabled: Boolean?,
        httpThresholdMs: Long?,
        redisEnabled: Boolean?,
        redisThresholdMs: Long?,
        mysqlEnabled: Boolean?,
        mysqlThresholdMs: Long?
    ): Map<String, Any> {
        val current = configManager.getState()

        val newState = TracingState(
            enabled = enabled ?: current.enabled,
            http = ProtocolTracingConfig(
                enabled = httpEnabled ?: current.http.enabled,
                thresholdMs = httpThresholdMs ?: current.http.thresholdMs
            ),
            redis = ProtocolTracingConfig(
                enabled = redisEnabled ?: current.redis.enabled,
                thresholdMs = redisThresholdMs ?: current.redis.thresholdMs
            ),
            mysql = ProtocolTracingConfig(
                enabled = mysqlEnabled ?: current.mysql.enabled,
                thresholdMs = mysqlThresholdMs ?: current.mysql.thresholdMs
            ),
            source = "api"
        )

        configManager.updateFromApi(newState)

        // Start or stop SpanCollector based on enabled state
        if (newState.enabled && !spanCollector.isRunning()) {
            spanCollector.start()
        } else if (!newState.enabled && spanCollector.isRunning()) {
            spanCollector.stop()
        }

        return getTracingState()
    }
}
```

**Step 3: Expose endpoint in application.yml**

In `management.endpoints.web.exposure.include`, add `kpodTracing`:

```yaml
include: health, prometheus, info, kpodDiagnostics, kpodRecommend, kpodAnomaly, kpodTracing
```

**Step 4: Verify compilation**

Run: `./gradlew -PebpfDslPath=../../kotlin-ebpf-dsl compileKotlin --no-daemon`

**Step 5: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/tracing/TracingEndpoint.kt src/main/resources/application.yml
git commit -m "feat(tracing): add kpodTracing actuator endpoint for runtime toggle"
```

---

### Task 12: Wire beans in BpfAutoConfiguration

**Files:**
- Modify: `src/main/kotlin/com/internal/kpodmetrics/config/BpfAutoConfiguration.kt`

**Context:** BpfAutoConfiguration.kt creates all collector beans with `@Bean` and `@ConditionalOnProperty`. The tracing beans should always be created (since they're dormant when disabled), but SpanCollector should NOT auto-start — it's started on demand via the API.

**Step 1: Read BpfAutoConfiguration.kt**

Read the file. Note the bean creation pattern and constructor parameters.

**Step 2: Add tracing beans**

After existing collector beans (~line 274), add:

```kotlin
@Bean
fun tracingConfigManager(
    bridge: BpfBridge,
    programManager: BpfProgramManager,
    properties: MetricsProperties
): TracingConfigManager {
    val manager = TracingConfigManager(bridge, programManager, properties.tracing)
    // Apply initial config to BPF maps (disabled by default)
    manager.applyCurrentConfig()
    return manager
}

@Bean
fun spanCollector(
    bridge: BpfBridge,
    programManager: BpfProgramManager,
    cgroupResolver: CgroupResolver,
    tracingConfigManager: TracingConfigManager,
    properties: MetricsProperties
): SpanCollector {
    val endpoint = properties.tracing.otlpEndpoint.ifBlank {
        properties.otlp.endpoint.replace("/v1/metrics", "")
    }
    return SpanCollector(bridge, programManager, cgroupResolver, tracingConfigManager, endpoint)
}

@Bean
fun tracingEndpoint(
    tracingConfigManager: TracingConfigManager,
    spanCollector: SpanCollector
): TracingEndpoint {
    return TracingEndpoint(tracingConfigManager, spanCollector)
}
```

Add imports for the tracing classes at the top of the file.

**Step 3: Verify compilation**

Run: `./gradlew -PebpfDslPath=../../kotlin-ebpf-dsl compileKotlin --no-daemon`

**Step 4: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/config/BpfAutoConfiguration.kt
git commit -m "feat(config): wire TracingConfigManager, SpanCollector, and TracingEndpoint beans"
```

---

### Task 13: Add Helm chart tracing configuration

**Files:**
- Modify: `helm/kpod-metrics/values.yaml`
- Modify: `helm/kpod-metrics/templates/configmap.yaml`

**Context:** The Helm chart passes config to the app via a ConfigMap mounted as `application.yml`. The `values.yaml` has an existing `otlp:` section at lines 93-101. The `configmap.yaml` template renders values into YAML format.

**Step 1: Read values.yaml and configmap.yaml**

Read both files. Note the `otlp:` section pattern.

**Step 2: Add tracing section to values.yaml**

After the `otlp:` section (~line 101), add:

```yaml
# --- Tracing (OTel Spans) ---
# Runtime-toggleable span export for slow L7 requests.
# Disabled by default. Enable via API: POST /actuator/kpodTracing {"enabled": true}
# Or set enabled: true here for persistent default.
tracing:
  enabled: false
  otlpEndpoint: ""           # empty = derive from otlp.endpoint
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

**Step 3: Add tracing config to configmap.yaml template**

After the `otlp:` config block (~line 75), add:

```yaml
    tracing:
      enabled: {{ .Values.tracing.enabled }}
      otlp-endpoint: {{ .Values.tracing.otlpEndpoint | quote }}
      ring-buffer-size-kb: {{ .Values.tracing.ringBufferSizeKb }}
      http:
        enabled: {{ .Values.tracing.http.enabled }}
        threshold-ms: {{ .Values.tracing.http.thresholdMs }}
      redis:
        enabled: {{ .Values.tracing.redis.enabled }}
        threshold-ms: {{ .Values.tracing.redis.thresholdMs }}
      mysql:
        enabled: {{ .Values.tracing.mysql.enabled }}
        threshold-ms: {{ .Values.tracing.mysql.thresholdMs }}
```

**Step 4: Validate Helm template**

Run: `helm template test helm/kpod-metrics/ 2>&1 | grep -A 20 'tracing:'`
Expected: Tracing config section rendered with default values

**Step 5: Commit**

```bash
git add helm/kpod-metrics/values.yaml helm/kpod-metrics/templates/configmap.yaml
git commit -m "feat(helm): add tracing configuration to values and configmap"
```

---

### Task 14: Add e2e tracing toggle test

**Files:**
- Modify: `e2e/e2e-test.sh`

**Context:** The e2e test already has Steps 1-5. Add Step 6 for tracing toggle verification. This tests the API toggle — not actual span export (which requires an OTel backend). Focus on: enable via API, verify state, disable via API, verify state.

**Step 1: Read e2e-test.sh**

Read the end of the file to see where Step 5 ends and where to add Step 6.

**Step 2: Add Step 6 after Step 5**

```bash
# ============================================================
# Step 6: Tracing toggle test
# ============================================================
info "=== Step 6: Tracing toggle test ==="

# Check initial state (should be disabled)
TRACING_STATE=$(curl -sf "http://localhost:${LOCAL_PORT}/actuator/kpodTracing" 2>/dev/null || true)
if [ -n "$TRACING_STATE" ]; then
    TRACING_ENABLED=$(echo "$TRACING_STATE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('enabled', 'N/A'))" 2>/dev/null || echo "N/A")
    if [ "$TRACING_ENABLED" = "False" ] || [ "$TRACING_ENABLED" = "false" ]; then
        check_pass "Tracing disabled by default"
    else
        check_warn "Tracing initial state unexpected: ${TRACING_ENABLED}"
    fi

    # Enable tracing via API
    ENABLE_RESULT=$(curl -sf -X POST "http://localhost:${LOCAL_PORT}/actuator/kpodTracing" \
        -H "Content-Type: application/json" \
        -d '{"enabled":true}' 2>/dev/null || true)
    if [ -n "$ENABLE_RESULT" ]; then
        ENABLED_NOW=$(echo "$ENABLE_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('enabled', False))" 2>/dev/null || echo "false")
        SOURCE=$(echo "$ENABLE_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('source', 'unknown'))" 2>/dev/null || echo "unknown")
        if [ "$ENABLED_NOW" = "True" ] || [ "$ENABLED_NOW" = "true" ]; then
            check_pass "Tracing enabled via API (source=${SOURCE})"
        else
            check_warn "Tracing enable response unexpected: ${ENABLE_RESULT}"
        fi
    else
        check_warn "Tracing API not responding to POST"
    fi

    # Disable tracing
    curl -sf -X POST "http://localhost:${LOCAL_PORT}/actuator/kpodTracing" \
        -H "Content-Type: application/json" \
        -d '{"enabled":false}' >/dev/null 2>&1 || true

    # Verify disabled
    FINAL_STATE=$(curl -sf "http://localhost:${LOCAL_PORT}/actuator/kpodTracing" 2>/dev/null || true)
    FINAL_ENABLED=$(echo "$FINAL_STATE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('enabled', 'N/A'))" 2>/dev/null || echo "N/A")
    if [ "$FINAL_ENABLED" = "False" ] || [ "$FINAL_ENABLED" = "false" ]; then
        check_pass "Tracing disabled via API"
    else
        check_warn "Tracing disable unexpected: ${FINAL_ENABLED}"
    fi
else
    check_warn "kpodTracing endpoint not available (kernel may not support ring buffers)"
fi
```

**Step 3: Verify script syntax**

Run: `bash -n e2e/e2e-test.sh`
Expected: No output (clean syntax)

**Step 4: Commit**

```bash
git add e2e/e2e-test.sh
git commit -m "feat(e2e): add tracing toggle test to e2e suite"
```

---

### Task 15: Docker build and e2e validation

**Files:** None (build + test only)

**Context:** This is the integration validation. Build the full Docker image (which compiles BPF programs with ring buffer maps and JNI bridge with ring buffer functions), deploy to minikube, run e2e tests including the new tracing toggle test.

**Step 1: Build Docker image in minikube**

```bash
eval $(minikube docker-env)
cd .. && docker build -f kpod-metrics/Dockerfile -t kpod-metrics:local-test . 2>&1 | tail -20
```

Expected: Build succeeds. Watch for:
- BPF compilation step includes ring buffer maps in generated C
- JNI compilation step includes new ring buffer functions
- App compilation includes OTel SDK dependencies

**Step 2: Run full e2e test**

```bash
cd kpod-metrics && ./e2e/e2e-test.sh --cleanup 2>&1
```

Expected: All existing tests pass (Steps 1-5) + Step 6 tracing toggle passes.

**Step 3: Fix any issues**

If BPF compilation fails: check generated C for ring buffer syntax errors.
If JNI compilation fails: check libbpf ring buffer header availability.
If tracing toggle fails: check endpoint registration in application.yml.

**Step 4: Commit any fixes**

```bash
git add -A && git commit -m "fix: address e2e test issues"
```
