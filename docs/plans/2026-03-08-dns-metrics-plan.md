# DNS Metrics Collector Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a DNS metrics BPF collector that captures per-pod DNS query rate, latency, error rate, and top domains via kprobes on UDP send/recv.

**Architecture:** New `dns` BPF program (kotlin-ebpf-dsl) attaches kprobes to `udp_sendmsg`/`udp_recvmsg`, parses DNS headers in-kernel, stores metrics in LRU_HASH maps keyed by cgroup ID. A new `DnsCollector` reads maps and exports to Micrometer. Multi-port support via a BPF HASH map populated at load time.

**Tech Stack:** kotlin-ebpf-dsl (BPF code generation), libbpf (JNI bridge), Micrometer (metrics), Spring Boot (bean wiring)

**Design doc:** `docs/plans/2026-03-08-dns-metrics-design.md`

---

### Task 1: Add `mapUpdate` to JNI Bridge

BpfProgramManager needs to write DNS port config into BPF maps at load time. No `mapUpdate` exists yet.

**Files:**
- Modify: `jni/bpf_bridge.c` (after line 217, near `nativeMapDelete`)
- Modify: `src/main/kotlin/com/internal/kpodmetrics/bpf/BpfBridge.kt` (after line 89, near `mapDelete`)

**Step 1: Add native C function**

In `jni/bpf_bridge.c`, add after the `nativeMapDelete` function:

```c
JNIEXPORT void JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeMapUpdate(
    JNIEnv *env, jobject obj, jint mapFd, jbyteArray key, jbyteArray value, jlong flags) {
    jsize keyLen = (*env)->GetArrayLength(env, key);
    jsize valLen = (*env)->GetArrayLength(env, value);
    jbyte *keyBuf = (*env)->GetByteArrayElements(env, key, NULL);
    jbyte *valBuf = (*env)->GetByteArrayElements(env, value, NULL);
    if (!keyBuf || !valBuf) {
        if (keyBuf) (*env)->ReleaseByteArrayElements(env, key, keyBuf, JNI_ABORT);
        if (valBuf) (*env)->ReleaseByteArrayElements(env, value, valBuf, JNI_ABORT);
        throwException(env, "Failed to get byte array elements");
        return;
    }
    int err = bpf_map_update_elem(mapFd, keyBuf, valBuf, (unsigned long long)flags);
    (*env)->ReleaseByteArrayElements(env, key, keyBuf, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, value, valBuf, JNI_ABORT);
    if (err) {
        char msg[128];
        snprintf(msg, sizeof(msg), "bpf_map_update_elem failed: %d", err);
        throwException(env, msg);
    }
}
```

**Step 2: Add JNI declaration + Kotlin wrapper in BpfBridge.kt**

Add native declaration (near line 40):
```kotlin
private external fun nativeMapUpdate(mapFd: Int, key: ByteArray, value: ByteArray, flags: Long)
```

Add public wrapper (after `mapDelete` at line 89):
```kotlin
fun mapUpdate(mapFd: Int, key: ByteArray, value: ByteArray, flags: Long = 0L) {
    nativeMapUpdate(mapFd, key, value, flags)
}
```

**Step 3: Commit**

```bash
git add jni/bpf_bridge.c src/main/kotlin/com/internal/kpodmetrics/bpf/BpfBridge.kt
git commit -m "feat: add mapUpdate to BpfBridge JNI interface"
```

---

### Task 2: Add DNS Structs to Structs.kt

**Files:**
- Modify: `src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/Structs.kt` (append after HistValue)

**Step 1: Add DNS-specific structs**

Append after `HistValue` (line 22):

```kotlin
object DnsReqKey : BpfStruct("dns_req_key") {
    val cgroupId by u64()
    val qtype by u16()
    val pad by u16(cName = "_pad1")
    val pad2 by u32(cName = "_pad2")
}

object DnsErrKey : BpfStruct("dns_err_key") {
    val cgroupId by u64()
    val rcode by u8()
    val pad by array(BpfScalar.U8, 7, cName = "_pad")
}

object DnsDomainKey : BpfStruct("dns_domain_key") {
    val cgroupId by u64()
    val domain by array(BpfScalar.U8, 32)
}

object DnsTxidKey : BpfStruct("dns_txid_key") {
    val cgroupId by u64()
    val txid by u16()
    val pad by u16(cName = "_pad1")
    val pad2 by u32(cName = "_pad2")
}

object DnsPortKey : BpfStruct("dns_port_key") {
    val port by u16()
    val pad by u16(cName = "_pad1")
    val pad2 by u32(cName = "_pad2")
}

object DnsPortValue : BpfStruct("dns_port_value") {
    val enabled by u8()
    val pad by array(BpfScalar.U8, 7, cName = "_pad")
}
```

**Step 2: Verify build**

```bash
cd /Users/jongsu/dev/kpod-metrics
./gradlew compileKotlin -PebpfDslPath=../kotlin-ebpf-dsl 2>&1 | tail -5
```
Expected: BUILD SUCCESSFUL

**Step 3: Commit**

```bash
git add src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/Structs.kt
git commit -m "feat: add DNS BPF struct definitions"
```

---

### Task 3: Create DnsProgram.kt (BPF Program Definition)

This is the most complex task — defining the eBPF program using kotlin-ebpf-dsl.

**Files:**
- Create: `src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/DnsProgram.kt`

**Step 1: Create the DNS BPF program**

```kotlin
package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

/**
 * Per-CPU stash for udp_recvmsg kprobe -> kretprobe data passing.
 * Stores the msghdr pointer so kretprobe can extract source port.
 */
object RecvStash : BpfStruct("recv_stash") {
    val msghdrPtr by u64()
    val cgroupId by u64()
}

/**
 * Timestamp value for inflight tracking.
 */
object TsValue : BpfStruct("ts_value") {
    val ts by u64()
}

val DNS_PREAMBLE = """
#include <linux/types.h>

// DNS header is 12 bytes
struct dns_header {
    __u16 txid;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

#define DNS_QR_MASK   0x8000  // Query/Response bit (network byte order comparison done after ntohs)
#define DNS_RCODE_MASK 0x000F

#define MAX_QNAME_LEN 32

// Helper: decode DNS label-encoded QNAME into dotted notation (truncated to MAX_QNAME_LEN)
// Returns offset past QNAME (points to qtype field) or -1 on error
static __always_inline int decode_qname(const __u8 *pkt, int offset, int pkt_len, __u8 *out) {
    int out_pos = 0;
    #pragma unroll
    for (int i = 0; i < 16; i++) {  // max 16 labels
        if (offset >= pkt_len) return -1;
        __u8 label_len = pkt[offset];
        if (label_len == 0) {
            offset++;  // skip null terminator
            break;
        }
        if (label_len > 63) return -1;  // pointer or invalid
        offset++;
        #pragma unroll
        for (int j = 0; j < 63; j++) {
            if (j >= label_len) break;
            if (offset >= pkt_len) return -1;
            if (out_pos < MAX_QNAME_LEN - 1) {
                out[out_pos++] = pkt[offset];
            }
            offset++;
        }
        if (out_pos < MAX_QNAME_LEN - 1) {
            out[out_pos++] = '.';
        }
    }
    // Remove trailing dot
    if (out_pos > 0 && out[out_pos - 1] == '.') out_pos--;
    // Null-terminate
    if (out_pos < MAX_QNAME_LEN) out[out_pos] = 0;
    return offset;
}
""".trimIndent()

/**
 * DSL definition for the dns BPF program.
 *
 * Maps:
 *   - dns_ports:     HASH, key=dns_port_key, value=dns_port_value (port filter, populated from userspace)
 *   - dns_requests:  LRU_HASH, key=dns_req_key, value=counter_value (query count by qtype)
 *   - dns_latency:   LRU_HASH, key=hist_key, value=hist_value (latency histogram)
 *   - dns_errors:    LRU_HASH, key=dns_err_key, value=counter_value (error count by rcode)
 *   - dns_domains:   LRU_HASH, key=dns_domain_key, value=counter_value (per-domain count)
 *   - dns_inflight:  LRU_HASH, key=dns_txid_key, value=ts_value (request timestamp for latency)
 *   - recv_stash_map: PERCPU_ARRAY, key=u32, value=recv_stash (kprobe->kretprobe stash)
 *
 * Programs:
 *   - kprobe/udp_sendmsg:    parse outgoing DNS query, record timestamp + counters
 *   - kprobe/udp_recvmsg:    stash msghdr pointer for kretprobe
 *   - kretprobe/udp_recvmsg: parse incoming DNS response, compute latency, record errors
 *
 * The actual BPF C logic uses raw() blocks because DNS packet parsing requires
 * complex pointer arithmetic that exceeds the DSL's current abstraction level.
 * The DSL is used for map/struct definitions and program scaffolding.
 */
val dnsProgram = ebpf("dns") {
    license("GPL")
    targetKernel("5.3")

    preamble(
        COMMON_PREAMBLE + "\n\n" + DNS_PREAMBLE +
            "\n\nDEFINE_STATS_MAP(dns_requests)\nDEFINE_STATS_MAP(dns_errors)"
    )

    // ── Maps ────────────────────────────────────────────────────────────
    val dnsPorts by hashMap(DnsPortKey, DnsPortValue, maxEntries = 8)
    val dnsRequests by lruHashMap(DnsReqKey, CounterValue, maxEntries = 10240)
    val dnsLatency by lruHashMap(HistKey, HistValue, maxEntries = 10240)
    val dnsErrors by lruHashMap(DnsErrKey, CounterValue, maxEntries = 10240)
    val dnsDomains by lruHashMap(DnsDomainKey, CounterValue, maxEntries = 1024)
    val dnsInflight by lruHashMap(DnsTxidKey, TsValue, maxEntries = 4096)
    val recvStashMap by percpuArrayMap(BpfScalar.U32, RecvStash, maxEntries = 1)

    // ── Program 1: kprobe/udp_sendmsg ──────────────────────────────────
    // Intercepts outgoing UDP packets, filters by DNS port, parses DNS query
    kprobe("udp_sendmsg") {
        // The DNS parsing logic is complex — use raw C block
        raw("""
        struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
        if (!msg) return 0;

        // Extract destination port from sockaddr
        struct sockaddr_in addr = {};
        bpf_probe_read_user(&addr, sizeof(addr), msg->msg_name);
        __u16 dport = __builtin_bswap16(addr.sin_port);

        // Check if this port is in our DNS ports set
        struct dns_port_key port_key = { .port = dport };
        if (!bpf_map_lookup_elem(&dns_ports, &port_key)) return 0;

        // Read first iov
        struct iovec iov = {};
        bpf_probe_read_user(&iov, sizeof(iov), msg->msg_iov);
        if (iov.iov_len < 17) return 0;  // DNS header(12) + min QNAME(1) + qtype(2) + qclass(2)

        // Read DNS packet (up to 44 bytes: 12 header + 32 QNAME max)
        __u8 pkt[44] = {};
        __u32 read_len = iov.iov_len < 44 ? iov.iov_len : 44;
        bpf_probe_read_user(pkt, read_len, iov.iov_base);

        // Parse DNS header
        struct dns_header *hdr = (struct dns_header *)pkt;
        __u16 txid = hdr->txid;  // keep network byte order for matching
        __u16 flags = __builtin_bswap16(hdr->flags);

        // Skip if this is a response (QR=1)
        if (flags & 0x8000) return 0;

        __u64 cgroup_id = bpf_get_current_cgroup_id();

        // Decode QNAME
        __u8 domain[MAX_QNAME_LEN] = {};
        int qtype_offset = decode_qname(pkt, 12, read_len, domain);

        // Extract qtype if we got a valid QNAME
        __u16 qtype = 0;
        if (qtype_offset > 0 && qtype_offset + 2 <= read_len) {
            qtype = __builtin_bswap16(*(__u16 *)(pkt + qtype_offset));
        }

        // Store inflight timestamp for latency calculation
        struct dns_txid_key txid_key = { .cgroup_id = cgroup_id, .txid = txid };
        struct ts_value ts = { .ts = bpf_ktime_get_ns() };
        bpf_map_update_elem(&dns_inflight, &txid_key, &ts, BPF_ANY);

        // Increment request counter
        struct dns_req_key req_key = { .cgroup_id = cgroup_id, .qtype = qtype };
        struct counter_value *req_val = bpf_map_lookup_elem(&dns_requests, &req_key);
        if (req_val) {
            __sync_fetch_and_add(&req_val->count, 1);
        } else {
            struct counter_value new_val = { .count = 1 };
            bpf_map_update_elem(&dns_requests, &req_key, &new_val, BPF_NOEXIST);
        }

        // Increment domain counter
        struct dns_domain_key dom_key = { .cgroup_id = cgroup_id };
        __builtin_memcpy(dom_key.domain, domain, MAX_QNAME_LEN);
        struct counter_value *dom_val = bpf_map_lookup_elem(&dns_domains, &dom_key);
        if (dom_val) {
            __sync_fetch_and_add(&dom_val->count, 1);
        } else {
            struct counter_value new_dom = { .count = 1 };
            bpf_map_update_elem(&dns_domains, &dom_key, &new_dom, BPF_NOEXIST);
        }

        return 0;
        """.trimIndent(), BpfScalar.S32)
        returnValue(literal(0, BpfScalar.S32))
    }

    // ── Program 2: kprobe/udp_recvmsg ─────────────────────────────────
    // Stash msghdr pointer + cgroup_id for kretprobe
    kprobe("udp_recvmsg") {
        raw("""
        struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
        __u32 key = 0;
        struct recv_stash *stash = bpf_map_lookup_elem(&recv_stash_map, &key);
        if (stash) {
            stash->msghdr_ptr = (__u64)msg;
            stash->cgroup_id = bpf_get_current_cgroup_id();
        }
        return 0;
        """.trimIndent(), BpfScalar.S32)
        returnValue(literal(0, BpfScalar.S32))
    }

    // ── Program 3: kretprobe/udp_recvmsg ──────────────────────────────
    // Parse DNS response, compute latency, record errors
    kretprobe("udp_recvmsg") {
        raw("""
        // Check return value — negative means error
        int ret = PT_REGS_RC(ctx);
        if (ret < 12) return 0;  // need at least DNS header

        __u32 stash_key = 0;
        struct recv_stash *stash = bpf_map_lookup_elem(&recv_stash_map, &stash_key);
        if (!stash || !stash->msghdr_ptr) return 0;

        struct msghdr *msg = (struct msghdr *)stash->msghdr_ptr;
        __u64 cgroup_id = stash->cgroup_id;

        // Extract source port from msg_name (sockaddr)
        struct sockaddr_in addr = {};
        bpf_probe_read_user(&addr, sizeof(addr), msg->msg_name);
        __u16 sport = __builtin_bswap16(addr.sin_port);

        // Check if this port is in our DNS ports set
        struct dns_port_key port_key = { .port = sport };
        if (!bpf_map_lookup_elem(&dns_ports, &port_key)) return 0;

        // Read DNS header from first iov
        struct iovec iov = {};
        bpf_probe_read_user(&iov, sizeof(iov), msg->msg_iov);
        if (iov.iov_len < 12) return 0;

        __u8 hdr_buf[12] = {};
        bpf_probe_read_user(hdr_buf, 12, iov.iov_base);

        struct dns_header *hdr = (struct dns_header *)hdr_buf;
        __u16 txid = hdr->txid;  // network byte order, matches what we stored
        __u16 flags = __builtin_bswap16(hdr->flags);

        // Must be a response (QR=1)
        if (!(flags & 0x8000)) return 0;

        // Compute latency from inflight map
        struct dns_txid_key txid_key = { .cgroup_id = cgroup_id, .txid = txid };
        struct ts_value *start = bpf_map_lookup_elem(&dns_inflight, &txid_key);
        if (start) {
            __u64 latency_ns = bpf_ktime_get_ns() - start->ts;
            bpf_map_delete_elem(&dns_inflight, &txid_key);

            // Update latency histogram
            struct hist_key hkey = { .cgroup_id = cgroup_id };
            struct hist_value *hval = bpf_map_lookup_elem(&dns_latency, &hkey);
            if (hval) {
                __u32 slot = log2l(latency_ns);
                if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
                __sync_fetch_and_add(&hval->slots[slot], 1);
                __sync_fetch_and_add(&hval->count, 1);
                __sync_fetch_and_add(&hval->sum_ns, latency_ns);
            } else {
                struct hist_value new_hval = { .count = 1, .sum_ns = latency_ns };
                __u32 slot = log2l(latency_ns);
                if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
                new_hval.slots[slot] = 1;
                bpf_map_update_elem(&dns_latency, &hkey, &new_hval, BPF_NOEXIST);
            }
        }

        // Record error if rcode != 0
        __u8 rcode = flags & 0x000F;
        if (rcode != 0) {
            struct dns_err_key err_key = { .cgroup_id = cgroup_id, .rcode = rcode };
            struct counter_value *err_val = bpf_map_lookup_elem(&dns_errors, &err_key);
            if (err_val) {
                __sync_fetch_and_add(&err_val->count, 1);
            } else {
                struct counter_value new_err = { .count = 1 };
                bpf_map_update_elem(&dns_errors, &err_key, &new_err, BPF_NOEXIST);
            }
        }

        return 0;
        """.trimIndent(), BpfScalar.S32)
        returnValue(literal(0, BpfScalar.S32))
    }
}
```

**Note:** This program uses heavy `raw()` blocks because DNS packet parsing requires pointer arithmetic beyond the DSL's current abstraction. This is the same pattern used in NetProgram.kt for accessing tracepoint context fields. If the DSL does not support `hashMap`, `percpuArrayMap`, or `kretprobe` builders, these may need to be added to kotlin-ebpf-dsl first, or the program can be written as hand-written C in `bpf/dns.bpf.c` instead. Check DSL capabilities before implementing.

**Step 2: Verify DSL capabilities**

Before writing the file, check if kotlin-ebpf-dsl supports:
```bash
grep -r "fun hashMap\|fun percpuArrayMap\|fun kretprobe" ../kotlin-ebpf-dsl/src/ | head -10
```

If any are missing, write the BPF program as hand-written C at `bpf/dns.bpf.c` instead and add it to the Dockerfile clang compilation step. The map reader Kotlin code would need to be hand-written too.

**Step 3: Register in GenerateBpf.kt**

In `src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/GenerateBpf.kt`, add `dnsProgram` to the list:

```kotlin
val programs = listOf(
    // Custom programs
    cpuSchedProgram, netProgram, syscallProgram, dnsProgram,
    // BCC-style tools from kotlin-ebpf-dsl
    biolatency(), cachestat(), tcpdrop(),
    hardirqs(), softirqs(), execsnoop()
)
```

**Step 4: Verify code generation**

```bash
./gradlew generateBpf -PebpfDslPath=../kotlin-ebpf-dsl 2>&1 | tail -10
ls build/generated/bpf/dns.bpf.c
ls build/generated/kotlin/com/internal/kpodmetrics/bpf/generated/DnsMapReader.kt
```
Expected: Both files exist. Inspect generated C to verify DNS structs and maps are correct.

**Step 5: Commit**

```bash
git add src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/DnsProgram.kt
git add src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/GenerateBpf.kt
git commit -m "feat: add DNS BPF program definition (kotlin-ebpf-dsl)"
```

---

### Task 4: Configuration Properties

**Files:**
- Modify: `src/main/kotlin/com/internal/kpodmetrics/config/MetricsProperties.kt`

**Step 1: Add dns fields to ExtendedProperties (line 146)**

```kotlin
data class ExtendedProperties(
    val biolatency: Boolean = false,
    val cachestat: Boolean = false,
    val tcpdrop: Boolean = false,
    val hardirqs: Boolean = false,
    val softirqs: Boolean = false,
    val execsnoop: Boolean = false,
    val dns: Boolean = false,
    val dnsPorts: List<Int> = listOf(53)
)
```

**Step 2: Add dns to CollectorIntervals (line 162)**

Add after `execsnoop`:
```kotlin
val dns: Long? = null,
```

**Step 3: Add dns to CollectorOverrides (line 198)**

Add after `execsnoop`:
```kotlin
val dns: Boolean? = null,
```

**Step 4: Update profile defaults in resolveProfile()**

In `standard` profile (line 46), change `ExtendedProperties` to:
```kotlin
extended = ExtendedProperties(tcpdrop = true, execsnoop = true, dns = true),
```

In `comprehensive` profile (line 57), change `ExtendedProperties` to:
```kotlin
extended = ExtendedProperties(
    biolatency = true, cachestat = true,
    tcpdrop = true, hardirqs = true, softirqs = true, execsnoop = true,
    dns = true
),
```

**Step 5: Verify**

```bash
./gradlew compileKotlin -PebpfDslPath=../kotlin-ebpf-dsl 2>&1 | tail -5
```
Expected: BUILD SUCCESSFUL

**Step 6: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/config/MetricsProperties.kt
git commit -m "feat: add DNS config to MetricsProperties and profiles"
```

---

### Task 5: BpfProgramManager — Load DNS + Inject Ports

**Files:**
- Modify: `src/main/kotlin/com/internal/kpodmetrics/bpf/BpfProgramManager.kt`

**Step 1: Add dns to loadAll() (after line 64)**

```kotlin
if (ext.dns) tryLoadProgram("dns")
```

**Step 2: Add port injection method**

Add after `isProgramLoaded()` (line 130):

```kotlin
fun configureDnsPorts(ports: List<Int>) {
    if (!isProgramLoaded("dns")) return
    val mapFd = getMapFd("dns", "dns_ports")
    for (port in ports) {
        val keyBytes = java.nio.ByteBuffer.allocate(8)
            .order(java.nio.ByteOrder.LITTLE_ENDIAN)
            .putShort(port.toShort())
            .putShort(0)  // pad
            .putInt(0)    // pad2
            .array()
        val valueBytes = java.nio.ByteBuffer.allocate(8)
            .order(java.nio.ByteOrder.LITTLE_ENDIAN)
            .put(1.toByte())  // enabled
            .put(ByteArray(7))  // pad
            .array()
        bridge.mapUpdate(mapFd, keyBytes, valueBytes)
    }
    log.info("DNS port filter configured: {}", ports)
}
```

**Step 3: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/bpf/BpfProgramManager.kt
git commit -m "feat: BpfProgramManager loads DNS program and injects port config"
```

---

### Task 6: DnsCollector

**Files:**
- Create: `src/main/kotlin/com/internal/kpodmetrics/collector/DnsCollector.kt`

**Step 1: Write the collector**

```kotlin
package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.generated.DnsMapReader
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.DistributionSummary
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory

class DnsCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(DnsCollector::class.java)

    companion object {
        private const val MAX_ENTRIES = 10240
        private const val MAX_DOMAIN_ENTRIES = 1024

        private val QTYPE_NAMES = mapOf(
            1.toShort() to "A",
            28.toShort() to "AAAA",
            5.toShort() to "CNAME",
            33.toShort() to "SRV",
            12.toShort() to "PTR"
        )

        private val RCODE_NAMES = mapOf(
            1.toByte() to "FORMERR",
            2.toByte() to "SERVFAIL",
            3.toByte() to "NXDOMAIN",
            5.toByte() to "REFUSED"
        )

        fun qtypeName(qtype: Short): String = QTYPE_NAMES[qtype] ?: "OTHER"
        fun rcodeName(rcode: Byte): String = RCODE_NAMES[rcode] ?: "OTHER"
    }

    fun collect() {
        if (!config.extended.dns) return
        collectRequests()
        collectLatency()
        collectErrors()
        collectDomains()
    }

    private fun collectRequests() {
        val mapFd = programManager.getMapFd("dns", "dns_requests")
        val entries = bridge.mapBatchLookupAndDelete(
            mapFd, DnsMapReader.DnsReqKeyLayout.SIZE,
            DnsMapReader.CounterLayout.SIZE, MAX_ENTRIES
        )
        entries.forEach { (keyBytes, valueBytes) ->
            val cgroupId = DnsMapReader.DnsReqKeyLayout.decodeCgroupId(keyBytes)
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@forEach
            val qtype = DnsMapReader.DnsReqKeyLayout.decodeQtype(keyBytes)
            val count = DnsMapReader.CounterLayout.decodeCount(valueBytes)

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "qtype", qtypeName(qtype.toShort())
            )
            registry.counter("kpod.dns.requests", tags).increment(count.toDouble())
        }
    }

    private fun collectLatency() {
        val mapFd = programManager.getMapFd("dns", "dns_latency")
        val entries = bridge.mapBatchLookupAndDelete(
            mapFd, DnsMapReader.HistKeyLayout.SIZE,
            DnsMapReader.HistValueLayout.SIZE, MAX_ENTRIES
        )
        entries.forEach { (keyBytes, valueBytes) ->
            val cgroupId = DnsMapReader.HistKeyLayout.decodeCgroupId(keyBytes)
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@forEach
            val count = DnsMapReader.HistValueLayout.decodeCount(valueBytes)
            val sumNs = DnsMapReader.HistValueLayout.decodeSumNs(valueBytes)

            if (count <= 0 || sumNs <= 0) return@forEach

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )
            DistributionSummary.builder("kpod.dns.latency")
                .tags(tags)
                .baseUnit("seconds")
                .register(registry)
                .record(sumNs.toDouble() / 1_000_000_000.0)
        }
    }

    private fun collectErrors() {
        val mapFd = programManager.getMapFd("dns", "dns_errors")
        val entries = bridge.mapBatchLookupAndDelete(
            mapFd, DnsMapReader.DnsErrKeyLayout.SIZE,
            DnsMapReader.CounterLayout.SIZE, MAX_ENTRIES
        )
        entries.forEach { (keyBytes, valueBytes) ->
            val cgroupId = DnsMapReader.DnsErrKeyLayout.decodeCgroupId(keyBytes)
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@forEach
            val rcode = DnsMapReader.DnsErrKeyLayout.decodeRcode(keyBytes)
            val count = DnsMapReader.CounterLayout.decodeCount(valueBytes)

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "rcode", rcodeName(rcode.toByte())
            )
            registry.counter("kpod.dns.errors", tags).increment(count.toDouble())
        }
    }

    private fun collectDomains() {
        val mapFd = programManager.getMapFd("dns", "dns_domains")
        val entries = bridge.mapBatchLookupAndDelete(
            mapFd, DnsMapReader.DnsDomainKeyLayout.SIZE,
            DnsMapReader.CounterLayout.SIZE, MAX_DOMAIN_ENTRIES
        )
        entries.forEach { (keyBytes, valueBytes) ->
            val cgroupId = DnsMapReader.DnsDomainKeyLayout.decodeCgroupId(keyBytes)
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@forEach
            val domainBytes = DnsMapReader.DnsDomainKeyLayout.decodeDomain(keyBytes)
            val domain = domainBytes.takeWhile { it != 0.toByte() }
                .toByteArray().toString(Charsets.UTF_8)
                .ifEmpty { "unknown" }
            val count = DnsMapReader.CounterLayout.decodeCount(valueBytes)

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "domain", domain
            )
            registry.counter("kpod.dns.top.domains", tags).increment(count.toDouble())
        }
    }
}
```

**Note:** The `DnsMapReader` class names (`DnsReqKeyLayout`, `DnsErrKeyLayout`, etc.) are auto-generated by kotlin-ebpf-dsl's `emit()`. After Task 3 generates the code, inspect `build/generated/kotlin/.../DnsMapReader.kt` to verify exact class and method names. Adjust field accessor names accordingly (e.g., `decodeCgroupId`, `decodeQtype`, `decodeRcode`, `decodeDomain`, `decodeCount`, `decodeSumNs`).

**Step 2: Verify compilation**

```bash
./gradlew compileKotlin -PebpfDslPath=../kotlin-ebpf-dsl 2>&1 | tail -5
```

**Step 3: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/collector/DnsCollector.kt
git commit -m "feat: add DnsCollector for DNS metrics collection"
```

---

### Task 7: Wire into Spring Boot

**Files:**
- Modify: `src/main/kotlin/com/internal/kpodmetrics/config/BpfAutoConfiguration.kt`
- Modify: `src/main/kotlin/com/internal/kpodmetrics/collector/MetricsCollectorService.kt`

**Step 1: Add DnsCollector bean in BpfAutoConfiguration.kt**

After `execsnoopCollector` bean (line 210), add:

```kotlin
@Bean
@ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
fun dnsCollector(
    bridge: BpfBridge,
    manager: BpfProgramManager,
    resolver: CgroupResolver,
    registry: MeterRegistry,
    config: ResolvedConfig
) = DnsCollector(bridge, manager, resolver, registry, config, props.nodeName)
```

**Step 2: Add DnsCollector to metricsCollectorService bean**

In the `metricsCollectorService` method signature (line 313), add parameter:
```kotlin
dnsCollector: DnsCollector,
```

In the `MetricsCollectorService(...)` constructor call (line 336), add after `execsnoopCollector`:
```kotlin
dnsCollector,
```

**Step 3: Add DNS port injection in onStartup()**

In `onStartup()`, after `it.loadAll()` (line 453), add:

```kotlin
// Configure DNS port filter
if (props.resolveProfile().extended.dns) {
    it.configureDnsPorts(props.resolveProfile().extended.dnsPorts)
}
```

**Step 4: Update MetricsCollectorService constructor**

Add `dnsCollector` parameter (after `execsnoopCollector` on line 35):
```kotlin
private val dnsCollector: DnsCollector,
```

**Step 5: Add to allBpfCollectors list (line 163)**

Add after the execsnoop entry:
```kotlin
"dns" to dnsCollector::collect,
```

**Step 6: Add to intervalMap and overrideMap**

In `intervalMap` (line 69), add:
```kotlin
"dns" to collectorIntervals.dns,
```

In `overrideMap` (line 85), add:
```kotlin
"dns" to collectorOverrides.dns,
```

**Step 7: Add to getEnabledCollectorCount (line 250)**

Add `"dns"` to the BPF collector list.

**Step 8: Add DNS maps to cleanupCgroupEntries (line 290)**

Add to `maps8ByteKey`:
```kotlin
"dns" to "dns_requests",
"dns" to "dns_latency",
"dns" to "dns_errors",
```

DNS domains and inflight maps have composite keys but still start with cgroup_id at offset 0, so they can use iterate+delete like syscall:

Add after the syscall cleanup block (line 338):
```kotlin
// dns_domains has 40-byte keys (cgroup_id + domain[32])
if (programManager.isProgramLoaded("dns")) {
    for (mapName in listOf("dns_domains", "dns_inflight")) {
        try {
            val keySize = if (mapName == "dns_domains") 40 else 16
            val fd = programManager.getMapFd("dns", mapName)
            val keysToDelete = mutableListOf<ByteArray>()
            var prevKey: ByteArray? = null
            while (true) {
                val nextKey = bridge.mapGetNextKey(fd, prevKey, keySize) ?: break
                val keyCgroupId = ByteBuffer.wrap(nextKey).order(ByteOrder.LITTLE_ENDIAN).long
                if (keyCgroupId == cgroupId) {
                    keysToDelete.add(nextKey)
                }
                prevKey = nextKey
            }
            for (k in keysToDelete) {
                bridge.mapDelete(fd, k)
            }
        } catch (_: Exception) {}
    }
}
```

**Step 9: Verify compilation**

```bash
./gradlew compileKotlin -PebpfDslPath=../kotlin-ebpf-dsl 2>&1 | tail -5
```

**Step 10: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/config/BpfAutoConfiguration.kt
git add src/main/kotlin/com/internal/kpodmetrics/collector/MetricsCollectorService.kt
git commit -m "feat: wire DnsCollector into Spring Boot and MetricsCollectorService"
```

---

### Task 8: Helm Chart Updates

**Files:**
- Modify: `helm/kpod-metrics/values.yaml`
- Modify: `helm/kpod-metrics/values.schema.json` (if exists)

**Step 1: Add dns to values.yaml collectors section**

In the commented collectors section (around line 133), add:
```yaml
  #   dns: true
  #   dnsPorts: [53]
```

**Step 2: Add dns to configmap propagation**

The configmap already uses `{{- toYaml .Values.config.collectors | nindent 8 }}` which will pass through `dns` and `dnsPorts` automatically. No template change needed.

**Step 3: Verify helm lint**

```bash
helm lint helm/kpod-metrics --strict
helm template test helm/kpod-metrics > /dev/null
```
Expected: no errors

**Step 4: Commit**

```bash
git add helm/kpod-metrics/
git commit -m "feat: add DNS collector config to Helm values"
```

---

### Task 9: DnsCollector Unit Test

**Files:**
- Create: `src/test/kotlin/com/internal/kpodmetrics/collector/DnsCollectorTest.kt`

**Step 1: Write the test**

```kotlin
package com.internal.kpodmetrics.collector

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class DnsCollectorTest {

    @Test
    fun `qtypeName returns known type names`() {
        assertEquals("A", DnsCollector.qtypeName(1))
        assertEquals("AAAA", DnsCollector.qtypeName(28))
        assertEquals("CNAME", DnsCollector.qtypeName(5))
        assertEquals("SRV", DnsCollector.qtypeName(33))
        assertEquals("PTR", DnsCollector.qtypeName(12))
    }

    @Test
    fun `qtypeName returns OTHER for unknown types`() {
        assertEquals("OTHER", DnsCollector.qtypeName(255))
        assertEquals("OTHER", DnsCollector.qtypeName(0))
    }

    @Test
    fun `rcodeName returns known rcode names`() {
        assertEquals("FORMERR", DnsCollector.rcodeName(1))
        assertEquals("SERVFAIL", DnsCollector.rcodeName(2))
        assertEquals("NXDOMAIN", DnsCollector.rcodeName(3))
        assertEquals("REFUSED", DnsCollector.rcodeName(5))
    }

    @Test
    fun `rcodeName returns OTHER for unknown rcodes`() {
        assertEquals("OTHER", DnsCollector.rcodeName(4))
        assertEquals("OTHER", DnsCollector.rcodeName(15))
    }
}
```

**Step 2: Run test**

```bash
./gradlew test --tests "com.internal.kpodmetrics.collector.DnsCollectorTest" -PebpfDslPath=../kotlin-ebpf-dsl
```
Expected: All tests PASS

**Step 3: Commit**

```bash
git add src/test/kotlin/com/internal/kpodmetrics/collector/DnsCollectorTest.kt
git commit -m "test: add DnsCollector unit tests"
```

---

### Task 10: Grafana Dashboard

**Files:**
- Create: `helm/kpod-metrics/dashboards/dns.json`

**Step 1: Create DNS dashboard JSON**

Create a Grafana dashboard with 4 panels:
1. **DNS Query Rate** — timeseries panel, query: `sum(rate(kpod_dns_requests_total{namespace=~"$namespace"}[5m])) by (pod, qtype)`
2. **DNS Latency** — heatmap panel, query: `kpod_dns_latency{namespace=~"$namespace"}`
3. **DNS Errors** — timeseries panel, query: `sum(rate(kpod_dns_errors_total{namespace=~"$namespace"}[5m])) by (pod, rcode)`
4. **Top Domains** — table panel, query: `topk(10, sum by (domain) (rate(kpod_dns_top_domains_total{namespace=~"$namespace"}[5m])))`

Use the same style/variables as existing dashboards in the dashboards directory. Include `$namespace`, `$pod`, `$node` template variables.

**Step 2: Verify dashboard is picked up**

Check if dashboards directory is referenced in Helm templates. If using ConfigMap-based provisioning, ensure the dashboard JSON is included.

**Step 3: Commit**

```bash
git add helm/kpod-metrics/dashboards/dns.json
git commit -m "feat: add Grafana DNS metrics dashboard"
```

---

### Task 11: Full Verification

**Step 1: Run all tests**

```bash
./gradlew test detekt -PebpfDslPath=../kotlin-ebpf-dsl
```
Expected: All tests pass, no detekt violations

**Step 2: Helm lint**

```bash
helm lint helm/kpod-metrics --strict
helm template test helm/kpod-metrics > /dev/null
helm template test helm/kpod-metrics --set config.profile=comprehensive > /dev/null
```

**Step 3: Docker build (if possible)**

```bash
cd /Users/jongsu/dev
docker build -f kpod-metrics/Dockerfile -t kpod-metrics:dns .
```

This verifies BPF C code compiles with clang.

**Step 4: Final commit**

```bash
git add -A
git status  # review any missed files
git commit -m "feat: DNS metrics collector — complete implementation"
```

---

## Task Dependency Graph

```
Task 1 (mapUpdate JNI) ──┐
Task 2 (DNS structs)  ───┤
                          ├── Task 3 (DnsProgram.kt) ── Task 6 (DnsCollector) ── Task 7 (Spring wiring)
Task 4 (Config props) ───┤                                                              │
                          │                                                              ├── Task 9 (Tests)
Task 5 (BpfProgramManager) ─────────────────────────────────────────────────────────────┘
                                                                                         │
Task 8 (Helm) ──────────────────────────────────────────────────────────────────── Task 11 (Verify)
Task 10 (Dashboard) ─────────────────────────────────────────────────────────────────────┘
```

Parallelizable groups:
- **Group A** (no deps): Tasks 1, 2, 4, 8 — can run in parallel
- **Group B** (depends on 2): Task 3
- **Group C** (depends on 1, 4): Task 5
- **Group D** (depends on 3, 5): Task 6
- **Group E** (depends on 4, 6): Task 7
- **Group F** (depends on 7): Tasks 9, 10 — can run in parallel
- **Group G** (depends on all): Task 11
