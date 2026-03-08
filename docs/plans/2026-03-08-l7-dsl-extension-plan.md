# L7 DSL Extension Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend kotlin-ebpf-dsl with buffer read/byte match primitives, then migrate hand-written DNS and HTTP BPF programs to the Kotlin DSL.

**Architecture:** Add 4 new IR node types (ProbeReadBuf, BufferByte, BufferMultiByte, ProbeReadUser) and 1 new helper (bpf_get_socket_cookie) to the DSL. Introduce a `BufferHandle` wrapper that provides type-safe byte access. Then rewrite dns.bpf.c and http.bpf.c as Kotlin DSL programs.

**Tech Stack:** Kotlin 2.1.10, kotlin-ebpf-dsl (IR + codegen), BPF C, JDK 21

**Repos:**
- DSL: `/Users/jongsu/dev/kotlin-ebpf-dsl`
- App: `/Users/jongsu/dev/kpod-metrics`

**Pre-existing DSL support** (no changes needed):
- `kretprobe()` — already in `EbpfProgramBuilder.kt`
- `percpuArray()` — already in `EbpfProgramBuilder.kt`
- `ProgramType.Kretprobe` — already in `ProgramType.kt`
- Context type `struct pt_regs *ctx` — already handled for Kretprobe

---

## Phase 1: kotlin-ebpf-dsl Extensions

### Task 1: Add `bpf_get_socket_cookie` helper

**Files:**
- Modify: `/Users/jongsu/dev/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/programs/HelperRegistry.kt`
- Modify: `/Users/jongsu/dev/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/api/ProgramBodyBuilder.kt`
- Test: `/Users/jongsu/dev/kotlin-ebpf-dsl/src/test/kotlin/dev/ebpf/dsl/api/ProgramBodyBuilderTest.kt`

**Step 1: Write failing test**

```kotlin
@Test
fun `getSocketCookie creates helper call`() {
    val builder = ProgramBodyBuilder(license = "GPL")
    val cookie = builder.getSocketCookie()
    assertThat(cookie.expr).isInstanceOf(BpfExpr.HelperCall::class.java)
    val call = cookie.expr as BpfExpr.HelperCall
    assertThat(call.helperName).isEqualTo("bpf_get_socket_cookie")
    assertThat(call.type).isEqualTo(BpfScalar.U64)
}
```

**Step 2: Run test — expect FAIL**

Run: `cd /Users/jongsu/dev/kotlin-ebpf-dsl && JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test --tests "*ProgramBodyBuilderTest*getSocketCookie*" -v`

**Step 3: Register helper in HelperRegistry.kt**

Add to `init {}` block after existing helpers (around line 160):

```kotlin
register(BpfHelper(
    id = 46, name = "bpf_get_socket_cookie",
    returnType = BpfScalar.U64,
    paramTypes = emptyList(),
    gplOnly = false,
    availableIn = emptySet(),
    minKernel = KernelVersion.V4_18,
))
```

**Step 4: Add wrapper in ProgramBodyBuilder.kt**

Add after `getCurrentTaskBtf()` (around line 95):

```kotlin
fun getSocketCookie() = helperCall("bpf_get_socket_cookie")
```

**Step 5: Run test — expect PASS**

**Step 6: Commit**

```bash
git add -A && git commit -m "feat: add bpf_get_socket_cookie helper"
```

---

### Task 2: Add `ProbeReadBuf` IR node and `BufferHandle`

This is the core primitive. `probeReadBuf(ptr, size)` reads bytes from a kernel pointer into a stack buffer and returns a `BufferHandle` for type-safe byte access.

**Files:**
- Modify: `/Users/jongsu/dev/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/ir/BpfExpr.kt`
- Modify: `/Users/jongsu/dev/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/ir/BpfStmt.kt`
- Create: `/Users/jongsu/dev/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/api/BufferHandle.kt`
- Modify: `/Users/jongsu/dev/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/api/ProgramBodyBuilder.kt`
- Modify: `/Users/jongsu/dev/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/codegen/CCodeGenerator.kt`
- Test: `/Users/jongsu/dev/kotlin-ebpf-dsl/src/test/kotlin/dev/ebpf/dsl/codegen/CCodeGeneratorTest.kt`

**Step 1: Write failing test for C codegen**

```kotlin
@Test
fun `probeReadBuf generates stack buffer and probe_read_kernel`() {
    val model = ebpf("test_buf") {
        license("GPL")
        kprobe("tcp_sendmsg") {
            val ptr = kprobeParam(1, "struct msghdr *")
            val buf = probeReadBuf(ptr, 64)
            val b0 = buf.byte(0)
            declareVar("first_byte", b0)
            returnValue(literal(0, BpfScalar.S32))
        }
    }
    val code = CCodeGenerator(model).generate()
    assertThat(code).contains("char __buf_0[64]")
    assertThat(code).contains("__builtin_memset(&__buf_0, 0, sizeof(__buf_0))")
    assertThat(code).contains("bpf_probe_read_kernel(&__buf_0, 64,")
    assertThat(code).contains("((__u8)__buf_0[0])")
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Add IR nodes**

In `BpfExpr.kt`, add two new variants:

```kotlin
// Buffer byte access: buf[index] as u8
data class BufferByte(val bufferName: String, val index: Int) : BpfExpr() {
    override val type: BpfType = BpfScalar.U8
}

// Buffer multi-byte access: *(u16/u32 *)&buf[offset] with optional byte swap
data class BufferMultiByte(
    val bufferName: String,
    val offset: Int,
    val readType: BpfScalar,   // U16 or U32
    val bigEndian: Boolean     // true = ntohs/ntohl, false = native
) : BpfExpr() {
    override val type: BpfType = readType
}
```

In `BpfStmt.kt`, add:

```kotlin
// Declares a stack buffer, zeroes it, and reads from a pointer
data class ProbeReadBuf(
    val bufferName: String,
    val size: Int,
    val srcPtr: BpfExpr,
    val useUserRead: Boolean = false  // false = kernel, true = user
) : BpfStmt()
```

**Step 4: Create BufferHandle**

Create `/Users/jongsu/dev/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/api/BufferHandle.kt`:

```kotlin
package dev.ebpf.dsl.api

import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar

class BufferHandle(
    val name: String,
    val size: Int,
    private val builder: ProgramBodyBuilder
) {
    fun byte(index: Int): ExprHandle {
        require(index in 0 until size) { "Buffer index $index out of bounds (size=$size)" }
        return ExprHandle(BpfExpr.BufferByte(name, index), builder)
    }

    fun u16be(offset: Int): ExprHandle {
        require(offset + 2 <= size) { "u16be at offset $offset exceeds buffer size $size" }
        return ExprHandle(BpfExpr.BufferMultiByte(name, offset, BpfScalar.U16, bigEndian = true), builder)
    }

    fun u16le(offset: Int): ExprHandle {
        require(offset + 2 <= size) { "u16le at offset $offset exceeds buffer size $size" }
        return ExprHandle(BpfExpr.BufferMultiByte(name, offset, BpfScalar.U16, bigEndian = false), builder)
    }

    fun u32be(offset: Int): ExprHandle {
        require(offset + 4 <= size) { "u32be at offset $offset exceeds buffer size $size" }
        return ExprHandle(BpfExpr.BufferMultiByte(name, offset, BpfScalar.U32, bigEndian = true), builder)
    }

    fun u32le(offset: Int): ExprHandle {
        require(offset + 4 <= size) { "u32le at offset $offset exceeds buffer size $size" }
        return ExprHandle(BpfExpr.BufferMultiByte(name, offset, BpfScalar.U32, bigEndian = false), builder)
    }
}
```

**Step 5: Add builder methods to ProgramBodyBuilder**

Add a buffer counter and methods (around line 95):

```kotlin
private var bufferCounter = 0

fun probeReadBuf(ptr: ExprHandle, size: Int): BufferHandle {
    val name = "__buf_${bufferCounter++}"
    addStmt(BpfStmt.ProbeReadBuf(name, size, ptr.expr, useUserRead = false))
    return BufferHandle(name, size, this)
}

fun probeReadUser(ptr: ExprHandle, size: Int): BufferHandle {
    val name = "__buf_${bufferCounter++}"
    addStmt(BpfStmt.ProbeReadBuf(name, size, ptr.expr, useUserRead = true))
    return BufferHandle(name, size, this)
}
```

**Step 6: Add codegen in CCodeGenerator**

In `renderStmt()`, add case for ProbeReadBuf:

```kotlin
is BpfStmt.ProbeReadBuf -> {
    sb.appendLine("${pad}char ${stmt.bufferName}[${stmt.size}];")
    sb.appendLine("${pad}__builtin_memset(&${stmt.bufferName}, 0, sizeof(${stmt.bufferName}));")
    val helper = if (stmt.useUserRead) "bpf_probe_read_user" else "bpf_probe_read_kernel"
    sb.appendLine("${pad}${helper}(&${stmt.bufferName}, ${stmt.size}, (void *)${renderExpr(stmt.srcPtr)});")
}
```

In `renderExpr()`, add cases:

```kotlin
is BpfExpr.BufferByte -> "((__u8)${expr.bufferName}[${expr.index}])"

is BpfExpr.BufferMultiByte -> {
    val castType = if (expr.readType == BpfScalar.U16) "__u16" else "__u32"
    val inner = "(*($castType *)&${expr.bufferName}[${expr.offset}])"
    if (expr.bigEndian) {
        val swap = if (expr.readType == BpfScalar.U16) "__bpf_ntohs" else "__bpf_ntohl"
        "$swap($inner)"
    } else {
        inner
    }
}
```

**Step 7: Run test — expect PASS**

**Step 8: Write additional tests**

```kotlin
@Test
fun `probeReadUser generates bpf_probe_read_user`() {
    val model = ebpf("test_user_buf") {
        license("GPL")
        kprobe("tcp_sendmsg") {
            val ptr = kprobeParam(1, "void *")
            val buf = probeReadUser(ptr, 32)
            val port = buf.u16be(0)
            declareVar("port", port)
            returnValue(literal(0, BpfScalar.S32))
        }
    }
    val code = CCodeGenerator(model).generate()
    assertThat(code).contains("bpf_probe_read_user")
    assertThat(code).contains("__bpf_ntohs(*(__u16 *)&__buf_0[0])")
}

@Test
fun `buffer u32le generates native read without swap`() {
    val model = ebpf("test_u32") {
        license("GPL")
        kprobe("test_fn") {
            val ptr = kprobeParam(1, "void *")
            val buf = probeReadBuf(ptr, 16)
            val len = buf.u32le(4)
            declareVar("len", len)
            returnValue(literal(0, BpfScalar.S32))
        }
    }
    val code = CCodeGenerator(model).generate()
    assertThat(code).contains("(*(__u32 *)&__buf_0[4])")
    assertThat(code).doesNotContain("__bpf_ntohl")
}

@Test
fun `buffer byte index out of bounds throws`() {
    assertThatThrownBy {
        ebpf("test_oob") {
            license("GPL")
            kprobe("test_fn") {
                val ptr = kprobeParam(1, "void *")
                val buf = probeReadBuf(ptr, 8)
                buf.byte(8)  // out of bounds
            }
        }
    }.isInstanceOf(IllegalArgumentException::class.java)
}
```

**Step 9: Run all tests — expect PASS**

Run: `cd /Users/jongsu/dev/kotlin-ebpf-dsl && JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test -v`

**Step 10: Commit**

```bash
git add -A && git commit -m "feat: add probeReadBuf, probeReadUser, and BufferHandle for L7 protocol parsing"
```

---

### Task 3: Add `kretprobeReturnValue()` helper

kretprobe programs need to read the return value via `PT_REGS_RC(ctx)`.

**Files:**
- Modify: `/Users/jongsu/dev/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/ir/BpfExpr.kt`
- Modify: `/Users/jongsu/dev/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/api/ProgramBodyBuilder.kt`
- Modify: `/Users/jongsu/dev/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/codegen/CCodeGenerator.kt`
- Test: `/Users/jongsu/dev/kotlin-ebpf-dsl/src/test/kotlin/dev/ebpf/dsl/codegen/CCodeGeneratorTest.kt`

**Step 1: Write failing test**

```kotlin
@Test
fun `kretprobeReturnValue generates PT_REGS_RC`() {
    val model = ebpf("test_kretprobe") {
        license("GPL")
        kretprobe("udp_recvmsg") {
            val ret = kretprobeReturnValue(BpfScalar.S32)
            declareVar("retval", ret)
            returnValue(literal(0, BpfScalar.S32))
        }
    }
    val code = CCodeGenerator(model).generate()
    assertThat(code).contains("SEC(\"kretprobe/udp_recvmsg\")")
    assertThat(code).contains("((__s32)PT_REGS_RC(ctx))")
}
```

**Step 2: Run test — expect FAIL**

**Step 3: Add IR node**

In `BpfExpr.kt`:

```kotlin
data class KretprobeReturn(val castType: BpfScalar) : BpfExpr() {
    override val type: BpfType = castType
}
```

**Step 4: Add builder method**

In `ProgramBodyBuilder.kt`:

```kotlin
fun kretprobeReturnValue(type: BpfScalar = BpfScalar.S64): ExprHandle =
    ExprHandle(BpfExpr.KretprobeReturn(type), this)
```

**Step 5: Add codegen**

In `CCodeGenerator.renderExpr()`:

```kotlin
is BpfExpr.KretprobeReturn -> "((${renderTypeName(expr.castType)})PT_REGS_RC(ctx))"
```

**Step 6: Run test — expect PASS**

**Step 7: Commit**

```bash
git add -A && git commit -m "feat: add kretprobeReturnValue for return probe access"
```

---

### Task 4: Run full DSL test suite

**Step 1: Run all tests**

```bash
cd /Users/jongsu/dev/kotlin-ebpf-dsl && JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test
```

Expected: all tests pass, no regressions.

**Step 2: Commit any fixes if needed**

---

## Phase 2: Migrate DNS Program to DSL

### Task 5: Create DNS struct definitions

**Files:**
- Create: `/Users/jongsu/dev/kpod-metrics/src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/DnsProgram.kt`

**Step 1: Define DNS-specific structs and the program skeleton**

```kotlin
package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

// --- DNS-specific structs ---

object PortKey : BpfStruct("port_key") {
    val port by u16()
    val pad1 by u16()
    val pad2 by u32()
}

object PortVal : BpfStruct("port_val") {
    val enabled by u8()
    val pad by array(BpfScalar.U8, 7)
}

object DnsReqKey : BpfStruct("dns_req_key") {
    val cgroupId by u64()
    val qtype by u16()
    val pad1 by u16()
    val pad2 by u32()
}

object DnsErrKey : BpfStruct("dns_err_key") {
    val cgroupId by u64()
    val rcode by u8()
    val pad by array(BpfScalar.U8, 7)
}

object DnsDomainKey : BpfStruct("dns_domain_key") {
    val cgroupId by u64()
    val domain by array(BpfScalar.U8, 32)
}

object DnsInflightKey : BpfStruct("dns_inflight_key") {
    val cgroupId by u64()
    val txid by u16()
    val pad1 by u16()
    val pad2 by u32()
}

object Timestamp : BpfStruct("timestamp") {
    val ts by u64()
}

object RecvStash : BpfStruct("recv_stash") {
    val cgroupId by u64()
    val msghdrPtr by u64()
}
```

This is just the struct definitions — the actual program body will be in Task 6.

**Step 2: Verify compilation**

```bash
cd /Users/jongsu/dev/kpod-metrics && JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew compileBpfGeneratorKotlin
```

**Step 3: Commit**

```bash
git add -A && git commit -m "feat: add DNS program struct definitions for DSL migration"
```

---

### Task 6: Implement DNS program body using DSL

**Files:**
- Modify: `/Users/jongsu/dev/kpod-metrics/src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/DnsProgram.kt`

This is the largest task. The program has 3 BPF programs (kprobe/udp_sendmsg, kprobe/udp_recvmsg, kretprobe/udp_recvmsg) and 7 maps.

**Step 1: Write the full DSL program**

The DNS program needs a preamble for iovec access helpers and network byte order macros. Use `preamble()` for these C helpers that can't be expressed in the DSL.

The program body will use:
- `probeReadBuf()` for reading msghdr, sockaddr, DNS payload
- `buf.byte()` for DNS flags parsing
- `buf.u16be()` for txid, qtype, port extraction
- `percpuArray` for kprobe→kretprobe stashing
- `getCurrentCgroupId()`, `ktimeGetNs()` for metadata
- `lruHashMap` for all data maps, `hashMap` for port filter

Reference the hand-written `bpf/dns.bpf.c` line by line to ensure equivalent logic.

**Step 2: Add to GenerateBpf.kt**

Add `dnsProgram` to the list of programs to generate in `GenerateBpf.kt`.

**Step 3: Generate and diff**

```bash
cd /Users/jongsu/dev/kpod-metrics && JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew generateBpf
diff bpf/dns.bpf.c build/generated/bpf/dns.bpf.c  # structural comparison
```

The generated C won't be byte-identical but should be functionally equivalent. Key checks:
- Same maps with same types and sizes
- Same SEC sections
- Same probe_read calls
- Same port filtering logic
- Same DNS header parsing
- Same latency tracking

**Step 4: Commit**

```bash
git add -A && git commit -m "feat: implement DNS BPF program using kotlin-ebpf-dsl"
```

---

### Task 7: Implement HTTP program using DSL

**Files:**
- Create or extend: `/Users/jongsu/dev/kpod-metrics/src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/HttpProgram.kt`

**Step 1: Define HTTP-specific structs**

```kotlin
object HttpEventKey : BpfStruct("http_event_key") {
    val cgroupId by u64()
    val method by u8()
    val direction by u8()
    val statusCode by u16()
    val pad by u32()
}

object HttpLatKey : BpfStruct("http_lat_key") {
    val cgroupId by u64()
    val method by u8()
    val direction by u8()
    val pad1 by u16()
    val pad2 by u32()
}

object HttpInflightKey : BpfStruct("http_inflight_key") {
    val cgroupId by u64()
    val sockCookie by u64()
}

object HttpInflightVal : BpfStruct("http_inflight_val") {
    val ts by u64()
    val method by u8()
    val direction by u8()
    val pad1 by u16()
    val pad2 by u32()
}
```

**Step 2: Write the full DSL program**

The HTTP program needs:
- `getSocketCookie()` for request/response correlation
- `probeReadBuf()` for reading iovec payload (first 16 bytes)
- `buf.byte()` for HTTP method detection (G-E-T, P-O-S-T, etc.)
- `buf.byte()` for HTTP response detection (H-T-T-P-/-1-.)
- Preamble for iovec access helpers (ITER_UBUF/ITER_IOVEC kernel compat)
- Port filtering via `hashMap`

**Step 3: Add to GenerateBpf.kt, generate, and diff against http.bpf.c**

**Step 4: Commit**

```bash
git add -A && git commit -m "feat: implement HTTP BPF program using kotlin-ebpf-dsl"
```

---

### Task 8: Wire DSL-generated programs into build

**Files:**
- Modify: `/Users/jongsu/dev/kpod-metrics/src/bpfGenerator/kotlin/com/internal/kpodmetrics/bpf/programs/GenerateBpf.kt`
- Modify: `/Users/jongsu/dev/kpod-metrics/Dockerfile` (if needed)

**Step 1: Update GenerateBpf.kt**

Add `dnsProgram` and `httpProgram` to the output list. Ensure they emit to the same output directory as other generated programs.

**Step 2: Update Dockerfile**

If the Dockerfile currently copies `bpf/dns.bpf.c` and `bpf/http.bpf.c` separately from generated programs, update to use the generated versions instead.

**Step 3: Verify Docker build compiles everything**

```bash
cd /Users/jongsu/dev && docker build -f kpod-metrics/Dockerfile -t kpod-metrics:l7-dsl .
```

**Step 4: Commit**

```bash
git add -A && git commit -m "build: wire DSL-generated DNS/HTTP programs into build pipeline"
```

---

### Task 9: Remove hand-written C files

**Files:**
- Delete: `/Users/jongsu/dev/kpod-metrics/bpf/dns.bpf.c`
- Delete: `/Users/jongsu/dev/kpod-metrics/bpf/http.bpf.c`

**Step 1: Verify generated programs are being used**

Confirm that `GenerateBpf.kt` outputs dns.bpf.c and http.bpf.c to the build directory and that the Dockerfile uses those.

**Step 2: Remove hand-written files**

```bash
git rm bpf/dns.bpf.c bpf/http.bpf.c
```

**Step 3: Full build verification**

```bash
cd /Users/jongsu/dev && docker build -f kpod-metrics/Dockerfile -t kpod-metrics:l7-dsl .
```

**Step 4: Commit**

```bash
git commit -m "refactor: remove hand-written dns.bpf.c and http.bpf.c, now DSL-generated"
```

---

## Phase 3: Verification

### Task 10: Run all tests

**Step 1: kotlin-ebpf-dsl tests**

```bash
cd /Users/jongsu/dev/kotlin-ebpf-dsl && JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test
```

**Step 2: kpod-metrics tests**

```bash
cd /Users/jongsu/dev/kpod-metrics && JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test
```

All existing DnsCollector and HttpCollector tests must pass unchanged — the generated BPF programs produce identical map structures, so the Kotlin collectors are unaffected.

**Step 3: Docker build**

```bash
cd /Users/jongsu/dev && docker build -f kpod-metrics/Dockerfile -t kpod-metrics:l7-dsl .
```

---

## Summary

| Phase | Tasks | Repo | Effort |
|-------|-------|------|--------|
| 1. DSL Extensions | 1-4 | kotlin-ebpf-dsl | ~1 day |
| 2. Program Migration | 5-9 | kpod-metrics | ~2 days |
| 3. Verification | 10 | both | ~0.5 day |

**Total: ~3.5 days**

After this work, adding new L7 protocols (MySQL, Redis, PostgreSQL) becomes a Kotlin-only task requiring ~50-100 lines per protocol instead of 300-500 lines of hand-written C.
