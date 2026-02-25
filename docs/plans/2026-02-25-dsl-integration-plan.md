# kotlin-ebpf-dsl Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace hand-written BPF C programs in kpod-metrics with kotlin-ebpf-dsl-generated code, and replace manual ByteBuffer deserialization in collectors with generated MapReader classes.

**Architecture:** Gradle composite build links kpod-metrics to kotlin-ebpf-dsl. DSL program definitions live in kpod-metrics. A Gradle JavaExec task generates `.bpf.c` files and Kotlin MapReader classes at build time. Collectors are rewritten to use generated decode methods.

**Tech Stack:** kotlin-ebpf-dsl (composite build), Gradle 9.3.1, Kotlin 2.1.10, JDK 21, clang/libbpf (unchanged)

**Repos:**
- DSL library: `/Users/jongsu/kotlin-ebpf-dsl/`
- Application: `/Users/jongsu/dev/kpod-metrics/`

---

## Phase 1: DSL Extensions (in kotlin-ebpf-dsl repo)

### Task 1: Add else branch to ifNonNull

The lookup-or-insert pattern used by every kpod-metrics BPF program needs `ifNonNull(...) { }.elseThen { }`.

**Files:**
- Modify: `/Users/jongsu/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/ir/BpfStmt.kt`
- Modify: `/Users/jongsu/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/api/ProgramBodyBuilder.kt`
- Modify: `/Users/jongsu/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/codegen/CCodeGenerator.kt`
- Modify: `/Users/jongsu/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/validation/TypeChecker.kt`
- Modify: `/Users/jongsu/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/validation/SemanticAnalyzer.kt`
- Test: `/Users/jongsu/kotlin-ebpf-dsl/src/test/kotlin/dev/ebpf/dsl/api/IfNonNullElseTest.kt`

**Step 1: Write the failing test**

```kotlin
package dev.ebpf.dsl.api

import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class IfNonNullElseTest {

    object Key : BpfStruct("key") {
        val id by u64()
    }
    object Val : BpfStruct("val") {
        val count by u64()
    }

    @Test
    fun `ifNonNull with elseThen generates correct C`() {
        val program = ebpf("test_else") {
            license("GPL")
            val myMap by lruHashMap(Key, Val, maxEntries = 1024, mapName = "my_map")
            tracepoint("sched", "sched_switch") {
                val key = stackVar(Key) {
                    it[Key.id] = literal(1u, BpfScalar.U64)
                }
                val entry = myMap.lookup(key)
                ifNonNull(entry) { e ->
                    e[Val.count].atomicAdd(literal(1u, BpfScalar.U64))
                }.elseThen {
                    val newVal = stackVar(Val) {
                        it[Val.count] = literal(1u, BpfScalar.U64)
                    }
                    myMap.update(key, newVal, flags = 1) // BPF_NOEXIST
                }
                returnValue(literal(0, BpfScalar.S32))
            }
        }

        val result = program.validate()
        assertThat(result.errors).isEmpty()

        val c = program.generateC()
        assertThat(c).contains("if (entry_")
        assertThat(c).contains("} else {")
        assertThat(c).contains("bpf_map_update_elem")
        assertThat(c).contains(", 1)")  // BPF_NOEXIST flag
    }

    @Test
    fun `ifNonNull without elseThen still works`() {
        val program = ebpf("test_no_else") {
            license("GPL")
            val myMap by lruHashMap(Key, Val, maxEntries = 1024, mapName = "my_map")
            tracepoint("sched", "sched_switch") {
                val key = stackVar(Key) {
                    it[Key.id] = literal(1u, BpfScalar.U64)
                }
                ifNonNull(myMap.lookup(key)) { e ->
                    e[Val.count].atomicAdd(literal(1u, BpfScalar.U64))
                }
                returnValue(literal(0, BpfScalar.S32))
            }
        }

        val c = program.generateC()
        assertThat(c).doesNotContain("} else {")
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/jongsu/kotlin-ebpf-dsl && ./gradlew test --tests "dev.ebpf.dsl.api.IfNonNullElseTest" 2>&1`
Expected: FAIL — `elseThen` method doesn't exist

**Step 3: Implement**

1. Modify `BpfStmt.IfNonNull` to add optional else body:
```kotlin
data class IfNonNull(val expr: BpfExpr, val variable: Variable, val body: List<BpfStmt>, val else_: List<BpfStmt>? = null) : BpfStmt()
```

2. Modify `ProgramBodyBuilder.ifNonNull` to return `IfNonNullBuilder`:
```kotlin
fun ifNonNull(expr: ExprHandle, block: (ExprHandle) -> Unit): IfNonNullBuilder {
    val v = Variable("entry_${varCounter++}", expr.type, false)
    val savedStmts = stmts.toList()
    stmts.clear()
    val handle = ExprHandle(BpfExpr.VarRef(v), this)
    block(handle)
    val bodyStmts = stmts.toList()
    stmts.clear()
    stmts.addAll(savedStmts)
    addStmt(BpfStmt.IfNonNull(expr.expr, v, bodyStmts))
    return IfNonNullBuilder(v, bodyStmts, expr.expr, this)
}

class IfNonNullBuilder(
    private val variable: Variable,
    private val body: List<BpfStmt>,
    private val expr: BpfExpr,
    private val builder: ProgramBodyBuilder,
) {
    fun elseThen(block: () -> Unit) {
        val saved = builder.stmts.toList()
        builder.stmts.clear()
        block()
        val elseStmts = builder.stmts.toList()
        builder.stmts.clear()
        builder.stmts.addAll(saved)
        // Replace last IfNonNull with version that has else
        val lastIndex = builder.stmts.indexOfLast { it is BpfStmt.IfNonNull }
        if (lastIndex >= 0) {
            builder.stmts[lastIndex] = BpfStmt.IfNonNull(expr, variable, body, elseStmts)
        }
    }
}
```

3. Modify `CCodeGenerator.renderStmt` for `IfNonNull`:
```kotlin
is BpfStmt.IfNonNull -> {
    val v = stmt.variable
    val valueTypeName = renderTypeName(v.type)
    sb.appendLine("${pad}${valueTypeName} *${v.name} = ${renderExpr(stmt.expr)};")
    sb.appendLine("${pad}if (${v.name}) {")
    for (s in stmt.body) renderStmt(sb, s, indent + 1)
    if (stmt.else_ != null) {
        sb.appendLine("${pad}} else {")
        for (s in stmt.else_) renderStmt(sb, s, indent + 1)
    }
    sb.appendLine("${pad}}")
}
```

4. Update `collectPointerVars` to also walk the else branch:
```kotlin
is BpfStmt.IfNonNull -> {
    pointerVars.add(stmt.variable.name)
    collectPointerVars(stmt.body)
    stmt.else_?.let { collectPointerVars(it) }
}
```

5. Update `TypeChecker` and `SemanticAnalyzer` to walk the else branch of IfNonNull (same pattern as the body — just add `stmt.else_?.let { walkStmts(it) }` wherever they walk `stmt.body`).

**Step 4: Run tests**

Run: `cd /Users/jongsu/kotlin-ebpf-dsl && ./gradlew test 2>&1`
Expected: ALL PASS (172 existing + 2 new)

**Step 5: Commit**

```bash
cd /Users/jongsu/kotlin-ebpf-dsl
git add -A && git commit -m "feat: add else branch to ifNonNull for lookup-or-insert pattern"
```

---

### Task 2: Add scalar-keyed map support and BPF flag constants

kpod-metrics uses maps with scalar keys/values (e.g., `wakeup_ts` is `__u32` → `__u64`). The DSL currently only supports `BpfStruct` keys/values in map factories. Also add `BPF_ANY`, `BPF_NOEXIST`, `BPF_EXIST` constants.

**Files:**
- Modify: `/Users/jongsu/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/api/EbpfProgramBuilder.kt`
- Modify: `/Users/jongsu/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/api/ProgramBodyBuilder.kt`
- Modify: `/Users/jongsu/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/api/MapHandle.kt`
- Test: `/Users/jongsu/kotlin-ebpf-dsl/src/test/kotlin/dev/ebpf/dsl/api/ScalarMapTest.kt`

**Step 1: Write the failing test**

```kotlin
package dev.ebpf.dsl.api

import dev.ebpf.dsl.types.BpfScalar
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class ScalarMapTest {

    @Test
    fun `hashMap with scalar key and value generates correct C`() {
        val program = ebpf("scalar_map") {
            license("GPL")
            val tsMap by scalarHashMap(
                keyType = BpfScalar.U32,
                valueType = BpfScalar.U64,
                maxEntries = 10240,
                mapName = "wakeup_ts"
            )
            tracepoint("sched", "sched_wakeup") {
                val pid = declareVar("pid", literal(42u, BpfScalar.U32))
                val ts = declareVar("ts", ktimeGetNs())
                tsMap.update(pid, ts, flags = BPF_ANY)
                returnValue(literal(0, BpfScalar.S32))
            }
        }

        val c = program.generateC()
        assertThat(c).contains("__type(key, __u32)")
        assertThat(c).contains("__type(value, __u64)")
        assertThat(c).contains("bpf_map_update_elem(&wakeup_ts, &pid, &ts, 0)")
    }

    @Test
    fun `BPF flag constants have correct values`() {
        val program = ebpf("flags") {
            license("GPL")
            val m by scalarHashMap(BpfScalar.U32, BpfScalar.U64, 1024, mapName = "m")
            tracepoint("sched", "sched_switch") {
                val k = declareVar("k", literal(1u, BpfScalar.U32))
                val v = declareVar("v", literal(2u, BpfScalar.U64))
                m.update(k, v, flags = BPF_NOEXIST)
                returnValue(literal(0, BpfScalar.S32))
            }
        }

        val c = program.generateC()
        assertThat(c).contains(", 1)")  // BPF_NOEXIST = 1
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/jongsu/kotlin-ebpf-dsl && ./gradlew test --tests "dev.ebpf.dsl.api.ScalarMapTest" 2>&1`
Expected: FAIL — `scalarHashMap` doesn't exist

**Step 3: Implement**

1. Add BPF flag constants to `ProgramBodyBuilder`:
```kotlin
@Suppress("PropertyName")
val BPF_ANY = 0L
@Suppress("PropertyName")
val BPF_NOEXIST = 1L
@Suppress("PropertyName")
val BPF_EXIST = 2L
```

2. Add `scalarHashMap` and `scalarLruHashMap` to `EbpfProgramBuilder`:
```kotlin
fun scalarHashMap(keyType: BpfScalar, valueType: BpfScalar, maxEntries: Int, mapName: String? = null) =
    ScalarMapDelegate(MapType.HASH, keyType, valueType, maxEntries, mapName)

fun scalarLruHashMap(keyType: BpfScalar, valueType: BpfScalar, maxEntries: Int, mapName: String? = null) =
    ScalarMapDelegate(MapType.LRU_HASH, keyType, valueType, maxEntries, mapName)

inner class ScalarMapDelegate(
    private val type: MapType,
    private val keyType: BpfScalar,
    private val valueType: BpfScalar,
    private val maxEntries: Int,
    private val explicitName: String?,
) {
    operator fun provideDelegate(thisRef: Any?, prop: KProperty<*>): ReadOnlyProperty<Any?, MapHandle> {
        val mapName = explicitName ?: BpfStruct.camelToSnake(prop.name)
        require(_mapNames.add(mapName)) { "Duplicate map name: '$mapName'" }
        val decl = MapDecl(mapName, type, keyType, valueType, maxEntries)
        _maps.add(decl)
        val handle = MapHandle(decl)
        return ReadOnlyProperty { _, _ -> handle }
    }
}
```

3. Update `CCodeGenerator.renderMap` to handle scalar types in `__type()` — check `renderTypeName()` which already handles `BpfScalar` via its `cName` property. Verify it renders `__type(key, __u32)` not `__type(key, struct __u32)`.

4. Update `MapHandle.lookup` in `ProgramBodyBuilder` to handle maps where `valueType` is a scalar (currently it force-unwraps `this.decl.valueType!!`). For scalar values, the lookup returns a pointer to that scalar.

**Step 4: Run tests**

Run: `cd /Users/jongsu/kotlin-ebpf-dsl && ./gradlew test 2>&1`
Expected: ALL PASS

**Step 5: Commit**

```bash
cd /Users/jongsu/kotlin-ebpf-dsl
git add -A && git commit -m "feat: add scalar-keyed map support and BPF flag constants"
```

---

### Task 3: Add preamble support

kpod-metrics BPF programs use `log2l()`, `DEFINE_STATS_MAP`, and `STATS_INC` macros. These need to be emitted as raw C before the struct/map definitions.

**Files:**
- Modify: `/Users/jongsu/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/api/BpfProgramModel.kt`
- Modify: `/Users/jongsu/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/api/EbpfProgramBuilder.kt`
- Modify: `/Users/jongsu/kotlin-ebpf-dsl/src/main/kotlin/dev/ebpf/dsl/codegen/CCodeGenerator.kt`
- Test: `/Users/jongsu/kotlin-ebpf-dsl/src/test/kotlin/dev/ebpf/dsl/codegen/PreambleTest.kt`

**Step 1: Write the failing test**

```kotlin
package dev.ebpf.dsl.codegen

import dev.ebpf.dsl.api.*
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class PreambleTest {

    object K : BpfStruct("k") { val id by u64() }
    object V : BpfStruct("v") { val count by u64() }

    @Test
    fun `preamble is emitted after includes and before structs`() {
        val program = ebpf("preamble_test") {
            license("GPL")
            preamble("""
static __always_inline __u32 log2l(__u64 v) {
    __u32 r = 0;
    while (v > 1) { v >>= 1; r++; }
    return r;
}
            """.trimIndent())
            val m by lruHashMap(K, V, maxEntries = 1024, mapName = "m")
            tracepoint("sched", "sched_switch") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }

        val c = program.generateC()
        val includePos = c.indexOf("#include")
        val preamblePos = c.indexOf("log2l")
        val structPos = c.indexOf("struct k {")
        assertThat(preamblePos).isGreaterThan(includePos)
        assertThat(preamblePos).isLessThan(structPos)
    }
}
```

**Step 2: Run test to verify it fails**

**Step 3: Implement**

1. Add `preamble` field to `BpfProgramModel`:
```kotlin
data class BpfProgramModel(
    val name: String,
    val license: String?,
    val maps: List<MapDecl>,
    val programs: List<ProgramDef>,
    val structs: Set<BpfStruct>,
    val preamble: String? = null,
)
```

2. Add `preamble()` to `EbpfProgramBuilder`:
```kotlin
private var _preamble: String? = null

fun preamble(code: String) {
    _preamble = code
}
```
And include it in `build()`.

3. In `CCodeGenerator.generate()`, emit preamble after license, before structs:
```kotlin
if (model.preamble != null) {
    sb.appendLine(model.preamble)
    sb.appendLine()
}
```

**Step 4: Run tests**

Run: `cd /Users/jongsu/kotlin-ebpf-dsl && ./gradlew test 2>&1`
Expected: ALL PASS

**Step 5: Commit**

```bash
cd /Users/jongsu/kotlin-ebpf-dsl
git add -A && git commit -m "feat: add preamble support for raw C helpers and macros"
git push
```

---

## Phase 2: kpod-metrics Integration Setup

### Task 4: Composite build + DSL dependency + generateBpf task

Wire kpod-metrics to consume kotlin-ebpf-dsl via Gradle composite build. Create the `generateBpf` Gradle task and the package structure for DSL program definitions.

**Files:**
- Modify: `/Users/jongsu/dev/kpod-metrics/settings.gradle.kts`
- Modify: `/Users/jongsu/dev/kpod-metrics/build.gradle.kts`
- Create: `/Users/jongsu/dev/kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/bpf/programs/GenerateBpf.kt` (stub)

**Step 1: Modify settings.gradle.kts**

Add composite build:
```kotlin
rootProject.name = "kpod-metrics"

includeBuild("../kotlin-ebpf-dsl")
```

**Step 2: Modify build.gradle.kts**

Add DSL dependency and generateBpf task:
```kotlin
dependencies {
    // ... existing deps ...
    implementation("dev.ebpf:kotlin-ebpf-dsl")
}

val generateBpf = tasks.register<JavaExec>("generateBpf") {
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.internal.kpodmetrics.bpf.programs.GenerateBpfKt")
    // Output dirs for up-to-date checking
    outputs.dir(layout.buildDirectory.dir("generated/bpf"))
    outputs.dir(layout.buildDirectory.dir("generated/kotlin"))
}

sourceSets["main"].kotlin.srcDir(layout.buildDirectory.dir("generated/kotlin"))

tasks.named("compileKotlin") {
    dependsOn(generateBpf)
}
```

**Step 3: Create stub GenerateBpf.kt**

```kotlin
package com.internal.kpodmetrics.bpf.programs

fun main() {
    println("generateBpf: no programs defined yet")
}
```

**Step 4: Verify build works**

Run: `cd /Users/jongsu/dev/kpod-metrics && ./gradlew generateBpf 2>&1`
Expected: SUCCESS, prints "no programs defined yet"

Run: `cd /Users/jongsu/dev/kpod-metrics && ./gradlew compileKotlin 2>&1`
Expected: SUCCESS (composite build resolves kotlin-ebpf-dsl)

**Step 5: Commit**

```bash
cd /Users/jongsu/dev/kpod-metrics
git add settings.gradle.kts build.gradle.kts src/main/kotlin/com/internal/kpodmetrics/bpf/programs/GenerateBpf.kt
git commit -m "feat: add kotlin-ebpf-dsl composite build and generateBpf task"
```

---

## Phase 3: Program Definitions

### Task 5: Shared structs + mem program definition

Define the shared BPF structs (from `common.h`) and the `mem` program in DSL form. Test that the generated C is structurally equivalent to the hand-written `mem.bpf.c`.

**Files:**
- Create: `/Users/jongsu/dev/kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/bpf/programs/Structs.kt`
- Create: `/Users/jongsu/dev/kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/bpf/programs/MemProgram.kt`
- Test: `/Users/jongsu/dev/kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/bpf/programs/MemProgramTest.kt`

**Context for implementer:**

The hand-written `mem.bpf.c` has:
- 2 LRU_HASH maps: `oom_kills` and `major_faults` (key=`counter_key`, value=`counter_value`)
- 2 stats PERCPU_ARRAY maps via `DEFINE_STATS_MAP` macro
- `tp/oom/mark_victim` — gets cgroup_id, does lookup-or-insert on `oom_kills`
- `kprobe/handle_mm_fault` — checks `flags & 0x4` for major faults, then lookup-or-insert on `major_faults`

Shared structs from `common.h`:
```c
struct counter_key { __u64 cgroup_id; };
struct counter_value { __u64 count; };
struct hist_key { __u64 cgroup_id; };
struct hist_value { __u64 slots[27]; __u64 count; __u64 sum_ns; };
```

The kprobe uses `BPF_KPROBE(handle_page_fault, struct vm_area_struct *vma, unsigned long address, unsigned int flags)`. In DSL, use `raw("(unsigned int)PT_REGS_PARM3(ctx)", BpfScalar.U32)` to access the flags parameter.

For `DEFINE_STATS_MAP` and `STATS_INC`, use `preamble()` with the macro definitions and `raw()` for STATS_INC calls in program bodies.

**Structs.kt should define:**
```kotlin
object CounterKey : BpfStruct("counter_key") { val cgroupId by u64() }
object CounterValue : BpfStruct("counter_value") { val count by u64() }
object HistKey : BpfStruct("hist_key") { val cgroupId by u64() }
object HistValue : BpfStruct("hist_value") {
    val slots by array(BpfScalar.U64, 27)
    val count by u64()
    val sumNs by u64()
}
```

**Preamble content** (shared across all programs that need it):
```kotlin
val COMMON_PREAMBLE = """
#define MAX_ENTRIES 10240
#define MAX_SLOTS 27

enum map_stat_idx {
    MAP_STAT_ENTRIES = 0,
    MAP_STAT_UPDATE_ERRORS = 1,
    MAP_STAT_MAX = 2,
};

#define DEFINE_STATS_MAP(name) \
struct { \
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); \
    __uint(max_entries, MAP_STAT_MAX); \
    __type(key, __u32); \
    __type(value, __s64); \
} name##_stats SEC(".maps");

#define STATS_INC(map, idx) do { \
    __u32 _k = (idx); \
    __s64 *_v = bpf_map_lookup_elem(&map, &_k); \
    if (_v) __sync_fetch_and_add(_v, 1); \
} while(0)

#define STATS_DEC(map, idx) do { \
    __u32 _k = (idx); \
    __s64 *_v = bpf_map_lookup_elem(&map, &_k); \
    if (_v) __sync_fetch_and_add(_v, -1); \
} while(0)

static __always_inline __u32 log2l(__u64 v) {
    __u32 r = 0;
    while (v > 1) { v >>= 1; r++; }
    return r;
}
""".trimIndent()
```

**Test assertions:** Generated C contains `SEC("tp/oom/mark_victim")`, `SEC("kprobe/handle_mm_fault")`, `oom_kills`, `major_faults`, `BPF_MAP_TYPE_LRU_HASH`, `__sync_fetch_and_add`, `bpf_map_update_elem`, `DEFINE_STATS_MAP`, `STATS_INC`. Validation passes with no errors.

**Step 1:** Write test
**Step 2:** Run test, verify fail
**Step 3:** Implement Structs.kt + MemProgram.kt
**Step 4:** Run test, verify pass
**Step 5:** Commit

```bash
git commit -m "feat: add shared BPF structs and mem program DSL definition"
```

---

### Task 6: cpu_sched program definition

**Files:**
- Create: `/Users/jongsu/dev/kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/bpf/programs/CpuSchedProgram.kt`
- Test: `/Users/jongsu/dev/kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/bpf/programs/CpuSchedProgramTest.kt`

**Context for implementer:**

The hand-written `cpu_sched.bpf.c` has:
- `wakeup_ts` — HASH map, key=`__u32` (PID), value=`__u64` (timestamp). This is a **scalar** map (not struct).
- `runq_latency` — LRU_HASH, key=`hist_key`, value=`hist_value`
- `ctx_switches` — LRU_HASH, key=`counter_key`, value=`counter_value`
- Stats maps for runq_latency and ctx_switches

Programs:
1. `tp/sched/sched_wakeup` — reads `ctx->pid` via `raw()`, stores PID→timestamp in `wakeup_ts`
2. `tp/sched/sched_switch` — reads `ctx->next_pid` via `raw()`, does lookup-or-insert on `ctx_switches`, then looks up `wakeup_ts` by PID, calculates delta, uses `log2l()` for histogram slot, lookup-or-insert on `runq_latency`

The tracepoint context field access uses:
```kotlin
val nextPid = declareVar("next_pid", raw("((struct trace_event_raw_sched_switch *)ctx)->next_pid", BpfScalar.U32))
```

For `bpf_map_delete_elem` on `wakeup_ts`, use the existing `mapHandle.delete(key)` DSL method.

For `log2l(delta_ns)`, use `raw("log2l(delta_ns)", BpfScalar.U32)` (the preamble defines the function).

For the `wakeup_ts` scalar map, use `scalarHashMap(BpfScalar.U32, BpfScalar.U64, ...)` from Task 2.

**Test assertions:** Generated C contains `SEC("tp/sched/sched_wakeup")`, `SEC("tp/sched/sched_switch")`, `wakeup_ts`, `runq_latency`, `ctx_switches`, `bpf_map_delete_elem`, `log2l`, `DEFINE_STATS_MAP`. Validation passes.

**Step 1-5:** TDD cycle, commit:
```bash
git commit -m "feat: add cpu_sched program DSL definition"
```

---

### Task 7: net program definition

**Files:**
- Create: `/Users/jongsu/dev/kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/bpf/programs/NetProgram.kt`
- Test: `/Users/jongsu/dev/kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/bpf/programs/NetProgramTest.kt`

**Context for implementer:**

The hand-written `net.bpf.c` has:

Additional struct:
```c
struct tcp_stats {
    __u64 bytes_sent;
    __u64 bytes_received;
    __u64 retransmits;
    __u64 connections;
    __u64 rtt_sum_us;
    __u64 rtt_count;
};
```

Define as:
```kotlin
object TcpStats : BpfStruct("tcp_stats") {
    val bytesSent by u64()
    val bytesReceived by u64()
    val retransmits by u64()
    val connections by u64()
    val rttSumUs by u64()
    val rttCount by u64()
}
```

Maps:
- `tcp_stats_map` — LRU_HASH, key=`counter_key`, value=`tcp_stats`
- `rtt_hist` — LRU_HASH, key=`hist_key`, value=`hist_value`
- Stats maps for both

5 programs:
1. `kprobe/tcp_sendmsg` — `size` = 3rd arg via `raw("PT_REGS_PARM3(ctx)", BpfScalar.U64)`, lookup-or-insert on `tcp_stats_map`, atomicAdd bytes_sent
2. `kprobe/tcp_recvmsg` — `len` = 3rd arg, same pattern for bytes_received
3. `tp/tcp/tcp_retransmit_skb` — lookup-or-insert, atomicAdd retransmits
4. `tp/sock/inet_sock_set_state` — check `ctx->newstate == 1` (TCP_ESTABLISHED), lookup-or-insert connections
5. `tp/tcp/tcp_probe` — read `ctx->srtt`, atomicAdd rtt_sum_us + rtt_count, plus histogram update on `rtt_hist`

Note: `tp/sock/inet_sock_set_state` and `tp/tcp/tcp_probe` are additional tracepoint categories. The DSL's `tracepoint("sock", "inet_sock_set_state")` and `tracepoint("tcp", "tcp_probe")` should generate `SEC("tp/sock/inet_sock_set_state")` and `SEC("tp/tcp/tcp_probe")` respectively.

**Test assertions:** Generated C contains all 5 SEC annotations, `tcp_stats` struct with 6 fields, both maps, `log2l`, atomic ops. Validation passes.

**Step 1-5:** TDD cycle, commit:
```bash
git commit -m "feat: add net program DSL definition"
```

---

### Task 8: syscall program definition

**Files:**
- Create: `/Users/jongsu/dev/kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/bpf/programs/SyscallProgram.kt`
- Test: `/Users/jongsu/dev/kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/bpf/programs/SyscallProgramTest.kt`

**Context for implementer:**

Additional structs:
```c
struct syscall_key { __u64 cgroup_id; __u32 syscall_nr; __u32 _pad; };
struct syscall_stats { __u64 count; __u64 error_count; __u64 latency_sum_ns; __u64 latency_slots[27]; };
```

Define as:
```kotlin
object SyscallKey : BpfStruct("syscall_key") {
    val cgroupId by u64()
    val syscallNr by u32()
    val pad by u32(cName = "_pad")  // explicit padding
}

object SyscallStats : BpfStruct("syscall_stats") {
    val count by u64()
    val errorCount by u64()
    val latencySumNs by u64()
    val latencySlots by array(BpfScalar.U64, 27)
}
```

Maps:
- `syscall_start` — HASH, key=`__u64` (pid_tgid), value=`__u64` (timestamp). Scalar map.
- `syscall_nr_map` — HASH, key=`__u64` (pid_tgid), value=`__u32` (syscall number). Scalar map.
- `syscall_stats_map` — LRU_HASH, key=`syscall_key`, value=`syscall_stats`. Map name must be ≤ 15 chars — use explicit `mapName = "syscall_stats"`.
- `tracked_syscalls` — HASH, key=`__u32`, value=`__u8`, maxEntries=64. Scalar map.
- Stats map for syscall_stats_map

Programs:
1. `raw_tracepoint/sys_enter` — read `ctx->args[1]` for syscall_nr via `raw()`, check tracked_syscalls map, store timestamp and syscall_nr
2. `raw_tracepoint/sys_exit` — read `ctx->args[1]` for return value, lookup start timestamp, calculate delta, lookup-or-insert on syscall_stats_map with histogram

Note: Uses `rawTracepoint("sys_enter")` and `rawTracepoint("sys_exit")` in the DSL, which generates `SEC("raw_tp/sys_enter")`.

The raw tracepoint context is `struct bpf_raw_tracepoint_args *ctx`. Access args via `raw("ctx->args[1]", BpfScalar.U32)`.

**Test assertions:** Generated C contains `SEC("raw_tp/sys_enter")`, `SEC("raw_tp/sys_exit")`, all 4 maps, `syscall_key` struct with padding, `bpf_map_delete_elem` for cleanup. Validation passes.

**Step 1-5:** TDD cycle, commit:
```bash
git commit -m "feat: add syscall program DSL definition"
```

---

### Task 9: GenerateBpf.kt entry point

Wire up all 4 program definitions into the `GenerateBpf.kt` main function that validates and emits C + Kotlin.

**Files:**
- Modify: `/Users/jongsu/dev/kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/bpf/programs/GenerateBpf.kt`

**Step 1: Implement**

```kotlin
package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.OutputConfig
import dev.ebpf.dsl.api.emit
import dev.ebpf.dsl.api.validate

fun main() {
    val programs = listOf(memProgram, cpuSchedProgram, netProgram, syscallProgram)

    // Validate all programs
    programs.forEach { prog ->
        val result = prog.validate()
        if (result.errors.isNotEmpty()) {
            System.err.println("Validation failed for ${prog.name}:")
            result.errors.forEach { System.err.println("  ERROR [${it.code}]: ${it.message}") }
            System.exit(1)
        }
        result.warnings.forEach { println("  WARNING [${it.code}]: ${it.message}") }
    }

    // Emit C + Kotlin
    val config = OutputConfig(
        cDir = "build/generated/bpf",
        kotlinDir = "build/generated/kotlin",
        kotlinPackage = "com.internal.kpodmetrics.bpf.generated"
    )
    programs.forEach { it.emit(config) }

    println("Generated ${programs.size} BPF programs")
    programs.forEach { println("  - ${it.name}") }
}
```

**Step 2: Run generateBpf task**

Run: `cd /Users/jongsu/dev/kpod-metrics && ./gradlew generateBpf 2>&1`
Expected: SUCCESS, prints 4 program names, creates files in `build/generated/`

**Step 3: Verify generated files**

Run: `ls -la build/generated/bpf/ && ls -la build/generated/kotlin/com/internal/kpodmetrics/bpf/generated/`
Expected: 4 `.bpf.c` files + 4 `*MapReader.kt` files

**Step 4: Verify full build works**

Run: `cd /Users/jongsu/dev/kpod-metrics && ./gradlew compileKotlin 2>&1`
Expected: SUCCESS (generated MapReader classes compile along with existing code)

**Step 5: Commit**

```bash
git commit -m "feat: wire GenerateBpf entry point with all 4 programs"
```

---

## Phase 4: Collector Rewrite

### Task 10: Rewrite MemoryCollector and CpuSchedulingCollector

Replace manual ByteBuffer parsing with generated MapReader layout decode methods.

**Files:**
- Modify: `/Users/jongsu/dev/kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/MemoryCollector.kt`
- Modify: `/Users/jongsu/dev/kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/CpuSchedulingCollector.kt`

**Context for implementer:**

After `./gradlew generateBpf` runs, there will be generated `*MapReader.kt` files in `build/generated/kotlin/com/internal/kpodmetrics/bpf/generated/`. These contain layout objects like:

```kotlin
object CounterKeyLayout {
    const val SIZE = 8
    const val CGROUP_ID_OFFSET = 0
    fun decodeCgroupId(bytes: ByteArray): Long = ...
}
object CounterValueLayout {
    const val SIZE = 8
    const val COUNT_OFFSET = 0
    fun decodeCount(bytes: ByteArray): Long = ...
}
object HistValueLayout {
    const val SIZE = 232
    fun decodeSlotsArray(bytes: ByteArray): LongArray = ...
    fun decodeCount(bytes: ByteArray): Long = ...
    fun decodeSumNs(bytes: ByteArray): Long = ...
}
```

**Changes to MemoryCollector:**
- Remove `KEY_SIZE` and `COUNTER_VALUE_SIZE` constants — use `CounterKeyLayout.SIZE` and `CounterValueLayout.SIZE`
- Replace `ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN).long` with `CounterKeyLayout.decodeCgroupId(keyBytes)`
- Replace `ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN).long` with `CounterValueLayout.decodeCount(valueBytes)`

**Changes to CpuSchedulingCollector:**
- Replace `KEY_SIZE`, `HIST_VALUE_SIZE`, `COUNTER_VALUE_SIZE` with layout constants
- Replace histogram ByteBuffer parsing with `HistValueLayout.decodeSlotsArray()`, `.decodeCount()`, `.decodeSumNs()`
- Replace counter parsing with `CounterValueLayout.decodeCount()`

**Important:** First run `./gradlew generateBpf` to ensure the MapReader classes exist before modifying the collectors. The generated classes need to be on the classpath.

**Testing:** Run existing collector tests. If there are mockk-based tests for these collectors, they should still pass since the collector API (inputs/outputs) doesn't change — only the internal deserialization changes.

Run: `cd /Users/jongsu/dev/kpod-metrics && ./gradlew test 2>&1`
Expected: ALL PASS

**Commit:**
```bash
git commit -m "refactor: use generated MapReader in MemoryCollector and CpuSchedulingCollector"
```

---

### Task 11: Rewrite NetworkCollector and SyscallCollector

**Files:**
- Modify: `/Users/jongsu/dev/kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/NetworkCollector.kt`
- Modify: `/Users/jongsu/dev/kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/SyscallCollector.kt`

**Context for implementer:**

Generated layout objects for NetworkCollector:
```kotlin
object TcpStatsLayout {
    const val SIZE = 48
    fun decodeBytesSent(bytes: ByteArray): Long = ...
    fun decodeBytesReceived(bytes: ByteArray): Long = ...
    fun decodeRetransmits(bytes: ByteArray): Long = ...
    fun decodeConnections(bytes: ByteArray): Long = ...
    fun decodeRttSumUs(bytes: ByteArray): Long = ...
    fun decodeRttCount(bytes: ByteArray): Long = ...
}
```

Generated layout objects for SyscallCollector:
```kotlin
object SyscallKeyLayout {
    const val SIZE = 16
    fun decodeCgroupId(bytes: ByteArray): Long = ...
    fun decodeSyscallNr(bytes: ByteArray): Int = ...
}
object SyscallStatsLayout {
    const val SIZE = 240
    fun decodeCount(bytes: ByteArray): Long = ...
    fun decodeErrorCount(bytes: ByteArray): Long = ...
    fun decodeLatencySumNs(bytes: ByteArray): Long = ...
    fun decodeLatencySlotsArray(bytes: ByteArray): LongArray = ...
}
```

**Changes to NetworkCollector:**
- Replace `TCP_STATS_VALUE_SIZE` with `TcpStatsLayout.SIZE`
- Replace 6-field ByteBuffer parsing with individual decode calls

**Changes to SyscallCollector:**
- Replace `KEY_SIZE`, `VALUE_SIZE` with layout constants
- Replace key parsing (cgroupId + syscallNr + skip padding) with `SyscallKeyLayout.decodeCgroupId()` and `SyscallKeyLayout.decodeSyscallNr()`
- Replace value parsing with `SyscallStatsLayout.decodeCount()` etc.

**Testing:** Run existing tests + full build.

**Commit:**
```bash
git commit -m "refactor: use generated MapReader in NetworkCollector and SyscallCollector"
```

---

## Phase 5: Cleanup

### Task 12: Delete hand-written BPF C files and update Dockerfile

**Files:**
- Delete: `/Users/jongsu/dev/kpod-metrics/bpf/common.h`
- Delete: `/Users/jongsu/dev/kpod-metrics/bpf/mem.bpf.c`
- Delete: `/Users/jongsu/dev/kpod-metrics/bpf/cpu_sched.bpf.c`
- Delete: `/Users/jongsu/dev/kpod-metrics/bpf/net.bpf.c`
- Delete: `/Users/jongsu/dev/kpod-metrics/bpf/syscall.bpf.c`
- Modify: `/Users/jongsu/dev/kpod-metrics/Dockerfile`

**Context for implementer:**

The Dockerfile currently has a stage that compiles `bpf/*.bpf.c` with clang. Update it to:
1. Add a Gradle stage that runs `./gradlew generateBpf` to produce `build/generated/bpf/*.bpf.c`
2. Change the clang compilation stage to compile from `build/generated/bpf/` instead of `bpf/`

Keep `bpf/vmlinux.h` if it exists (it's a kernel header, not generated). If there's no `vmlinux.h` in the bpf/ directory (it's typically generated or downloaded at build time), then the entire `bpf/` directory can be removed.

**Testing:**
- Verify `./gradlew generateBpf` still produces all 4 `.bpf.c` files
- Verify the generated C files contain all the same maps, programs, and struct definitions as the deleted ones
- Run `./gradlew test` to verify nothing breaks

**Commit:**
```bash
git commit -m "chore: remove hand-written BPF C files, now generated by DSL"
```
