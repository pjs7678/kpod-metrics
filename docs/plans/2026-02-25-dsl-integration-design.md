# kotlin-ebpf-dsl Integration Design

**Goal:** Replace hand-written BPF C programs in kpod-metrics with DSL-generated code from kotlin-ebpf-dsl, and replace manual ByteBuffer deserialization in collectors with generated MapReader classes.

**Architecture:** Gradle composite build links the two repos. A custom `generateBpf` Gradle task runs DSL definitions at build time, producing `.bpf.c` files and Kotlin MapReader classes. Collectors are rewritten to use generated decode methods.

**Tech Stack:** kotlin-ebpf-dsl (local composite build), Gradle JavaExec task, existing clang/libbpf/JNI pipeline unchanged.

---

## Section 1: Module Structure & Dependency Wiring

Single-module kpod-metrics with composite build:

```
kpod-metrics/
  settings.gradle.kts       ← add: includeBuild("../kotlin-ebpf-dsl")
  build.gradle.kts           ← add: implementation("dev.ebpf:kotlin-ebpf-dsl")
                                     + generateBpf task
  src/main/kotlin/
    com/internal/kpodmetrics/
      bpf/programs/           ← NEW: DSL program definitions
        GenerateBpf.kt        ← main() entry point for codegen task
        Structs.kt            ← shared BpfStruct definitions
        MemProgram.kt
        CpuSchedProgram.kt
        NetProgram.kt
        SyscallProgram.kt
  build/generated/
    bpf/                      ← generated .bpf.c files
    kotlin/                   ← generated MapReader classes
```

**settings.gradle.kts** adds:
```kotlin
includeBuild("../kotlin-ebpf-dsl")
```

**build.gradle.kts** adds:
```kotlin
dependencies {
    implementation("dev.ebpf:kotlin-ebpf-dsl")
}

val generateBpf = tasks.register<JavaExec>("generateBpf") {
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.internal.kpodmetrics.bpf.programs.GenerateBpfKt")
}
sourceSets["main"].kotlin.srcDir("build/generated/kotlin")
tasks.named("compileKotlin") { dependsOn(generateBpf) }
```

No multi-module setup needed. The DSL definitions are regular Kotlin source in the main module. Generated Kotlin goes to `build/generated/kotlin/` which is added as a source directory.

---

## Section 2: BPF Program Definitions

### Shared Structs

From `common.h`, mapped to DSL:

```kotlin
object CounterKey : BpfStruct("counter_key") {
    val cgroupId by u64()
}

object CounterValue : BpfStruct("counter_value") {
    val count by u64()
}

object HistKey : BpfStruct("hist_key") {
    val cgroupId by u64()
}

object HistValue : BpfStruct("hist_value") {
    val slots by array(BpfScalar.U64, 27)
    val count by u64()
    val sumNs by u64()
}
```

### Programs

| Program | Hooks | Maps | Notes |
|---------|-------|------|-------|
| `mem` | `tp/oom/mark_victim`, `kprobe/handle_mm_fault` | `oom_kills`, `major_faults` + stats | kprobe uses `BPF_KPROBE` macro via `raw()` |
| `cpu_sched` | `tp/sched/sched_wakeup`, `tp/sched/sched_switch` | `wakeup_ts`, `runq_latency`, `ctx_switches` + stats | `log2l()` via preamble, cross-map PID lookup |
| `net` | `kprobe/tcp_sendmsg`, `kprobe/tcp_recvmsg`, `tp/tcp/tcp_retransmit_skb` | `tcp_stats_map`, `rtt_hist` + stats | multi-field value struct |
| `syscall` | syscall enter/exit tracepoints | `syscall_stats` + stats | counter pattern |

### Lookup-or-insert pattern

Every program uses this C pattern:
```c
val = bpf_map_lookup_elem(&map, &key);
if (val) {
    __sync_fetch_and_add(&val->count, 1);
} else {
    struct counter_value new_val = { .count = 1 };
    bpf_map_update_elem(&map, &key, &new_val, BPF_NOEXIST);
}
```

The DSL will express this with the new `ifNonNull` else branch:
```kotlin
ifNonNull(map.lookup(key)) { entry ->
    entry[CounterValue.count].atomicAdd(literal(1u, BpfScalar.U64))
}.elseThen {
    val newVal = stackVar(CounterValue) {
        it[CounterValue.count] = literal(1u, BpfScalar.U64)
    }
    map.update(key, newVal, flags = BPF_NOEXIST)
}
```

---

## Section 3: Collector Rewrite

Collectors keep their existing structure but replace manual ByteBuffer parsing with generated decode methods:

```kotlin
// Before (manual):
val buf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
val slots = LongArray(27) { buf.long }
val count = buf.long
val sumNs = buf.long

// After (generated MapReader layout objects):
val slots = HistValueLayout.decodeSlotsArray(valueBytes)
val count = HistValueLayout.decodeCount(valueBytes)
val sumNs = HistValueLayout.decodeSumNs(valueBytes)
```

What stays the same:
- `BpfBridge`, `BpfProgramManager`, `CgroupResolver` untouched
- `bridge.mapBatchLookupAndDelete()` call pattern unchanged
- Micrometer metric recording unchanged
- Spring Boot wiring unchanged

The generated `readXxx()` batch methods in MapReader classes are available but optional — kpod-metrics uses its own BpfBridge API for map reads.

---

## Section 4: Build Pipeline & Codegen Task

### GenerateBpf.kt

```kotlin
fun main() {
    val programs = listOf(memProgram, cpuSchedProgram, netProgram, syscallProgram)
    programs.forEach { prog ->
        prog.validate().throwOnError()
        prog.emit(OutputConfig(
            cDir = "build/generated/bpf",
            kotlinDir = "build/generated/kotlin",
            kotlinPackage = "com.internal.kpodmetrics.bpf.generated"
        ))
    }
}
```

### Dockerfile changes

Current flow:
```
Stage 1: clang compiles bpf/*.bpf.c → *.bpf.o
Stage 2: cmake builds JNI
Stage 3: gradle builds Kotlin app
```

New flow:
```
Stage 1: gradle generateBpf → build/generated/bpf/*.bpf.c
Stage 2: clang compiles build/generated/bpf/*.bpf.c → *.bpf.o
Stage 3: cmake builds JNI (unchanged)
Stage 4: gradle builds Kotlin app (with generated MapReader on classpath)
```

Stage 1 needs a JDK + Gradle to run the codegen task. The generated C files are then passed to clang in Stage 2.

### Cleanup

After all 4 programs are ported:
- Delete `bpf/cpu_sched.bpf.c`, `bpf/mem.bpf.c`, `bpf/net.bpf.c`, `bpf/syscall.bpf.c`
- Delete `bpf/common.h`
- Keep `bpf/vmlinux.h` if used, or reference it from the build output

---

## Section 5: DSL Extensions Required

Changes to kotlin-ebpf-dsl repo:

### 1. Else branch for ifNonNull (required)

Add optional else body to `BpfStmt.IfNonNull`:
```kotlin
data class IfNonNull(
    val expr: BpfExpr, val variable: Variable,
    val body: List<BpfStmt>,
    val else_: List<BpfStmt>?  // NEW
)
```

Add `IfNonNullBuilder` to `ProgramBodyBuilder`:
```kotlin
fun ifNonNull(expr: ExprHandle, block: (ExprHandle) -> Unit): IfNonNullBuilder
```

Update `CCodeGenerator` to render `} else {` block.

### 2. Map update flags constants (required)

Add to `ProgramBodyBuilder`:
```kotlin
val BPF_ANY = 0L
val BPF_NOEXIST = 1L
val BPF_EXIST = 2L
```

### 3. Preamble support (required)

Add optional preamble to `BpfProgramModel`:
```kotlin
data class BpfProgramModel(
    ...
    val preamble: String? = null  // raw C code emitted before structs
)
```

Used for `log2l()` inline helper and `DEFINE_STATS_MAP` / `STATS_INC` macros. Builder gets:
```kotlin
fun preamble(code: String)
```

---

## Section 6: Testing Strategy

### DSL extension tests (in kotlin-ebpf-dsl)
- `ifNonNull` with else branch: IR construction + C codegen output
- Map update with flags: verify `BPF_NOEXIST` renders in C
- Preamble: verify raw C appears before struct definitions

### Integration tests (in kpod-metrics)
- Each DSL program definition: build → validate → generateC
- Assert structural equivalence with hand-written C: same map names, SEC annotations, struct fields, helper calls
- Golden output comparison (not char-for-char, but key patterns)

### Existing tests
- Collector unit tests (mockk-based) stay, updated to use generated layout constants
- E2E tests (`test-local-k8s.sh`, `stress-test.sh`) validate full pipeline unchanged
