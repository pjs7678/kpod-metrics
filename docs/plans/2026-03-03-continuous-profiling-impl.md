# Continuous Profiling Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add eBPF-based CPU profiling to kpod-metrics, pushing pprof profiles to Pyroscope.

**Architecture:** A hand-written BPF program (`cpu_profile.bpf.c`) uses `perf_event` sampling at 99Hz to collect kernel+user stack traces per cgroup. A new JNI method attaches it to perf_events on each CPU. The `CpuProfileCollector` drains the maps every 29s, resolves symbols via `/proc/kallsyms` and ELF symtab, builds pprof protobuf, and pushes to Pyroscope's ingest API. Java workloads use Pyroscope's existing Java agent (Helm sidecar).

**Tech Stack:** BPF C (perf_event + STACK_TRACE map), JNI/C (perf_event_open syscall), Kotlin (collector + symbol resolver + pprof builder), protobuf (pprof format), OkHttp (Pyroscope push)

**Design doc:** `docs/plans/2026-03-03-continuous-profiling-design.md`

---

## Phase 1: BPF Program + Map Drain

### Task 1: Write the BPF program (hand-written C)

The DSL doesn't support `perf_event` or `BPF_MAP_TYPE_STACK_TRACE`. Write raw C.

**Files:**
- Create: `bpf/cpu_profile.bpf.c`

**Step 1: Write the BPF program**

```c
// bpf/cpu_profile.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_STACK_DEPTH 128
#define MAX_PROFILE_ENTRIES 65536
#define MAX_STACK_ENTRIES 32768

struct profile_key {
    __u64 cgroup_id;
    __u32 tgid;
    __s32 kern_stack_id;
    __s32 user_stack_id;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, MAX_STACK_ENTRIES);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_PROFILE_ENTRIES);
    __type(key, struct profile_key);
    __type(value, __u64);
} profile_counts SEC(".maps");

SEC("perf_event")
int cpu_profile(struct bpf_perf_event_data *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u64 tgid_pid = bpf_get_current_pid_tgid();
    __u32 tgid = tgid_pid >> 32;

    __s32 kern_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
    __s32 user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);

    struct profile_key key = {
        .cgroup_id = cgroup_id,
        .tgid = tgid,
        .kern_stack_id = kern_stack_id,
        .user_stack_id = user_stack_id,
    };

    __u64 *count = bpf_map_lookup_elem(&profile_counts, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&profile_counts, &key, &one, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

**Step 2: Commit**

```bash
git add bpf/cpu_profile.bpf.c
git commit -m "feat(profiling): add cpu_profile BPF program for perf_event sampling"
```

---

### Task 2: Add JNI method for perf_event attachment

`attachAll()` uses `bpf_program__attach()` which doesn't work for perf_event programs (they need a target CPU). Add a new JNI method that calls `perf_event_open()` per CPU and attaches the BPF program.

**Files:**
- Modify: `jni/bpf_bridge.h`
- Modify: `jni/bpf_bridge.c`
- Modify: `src/main/kotlin/com/internal/kpodmetrics/bpf/BpfBridge.kt`

**Step 1: Add C header declaration**

Append to `jni/bpf_bridge.h` before the closing `#endif`:

```c
JNIEXPORT jint JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativePerfEventAttach(
    JNIEnv *env, jobject self, jlong objPtr, jstring progName, jint sampleFreq);
```

**Step 2: Implement in C**

Append to `jni/bpf_bridge.c`:

```c
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static int perf_event_open_cpu(int cpu, int freq) {
    struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_CPU_CLOCK,
        .sample_freq = freq,
        .freq = 1,
        .size = sizeof(attr),
    };
    return syscall(__NR_perf_event_open, &attr, -1 /* all pids */, cpu, -1, PERF_FLAG_FD_CLOEXEC);
}

JNIEXPORT jint JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativePerfEventAttach(
    JNIEnv *env, jobject self, jlong ptr, jstring progName, jint sampleFreq) {
    (void)self;
    if (ptr == 0) {
        throw_load_exception(env, "Null BPF object pointer");
        return -1;
    }
    struct bpf_obj_wrapper *wrapper = (struct bpf_obj_wrapper *)(uintptr_t)ptr;
    const char *name_str = (*env)->GetStringUTFChars(env, progName, NULL);
    if (!name_str) {
        throw_load_exception(env, "Failed to get program name string");
        return -1;
    }
    struct bpf_program *prog = bpf_object__find_program_by_name(wrapper->obj, name_str);
    (*env)->ReleaseStringUTFChars(env, progName, name_str);
    if (!prog) {
        throw_load_exception(env, "BPF program not found");
        return -1;
    }
    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        throw_load_exception(env, "BPF program fd not available");
        return -1;
    }

    int num_cpus = libbpf_num_possible_cpus();
    int attached = 0;
    for (int cpu = 0; cpu < num_cpus; cpu++) {
        if (wrapper->link_count >= MAX_BPF_LINKS) break;
        int perf_fd = perf_event_open_cpu(cpu, sampleFreq);
        if (perf_fd < 0) continue; /* CPU may be offline */
        if (ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd) != 0) {
            close(perf_fd);
            continue;
        }
        ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
        /* Store as bpf_link via perf_event attach for cleanup */
        struct bpf_link *link = bpf_program__attach_perf_event(prog, perf_fd);
        if (link) {
            wrapper->links[wrapper->link_count++] = link;
            attached++;
        } else {
            close(perf_fd);
        }
    }
    return attached;
}
```

**Step 3: Add Kotlin JNI declaration and wrapper**

Add to `BpfBridge.kt` — native declaration alongside the others:

```kotlin
private external fun nativePerfEventAttach(objPtr: Long, progName: String, sampleFreq: Int): Int
```

Public wrapper:

```kotlin
fun perfEventAttach(handle: Long, progName: String, sampleFreq: Int): Int {
    val ptr = handleRegistry.resolve(handle)
    return nativePerfEventAttach(ptr, progName, sampleFreq)
}
```

**Step 4: Commit**

```bash
git add jni/bpf_bridge.h jni/bpf_bridge.c src/main/kotlin/com/internal/kpodmetrics/bpf/BpfBridge.kt
git commit -m "feat(profiling): add JNI perfEventAttach for per-CPU perf_event BPF attachment"
```

---

### Task 3: Update Dockerfile to compile cpu_profile.bpf.c

The hand-written BPF file needs to be copied alongside the generated files in Stage 2.

**Files:**
- Modify: `Dockerfile`

**Step 1: Add COPY for hand-written BPF file in Stage 2**

After line `COPY --from=codegen /build/build/generated/bpf/ /build/bpf/`, add:

```dockerfile
# Hand-written BPF programs (not generated by DSL)
COPY kpod-metrics/bpf/cpu_profile.bpf.c /build/bpf/cpu_profile.bpf.c
```

The existing `for f in /build/bpf/*.bpf.c` loop will automatically pick it up for both CO-RE and legacy builds.

**Step 2: Commit**

```bash
git add Dockerfile
git commit -m "build: include cpu_profile.bpf.c in BPF compilation stages"
```

---

### Task 4: Add profiling configuration properties

**Files:**
- Modify: `src/main/kotlin/com/internal/kpodmetrics/config/MetricsProperties.kt`

**Step 1: Add ProfilingProperties data class and wire it**

Add after `OtlpProperties`:

```kotlin
data class ProfilingProperties(
    val enabled: Boolean = false,
    val cpu: CpuProfilingProperties = CpuProfilingProperties(),
    val pyroscope: PyroscopeProperties = PyroscopeProperties(),
    val symbolCacheMaxEntries: Int = 50000
)

data class CpuProfilingProperties(
    val enabled: Boolean = true,
    val frequency: Int = 99,
    val stackDepth: Int = 128
)

data class PyroscopeProperties(
    val endpoint: String = "http://pyroscope:4040",
    val tenantId: String = "",
    val authToken: String = ""
)
```

Add to `MetricsProperties`:

```kotlin
val profiling: ProfilingProperties = ProfilingProperties()
```

**Step 2: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/config/MetricsProperties.kt
git commit -m "feat(profiling): add profiling configuration properties"
```

---

### Task 5: Load cpu_profile program in BpfProgramManager

**Files:**
- Modify: `src/main/kotlin/com/internal/kpodmetrics/bpf/BpfProgramManager.kt`

**Step 1: Add perf_event loading path**

Add after `loadAll()` method:

```kotlin
fun loadCpuProfile(sampleFreq: Int) {
    try {
        val path = "$resolvedProgramDir/cpu_profile.bpf.o"
        log.info("Loading CPU profile BPF program: {}", path)
        val sample = registry?.let { Timer.start() }
        val handle = bridge.openObject(path)
        bridge.loadObject(handle)
        val cpuCount = bridge.perfEventAttach(handle, "cpu_profile", sampleFreq)
        loadedPrograms["cpu_profile"] = handle
        sample?.stop(Timer.builder("kpod.bpf.program.load.duration")
            .tag("program", "cpu_profile")
            .register(registry!!))
        log.info("CPU profile BPF program attached to {} CPUs at {}Hz", cpuCount, sampleFreq)
    } catch (e: Exception) {
        log.warn("Failed to load CPU profile BPF program: {}", e.message)
        _failedPrograms.add("cpu_profile")
    }
}
```

**Step 2: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/bpf/BpfProgramManager.kt
git commit -m "feat(profiling): add loadCpuProfile to BpfProgramManager"
```

---

### Task 6: Write CpuProfileCollector (map drain only, no symbols yet)

**Files:**
- Create: `src/main/kotlin/com/internal/kpodmetrics/collector/CpuProfileCollector.kt`
- Create: `src/test/kotlin/com/internal/kpodmetrics/collector/CpuProfileCollectorTest.kt`

**Step 1: Write the test**

```kotlin
package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.PodInfo
import io.mockk.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CpuProfileCollectorTest {

    private lateinit var bridge: BpfBridge
    private lateinit var programManager: BpfProgramManager
    private lateinit var cgroupResolver: CgroupResolver
    private lateinit var collector: CpuProfileCollector

    @BeforeEach
    fun setup() {
        bridge = mockk(relaxed = true)
        programManager = mockk(relaxed = true)
        cgroupResolver = CgroupResolver()
        collector = CpuProfileCollector(bridge, programManager, cgroupResolver)
    }

    @Test
    fun `collect drains profile_counts and groups by pod`() {
        val cgroupId = 12345L
        cgroupResolver.register(cgroupId, PodInfo("uid1", "cid1", "default", "myapp", "main"))
        every { programManager.getMapFd("cpu_profile", "profile_counts") } returns 10
        every { programManager.getMapFd("cpu_profile", "stack_traces") } returns 11

        // profile_counts entry: (cgroup_id=12345, tgid=100, kern_stack=1, user_stack=2) -> count=50
        val key = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(cgroupId).putInt(100).putInt(1).putInt(2).array()
        val value = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(50).array()
        every { bridge.mapBatchLookupAndDelete(10, 20, 8, any()) } returns listOf(key to value)

        // stack_traces: stack_id=1 -> [0xaddr1, 0xaddr2], stack_id=2 -> [0xaddr3]
        val stackKey1 = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(1).array()
        val stackKey2 = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(2).array()
        val stackVal1 = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(0xFFFF_1234L).putLong(0xFFFF_5678L).array()
        val stackVal2 = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(0x0040_1000L).array()

        every { bridge.mapLookup(11, stackKey1, any()) } returns stackVal1
        every { bridge.mapLookup(11, stackKey2, any()) } returns stackVal2

        val profiles = collector.collect()

        assertEquals(1, profiles.size)
        val podProfile = profiles.entries.first()
        assertEquals("myapp", podProfile.key.podName)
        assertEquals(1, podProfile.value.size)
        assertEquals(50L, podProfile.value[0].count)
    }

    @Test
    fun `collect skips unresolved cgroups`() {
        every { programManager.getMapFd("cpu_profile", "profile_counts") } returns 10
        every { programManager.getMapFd("cpu_profile", "stack_traces") } returns 11

        val key = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(99999L).putInt(100).putInt(1).putInt(2).array()
        val value = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(10).array()
        every { bridge.mapBatchLookupAndDelete(10, 20, 8, any()) } returns listOf(key to value)

        val profiles = collector.collect()
        assertTrue(profiles.isEmpty())
    }
}
```

**Step 2: Run test to verify it fails**

Run: `./gradlew test --tests "*CpuProfileCollectorTest*" --info`
Expected: FAIL (CpuProfileCollector class doesn't exist yet)

**Step 3: Write CpuProfileCollector**

```kotlin
package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.PodInfo
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

data class StackSample(
    val tgid: Int,
    val kernelStackIps: LongArray,
    val userStackIps: LongArray,
    val count: Long
)

class CpuProfileCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val maxStackDepth: Int = 128
) {
    private val log = LoggerFactory.getLogger(CpuProfileCollector::class.java)

    companion object {
        private const val MAX_ENTRIES = 65536
        private const val PROFILE_KEY_SIZE = 20  // u64 + u32 + i32 + i32
        private const val PROFILE_VALUE_SIZE = 8 // u64
    }

    /**
     * Drains the BPF maps and returns stack samples grouped by pod.
     */
    fun collect(): Map<PodInfo, List<StackSample>> {
        val countsFd = programManager.getMapFd("cpu_profile", "profile_counts")
        val stacksFd = programManager.getMapFd("cpu_profile", "stack_traces")

        val entries = bridge.mapBatchLookupAndDelete(countsFd, PROFILE_KEY_SIZE, PROFILE_VALUE_SIZE, MAX_ENTRIES)
        if (entries.isEmpty()) return emptyMap()

        // Collect unique stack IDs to resolve
        val stackCache = HashMap<Int, LongArray>()
        val result = HashMap<PodInfo, MutableList<StackSample>>()

        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long
            val tgid = buf.int
            val kernStackId = buf.int
            val userStackId = buf.int
            val count = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN).long

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue
            if (count <= 0) continue

            val kernIps = if (kernStackId >= 0) {
                stackCache.getOrPut(kernStackId) { readStack(stacksFd, kernStackId) }
            } else LongArray(0)

            val userIps = if (userStackId >= 0) {
                stackCache.getOrPut(userStackId) { readStack(stacksFd, userStackId) }
            } else LongArray(0)

            result.getOrPut(podInfo) { mutableListOf() }
                .add(StackSample(tgid, kernIps, userIps, count))
        }

        log.debug("Collected {} profile entries for {} pods ({} unique stacks)",
            entries.size, result.size, stackCache.size)
        return result
    }

    private fun readStack(stacksFd: Int, stackId: Int): LongArray {
        val key = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(stackId).array()
        val valueSize = maxStackDepth * 8
        val raw = bridge.mapLookup(stacksFd, key, valueSize) ?: return LongArray(0)

        val buf = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN)
        val ips = mutableListOf<Long>()
        while (buf.remaining() >= 8) {
            val ip = buf.long
            if (ip == 0L) break
            ips.add(ip)
        }
        return ips.toLongArray()
    }
}
```

**Step 4: Run test to verify it passes**

Run: `./gradlew test --tests "*CpuProfileCollectorTest*" --info`
Expected: PASS

**Step 5: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/collector/CpuProfileCollector.kt \
        src/test/kotlin/com/internal/kpodmetrics/collector/CpuProfileCollectorTest.kt
git commit -m "feat(profiling): add CpuProfileCollector with map drain and pod grouping"
```

---

### Task 7: Wire profiling into BpfAutoConfiguration

**Files:**
- Modify: `src/main/kotlin/com/internal/kpodmetrics/config/BpfAutoConfiguration.kt`

**Step 1: Add bean and startup wiring**

Add bean method:

```kotlin
@Bean
@ConditionalOnProperty("kpod.profiling.enabled", havingValue = "true")
fun cpuProfileCollector(
    bridge: BpfBridge,
    manager: BpfProgramManager,
    resolver: CgroupResolver
) = CpuProfileCollector(bridge, manager, resolver, props.profiling.cpu.stackDepth)
```

In `onStartup()`, after `it.loadAll()`, add:

```kotlin
if (props.profiling.enabled && props.profiling.cpu.enabled) {
    try {
        it.loadCpuProfile(props.profiling.cpu.frequency)
    } catch (e: Exception) {
        log.warn("CPU profiling BPF program failed to load: {}", e.message)
    }
}
```

**Step 2: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/config/BpfAutoConfiguration.kt
git commit -m "feat(profiling): wire CpuProfileCollector into Spring configuration"
```

---

## Phase 2: Symbol Resolution

### Task 8: Implement KallsymsResolver (kernel symbols)

**Files:**
- Create: `src/main/kotlin/com/internal/kpodmetrics/profiling/KallsymsResolver.kt`
- Create: `src/test/kotlin/com/internal/kpodmetrics/profiling/KallsymsResolverTest.kt`

**Step 1: Write the test**

```kotlin
package com.internal.kpodmetrics.profiling

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class KallsymsResolverTest {

    @Test
    fun `resolves kernel address to symbol`() {
        val resolver = KallsymsResolver.fromLines(listOf(
            "ffffffff81000000 T _stext",
            "ffffffff81000100 T cpu_startup_entry",
            "ffffffff81000200 T do_idle"
        ))
        assertEquals("cpu_startup_entry", resolver.resolve(0xffffffff81000100u.toLong()))
        assertEquals("cpu_startup_entry", resolver.resolve(0xffffffff81000150u.toLong()))
        assertEquals("do_idle", resolver.resolve(0xffffffff81000200u.toLong()))
    }

    @Test
    fun `returns null for address below first symbol`() {
        val resolver = KallsymsResolver.fromLines(listOf(
            "ffffffff81000000 T _stext"
        ))
        assertNull(resolver.resolve(0x1000L))
    }
}
```

**Step 2: Run test to verify it fails**

Run: `./gradlew test --tests "*KallsymsResolverTest*" --info`

**Step 3: Implement KallsymsResolver**

```kotlin
package com.internal.kpodmetrics.profiling

import java.io.File
import java.util.TreeMap

class KallsymsResolver private constructor(
    private val symbols: TreeMap<Long, String>
) {
    companion object {
        fun fromFile(path: String = "/proc/kallsyms"): KallsymsResolver {
            return fromLines(File(path).readLines())
        }

        fun fromLines(lines: List<String>): KallsymsResolver {
            val symbols = TreeMap<Long, String>()
            for (line in lines) {
                val parts = line.split(" ", limit = 3)
                if (parts.size < 3) continue
                val addr = parts[0].toLongOrNull(16) ?: continue
                val name = parts[2].substringBefore('\t')
                if (addr != 0L) symbols[addr] = name
            }
            return KallsymsResolver(symbols)
        }
    }

    fun resolve(addr: Long): String? {
        val entry = symbols.floorEntry(addr) ?: return null
        return entry.value
    }
}
```

**Step 4: Run test, verify pass**

Run: `./gradlew test --tests "*KallsymsResolverTest*" --info`

**Step 5: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/profiling/KallsymsResolver.kt \
        src/test/kotlin/com/internal/kpodmetrics/profiling/KallsymsResolverTest.kt
git commit -m "feat(profiling): add KallsymsResolver for kernel symbol resolution"
```

---

### Task 9: Implement ElfSymbolResolver (userspace symbols)

**Files:**
- Create: `src/main/kotlin/com/internal/kpodmetrics/profiling/ElfSymbolResolver.kt`
- Create: `src/test/kotlin/com/internal/kpodmetrics/profiling/ElfSymbolResolverTest.kt`

**Step 1: Write the test**

```kotlin
package com.internal.kpodmetrics.profiling

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class ElfSymbolResolverTest {

    @Test
    fun `resolves address via proc maps and simulated symtab`() {
        // Simulate /proc/<pid>/maps line: "00400000-00500000 r-xp ... /usr/bin/myapp"
        val maps = listOf(
            ProcMapEntry(0x400000L, 0x500000L, 0L, "/usr/bin/myapp")
        )
        // Simulate symbols: offset 0x1000 = "main", offset 0x2000 = "doWork"
        val symtab = mapOf(
            0x1000L to "main",
            0x2000L to "doWork"
        )
        val resolver = ElfSymbolResolver(maps, mapOf("/usr/bin/myapp" to symtab))

        assertEquals("main", resolver.resolve(0x401000L))
        assertEquals("doWork", resolver.resolve(0x402000L))
    }

    @Test
    fun `returns binary+offset for unknown symbol`() {
        val maps = listOf(
            ProcMapEntry(0x400000L, 0x500000L, 0L, "/usr/bin/myapp")
        )
        val resolver = ElfSymbolResolver(maps, emptyMap())
        val result = resolver.resolve(0x401000L)
        assertNotNull(result)
        assertEquals("[/usr/bin/myapp+0x1000]", result)
    }
}
```

**Step 2: Run test, verify fail**

**Step 3: Implement**

```kotlin
package com.internal.kpodmetrics.profiling

data class ProcMapEntry(
    val start: Long,
    val end: Long,
    val fileOffset: Long,
    val pathname: String
)

class ElfSymbolResolver(
    private val maps: List<ProcMapEntry>,
    private val symtabs: Map<String, Map<Long, String>>
) {
    companion object {
        fun parseProcMaps(lines: List<String>): List<ProcMapEntry> {
            return lines.mapNotNull { line ->
                // Format: start-end perms offset dev inode pathname
                val parts = line.trim().split(Regex("\\s+"), limit = 6)
                if (parts.size < 6) return@mapNotNull null
                if (!parts[1].contains('x')) return@mapNotNull null // only executable mappings
                val (startStr, endStr) = parts[0].split("-")
                val start = startStr.toLongOrNull(16) ?: return@mapNotNull null
                val end = endStr.toLongOrNull(16) ?: return@mapNotNull null
                val offset = parts[2].toLongOrNull(16) ?: 0L
                val pathname = parts[5]
                if (pathname.startsWith("[")) return@mapNotNull null // skip [vdso], [stack], etc.
                ProcMapEntry(start, end, offset, pathname)
            }
        }
    }

    fun resolve(addr: Long): String? {
        val mapping = maps.find { addr in it.start until it.end } ?: return null
        val fileOffset = addr - mapping.start + mapping.fileOffset
        val symtab = symtabs[mapping.pathname]
        if (symtab != null) {
            // Find the closest symbol at or before the offset
            val sorted = symtab.entries.sortedBy { it.key }
            val symbol = sorted.lastOrNull { it.key <= fileOffset }
            if (symbol != null) return symbol.value
        }
        return "[${mapping.pathname}+0x${fileOffset.toString(16)}]"
    }
}
```

**Step 4: Run test, verify pass**

**Step 5: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/profiling/ElfSymbolResolver.kt \
        src/test/kotlin/com/internal/kpodmetrics/profiling/ElfSymbolResolverTest.kt
git commit -m "feat(profiling): add ElfSymbolResolver for userspace symbol resolution"
```

---

### Task 10: Implement SymbolResolver facade

Combines kernel + userspace resolution with caching.

**Files:**
- Create: `src/main/kotlin/com/internal/kpodmetrics/profiling/SymbolResolver.kt`
- Create: `src/test/kotlin/com/internal/kpodmetrics/profiling/SymbolResolverTest.kt`

**Step 1: Write test**

```kotlin
package com.internal.kpodmetrics.profiling

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class SymbolResolverTest {

    @Test
    fun `resolves kernel address via kallsyms`() {
        val kallsyms = KallsymsResolver.fromLines(listOf(
            "ffffffff81000000 T do_idle",
            "ffffffff81000100 T cpu_startup_entry"
        ))
        val resolver = SymbolResolver(kallsyms)

        val result = resolver.resolveKernel(0xffffffff81000000u.toLong())
        assertEquals("do_idle", result)
    }

    @Test
    fun `resolves user address via proc maps`() {
        val kallsyms = KallsymsResolver.fromLines(emptyList())
        val resolver = SymbolResolver(kallsyms)

        val maps = listOf(ProcMapEntry(0x400000L, 0x500000L, 0L, "/usr/bin/app"))
        val symtab = mapOf(0x1000L to "main")
        val elfResolver = ElfSymbolResolver(maps, mapOf("/usr/bin/app" to symtab))

        val result = resolver.resolveUser(0x401000L, elfResolver)
        assertEquals("main", result)
    }
}
```

**Step 2: Implement**

```kotlin
package com.internal.kpodmetrics.profiling

import org.slf4j.LoggerFactory
import java.io.File
import java.util.concurrent.ConcurrentHashMap

class SymbolResolver(
    private val kallsyms: KallsymsResolver,
    private val cacheMaxEntries: Int = 50000
) {
    private val log = LoggerFactory.getLogger(SymbolResolver::class.java)
    private val userResolverCache = ConcurrentHashMap<Int, ElfSymbolResolver>() // tgid -> resolver
    private val symbolCache = ConcurrentHashMap<Long, String>() // addr -> symbol

    fun resolveKernel(addr: Long): String {
        return symbolCache.getOrPut(addr) {
            kallsyms.resolve(addr) ?: "[kernel+0x${addr.toULong().toString(16)}]"
        }
    }

    fun resolveUser(addr: Long, elfResolver: ElfSymbolResolver): String {
        return elfResolver.resolve(addr) ?: "[unknown+0x${addr.toULong().toString(16)}]"
    }

    fun getOrCreateElfResolver(tgid: Int): ElfSymbolResolver? {
        return userResolverCache.getOrPut(tgid) {
            try {
                val mapsLines = File("/proc/$tgid/maps").readLines()
                val maps = ElfSymbolResolver.parseProcMaps(mapsLines)
                // TODO: Phase 2b — parse ELF symtab from binaries
                ElfSymbolResolver(maps, emptyMap())
            } catch (e: Exception) {
                log.debug("Cannot read /proc/{}/maps: {}", tgid, e.message)
                return null
            }
        }
    }

    fun evictProcess(tgid: Int) {
        userResolverCache.remove(tgid)
    }

    fun trimCache() {
        if (symbolCache.size > cacheMaxEntries) {
            val toRemove = symbolCache.size - cacheMaxEntries
            symbolCache.keys.take(toRemove).forEach { symbolCache.remove(it) }
        }
    }
}
```

**Step 3: Run test, verify pass**

**Step 4: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/profiling/SymbolResolver.kt \
        src/test/kotlin/com/internal/kpodmetrics/profiling/SymbolResolverTest.kt
git commit -m "feat(profiling): add SymbolResolver facade with kernel + userspace resolution"
```

---

## Phase 3: pprof + Pyroscope Push

### Task 11: Add protobuf dependency and pprof proto

**Files:**
- Modify: `build.gradle.kts`
- Modify: `gradle/libs.versions.toml` (if exists, otherwise `build.gradle.kts`)

Add dependency:

```kotlin
implementation("com.google.protobuf:protobuf-kotlin:4.29.3")
```

Use the pprof proto from Google's perftools: generate a Kotlin data class that builds pprof `Profile` protobuf manually (or use the well-known proto). The simplest approach: write a `PprofBuilder` that constructs the protobuf bytes directly using protobuf-java's `CodedOutputStream`.

**Commit after adding dependency.**

---

### Task 12: Implement PprofBuilder

**Files:**
- Create: `src/main/kotlin/com/internal/kpodmetrics/profiling/PprofBuilder.kt`
- Create: `src/test/kotlin/com/internal/kpodmetrics/profiling/PprofBuilderTest.kt`

Builds a pprof `Profile` protobuf from resolved stack samples. The pprof format:
- `string_table`: all unique strings (function names, filenames)
- `function`: function entries referencing string_table
- `location`: locations with line referencing function
- `sample`: each sample has location_ids + value (count)
- `sample_type`: `{type: "cpu", unit: "nanoseconds"}`

**Test**: construct a PprofBuilder, add samples, serialize, verify protobuf is parseable.

**Commit after test passes.**

---

### Task 13: Implement PyroscopePusher

**Files:**
- Create: `src/main/kotlin/com/internal/kpodmetrics/profiling/PyroscopePusher.kt`
- Create: `src/test/kotlin/com/internal/kpodmetrics/profiling/PyroscopePusherTest.kt`

HTTP POST to Pyroscope `/ingest` endpoint with gzip-compressed pprof. Uses Spring's `RestTemplate` or OkHttp (Spring Boot already includes an HTTP client).

```
POST /ingest?name=kpod.cpu{namespace=X,pod=Y,node=Z}&sampleRate=99&from=T1&until=T2&format=pprof
Content-Type: application/x-protobuf
Content-Encoding: gzip
X-Scope-OrgID: <tenantId>  (if configured)
Authorization: Bearer <token> (if configured)
Body: <gzip pprof bytes>
```

**Commit after test passes.**

---

### Task 14: Wire profiling pipeline end-to-end

**Files:**
- Modify: `src/main/kotlin/com/internal/kpodmetrics/collector/CpuProfileCollector.kt`
- Modify: `src/main/kotlin/com/internal/kpodmetrics/config/BpfAutoConfiguration.kt`
- Modify: `src/main/kotlin/com/internal/kpodmetrics/collector/MetricsCollectorService.kt`

Integrate the full pipeline: `CpuProfileCollector.collect()` → `SymbolResolver` → `PprofBuilder` → `PyroscopePusher`. Add the profiling collector to `MetricsCollectorService`'s collection cycle.

**Commit after integration.**

---

### Task 15: Update Helm chart

**Files:**
- Modify: `helm/kpod-metrics/values.yaml`
- Modify: `helm/kpod-metrics/templates/configmap.yaml`

Add profiling configuration to values and configmap template.

**Commit.**

---

## Phase 4: Java Agent Integration (Helm only)

### Task 16: Add Helm template for Pyroscope Java agent sidecar

**Files:**
- Create: `helm/kpod-metrics/templates/_java-profiler.tpl`
- Modify: `helm/kpod-metrics/values.yaml`
- Modify: `helm/kpod-metrics/templates/NOTES.txt`

Provide a Helm helper template that other charts can use to inject the Pyroscope Java agent as a sidecar. Document the `JAVA_TOOL_OPTIONS` approach.

**Commit.**

---

## Summary

| Task | Phase | Deliverable |
|------|-------|-------------|
| 1 | 1 | BPF program `cpu_profile.bpf.c` |
| 2 | 1 | JNI `perfEventAttach()` |
| 3 | 1 | Dockerfile compilation |
| 4 | 1 | Profiling config properties |
| 5 | 1 | BpfProgramManager loading |
| 6 | 1 | CpuProfileCollector (map drain) |
| 7 | 1 | Spring wiring |
| 8 | 2 | KallsymsResolver |
| 9 | 2 | ElfSymbolResolver |
| 10 | 2 | SymbolResolver facade |
| 11 | 3 | Protobuf dependency |
| 12 | 3 | PprofBuilder |
| 13 | 3 | PyroscopePusher |
| 14 | 3 | End-to-end wiring |
| 15 | 3 | Helm config |
| 16 | 4 | Java agent Helm template |
