# kpod-metrics Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build an eBPF-based Kubernetes pod-level kernel metrics collector that exposes CPU scheduling, network, memory, and syscall metrics in Prometheus format via a Kotlin/Spring Boot application with JNI bridge to libbpf.

**Architecture:** Single Kotlin/Spring Boot 3.2+ process per K8s node (DaemonSet). eBPF programs written in C (CO-RE) are loaded via a JNI bridge to libbpf. Collectors poll BPF maps using Kotlin coroutines on virtual threads. Metrics exposed via Micrometer/Actuator at `/actuator/prometheus`.

**Tech Stack:** Kotlin 1.9+, Spring Boot 3.2+ (MVC, virtual threads), JDK 21, Micrometer, libbpf (C), clang/LLVM (BPF compiler), CMake (native build), Gradle (Kotlin build), Helm 3 (deployment)

**Design doc:** `docs/plans/2026-02-22-kpod-metrics-design.md`

---

## Phase 1: Project Foundation

### Task 1: Scaffold Gradle Project

**Files:**
- Create: `kpod-metrics/build.gradle.kts`
- Create: `kpod-metrics/settings.gradle.kts`
- Create: `kpod-metrics/gradle.properties`

**Step 1: Create project directory**

```bash
mkdir -p kpod-metrics
cd kpod-metrics
```

**Step 2: Write `settings.gradle.kts`**

```kotlin
rootProject.name = "kpod-metrics"
```

**Step 3: Write `build.gradle.kts`**

```kotlin
plugins {
    id("org.springframework.boot") version "3.4.3"
    id("io.spring.dependency-management") version "1.1.7"
    kotlin("jvm") version "2.1.10"
    kotlin("plugin.spring") version "2.1.10"
}

group = "com.internal"
version = "0.1.0-SNAPSHOT"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // Spring Boot
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-actuator")

    // Kotlin
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.1")

    // Prometheus metrics
    implementation("io.micrometer:micrometer-registry-prometheus")

    // Kubernetes client
    implementation("io.fabric8:kubernetes-client:7.1.0")

    // Test
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("io.mockk:mockk:1.13.16")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.1")
}

kotlin {
    compilerOptions {
        freeCompilerArgs.addAll("-Xjsr305=strict")
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}
```

**Step 4: Write `gradle.properties`**

```properties
kotlin.code.style=official
org.gradle.parallel=true
```

**Step 5: Initialize Gradle wrapper**

Run: `cd kpod-metrics && gradle wrapper --gradle-version 8.12`
Expected: `gradle/wrapper/` directory created

**Step 6: Verify build compiles**

Run: `cd kpod-metrics && ./gradlew dependencies --configuration compileClasspath`
Expected: Dependencies resolve without errors

**Step 7: Commit**

```bash
cd kpod-metrics
git init
git add build.gradle.kts settings.gradle.kts gradle.properties gradle/ gradlew gradlew.bat
git commit -m "feat: scaffold Gradle project with Spring Boot 3.4 + Kotlin"
```

---

### Task 2: Spring Boot Application Entry Point

**Files:**
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/KpodMetricsApplication.kt`
- Create: `kpod-metrics/src/main/resources/application.yml`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/KpodMetricsApplicationTest.kt`

**Step 1: Write the failing test**

```kotlin
// src/test/kotlin/com/internal/kpodmetrics/KpodMetricsApplicationTest.kt
package com.internal.kpodmetrics

import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.TestPropertySource

@SpringBootTest
@TestPropertySource(properties = [
    "kpod.node-name=test-node",
    "kpod.bpf.enabled=false"  // Disable BPF loading in tests
])
class KpodMetricsApplicationTest {

    @Test
    fun contextLoads() {
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd kpod-metrics && ./gradlew test`
Expected: FAIL — main class not found

**Step 3: Write application entry point**

```kotlin
// src/main/kotlin/com/internal/kpodmetrics/KpodMetricsApplication.kt
package com.internal.kpodmetrics

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.scheduling.annotation.EnableScheduling

@SpringBootApplication
@EnableScheduling
class KpodMetricsApplication

fun main(args: Array<String>) {
    runApplication<KpodMetricsApplication>(*args)
}
```

**Step 4: Write `application.yml`**

```yaml
# src/main/resources/application.yml
spring:
  application:
    name: kpod-metrics
  threads:
    virtual:
      enabled: true

server:
  port: 9090

management:
  endpoints:
    web:
      exposure:
        include: health, prometheus, info
  metrics:
    export:
      prometheus:
        enabled: true

kpod:
  profile: standard
  poll-interval: 15000
  node-name: ${NODE_NAME:unknown}
  bpf:
    enabled: true
    program-dir: /app/bpf
```

**Step 5: Run test to verify it passes**

Run: `cd kpod-metrics && ./gradlew test`
Expected: PASS

**Step 6: Verify Prometheus endpoint works**

Run: `cd kpod-metrics && ./gradlew bootRun &` then `curl -s http://localhost:9090/actuator/prometheus | head -5`
Expected: Prometheus text format output with JVM metrics

**Step 7: Commit**

```bash
git add src/
git commit -m "feat: add Spring Boot entry point with Actuator and Prometheus"
```

---

### Task 3: Configuration Properties and Profile System

**Files:**
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/config/MetricsProperties.kt`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/config/MetricsPropertiesTest.kt`

**Step 1: Write the failing test**

```kotlin
// src/test/kotlin/com/internal/kpodmetrics/config/MetricsPropertiesTest.kt
package com.internal.kpodmetrics.config

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.TestPropertySource

@SpringBootTest
@TestPropertySource(properties = [
    "kpod.profile=standard",
    "kpod.node-name=test-node",
    "kpod.poll-interval=15000",
    "kpod.bpf.enabled=false"
])
class MetricsPropertiesTest {

    @Autowired
    lateinit var props: MetricsProperties

    @Test
    fun `standard profile enables cpu, network, memory but not syscall`() {
        val resolved = props.resolveProfile()
        assertTrue(resolved.cpu.scheduling.enabled)
        assertTrue(resolved.cpu.throttling.enabled)
        assertTrue(resolved.network.tcp.enabled)
        assertTrue(resolved.memory.oom)
        assertTrue(resolved.memory.pageFaults)
        assertTrue(resolved.memory.cgroupStats)
        assertFalse(resolved.syscall.enabled)
    }

    @Test
    fun `minimal profile enables only cpu scheduling, throttling, oom, cgroup stats`() {
        val resolved = props.resolveProfile(override = "minimal")
        assertTrue(resolved.cpu.scheduling.enabled)
        assertTrue(resolved.cpu.throttling.enabled)
        assertFalse(resolved.network.tcp.enabled)
        assertTrue(resolved.memory.oom)
        assertFalse(resolved.memory.pageFaults)
        assertTrue(resolved.memory.cgroupStats)
        assertFalse(resolved.syscall.enabled)
    }

    @Test
    fun `comprehensive profile enables everything including syscall`() {
        val resolved = props.resolveProfile(override = "comprehensive")
        assertTrue(resolved.cpu.scheduling.enabled)
        assertTrue(resolved.network.tcp.enabled)
        assertTrue(resolved.memory.oom)
        assertTrue(resolved.syscall.enabled)
        assertTrue(resolved.syscall.trackedSyscalls.isNotEmpty())
    }

    @Test
    fun `poll interval is bound correctly`() {
        assertEquals(15000L, props.pollInterval)
    }

    @Test
    fun `node name is bound correctly`() {
        assertEquals("test-node", props.nodeName)
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd kpod-metrics && ./gradlew test --tests '*MetricsPropertiesTest*'`
Expected: FAIL — `MetricsProperties` not found

**Step 3: Write MetricsProperties**

```kotlin
// src/main/kotlin/com/internal/kpodmetrics/config/MetricsProperties.kt
package com.internal.kpodmetrics.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "kpod")
data class MetricsProperties(
    val profile: String = "standard",
    val pollInterval: Long = 15000,
    val nodeName: String = "unknown",
    val cpu: CpuProperties = CpuProperties(),
    val network: NetworkProperties = NetworkProperties(),
    val memory: MemoryProperties = MemoryProperties(),
    val syscall: SyscallProperties = SyscallProperties(),
    val filter: FilterProperties = FilterProperties(),
    val bpf: BpfProperties = BpfProperties()
) {
    fun resolveProfile(override: String? = null): ResolvedConfig {
        return when (override ?: profile) {
            "minimal" -> ResolvedConfig(
                cpu = CpuProperties(
                    scheduling = SchedulingProperties(enabled = true),
                    throttling = ThrottlingProperties(enabled = true)
                ),
                network = NetworkProperties(tcp = TcpProperties(enabled = false)),
                memory = MemoryProperties(oom = true, pageFaults = false, cgroupStats = true),
                syscall = SyscallProperties(enabled = false)
            )
            "standard" -> ResolvedConfig(
                cpu = CpuProperties(
                    scheduling = SchedulingProperties(enabled = true),
                    throttling = ThrottlingProperties(enabled = true)
                ),
                network = NetworkProperties(tcp = TcpProperties(enabled = true)),
                memory = MemoryProperties(oom = true, pageFaults = true, cgroupStats = true),
                syscall = SyscallProperties(enabled = false)
            )
            "comprehensive" -> ResolvedConfig(
                cpu = CpuProperties(
                    scheduling = SchedulingProperties(enabled = true),
                    throttling = ThrottlingProperties(enabled = true)
                ),
                network = NetworkProperties(tcp = TcpProperties(enabled = true)),
                memory = MemoryProperties(oom = true, pageFaults = true, cgroupStats = true),
                syscall = SyscallProperties(
                    enabled = true,
                    trackedSyscalls = DEFAULT_TRACKED_SYSCALLS
                )
            )
            "custom" -> ResolvedConfig(cpu = cpu, network = network, memory = memory, syscall = syscall)
            else -> throw IllegalArgumentException("Unknown profile: ${override ?: profile}")
        }
    }
}

data class ResolvedConfig(
    val cpu: CpuProperties,
    val network: NetworkProperties,
    val memory: MemoryProperties,
    val syscall: SyscallProperties
)

data class CpuProperties(
    val scheduling: SchedulingProperties = SchedulingProperties(),
    val throttling: ThrottlingProperties = ThrottlingProperties()
)

data class SchedulingProperties(
    val enabled: Boolean = true,
    val histogramBuckets: List<Double> = listOf(0.000001, 0.00001, 0.0001, 0.001, 0.01, 0.1, 1.0)
)

data class ThrottlingProperties(
    val enabled: Boolean = true
)

data class NetworkProperties(
    val tcp: TcpProperties = TcpProperties()
)

data class TcpProperties(
    val enabled: Boolean = true,
    val rttHistogramBuckets: List<Double> = listOf(0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5),
    val connectionLatencyBuckets: List<Double> = listOf(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0)
)

data class MemoryProperties(
    val oom: Boolean = true,
    val pageFaults: Boolean = true,
    val cgroupStats: Boolean = true
)

data class SyscallProperties(
    val enabled: Boolean = false,
    val trackedSyscalls: List<String> = emptyList(),
    val latencyHistogramBuckets: List<Double> = listOf(0.000001, 0.00001, 0.0001, 0.001, 0.01, 0.1)
)

data class FilterProperties(
    val namespaces: List<String> = emptyList(),
    val excludeNamespaces: List<String> = listOf("kube-system", "kube-public"),
    val labelSelector: String = ""
)

data class BpfProperties(
    val enabled: Boolean = true,
    val programDir: String = "/app/bpf"
)

val DEFAULT_TRACKED_SYSCALLS = listOf(
    "read", "write", "openat", "close", "connect",
    "accept4", "sendto", "recvfrom", "epoll_wait", "futex"
)
```

**Step 4: Enable configuration properties scanning**

```kotlin
// src/main/kotlin/com/internal/kpodmetrics/config/BpfAutoConfiguration.kt
package com.internal.kpodmetrics.config

import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Configuration

@Configuration
@EnableConfigurationProperties(MetricsProperties::class)
class BpfAutoConfiguration
```

**Step 5: Run tests to verify they pass**

Run: `cd kpod-metrics && ./gradlew test --tests '*MetricsPropertiesTest*'`
Expected: All 5 tests PASS

**Step 6: Commit**

```bash
git add src/
git commit -m "feat: add MetricsProperties with profile system (minimal/standard/comprehensive/custom)"
```

---

## Phase 2: JNI Bridge Layer

### Task 4: BPF Exception Hierarchy and Bridge Kotlin Interface

**Files:**
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/bpf/BpfException.kt`
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/bpf/BpfBridge.kt`
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/bpf/NativeHandle.kt`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/bpf/NativeHandleTest.kt`

**Step 1: Write the failing test for NativeHandle registry**

```kotlin
// src/test/kotlin/com/internal/kpodmetrics/bpf/NativeHandleTest.kt
package com.internal.kpodmetrics.bpf

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.assertThrows

class NativeHandleTest {

    @Test
    fun `register and validate handle`() {
        val registry = HandleRegistry()
        val handle = registry.register(0xDEADBEEFL)
        assertTrue(registry.isValid(handle))
    }

    @Test
    fun `invalidated handle is rejected`() {
        val registry = HandleRegistry()
        val handle = registry.register(0xDEADBEEFL)
        registry.invalidate(handle)
        assertFalse(registry.isValid(handle))
    }

    @Test
    fun `resolve returns native pointer for valid handle`() {
        val registry = HandleRegistry()
        val handle = registry.register(0xDEADBEEFL)
        assertEquals(0xDEADBEEFL, registry.resolve(handle))
    }

    @Test
    fun `resolve throws for invalidated handle`() {
        val registry = HandleRegistry()
        val handle = registry.register(0xDEADBEEFL)
        registry.invalidate(handle)
        assertThrows<BpfException> { registry.resolve(handle) }
    }

    @Test
    fun `concurrent register and resolve is safe`() {
        val registry = HandleRegistry()
        val handles = (1L..1000L).map { registry.register(it) }
        handles.parallelStream().forEach { h ->
            assertTrue(registry.isValid(h))
        }
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd kpod-metrics && ./gradlew test --tests '*NativeHandleTest*'`
Expected: FAIL — classes not found

**Step 3: Write BpfException hierarchy**

```kotlin
// src/main/kotlin/com/internal/kpodmetrics/bpf/BpfException.kt
package com.internal.kpodmetrics.bpf

sealed class BpfException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)

class BpfLoadException(message: String, cause: Throwable? = null) :
    BpfException(message, cause)

class BpfMapException(message: String, cause: Throwable? = null) :
    BpfException(message, cause)

class BpfHandleException(message: String) :
    BpfException(message)
```

**Step 4: Write HandleRegistry**

```kotlin
// src/main/kotlin/com/internal/kpodmetrics/bpf/NativeHandle.kt
package com.internal.kpodmetrics.bpf

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

class HandleRegistry {
    private val counter = AtomicLong(0)
    private val handles = ConcurrentHashMap<Long, Long>()

    fun register(nativePointer: Long): Long {
        val id = counter.incrementAndGet()
        handles[id] = nativePointer
        return id
    }

    fun isValid(handleId: Long): Boolean = handles.containsKey(handleId)

    fun resolve(handleId: Long): Long {
        return handles[handleId]
            ?: throw BpfHandleException("Invalid or stale handle: $handleId")
    }

    fun invalidate(handleId: Long) {
        handles.remove(handleId)
    }
}
```

**Step 5: Write BpfBridge Kotlin JNI interface**

```kotlin
// src/main/kotlin/com/internal/kpodmetrics/bpf/BpfBridge.kt
package com.internal.kpodmetrics.bpf

import org.slf4j.LoggerFactory

class BpfBridge {
    private val log = LoggerFactory.getLogger(BpfBridge::class.java)
    private val handleRegistry = HandleRegistry()

    companion object {
        private var loaded = false

        fun loadLibrary() {
            if (!loaded) {
                System.loadLibrary("kpod_bpf")
                loaded = true
            }
        }
    }

    // --- JNI native declarations ---

    @Throws(BpfLoadException::class)
    private external fun nativeOpenObject(path: String): Long

    @Throws(BpfLoadException::class)
    private external fun nativeLoadObject(ptr: Long): Int

    @Throws(BpfLoadException::class)
    private external fun nativeAttachAll(ptr: Long): Int

    private external fun nativeDestroyObject(ptr: Long)

    private external fun nativeGetMapFd(objPtr: Long, mapName: String): Int

    @Throws(BpfMapException::class)
    private external fun nativeMapLookup(mapFd: Int, key: ByteArray, valueSize: Int): ByteArray?

    private external fun nativeMapGetNextKey(mapFd: Int, key: ByteArray?, keySize: Int): ByteArray?

    private external fun nativeMapDelete(mapFd: Int, key: ByteArray)

    // --- Public API wrapping JNI with handle safety ---

    fun openObject(path: String): Long {
        val ptr = nativeOpenObject(path)
        return handleRegistry.register(ptr)
    }

    fun loadObject(handle: Long): Int {
        val ptr = handleRegistry.resolve(handle)
        return nativeLoadObject(ptr)
    }

    fun attachAll(handle: Long): Int {
        val ptr = handleRegistry.resolve(handle)
        return nativeAttachAll(ptr)
    }

    fun destroyObject(handle: Long) {
        val ptr = handleRegistry.resolve(handle)
        handleRegistry.invalidate(handle)
        nativeDestroyObject(ptr)
    }

    fun getMapFd(handle: Long, mapName: String): Int {
        val ptr = handleRegistry.resolve(handle)
        return nativeGetMapFd(ptr, mapName)
    }

    fun mapLookup(mapFd: Int, key: ByteArray, valueSize: Int): ByteArray? {
        return nativeMapLookup(mapFd, key, valueSize)
    }

    fun mapGetNextKey(mapFd: Int, key: ByteArray?, keySize: Int): ByteArray? {
        return nativeMapGetNextKey(mapFd, key, keySize)
    }

    fun mapDelete(mapFd: Int, key: ByteArray) {
        nativeMapDelete(mapFd, key)
    }

    fun <T> withBpfObject(path: String, block: (Long) -> T): T {
        val handle = openObject(path)
        try {
            return block(handle)
        } finally {
            try {
                destroyObject(handle)
            } catch (e: Exception) {
                log.warn("Failed to destroy BPF object: {}", e.message)
            }
        }
    }
}
```

**Step 6: Run tests to verify they pass**

Run: `cd kpod-metrics && ./gradlew test --tests '*NativeHandleTest*'`
Expected: All 5 tests PASS

**Step 7: Commit**

```bash
git add src/
git commit -m "feat: add BpfBridge JNI interface with handle registry and exception hierarchy"
```

---

### Task 5: JNI Bridge C Implementation

**Files:**
- Create: `kpod-metrics/jni/bpf_bridge.h`
- Create: `kpod-metrics/jni/bpf_bridge.c`
- Create: `kpod-metrics/jni/CMakeLists.txt`

**Step 1: Generate JNI header from Kotlin class**

Run: `cd kpod-metrics && ./gradlew compileKotlin && javac -h jni/ -cp build/classes/kotlin/main src/main/kotlin/com/internal/kpodmetrics/bpf/BpfBridge.kt` (or use `javah` equivalent)

Note: In practice, write the JNI header manually based on the Kotlin `external` declarations.

**Step 2: Write JNI header**

```c
// jni/bpf_bridge.h
#ifndef KPOD_BPF_BRIDGE_H
#define KPOD_BPF_BRIDGE_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

// Lifecycle
JNIEXPORT jlong JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeOpenObject(
    JNIEnv *env, jobject self, jstring path);

JNIEXPORT jint JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeLoadObject(
    JNIEnv *env, jobject self, jlong ptr);

JNIEXPORT jint JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeAttachAll(
    JNIEnv *env, jobject self, jlong ptr);

JNIEXPORT void JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeDestroyObject(
    JNIEnv *env, jobject self, jlong ptr);

JNIEXPORT jint JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeGetMapFd(
    JNIEnv *env, jobject self, jlong objPtr, jstring mapName);

// Map access
JNIEXPORT jbyteArray JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeMapLookup(
    JNIEnv *env, jobject self, jint mapFd, jbyteArray key, jint valueSize);

JNIEXPORT jbyteArray JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeMapGetNextKey(
    JNIEnv *env, jobject self, jint mapFd, jbyteArray key, jint keySize);

JNIEXPORT void JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeMapDelete(
    JNIEnv *env, jobject self, jint mapFd, jbyteArray key);

#ifdef __cplusplus
}
#endif

#endif // KPOD_BPF_BRIDGE_H
```

**Step 3: Write JNI C implementation**

```c
// jni/bpf_bridge.c
#include "bpf_bridge.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

// Helper: throw a Java exception from native code
static void throw_bpf_exception(JNIEnv *env, const char *class_name, const char *fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    jclass exc = (*env)->FindClass(env, class_name);
    if (exc) {
        (*env)->ThrowNew(env, exc, buf);
    }
}

static void throw_load_exception(JNIEnv *env, const char *msg) {
    throw_bpf_exception(env, "com/internal/kpodmetrics/bpf/BpfLoadException", "%s", msg);
}

static void throw_map_exception(JNIEnv *env, const char *msg) {
    throw_bpf_exception(env, "com/internal/kpodmetrics/bpf/BpfMapException", "%s", msg);
}

// --- Lifecycle ---

JNIEXPORT jlong JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeOpenObject(
    JNIEnv *env, jobject self, jstring path) {

    const char *path_str = (*env)->GetStringUTFChars(env, path, NULL);
    if (!path_str) {
        throw_load_exception(env, "Failed to get path string");
        return 0;
    }

    struct bpf_object *obj = bpf_object__open(path_str);
    (*env)->ReleaseStringUTFChars(env, path, path_str);

    if (!obj) {
        char errmsg[256];
        snprintf(errmsg, sizeof(errmsg), "Failed to open BPF object: %s (errno=%d)",
                 strerror(errno), errno);
        throw_load_exception(env, errmsg);
        return 0;
    }

    return (jlong)(uintptr_t)obj;
}

JNIEXPORT jint JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeLoadObject(
    JNIEnv *env, jobject self, jlong ptr) {

    if (ptr == 0) {
        throw_load_exception(env, "Null BPF object pointer");
        return -1;
    }

    struct bpf_object *obj = (struct bpf_object *)(uintptr_t)ptr;
    int err = bpf_object__load(obj);
    if (err) {
        char errmsg[256];
        snprintf(errmsg, sizeof(errmsg), "Failed to load BPF object: %s (errno=%d)",
                 strerror(-err), -err);
        throw_load_exception(env, errmsg);
        return err;
    }
    return 0;
}

JNIEXPORT jint JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeAttachAll(
    JNIEnv *env, jobject self, jlong ptr) {

    if (ptr == 0) {
        throw_load_exception(env, "Null BPF object pointer");
        return -1;
    }

    struct bpf_object *obj = (struct bpf_object *)(uintptr_t)ptr;
    struct bpf_program *prog;
    int err = 0;

    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) {
            char errmsg[256];
            snprintf(errmsg, sizeof(errmsg), "Failed to attach program '%s': %s",
                     bpf_program__name(prog), strerror(errno));
            throw_load_exception(env, errmsg);
            return -1;
        }
    }
    return 0;
}

JNIEXPORT void JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeDestroyObject(
    JNIEnv *env, jobject self, jlong ptr) {

    if (ptr == 0) return;
    struct bpf_object *obj = (struct bpf_object *)(uintptr_t)ptr;
    bpf_object__close(obj);
}

JNIEXPORT jint JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeGetMapFd(
    JNIEnv *env, jobject self, jlong objPtr, jstring mapName) {

    if (objPtr == 0) {
        throw_map_exception(env, "Null BPF object pointer");
        return -1;
    }

    const char *name_str = (*env)->GetStringUTFChars(env, mapName, NULL);
    if (!name_str) {
        throw_map_exception(env, "Failed to get map name string");
        return -1;
    }

    struct bpf_object *obj = (struct bpf_object *)(uintptr_t)objPtr;
    struct bpf_map *map = bpf_object__find_map_by_name(obj, name_str);
    (*env)->ReleaseStringUTFChars(env, mapName, name_str);

    if (!map) {
        char errmsg[256];
        snprintf(errmsg, sizeof(errmsg), "Map not found: %s", name_str);
        throw_map_exception(env, errmsg);
        return -1;
    }

    return bpf_map__fd(map);
}

// --- Map access ---

JNIEXPORT jbyteArray JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeMapLookup(
    JNIEnv *env, jobject self, jint mapFd, jbyteArray key, jint valueSize) {

    jsize keyLen = (*env)->GetArrayLength(env, key);
    jbyte *keyBuf = (*env)->GetByteArrayElements(env, key, NULL);
    if (!keyBuf) return NULL;

    void *valueBuf = malloc(valueSize);
    if (!valueBuf) {
        (*env)->ReleaseByteArrayElements(env, key, keyBuf, JNI_ABORT);
        throw_map_exception(env, "malloc failed for value buffer");
        return NULL;
    }

    int err = bpf_map_lookup_elem(mapFd, keyBuf, valueBuf);
    (*env)->ReleaseByteArrayElements(env, key, keyBuf, JNI_ABORT);

    if (err) {
        free(valueBuf);
        return NULL;  // Not found — not an error
    }

    jbyteArray result = (*env)->NewByteArray(env, valueSize);
    if (result) {
        (*env)->SetByteArrayRegion(env, result, 0, valueSize, (jbyte *)valueBuf);
    }
    free(valueBuf);
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeMapGetNextKey(
    JNIEnv *env, jobject self, jint mapFd, jbyteArray key, jint keySize) {

    void *nextKeyBuf = malloc(keySize);
    if (!nextKeyBuf) {
        throw_map_exception(env, "malloc failed for next key buffer");
        return NULL;
    }

    int err;
    if (key == NULL) {
        // First key
        err = bpf_map_get_next_key(mapFd, NULL, nextKeyBuf);
    } else {
        jbyte *keyBuf = (*env)->GetByteArrayElements(env, key, NULL);
        if (!keyBuf) {
            free(nextKeyBuf);
            return NULL;
        }
        err = bpf_map_get_next_key(mapFd, keyBuf, nextKeyBuf);
        (*env)->ReleaseByteArrayElements(env, key, keyBuf, JNI_ABORT);
    }

    if (err) {
        free(nextKeyBuf);
        return NULL;  // No more keys
    }

    jbyteArray result = (*env)->NewByteArray(env, keySize);
    if (result) {
        (*env)->SetByteArrayRegion(env, result, 0, keySize, (jbyte *)nextKeyBuf);
    }
    free(nextKeyBuf);
    return result;
}

JNIEXPORT void JNICALL Java_com_internal_kpodmetrics_bpf_BpfBridge_nativeMapDelete(
    JNIEnv *env, jobject self, jint mapFd, jbyteArray key) {

    jbyte *keyBuf = (*env)->GetByteArrayElements(env, key, NULL);
    if (!keyBuf) return;

    bpf_map_delete_elem(mapFd, keyBuf);
    (*env)->ReleaseByteArrayElements(env, key, keyBuf, JNI_ABORT);
}
```

**Step 4: Write CMakeLists.txt**

```cmake
# jni/CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(kpod_bpf C)

find_package(JNI REQUIRED)

# Find libbpf
find_library(LIBBPF_LIB bpf REQUIRED)
find_path(LIBBPF_INCLUDE bpf/libbpf.h REQUIRED)

add_library(kpod_bpf SHARED bpf_bridge.c)

target_include_directories(kpod_bpf PRIVATE
    ${JNI_INCLUDE_DIRS}
    ${LIBBPF_INCLUDE}
)

target_link_libraries(kpod_bpf PRIVATE
    ${LIBBPF_LIB}
    elf
    z
)

# Enable warnings
target_compile_options(kpod_bpf PRIVATE -Wall -Wextra -Werror)

install(TARGETS kpod_bpf LIBRARY DESTINATION lib)
```

**Step 5: Verify CMake configures (on Linux only)**

Run: `cd kpod-metrics/jni && cmake -B build .`
Expected: Configuration succeeds (requires libbpf-dev, JDK headers installed)

**Step 6: Commit**

```bash
git add jni/
git commit -m "feat: add JNI bridge C implementation wrapping libbpf"
```

---

## Phase 3: eBPF Programs

### Task 6: CPU Scheduling eBPF Program

**Files:**
- Create: `kpod-metrics/bpf/common.h`
- Create: `kpod-metrics/bpf/cpu_sched.bpf.c`

**Step 1: Write common BPF header with shared types**

```c
// bpf/common.h
#ifndef KPOD_COMMON_H
#define KPOD_COMMON_H

#define MAX_ENTRIES 10240
#define MAX_SLOTS 27  // log2 histogram: 1ns to ~67s

// Histogram key: cgroup ID
struct hist_key {
    __u64 cgroup_id;
};

// Histogram value: log2 buckets + count
struct hist_value {
    __u64 slots[MAX_SLOTS];
    __u64 count;
    __u64 sum_ns;
};

// Counter key: cgroup ID
struct counter_key {
    __u64 cgroup_id;
};

// Simple counter value
struct counter_value {
    __u64 count;
};

// Helper: compute log2 bucket index for a value in nanoseconds
static __always_inline __u32 log2l(__u64 v) {
    __u32 r = 0;
    while (v > 1) {
        v >>= 1;
        r++;
    }
    return r;
}

#endif // KPOD_COMMON_H
```

**Step 2: Write cpu_sched.bpf.c**

```c
// bpf/cpu_sched.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

// Map: wakeup timestamps keyed by PID (temporary, for latency calculation)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);       // pid
    __type(value, __u64);     // wakeup timestamp (ns)
} wakeup_ts SEC(".maps");

// Map: run queue latency histogram per cgroup
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct hist_key);
    __type(value, struct hist_value);
} runq_latency SEC(".maps");

// Map: context switch counter per cgroup
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct counter_key);
    __type(value, struct counter_value);
} ctx_switches SEC(".maps");

SEC("tp/sched/sched_wakeup")
int handle_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx) {
    __u32 pid = ctx->pid;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&wakeup_ts, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("tp/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    // Record context switch for the incoming task
    __u32 next_pid = ctx->next_pid;
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    // Increment context switch counter
    struct counter_key ckey = { .cgroup_id = cgroup_id };
    struct counter_value *cval = bpf_map_lookup_elem(&ctx_switches, &ckey);
    if (cval) {
        __sync_fetch_and_add(&cval->count, 1);
    } else {
        struct counter_value new_val = { .count = 1 };
        bpf_map_update_elem(&ctx_switches, &ckey, &new_val, BPF_NOEXIST);
    }

    // Calculate run queue latency for the incoming task
    __u64 *tsp = bpf_map_lookup_elem(&wakeup_ts, &next_pid);
    if (!tsp) return 0;

    __u64 delta_ns = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&wakeup_ts, &next_pid);

    // Update histogram
    struct hist_key hkey = { .cgroup_id = cgroup_id };
    struct hist_value *hval = bpf_map_lookup_elem(&runq_latency, &hkey);
    if (hval) {
        __u32 slot = log2l(delta_ns);
        if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
        __sync_fetch_and_add(&hval->slots[slot], 1);
        __sync_fetch_and_add(&hval->count, 1);
        __sync_fetch_and_add(&hval->sum_ns, delta_ns);
    } else {
        struct hist_value new_val = {};
        __u32 slot = log2l(delta_ns);
        if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
        new_val.slots[slot] = 1;
        new_val.count = 1;
        new_val.sum_ns = delta_ns;
        bpf_map_update_elem(&runq_latency, &hkey, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

**Step 3: Verify compilation (on Linux with clang/BPF target)**

Run: `clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include -c bpf/cpu_sched.bpf.c -o bpf/cpu_sched.bpf.o`
Expected: Compiles without errors

Note: `vmlinux.h` must be generated first via `bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h` on the target Linux system.

**Step 4: Commit**

```bash
git add bpf/common.h bpf/cpu_sched.bpf.c
git commit -m "feat: add CPU scheduling eBPF program (runqueue latency, context switches)"
```

---

### Task 7: Network eBPF Program

**Files:**
- Create: `kpod-metrics/bpf/net.bpf.c`

**Step 1: Write net.bpf.c**

```c
// bpf/net.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

// TCP stats per cgroup
struct tcp_stats {
    __u64 bytes_sent;
    __u64 bytes_received;
    __u64 retransmits;
    __u64 connections;
    __u64 rtt_sum_us;
    __u64 rtt_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct counter_key);
    __type(value, struct tcp_stats);
} tcp_stats_map SEC(".maps");

// Connection latency tracking: SYN_SENT timestamp per socket cookie
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);       // socket cookie
    __type(value, __u64);     // SYN_SENT timestamp
} conn_start SEC(".maps");

// Connection latency histogram per cgroup
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct hist_key);
    __type(value, struct hist_value);
} conn_latency SEC(".maps");

// RTT histogram per cgroup
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct hist_key);
    __type(value, struct hist_value);
} rtt_hist SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(handle_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct counter_key key = { .cgroup_id = cgroup_id };

    struct tcp_stats *stats = bpf_map_lookup_elem(&tcp_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->bytes_sent, size);
    } else {
        struct tcp_stats new_stats = { .bytes_sent = size };
        bpf_map_update_elem(&tcp_stats_map, &key, &new_stats, BPF_NOEXIST);
    }
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(handle_tcp_recvmsg, struct sock *sk, struct msghdr *msg,
               size_t len, int flags, int *addr_len) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct counter_key key = { .cgroup_id = cgroup_id };

    struct tcp_stats *stats = bpf_map_lookup_elem(&tcp_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->bytes_received, len);
    } else {
        struct tcp_stats new_stats = { .bytes_received = len };
        bpf_map_update_elem(&tcp_stats_map, &key, &new_stats, BPF_NOEXIST);
    }
    return 0;
}

SEC("tp/tcp/tcp_retransmit_skb")
int handle_tcp_retransmit(struct trace_event_raw_tcp_event_sk_skb *ctx) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct counter_key key = { .cgroup_id = cgroup_id };

    struct tcp_stats *stats = bpf_map_lookup_elem(&tcp_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->retransmits, 1);
    } else {
        struct tcp_stats new_stats = { .retransmits = 1 };
        bpf_map_update_elem(&tcp_stats_map, &key, &new_stats, BPF_NOEXIST);
    }
    return 0;
}

SEC("tp/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    int oldstate = ctx->oldstate;
    int newstate = ctx->newstate;
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    // Track SYN_SENT for connection latency
    if (newstate == 2) {  // TCP_SYN_SENT
        __u64 cookie = bpf_get_socket_cookie((struct sock *)0);  // TODO: get from ctx
        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&conn_start, &cookie, &ts, BPF_ANY);
    }

    // Count new ESTABLISHED connections
    if (newstate == 1) {  // TCP_ESTABLISHED
        struct counter_key key = { .cgroup_id = cgroup_id };
        struct tcp_stats *stats = bpf_map_lookup_elem(&tcp_stats_map, &key);
        if (stats) {
            __sync_fetch_and_add(&stats->connections, 1);
        } else {
            struct tcp_stats new_stats = { .connections = 1 };
            bpf_map_update_elem(&tcp_stats_map, &key, &new_stats, BPF_NOEXIST);
        }
    }

    return 0;
}

SEC("tp/tcp/tcp_probe")
int handle_tcp_probe(struct trace_event_raw_tcp_probe *ctx) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u32 srtt_us = ctx->srtt;

    struct counter_key key = { .cgroup_id = cgroup_id };
    struct tcp_stats *stats = bpf_map_lookup_elem(&tcp_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->rtt_sum_us, srtt_us);
        __sync_fetch_and_add(&stats->rtt_count, 1);
    }

    // Update RTT histogram
    struct hist_key hkey = { .cgroup_id = cgroup_id };
    __u64 rtt_ns = (__u64)srtt_us * 1000;
    struct hist_value *hval = bpf_map_lookup_elem(&rtt_hist, &hkey);
    if (hval) {
        __u32 slot = log2l(rtt_ns);
        if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
        __sync_fetch_and_add(&hval->slots[slot], 1);
        __sync_fetch_and_add(&hval->count, 1);
        __sync_fetch_and_add(&hval->sum_ns, rtt_ns);
    } else {
        struct hist_value new_val = {};
        __u32 slot = log2l(rtt_ns);
        if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
        new_val.slots[slot] = 1;
        new_val.count = 1;
        new_val.sum_ns = rtt_ns;
        bpf_map_update_elem(&rtt_hist, &hkey, &new_val, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

**Step 2: Verify compilation**

Run: `clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c bpf/net.bpf.c -o bpf/net.bpf.o`
Expected: Compiles without errors

**Step 3: Commit**

```bash
git add bpf/net.bpf.c
git commit -m "feat: add network eBPF program (TCP bytes, retransmits, RTT, connections)"
```

---

### Task 8: Memory and Syscall eBPF Programs

**Files:**
- Create: `kpod-metrics/bpf/mem.bpf.c`
- Create: `kpod-metrics/bpf/syscall.bpf.c`

**Step 1: Write mem.bpf.c**

```c
// bpf/mem.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

// OOM kill counter per cgroup
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct counter_key);
    __type(value, struct counter_value);
} oom_kills SEC(".maps");

// Major page fault counter per cgroup
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct counter_key);
    __type(value, struct counter_value);
} major_faults SEC(".maps");

SEC("tp/oom/mark_victim")
int handle_oom_kill(struct trace_event_raw_mark_victim *ctx) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct counter_key key = { .cgroup_id = cgroup_id };

    struct counter_value *val = bpf_map_lookup_elem(&oom_kills, &key);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
    } else {
        struct counter_value new_val = { .count = 1 };
        bpf_map_update_elem(&oom_kills, &key, &new_val, BPF_NOEXIST);
    }
    return 0;
}

SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(handle_page_fault, struct vm_area_struct *vma,
               unsigned long address, unsigned int flags) {
    // Only count major faults
    if (!(flags & 0x4))  // FAULT_FLAG_MAJOR = 0x4 (check vmlinux.h)
        return 0;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct counter_key key = { .cgroup_id = cgroup_id };

    struct counter_value *val = bpf_map_lookup_elem(&major_faults, &key);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
    } else {
        struct counter_value new_val = { .count = 1 };
        bpf_map_update_elem(&major_faults, &key, &new_val, BPF_NOEXIST);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

**Step 2: Write syscall.bpf.c**

```c
// bpf/syscall.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

#define MAX_TRACKED_SYSCALLS 64

// Syscall stats key: cgroup ID + syscall number
struct syscall_key {
    __u64 cgroup_id;
    __u32 syscall_nr;
    __u32 _pad;
};

// Syscall stats value
struct syscall_stats {
    __u64 count;
    __u64 error_count;
    __u64 latency_sum_ns;
    __u64 latency_slots[MAX_SLOTS];
};

// Syscall enter timestamps per task
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);       // pid_tgid
    __type(value, __u64);     // entry timestamp
} syscall_start SEC(".maps");

// Syscall number per task (to correlate enter/exit)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);       // pid_tgid
    __type(value, __u32);     // syscall_nr
} syscall_nr_map SEC(".maps");

// Aggregated syscall stats
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct syscall_key);
    __type(value, struct syscall_stats);
} syscall_stats_map SEC(".maps");

// Allowlist of tracked syscall numbers (populated from userspace)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TRACKED_SYSCALLS);
    __type(key, __u32);       // syscall_nr
    __type(value, __u8);      // 1 = tracked
} tracked_syscalls SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    __u32 syscall_nr = (__u32)ctx->args[1];

    // Check allowlist
    __u8 *tracked = bpf_map_lookup_elem(&tracked_syscalls, &syscall_nr);
    if (!tracked) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&syscall_start, &pid_tgid, &ts, BPF_ANY);
    bpf_map_update_elem(&syscall_nr_map, &pid_tgid, &syscall_nr, BPF_ANY);

    return 0;
}

SEC("raw_tracepoint/sys_exit")
int handle_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    long ret = (long)ctx->args[1];

    __u64 *tsp = bpf_map_lookup_elem(&syscall_start, &pid_tgid);
    if (!tsp) return 0;

    __u32 *nr = bpf_map_lookup_elem(&syscall_nr_map, &pid_tgid);
    if (!nr) {
        bpf_map_delete_elem(&syscall_start, &pid_tgid);
        return 0;
    }

    __u64 delta_ns = bpf_ktime_get_ns() - *tsp;
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    struct syscall_key key = {
        .cgroup_id = cgroup_id,
        .syscall_nr = *nr,
    };

    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->count, 1);
        if (ret < 0) {
            __sync_fetch_and_add(&stats->error_count, 1);
        }
        __sync_fetch_and_add(&stats->latency_sum_ns, delta_ns);
        __u32 slot = log2l(delta_ns);
        if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
        __sync_fetch_and_add(&stats->latency_slots[slot], 1);
    } else {
        struct syscall_stats new_stats = {
            .count = 1,
            .error_count = (ret < 0) ? 1 : 0,
            .latency_sum_ns = delta_ns,
        };
        __u32 slot = log2l(delta_ns);
        if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
        new_stats.latency_slots[slot] = 1;
        bpf_map_update_elem(&syscall_stats_map, &key, &new_stats, BPF_NOEXIST);
    }

    bpf_map_delete_elem(&syscall_start, &pid_tgid);
    bpf_map_delete_elem(&syscall_nr_map, &pid_tgid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

**Step 3: Commit**

```bash
git add bpf/mem.bpf.c bpf/syscall.bpf.c
git commit -m "feat: add memory (OOM, page faults) and syscall eBPF programs"
```

---

## Phase 4: Kotlin Application Core

### Task 9: BpfProgramManager (Lifecycle)

**Files:**
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/bpf/BpfProgramManager.kt`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/bpf/BpfProgramManagerTest.kt`

**Step 1: Write the failing test**

```kotlin
// src/test/kotlin/com/internal/kpodmetrics/bpf/BpfProgramManagerTest.kt
package com.internal.kpodmetrics.bpf

import com.internal.kpodmetrics.config.*
import io.mockk.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach

class BpfProgramManagerTest {

    private lateinit var bridge: BpfBridge
    private lateinit var manager: BpfProgramManager

    @BeforeEach
    fun setup() {
        bridge = mockk(relaxed = true)
    }

    @Test
    fun `loads only enabled programs based on profile`() {
        val config = MetricsProperties(profile = "minimal").resolveProfile()
        manager = BpfProgramManager(bridge, "/test/bpf", config)

        every { bridge.openObject(any()) } returns 1L
        every { bridge.loadObject(any()) } returns 0
        every { bridge.attachAll(any()) } returns 0

        manager.loadAll()

        // minimal: cpu + memory, no network or syscall
        verify { bridge.openObject("/test/bpf/cpu_sched.bpf.o") }
        verify { bridge.openObject("/test/bpf/mem.bpf.o") }
        verify(exactly = 0) { bridge.openObject("/test/bpf/net.bpf.o") }
        verify(exactly = 0) { bridge.openObject("/test/bpf/syscall.bpf.o") }
    }

    @Test
    fun `standard profile loads cpu, network, memory`() {
        val config = MetricsProperties(profile = "standard").resolveProfile()
        manager = BpfProgramManager(bridge, "/test/bpf", config)

        every { bridge.openObject(any()) } returns 1L
        every { bridge.loadObject(any()) } returns 0
        every { bridge.attachAll(any()) } returns 0

        manager.loadAll()

        verify { bridge.openObject("/test/bpf/cpu_sched.bpf.o") }
        verify { bridge.openObject("/test/bpf/net.bpf.o") }
        verify { bridge.openObject("/test/bpf/mem.bpf.o") }
        verify(exactly = 0) { bridge.openObject("/test/bpf/syscall.bpf.o") }
    }

    @Test
    fun `destroyAll cleans up all loaded programs`() {
        val config = MetricsProperties(profile = "standard").resolveProfile()
        manager = BpfProgramManager(bridge, "/test/bpf", config)

        every { bridge.openObject(any()) } returnsMany listOf(1L, 2L, 3L)
        every { bridge.loadObject(any()) } returns 0
        every { bridge.attachAll(any()) } returns 0

        manager.loadAll()
        manager.destroyAll()

        verify { bridge.destroyObject(1L) }
        verify { bridge.destroyObject(2L) }
        verify { bridge.destroyObject(3L) }
    }

    @Test
    fun `getMapFd delegates to bridge with correct handle`() {
        val config = MetricsProperties(profile = "minimal").resolveProfile()
        manager = BpfProgramManager(bridge, "/test/bpf", config)

        every { bridge.openObject("/test/bpf/cpu_sched.bpf.o") } returns 42L
        every { bridge.loadObject(42L) } returns 0
        every { bridge.attachAll(42L) } returns 0
        every { bridge.getMapFd(42L, "runq_latency") } returns 7

        manager.loadAll()
        val fd = manager.getMapFd("cpu_sched", "runq_latency")

        assertEquals(7, fd)
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd kpod-metrics && ./gradlew test --tests '*BpfProgramManagerTest*'`
Expected: FAIL — `BpfProgramManager` not found

**Step 3: Write BpfProgramManager**

```kotlin
// src/main/kotlin/com/internal/kpodmetrics/bpf/BpfProgramManager.kt
package com.internal.kpodmetrics.bpf

import com.internal.kpodmetrics.config.ResolvedConfig
import org.slf4j.LoggerFactory

class BpfProgramManager(
    private val bridge: BpfBridge,
    private val programDir: String,
    private val config: ResolvedConfig
) {
    private val log = LoggerFactory.getLogger(BpfProgramManager::class.java)
    private val loadedPrograms = mutableMapOf<String, Long>()  // name -> handle

    fun loadAll() {
        if (config.cpu.scheduling.enabled || config.cpu.throttling.enabled) {
            loadProgram("cpu_sched")
        }
        if (config.network.tcp.enabled) {
            loadProgram("net")
        }
        if (config.memory.oom || config.memory.pageFaults) {
            loadProgram("mem")
        }
        if (config.syscall.enabled) {
            loadProgram("syscall")
        }
        log.info("Loaded {} BPF programs: {}", loadedPrograms.size, loadedPrograms.keys)
    }

    private fun loadProgram(name: String) {
        val path = "$programDir/$name.bpf.o"
        log.info("Loading BPF program: {}", path)
        val handle = bridge.openObject(path)
        bridge.loadObject(handle)
        bridge.attachAll(handle)
        loadedPrograms[name] = handle
    }

    fun destroyAll() {
        loadedPrograms.forEach { (name, handle) ->
            try {
                bridge.destroyObject(handle)
                log.info("Destroyed BPF program: {}", name)
            } catch (e: Exception) {
                log.warn("Failed to destroy BPF program {}: {}", name, e.message)
            }
        }
        loadedPrograms.clear()
    }

    fun getMapFd(programName: String, mapName: String): Int {
        val handle = loadedPrograms[programName]
            ?: throw BpfMapException("Program not loaded: $programName")
        return bridge.getMapFd(handle, mapName)
    }

    fun isProgramLoaded(name: String): Boolean = loadedPrograms.containsKey(name)
}
```

**Step 4: Run tests to verify they pass**

Run: `cd kpod-metrics && ./gradlew test --tests '*BpfProgramManagerTest*'`
Expected: All 4 tests PASS

**Step 5: Commit**

```bash
git add src/
git commit -m "feat: add BpfProgramManager for lifecycle management of eBPF programs"
```

---

### Task 10: CgroupResolver (Pod Attribution)

**Files:**
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/bpf/CgroupResolver.kt`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/bpf/CgroupResolverTest.kt`

**Step 1: Write the failing test**

```kotlin
// src/test/kotlin/com/internal/kpodmetrics/bpf/CgroupResolverTest.kt
package com.internal.kpodmetrics.bpf

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class CgroupResolverTest {

    @Test
    fun `parse systemd cgroup path for burstable pod`() {
        val path = "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/" +
            "kubepods-burstable-pod1234abcd.slice/" +
            "cri-containerd-deadbeef5678.scope"
        val info = CgroupResolver.parseCgroupPath(path)
        assertNotNull(info)
        assertEquals("1234abcd", info!!.podUid)
        assertEquals("deadbeef5678", info.containerId)
    }

    @Test
    fun `parse cgroupfs cgroup path for guaranteed pod`() {
        val path = "/sys/fs/cgroup/kubepods/pod1234-abcd-efgh-5678/container123abc"
        val info = CgroupResolver.parseCgroupPath(path)
        assertNotNull(info)
        assertEquals("1234-abcd-efgh-5678", info!!.podUid)
        assertEquals("container123abc", info.containerId)
    }

    @Test
    fun `parse systemd cgroup path for besteffort pod`() {
        val path = "/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/" +
            "kubepods-besteffort-podaabbccdd.slice/" +
            "cri-containerd-11223344.scope"
        val info = CgroupResolver.parseCgroupPath(path)
        assertNotNull(info)
        assertEquals("aabbccdd", info!!.podUid)
        assertEquals("11223344", info.containerId)
    }

    @Test
    fun `non-kubernetes cgroup path returns null`() {
        val path = "/sys/fs/cgroup/user.slice/user-1000.slice"
        val info = CgroupResolver.parseCgroupPath(path)
        assertNull(info)
    }

    @Test
    fun `register and resolve pod info by cgroup id`() {
        val resolver = CgroupResolver()
        val podInfo = PodInfo(
            podUid = "1234",
            containerId = "abcd",
            namespace = "default",
            podName = "nginx-xyz",
            containerName = "nginx"
        )
        resolver.register(42L, podInfo)
        val resolved = resolver.resolve(42L)
        assertEquals(podInfo, resolved)
    }

    @Test
    fun `resolve returns null for unknown cgroup id`() {
        val resolver = CgroupResolver()
        assertNull(resolver.resolve(999L))
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd kpod-metrics && ./gradlew test --tests '*CgroupResolverTest*'`
Expected: FAIL — classes not found

**Step 3: Write CgroupResolver**

```kotlin
// src/main/kotlin/com/internal/kpodmetrics/bpf/CgroupResolver.kt
package com.internal.kpodmetrics.bpf

import java.util.concurrent.ConcurrentHashMap

data class PodInfo(
    val podUid: String,
    val containerId: String,
    val namespace: String = "",
    val podName: String = "",
    val containerName: String = ""
)

data class CgroupContainerInfo(
    val podUid: String,
    val containerId: String
)

class CgroupResolver {
    private val cache = ConcurrentHashMap<Long, PodInfo>()

    companion object {
        // systemd cgroup driver: kubepods-<qos>-pod<uid>.slice/cri-containerd-<id>.scope
        private val SYSTEMD_PATTERN = Regex(
            "kubepods-(?:burstable|besteffort|guaranteed)-pod([a-f0-9]+)\\.slice/" +
            "cri-containerd-([a-f0-9]+)\\.scope$"
        )

        // cgroupfs driver: kubepods/pod<uid>/<container-id>
        private val CGROUPFS_PATTERN = Regex(
            "kubepods/(?:burstable/|besteffort/)?pod([a-f0-9-]+)/([a-f0-9]+)$"
        )

        fun parseCgroupPath(path: String): CgroupContainerInfo? {
            SYSTEMD_PATTERN.find(path)?.let { match ->
                return CgroupContainerInfo(
                    podUid = match.groupValues[1],
                    containerId = match.groupValues[2]
                )
            }
            CGROUPFS_PATTERN.find(path)?.let { match ->
                return CgroupContainerInfo(
                    podUid = match.groupValues[1],
                    containerId = match.groupValues[2]
                )
            }
            return null
        }
    }

    fun register(cgroupId: Long, podInfo: PodInfo) {
        cache[cgroupId] = podInfo
    }

    fun resolve(cgroupId: Long): PodInfo? = cache[cgroupId]

    fun evict(cgroupId: Long) {
        cache.remove(cgroupId)
    }

    fun size(): Int = cache.size
}
```

**Step 4: Run tests to verify they pass**

Run: `cd kpod-metrics && ./gradlew test --tests '*CgroupResolverTest*'`
Expected: All 6 tests PASS

**Step 5: Commit**

```bash
git add src/
git commit -m "feat: add CgroupResolver for cgroup ID to pod metadata mapping"
```

---

### Task 11: PodWatcher (K8s API Informer)

**Files:**
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/k8s/PodWatcher.kt`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/k8s/PodWatcherTest.kt`

**Step 1: Write the failing test**

```kotlin
// src/test/kotlin/com/internal/kpodmetrics/k8s/PodWatcherTest.kt
package com.internal.kpodmetrics.k8s

import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.PodInfo
import com.internal.kpodmetrics.config.FilterProperties
import io.fabric8.kubernetes.api.model.ContainerStatusBuilder
import io.fabric8.kubernetes.api.model.PodBuilder
import io.fabric8.kubernetes.api.model.PodStatusBuilder
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class PodWatcherTest {

    @Test
    fun `extractPodInfos returns PodInfo for each container`() {
        val pod = PodBuilder()
            .withNewMetadata()
                .withName("nginx-abc")
                .withNamespace("default")
                .withUid("pod-uid-123")
            .endMetadata()
            .withNewSpec()
                .addNewContainer().withName("nginx").endContainer()
                .addNewContainer().withName("sidecar").endContainer()
            .endSpec()
            .withStatus(PodStatusBuilder()
                .withContainerStatuses(
                    ContainerStatusBuilder()
                        .withName("nginx")
                        .withContainerID("containerd://aabbccdd1122")
                        .build(),
                    ContainerStatusBuilder()
                        .withName("sidecar")
                        .withContainerID("containerd://eeff33445566")
                        .build()
                )
                .build())
            .build()

        val infos = PodWatcher.extractPodInfos(pod)

        assertEquals(2, infos.size)
        assertEquals("nginx", infos[0].containerName)
        assertEquals("aabbccdd1122", infos[0].containerId)
        assertEquals("default", infos[0].namespace)
        assertEquals("nginx-abc", infos[0].podName)
        assertEquals("sidecar", infos[1].containerName)
    }

    @Test
    fun `shouldWatch respects namespace filter`() {
        val filter = FilterProperties(
            excludeNamespaces = listOf("kube-system", "kube-public")
        )
        assertTrue(PodWatcher.shouldWatch("default", filter))
        assertFalse(PodWatcher.shouldWatch("kube-system", filter))
    }

    @Test
    fun `shouldWatch with namespace allowlist`() {
        val filter = FilterProperties(
            namespaces = listOf("production", "staging")
        )
        assertTrue(PodWatcher.shouldWatch("production", filter))
        assertFalse(PodWatcher.shouldWatch("default", filter))
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd kpod-metrics && ./gradlew test --tests '*PodWatcherTest*'`
Expected: FAIL — `PodWatcher` not found

**Step 3: Write PodWatcher**

```kotlin
// src/main/kotlin/com/internal/kpodmetrics/k8s/PodWatcher.kt
package com.internal.kpodmetrics.k8s

import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.PodInfo
import com.internal.kpodmetrics.config.FilterProperties
import io.fabric8.kubernetes.api.model.Pod
import org.slf4j.LoggerFactory

class PodWatcher(
    private val cgroupResolver: CgroupResolver,
    private val filter: FilterProperties,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(PodWatcher::class.java)

    companion object {
        fun extractPodInfos(pod: Pod): List<PodInfo> {
            val metadata = pod.metadata
            val statuses = pod.status?.containerStatuses ?: return emptyList()

            return statuses.mapNotNull { status ->
                val rawId = status.containerID ?: return@mapNotNull null
                // Format: containerd://abcdef1234 or docker://abcdef1234
                val containerId = rawId.substringAfter("://")
                PodInfo(
                    podUid = metadata.uid,
                    containerId = containerId,
                    namespace = metadata.namespace,
                    podName = metadata.name,
                    containerName = status.name
                )
            }
        }

        fun shouldWatch(namespace: String, filter: FilterProperties): Boolean {
            if (filter.namespaces.isNotEmpty()) {
                return namespace in filter.namespaces
            }
            return namespace !in filter.excludeNamespaces
        }
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cd kpod-metrics && ./gradlew test --tests '*PodWatcherTest*'`
Expected: All 3 tests PASS

**Step 5: Commit**

```bash
git add src/
git commit -m "feat: add PodWatcher for K8s pod metadata extraction and namespace filtering"
```

---

## Phase 5: Collectors

### Task 12: CpuSchedulingCollector

**Files:**
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/CpuSchedulingCollector.kt`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/collector/CpuSchedulingCollectorTest.kt`

**Step 1: Write the failing test**

```kotlin
// src/test/kotlin/com/internal/kpodmetrics/collector/CpuSchedulingCollectorTest.kt
package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.*
import com.internal.kpodmetrics.config.MetricsProperties
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import io.mockk.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import java.nio.ByteBuffer
import java.nio.ByteOrder

class CpuSchedulingCollectorTest {

    private lateinit var bridge: BpfBridge
    private lateinit var programManager: BpfProgramManager
    private lateinit var cgroupResolver: CgroupResolver
    private lateinit var registry: MeterRegistry
    private lateinit var collector: CpuSchedulingCollector

    @BeforeEach
    fun setup() {
        bridge = mockk(relaxed = true)
        programManager = mockk(relaxed = true)
        cgroupResolver = CgroupResolver()
        registry = SimpleMeterRegistry()

        cgroupResolver.register(100L, PodInfo(
            podUid = "uid-1", containerId = "cid-1",
            namespace = "default", podName = "test-pod", containerName = "app"
        ))

        val config = MetricsProperties().resolveProfile()
        collector = CpuSchedulingCollector(bridge, programManager, cgroupResolver, registry, config, "test-node")
    }

    @Test
    fun `collect reads runqueue latency map and registers histogram`() {
        every { programManager.getMapFd("cpu_sched", "runq_latency") } returns 5
        every { programManager.getMapFd("cpu_sched", "ctx_switches") } returns 6

        // Simulate map iteration: one entry with cgroup_id=100
        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(100L).array()
        every { bridge.mapGetNextKey(5, null, 8) } returns keyBytes
        every { bridge.mapGetNextKey(5, keyBytes, 8) } returns null

        // Simulate histogram value: 10 events in slot 10 (~1us), sum=10000ns
        val valueBytes = buildHistValue(slot = 10, count = 10, sumNs = 10000)
        every { bridge.mapLookup(5, keyBytes, any()) } returns valueBytes

        // No context switches
        every { bridge.mapGetNextKey(6, null, 8) } returns null

        collector.collect()

        val meters = registry.meters
        assertTrue(meters.any { it.id.name == "kpod.cpu.runqueue.latency" })
    }

    @Test
    fun `collect skips unknown cgroup ids`() {
        every { programManager.getMapFd("cpu_sched", "runq_latency") } returns 5
        every { programManager.getMapFd("cpu_sched", "ctx_switches") } returns 6

        // cgroup_id=999 not registered in resolver
        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(999L).array()
        every { bridge.mapGetNextKey(5, null, 8) } returns keyBytes
        every { bridge.mapGetNextKey(5, keyBytes, 8) } returns null
        every { bridge.mapLookup(5, keyBytes, any()) } returns buildHistValue(10, 5, 5000)
        every { bridge.mapGetNextKey(6, null, 8) } returns null

        collector.collect()

        // No metrics registered for unknown cgroup
        assertTrue(registry.meters.none {
            it.id.getTag("pod") == null && it.id.name.startsWith("kpod")
        })
    }

    private fun buildHistValue(slot: Int, count: Long, sumNs: Long): ByteArray {
        // struct hist_value: slots[27] + count + sum_ns = 27*8 + 8 + 8 = 232 bytes
        val buf = ByteBuffer.allocate(232).order(ByteOrder.LITTLE_ENDIAN)
        for (i in 0 until 27) {
            buf.putLong(if (i == slot) count else 0L)
        }
        buf.putLong(count)
        buf.putLong(sumNs)
        return buf.array()
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd kpod-metrics && ./gradlew test --tests '*CpuSchedulingCollectorTest*'`
Expected: FAIL — `CpuSchedulingCollector` not found

**Step 3: Write CpuSchedulingCollector**

```kotlin
// src/main/kotlin/com/internal/kpodmetrics/collector/CpuSchedulingCollector.kt
package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import io.micrometer.core.instrument.DistributionSummary
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

class CpuSchedulingCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(CpuSchedulingCollector::class.java)

    companion object {
        private const val KEY_SIZE = 8           // struct hist_key / counter_key = u64
        private const val HIST_VALUE_SIZE = 232  // 27*8 + 8 + 8
        private const val COUNTER_VALUE_SIZE = 8 // u64
        private const val MAX_SLOTS = 27
    }

    fun collect() {
        if (config.cpu.scheduling.enabled) {
            collectRunqueueLatency()
        }
        if (config.cpu.throttling.enabled) {
            collectContextSwitches()
        }
    }

    private fun collectRunqueueLatency() {
        val mapFd = programManager.getMapFd("cpu_sched", "runq_latency")
        iterateMap(mapFd, KEY_SIZE, HIST_VALUE_SIZE) { keyBytes, valueBytes ->
            val cgroupId = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN).long
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@iterateMap

            val buf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            val slots = LongArray(MAX_SLOTS) { buf.long }
            val count = buf.long
            val sumNs = buf.long

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )

            DistributionSummary.builder("kpod.cpu.runqueue.latency")
                .tags(tags)
                .baseUnit("seconds")
                .register(registry)
                .record(sumNs.toDouble() / 1_000_000_000.0)
        }
    }

    private fun collectContextSwitches() {
        val mapFd = programManager.getMapFd("cpu_sched", "ctx_switches")
        iterateMap(mapFd, KEY_SIZE, COUNTER_VALUE_SIZE) { keyBytes, valueBytes ->
            val cgroupId = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN).long
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@iterateMap

            val count = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN).long

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )

            registry.counter("kpod.cpu.context.switches", tags).increment(count.toDouble())
        }
    }

    private fun iterateMap(
        mapFd: Int, keySize: Int, valueSize: Int,
        handler: (ByteArray, ByteArray) -> Unit
    ) {
        var key: ByteArray? = null
        while (true) {
            val nextKey = bridge.mapGetNextKey(mapFd, key, keySize) ?: break
            val value = bridge.mapLookup(mapFd, nextKey, valueSize)
            if (value != null) {
                handler(nextKey, value)
            }
            key = nextKey
        }
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cd kpod-metrics && ./gradlew test --tests '*CpuSchedulingCollectorTest*'`
Expected: All 2 tests PASS

**Step 5: Commit**

```bash
git add src/
git commit -m "feat: add CpuSchedulingCollector reading BPF maps into Micrometer metrics"
```

---

### Task 13: NetworkCollector, MemoryCollector, SyscallCollector

**Files:**
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/NetworkCollector.kt`
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/MemoryCollector.kt`
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/SyscallCollector.kt`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/collector/NetworkCollectorTest.kt`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/collector/MemoryCollectorTest.kt`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/collector/SyscallCollectorTest.kt`

These follow the same pattern as CpuSchedulingCollector. Each collector:

1. Gets the map fd from `BpfProgramManager`
2. Iterates the BPF map via `BpfBridge`
3. Resolves cgroup ID to pod info via `CgroupResolver`
4. Registers metrics in Micrometer `MeterRegistry`

**Step 1: Write failing tests for all three collectors**

Each test follows the same pattern as `CpuSchedulingCollectorTest`: mock the bridge and programManager, register a pod in cgroupResolver, simulate map entries, verify Micrometer metrics are registered.

Key metrics per collector:

- **NetworkCollector:** `kpod.net.tcp.bytes.sent`, `kpod.net.tcp.bytes.received`, `kpod.net.tcp.retransmits`, `kpod.net.tcp.rtt`, `kpod.net.tcp.connections`
  - Reads `tcp_stats_map` (key=8B cgroup_id, value=48B tcp_stats struct)

- **MemoryCollector:** `kpod.mem.oom.kills`, `kpod.mem.major.page.faults`, `kpod.mem.rss.bytes`, `kpod.mem.working.set.bytes`, `kpod.mem.cache.bytes`
  - Reads `oom_kills` and `major_faults` maps from BPF
  - Reads RSS/working set/cache from cgroup v2 sysfs: `/sys/fs/cgroup/<path>/memory.current` and `/sys/fs/cgroup/<path>/memory.stat`

- **SyscallCollector:** `kpod.syscall.count`, `kpod.syscall.errors`, `kpod.syscall.latency`
  - Reads `syscall_stats_map` (key=16B syscall_key, value=232B+ syscall_stats struct)
  - Adds `{syscall}` label with syscall name resolved from syscall number

**Step 2: Run tests to verify they fail**

**Step 3: Implement all three collectors following the CpuSchedulingCollector pattern**

**Step 4: Run tests to verify they pass**

Run: `cd kpod-metrics && ./gradlew test --tests '*CollectorTest*'`
Expected: All collector tests PASS

**Step 5: Commit**

```bash
git add src/
git commit -m "feat: add Network, Memory, and Syscall collectors"
```

---

### Task 14: MetricsCollectorService (Coroutine Orchestrator)

**Files:**
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/MetricsCollectorService.kt`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/collector/MetricsCollectorServiceTest.kt`

**Step 1: Write the failing test**

```kotlin
// src/test/kotlin/com/internal/kpodmetrics/collector/MetricsCollectorServiceTest.kt
package com.internal.kpodmetrics.collector

import io.mockk.*
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.BeforeEach

class MetricsCollectorServiceTest {

    private lateinit var cpuCollector: CpuSchedulingCollector
    private lateinit var netCollector: NetworkCollector
    private lateinit var memCollector: MemoryCollector
    private lateinit var syscallCollector: SyscallCollector
    private lateinit var service: MetricsCollectorService

    @BeforeEach
    fun setup() {
        cpuCollector = mockk(relaxed = true)
        netCollector = mockk(relaxed = true)
        memCollector = mockk(relaxed = true)
        syscallCollector = mockk(relaxed = true)
        service = MetricsCollectorService(cpuCollector, netCollector, memCollector, syscallCollector)
    }

    @Test
    fun `collect calls all enabled collectors`() {
        service.collect()
        verify { cpuCollector.collect() }
        verify { netCollector.collect() }
        verify { memCollector.collect() }
        verify { syscallCollector.collect() }
    }

    @Test
    fun `collector failure does not stop other collectors`() {
        every { netCollector.collect() } throws RuntimeException("boom")
        service.collect()
        verify { cpuCollector.collect() }
        verify { memCollector.collect() }
        verify { syscallCollector.collect() }
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd kpod-metrics && ./gradlew test --tests '*MetricsCollectorServiceTest*'`
Expected: FAIL — `MetricsCollectorService` not found

**Step 3: Write MetricsCollectorService**

```kotlin
// src/main/kotlin/com/internal/kpodmetrics/collector/MetricsCollectorService.kt
package com.internal.kpodmetrics.collector

import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import java.util.concurrent.Executors

@Component
class MetricsCollectorService(
    private val cpuCollector: CpuSchedulingCollector,
    private val netCollector: NetworkCollector,
    private val memCollector: MemoryCollector,
    private val syscallCollector: SyscallCollector
) {
    private val log = LoggerFactory.getLogger(MetricsCollectorService::class.java)
    private val vtDispatcher = Executors.newVirtualThreadPerTaskExecutor().asCoroutineDispatcher()

    @Scheduled(fixedDelayString = "\${kpod.poll-interval:15000}")
    fun collect() = runBlocking(vtDispatcher) {
        val collectors = listOf(
            "cpu" to cpuCollector::collect,
            "network" to netCollector::collect,
            "memory" to memCollector::collect,
            "syscall" to syscallCollector::collect
        )

        collectors.map { (name, collectFn) ->
            launch {
                try {
                    collectFn()
                } catch (e: Exception) {
                    log.error("Collector '{}' failed: {}", name, e.message, e)
                }
            }
        }.joinAll()
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cd kpod-metrics && ./gradlew test --tests '*MetricsCollectorServiceTest*'`
Expected: All 2 tests PASS

**Step 5: Commit**

```bash
git add src/
git commit -m "feat: add MetricsCollectorService with coroutine-based parallel collection"
```

---

## Phase 6: Spring Wiring & Integration

### Task 15: Spring Bean Configuration

**Files:**
- Modify: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/config/BpfAutoConfiguration.kt`

**Step 1: Wire all beans together**

```kotlin
// src/main/kotlin/com/internal/kpodmetrics/config/BpfAutoConfiguration.kt
package com.internal.kpodmetrics.config

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.collector.*
import com.internal.kpodmetrics.k8s.PodWatcher
import io.micrometer.core.instrument.MeterRegistry
import jakarta.annotation.PreDestroy
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.event.ContextRefreshedEvent
import org.springframework.context.event.EventListener

@Configuration
@EnableConfigurationProperties(MetricsProperties::class)
class BpfAutoConfiguration(private val props: MetricsProperties) {

    private val log = LoggerFactory.getLogger(BpfAutoConfiguration::class.java)
    private var programManager: BpfProgramManager? = null

    @Bean
    fun resolvedConfig(): ResolvedConfig = props.resolveProfile()

    @Bean
    fun cgroupResolver(): CgroupResolver = CgroupResolver()

    @Bean
    fun podWatcher(cgroupResolver: CgroupResolver): PodWatcher =
        PodWatcher(cgroupResolver, props.filter, props.nodeName)

    @Bean
    @ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
    fun bpfBridge(): BpfBridge {
        BpfBridge.loadLibrary()
        return BpfBridge()
    }

    @Bean
    @ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
    fun bpfProgramManager(bridge: BpfBridge, config: ResolvedConfig): BpfProgramManager {
        val manager = BpfProgramManager(bridge, props.bpf.programDir, config)
        this.programManager = manager
        return manager
    }

    @Bean
    fun cpuSchedulingCollector(
        bridge: BpfBridge,
        manager: BpfProgramManager,
        resolver: CgroupResolver,
        registry: MeterRegistry,
        config: ResolvedConfig
    ) = CpuSchedulingCollector(bridge, manager, resolver, registry, config, props.nodeName)

    @Bean
    fun networkCollector(
        bridge: BpfBridge,
        manager: BpfProgramManager,
        resolver: CgroupResolver,
        registry: MeterRegistry,
        config: ResolvedConfig
    ) = NetworkCollector(bridge, manager, resolver, registry, config, props.nodeName)

    @Bean
    fun memoryCollector(
        bridge: BpfBridge,
        manager: BpfProgramManager,
        resolver: CgroupResolver,
        registry: MeterRegistry,
        config: ResolvedConfig
    ) = MemoryCollector(bridge, manager, resolver, registry, config, props.nodeName)

    @Bean
    fun syscallCollector(
        bridge: BpfBridge,
        manager: BpfProgramManager,
        resolver: CgroupResolver,
        registry: MeterRegistry,
        config: ResolvedConfig
    ) = SyscallCollector(bridge, manager, resolver, registry, config, props.nodeName)

    @EventListener(ContextRefreshedEvent::class)
    fun onStartup() {
        programManager?.let {
            log.info("Loading BPF programs from {}", props.bpf.programDir)
            it.loadAll()
            log.info("BPF programs loaded successfully")
        }
    }

    @PreDestroy
    fun onShutdown() {
        programManager?.let {
            log.info("Destroying BPF programs")
            it.destroyAll()
        }
    }
}
```

**Step 2: Run full test suite**

Run: `cd kpod-metrics && ./gradlew test`
Expected: All tests PASS

**Step 3: Commit**

```bash
git add src/
git commit -m "feat: wire Spring beans for BPF lifecycle and collector orchestration"
```

---

## Phase 7: Deployment

### Task 16: Dockerfile

**Files:**
- Create: `kpod-metrics/Dockerfile`

**Step 1: Write multi-stage Dockerfile**

```dockerfile
# kpod-metrics/Dockerfile

# Stage 1: Compile eBPF programs
FROM ubuntu:22.04 AS bpf-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev linux-tools-common bpftool \
    && rm -rf /var/lib/apt/lists/*

COPY bpf/ /build/bpf/

# Generate vmlinux.h (will be provided at build time or pre-generated)
# RUN bpftool btf dump file /sys/kernel/btf/vmlinux format c > /build/bpf/vmlinux.h

RUN clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -c /build/bpf/cpu_sched.bpf.c -o /build/bpf/cpu_sched.bpf.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -c /build/bpf/net.bpf.c -o /build/bpf/net.bpf.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -c /build/bpf/mem.bpf.c -o /build/bpf/mem.bpf.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -c /build/bpf/syscall.bpf.c -o /build/bpf/syscall.bpf.o

# Stage 2: Build JNI native library
FROM ubuntu:22.04 AS jni-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake gcc libbpf-dev libelf-dev zlib1g-dev openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

COPY jni/ /build/jni/
RUN cmake -B /build/jni/build /build/jni && cmake --build /build/jni/build

# Stage 3: Build Kotlin application
FROM gradle:8-jdk21 AS app-builder
WORKDIR /build
COPY build.gradle.kts settings.gradle.kts gradle.properties ./
COPY gradle/ gradle/
RUN gradle dependencies --no-daemon
COPY src/ src/
RUN gradle bootJar --no-daemon

# Stage 4: Runtime
FROM eclipse-temurin:21-jre-jammy
RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1 zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=bpf-builder /build/bpf/*.bpf.o /app/bpf/
COPY --from=jni-builder /build/jni/build/libkpod_bpf.so /app/lib/
COPY --from=app-builder /build/build/libs/*.jar /app/kpod-metrics.jar

ENV JAVA_OPTS="-XX:MaxRAMPercentage=75 -XX:+UseG1GC -Xss256k"

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -Djava.library.path=/app/lib -jar /app/kpod-metrics.jar"]
```

**Step 2: Commit**

```bash
git add Dockerfile
git commit -m "feat: add multi-stage Dockerfile for BPF, JNI, and Spring Boot build"
```

---

### Task 17: Helm Chart

**Files:**
- Create: `kpod-metrics/helm/kpod-metrics/Chart.yaml`
- Create: `kpod-metrics/helm/kpod-metrics/values.yaml`
- Create: `kpod-metrics/helm/kpod-metrics/templates/daemonset.yaml`
- Create: `kpod-metrics/helm/kpod-metrics/templates/serviceaccount.yaml`
- Create: `kpod-metrics/helm/kpod-metrics/templates/clusterrole.yaml`
- Create: `kpod-metrics/helm/kpod-metrics/templates/configmap.yaml`

**Step 1: Write Chart.yaml**

```yaml
# helm/kpod-metrics/Chart.yaml
apiVersion: v2
name: kpod-metrics
description: eBPF-based pod-level kernel metrics for Kubernetes
type: application
version: 0.1.0
appVersion: "0.1.0"
```

**Step 2: Write values.yaml**

```yaml
# helm/kpod-metrics/values.yaml
image:
  repository: internal-registry/kpod-metrics
  tag: "0.1.0"
  pullPolicy: IfNotPresent

resources:
  requests:
    cpu: 50m
    memory: 128Mi
  limits:
    cpu: 200m
    memory: 256Mi

podAnnotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "9090"
  prometheus.io/path: "/actuator/prometheus"

tolerations:
  - operator: Exists

config:
  profile: standard
  pollInterval: 15000
```

**Step 3: Write DaemonSet template**

```yaml
# helm/kpod-metrics/templates/daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: {{ .Release.Name }}
  labels:
    app.kubernetes.io/name: kpod-metrics
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: kpod-metrics
  template:
    metadata:
      labels:
        app.kubernetes.io/name: kpod-metrics
      annotations:
        {{- toYaml .Values.podAnnotations | nindent 8 }}
    spec:
      serviceAccountName: {{ .Release.Name }}
      hostPID: true
      containers:
        - name: kpod-metrics
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          ports:
            - containerPort: 9090
              name: metrics
          env:
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          securityContext:
            privileged: false
            capabilities:
              add:
                - BPF
                - PERFMON
                - SYS_RESOURCE
                - NET_ADMIN
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
          volumeMounts:
            - name: sys-kernel-btf
              mountPath: /sys/kernel/btf
              readOnly: true
            - name: sys-fs-cgroup
              mountPath: /sys/fs/cgroup
              readOnly: true
            - name: proc
              mountPath: /host/proc
              readOnly: true
            - name: config
              mountPath: /app/config
          livenessProbe:
            httpGet:
              path: /actuator/health/liveness
              port: 9090
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /actuator/health/readiness
              port: 9090
            initialDelaySeconds: 15
            periodSeconds: 5
      volumes:
        - name: sys-kernel-btf
          hostPath:
            path: /sys/kernel/btf
        - name: sys-fs-cgroup
          hostPath:
            path: /sys/fs/cgroup
        - name: proc
          hostPath:
            path: /proc
            type: Directory
        - name: config
          configMap:
            name: {{ .Release.Name }}-config
      tolerations:
        {{- toYaml .Values.tolerations | nindent 8 }}
```

**Step 4: Write ServiceAccount, ClusterRole, ConfigMap templates**

```yaml
# helm/kpod-metrics/templates/serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ .Release.Name }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ .Release.Name }}
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {{ .Release.Name }}
subjects:
  - kind: ServiceAccount
    name: {{ .Release.Name }}
    namespace: {{ .Release.Namespace }}
roleRef:
  kind: ClusterRole
  name: {{ .Release.Name }}
  apiGroup: rbac.authorization.k8s.io
```

```yaml
# helm/kpod-metrics/templates/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}-config
data:
  application.yml: |
    kpod:
      profile: {{ .Values.config.profile }}
      poll-interval: {{ .Values.config.pollInterval }}
      node-name: ${NODE_NAME}
      bpf:
        program-dir: /app/bpf
    spring:
      threads:
        virtual:
          enabled: true
    server:
      port: 9090
    management:
      endpoints:
        web:
          exposure:
            include: health, prometheus, info
      metrics:
        export:
          prometheus:
            enabled: true
```

**Step 5: Validate Helm chart**

Run: `helm lint kpod-metrics/helm/kpod-metrics`
Expected: Linting passes

**Step 6: Commit**

```bash
git add helm/
git commit -m "feat: add Helm chart with DaemonSet, RBAC, and ConfigMap"
```

---

## Phase 8: Verification

### Task 18: Full Build Verification

**Step 1: Run all unit tests**

Run: `cd kpod-metrics && ./gradlew test`
Expected: All tests PASS

**Step 2: Verify Gradle build produces bootJar**

Run: `cd kpod-metrics && ./gradlew bootJar && ls -la build/libs/`
Expected: `kpod-metrics-0.1.0-SNAPSHOT.jar` exists

**Step 3: Verify Helm chart lints**

Run: `helm lint kpod-metrics/helm/kpod-metrics`
Expected: No errors

**Step 4: Verify Helm template renders**

Run: `helm template test kpod-metrics/helm/kpod-metrics`
Expected: Valid YAML output with DaemonSet, ServiceAccount, ClusterRole, ConfigMap

**Step 5: Final commit**

```bash
git add -A
git commit -m "chore: verify full build pipeline"
```

---

## Summary

| Phase | Tasks | Key Deliverables |
|---|---|---|
| 1. Foundation | 1-3 | Gradle project, Spring Boot app, config profiles |
| 2. JNI Bridge | 4-5 | Kotlin JNI interface, C implementation, CMake |
| 3. eBPF Programs | 6-8 | cpu_sched, net, mem, syscall .bpf.c files |
| 4. App Core | 9-11 | BpfProgramManager, CgroupResolver, PodWatcher |
| 5. Collectors | 12-14 | CPU, Network, Memory, Syscall collectors + orchestrator |
| 6. Spring Wiring | 15 | Bean configuration, lifecycle management |
| 7. Deployment | 16-17 | Dockerfile, Helm chart |
| 8. Verification | 18 | Full build + lint validation |

**Total: 18 tasks, ~70 steps**

**Critical path risk:** Task 5 (JNI C implementation) is the highest-risk task. If JNI + libbpf integration proves problematic, fallback to Approach 2 (Go sidecar) from the design doc.
