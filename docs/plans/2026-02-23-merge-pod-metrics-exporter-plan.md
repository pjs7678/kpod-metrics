# Merge pod-metrics-exporter into kpod-metrics - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Port pod-metrics-exporter's cgroup-based collectors (disk I/O, interface network, filesystem), pod discovery (dual informer + kubelet polling), and cgroup V1/V2 resolution into kpod-metrics, producing a single DaemonSet that collects both eBPF kernel metrics and cgroup/proc filesystem metrics.

**Architecture:** kpod-metrics is the base. We add a `cgroup/` package for filesystem-based cgroup reading, a `discovery/` package for pluggable pod discovery, a `model/` package for shared data types, and three new Micrometer-based collectors. The existing eBPF stack is untouched.

**Tech Stack:** Kotlin 2.1.10, Spring Boot 3.4.3, Micrometer, fabric8 Kubernetes client, JDK 21 HttpClient (for kubelet polling), Gradle 8.12

**Source reference:** pod-metrics-exporter lives at `/Users/jongsu/dev/pod-metrics-exporter/`. kpod-metrics files are in git HEAD (deleted from working tree but recoverable via `git checkout HEAD -- kpod-metrics/`).

---

## Pre-requisite: Restore kpod-metrics files

The kpod-metrics files show as deleted in the working tree. Before starting, restore them:

```bash
cd /Users/jongsu && git checkout HEAD -- kpod-metrics/
```

---

## Task 1: Add model package (data types)

**Files:**
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/model/CgroupVersion.kt`
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/model/DiscoveredPod.kt`
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/model/PodCgroupTarget.kt`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/model/ModelTest.kt`

**Step 1: Write the failing test**

```kotlin
// kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/model/ModelTest.kt
package com.internal.kpodmetrics.model

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class ModelTest {
    @Test
    fun `CgroupVersion enum has V1 and V2`() {
        assertEquals(2, CgroupVersion.entries.size)
        assertNotNull(CgroupVersion.V1)
        assertNotNull(CgroupVersion.V2)
    }

    @Test
    fun `DiscoveredPod holds pod metadata with containers`() {
        val containers = listOf(ContainerInfo("nginx", "abc123def456"))
        val pod = DiscoveredPod(
            uid = "12345678-1234-1234-1234-123456789abc",
            name = "nginx-7b4f5d8c9-x2k4p",
            namespace = "default",
            qosClass = QosClass.BURSTABLE,
            containers = containers
        )
        assertEquals("nginx-7b4f5d8c9-x2k4p", pod.name)
        assertEquals(QosClass.BURSTABLE, pod.qosClass)
        assertEquals(1, pod.containers.size)
        assertEquals("nginx", pod.containers[0].name)
    }

    @Test
    fun `PodCgroupTarget holds resolved collection target`() {
        val target = PodCgroupTarget(
            podName = "nginx-pod",
            namespace = "default",
            containerName = "nginx",
            cgroupPath = "/sys/fs/cgroup/kubepods.slice/...",
            nodeName = "node-1"
        )
        assertEquals("nginx", target.containerName)
        assertEquals("node-1", target.nodeName)
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.model.ModelTest" --no-daemon`
Expected: FAIL - classes not found

**Step 3: Write the model classes**

```kotlin
// kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/model/CgroupVersion.kt
package com.internal.kpodmetrics.model

enum class CgroupVersion { V1, V2 }
```

```kotlin
// kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/model/DiscoveredPod.kt
package com.internal.kpodmetrics.model

enum class QosClass { GUARANTEED, BURSTABLE, BEST_EFFORT }

data class ContainerInfo(
    val name: String,
    val containerId: String
)

data class DiscoveredPod(
    val uid: String,
    val name: String,
    val namespace: String,
    val qosClass: QosClass,
    val containers: List<ContainerInfo>
)
```

```kotlin
// kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/model/PodCgroupTarget.kt
package com.internal.kpodmetrics.model

data class PodCgroupTarget(
    val podName: String,
    val namespace: String,
    val containerName: String,
    val cgroupPath: String,
    val nodeName: String
)
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.model.ModelTest" --no-daemon`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/jongsu && git add kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/model/ kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/model/
git commit -m "feat: add model package for cgroup types (CgroupVersion, DiscoveredPod, PodCgroupTarget)"
```

---

## Task 2: Add CgroupVersionDetector

**Files:**
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/cgroup/CgroupVersionDetector.kt`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/cgroup/CgroupVersionDetectorTest.kt`

**Step 1: Write the failing test**

```kotlin
// kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/cgroup/CgroupVersionDetectorTest.kt
package com.internal.kpodmetrics.cgroup

import com.internal.kpodmetrics.model.CgroupVersion
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.createFile

class CgroupVersionDetectorTest {
    @TempDir
    lateinit var tempDir: Path

    @Test
    fun `detects cgroup v2 when cgroup_controllers file exists`() {
        tempDir.resolve("cgroup.controllers").createFile()
        val detector = CgroupVersionDetector(tempDir.toString())
        assertEquals(CgroupVersion.V2, detector.detect())
    }

    @Test
    fun `detects cgroup v1 when cgroup_controllers file does not exist`() {
        val detector = CgroupVersionDetector(tempDir.toString())
        assertEquals(CgroupVersion.V1, detector.detect())
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.cgroup.CgroupVersionDetectorTest" --no-daemon`
Expected: FAIL

**Step 3: Write the implementation**

```kotlin
// kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/cgroup/CgroupVersionDetector.kt
package com.internal.kpodmetrics.cgroup

import com.internal.kpodmetrics.model.CgroupVersion
import java.nio.file.Files
import java.nio.file.Paths

class CgroupVersionDetector(private val cgroupRoot: String) {
    fun detect(): CgroupVersion {
        val controllersFile = Paths.get(cgroupRoot, "cgroup.controllers")
        return if (Files.exists(controllersFile)) CgroupVersion.V2 else CgroupVersion.V1
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.cgroup.CgroupVersionDetectorTest" --no-daemon`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/jongsu && git add kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/cgroup/CgroupVersionDetector.kt kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/cgroup/CgroupVersionDetectorTest.kt
git commit -m "feat: add CgroupVersionDetector with V1/V2 auto-detection"
```

---

## Task 3: Add CgroupPathResolver

**Files:**
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/cgroup/CgroupPathResolver.kt`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/cgroup/CgroupPathResolverTest.kt`

**Step 1: Write the failing test**

```kotlin
// kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/cgroup/CgroupPathResolverTest.kt
package com.internal.kpodmetrics.cgroup

import com.internal.kpodmetrics.model.CgroupVersion
import com.internal.kpodmetrics.model.QosClass
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.createDirectories

class CgroupPathResolverTest {
    @TempDir
    lateinit var tempDir: Path

    @Test
    fun `v2 resolves Burstable pod path with systemd style`() {
        val uid = "12345678-1234-1234-1234-123456789abc"
        val escapedUid = uid.replace("-", "_")
        val podDir = tempDir.resolve("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod${escapedUid}.slice")
        podDir.createDirectories()
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val path = resolver.resolvePodPath(uid, QosClass.BURSTABLE)
        assertNotNull(path)
        assertTrue(path!!.endsWith("kubepods-burstable-pod${escapedUid}.slice"))
    }

    @Test
    fun `v2 resolves Guaranteed pod path`() {
        val uid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        val escapedUid = uid.replace("-", "_")
        val podDir = tempDir.resolve("kubepods.slice/kubepods-pod${escapedUid}.slice")
        podDir.createDirectories()
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val path = resolver.resolvePodPath(uid, QosClass.GUARANTEED)
        assertNotNull(path)
    }

    @Test
    fun `v2 resolves BestEffort pod path`() {
        val uid = "11111111-2222-3333-4444-555555555555"
        val escapedUid = uid.replace("-", "_")
        val podDir = tempDir.resolve("kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod${escapedUid}.slice")
        podDir.createDirectories()
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val path = resolver.resolvePodPath(uid, QosClass.BEST_EFFORT)
        assertNotNull(path)
    }

    @Test
    fun `v2 falls back to kubelet_slice style`() {
        val uid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        val escapedUid = uid.replace("-", "_")
        val podDir = tempDir.resolve("kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod${escapedUid}.slice")
        podDir.createDirectories()
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val path = resolver.resolvePodPath(uid, QosClass.GUARANTEED)
        assertNotNull(path)
    }

    @Test
    fun `v2 returns null for non-existent pod`() {
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        assertNull(resolver.resolvePodPath("nonexistent-uid", QosClass.BURSTABLE))
    }

    @Test
    fun `v2 lists container directories`() {
        val uid = "12345678-1234-1234-1234-123456789abc"
        val escapedUid = uid.replace("-", "_")
        val podDir = tempDir.resolve("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod${escapedUid}.slice")
        podDir.createDirectories()
        podDir.resolve("cri-containerd-abc123.scope").createDirectories()
        podDir.resolve("cri-containerd-def456.scope").createDirectories()
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val containers = resolver.listContainerPaths(podDir.toString())
        assertEquals(2, containers.size)
        assertTrue(containers.any { it.containerId == "abc123" })
        assertTrue(containers.any { it.containerId == "def456" })
    }

    @Test
    fun `v1 resolves Burstable pod path`() {
        val uid = "12345678-1234-1234-1234-123456789abc"
        val podDir = tempDir.resolve("blkio/kubepods/burstable/pod${uid}")
        podDir.createDirectories()
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V1)
        val path = resolver.resolvePodPath(uid, QosClass.BURSTABLE, "blkio")
        assertNotNull(path)
        assertTrue(path!!.endsWith("pod${uid}"))
    }

    @Test
    fun `v1 resolves Guaranteed pod path`() {
        val uid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        val podDir = tempDir.resolve("blkio/kubepods/pod${uid}")
        podDir.createDirectories()
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V1)
        val path = resolver.resolvePodPath(uid, QosClass.GUARANTEED, "blkio")
        assertNotNull(path)
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.cgroup.CgroupPathResolverTest" --no-daemon`
Expected: FAIL

**Step 3: Write the implementation**

```kotlin
// kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/cgroup/CgroupPathResolver.kt
package com.internal.kpodmetrics.cgroup

import com.internal.kpodmetrics.model.CgroupVersion
import com.internal.kpodmetrics.model.QosClass
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

data class ContainerCgroup(
    val containerId: String,
    val path: String
)

class CgroupPathResolver(
    private val cgroupRoot: String,
    private val version: CgroupVersion
) {
    fun resolvePodPath(podUid: String, qosClass: QosClass, subsystem: String? = null): String? {
        val path = when (version) {
            CgroupVersion.V2 -> resolveV2PodPath(podUid, qosClass)
            CgroupVersion.V1 -> resolveV1PodPath(podUid, qosClass, subsystem ?: "blkio")
        }
        return if (Files.isDirectory(path)) path.toString() else null
    }

    fun listContainerPaths(podCgroupPath: String): List<ContainerCgroup> {
        val podDir = Paths.get(podCgroupPath)
        if (!Files.isDirectory(podDir)) return emptyList()
        return Files.list(podDir).use { stream ->
            stream.filter { Files.isDirectory(it) }
                .map { dir ->
                    val dirName = dir.fileName.toString()
                    val containerId = extractContainerId(dirName)
                    ContainerCgroup(containerId = containerId, path = dir.toString())
                }
                .toList()
        }
    }

    private fun resolveV2PodPath(podUid: String, qosClass: QosClass): Path {
        val escapedUid = podUid.replace("-", "_")

        // 1) Standard systemd-style
        val systemdPath = when (qosClass) {
            QosClass.GUARANTEED -> Paths.get(cgroupRoot, "kubepods.slice", "kubepods-pod${escapedUid}.slice")
            QosClass.BURSTABLE -> Paths.get(cgroupRoot, "kubepods.slice", "kubepods-burstable.slice", "kubepods-burstable-pod${escapedUid}.slice")
            QosClass.BEST_EFFORT -> Paths.get(cgroupRoot, "kubepods.slice", "kubepods-besteffort.slice", "kubepods-besteffort-pod${escapedUid}.slice")
        }
        if (Files.isDirectory(systemdPath)) return systemdPath

        // 2) Nested kubelet.slice style (kind / newer kubelet)
        val kubeletSlicePath = when (qosClass) {
            QosClass.GUARANTEED -> Paths.get(cgroupRoot, "kubelet.slice", "kubelet-kubepods.slice", "kubelet-kubepods-pod${escapedUid}.slice")
            QosClass.BURSTABLE -> Paths.get(cgroupRoot, "kubelet.slice", "kubelet-kubepods.slice", "kubelet-kubepods-burstable.slice", "kubelet-kubepods-burstable-pod${escapedUid}.slice")
            QosClass.BEST_EFFORT -> Paths.get(cgroupRoot, "kubelet.slice", "kubelet-kubepods.slice", "kubelet-kubepods-besteffort.slice", "kubelet-kubepods-besteffort-pod${escapedUid}.slice")
        }
        if (Files.isDirectory(kubeletSlicePath)) return kubeletSlicePath

        // 3) cgroupfs-style fallback
        return when (qosClass) {
            QosClass.GUARANTEED -> Paths.get(cgroupRoot, "kubepods", "pod${podUid}")
            QosClass.BURSTABLE -> Paths.get(cgroupRoot, "kubepods", "burstable", "pod${podUid}")
            QosClass.BEST_EFFORT -> Paths.get(cgroupRoot, "kubepods", "besteffort", "pod${podUid}")
        }
    }

    private fun resolveV1PodPath(podUid: String, qosClass: QosClass, subsystem: String): Path {
        return when (qosClass) {
            QosClass.GUARANTEED -> Paths.get(cgroupRoot, subsystem, "kubepods", "pod${podUid}")
            QosClass.BURSTABLE -> Paths.get(cgroupRoot, subsystem, "kubepods", "burstable", "pod${podUid}")
            QosClass.BEST_EFFORT -> Paths.get(cgroupRoot, subsystem, "kubepods", "besteffort", "pod${podUid}")
        }
    }

    private fun extractContainerId(dirName: String): String {
        return dirName
            .removePrefix("cri-containerd-")
            .removePrefix("docker-")
            .removePrefix("crio-")
            .removeSuffix(".scope")
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.cgroup.CgroupPathResolverTest" --no-daemon`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/jongsu && git add kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/cgroup/CgroupPathResolver.kt kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/cgroup/CgroupPathResolverTest.kt
git commit -m "feat: add CgroupPathResolver with V1/V2 and systemd/kubelet.slice/cgroupfs support"
```

---

## Task 4: Add CgroupReader

**Files:**
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/cgroup/CgroupReader.kt`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/cgroup/CgroupReaderTest.kt`

**Step 1: Write the failing test**

```kotlin
// kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/cgroup/CgroupReaderTest.kt
package com.internal.kpodmetrics.cgroup

import com.internal.kpodmetrics.model.CgroupVersion
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText

class CgroupReaderTest {
    @TempDir
    lateinit var tempDir: Path

    // --- Disk I/O ---

    @Test
    fun `v2 reads io_stat with multiple devices`() {
        val containerDir = tempDir.resolve("container1")
        containerDir.createDirectories()
        containerDir.resolve("io.stat").writeText(
            "8:0 rbytes=1048576 wbytes=524288 rios=100 wios=50 dbytes=0 dios=0\n" +
            "8:16 rbytes=2097152 wbytes=0 rios=200 wios=0 dbytes=0 dios=0\n"
        )
        val reader = CgroupReader(CgroupVersion.V2)
        val stats = reader.readDiskIO(containerDir.toString())
        assertEquals(2, stats.size)
        val sda = stats.find { it.major == 8 && it.minor == 0 }!!
        assertEquals(1048576L, sda.readBytes)
        assertEquals(524288L, sda.writeBytes)
        assertEquals(100L, sda.reads)
        assertEquals(50L, sda.writes)
    }

    @Test
    fun `v2 returns empty list when io_stat missing`() {
        val containerDir = tempDir.resolve("container2")
        containerDir.createDirectories()
        val reader = CgroupReader(CgroupVersion.V2)
        assertTrue(reader.readDiskIO(containerDir.toString()).isEmpty())
    }

    @Test
    fun `v1 reads blkio throttle files`() {
        val containerDir = tempDir.resolve("container3")
        containerDir.createDirectories()
        containerDir.resolve("blkio.throttle.io_service_bytes").writeText(
            "8:0 Read 1048576\n8:0 Write 524288\n8:0 Sync 0\n8:0 Async 0\n8:0 Total 1572864\n"
        )
        containerDir.resolve("blkio.throttle.io_serviced").writeText(
            "8:0 Read 100\n8:0 Write 50\n8:0 Sync 0\n8:0 Async 0\n8:0 Total 150\n"
        )
        val reader = CgroupReader(CgroupVersion.V1)
        val stats = reader.readDiskIO(containerDir.toString())
        assertEquals(1, stats.size)
        assertEquals(1048576L, stats[0].readBytes)
        assertEquals(524288L, stats[0].writeBytes)
    }

    // --- Network ---

    @Test
    fun `reads proc net dev`() {
        val procDir = tempDir.resolve("123/net")
        procDir.createDirectories()
        procDir.resolve("dev").writeText(
            "Inter-|   Receive                                                |  Transmit\n" +
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
            "  eth0: 9876543    5432    1    2    0     0          0         0  1111111    3333    0    1    0     0       0          0\n"
        )
        val reader = CgroupReader(CgroupVersion.V2)
        val stats = reader.readNetworkStats(tempDir.toString(), 123)
        assertEquals(1, stats.size)
        val eth0 = stats[0]
        assertEquals("eth0", eth0.interfaceName)
        assertEquals(9876543L, eth0.rxBytes)
        assertEquals(5432L, eth0.rxPackets)
        assertEquals(1L, eth0.rxErrors)
        assertEquals(2L, eth0.rxDrops)
        assertEquals(1111111L, eth0.txBytes)
        assertEquals(3333L, eth0.txPackets)
        assertEquals(1L, eth0.txDrops)
    }

    // --- PID ---

    @Test
    fun `v2 reads init pid from cgroup_procs`() {
        val containerDir = tempDir.resolve("container4")
        containerDir.createDirectories()
        containerDir.resolve("cgroup.procs").writeText("12345\n12346\n")
        val reader = CgroupReader(CgroupVersion.V2)
        assertEquals(12345, reader.readInitPid(containerDir.toString()))
    }

    @Test
    fun `v1 reads init pid from tasks`() {
        val containerDir = tempDir.resolve("container5")
        containerDir.createDirectories()
        containerDir.resolve("tasks").writeText("99999\n99998\n")
        val reader = CgroupReader(CgroupVersion.V1)
        assertEquals(99999, reader.readInitPid(containerDir.toString()))
    }

    @Test
    fun `returns null pid when file is empty`() {
        val containerDir = tempDir.resolve("container6")
        containerDir.createDirectories()
        containerDir.resolve("cgroup.procs").writeText("")
        val reader = CgroupReader(CgroupVersion.V2)
        assertNull(reader.readInitPid(containerDir.toString()))
    }

    // --- Filesystem ---

    @Test
    fun `parseMountInfoLine extracts overlay mount`() {
        val reader = CgroupReader(CgroupVersion.V2)
        val result = reader.parseMountInfoLine(
            "22 1 0:21 / / rw,relatime shared:1 - overlay overlay rw,lowerdir=/lower"
        )
        assertNotNull(result)
        assertEquals("/", result!!.first)
        assertEquals("overlay", result.second)
    }

    @Test
    fun `parseMountInfoLine filters proc filesystem`() {
        val reader = CgroupReader(CgroupVersion.V2)
        assertNull(reader.parseMountInfoLine(
            "35 22 0:22 / /proc rw,nosuid,nodev,noexec - proc proc rw"
        ))
    }

    @Test
    fun `parseMountInfoLine filters tmpfs filesystem`() {
        val reader = CgroupReader(CgroupVersion.V2)
        assertNull(reader.parseMountInfoLine(
            "40 22 0:23 / /dev/shm rw,nosuid,nodev - tmpfs tmpfs rw"
        ))
    }

    @Test
    fun `readFilesystemStats reads overlay mount and returns stats`() {
        val procDir = tempDir.resolve("42")
        procDir.createDirectories()
        procDir.resolve("mountinfo").writeText(
            "22 1 0:21 / / rw,relatime - overlay overlay rw\n" +
            "35 22 0:22 / /proc rw,nosuid - proc proc rw\n"
        )
        procDir.resolve("root").createDirectories()
        val reader = CgroupReader(CgroupVersion.V2)
        val stats = reader.readFilesystemStats(tempDir.toString(), 42)
        assertEquals(1, stats.size)
        assertEquals("/", stats[0].mountPoint)
        assertTrue(stats[0].totalBytes > 0)
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.cgroup.CgroupReaderTest" --no-daemon`
Expected: FAIL

**Step 3: Write the implementation**

```kotlin
// kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/cgroup/CgroupReader.kt
package com.internal.kpodmetrics.cgroup

import com.internal.kpodmetrics.model.CgroupVersion
import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.Paths

data class DiskIOStat(
    val major: Int, val minor: Int,
    val readBytes: Long, val writeBytes: Long,
    val reads: Long, val writes: Long
)

data class NetworkStat(
    val interfaceName: String,
    val rxBytes: Long, val rxPackets: Long, val rxErrors: Long, val rxDrops: Long,
    val txBytes: Long, val txPackets: Long, val txErrors: Long, val txDrops: Long
)

data class FilesystemStat(
    val mountPoint: String,
    val totalBytes: Long,
    val usedBytes: Long,
    val availableBytes: Long
)

class CgroupReader(private val version: CgroupVersion) {
    private val log = LoggerFactory.getLogger(CgroupReader::class.java)

    fun readDiskIO(containerCgroupPath: String): List<DiskIOStat> {
        return when (version) {
            CgroupVersion.V2 -> readDiskIOV2(containerCgroupPath)
            CgroupVersion.V1 -> readDiskIOV1(containerCgroupPath)
        }
    }

    fun readInitPid(containerCgroupPath: String): Int? {
        val fileName = when (version) {
            CgroupVersion.V2 -> "cgroup.procs"
            CgroupVersion.V1 -> "tasks"
        }
        val file = Paths.get(containerCgroupPath, fileName)
        if (!Files.exists(file)) return null
        return try {
            Files.readAllLines(file)
                .firstOrNull { it.isNotBlank() }
                ?.trim()?.toIntOrNull()
        } catch (e: Exception) {
            log.warn("Failed to read PID from {}: {}", file, e.message)
            null
        }
    }

    fun readNetworkStats(procRoot: String, pid: Int): List<NetworkStat> {
        val netDev = Paths.get(procRoot, pid.toString(), "net", "dev")
        if (!Files.exists(netDev)) return emptyList()
        return try {
            Files.readAllLines(netDev)
                .drop(2)
                .filter { it.contains(":") }
                .mapNotNull { parseNetDevLine(it) }
        } catch (e: Exception) {
            log.warn("Failed to read network stats for PID {}: {}", pid, e.message)
            emptyList()
        }
    }

    fun readFilesystemStats(procRoot: String, pid: Int): List<FilesystemStat> {
        val mountInfo = Paths.get(procRoot, pid.toString(), "mountinfo")
        if (!Files.exists(mountInfo)) return emptyList()
        return try {
            Files.readAllLines(mountInfo)
                .mapNotNull { parseMountInfoLine(it) }
                .mapNotNull { (mountPoint, _) ->
                    try {
                        val resolvedPath = Paths.get(procRoot, pid.toString(), "root", mountPoint.removePrefix("/"))
                        if (!Files.exists(resolvedPath)) return@mapNotNull null
                        val store = Files.getFileStore(resolvedPath)
                        val total = store.totalSpace
                        val available = store.usableSpace
                        FilesystemStat(mountPoint, total, total - available, available)
                    } catch (e: Exception) {
                        log.debug("Skipping mount {}: {}", mountPoint, e.message)
                        null
                    }
                }
        } catch (e: Exception) {
            log.warn("Failed to read filesystem stats for PID {}: {}", pid, e.message)
            emptyList()
        }
    }

    internal fun parseMountInfoLine(line: String): Pair<String, String>? {
        val parts = line.trim().split("\\s+".toRegex())
        val separatorIndex = parts.indexOf("-")
        if (separatorIndex < 0 || separatorIndex + 1 >= parts.size) return null
        if (parts.size < 5) return null
        val mountPoint = parts[4]
        val fsType = parts[separatorIndex + 1]
        val realFilesystems = setOf("overlay", "ext4", "xfs", "btrfs")
        if (fsType !in realFilesystems) return null
        return mountPoint to fsType
    }

    private fun readDiskIOV2(containerCgroupPath: String): List<DiskIOStat> {
        val ioStat = Paths.get(containerCgroupPath, "io.stat")
        if (!Files.exists(ioStat)) return emptyList()
        return try {
            Files.readAllLines(ioStat)
                .filter { it.isNotBlank() }
                .mapNotNull { parseIOStatV2Line(it) }
        } catch (e: Exception) {
            log.warn("Failed to read io.stat from {}: {}", containerCgroupPath, e.message)
            emptyList()
        }
    }

    private fun parseIOStatV2Line(line: String): DiskIOStat? {
        val parts = line.trim().split("\\s+".toRegex())
        if (parts.size < 2) return null
        val deviceParts = parts[0].split(":")
        if (deviceParts.size != 2) return null
        val kvMap = parts.drop(1).mapNotNull {
            val kv = it.split("=")
            if (kv.size == 2) kv[0] to kv[1].toLongOrNull() else null
        }.toMap()
        return DiskIOStat(
            major = deviceParts[0].toIntOrNull() ?: return null,
            minor = deviceParts[1].toIntOrNull() ?: return null,
            readBytes = kvMap["rbytes"] ?: 0L,
            writeBytes = kvMap["wbytes"] ?: 0L,
            reads = kvMap["rios"] ?: 0L,
            writes = kvMap["wios"] ?: 0L
        )
    }

    private fun readDiskIOV1(containerCgroupPath: String): List<DiskIOStat> {
        val bytesFile = Paths.get(containerCgroupPath, "blkio.throttle.io_service_bytes")
        val opsFile = Paths.get(containerCgroupPath, "blkio.throttle.io_serviced")
        if (!Files.exists(bytesFile) || !Files.exists(opsFile)) return emptyList()
        return try {
            val bytesMap = parseBlkioV1(Files.readAllLines(bytesFile))
            val opsMap = parseBlkioV1(Files.readAllLines(opsFile))
            val devices = bytesMap.keys union opsMap.keys
            devices.mapNotNull { device ->
                val bytes = bytesMap[device] ?: emptyMap()
                val ops = opsMap[device] ?: emptyMap()
                val deviceParts = device.split(":")
                if (deviceParts.size != 2) return@mapNotNull null
                DiskIOStat(
                    major = deviceParts[0].toIntOrNull() ?: return@mapNotNull null,
                    minor = deviceParts[1].toIntOrNull() ?: return@mapNotNull null,
                    readBytes = bytes["Read"] ?: 0L, writeBytes = bytes["Write"] ?: 0L,
                    reads = ops["Read"] ?: 0L, writes = ops["Write"] ?: 0L
                )
            }
        } catch (e: Exception) {
            log.warn("Failed to read blkio stats: {}", e.message)
            emptyList()
        }
    }

    private fun parseBlkioV1(lines: List<String>): Map<String, Map<String, Long>> {
        val result = mutableMapOf<String, MutableMap<String, Long>>()
        for (line in lines) {
            val parts = line.trim().split("\\s+".toRegex())
            if (parts.size != 3) continue
            val device = parts[0]; val op = parts[1]; val value = parts[2].toLongOrNull() ?: continue
            if (op == "Total" || op == "Sync" || op == "Async") continue
            result.getOrPut(device) { mutableMapOf() }[op] = value
        }
        return result
    }

    private fun parseNetDevLine(line: String): NetworkStat? {
        val colonIndex = line.indexOf(':')
        if (colonIndex < 0) return null
        val iface = line.substring(0, colonIndex).trim()
        val values = line.substring(colonIndex + 1).trim().split("\\s+".toRegex())
        if (values.size < 16) return null
        return NetworkStat(
            interfaceName = iface,
            rxBytes = values[0].toLongOrNull() ?: 0L,
            rxPackets = values[1].toLongOrNull() ?: 0L,
            rxErrors = values[2].toLongOrNull() ?: 0L,
            rxDrops = values[3].toLongOrNull() ?: 0L,
            txBytes = values[8].toLongOrNull() ?: 0L,
            txPackets = values[9].toLongOrNull() ?: 0L,
            txErrors = values[10].toLongOrNull() ?: 0L,
            txDrops = values[11].toLongOrNull() ?: 0L
        )
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.cgroup.CgroupReaderTest" --no-daemon`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/jongsu && git add kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/cgroup/CgroupReader.kt kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/cgroup/CgroupReaderTest.kt
git commit -m "feat: add CgroupReader for disk I/O, network, filesystem, and PID reading (V1+V2)"
```

---

## Task 5: Add PodProvider interface and PodCgroupMapper

**Files:**
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/discovery/PodProvider.kt`
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/discovery/PodCgroupMapper.kt`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/discovery/PodCgroupMapperTest.kt`

**Step 1: Write the failing test**

```kotlin
// kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/discovery/PodCgroupMapperTest.kt
package com.internal.kpodmetrics.discovery

import com.internal.kpodmetrics.cgroup.CgroupPathResolver
import com.internal.kpodmetrics.model.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.createDirectories

class PodCgroupMapperTest {
    @TempDir
    lateinit var tempDir: Path

    @Test
    fun `maps pods to cgroup targets for v2`() {
        val uid = "12345678-1234-1234-1234-123456789abc"
        val escapedUid = uid.replace("-", "_")
        val containerId = "abc123def456"
        val podDir = tempDir.resolve("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod${escapedUid}.slice")
        podDir.createDirectories()
        podDir.resolve("cri-containerd-${containerId}.scope").createDirectories()

        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val provider = object : PodProvider {
            override fun getDiscoveredPods(): Map<String, DiscoveredPod> = mapOf(
                uid to DiscoveredPod(uid, "nginx-pod", "default", QosClass.BURSTABLE,
                    listOf(ContainerInfo("nginx", containerId)))
            )
        }

        val mapper = PodCgroupMapper(provider, resolver, "test-node")
        val targets = mapper.resolve()
        assertEquals(1, targets.size)
        assertEquals("nginx-pod", targets[0].podName)
        assertEquals("nginx", targets[0].containerName)
        assertEquals("test-node", targets[0].nodeName)
    }

    @Test
    fun `skips pods with no matching cgroup path`() {
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val provider = object : PodProvider {
            override fun getDiscoveredPods(): Map<String, DiscoveredPod> = mapOf(
                "uid-1" to DiscoveredPod("uid-1", "ghost-pod", "default", QosClass.BURSTABLE,
                    listOf(ContainerInfo("ghost", "nonexistent")))
            )
        }
        val mapper = PodCgroupMapper(provider, resolver, "test-node")
        assertTrue(mapper.resolve().isEmpty())
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.discovery.PodCgroupMapperTest" --no-daemon`
Expected: FAIL

**Step 3: Write the implementations**

```kotlin
// kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/discovery/PodProvider.kt
package com.internal.kpodmetrics.discovery

import com.internal.kpodmetrics.model.DiscoveredPod

interface PodProvider {
    fun getDiscoveredPods(): Map<String, DiscoveredPod>
}
```

```kotlin
// kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/discovery/PodCgroupMapper.kt
package com.internal.kpodmetrics.discovery

import com.internal.kpodmetrics.cgroup.CgroupPathResolver
import com.internal.kpodmetrics.model.PodCgroupTarget
import org.slf4j.LoggerFactory

class PodCgroupMapper(
    private val podProvider: PodProvider,
    private val pathResolver: CgroupPathResolver,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(PodCgroupMapper::class.java)

    fun resolve(): List<PodCgroupTarget> {
        val targets = mutableListOf<PodCgroupTarget>()
        for ((_, pod) in podProvider.getDiscoveredPods()) {
            val podPath = pathResolver.resolvePodPath(pod.uid, pod.qosClass) ?: continue
            val containerCgroups = pathResolver.listContainerPaths(podPath)
            for (container in pod.containers) {
                val matchedCgroup = containerCgroups.find { cg ->
                    cg.containerId == container.containerId ||
                    container.containerId.startsWith(cg.containerId) ||
                    cg.containerId.startsWith(container.containerId)
                }
                if (matchedCgroup != null) {
                    targets.add(PodCgroupTarget(
                        podName = pod.name, namespace = pod.namespace,
                        containerName = container.name, cgroupPath = matchedCgroup.path,
                        nodeName = nodeName
                    ))
                } else {
                    log.debug("No cgroup match for container {} in pod {}", container.name, pod.name)
                }
            }
        }
        return targets
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.discovery.PodCgroupMapperTest" --no-daemon`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/jongsu && git add kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/discovery/ kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/discovery/
git commit -m "feat: add PodProvider interface and PodCgroupMapper for cgroup path resolution"
```

---

## Task 6: Make PodWatcher implement PodProvider

**Files:**
- Modify: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/k8s/PodWatcher.kt`
- Modify: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/k8s/PodWatcherTest.kt`

**Step 1: Write the failing test**

Add a new test to the existing `PodWatcherTest.kt`:

```kotlin
@Test
fun `getDiscoveredPods returns discovered pods`() {
    // Create a PodWatcher and verify it implements PodProvider
    val resolver = CgroupResolver()
    val props = MetricsProperties(nodeName = "test-node")
    val client = mockk<KubernetesClient>(relaxed = true)
    val watcher = PodWatcher(client, resolver, props)

    // PodWatcher should implement PodProvider
    assertTrue(watcher is PodProvider)

    // After adding a pod, getDiscoveredPods should return it
    // (We test via the internal method that processes pods)
    val pods = watcher.getDiscoveredPods()
    assertNotNull(pods)
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.k8s.PodWatcherTest" --no-daemon`
Expected: FAIL (PodWatcher does not implement PodProvider)

**Step 3: Modify PodWatcher**

Add the following to `PodWatcher.kt`:

1. Import `PodProvider`, `DiscoveredPod`, `ContainerInfo` (model), `QosClass`
2. Implement `PodProvider` interface
3. Maintain a `ConcurrentHashMap<String, DiscoveredPod>` alongside existing CgroupResolver logic
4. Populate it in `registerPod()`

Key changes to the class:

```kotlin
// Add to imports:
import com.internal.kpodmetrics.discovery.PodProvider
import com.internal.kpodmetrics.model.ContainerInfo as ModelContainerInfo
import com.internal.kpodmetrics.model.DiscoveredPod
import com.internal.kpodmetrics.model.QosClass
import java.util.concurrent.ConcurrentHashMap

// Change class declaration:
class PodWatcher(
    private val kubernetesClient: KubernetesClient,
    private val cgroupResolver: CgroupResolver,
    private val properties: MetricsProperties
) : PodProvider {

    // Add field:
    private val discoveredPods = ConcurrentHashMap<String, DiscoveredPod>()

    // Add PodProvider implementation:
    override fun getDiscoveredPods(): Map<String, DiscoveredPod> =
        java.util.Collections.unmodifiableMap(HashMap(discoveredPods))

    // In registerPod(), after existing logic, also track DiscoveredPod:
    private fun registerPod(pod: Pod): Int {
        val podInfos = extractPodInfos(pod)
        var count = 0
        for (info in podInfos) {
            val cgroupId = resolveCgroupId(info) ?: continue
            cgroupResolver.register(cgroupId, info)
            count++
        }

        // Also track as DiscoveredPod for cgroup collectors
        toDiscoveredPod(pod)?.let { discoveredPods[it.uid] = it }

        if (podInfos.isNotEmpty() && count == 0) {
            log.debug("Pod {}/{}: {} containers found but no cgroup IDs resolved",
                pod.metadata.namespace, pod.metadata.name, podInfos.size)
        }
        return count
    }

    // In the DELETED event handler, also remove from discoveredPods:
    // pod.metadata?.uid?.let { discoveredPods.remove(it) }
}

// Add companion function:
companion object {
    // ... existing companion functions ...

    fun toDiscoveredPod(pod: Pod): DiscoveredPod? {
        val metadata = pod.metadata ?: return null
        val uid = metadata.uid ?: return null
        val statuses = pod.status?.containerStatuses ?: return null
        val qosClass = when (pod.status?.qosClass) {
            "Guaranteed" -> QosClass.GUARANTEED
            "BestEffort" -> QosClass.BEST_EFFORT
            else -> QosClass.BURSTABLE
        }
        val containers = statuses.mapNotNull { status ->
            val rawId = status.containerID ?: return@mapNotNull null
            ModelContainerInfo(status.name, rawId.substringAfter("://"))
        }
        return DiscoveredPod(uid, metadata.name ?: "unknown",
            metadata.namespace ?: "default", qosClass, containers)
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.k8s.PodWatcherTest" --no-daemon`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/jongsu && git add kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/k8s/PodWatcher.kt kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/k8s/PodWatcherTest.kt
git commit -m "feat: make PodWatcher implement PodProvider for cgroup collector integration"
```

---

## Task 7: Add KubeletPodProvider

**Files:**
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/discovery/KubeletPodProvider.kt`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/discovery/KubeletPodProviderTest.kt`

Uses JDK 21 HttpClient instead of OkHttp to avoid extra dependencies.

**Step 1: Write the failing test**

```kotlin
// kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/discovery/KubeletPodProviderTest.kt
package com.internal.kpodmetrics.discovery

import com.internal.kpodmetrics.model.QosClass
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class KubeletPodProviderTest {

    private val sampleResponse = """
    {
      "items": [
        {
          "metadata": { "uid": "uid-1", "name": "nginx-abc", "namespace": "default" },
          "status": {
            "qosClass": "Burstable",
            "containerStatuses": [
              { "name": "nginx", "containerID": "containerd://abc123" }
            ]
          }
        },
        {
          "metadata": { "uid": "uid-2", "name": "redis-xyz", "namespace": "cache" },
          "status": {
            "qosClass": "Guaranteed",
            "containerStatuses": [
              { "name": "redis", "containerID": "containerd://def456" }
            ]
          }
        }
      ]
    }
    """.trimIndent()

    @Test
    fun `parsePodListJson parses kubelet response`() {
        val pods = KubeletPodProvider.parsePodListJson(sampleResponse)
        assertEquals(2, pods.size)
        val nginx = pods["uid-1"]!!
        assertEquals("nginx-abc", nginx.name)
        assertEquals("default", nginx.namespace)
        assertEquals(QosClass.BURSTABLE, nginx.qosClass)
        assertEquals(1, nginx.containers.size)
        assertEquals("nginx", nginx.containers[0].name)
        assertEquals("abc123", nginx.containers[0].containerId)

        val redis = pods["uid-2"]!!
        assertEquals(QosClass.GUARANTEED, redis.qosClass)
    }

    @Test
    fun `parsePodListJson handles missing fields gracefully`() {
        val json = """{"items": [{"metadata": {}, "status": {}}]}"""
        val pods = KubeletPodProvider.parsePodListJson(json)
        assertTrue(pods.isEmpty())
    }

    @Test
    fun `reconcile removes stale pods`() {
        val provider = KubeletPodProvider("10.0.0.1", 10250, 30)
        // Simulate first poll
        val first = KubeletPodProvider.parsePodListJson(sampleResponse)
        provider.reconcile(first)
        assertEquals(2, provider.getDiscoveredPods().size)

        // Simulate second poll with only one pod
        val second = KubeletPodProvider.parsePodListJson("""
            {"items": [{"metadata": {"uid": "uid-1", "name": "nginx-abc", "namespace": "default"},
            "status": {"qosClass": "Burstable", "containerStatuses": [{"name": "nginx", "containerID": "containerd://abc123"}]}}]}
        """.trimIndent())
        provider.reconcile(second)
        assertEquals(1, provider.getDiscoveredPods().size)
        assertNotNull(provider.getDiscoveredPods()["uid-1"])
        assertNull(provider.getDiscoveredPods()["uid-2"])
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.discovery.KubeletPodProviderTest" --no-daemon`
Expected: FAIL

**Step 3: Write the implementation**

```kotlin
// kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/discovery/KubeletPodProvider.kt
package com.internal.kpodmetrics.discovery

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.internal.kpodmetrics.model.ContainerInfo
import com.internal.kpodmetrics.model.DiscoveredPod
import com.internal.kpodmetrics.model.QosClass
import org.slf4j.LoggerFactory
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class KubeletPodProvider(
    private val nodeIp: String,
    private val kubeletPort: Int = 10250,
    private val pollIntervalSeconds: Long = 30
) : PodProvider {
    private val log = LoggerFactory.getLogger(KubeletPodProvider::class.java)
    private val pods = ConcurrentHashMap<String, DiscoveredPod>()
    private var scheduler: ScheduledExecutorService? = null
    private val httpClient: HttpClient = buildInsecureClient()

    override fun getDiscoveredPods(): Map<String, DiscoveredPod> =
        java.util.Collections.unmodifiableMap(HashMap(pods))

    fun start() {
        if (nodeIp.isBlank()) {
            log.warn("NODE_IP not set, kubelet pod polling disabled")
            return
        }
        scheduler = Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "kubelet-pod-poller").apply { isDaemon = true }
        }
        scheduler!!.scheduleWithFixedDelay(::poll, 0, pollIntervalSeconds, TimeUnit.SECONDS)
        log.info("Started kubelet pod polling on {}:{} every {}s", nodeIp, kubeletPort, pollIntervalSeconds)
    }

    fun stop() {
        scheduler?.shutdownNow()
    }

    internal fun poll() {
        try {
            val token = readServiceAccountToken()
            val url = "https://$nodeIp:$kubeletPort/pods"
            val requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .GET()
            if (token.isNotBlank()) {
                requestBuilder.header("Authorization", "Bearer $token")
            }
            val response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString())
            if (response.statusCode() != 200) {
                log.warn("Kubelet /pods returned {}", response.statusCode())
                return
            }
            val parsed = parsePodListJson(response.body())
            reconcile(parsed)
        } catch (e: Exception) {
            log.error("Failed to poll kubelet /pods: {}", e.message, e)
        }
    }

    internal fun reconcile(freshPods: Map<String, DiscoveredPod>) {
        pods.keys.removeAll { it !in freshPods.keys }
        pods.putAll(freshPods)
    }

    private fun readServiceAccountToken(): String {
        return try {
            java.io.File("/var/run/secrets/kubernetes.io/serviceaccount/token").readText()
        } catch (_: Exception) { "" }
    }

    private fun buildInsecureClient(): HttpClient {
        val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, SecureRandom())
        return HttpClient.newBuilder()
            .sslContext(sslContext)
            .connectTimeout(Duration.ofSeconds(10))
            .build()
    }

    companion object {
        private val mapper = jacksonObjectMapper()

        fun parsePodListJson(json: String): Map<String, DiscoveredPod> {
            val podList = mapper.readValue<KubeletPodList>(json)
            val result = mutableMapOf<String, DiscoveredPod>()
            for (item in podList.items) {
                val uid = item.metadata?.uid ?: continue
                val name = item.metadata.name ?: continue
                val namespace = item.metadata.namespace ?: "default"
                val qosClass = when (item.status?.qosClass) {
                    "Guaranteed" -> QosClass.GUARANTEED
                    "BestEffort" -> QosClass.BEST_EFFORT
                    else -> QosClass.BURSTABLE
                }
                val containers = (item.status?.containerStatuses ?: emptyList()).mapNotNull { cs ->
                    val cName = cs.name ?: return@mapNotNull null
                    val rawId = cs.containerID ?: return@mapNotNull null
                    ContainerInfo(cName, rawId.substringAfter("://"))
                }
                result[uid] = DiscoveredPod(uid, name, namespace, qosClass, containers)
            }
            return result
        }
    }
}

// Kubelet response DTOs
@JsonIgnoreProperties(ignoreUnknown = true)
data class KubeletPodList(val items: List<KubeletPod> = emptyList())

@JsonIgnoreProperties(ignoreUnknown = true)
data class KubeletPod(val metadata: KubeletPodMeta? = null, val status: KubeletPodStatus? = null)

@JsonIgnoreProperties(ignoreUnknown = true)
data class KubeletPodMeta(val uid: String? = null, val name: String? = null, val namespace: String? = null)

@JsonIgnoreProperties(ignoreUnknown = true)
data class KubeletPodStatus(val qosClass: String? = null, val containerStatuses: List<KubeletContainerStatus>? = null)

@JsonIgnoreProperties(ignoreUnknown = true)
data class KubeletContainerStatus(val name: String? = null, val containerID: String? = null)
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.discovery.KubeletPodProviderTest" --no-daemon`
Expected: PASS

**Note:** Add `com.fasterxml.jackson.module:jackson-module-kotlin` to `build.gradle.kts` dependencies:
```kotlin
implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
```

**Step 5: Commit**

```bash
cd /Users/jongsu && git add kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/discovery/KubeletPodProvider.kt kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/discovery/KubeletPodProviderTest.kt kpod-metrics/build.gradle.kts
git commit -m "feat: add KubeletPodProvider with kubelet /pods polling fallback"
```

---

## Task 8: Add DiskIOCollector (Micrometer)

**Files:**
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/DiskIOCollector.kt`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/collector/DiskIOCollectorTest.kt`

**Step 1: Write the failing test**

```kotlin
// kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/collector/DiskIOCollectorTest.kt
package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.model.CgroupVersion
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText

class DiskIOCollectorTest {
    @TempDir
    lateinit var tempDir: Path
    private lateinit var registry: SimpleMeterRegistry

    @BeforeEach
    fun setUp() { registry = SimpleMeterRegistry() }

    @Test
    fun `collects disk IO metrics for v2 and registers with Micrometer`() {
        val containerDir = tempDir.resolve("container1")
        containerDir.createDirectories()
        containerDir.resolve("io.stat").writeText(
            "8:0 rbytes=1048576 wbytes=524288 rios=100 wios=50 dbytes=0 dios=0\n"
        )
        val reader = CgroupReader(CgroupVersion.V2)
        val collector = DiskIOCollector(reader, registry)
        val targets = listOf(PodCgroupTarget("nginx-pod", "default", "nginx",
            containerDir.toString(), "test-node"))
        collector.collect(targets)

        val readCounter = registry.counter("kpod.disk.read.bytes",
            "namespace", "default", "pod", "nginx-pod", "container", "nginx",
            "node", "test-node", "device", "8:0")
        assertEquals(1048576.0, readCounter.count())

        val writeOps = registry.counter("kpod.disk.writes",
            "namespace", "default", "pod", "nginx-pod", "container", "nginx",
            "node", "test-node", "device", "8:0")
        assertEquals(50.0, writeOps.count())
    }

    @Test
    fun `handles missing io_stat gracefully`() {
        val containerDir = tempDir.resolve("container2")
        containerDir.createDirectories()
        val reader = CgroupReader(CgroupVersion.V2)
        val collector = DiskIOCollector(reader, registry)
        val targets = listOf(PodCgroupTarget("empty-pod", "default", "empty",
            containerDir.toString(), "test-node"))
        collector.collect(targets)
        assertTrue(registry.meters.isEmpty())
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.collector.DiskIOCollectorTest" --no-daemon`
Expected: FAIL

**Step 3: Write the implementation**

```kotlin
// kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/DiskIOCollector.kt
package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags

class DiskIOCollector(
    private val reader: CgroupReader,
    private val registry: MeterRegistry
) {
    fun collect(targets: List<PodCgroupTarget>) {
        for (target in targets) {
            val stats = reader.readDiskIO(target.cgroupPath)
            for (stat in stats) {
                val device = "${stat.major}:${stat.minor}"
                val tags = Tags.of(
                    "namespace", target.namespace,
                    "pod", target.podName,
                    "container", target.containerName,
                    "node", target.nodeName,
                    "device", device
                )
                registry.counter("kpod.disk.read.bytes", tags).increment(stat.readBytes.toDouble())
                registry.counter("kpod.disk.written.bytes", tags).increment(stat.writeBytes.toDouble())
                registry.counter("kpod.disk.reads", tags).increment(stat.reads.toDouble())
                registry.counter("kpod.disk.writes", tags).increment(stat.writes.toDouble())
            }
        }
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.collector.DiskIOCollectorTest" --no-daemon`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/jongsu && git add kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/DiskIOCollector.kt kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/collector/DiskIOCollectorTest.kt
git commit -m "feat: add DiskIOCollector with Micrometer metrics for cgroup disk I/O"
```

---

## Task 9: Add InterfaceNetworkCollector (Micrometer)

**Files:**
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/InterfaceNetworkCollector.kt`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/collector/InterfaceNetworkCollectorTest.kt`

**Step 1: Write the failing test**

```kotlin
// kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/collector/InterfaceNetworkCollectorTest.kt
package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.model.CgroupVersion
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText

class InterfaceNetworkCollectorTest {
    @TempDir
    lateinit var tempDir: Path
    private lateinit var registry: SimpleMeterRegistry

    @BeforeEach
    fun setUp() { registry = SimpleMeterRegistry() }

    @Test
    fun `collects interface network metrics from proc net dev`() {
        val containerDir = tempDir.resolve("cgroup/container1")
        containerDir.createDirectories()
        containerDir.resolve("cgroup.procs").writeText("42\n")
        val procDir = tempDir.resolve("proc/42/net")
        procDir.createDirectories()
        procDir.resolve("dev").writeText(
            "Inter-|   Receive                                                |  Transmit\n" +
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
            "  eth0: 9876543    5432    1    2    0     0          0         0  1111111    3333    0    1    0     0       0          0\n"
        )
        val reader = CgroupReader(CgroupVersion.V2)
        val collector = InterfaceNetworkCollector(reader, tempDir.resolve("proc").toString(), registry)
        val targets = listOf(PodCgroupTarget("nginx-pod", "default", "nginx",
            containerDir.toString(), "test-node"))
        collector.collect(targets)

        val rxBytes = registry.counter("kpod.net.iface.rx.bytes",
            "namespace", "default", "pod", "nginx-pod", "container", "nginx",
            "node", "test-node", "interface", "eth0")
        assertEquals(9876543.0, rxBytes.count())

        val txPackets = registry.counter("kpod.net.iface.tx.packets",
            "namespace", "default", "pod", "nginx-pod", "container", "nginx",
            "node", "test-node", "interface", "eth0")
        assertEquals(3333.0, txPackets.count())
    }

    @Test
    fun `skips container when PID not found`() {
        val containerDir = tempDir.resolve("cgroup/container2")
        containerDir.createDirectories()
        val reader = CgroupReader(CgroupVersion.V2)
        val collector = InterfaceNetworkCollector(reader, tempDir.resolve("proc").toString(), registry)
        val targets = listOf(PodCgroupTarget("no-pid-pod", "default", "ghost",
            containerDir.toString(), "test-node"))
        collector.collect(targets)
        assertTrue(registry.meters.isEmpty())
    }
}
```

**Step 2: Run test, Step 3: Write implementation**

```kotlin
// kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/InterfaceNetworkCollector.kt
package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags

class InterfaceNetworkCollector(
    private val reader: CgroupReader,
    private val procRoot: String,
    private val registry: MeterRegistry
) {
    fun collect(targets: List<PodCgroupTarget>) {
        for (target in targets) {
            val pid = reader.readInitPid(target.cgroupPath) ?: continue
            val stats = reader.readNetworkStats(procRoot, pid)
            for (stat in stats) {
                val tags = Tags.of(
                    "namespace", target.namespace,
                    "pod", target.podName,
                    "container", target.containerName,
                    "node", target.nodeName,
                    "interface", stat.interfaceName
                )
                registry.counter("kpod.net.iface.rx.bytes", tags).increment(stat.rxBytes.toDouble())
                registry.counter("kpod.net.iface.tx.bytes", tags).increment(stat.txBytes.toDouble())
                registry.counter("kpod.net.iface.rx.packets", tags).increment(stat.rxPackets.toDouble())
                registry.counter("kpod.net.iface.tx.packets", tags).increment(stat.txPackets.toDouble())
                registry.counter("kpod.net.iface.rx.errors", tags).increment(stat.rxErrors.toDouble())
                registry.counter("kpod.net.iface.tx.errors", tags).increment(stat.txErrors.toDouble())
                registry.counter("kpod.net.iface.rx.drops", tags).increment(stat.rxDrops.toDouble())
                registry.counter("kpod.net.iface.tx.drops", tags).increment(stat.txDrops.toDouble())
            }
        }
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.collector.InterfaceNetworkCollectorTest" --no-daemon`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/jongsu && git add kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/InterfaceNetworkCollector.kt kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/collector/InterfaceNetworkCollectorTest.kt
git commit -m "feat: add InterfaceNetworkCollector for /proc/net/dev interface-level metrics"
```

---

## Task 10: Add FilesystemCollector (Micrometer)

**Files:**
- Create: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/FilesystemCollector.kt`
- Test: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/collector/FilesystemCollectorTest.kt`

**Step 1: Write the failing test**

```kotlin
// kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/collector/FilesystemCollectorTest.kt
package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.model.CgroupVersion
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText

class FilesystemCollectorTest {
    @TempDir
    lateinit var tempDir: Path
    private lateinit var registry: SimpleMeterRegistry

    @BeforeEach
    fun setUp() { registry = SimpleMeterRegistry() }

    @Test
    fun `collects filesystem metrics from mountinfo`() {
        val containerDir = tempDir.resolve("cgroup/container1")
        containerDir.createDirectories()
        containerDir.resolve("cgroup.procs").writeText("42\n")
        val mountInfoDir = tempDir.resolve("proc/42")
        mountInfoDir.createDirectories()
        mountInfoDir.resolve("mountinfo").writeText(
            "22 1 0:21 / / rw,relatime - overlay overlay rw\n" +
            "35 22 0:22 / /proc rw,nosuid - proc proc rw\n"
        )
        mountInfoDir.resolve("root").createDirectories()

        val reader = CgroupReader(CgroupVersion.V2)
        val collector = FilesystemCollector(reader, tempDir.resolve("proc").toString(), registry)
        val targets = listOf(PodCgroupTarget("web-pod", "default", "app",
            containerDir.toString(), "test-node"))
        collector.collect(targets)

        // Verify gauge was registered for overlay mount (not proc)
        val capacity = registry.find("kpod.fs.capacity.bytes")
            .tag("pod", "web-pod").gauge()
        assertNotNull(capacity)
        assertTrue(capacity!!.value() > 0)
    }

    @Test
    fun `skips container when PID not found`() {
        val containerDir = tempDir.resolve("cgroup/container2")
        containerDir.createDirectories()
        val reader = CgroupReader(CgroupVersion.V2)
        val collector = FilesystemCollector(reader, tempDir.resolve("proc").toString(), registry)
        val targets = listOf(PodCgroupTarget("no-pid-pod", "default", "ghost",
            containerDir.toString(), "test-node"))
        collector.collect(targets)
        assertTrue(registry.meters.isEmpty())
    }
}
```

**Step 2: Run test, Step 3: Write implementation**

```kotlin
// kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/FilesystemCollector.kt
package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import java.util.concurrent.atomic.AtomicLong

class FilesystemCollector(
    private val reader: CgroupReader,
    private val procRoot: String,
    private val registry: MeterRegistry
) {
    private data class GaugeKey(val pod: String, val ns: String, val container: String, val node: String, val mount: String)
    private val capacityValues = java.util.concurrent.ConcurrentHashMap<GaugeKey, AtomicLong>()
    private val usageValues = java.util.concurrent.ConcurrentHashMap<GaugeKey, AtomicLong>()
    private val availableValues = java.util.concurrent.ConcurrentHashMap<GaugeKey, AtomicLong>()

    fun collect(targets: List<PodCgroupTarget>) {
        for (target in targets) {
            val pid = reader.readInitPid(target.cgroupPath) ?: continue
            val stats = reader.readFilesystemStats(procRoot, pid)
            for (stat in stats) {
                val key = GaugeKey(target.podName, target.namespace, target.containerName, target.nodeName, stat.mountPoint)
                val tags = Tags.of(
                    "namespace", target.namespace,
                    "pod", target.podName,
                    "container", target.containerName,
                    "node", target.nodeName,
                    "mountpoint", stat.mountPoint
                )
                getOrRegisterGauge(capacityValues, key, "kpod.fs.capacity.bytes", tags).set(stat.totalBytes)
                getOrRegisterGauge(usageValues, key, "kpod.fs.usage.bytes", tags).set(stat.usedBytes)
                getOrRegisterGauge(availableValues, key, "kpod.fs.available.bytes", tags).set(stat.availableBytes)
            }
        }
    }

    private fun getOrRegisterGauge(
        store: java.util.concurrent.ConcurrentHashMap<GaugeKey, AtomicLong>,
        key: GaugeKey, name: String, tags: Tags
    ): AtomicLong {
        return store.computeIfAbsent(key) { k ->
            val value = AtomicLong(0)
            registry.gauge(name, tags, value) { it.toDouble() }
            value
        }
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.collector.FilesystemCollectorTest" --no-daemon`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/jongsu && git add kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/FilesystemCollector.kt kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/collector/FilesystemCollectorTest.kt
git commit -m "feat: add FilesystemCollector for filesystem capacity/usage/available metrics"
```

---

## Task 11: Update MetricsProperties and profiles

**Files:**
- Modify: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/config/MetricsProperties.kt`
- Modify: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/config/MetricsPropertiesTest.kt`

**Step 1: Write the failing test**

Add tests for the new config options and updated profiles:

```kotlin
@Test
fun `standard profile enables diskIO, interfaceNet, and filesystem cgroup collectors`() {
    val resolved = props.resolveProfile()
    assertTrue(resolved.cgroup.diskIO)
    assertTrue(resolved.cgroup.interfaceNetwork)
    assertTrue(resolved.cgroup.filesystem)
}

@Test
fun `minimal profile enables only diskIO cgroup collector`() {
    val resolved = props.resolveProfile(override = "minimal")
    assertTrue(resolved.cgroup.diskIO)
    assertFalse(resolved.cgroup.interfaceNetwork)
    assertFalse(resolved.cgroup.filesystem)
}

@Test
fun `comprehensive profile enables all cgroup collectors`() {
    val resolved = props.resolveProfile(override = "comprehensive")
    assertTrue(resolved.cgroup.diskIO)
    assertTrue(resolved.cgroup.interfaceNetwork)
    assertTrue(resolved.cgroup.filesystem)
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.config.MetricsPropertiesTest" --no-daemon`
Expected: FAIL

**Step 3: Update MetricsProperties**

Add to `MetricsProperties.kt`:

```kotlin
// Add new properties classes:
data class DiscoveryProperties(
    val mode: String = "informer",
    val kubeletPollInterval: Long = 30,
    val nodeIp: String = ""
)

data class CgroupProperties(
    val root: String = "/host/sys/fs/cgroup",
    val procRoot: String = "/host/proc"
)

data class CgroupCollectorProperties(
    val diskIO: Boolean = true,
    val interfaceNetwork: Boolean = true,
    val filesystem: Boolean = true
)

// Add to MetricsProperties data class:
val discovery: DiscoveryProperties = DiscoveryProperties(),
val cgroup: CgroupProperties = CgroupProperties(),

// Add to ResolvedConfig:
data class ResolvedConfig(
    val cpu: CpuProperties,
    val network: NetworkProperties,
    val memory: MemoryProperties,
    val syscall: SyscallProperties,
    val cgroup: CgroupCollectorProperties = CgroupCollectorProperties()
)

// Update resolveProfile() to include cgroup config per profile:
// minimal: cgroup = CgroupCollectorProperties(diskIO = true, interfaceNetwork = false, filesystem = false)
// standard: cgroup = CgroupCollectorProperties(diskIO = true, interfaceNetwork = true, filesystem = true)
// comprehensive: cgroup = CgroupCollectorProperties(diskIO = true, interfaceNetwork = true, filesystem = true)
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.config.MetricsPropertiesTest" --no-daemon`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/jongsu && git add kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/config/MetricsProperties.kt kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/config/MetricsPropertiesTest.kt
git commit -m "feat: add discovery, cgroup config, and cgroup collector profile settings"
```

---

## Task 12: Update MetricsCollectorService to include cgroup collectors

**Files:**
- Modify: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/MetricsCollectorService.kt`
- Modify: `kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/collector/MetricsCollectorServiceTest.kt`

**Step 1: Write the failing test**

```kotlin
@Test
fun `collect runs cgroup collectors with resolved targets`() {
    val diskIOCollector = mockk<DiskIOCollector>(relaxed = true)
    val ifaceNetCollector = mockk<InterfaceNetworkCollector>(relaxed = true)
    val fsCollector = mockk<FilesystemCollector>(relaxed = true)
    val mapper = mockk<PodCgroupMapper>()
    val targets = listOf(PodCgroupTarget("pod", "ns", "c", "/cg", "node"))
    every { mapper.resolve() } returns targets

    val service = MetricsCollectorService(
        cpuCollector, netCollector, memCollector, syscallCollector,
        diskIOCollector, ifaceNetCollector, fsCollector, mapper
    )
    service.collect()

    verify { diskIOCollector.collect(targets) }
    verify { ifaceNetCollector.collect(targets) }
    verify { fsCollector.collect(targets) }
}
```

**Step 2: Run test to verify it fails**

**Step 3: Update MetricsCollectorService**

Add the three new collectors and PodCgroupMapper to the constructor. In `collect()`, resolve targets from mapper and pass to cgroup collectors alongside the existing eBPF collectors:

```kotlin
class MetricsCollectorService(
    private val cpuCollector: CpuSchedulingCollector,
    private val netCollector: NetworkCollector,
    private val memCollector: MemoryCollector,
    private val syscallCollector: SyscallCollector,
    private val diskIOCollector: DiskIOCollector? = null,
    private val ifaceNetCollector: InterfaceNetworkCollector? = null,
    private val fsCollector: FilesystemCollector? = null,
    private val podCgroupMapper: PodCgroupMapper? = null
) {
    // ... existing fields ...

    @Scheduled(fixedDelayString = "\${kpod.poll-interval:15000}")
    fun collect() = runBlocking(vtDispatcher) {
        // eBPF collectors (no input needed)
        val bpfCollectors = listOf(
            "cpu" to cpuCollector::collect,
            "network" to netCollector::collect,
            "memory" to memCollector::collect,
            "syscall" to syscallCollector::collect
        )

        // Cgroup collectors (need resolved targets)
        val targets = try {
            podCgroupMapper?.resolve() ?: emptyList()
        } catch (e: Exception) {
            log.error("Failed to resolve cgroup targets: {}", e.message, e)
            emptyList()
        }

        val cgroupCollectors = listOfNotNull(
            diskIOCollector?.let { "diskIO" to { it.collect(targets) } },
            ifaceNetCollector?.let { "ifaceNet" to { it.collect(targets) } },
            fsCollector?.let { "filesystem" to { it.collect(targets) } }
        )

        (bpfCollectors + cgroupCollectors).map { (name, collectFn) ->
            launch {
                try { collectFn() }
                catch (e: Exception) { log.error("Collector '{}' failed: {}", name, e.message, e) }
            }
        }.joinAll()
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --tests "com.internal.kpodmetrics.collector.MetricsCollectorServiceTest" --no-daemon`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/jongsu && git add kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/collector/MetricsCollectorService.kt kpod-metrics/src/test/kotlin/com/internal/kpodmetrics/collector/MetricsCollectorServiceTest.kt
git commit -m "feat: update MetricsCollectorService to orchestrate both eBPF and cgroup collectors"
```

---

## Task 13: Update BpfAutoConfiguration to wire everything together

**Files:**
- Modify: `kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/config/BpfAutoConfiguration.kt`

**Step 1: Update the configuration class**

Add beans for:
- CgroupVersionDetector
- CgroupReader
- CgroupPathResolver
- PodProvider (conditional on discovery mode)
- KubeletPodProvider (when mode = kubelet)
- PodCgroupMapper
- DiskIOCollector, InterfaceNetworkCollector, FilesystemCollector
- Update MetricsCollectorService bean to include new collectors

Fix existing bug: `properties` → `props` in podWatcher bean.

Key beans to add:

```kotlin
@Bean
fun cgroupVersionDetector(): CgroupVersionDetector =
    CgroupVersionDetector(props.cgroup.root)

@Bean
fun cgroupReader(detector: CgroupVersionDetector): CgroupReader =
    CgroupReader(detector.detect())

@Bean
fun cgroupPathResolver(detector: CgroupVersionDetector): CgroupPathResolver =
    CgroupPathResolver(props.cgroup.root, detector.detect())

@Bean
fun podCgroupMapper(podProvider: PodProvider, resolver: CgroupPathResolver): PodCgroupMapper =
    PodCgroupMapper(podProvider, resolver, props.nodeName)

@Bean
fun diskIOCollector(reader: CgroupReader, registry: MeterRegistry, config: ResolvedConfig): DiskIOCollector? {
    if (!config.cgroup.diskIO) return null
    return DiskIOCollector(reader, registry)
}

@Bean
fun interfaceNetworkCollector(reader: CgroupReader, registry: MeterRegistry, config: ResolvedConfig): InterfaceNetworkCollector? {
    if (!config.cgroup.interfaceNetwork) return null
    return InterfaceNetworkCollector(reader, props.cgroup.procRoot, registry)
}

@Bean
fun filesystemCollector(reader: CgroupReader, registry: MeterRegistry, config: ResolvedConfig): FilesystemCollector? {
    if (!config.cgroup.filesystem) return null
    return FilesystemCollector(reader, props.cgroup.procRoot, registry)
}
```

**Step 2: Run all tests**

Run: `cd /Users/jongsu/kpod-metrics && ./gradlew test --no-daemon`
Expected: ALL PASS

**Step 3: Commit**

```bash
cd /Users/jongsu && git add kpod-metrics/src/main/kotlin/com/internal/kpodmetrics/config/BpfAutoConfiguration.kt
git commit -m "feat: wire cgroup infrastructure and collectors in BpfAutoConfiguration"
```

---

## Task 14: Update application.yml

**Files:**
- Modify: `kpod-metrics/src/main/resources/application.yml`

Add the new configuration sections:

```yaml
kpod:
  profile: standard
  poll-interval: 15000
  node-name: ${NODE_NAME:unknown}
  discovery:
    mode: ${KPOD_DISCOVERY_MODE:informer}
    kubelet-poll-interval: ${KUBELET_POLL_INTERVAL:30}
    node-ip: ${NODE_IP:}
  bpf:
    enabled: true
    program-dir: /app/bpf
  cgroup:
    root: ${KPOD_CGROUP_ROOT:/host/sys/fs/cgroup}
    proc-root: ${KPOD_PROC_ROOT:/host/proc}
  filter:
    namespaces: []
    exclude-namespaces:
      - kube-system
      - kube-public
```

**Commit:**

```bash
cd /Users/jongsu && git add kpod-metrics/src/main/resources/application.yml
git commit -m "feat: add discovery and cgroup config to application.yml"
```

---

## Task 15: Update build.gradle.kts

**Files:**
- Modify: `kpod-metrics/build.gradle.kts`

Add:
```kotlin
implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
```

(If not already added in Task 7.)

**Commit:**

```bash
cd /Users/jongsu && git add kpod-metrics/build.gradle.kts
git commit -m "feat: add jackson-module-kotlin dependency for kubelet JSON parsing"
```

---

## Task 16: Update Helm chart

**Files:**
- Modify: `kpod-metrics/helm/kpod-metrics/values.yaml`
- Modify: `kpod-metrics/helm/kpod-metrics/templates/configmap.yaml`
- Modify: `kpod-metrics/helm/kpod-metrics/templates/daemonset.yaml`

**values.yaml** - Add new config:
```yaml
config:
  profile: standard
  pollInterval: 15000
  discovery:
    mode: informer
    kubeletPollInterval: 30
  cgroup:
    root: /host/sys/fs/cgroup
    procRoot: /host/proc
```

**configmap.yaml** - Add cgroup and discovery config sections to the rendered application.yml.

**daemonset.yaml** - Add `NODE_IP` env var:
```yaml
- name: NODE_IP
  valueFrom:
    fieldRef:
      fieldPath: status.hostIP
```

**Commit:**

```bash
cd /Users/jongsu && git add kpod-metrics/helm/
git commit -m "feat: update Helm chart with discovery and cgroup configuration"
```

---

## Task 17: Run full test suite and verify

**Step 1: Run all tests**

```bash
cd /Users/jongsu/kpod-metrics && ./gradlew test --no-daemon
```

Expected: ALL PASS

**Step 2: Verify compilation**

```bash
cd /Users/jongsu/kpod-metrics && ./gradlew compileKotlin --no-daemon
```

Expected: BUILD SUCCESSFUL

**Step 3: Final commit (if any fixes needed)**

```bash
cd /Users/jongsu && git add -A kpod-metrics/ && git commit -m "fix: resolve any remaining compilation/test issues from merge"
```
