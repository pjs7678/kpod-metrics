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
        assertNull(registry.find("kpod.fs.capacity.bytes").tag("pod", "no-pid-pod").gauge())
    }
}
