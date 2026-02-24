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
