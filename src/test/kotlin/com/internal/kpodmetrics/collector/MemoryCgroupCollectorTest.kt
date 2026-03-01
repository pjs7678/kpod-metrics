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

class MemoryCgroupCollectorTest {
    @TempDir
    lateinit var tempDir: Path
    private lateinit var registry: SimpleMeterRegistry

    @BeforeEach
    fun setUp() { registry = SimpleMeterRegistry() }

    @Test
    fun `collects memory metrics for v2 cgroup`() {
        val containerDir = tempDir.resolve("container1")
        containerDir.createDirectories()
        containerDir.resolve("memory.current").writeText("104857600\n")
        containerDir.resolve("memory.peak").writeText("209715200\n")
        containerDir.resolve("memory.swap.current").writeText("1048576\n")
        containerDir.resolve("memory.stat").writeText(
            "anon 50000000\ninactive_file 20000000\nactive_file 10000000\n"
        )
        val reader = CgroupReader(CgroupVersion.V2)
        val collector = MemoryCgroupCollector(reader, registry)
        val targets = listOf(PodCgroupTarget("nginx-pod", "default", "nginx",
            containerDir.toString(), "test-node"))
        collector.collect(targets)

        val usage = registry.find("kpod.mem.cgroup.usage.bytes")
            .tag("pod", "nginx-pod").gauge()
        assertNotNull(usage)
        assertEquals(104857600.0, usage!!.value())

        val peak = registry.find("kpod.mem.cgroup.peak.bytes")
            .tag("pod", "nginx-pod").gauge()
        assertNotNull(peak)
        assertEquals(209715200.0, peak!!.value())

        val cache = registry.find("kpod.mem.cgroup.cache.bytes")
            .tag("pod", "nginx-pod").gauge()
        assertNotNull(cache)
        assertEquals(30000000.0, cache!!.value())

        val swap = registry.find("kpod.mem.cgroup.swap.bytes")
            .tag("pod", "nginx-pod").gauge()
        assertNotNull(swap)
        assertEquals(1048576.0, swap!!.value())
    }

    @Test
    fun `handles missing memory files gracefully`() {
        val containerDir = tempDir.resolve("container2")
        containerDir.createDirectories()
        val reader = CgroupReader(CgroupVersion.V2)
        val collector = MemoryCgroupCollector(reader, registry)
        val targets = listOf(PodCgroupTarget("empty-pod", "default", "empty",
            containerDir.toString(), "test-node"))
        collector.collect(targets)

        // No memory metrics should be registered for this pod
        assertNull(registry.find("kpod.mem.cgroup.usage.bytes").tag("pod", "empty-pod").gauge())
    }

    @Test
    fun `single target failure does not block other targets`() {
        val goodDir = tempDir.resolve("good")
        goodDir.createDirectories()
        goodDir.resolve("memory.current").writeText("50000000\n")
        goodDir.resolve("memory.stat").writeText("inactive_file 5000000\nactive_file 3000000\n")

        val reader = CgroupReader(CgroupVersion.V2)
        val collector = MemoryCgroupCollector(reader, registry)
        val targets = listOf(
            PodCgroupTarget("bad-pod", "ns", "c", "/nonexistent/path", "node"),
            PodCgroupTarget("good-pod", "ns", "c", goodDir.toString(), "node")
        )
        collector.collect(targets)

        val usage = registry.find("kpod.mem.cgroup.usage.bytes").tag("pod", "good-pod").gauge()
        assertNotNull(usage)
        assertEquals(50000000.0, usage!!.value())
    }

    @Test
    fun `collects memory metrics for v1 cgroup`() {
        val containerDir = tempDir.resolve("container-v1")
        containerDir.createDirectories()
        containerDir.resolve("memory.usage_in_bytes").writeText("80000000\n")
        containerDir.resolve("memory.max_usage_in_bytes").writeText("160000000\n")
        containerDir.resolve("memory.memsw.usage_in_bytes").writeText("82000000\n")
        containerDir.resolve("memory.stat").writeText("total_cache 15000000\nrss 65000000\n")

        val reader = CgroupReader(CgroupVersion.V1)
        val collector = MemoryCgroupCollector(reader, registry)
        val targets = listOf(PodCgroupTarget("v1-pod", "default", "app",
            containerDir.toString(), "test-node"))
        collector.collect(targets)

        val usage = registry.find("kpod.mem.cgroup.usage.bytes")
            .tag("pod", "v1-pod").gauge()
        assertNotNull(usage)
        assertEquals(80000000.0, usage!!.value())

        val peak = registry.find("kpod.mem.cgroup.peak.bytes")
            .tag("pod", "v1-pod").gauge()
        assertNotNull(peak)
        assertEquals(160000000.0, peak!!.value())

        val cache = registry.find("kpod.mem.cgroup.cache.bytes")
            .tag("pod", "v1-pod").gauge()
        assertNotNull(cache)
        assertEquals(15000000.0, cache!!.value())

        // swap = memsw - usage = 82M - 80M = 2M
        val swap = registry.find("kpod.mem.cgroup.swap.bytes")
            .tag("pod", "v1-pod").gauge()
        assertNotNull(swap)
        assertEquals(2000000.0, swap!!.value())
    }

    @Test
    fun `propagates pod labels as metric tags`() {
        val containerDir = tempDir.resolve("labeled")
        containerDir.createDirectories()
        containerDir.resolve("memory.current").writeText("50000000\n")
        containerDir.resolve("memory.stat").writeText("inactive_file 1000\nactive_file 2000\n")

        val reader = CgroupReader(CgroupVersion.V2)
        val collector = MemoryCgroupCollector(reader, registry)
        val targets = listOf(PodCgroupTarget(
            "labeled-pod", "default", "nginx",
            containerDir.toString(), "test-node",
            labels = mapOf("app" to "myapp")
        ))
        collector.collect(targets)

        val usage = registry.find("kpod.mem.cgroup.usage.bytes")
            .tag("pod", "labeled-pod")
            .tag("label_app", "myapp")
            .gauge()
        assertNotNull(usage)
        assertEquals(50000000.0, usage!!.value())
    }
}
