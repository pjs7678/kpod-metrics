package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.*
import com.internal.kpodmetrics.config.MetricsProperties
import com.internal.kpodmetrics.config.MemoryProperties
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import io.mockk.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class MemoryCollectorTest {

    private lateinit var bridge: BpfBridge
    private lateinit var programManager: BpfProgramManager
    private lateinit var cgroupResolver: CgroupResolver
    private lateinit var registry: MeterRegistry
    private lateinit var collector: MemoryCollector

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
        collector = MemoryCollector(bridge, programManager, cgroupResolver, registry, config, "test-node")
    }

    @Test
    fun `collect reads oom kills map and registers counter`() {
        every { programManager.getMapFd("mem", "oom_kills") } returns 20
        every { programManager.getMapFd("mem", "major_faults") } returns 21

        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(100L).array()
        every { bridge.mapGetNextKey(20, null, 8) } returns keyBytes
        every { bridge.mapGetNextKey(20, keyBytes, 8) } returns null

        val valueBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(3L).array()
        every { bridge.mapLookup(20, keyBytes, 8) } returns valueBytes

        every { bridge.mapGetNextKey(21, null, 8) } returns null

        collector.collect()

        val counter = registry.counter("kpod.mem.oom.kills",
            "namespace", "default", "pod", "test-pod", "container", "app", "node", "test-node")
        assertEquals(3.0, counter.count())
    }

    @Test
    fun `collect reads major faults map and registers counter`() {
        every { programManager.getMapFd("mem", "oom_kills") } returns 20
        every { programManager.getMapFd("mem", "major_faults") } returns 21

        every { bridge.mapGetNextKey(20, null, 8) } returns null

        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(100L).array()
        every { bridge.mapGetNextKey(21, null, 8) } returns keyBytes
        every { bridge.mapGetNextKey(21, keyBytes, 8) } returns null

        val valueBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(42L).array()
        every { bridge.mapLookup(21, keyBytes, 8) } returns valueBytes

        collector.collect()

        val counter = registry.counter("kpod.mem.major.page.faults",
            "namespace", "default", "pod", "test-pod", "container", "app", "node", "test-node")
        assertEquals(42.0, counter.count())
    }

    @Test
    fun `collect skips unknown cgroup ids`() {
        every { programManager.getMapFd("mem", "oom_kills") } returns 20
        every { programManager.getMapFd("mem", "major_faults") } returns 21

        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(999L).array()
        every { bridge.mapGetNextKey(20, null, 8) } returns keyBytes
        every { bridge.mapGetNextKey(20, keyBytes, 8) } returns null
        every { bridge.mapLookup(20, keyBytes, 8) } returns ByteBuffer.allocate(8)
            .order(ByteOrder.LITTLE_ENDIAN).putLong(1L).array()

        every { bridge.mapGetNextKey(21, null, 8) } returns null

        collector.collect()

        assertTrue(registry.meters.none {
            it.id.name.startsWith("kpod") && it.id.getTag("pod") != null
        })
    }

    @Test
    fun `collect skips oom when oom disabled`() {
        val config = MetricsProperties().resolveProfile("minimal")
        // minimal has oom=true, pageFaults=false
        // We need a config with oom=false
        val customConfig = ResolvedConfig(
            cpu = config.cpu,
            network = config.network,
            memory = MemoryProperties(oom = false, pageFaults = false, cgroupStats = false),
            syscall = config.syscall
        )
        val disabledCollector = MemoryCollector(bridge, programManager, cgroupResolver, registry, customConfig, "test-node")

        disabledCollector.collect()

        verify(exactly = 0) { programManager.getMapFd(any(), any()) }
        assertTrue(registry.meters.isEmpty())
    }

    @Test
    fun `collect skips major faults when page faults disabled`() {
        val config = MetricsProperties().resolveProfile("minimal")
        // minimal: oom=true, pageFaults=false
        val collector = MemoryCollector(bridge, programManager, cgroupResolver, registry, config, "test-node")

        every { programManager.getMapFd("mem", "oom_kills") } returns 20
        every { bridge.mapGetNextKey(20, null, 8) } returns null

        collector.collect()

        verify(exactly = 1) { programManager.getMapFd("mem", "oom_kills") }
        verify(exactly = 0) { programManager.getMapFd("mem", "major_faults") }
    }
}
