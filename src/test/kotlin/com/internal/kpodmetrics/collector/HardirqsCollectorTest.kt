package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.*
import com.internal.kpodmetrics.config.MetricsProperties
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import io.mockk.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class HardirqsCollectorTest {

    private lateinit var bridge: BpfBridge
    private lateinit var programManager: BpfProgramManager
    private lateinit var cgroupResolver: CgroupResolver
    private lateinit var registry: MeterRegistry
    private lateinit var collector: HardirqsCollector

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

        val config = MetricsProperties().resolveProfile("comprehensive")
        collector = HardirqsCollector(bridge, programManager, cgroupResolver, registry, config, "test-node")
    }

    @Test
    fun `collect reads irq latency and count maps and registers metrics`() {
        every { programManager.getMapFd("hardirqs", "irq_latency") } returns 5
        every { programManager.getMapFd("hardirqs", "irq_count") } returns 6

        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(100L).array()

        val latencyValue = buildHistValue(count = 10, sumNs = 2_000_000_000L)
        every { bridge.mapBatchLookupAndDelete(5, 8, 232, any()) } returns listOf(keyBytes to latencyValue)

        val countKeyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(100L).array()
        val countValue = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(42L).array()
        every { bridge.mapBatchLookupAndDelete(6, 8, 8, any()) } returns listOf(countKeyBytes to countValue)

        collector.collect()

        assertTrue(registry.meters.any { it.id.name == "kpod.irq.hw.latency" })

        val counter = registry.counter("kpod.irq.hw.count",
            "namespace", "default", "pod", "test-pod", "container", "app", "node", "test-node")
        assertEquals(42.0, counter.count())
    }

    @Test
    fun `collect skips latency entries with zero count`() {
        every { programManager.getMapFd("hardirqs", "irq_latency") } returns 5
        every { programManager.getMapFd("hardirqs", "irq_count") } returns 6

        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(100L).array()
        val latencyValue = buildHistValue(count = 0, sumNs = 0)
        every { bridge.mapBatchLookupAndDelete(5, 8, 232, any()) } returns listOf(keyBytes to latencyValue)
        every { bridge.mapBatchLookupAndDelete(6, 8, 8, any()) } returns emptyList()

        collector.collect()

        assertTrue(registry.meters.none { it.id.name == "kpod.irq.hw.latency" })
    }

    @Test
    fun `collect skips unknown cgroup ids`() {
        every { programManager.getMapFd("hardirqs", "irq_latency") } returns 5
        every { programManager.getMapFd("hardirqs", "irq_count") } returns 6

        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(999L).array()
        val latencyValue = buildHistValue(count = 5, sumNs = 1_000_000_000L)
        every { bridge.mapBatchLookupAndDelete(5, 8, 232, any()) } returns listOf(keyBytes to latencyValue)

        val countKeyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(999L).array()
        val countValue = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(10L).array()
        every { bridge.mapBatchLookupAndDelete(6, 8, 8, any()) } returns listOf(countKeyBytes to countValue)

        collector.collect()

        assertTrue(registry.meters.none {
            it.id.name.startsWith("kpod") && it.id.getTag("pod") != null
        })
    }

    @Test
    fun `collect does nothing when hardirqs disabled`() {
        val config = MetricsProperties().resolveProfile("standard")
        val disabledCollector = HardirqsCollector(bridge, programManager, cgroupResolver, registry, config, "test-node")

        disabledCollector.collect()

        verify(exactly = 0) { programManager.getMapFd(any(), any()) }
        assertTrue(registry.meters.isEmpty())
    }

    private fun buildHistValue(count: Long, sumNs: Long): ByteArray {
        val buf = ByteBuffer.allocate(232).order(ByteOrder.LITTLE_ENDIAN)
        for (i in 0 until 27) {
            buf.putLong(0L)
        }
        buf.putLong(count)
        buf.putLong(sumNs)
        return buf.array()
    }
}
