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

class SoftirqsCollectorTest {

    private lateinit var bridge: BpfBridge
    private lateinit var programManager: BpfProgramManager
    private lateinit var cgroupResolver: CgroupResolver
    private lateinit var registry: MeterRegistry
    private lateinit var collector: SoftirqsCollector

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
        collector = SoftirqsCollector(bridge, programManager, cgroupResolver, registry, config, "test-node")
    }

    @Test
    fun `collect reads softirq latency map and registers distribution summary`() {
        every { programManager.getMapFd("softirqs", "softirq_latency") } returns 5

        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(100L).array()
        val valueBytes = buildHistValue(count = 15, sumNs = 3_000_000_000L)

        every { bridge.mapBatchLookupAndDelete(5, 8, 232, any()) } returns listOf(keyBytes to valueBytes)

        collector.collect()

        assertTrue(registry.meters.any { it.id.name == "kpod.irq.sw.latency" })
    }

    @Test
    fun `collect skips entries with zero count`() {
        every { programManager.getMapFd("softirqs", "softirq_latency") } returns 5

        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(100L).array()
        val valueBytes = buildHistValue(count = 0, sumNs = 0)

        every { bridge.mapBatchLookupAndDelete(5, 8, 232, any()) } returns listOf(keyBytes to valueBytes)

        collector.collect()

        assertTrue(registry.meters.none { it.id.name == "kpod.irq.sw.latency" })
    }

    @Test
    fun `collect skips unknown cgroup ids`() {
        every { programManager.getMapFd("softirqs", "softirq_latency") } returns 5

        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(999L).array()
        val valueBytes = buildHistValue(count = 5, sumNs = 1_000_000_000L)

        every { bridge.mapBatchLookupAndDelete(5, 8, 232, any()) } returns listOf(keyBytes to valueBytes)

        collector.collect()

        assertTrue(registry.meters.none {
            it.id.name.startsWith("kpod") && it.id.getTag("pod") != null
        })
    }

    @Test
    fun `collect does nothing when softirqs disabled`() {
        val config = MetricsProperties().resolveProfile("standard")
        val disabledCollector = SoftirqsCollector(bridge, programManager, cgroupResolver, registry, config, "test-node")

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
