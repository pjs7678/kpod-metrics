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

        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(100L).array()

        val valueBytes = buildHistValue(slot = 10, count = 10, sumNs = 10000)
        every { bridge.mapBatchLookupAndDelete(5, 8, 232, any()) } returns listOf(keyBytes to valueBytes)

        every { bridge.mapBatchLookupAndDelete(6, 8, 8, any()) } returns emptyList()

        collector.collect()

        val meters = registry.meters
        assertTrue(meters.any { it.id.name == "kpod.cpu.runqueue.latency" })
    }

    @Test
    fun `collect skips unknown cgroup ids`() {
        every { programManager.getMapFd("cpu_sched", "runq_latency") } returns 5
        every { programManager.getMapFd("cpu_sched", "ctx_switches") } returns 6

        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(999L).array()
        every { bridge.mapBatchLookupAndDelete(5, 8, 232, any()) } returns listOf(keyBytes to buildHistValue(10, 5, 5000))
        every { bridge.mapBatchLookupAndDelete(6, 8, 8, any()) } returns emptyList()

        collector.collect()

        assertTrue(registry.meters.none {
            it.id.name.startsWith("kpod") && it.id.getTag("pod") != null
        })
    }

    private fun buildHistValue(slot: Int, count: Long, sumNs: Long): ByteArray {
        val buf = ByteBuffer.allocate(232).order(ByteOrder.LITTLE_ENDIAN)
        for (i in 0 until 27) {
            buf.putLong(if (i == slot) count else 0L)
        }
        buf.putLong(count)
        buf.putLong(sumNs)
        return buf.array()
    }
}
