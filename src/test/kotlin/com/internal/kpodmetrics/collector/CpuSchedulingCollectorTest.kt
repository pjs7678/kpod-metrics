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
        every { bridge.mapGetNextKey(5, null, 8) } returns keyBytes
        every { bridge.mapGetNextKey(5, keyBytes, 8) } returns null

        val valueBytes = buildHistValue(slot = 10, count = 10, sumNs = 10000)
        every { bridge.mapLookup(5, keyBytes, any()) } returns valueBytes

        every { bridge.mapGetNextKey(6, null, 8) } returns null

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
        every { bridge.mapGetNextKey(5, null, 8) } returns keyBytes
        every { bridge.mapGetNextKey(5, keyBytes, 8) } returns null
        every { bridge.mapLookup(5, keyBytes, any()) } returns buildHistValue(10, 5, 5000)
        every { bridge.mapGetNextKey(6, null, 8) } returns null

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
