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

class ExecsnoopCollectorTest {

    private lateinit var bridge: BpfBridge
    private lateinit var programManager: BpfProgramManager
    private lateinit var cgroupResolver: CgroupResolver
    private lateinit var registry: MeterRegistry
    private lateinit var collector: ExecsnoopCollector

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
        collector = ExecsnoopCollector(bridge, programManager, cgroupResolver, registry, config, "test-node")
    }

    @Test
    fun `collect reads exec stats map and registers counters`() {
        every { programManager.getMapFd("execsnoop", "exec_stats") } returns 5

        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(100L).array()
        val valueBytes = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(10L)  // execs
            .putLong(5L)   // exits
            .putLong(3L)   // forks
            .array()

        every { bridge.mapBatchLookupAndDelete(5, 8, 24, any()) } returns listOf(keyBytes to valueBytes)

        collector.collect()

        val execs = registry.counter("kpod.proc.execs",
            "namespace", "default", "pod", "test-pod", "container", "app", "node", "test-node")
        assertEquals(10.0, execs.count())

        val exits = registry.counter("kpod.proc.exits",
            "namespace", "default", "pod", "test-pod", "container", "app", "node", "test-node")
        assertEquals(5.0, exits.count())

        val forks = registry.counter("kpod.proc.forks",
            "namespace", "default", "pod", "test-pod", "container", "app", "node", "test-node")
        assertEquals(3.0, forks.count())
    }

    @Test
    fun `collect skips unknown cgroup ids`() {
        every { programManager.getMapFd("execsnoop", "exec_stats") } returns 5

        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(999L).array()
        val valueBytes = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(1L).putLong(1L).putLong(1L).array()

        every { bridge.mapBatchLookupAndDelete(5, 8, 24, any()) } returns listOf(keyBytes to valueBytes)

        collector.collect()

        assertTrue(registry.meters.none {
            it.id.name.startsWith("kpod") && it.id.getTag("pod") != null
        })
    }

    @Test
    fun `collect does nothing when execsnoop disabled`() {
        val config = MetricsProperties().resolveProfile("minimal")
        val disabledCollector = ExecsnoopCollector(bridge, programManager, cgroupResolver, registry, config, "test-node")

        disabledCollector.collect()

        verify(exactly = 0) { programManager.getMapFd(any(), any()) }
        assertTrue(registry.meters.isEmpty())
    }
}
