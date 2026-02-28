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

class CachestatCollectorTest {

    private lateinit var bridge: BpfBridge
    private lateinit var programManager: BpfProgramManager
    private lateinit var cgroupResolver: CgroupResolver
    private lateinit var registry: MeterRegistry
    private lateinit var collector: CachestatCollector

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
        collector = CachestatCollector(bridge, programManager, cgroupResolver, registry, config, "test-node")
    }

    @Test
    fun `collect reads cache stats map and registers counters`() {
        every { programManager.getMapFd("cachestat", "cache_stats") } returns 5

        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(100L).array()
        val valueBytes = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(1000L)  // accesses
            .putLong(200L)   // additions
            .putLong(50L)    // dirtied
            .putLong(10L)    // bufDirtied
            .array()

        every { bridge.mapBatchLookupAndDelete(5, 8, 32, any()) } returns listOf(keyBytes to valueBytes)

        collector.collect()

        val accesses = registry.counter("kpod.mem.cache.accesses",
            "namespace", "default", "pod", "test-pod", "container", "app", "node", "test-node")
        assertEquals(1000.0, accesses.count())

        val additions = registry.counter("kpod.mem.cache.additions",
            "namespace", "default", "pod", "test-pod", "container", "app", "node", "test-node")
        assertEquals(200.0, additions.count())

        val dirtied = registry.counter("kpod.mem.cache.dirtied",
            "namespace", "default", "pod", "test-pod", "container", "app", "node", "test-node")
        assertEquals(50.0, dirtied.count())

        val bufDirtied = registry.counter("kpod.mem.cache.buf.dirtied",
            "namespace", "default", "pod", "test-pod", "container", "app", "node", "test-node")
        assertEquals(10.0, bufDirtied.count())
    }

    @Test
    fun `collect skips unknown cgroup ids`() {
        every { programManager.getMapFd("cachestat", "cache_stats") } returns 5

        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(999L).array()
        val valueBytes = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(100L).putLong(20L).putLong(5L).putLong(1L).array()

        every { bridge.mapBatchLookupAndDelete(5, 8, 32, any()) } returns listOf(keyBytes to valueBytes)

        collector.collect()

        assertTrue(registry.meters.none {
            it.id.name.startsWith("kpod") && it.id.getTag("pod") != null
        })
    }

    @Test
    fun `collect does nothing when cachestat disabled`() {
        val config = MetricsProperties().resolveProfile("standard")
        val disabledCollector = CachestatCollector(bridge, programManager, cgroupResolver, registry, config, "test-node")

        disabledCollector.collect()

        verify(exactly = 0) { programManager.getMapFd(any(), any()) }
        assertTrue(registry.meters.isEmpty())
    }
}
