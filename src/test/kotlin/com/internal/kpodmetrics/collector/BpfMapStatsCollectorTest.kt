package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import io.mockk.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class BpfMapStatsCollectorTest {

    private lateinit var bridge: BpfBridge
    private lateinit var programManager: BpfProgramManager
    private lateinit var registry: MeterRegistry
    private lateinit var collector: BpfMapStatsCollector

    @BeforeEach
    fun setup() {
        bridge = mockk(relaxed = true)
        programManager = mockk(relaxed = true)
        registry = SimpleMeterRegistry()
        collector = BpfMapStatsCollector(bridge, programManager, registry)
    }

    @Test
    fun `collect reads stats from loaded programs`() {
        every { programManager.isProgramLoaded("cpu_sched") } returns true
        every { programManager.isProgramLoaded("net") } returns false
        every { programManager.isProgramLoaded("syscall") } returns false

        every { programManager.getMapFd("cpu_sched", "ctx_switches_stats") } returns 10
        every { programManager.getMapFd("cpu_sched", "runq_latency_stats") } returns 11

        // entries stat (index 0)
        val entriesKey = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(0).array()
        every { bridge.mapLookupPercpuSum(10, entriesKey, 8) } returns 150L
        every { bridge.mapLookupPercpuSum(11, entriesKey, 8) } returns 200L

        // update errors stat (index 1)
        val errorsKey = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(1).array()
        every { bridge.mapLookupPercpuSum(10, errorsKey, 8) } returns 3L
        every { bridge.mapLookupPercpuSum(11, errorsKey, 8) } returns 0L

        collector.collect()

        assertTrue(registry.meters.any { it.id.name == "kpod.bpf.map.entries" })
        assertTrue(registry.meters.any { it.id.name == "kpod.bpf.map.capacity" })
        assertTrue(registry.meters.any { it.id.name == "kpod.bpf.map.update.errors.total" })
    }

    @Test
    fun `collect skips programs that are not loaded`() {
        every { programManager.isProgramLoaded(any()) } returns false

        collector.collect()

        verify(exactly = 0) { programManager.getMapFd(any(), any()) }
        assertTrue(registry.meters.isEmpty())
    }

    @Test
    fun `collect handles exception from individual map gracefully`() {
        every { programManager.isProgramLoaded("cpu_sched") } returns true
        every { programManager.isProgramLoaded("net") } returns true
        every { programManager.isProgramLoaded("syscall") } returns false

        every { programManager.getMapFd("cpu_sched", "ctx_switches_stats") } throws RuntimeException("map not found")
        every { programManager.getMapFd("cpu_sched", "runq_latency_stats") } throws RuntimeException("map not found")

        every { programManager.getMapFd("net", "tcp_stats_map_stats") } returns 20
        every { programManager.getMapFd("net", "rtt_hist_stats") } returns 21

        val entriesKey = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(0).array()
        every { bridge.mapLookupPercpuSum(20, entriesKey, 8) } returns 50L
        every { bridge.mapLookupPercpuSum(21, entriesKey, 8) } returns 30L

        val errorsKey = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(1).array()
        every { bridge.mapLookupPercpuSum(20, errorsKey, 8) } returns 0L
        every { bridge.mapLookupPercpuSum(21, errorsKey, 8) } returns 0L

        assertDoesNotThrow { collector.collect() }

        // Net stats maps should still be collected despite cpu_sched failure
        assertTrue(registry.meters.any {
            it.id.name == "kpod.bpf.map.entries" && it.id.getTag("map") == "tcp_stats_map"
        })
    }
}
