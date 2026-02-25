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

class SyscallCollectorTest {

    private lateinit var bridge: BpfBridge
    private lateinit var programManager: BpfProgramManager
    private lateinit var cgroupResolver: CgroupResolver
    private lateinit var registry: MeterRegistry
    private lateinit var collector: SyscallCollector

    private val isArm64 = System.getProperty("os.arch").let { it == "aarch64" || it == "arm64" }
    // Syscall numbers differ per architecture
    private val writeSyscallNr = if (isArm64) 64 else 1
    private val readSyscallNr = if (isArm64) 63 else 0
    private val connectSyscallNr = if (isArm64) 203 else 42

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
        collector = SyscallCollector(bridge, programManager, cgroupResolver, registry, config, "test-node")
    }

    @Test
    fun `collect reads syscall stats map and registers metrics with syscall label`() {
        every { programManager.getMapFd("syscall", "syscall_stats") } returns 30

        val keyBytes = buildSyscallKey(cgroupId = 100L, syscallNr = writeSyscallNr) // write

        val valueBytes = buildSyscallStatsValue(count = 50, errorCount = 2, latencySumNs = 5_000_000L)
        every { bridge.mapBatchLookupAndDelete(30, 16, 240, any()) } returns listOf(keyBytes to valueBytes)

        collector.collect()

        val meters = registry.meters
        assertTrue(meters.any { it.id.name == "kpod.syscall.count" && it.id.getTag("syscall") == "write" })
        assertTrue(meters.any { it.id.name == "kpod.syscall.errors" && it.id.getTag("syscall") == "write" })
        assertTrue(meters.any { it.id.name == "kpod.syscall.latency" && it.id.getTag("syscall") == "write" })

        val countCounter = registry.counter("kpod.syscall.count",
            "namespace", "default", "pod", "test-pod", "container", "app",
            "node", "test-node", "syscall", "write")
        assertEquals(50.0, countCounter.count())

        val errCounter = registry.counter("kpod.syscall.errors",
            "namespace", "default", "pod", "test-pod", "container", "app",
            "node", "test-node", "syscall", "write")
        assertEquals(2.0, errCounter.count())
    }

    @Test
    fun `collect uses fallback name for unknown syscall number`() {
        every { programManager.getMapFd("syscall", "syscall_stats") } returns 30

        val keyBytes = buildSyscallKey(cgroupId = 100L, syscallNr = 999)

        val valueBytes = buildSyscallStatsValue(count = 10, errorCount = 0, latencySumNs = 1000L)
        every { bridge.mapBatchLookupAndDelete(30, 16, 240, any()) } returns listOf(keyBytes to valueBytes)

        collector.collect()

        assertTrue(registry.meters.any {
            it.id.name == "kpod.syscall.count" && it.id.getTag("syscall") == "syscall_999"
        })
    }

    @Test
    fun `collect skips unknown cgroup ids`() {
        every { programManager.getMapFd("syscall", "syscall_stats") } returns 30

        val keyBytes = buildSyscallKey(cgroupId = 999L, syscallNr = 0)
        every { bridge.mapBatchLookupAndDelete(30, 16, 240, any()) } returns listOf(
            keyBytes to buildSyscallStatsValue(5, 0, 500L)
        )

        collector.collect()

        assertTrue(registry.meters.none {
            it.id.name.startsWith("kpod") && it.id.getTag("pod") != null
        })
    }

    @Test
    fun `collect does nothing when syscall disabled`() {
        val config = MetricsProperties().resolveProfile("standard")
        val disabledCollector = SyscallCollector(bridge, programManager, cgroupResolver, registry, config, "test-node")

        disabledCollector.collect()

        verify(exactly = 0) { programManager.getMapFd(any(), any()) }
        assertTrue(registry.meters.isEmpty())
    }

    @Test
    fun `collect resolves known syscall names correctly`() {
        every { programManager.getMapFd("syscall", "syscall_stats") } returns 30

        val keyRead = buildSyscallKey(cgroupId = 100L, syscallNr = readSyscallNr)
        val keyConnect = buildSyscallKey(cgroupId = 100L, syscallNr = connectSyscallNr)

        every { bridge.mapBatchLookupAndDelete(30, 16, 240, any()) } returns listOf(
            keyRead to buildSyscallStatsValue(10, 1, 100L),
            keyConnect to buildSyscallStatsValue(20, 0, 200L)
        )

        collector.collect()

        assertTrue(registry.meters.any {
            it.id.name == "kpod.syscall.count" && it.id.getTag("syscall") == "read"
        })
        assertTrue(registry.meters.any {
            it.id.name == "kpod.syscall.count" && it.id.getTag("syscall") == "connect"
        })
    }

    private fun buildSyscallKey(cgroupId: Long, syscallNr: Int): ByteArray {
        return ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(cgroupId)
            .putInt(syscallNr)
            .putInt(0) // padding
            .array()
    }

    private fun buildSyscallStatsValue(count: Long, errorCount: Long, latencySumNs: Long): ByteArray {
        val buf = ByteBuffer.allocate(240).order(ByteOrder.LITTLE_ENDIAN)
        buf.putLong(count)
        buf.putLong(errorCount)
        buf.putLong(latencySumNs)
        // Fill remaining 27 latency slots with zeros
        for (i in 0 until 27) {
            buf.putLong(0L)
        }
        return buf.array()
    }
}
