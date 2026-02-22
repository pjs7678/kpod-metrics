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

class NetworkCollectorTest {

    private lateinit var bridge: BpfBridge
    private lateinit var programManager: BpfProgramManager
    private lateinit var cgroupResolver: CgroupResolver
    private lateinit var registry: MeterRegistry
    private lateinit var collector: NetworkCollector

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
        collector = NetworkCollector(bridge, programManager, cgroupResolver, registry, config, "test-node")
    }

    @Test
    fun `collect reads tcp stats map and registers counters and rtt`() {
        every { programManager.getMapFd("net", "tcp_stats_map") } returns 10

        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(100L).array()
        every { bridge.mapGetNextKey(10, null, 8) } returns keyBytes
        every { bridge.mapGetNextKey(10, keyBytes, 8) } returns null

        val valueBytes = buildTcpStatsValue(
            bytesSent = 1024, bytesReceived = 2048,
            retransmits = 3, connections = 5,
            rttSumUs = 50000, rttCount = 10
        )
        every { bridge.mapLookup(10, keyBytes, 48) } returns valueBytes

        collector.collect()

        val meters = registry.meters
        assertTrue(meters.any { it.id.name == "kpod.net.tcp.bytes.sent" })
        assertTrue(meters.any { it.id.name == "kpod.net.tcp.bytes.received" })
        assertTrue(meters.any { it.id.name == "kpod.net.tcp.retransmits" })
        assertTrue(meters.any { it.id.name == "kpod.net.tcp.connections" })
        assertTrue(meters.any { it.id.name == "kpod.net.tcp.rtt" })

        val sentCounter = registry.counter("kpod.net.tcp.bytes.sent",
            "namespace", "default", "pod", "test-pod", "container", "app", "node", "test-node")
        assertEquals(1024.0, sentCounter.count())

        val receivedCounter = registry.counter("kpod.net.tcp.bytes.received",
            "namespace", "default", "pod", "test-pod", "container", "app", "node", "test-node")
        assertEquals(2048.0, receivedCounter.count())

        val retransmitsCounter = registry.counter("kpod.net.tcp.retransmits",
            "namespace", "default", "pod", "test-pod", "container", "app", "node", "test-node")
        assertEquals(3.0, retransmitsCounter.count())

        val connectionsCounter = registry.counter("kpod.net.tcp.connections",
            "namespace", "default", "pod", "test-pod", "container", "app", "node", "test-node")
        assertEquals(5.0, connectionsCounter.count())
    }

    @Test
    fun `collect skips unknown cgroup ids`() {
        every { programManager.getMapFd("net", "tcp_stats_map") } returns 10

        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(999L).array()
        every { bridge.mapGetNextKey(10, null, 8) } returns keyBytes
        every { bridge.mapGetNextKey(10, keyBytes, 8) } returns null
        every { bridge.mapLookup(10, keyBytes, 48) } returns buildTcpStatsValue(
            100, 200, 1, 1, 1000, 1
        )

        collector.collect()

        assertTrue(registry.meters.none {
            it.id.name.startsWith("kpod") && it.id.getTag("pod") != null
        })
    }

    @Test
    fun `collect skips rtt when rtt count is zero`() {
        every { programManager.getMapFd("net", "tcp_stats_map") } returns 10

        val keyBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(100L).array()
        every { bridge.mapGetNextKey(10, null, 8) } returns keyBytes
        every { bridge.mapGetNextKey(10, keyBytes, 8) } returns null

        val valueBytes = buildTcpStatsValue(
            bytesSent = 512, bytesReceived = 256,
            retransmits = 0, connections = 1,
            rttSumUs = 0, rttCount = 0
        )
        every { bridge.mapLookup(10, keyBytes, 48) } returns valueBytes

        collector.collect()

        assertTrue(registry.meters.none { it.id.name == "kpod.net.tcp.rtt" })
        assertTrue(registry.meters.any { it.id.name == "kpod.net.tcp.bytes.sent" })
    }

    @Test
    fun `collect does nothing when tcp disabled`() {
        val config = MetricsProperties().resolveProfile("minimal")
        val disabledCollector = NetworkCollector(bridge, programManager, cgroupResolver, registry, config, "test-node")

        disabledCollector.collect()

        verify(exactly = 0) { programManager.getMapFd(any(), any()) }
        assertTrue(registry.meters.isEmpty())
    }

    private fun buildTcpStatsValue(
        bytesSent: Long, bytesReceived: Long,
        retransmits: Long, connections: Long,
        rttSumUs: Long, rttCount: Long
    ): ByteArray {
        return ByteBuffer.allocate(48).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(bytesSent)
            .putLong(bytesReceived)
            .putLong(retransmits)
            .putLong(connections)
            .putLong(rttSumUs)
            .putLong(rttCount)
            .array()
    }
}
