package com.internal.kpodmetrics.topology

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TopologyAggregatorTest {

    private fun conn(
        srcService: String = "svc-a",
        srcNamespace: String = "default",
        srcPod: String = "pod-a-1",
        dstId: String = "default/svc-b",
        dstName: String = "svc-b",
        dstNamespace: String? = "default",
        dstType: String = "service",
        requestCount: Long = 1,
        rttSumUs: Long = 0,
        rttCount: Long = 0,
        direction: String = "client",
        remotePort: Int = 8080
    ) = ConnectionRecord(
        srcNamespace = srcNamespace,
        srcPod = srcPod,
        srcService = srcService,
        dstId = dstId,
        dstName = dstName,
        dstNamespace = dstNamespace,
        dstType = dstType,
        requestCount = requestCount,
        rttSumUs = rttSumUs,
        rttCount = rttCount,
        direction = direction,
        remotePort = remotePort
    )

    @Test
    fun `ingest groups connections by service`() {
        val agg = TopologyAggregator()
        agg.ingest(
            listOf(
                conn(srcPod = "pod-a-1", requestCount = 10),
                conn(srcPod = "pod-a-2", requestCount = 5)
            )
        )
        agg.advanceWindow()
        val topo = agg.getTopology()

        assertEquals(2, topo.nodes.size, "expected source + destination nodes")
        assertEquals(1, topo.edges.size, "two pods of same service should produce one edge")
        assertEquals(15, topo.edges[0].requestCount)
    }

    @Test
    fun `sliding window evicts old snapshots`() {
        val agg = TopologyAggregator(windowSize = 2)

        // Cycle 1
        agg.ingest(listOf(conn(requestCount = 100)))
        agg.advanceWindow()

        // Cycle 2
        agg.ingest(listOf(conn(requestCount = 200)))
        agg.advanceWindow()

        // Cycle 3 — should evict cycle 1
        agg.ingest(listOf(conn(requestCount = 300)))
        agg.advanceWindow()

        val topo = agg.getTopology()
        assertEquals(1, topo.edges.size)
        assertEquals(500, topo.edges[0].requestCount, "only cycles 2+3 should remain (200+300)")
    }

    @Test
    fun `external nodes capped at maxExternalNodes`() {
        val agg = TopologyAggregator(maxExternalNodes = 2)

        val connections = (1..5).map { i ->
            conn(
                dstId = "external:10.0.0.$i:443",
                dstName = "10.0.0.$i:443",
                dstNamespace = null,
                dstType = "external",
                requestCount = (6 - i).toLong(), // 5, 4, 3, 2, 1
                remotePort = 443
            )
        }
        agg.ingest(connections)
        agg.advanceWindow()

        val topo = agg.getTopology()
        val externalNodes = topo.nodes.filter { it.type == "external" }
        // 2 top external + 1 "other-external" = 3
        assertEquals(3, externalNodes.size, "should have top-2 + other-external")

        val otherNode = externalNodes.find { it.id == "other-external" }
        assertTrue(otherNode != null, "should have an other-external node")

        val otherEdge = topo.edges.find { it.target == "other-external" }
        assertTrue(otherEdge != null, "should have an edge to other-external")
        // merged: 3 + 2 + 1 = 6
        assertEquals(6, otherEdge.requestCount)
    }

    @Test
    fun `protocol inferred from port`() {
        assertEquals("redis", TopologyAggregator.inferProtocol(6379))
        assertEquals("http", TopologyAggregator.inferProtocol(80))
        assertEquals("http", TopologyAggregator.inferProtocol(443))
        assertEquals("http", TopologyAggregator.inferProtocol(8080))
        assertEquals("http", TopologyAggregator.inferProtocol(8443))
        assertEquals("mysql", TopologyAggregator.inferProtocol(3306))
        assertEquals("postgresql", TopologyAggregator.inferProtocol(5432))
        assertEquals("tcp", TopologyAggregator.inferProtocol(9999))
    }

    @Test
    fun `avg latency calculated correctly`() {
        val agg = TopologyAggregator()
        agg.ingest(
            listOf(
                conn(rttSumUs = 500_000, rttCount = 100, requestCount = 100)
            )
        )
        agg.advanceWindow()

        val topo = agg.getTopology()
        assertEquals(1, topo.edges.size)
        assertEquals(5.0, topo.edges[0].avgLatencyMs, "500000us / 100 = 5000us = 5.0ms")
    }

    @Test
    fun `reset clears all snapshots`() {
        val agg = TopologyAggregator()
        agg.ingest(listOf(conn(requestCount = 42)))
        agg.advanceWindow()

        agg.reset()
        val topo = agg.getTopology()
        assertTrue(topo.nodes.isEmpty())
        assertTrue(topo.edges.isEmpty())
    }
}
