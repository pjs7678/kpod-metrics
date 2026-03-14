package com.internal.kpodmetrics.topology

import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TopologyEndpointTest {

    @Test
    fun `read returns topology with nodes and edges`() {
        val aggregator = mockk<TopologyAggregator>()
        every { aggregator.getTopology() } returns TopologySnapshot(
            nodes = listOf(
                ServiceNode(id = "svc-a", title = "svc-a", subTitle = "default", type = "service"),
                ServiceNode(id = "default/svc-b", title = "svc-b", subTitle = "default", type = "service")
            ),
            edges = listOf(
                ServiceEdge(
                    id = "svc-a->default/svc-b",
                    source = "svc-a",
                    target = "default/svc-b",
                    requestCount = 1500,
                    errorCount = 3,
                    avgLatencyMs = 12.4,
                    p99LatencyMs = 45.0,
                    bytesTotal = 50000,
                    protocols = setOf("http", "redis")
                )
            )
        )

        val endpoint = TopologyEndpoint(aggregator)
        val result = endpoint.read()

        @Suppress("UNCHECKED_CAST")
        val nodes = result["nodes"] as List<Map<String, Any?>>
        @Suppress("UNCHECKED_CAST")
        val edges = result["edges"] as List<Map<String, Any?>>

        assertEquals(2, nodes.size)
        assertEquals(1, edges.size)

        // Verify node structure
        val nodeA = nodes.find { it["id"] == "svc-a" }!!
        assertEquals("svc-a", nodeA["title"])
        assertEquals("default", nodeA["subTitle"])
        // mainStat = total requests across connected edges = 1500
        assertEquals("1.5 K", nodeA["mainStat"])
        // arc fields: fraction of traffic by protocol
        assertTrue(nodeA.containsKey("arc__http"))
        assertTrue(nodeA.containsKey("arc__redis"))
        // Both protocols on the single edge, so each is 0.5
        assertEquals(0.5, nodeA["arc__http"])
        assertEquals(0.5, nodeA["arc__redis"])

        // Verify edge structure
        val edge = edges[0]
        assertEquals("svc-a->default/svc-b", edge["id"])
        assertEquals("svc-a", edge["source"])
        assertEquals("default/svc-b", edge["target"])
        assertEquals("1.5 K", edge["mainStat"])
        assertEquals("12.4ms avg", edge["secondaryStat"])
        assertEquals(1500L, edge["detail__requestCount"])
        assertEquals(3L, edge["detail__errorCount"])
        assertEquals(12.4, edge["detail__avgLatencyMs"])
        assertEquals(45.0, edge["detail__p99LatencyMs"])
        assertEquals("http, redis", edge["detail__protocols"])
    }

    @Test
    fun `read returns empty when no data`() {
        val aggregator = mockk<TopologyAggregator>()
        every { aggregator.getTopology() } returns TopologySnapshot(
            nodes = emptyList(),
            edges = emptyList()
        )

        val endpoint = TopologyEndpoint(aggregator)
        val result = endpoint.read()

        @Suppress("UNCHECKED_CAST")
        val nodes = result["nodes"] as List<Map<String, Any?>>
        @Suppress("UNCHECKED_CAST")
        val edges = result["edges"] as List<Map<String, Any?>>

        assertTrue(nodes.isEmpty())
        assertTrue(edges.isEmpty())
    }
}
