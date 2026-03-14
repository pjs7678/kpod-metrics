package com.internal.kpodmetrics.topology

import org.springframework.boot.actuate.endpoint.annotation.Endpoint
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation

@Endpoint(id = "kpodTopology")
class TopologyEndpoint(
    private val aggregator: TopologyAggregator
) {

    @ReadOperation
    fun read(): Map<String, Any> {
        val snapshot = aggregator.getTopology()

        // Pre-compute per-node request totals and protocol counts from connected edges
        data class NodeTraffic(
            var totalRequests: Long = 0,
            val protocolCounts: MutableMap<String, Double> = mutableMapOf()
        )

        val trafficByNode = mutableMapOf<String, NodeTraffic>()

        for (edge in snapshot.edges) {
            // Count traffic for both source and target nodes
            for (nodeId in listOf(edge.source, edge.target)) {
                val traffic = trafficByNode.getOrPut(nodeId) { NodeTraffic() }
                traffic.totalRequests += edge.requestCount
                // Split request count evenly among protocols on this edge
                val protocolCount = edge.protocols.size.coerceAtLeast(1)
                val perProtocol = edge.requestCount.toDouble() / protocolCount
                for (protocol in edge.protocols) {
                    traffic.protocolCounts[protocol] =
                        (traffic.protocolCounts[protocol] ?: 0.0) + perProtocol
                }
            }
        }

        val nodes = snapshot.nodes.map { node ->
            val traffic = trafficByNode[node.id]
            val totalRequests = traffic?.totalRequests ?: 0L
            val base = mutableMapOf<String, Any?>(
                "id" to node.id,
                "title" to node.title,
                "subTitle" to node.subTitle,
                "mainStat" to formatRate(totalRequests)
            )
            // Add arc__<protocol> fields as fractions
            if (traffic != null && traffic.totalRequests > 0) {
                for ((protocol, count) in traffic.protocolCounts) {
                    base["arc__$protocol"] = count.toDouble() / traffic.totalRequests
                }
            }
            base
        }

        val edges = snapshot.edges.map { edge ->
            mapOf<String, Any?>(
                "id" to edge.id,
                "source" to edge.source,
                "target" to edge.target,
                "mainStat" to formatRate(edge.requestCount),
                "secondaryStat" to "${formatLatency(edge.avgLatencyMs)}ms avg",
                "detail__requestCount" to edge.requestCount,
                "detail__errorCount" to edge.errorCount,
                "detail__avgLatencyMs" to edge.avgLatencyMs,
                "detail__p99LatencyMs" to edge.p99LatencyMs,
                "detail__protocols" to edge.protocols.sorted().joinToString(", ")
            )
        }

        return mapOf("nodes" to nodes, "edges" to edges)
    }

    companion object {
        fun formatRate(count: Long): String {
            return if (count >= 1000) {
                val k = count / 1000.0
                "${formatDecimal(k)} K"
            } else {
                "$count"
            }
        }

        private fun formatLatency(ms: Double): String = formatDecimal(ms)

        private fun formatDecimal(value: Double): String {
            // Format with one decimal place, strip trailing zero if whole number
            val formatted = "%.1f".format(value)
            return if (formatted.endsWith(".0")) {
                formatted.dropLast(2)
            } else {
                formatted
            }
        }
    }
}
