package com.internal.kpodmetrics.topology

data class ConnectionRecord(
    val srcNamespace: String,
    val srcPod: String,
    val srcService: String,
    val dstId: String,
    val dstName: String,
    val dstNamespace: String?,
    val dstType: String,
    val requestCount: Long,
    val rttSumUs: Long,
    val rttCount: Long,
    val direction: String,
    val remotePort: Int
)

data class ServiceNode(
    val id: String,
    val title: String,
    val subTitle: String?,
    val type: String
)

data class ServiceEdge(
    val id: String,
    val source: String,
    val target: String,
    val requestCount: Long,
    val errorCount: Long,
    val avgLatencyMs: Double,
    val p99LatencyMs: Double,
    val bytesTotal: Long,
    val protocols: Set<String>
)

data class TopologySnapshot(
    val nodes: List<ServiceNode>,
    val edges: List<ServiceEdge>
)

class TopologyAggregator(
    private val windowSize: Int = 10,
    private val maxExternalNodes: Int = 20
) {
    private data class EdgeKey(val source: String, val target: String)

    private data class EdgeStats(
        var requestCount: Long = 0,
        var errorCount: Long = 0,
        var rttSumUs: Long = 0,
        var rttCount: Long = 0,
        var bytesTotal: Long = 0,
        val protocols: MutableSet<String> = mutableSetOf(),
        var dstName: String = "",
        var dstNamespace: String? = null,
        var dstType: String = "service"
    )

    private val snapshots = ArrayDeque<Map<EdgeKey, EdgeStats>>()
    private var currentCycle = mutableMapOf<EdgeKey, EdgeStats>()

    @Synchronized
    fun ingest(connections: List<ConnectionRecord>) {
        for (conn in connections) {
            if (conn.direction != "client") continue

            val key = EdgeKey(conn.srcService, conn.dstId)
            val stats = currentCycle.getOrPut(key) {
                EdgeStats(
                    dstName = conn.dstName,
                    dstNamespace = conn.dstNamespace,
                    dstType = conn.dstType
                )
            }
            stats.requestCount += conn.requestCount
            stats.rttSumUs += conn.rttSumUs
            stats.rttCount += conn.rttCount
            stats.protocols.add(inferProtocol(conn.remotePort))
        }
    }

    @Synchronized
    fun advanceWindow() {
        snapshots.addLast(currentCycle)
        if (snapshots.size > windowSize) {
            snapshots.removeFirst()
        }
        currentCycle = mutableMapOf()
    }

    @Synchronized
    fun getTopology(): TopologySnapshot {
        // Merge all snapshots
        val merged = mutableMapOf<EdgeKey, EdgeStats>()
        for (snapshot in snapshots) {
            for ((key, stats) in snapshot) {
                val m = merged.getOrPut(key) {
                    EdgeStats(
                        dstName = stats.dstName,
                        dstNamespace = stats.dstNamespace,
                        dstType = stats.dstType
                    )
                }
                m.requestCount += stats.requestCount
                m.errorCount += stats.errorCount
                m.rttSumUs += stats.rttSumUs
                m.rttCount += stats.rttCount
                m.bytesTotal += stats.bytesTotal
                m.protocols.addAll(stats.protocols)
            }
        }

        if (merged.isEmpty()) {
            return TopologySnapshot(emptyList(), emptyList())
        }

        // Cap external nodes
        val externalTargets = merged.entries
            .filter { it.value.dstType == "external" }
            .groupBy { it.key.target }

        if (externalTargets.size > maxExternalNodes) {
            // Sum request counts per external target
            val externalByCount = externalTargets.map { (targetId, entries) ->
                targetId to entries.sumOf { it.value.requestCount }
            }.sortedByDescending { it.second }

            val keep = externalByCount.take(maxExternalNodes).map { it.first }.toSet()
            val evict = externalByCount.drop(maxExternalNodes).map { it.first }.toSet()

            // For each source that has evicted external targets, merge into other-external
            val edgesToRemove = mutableListOf<EdgeKey>()
            val otherExternalEdges = mutableMapOf<String, EdgeStats>()

            for ((key, stats) in merged) {
                if (key.target in evict) {
                    edgesToRemove.add(key)
                    val otherStats = otherExternalEdges.getOrPut(key.source) {
                        EdgeStats(
                            dstName = "other-external",
                            dstNamespace = null,
                            dstType = "external"
                        )
                    }
                    otherStats.requestCount += stats.requestCount
                    otherStats.errorCount += stats.errorCount
                    otherStats.rttSumUs += stats.rttSumUs
                    otherStats.rttCount += stats.rttCount
                    otherStats.bytesTotal += stats.bytesTotal
                    otherStats.protocols.addAll(stats.protocols)
                }
            }

            for (key in edgesToRemove) {
                merged.remove(key)
            }
            for ((source, stats) in otherExternalEdges) {
                merged[EdgeKey(source, "other-external")] = stats
            }
        }

        // Build nodes
        val nodeMap = mutableMapOf<String, ServiceNode>()
        for ((key, stats) in merged) {
            // Source node (always a service)
            nodeMap.getOrPut(key.source) {
                ServiceNode(
                    id = key.source,
                    title = key.source,
                    subTitle = null,
                    type = "service"
                )
            }
            // Destination node
            nodeMap.getOrPut(key.target) {
                ServiceNode(
                    id = key.target,
                    title = stats.dstName,
                    subTitle = stats.dstNamespace,
                    type = stats.dstType
                )
            }
        }

        // Build edges
        val edges = merged.map { (key, stats) ->
            val avgLatencyMs = if (stats.rttCount > 0) {
                stats.rttSumUs.toDouble() / stats.rttCount / 1000.0
            } else {
                0.0
            }

            ServiceEdge(
                id = "${key.source}->${key.target}",
                source = key.source,
                target = key.target,
                requestCount = stats.requestCount,
                errorCount = stats.errorCount,
                avgLatencyMs = avgLatencyMs,
                p99LatencyMs = 0.0, // requires histogram data
                bytesTotal = stats.bytesTotal,
                protocols = stats.protocols.toSet()
            )
        }

        return TopologySnapshot(
            nodes = nodeMap.values.toList(),
            edges = edges
        )
    }

    @Synchronized
    fun reset() {
        snapshots.clear()
        currentCycle = mutableMapOf()
    }

    companion object {
        fun inferProtocol(port: Int): String = when (port) {
            80, 443, 8080, 8443 -> "http"
            6379 -> "redis"
            3306 -> "mysql"
            5432 -> "postgresql"
            else -> "tcp"
        }
    }
}
