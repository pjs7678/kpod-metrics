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

data class RttRecord(
    val srcService: String,
    val dstId: String,
    val rttSumUs: Long,
    val rttCount: Long,
    val histogram: LongArray
)

data class ServiceNode(
    val id: String,
    val title: String,
    val subTitle: String?,
    val type: String,
    val tcpDrops: Long = 0
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
    companion object {
        const val RTT_HISTOGRAM_SLOTS = 27

        fun inferProtocol(port: Int): String = when (port) {
            80, 443, 8080, 8443 -> "http"
            6379 -> "redis"
            3306 -> "mysql"
            5432 -> "postgresql"
            else -> "tcp"
        }

        /**
         * Compute p99 from a log2 histogram (slot i covers [2^i, 2^(i+1)) microseconds).
         * Returns p99 in milliseconds.
         */
        fun computeP99Ms(histogram: LongArray, totalCount: Long): Double {
            if (totalCount <= 0) return 0.0
            val histogramTotal = histogram.sum()
            if (histogramTotal <= 0) return 0.0
            val target = (histogramTotal * 99 + 99) / 100 // ceiling of 99th percentile
            var cumulative = 0L
            for (i in histogram.indices) {
                cumulative += histogram[i]
                if (cumulative >= target) {
                    // Upper bound of this bucket in microseconds: 2^(i+1)
                    val upperBoundUs = 1L shl (i + 1)
                    return upperBoundUs.toDouble() / 1000.0
                }
            }
            // All samples in the last bucket
            return (1L shl RTT_HISTOGRAM_SLOTS).toDouble() / 1000.0
        }
    }

    private data class EdgeKey(val source: String, val target: String)

    private data class EdgeStats(
        var requestCount: Long = 0,
        var errorCount: Long = 0,
        var rttSumUs: Long = 0,
        var rttCount: Long = 0,
        var bytesTotal: Long = 0,
        val rttHistogram: LongArray = LongArray(RTT_HISTOGRAM_SLOTS),
        val protocols: MutableSet<String> = mutableSetOf(),
        var dstName: String = "",
        var dstNamespace: String? = null,
        var dstType: String = "service"
    )

    private val snapshots = ArrayDeque<Map<EdgeKey, EdgeStats>>()
    private var currentCycle = mutableMapOf<EdgeKey, EdgeStats>()
    private val tcpDropSnapshots = ArrayDeque<Map<String, Long>>()
    private var currentTcpDrops = mutableMapOf<String, Long>()

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
    fun ingestTcpDrops(drops: Map<String, Long>) {
        for ((service, count) in drops) {
            currentTcpDrops[service] = (currentTcpDrops[service] ?: 0) + count
        }
    }

    @Synchronized
    fun ingestRtt(rttRecords: List<RttRecord>) {
        for (rtt in rttRecords) {
            val key = EdgeKey(rtt.srcService, rtt.dstId)
            val stats = currentCycle[key] ?: continue // only enrich existing edges
            stats.rttSumUs += rtt.rttSumUs
            stats.rttCount += rtt.rttCount
            for (i in rtt.histogram.indices.take(RTT_HISTOGRAM_SLOTS)) {
                stats.rttHistogram[i] += rtt.histogram[i]
            }
        }
    }

    @Synchronized
    fun advanceWindow() {
        snapshots.addLast(currentCycle)
        if (snapshots.size > windowSize) {
            snapshots.removeFirst()
        }
        currentCycle = mutableMapOf()

        tcpDropSnapshots.addLast(currentTcpDrops)
        if (tcpDropSnapshots.size > windowSize) {
            tcpDropSnapshots.removeFirst()
        }
        currentTcpDrops = mutableMapOf()
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
                for (i in stats.rttHistogram.indices) {
                    m.rttHistogram[i] += stats.rttHistogram[i]
                }
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
                    for (i in stats.rttHistogram.indices) {
                        otherStats.rttHistogram[i] += stats.rttHistogram[i]
                    }
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

        // Merge tcp drop snapshots per service
        val mergedDrops = mutableMapOf<String, Long>()
        for (snapshot in tcpDropSnapshots) {
            for ((service, count) in snapshot) {
                mergedDrops[service] = (mergedDrops[service] ?: 0) + count
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
                    type = "service",
                    tcpDrops = mergedDrops[key.source] ?: 0
                )
            }
            // Destination node
            nodeMap.getOrPut(key.target) {
                ServiceNode(
                    id = key.target,
                    title = stats.dstName,
                    subTitle = stats.dstNamespace,
                    type = stats.dstType,
                    tcpDrops = mergedDrops[key.target] ?: 0
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
                p99LatencyMs = computeP99Ms(stats.rttHistogram, stats.rttCount),
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
        tcpDropSnapshots.clear()
        currentTcpDrops = mutableMapOf()
    }

    fun loadDemoData() {
        val demoConnections = listOf(
            ConnectionRecord("default", "frontend-abc12-x9k2z", "frontend", "default/api-server", "api-server", "default", "service", 142, 1704000, 142, "client", 8080),
            ConnectionRecord("default", "frontend-abc12-x9k2z", "frontend", "default/auth-service", "auth-service", "default", "service", 38, 760000, 38, "client", 8080),
            ConnectionRecord("default", "api-server-def34-m3n7q", "api-server", "default/user-db", "user-db", "default", "service", 95, 285000, 95, "client", 3306),
            ConnectionRecord("default", "api-server-def34-m3n7q", "api-server", "default/cache", "cache", "default", "service", 210, 420000, 210, "client", 6379),
            ConnectionRecord("default", "api-server-def34-m3n7q", "api-server", "default/order-service", "order-service", "default", "service", 67, 1005000, 67, "client", 8080),
            ConnectionRecord("default", "order-service-ghi56-p2r8w", "order-service", "default/payment-gateway", "payment-gateway", "default", "service", 23, 2070000, 23, "client", 443),
            ConnectionRecord("default", "order-service-ghi56-p2r8w", "order-service", "default/user-db", "user-db", "default", "service", 45, 135000, 45, "client", 3306),
            ConnectionRecord("default", "auth-service-jkl78-s4t6v", "auth-service", "default/cache", "cache", "default", "service", 120, 180000, 120, "client", 6379),
            ConnectionRecord("default", "payment-gateway-mno90-u5v1y", "payment-gateway", "external:35.201.97.12:443", "35.201.97.12:443", null, "external", 23, 4600000, 23, "client", 443),
            ConnectionRecord("default", "frontend-abc12-x9k2z", "frontend", "external:142.250.80.46:443", "142.250.80.46:443", null, "external", 15, 450000, 15, "client", 443)
        )
        // Demo RTT histograms: slot i covers [2^i, 2^(i+1)) microseconds
        // slot 10 = [1024us, 2048us) ≈ 1-2ms, slot 13 = [8192us, 16384us) ≈ 8-16ms
        // slot 14 = [16384us, 32768us) ≈ 16-32ms, slot 17 = [131072us, 262144us) ≈ 131-262ms
        fun hist(vararg pairs: Pair<Int, Long>): LongArray {
            val h = LongArray(RTT_HISTOGRAM_SLOTS)
            for ((slot, count) in pairs) h[slot] = count
            return h
        }

        val demoRttRecords = listOf(
            // frontend -> api-server: ~12ms avg, p99 ~32ms (slot 14 upper)
            RttRecord("frontend", "default/api-server", 1704000, 142, hist(10 to 50, 13 to 80, 14 to 12)),
            // frontend -> auth-service: ~20ms avg, p99 ~65ms (slot 15 upper)
            RttRecord("frontend", "default/auth-service", 760000, 38, hist(13 to 25, 14 to 10, 15 to 3)),
            // api-server -> user-db: ~3ms avg, p99 ~8ms (slot 12 upper)
            RttRecord("api-server", "default/user-db", 285000, 95, hist(10 to 70, 11 to 20, 12 to 5)),
            // api-server -> cache: ~2ms avg, p99 ~4ms (slot 11 upper)
            RttRecord("api-server", "default/cache", 420000, 210, hist(10 to 190, 11 to 20)),
            // api-server -> order-service: ~15ms avg, p99 ~32ms (slot 14 upper)
            RttRecord("api-server", "default/order-service", 1005000, 67, hist(13 to 50, 14 to 15, 15 to 2)),
            // order-service -> payment-gateway: ~90ms avg, p99 ~262ms (slot 17 upper)
            RttRecord("order-service", "default/payment-gateway", 2070000, 23, hist(16 to 18, 17 to 5)),
            // order-service -> user-db: ~3ms avg, p99 ~8ms (slot 12 upper)
            RttRecord("order-service", "default/user-db", 135000, 45, hist(10 to 30, 11 to 10, 12 to 5)),
            // auth-service -> cache: ~1.5ms avg, p99 ~4ms (slot 11 upper)
            RttRecord("auth-service", "default/cache", 180000, 120, hist(10 to 110, 11 to 10)),
            // payment-gateway -> external: ~200ms avg, p99 ~524ms (slot 18 upper)
            RttRecord("payment-gateway", "external:35.201.97.12:443", 4600000, 23, hist(17 to 15, 18 to 8)),
            // frontend -> external: ~30ms avg, p99 ~65ms (slot 15 upper)
            RttRecord("frontend", "external:142.250.80.46:443", 450000, 15, hist(14 to 10, 15 to 5))
        )

        val demoTcpDrops = mapOf(
            "payment-gateway" to 3L,
            "user-db" to 1L
        )

        // Fill entire window so demo data survives collection cycle evictions
        repeat(windowSize) {
            ingest(demoConnections)
            ingestRtt(demoRttRecords)
            ingestTcpDrops(demoTcpDrops)
            advanceWindow()
        }
    }

}
