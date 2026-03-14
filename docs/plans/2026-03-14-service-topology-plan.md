# Service Topology Map Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Auto-discovered service dependency graph from existing eBPF TCP peer data, exposed as actuator API + Grafana Node Graph dashboard.

**Architecture:** TopologyAggregator receives connection data from TcpPeerCollector each cycle, groups by service, accumulates in a sliding window, and serves via actuator endpoint. Zero new BPF programs.

**Tech Stack:** Kotlin, Spring Boot Actuator, Grafana Node Graph panel, existing TcpPeerCollector/PodIpResolver

---

### Task 1: Add TopologyProperties configuration

**Files:**
- Modify: `src/main/kotlin/com/internal/kpodmetrics/config/MetricsProperties.kt`
- Modify: `src/main/resources/application.yml`

**Step 1: Add TopologyProperties data class**

Add after `TracingProperties` in `MetricsProperties.kt`:

```kotlin
data class TopologyProperties(
    val enabled: Boolean = true,
    val windowSize: Int = 10,
    val maxExternalNodes: Int = 20
)
```

Add to `MetricsProperties` class:

```kotlin
val topology: TopologyProperties = TopologyProperties()
```

**Step 2: Add topology section to application.yml**

Add under `kpod:` section after `tracing:`:

```yaml
  topology:
    enabled: true
    window-size: 10
    max-external-nodes: 20
```

Add `kpodTopology` to actuator endpoint exposure:

```yaml
include: health, prometheus, info, kpodDiagnostics, kpodRecommend, kpodAnomaly, kpodTracing, kpodTopology
```

**Step 3: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/config/MetricsProperties.kt src/main/resources/application.yml
git commit -m "feat(config): add TopologyProperties configuration"
```

---

### Task 2: Implement TopologyAggregator

**Files:**
- Create: `src/main/kotlin/com/internal/kpodmetrics/topology/TopologyAggregator.kt`
- Create: `src/test/kotlin/com/internal/kpodmetrics/topology/TopologyAggregatorTest.kt`

**Step 1: Write tests for TopologyAggregator**

```kotlin
package com.internal.kpodmetrics.topology

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TopologyAggregatorTest {

    @Test
    fun `ingest groups connections by service`() {
        val aggregator = TopologyAggregator(windowSize = 3, maxExternalNodes = 5)

        aggregator.ingest(listOf(
            ConnectionRecord(
                srcNamespace = "default", srcPod = "frontend-abc", srcService = "frontend",
                dstId = "default/api-server", dstName = "api-server", dstNamespace = "default", dstType = "service",
                requestCount = 10, rttSumUs = 5000, rttCount = 10, direction = "client", remotePort = 8080
            ),
            ConnectionRecord(
                srcNamespace = "default", srcPod = "frontend-xyz", srcService = "frontend",
                dstId = "default/api-server", dstName = "api-server", dstNamespace = "default", dstType = "service",
                requestCount = 5, rttSumUs = 2500, rttCount = 5, direction = "client", remotePort = 8080
            )
        ))
        aggregator.advanceWindow()

        val topology = aggregator.getTopology()
        assertEquals(2, topology.nodes.size)
        assertEquals(1, topology.edges.size)
        assertEquals(15, topology.edges[0].requestCount)
    }

    @Test
    fun `sliding window evicts old snapshots`() {
        val aggregator = TopologyAggregator(windowSize = 2, maxExternalNodes = 5)

        aggregator.ingest(listOf(
            ConnectionRecord(
                srcNamespace = "default", srcPod = "a-1", srcService = "a",
                dstId = "default/b", dstName = "b", dstNamespace = "default", dstType = "service",
                requestCount = 10, rttSumUs = 1000, rttCount = 10, direction = "client", remotePort = 80
            )
        ))
        aggregator.advanceWindow()

        aggregator.ingest(listOf(
            ConnectionRecord(
                srcNamespace = "default", srcPod = "a-1", srcService = "a",
                dstId = "default/b", dstName = "b", dstNamespace = "default", dstType = "service",
                requestCount = 20, rttSumUs = 2000, rttCount = 20, direction = "client", remotePort = 80
            )
        ))
        aggregator.advanceWindow()

        // Window has both: 10 + 20 = 30
        assertEquals(30, aggregator.getTopology().edges[0].requestCount)

        // Third cycle evicts first: only 20 + 5 = 25
        aggregator.ingest(listOf(
            ConnectionRecord(
                srcNamespace = "default", srcPod = "a-1", srcService = "a",
                dstId = "default/b", dstName = "b", dstNamespace = "default", dstType = "service",
                requestCount = 5, rttSumUs = 500, rttCount = 5, direction = "client", remotePort = 80
            )
        ))
        aggregator.advanceWindow()

        assertEquals(25, aggregator.getTopology().edges[0].requestCount)
    }

    @Test
    fun `external nodes capped at maxExternalNodes`() {
        val aggregator = TopologyAggregator(windowSize = 3, maxExternalNodes = 2)

        val connections = (1..5).map { i ->
            ConnectionRecord(
                srcNamespace = "default", srcPod = "app-1", srcService = "app",
                dstId = "external:10.0.0.$i:443", dstName = "10.0.0.$i:443", dstNamespace = null, dstType = "external",
                requestCount = (6 - i).toLong(), rttSumUs = 1000, rttCount = 1, direction = "client", remotePort = 443
            )
        }
        aggregator.ingest(connections)
        aggregator.advanceWindow()

        val topology = aggregator.getTopology()
        val externalNodes = topology.nodes.filter { it.type == "external" }
        // 2 top external + 1 "other-external" = 3
        assertTrue(externalNodes.size <= 3)
        assertTrue(externalNodes.any { it.id == "other-external" })
    }

    @Test
    fun `protocol inferred from port`() {
        val aggregator = TopologyAggregator(windowSize = 3, maxExternalNodes = 5)

        aggregator.ingest(listOf(
            ConnectionRecord(
                srcNamespace = "default", srcPod = "app-1", srcService = "app",
                dstId = "default/redis", dstName = "redis", dstNamespace = "default", dstType = "service",
                requestCount = 1, rttSumUs = 100, rttCount = 1, direction = "client", remotePort = 6379
            )
        ))
        aggregator.advanceWindow()

        val edge = aggregator.getTopology().edges[0]
        assertTrue(edge.protocols.contains("redis"))
    }

    @Test
    fun `avg and p99 latency calculated correctly`() {
        val aggregator = TopologyAggregator(windowSize = 3, maxExternalNodes = 5)

        aggregator.ingest(listOf(
            ConnectionRecord(
                srcNamespace = "default", srcPod = "a-1", srcService = "a",
                dstId = "default/b", dstName = "b", dstNamespace = "default", dstType = "service",
                requestCount = 100, rttSumUs = 500_000, rttCount = 100, direction = "client", remotePort = 80
            )
        ))
        aggregator.advanceWindow()

        val edge = aggregator.getTopology().edges[0]
        assertEquals(5.0, edge.avgLatencyMs, 0.01)
    }

    @Test
    fun `reset clears all snapshots`() {
        val aggregator = TopologyAggregator(windowSize = 3, maxExternalNodes = 5)

        aggregator.ingest(listOf(
            ConnectionRecord(
                srcNamespace = "default", srcPod = "a-1", srcService = "a",
                dstId = "default/b", dstName = "b", dstNamespace = "default", dstType = "service",
                requestCount = 10, rttSumUs = 1000, rttCount = 10, direction = "client", remotePort = 80
            )
        ))
        aggregator.advanceWindow()

        aggregator.reset()
        val topology = aggregator.getTopology()
        assertTrue(topology.nodes.isEmpty())
        assertTrue(topology.edges.isEmpty())
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test --tests "com.internal.kpodmetrics.topology.TopologyAggregatorTest" -PebpfDslPath=../kotlin-ebpf-dsl`
Expected: FAIL — class not found

**Step 3: Implement TopologyAggregator**

```kotlin
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

private data class EdgeKey(val source: String, val target: String)

private data class EdgeStats(
    var requestCount: Long = 0,
    var rttSumUs: Long = 0,
    var rttCount: Long = 0,
    val protocols: MutableSet<String> = mutableSetOf()
)

class TopologyAggregator(
    private val windowSize: Int = 10,
    private val maxExternalNodes: Int = 20
) {
    private val snapshots = ArrayDeque<Map<EdgeKey, EdgeStats>>()
    private var currentCycle = mutableMapOf<EdgeKey, EdgeStats>()

    @Synchronized
    fun ingest(connections: List<ConnectionRecord>) {
        for (conn in connections) {
            if (conn.direction != "client") continue

            val srcId = "${conn.srcNamespace}/${conn.srcService}"
            val key = EdgeKey(srcId, conn.dstId)
            val stats = currentCycle.getOrPut(key) { EdgeStats() }
            stats.requestCount += conn.requestCount
            stats.rttSumUs += conn.rttSumUs
            stats.rttCount += conn.rttCount
            stats.protocols.add(inferProtocol(conn.remotePort))
        }
    }

    @Synchronized
    fun advanceWindow() {
        if (currentCycle.isNotEmpty()) {
            snapshots.addLast(currentCycle.toMap())
            if (snapshots.size > windowSize) {
                snapshots.removeFirst()
            }
        }
        currentCycle = mutableMapOf()
    }

    @Synchronized
    fun getTopology(): TopologySnapshot {
        val mergedEdges = mutableMapOf<EdgeKey, EdgeStats>()
        for (snapshot in snapshots) {
            for ((key, stats) in snapshot) {
                val merged = mergedEdges.getOrPut(key) { EdgeStats() }
                merged.requestCount += stats.requestCount
                merged.rttSumUs += stats.rttSumUs
                merged.rttCount += stats.rttCount
                merged.protocols.addAll(stats.protocols)
            }
        }

        val cappedEdges = capExternalNodes(mergedEdges)

        val nodeIds = mutableSetOf<String>()
        for ((key, _) in cappedEdges) {
            nodeIds.add(key.source)
            nodeIds.add(key.target)
        }

        val nodes = nodeIds.map { id -> toServiceNode(id) }
        val edges = cappedEdges.map { (key, stats) ->
            ServiceEdge(
                id = "${key.source}->${key.target}",
                source = key.source,
                target = key.target,
                requestCount = stats.requestCount,
                errorCount = 0,
                avgLatencyMs = if (stats.rttCount > 0) stats.rttSumUs.toDouble() / stats.rttCount / 1000.0 else 0.0,
                p99LatencyMs = 0.0,
                bytesTotal = 0,
                protocols = stats.protocols.toSet()
            )
        }

        return TopologySnapshot(nodes, edges)
    }

    @Synchronized
    fun reset() {
        snapshots.clear()
        currentCycle.clear()
    }

    private fun capExternalNodes(edges: Map<EdgeKey, EdgeStats>): Map<EdgeKey, EdgeStats> {
        val externalEdges = edges.filter { it.key.target.startsWith("external:") }
        if (externalEdges.size <= maxExternalNodes) return edges

        val sorted = externalEdges.entries.sortedByDescending { it.value.requestCount }
        val keep = sorted.take(maxExternalNodes).map { it.key.target }.toSet()

        val result = edges.toMutableMap()
        val otherKey = EdgeKey("", "other-external")
        val otherStats = EdgeStats()

        val toRemove = mutableListOf<EdgeKey>()
        for ((key, stats) in result) {
            if (key.target.startsWith("external:") && key.target !in keep) {
                val mergedKey = EdgeKey(key.source, "other-external")
                val merged = result.getOrPut(mergedKey) { EdgeStats() }
                merged.requestCount += stats.requestCount
                merged.rttSumUs += stats.rttSumUs
                merged.rttCount += stats.rttCount
                merged.protocols.addAll(stats.protocols)
                toRemove.add(key)
            }
        }
        toRemove.forEach { result.remove(it) }

        return result
    }

    private fun toServiceNode(id: String): ServiceNode {
        return when {
            id == "other-external" -> ServiceNode(id, "other-external", null, "external")
            id.startsWith("external:") -> ServiceNode(id, id.removePrefix("external:"), null, "external")
            "/" in id -> {
                val (ns, name) = id.split("/", limit = 2)
                ServiceNode(id, name, ns, "service")
            }
            else -> ServiceNode(id, id, null, "service")
        }
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
```

**Step 4: Run tests to verify they pass**

Run: `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test --tests "com.internal.kpodmetrics.topology.TopologyAggregatorTest" -PebpfDslPath=../kotlin-ebpf-dsl`
Expected: PASS

**Step 5: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/topology/TopologyAggregator.kt \
        src/test/kotlin/com/internal/kpodmetrics/topology/TopologyAggregatorTest.kt
git commit -m "feat(topology): add TopologyAggregator with sliding window"
```

---

### Task 3: Implement TopologyEndpoint

**Files:**
- Create: `src/main/kotlin/com/internal/kpodmetrics/topology/TopologyEndpoint.kt`
- Create: `src/test/kotlin/com/internal/kpodmetrics/topology/TopologyEndpointTest.kt`

**Step 1: Write tests**

```kotlin
package com.internal.kpodmetrics.topology

import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class TopologyEndpointTest {

    private val aggregator = mockk<TopologyAggregator>()
    private val endpoint = TopologyEndpoint(aggregator)

    @Test
    fun `read returns topology with nodes and edges`() {
        every { aggregator.getTopology() } returns TopologySnapshot(
            nodes = listOf(ServiceNode("default/a", "a", "default", "service")),
            edges = listOf(
                ServiceEdge("default/a->default/b", "default/a", "default/b",
                    requestCount = 100, errorCount = 0, avgLatencyMs = 5.0,
                    p99LatencyMs = 0.0, bytesTotal = 0, protocols = setOf("http"))
            )
        )

        val result = endpoint.read()
        val nodes = result["nodes"] as List<*>
        val edges = result["edges"] as List<*>
        assertEquals(1, nodes.size)
        assertEquals(1, edges.size)
    }

    @Test
    fun `read returns empty when no data`() {
        every { aggregator.getTopology() } returns TopologySnapshot(emptyList(), emptyList())

        val result = endpoint.read()
        val nodes = result["nodes"] as List<*>
        assertTrue(nodes.isEmpty())
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test --tests "com.internal.kpodmetrics.topology.TopologyEndpointTest" -PebpfDslPath=../kotlin-ebpf-dsl`
Expected: FAIL

**Step 3: Implement TopologyEndpoint**

```kotlin
package com.internal.kpodmetrics.topology

import org.springframework.boot.actuate.endpoint.annotation.Endpoint
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation

@Endpoint(id = "kpodTopology")
class TopologyEndpoint(
    private val aggregator: TopologyAggregator
) {

    @ReadOperation
    fun read(): Map<String, Any> {
        val topology = aggregator.getTopology()
        val windowSeconds = 0L // placeholder — computed from snapshot count × cycle interval

        val nodes = topology.nodes.map { node ->
            val nodeEdges = topology.edges.filter { it.source == node.id || it.target == node.id }
            val totalRequests = nodeEdges.sumOf { it.requestCount }
            val protocolBreakdown = nodeEdges.flatMap { it.protocols }
                .groupingBy { it }.eachCount()
            val totalProtocol = protocolBreakdown.values.sum().coerceAtLeast(1)

            val result = mutableMapOf<String, Any?>(
                "id" to node.id,
                "title" to node.title,
                "subTitle" to (node.subTitle ?: ""),
                "mainStat" to formatRate(totalRequests)
            )
            for ((proto, count) in protocolBreakdown) {
                result["arc__$proto"] = count.toDouble() / totalProtocol
            }
            result
        }

        val edges = topology.edges.map { edge ->
            mapOf(
                "id" to edge.id,
                "source" to edge.source,
                "target" to edge.target,
                "mainStat" to formatRate(edge.requestCount),
                "secondaryStat" to "%.1fms avg".format(edge.avgLatencyMs),
                "detail__requestCount" to edge.requestCount,
                "detail__errorCount" to edge.errorCount,
                "detail__avgLatencyMs" to edge.avgLatencyMs,
                "detail__p99LatencyMs" to edge.p99LatencyMs,
                "detail__protocols" to edge.protocols.joinToString(",")
            )
        }

        return mapOf("nodes" to nodes, "edges" to edges)
    }

    private fun formatRate(count: Long): String {
        return when {
            count > 1000 -> "%.1f K".format(count / 1000.0)
            else -> "$count"
        }
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew test --tests "com.internal.kpodmetrics.topology.TopologyEndpointTest" -PebpfDslPath=../kotlin-ebpf-dsl`
Expected: PASS

**Step 5: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/topology/TopologyEndpoint.kt \
        src/test/kotlin/com/internal/kpodmetrics/topology/TopologyEndpointTest.kt
git commit -m "feat(topology): add kpodTopology actuator endpoint"
```

---

### Task 4: Integrate TopologyAggregator with TcpPeerCollector

**Files:**
- Modify: `src/main/kotlin/com/internal/kpodmetrics/collector/TcpPeerCollector.kt`

**Step 1: Add TopologyAggregator parameter to constructor**

Add `private val topologyAggregator: TopologyAggregator? = null` as the last constructor parameter.

**Step 2: Build ConnectionRecord in collectConnections()**

After the existing `registry.counter(...)` call in `collectConnections()`, add logic to build `ConnectionRecord` and call `topologyAggregator?.ingest()`. The data is already available:
- `podInfo.namespace`, `podInfo.podName` — source pod
- `podInfo` needs service label — derive from pod name by stripping the replica suffix (e.g., `frontend-abc123` → `frontend`)
- `peerInfo?.serviceName` or `peerInfo?.podName` — destination
- `remoteIpStr`, `remotePort` — for external destinations
- `count` — request count
- `direction` — client/server

At the end of `collect()`, after `collectConnections()` and `collectRtt()`, call `topologyAggregator?.advanceWindow()`.

**Service name derivation**: For source pods, strip the pod hash suffix. Common patterns:
- `deployment-name-<replicaset-hash>-<pod-hash>` → `deployment-name`
- `statefulset-name-0` → `statefulset-name`

Use pod labels if available from `CgroupResolver.PodInfo`, or fall back to stripping `-[a-z0-9]{5,10}$` suffixes.

**Destination ID construction**:
- `peerInfo?.serviceName != null` → `"${peerInfo.namespace}/${peerInfo.serviceName}"` (type = "service")
- `peerInfo?.podName != null` → derive service name from pod name, `"${peerInfo.namespace}/$serviceName"` (type = "service")
- `peerInfo == null` → `"external:${remoteIpStr}:${remotePort}"` (type = "external")

**Step 3: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/collector/TcpPeerCollector.kt
git commit -m "feat(topology): integrate TopologyAggregator into TcpPeerCollector"
```

---

### Task 5: Wire beans in BpfAutoConfiguration

**Files:**
- Modify: `src/main/kotlin/com/internal/kpodmetrics/config/BpfAutoConfiguration.kt`

**Step 1: Add TopologyAggregator bean**

Add after the tracing beans (follow existing `@Bean` + `@ConditionalOnProperty` pattern):

```kotlin
@Bean
@ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
fun topologyAggregator(): TopologyAggregator? {
    if (!props.topology.enabled) return null
    return TopologyAggregator(
        windowSize = props.topology.windowSize,
        maxExternalNodes = props.topology.maxExternalNodes
    )
}

@Bean
@ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
fun topologyEndpoint(topologyAggregator: java.util.Optional<TopologyAggregator>): TopologyEndpoint? {
    return topologyAggregator.map { TopologyEndpoint(it) }.orElse(null)
}
```

**Step 2: Update TcpPeerCollector bean to inject TopologyAggregator**

Find the existing `tcpPeerCollector()` bean method. Add `topologyAggregator: java.util.Optional<TopologyAggregator>` parameter and pass `topologyAggregator.orElse(null)` to constructor.

**Step 3: Commit**

```bash
git add src/main/kotlin/com/internal/kpodmetrics/config/BpfAutoConfiguration.kt
git commit -m "feat(topology): wire TopologyAggregator and TopologyEndpoint beans"
```

---

### Task 6: Add Helm chart topology configuration

**Files:**
- Modify: `helm/kpod-metrics/values.yaml`
- Modify: `helm/kpod-metrics/templates/configmap.yaml`

**Step 1: Add topology section to values.yaml**

Add after the `tracing:` section:

```yaml
# --- Topology (Service dependency map) ---
topology:
  enabled: true
  windowSize: 10
  maxExternalNodes: 20
```

**Step 2: Add topology rendering to configmap.yaml**

Add after the tracing section in the configmap template:

```yaml
      topology:
        enabled: {{ .Values.topology.enabled }}
        window-size: {{ .Values.topology.windowSize }}
        max-external-nodes: {{ .Values.topology.maxExternalNodes }}
```

Add `kpodTopology` to the actuator endpoint exposure `include` list.

**Step 3: Commit**

```bash
git add helm/kpod-metrics/values.yaml helm/kpod-metrics/templates/configmap.yaml
git commit -m "feat(helm): add topology configuration to values and configmap"
```

---

### Task 7: Add Grafana Node Graph dashboard

**Files:**
- Create: `helm/kpod-metrics/dashboards/topology.json`

**Step 1: Create dashboard JSON**

Create a Grafana dashboard with a Node Graph panel. The panel uses the Infinity data source (JSON API) to query `http://kpod-metrics:9090/actuator/kpodTopology`. The response `nodes` and `edges` arrays map directly to Grafana's Node Graph data frames.

The dashboard should have:
- One Node Graph panel taking full width
- Auto-refresh every 30s
- Title: "kpod-metrics Service Topology"
- Variables: none needed (single topology view)

**Step 2: Commit**

```bash
git add helm/kpod-metrics/dashboards/topology.json
git commit -m "feat(grafana): add service topology Node Graph dashboard"
```

---

### Task 8: Add e2e topology endpoint test

**Files:**
- Modify: `e2e/e2e-test.sh`

**Step 1: Add Step 7 after Step 6 (tracing toggle test)**

```bash
info "=== Step 7: Topology endpoint test ==="

TOPOLOGY_RESPONSE=$(curl -sf "http://localhost:${LOCAL_PORT}/actuator/kpodTopology" 2>/dev/null || true)
if [ -n "$TOPOLOGY_RESPONSE" ]; then
    NODE_COUNT=$(echo "$TOPOLOGY_RESPONSE" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('nodes', [])))" 2>/dev/null || echo "0")
    EDGE_COUNT=$(echo "$TOPOLOGY_RESPONSE" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('edges', [])))" 2>/dev/null || echo "0")

    if [ "${NODE_COUNT:-0}" -gt 0 ]; then
        check_pass "Topology has ${NODE_COUNT} nodes and ${EDGE_COUNT} edges"
    else
        check_warn "Topology empty (may need more traffic on minikube)"
    fi
else
    check_warn "kpodTopology endpoint not available"
fi
```

**Step 2: Commit**

```bash
git add e2e/e2e-test.sh
git commit -m "feat(e2e): add topology endpoint test"
```

---

### Task 9: Docker build and e2e validation

**Step 1: Build Docker image**

```bash
cd /Users/jongsu/dev && eval $(minikube docker-env) && \
docker build -f kpod-metrics/Dockerfile -t kpod-metrics:local-test .
```

Expected: Build succeeds with all 14 BPF programs generated.

**Step 2: Run e2e test**

```bash
cd /Users/jongsu/dev/kpod-metrics && bash e2e/e2e-test.sh --skip-build --cleanup
```

Expected:
- All existing tests pass (same 2 pre-existing minikube cgroup FAILs)
- Step 6 tracing toggle: 3 PASS
- Step 7 topology: PASS or WARN (topology may be empty on minikube if TCP peer data isn't collected)

**Step 3: If topology endpoint doesn't respond, debug:**
- Check pod logs: `kubectl logs <pod> | grep -i topology`
- Verify endpoint exposure: `curl http://localhost:19091/actuator | python3 -m json.tool`
- Fix and re-test

**Step 4: Commit any fixes**

```bash
git add -A && git commit -m "fix: address e2e topology test issues"
```
