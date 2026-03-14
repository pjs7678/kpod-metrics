# Service Topology Map — Design

## Goal

Auto-discovered service dependency graph from existing eBPF TCP peer data, exposed as an actuator API and Grafana Node Graph dashboard. Zero new BPF programs — pure Kotlin aggregation over data already collected by TcpPeerCollector.

## Decisions

- **Service-level granularity** — pods grouped by owning service/deployment, not individual pods
- **Rich edge metadata** — request count, error count, avg/p99 latency, bytes, protocol
- **Actuator API + Grafana Node Graph panel** — API returns Grafana-compatible data frames
- **Per-IP external nodes** — each external IP gets its own node, capped at 20 (rest rolled into "other-external")
- **Sliding window** — 10 snapshots × 29s collection cycle ≈ 5 minutes, configurable
- **Protocol inference from ports** — 80/443→HTTP, 6379→Redis, 3306→MySQL, else "tcp"

## Architecture

### Data Flow

```
TcpPeerCollector (every 29s)
  │ batch lookup-and-delete from BPF maps
  │ resolves cgroup_id → PodInfo (src pod)
  │ resolves remote_ip → PeerInfo (dst pod/service)
  │
  ▼
TopologyAggregator.ingest(connections)
  │ groups by (srcService, dstService)
  │ accumulates: requestCount, errorCount, rttSum, rttCount, bytes
  │ stores as snapshot in sliding window ring buffer
  │
  ▼
Sliding Window (ring of N snapshots, default 10 ≈ 5 min)
  │ on query: sum across all snapshots in window
  │ oldest snapshot evicted when new one arrives
  │
  ▼
TopologyEndpoint (GET /actuator/kpodTopology)
  │ returns { nodes: [...], edges: [...] }
  │
  ▼
Grafana Node Graph panel
```

### Service Grouping

Source pods are grouped by owning service using pod labels (`app.kubernetes.io/name` or `app`). Destinations resolved via PodIpResolver: ClusterIP → service name, pod IP → pod's owning service label, unresolved → `external:ip:port`.

### Zero BPF Cost

TcpPeerCollector already collects `tcp_peer_conns` (cgroup_id, remote_ip, remote_port, direction, count) and `tcp_peer_rtt` (histogram). TopologyAggregator only adds Kotlin-side grouping and accumulation. No new BPF programs, maps, or probes.

## Data Structures

### ServiceNode

```kotlin
data class ServiceNode(
    val id: String,           // "namespace/serviceName" or "external:ip:port"
    val name: String,         // display name
    val namespace: String?,   // null for external
    val type: String          // "service" | "external"
)
```

### ServiceEdge

```kotlin
data class ServiceEdge(
    val source: String,       // node id
    val target: String,       // node id
    val requestCount: Long,
    val errorCount: Long,
    val avgLatencyMs: Double, // from RTT sum/count
    val p99LatencyMs: Double, // estimated from histogram buckets
    val bytesTotal: Long,
    val protocols: Set<String> // "tcp", "http", "redis", "mysql"
)
```

### Sliding Window

Array of 10 `CycleSnapshot` entries. Each snapshot: `Map<EdgeKey, EdgeStats>` where `EdgeKey = Pair<srcId, dstId>`. On query, sum stats across all snapshots. Oldest evicted when new arrives.

### Protocol Inference

Well-known port mapping: 80/443→HTTP, 6379→Redis, 3306→MySQL. Otherwise "tcp". No L7 inspection needed.

## API

### GET /actuator/kpodTopology

Grafana Node Graph compatible response:

```json
{
  "nodes": [
    {
      "id": "default/frontend",
      "title": "frontend",
      "subTitle": "default",
      "mainStat": "142 req/s",
      "arc__http": 0.8,
      "arc__redis": 0.2
    }
  ],
  "edges": [
    {
      "id": "default/frontend->default/api-server",
      "source": "default/frontend",
      "target": "default/api-server",
      "mainStat": "95 req/s",
      "secondaryStat": "12ms avg",
      "detail__requestCount": 4750,
      "detail__errorCount": 3,
      "detail__avgLatencyMs": 12.4,
      "detail__p99LatencyMs": 89.2,
      "detail__protocols": "http"
    }
  ]
}
```

Node `mainStat`: total request rate. `arc__*`: traffic breakdown by protocol (colored donut).
Edge `mainStat`: request rate. `secondaryStat`: avg latency.

### External Node Capping

Max 20 external nodes (top by request count). Remaining rolled into single "other-external" node.

## Configuration

```yaml
kpod:
  topology:
    enabled: true
    windowSize: 10
    maxExternalNodes: 20
```

## Integration

- `TopologyAggregator`: Spring bean, injected into `TcpPeerCollector`
- `TcpPeerCollector`: calls `aggregator.ingest(connections)` at end of each collection cycle
- `TopologyEndpoint`: `@Endpoint(id = "kpodTopology")` actuator endpoint
- `application.yml`: add `kpodTopology` to endpoint exposure list
- No changes to: BPF programs, JNI bridge, other collectors

## Helm Changes

- `values.yaml`: add `topology:` section
- `configmap.yaml`: render topology config
- `dashboards/topology.json`: new Grafana Node Graph dashboard

## Testing

**Unit tests:**
- TopologyAggregator: sliding window accumulation, snapshot eviction, edge merging
- Service grouping: pod label resolution, external IP handling, capping logic
- API response: Grafana-compatible format, rate calculation

**E2E test:**
- Step 7 in `e2e-test.sh`: deploy workloads generating inter-pod traffic, hit `/actuator/kpodTopology`, verify nodes and edges present
