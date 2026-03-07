# TCP Peer Tracking Design

## Goal

Track per-peer TCP connections and RTT with remote IP/port resolution to Kubernetes pod/service names, enabling "who talks to whom" visibility at L4.

## Architecture

Hand-written BPF C program (`tcp_peer.bpf.c`) attached via kprobe/kretprobe to `tcp_connect` (client) and `inet_csk_accept` (server), plus `tp/tcp/tcp_probe` for per-peer RTT. Kotlin-side collector reads BPF maps, resolves remote IPs to pod/service names via fabric8 Kubernetes client with caching.

## Metrics

| Metric | Type | Labels |
|--------|------|--------|
| `kpod.net.tcp.peer.connections` | Counter | namespace, pod, container, node, remote_ip, remote_port, direction, remote_pod, remote_service |
| `kpod.net.tcp.peer.rtt` | DistributionSummary | namespace, pod, container, node, remote_ip, remote_port, remote_pod, remote_service |

`direction` = `client` (outgoing via tcp_connect) or `server` (incoming via inet_csk_accept).

## BPF Program: `tcp_peer.bpf.c`

### Maps

1. **`tcp_peer_conns`** — LRU_HASH, max_entries=10240
   - Key (20 bytes): `{ u64 cgroup_id, u32 remote_ip4, u16 remote_port, u8 direction, u8 _pad }`
   - Value (8 bytes): `{ u64 count }`

2. **`tcp_peer_rtt`** — LRU_HASH, max_entries=10240
   - Key (16 bytes): `{ u64 cgroup_id, u32 remote_ip4, u16 remote_port, u16 _pad }`
   - Value (232 bytes): `{ u64 slots[27], u64 count, u64 sum_us }`

### Programs

1. **`kprobe/tcp_connect`** — Client-side connection. Extract `sk->__sk_common.skc_daddr` and `sk->__sk_common.skc_dport` from the `struct sock *` (arg1). Increment `tcp_peer_conns[cgroup, remote_ip, port, CLIENT]`.

2. **`kretprobe/inet_csk_accept`** — Server-side accept. Read returned `struct sock *` from retval. Extract `sk->__sk_common.skc_daddr` (remote peer) and `sk->__sk_common.skc_num` (local port, but we want remote port = `skc_dport`). Increment `tcp_peer_conns[cgroup, remote_ip, port, SERVER]`.

3. **`tp/tcp/tcp_probe`** — RTT measurement per peer. Read `saddr`, `daddr`, `dport`, `srtt` from tracepoint args. Update `tcp_peer_rtt[cgroup, remote_ip, port]` histogram.

### Sock field access

Use `bpf_probe_read_kernel` to read `struct sock` fields:
- `skc_daddr` at `__sk_common` offset — remote IPv4 address
- `skc_dport` at `__sk_common` offset — remote port (network byte order)
- For `tcp_probe` tracepoint: fields available directly in tracepoint args

## Kotlin Side

### `PodIpResolver.kt`

Caches IP → (podName, namespace, serviceName) mappings:
- On startup: lists all pods and services, builds IP index
- Refreshes every 30 seconds via PodWatcher events
- Falls back to raw IP string if unresolved
- Also resolves ClusterIP services

```kotlin
class PodIpResolver(kubernetesClient: KubernetesClient) {
    fun resolve(ip: String): PeerInfo?  // returns (podName, namespace, serviceName?)
    fun refresh()  // called periodically or on pod events
}
```

### `TcpPeerCollector.kt`

Same pattern as DnsCollector — manual ByteBuffer parsing:
- Reads `tcp_peer_conns` map (20B key, 8B value)
- Reads `tcp_peer_rtt` map (16B key, 232B value)
- Resolves cgroup → pod via CgroupResolver
- Resolves remote IP → pod/service via PodIpResolver
- Exports metrics with full label set

### Config

- `ExtendedProperties.tcpPeer: Boolean = false` (default)
- Standard profile: `tcpPeer = true`
- Comprehensive profile: `tcpPeer = true`
- `CollectorIntervals.tcpPeer: Long? = null`
- `CollectorOverrides.tcpPeer: Boolean? = null`

## Files

### New
- `bpf/tcp_peer.bpf.c` (~200 lines)
- `src/.../collector/TcpPeerCollector.kt` (~150 lines)
- `src/.../collector/PodIpResolver.kt` (~80 lines)
- `src/test/.../collector/TcpPeerCollectorTest.kt`
- `src/test/.../collector/PodIpResolverTest.kt`
- `helm/kpod-metrics/dashboards/tcp_peer.json`

### Modified
- `src/.../config/MetricsProperties.kt` — add tcpPeer config
- `src/.../config/BpfAutoConfiguration.kt` — wire beans
- `src/.../bpf/BpfProgramManager.kt` — load tcp_peer program
- `src/.../collector/MetricsCollectorService.kt` — add tcpPeer collector
- `Dockerfile` — copy tcp_peer.bpf.c
- `e2e/e2e-test.sh` — assert tcp peer metrics
- `e2e/workloads.yaml` — existing net workloads sufficient
- `helm/kpod-metrics/values.yaml` — document tcp peer config
