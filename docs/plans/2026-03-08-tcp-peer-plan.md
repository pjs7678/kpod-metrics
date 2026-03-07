# TCP Peer Tracking Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Track per-peer TCP connections and RTT via eBPF, with Kubernetes IP-to-pod resolution.

**Architecture:** Hand-written BPF C program with kprobe/kretprobe on tcp_connect/inet_csk_accept + tcp_probe tracepoint. Kotlin collector with manual ByteBuffer parsing. PodIpResolver for K8s-aware IP resolution.

**Tech Stack:** eBPF/C, Kotlin, Spring Boot, Micrometer, fabric8 Kubernetes client

---

### Task 1: BPF Program — `tcp_peer.bpf.c`

**Files:**
- Create: `bpf/tcp_peer.bpf.c`

Write the BPF C program with:
- 2 maps: `tcp_peer_conns` (LRU_HASH, 20B key, 8B value), `tcp_peer_rtt` (LRU_HASH, 16B key, 232B value)
- `kprobe/tcp_connect`: read `struct sock *` arg1, extract skc_daddr/skc_dport, increment conns with direction=0 (CLIENT)
- `kretprobe/inet_csk_accept`: read returned sock, extract remote IP/port, increment conns with direction=1 (SERVER)
- `tp/tcp/tcp_probe`: read srtt from tracepoint args, update RTT histogram per peer
- Include `vmlinux.h`, use `bpf_probe_read_kernel` for sock field access
- Use same `inc_counter` and `log2l` helpers as dns.bpf.c

### Task 2: Dockerfile — Add tcp_peer.bpf.c to build

**Files:**
- Modify: `Dockerfile`

Add `COPY kpod-metrics/bpf/tcp_peer.bpf.c /build/bpf/tcp_peer.bpf.c` after the dns.bpf.c COPY line.

### Task 3: Config — Add tcpPeer to MetricsProperties

**Files:**
- Modify: `src/main/kotlin/com/internal/kpodmetrics/config/MetricsProperties.kt`

- Add `tcpPeer: Boolean = false` to `ExtendedProperties`
- Add `tcpPeer: Long? = null` to `CollectorIntervals`
- Add `tcpPeer: Boolean? = null` to `CollectorOverrides`
- Set `tcpPeer = true` in standard and comprehensive profiles

### Task 4: BpfProgramManager — Load tcp_peer program

**Files:**
- Modify: `src/main/kotlin/com/internal/kpodmetrics/bpf/BpfProgramManager.kt`

Add `if (ext.tcpPeer) tryLoadProgram("tcp_peer")` in `loadAll()` after the dns line.

### Task 5: PodIpResolver — Kubernetes IP-to-pod/service resolution

**Files:**
- Create: `src/main/kotlin/com/internal/kpodmetrics/collector/PodIpResolver.kt`
- Create: `src/test/kotlin/com/internal/kpodmetrics/collector/PodIpResolverTest.kt`

PodIpResolver:
- Constructor takes `KubernetesClient`
- `data class PeerInfo(val podName: String?, val namespace: String?, val serviceName: String?)`
- `fun resolve(ip: String): PeerInfo?` — lookup cached IP→peer mapping
- `fun refresh()` — rebuild cache: list all pods (podIP→podName/ns), list all services (clusterIP→serviceName)
- Cache is a ConcurrentHashMap<String, PeerInfo>
- Initial refresh in constructor

Test:
- Mock KubernetesClient, verify resolve returns correct PeerInfo
- Verify unknown IP returns null

### Task 6: TcpPeerCollector — Collect and export metrics

**Files:**
- Create: `src/main/kotlin/com/internal/kpodmetrics/collector/TcpPeerCollector.kt`
- Create: `src/test/kotlin/com/internal/kpodmetrics/collector/TcpPeerCollectorTest.kt`

TcpPeerCollector:
- Same constructor pattern as DnsCollector (bridge, programManager, cgroupResolver, registry, config, nodeName) + PodIpResolver
- `collect()` checks `config.extended.tcpPeer` and `programManager.isProgramLoaded("tcp_peer")`
- `collectConnections()`: batch read tcp_peer_conns map, decode 20B key (cgroup_id u64, remote_ip4 u32, remote_port u16, direction u8, pad u8), decode 8B value (count u64). Convert IP to dotted string. Resolve via PodIpResolver. Export `kpod.net.tcp.peer.connections` counter.
- `collectRtt()`: batch read tcp_peer_rtt map, decode 16B key (cgroup_id u64, remote_ip4 u32, remote_port u16, pad u16), decode 232B value (hist). Export `kpod.net.tcp.peer.rtt` distribution summary.
- Direction label: 0 → "client", 1 → "server"

Constants:
- `CONN_KEY_SIZE = 20`, `CONN_VALUE_SIZE = 8`
- `RTT_KEY_SIZE = 16`, `RTT_VALUE_SIZE = 232`

Test:
- Test IP conversion helper (u32 → dotted string)
- Test direction label mapping

### Task 7: Wire into BpfAutoConfiguration and MetricsCollectorService

**Files:**
- Modify: `src/main/kotlin/com/internal/kpodmetrics/config/BpfAutoConfiguration.kt`
- Modify: `src/main/kotlin/com/internal/kpodmetrics/collector/MetricsCollectorService.kt`

BpfAutoConfiguration:
- Add `podIpResolver` bean (takes kubernetesClient)
- Add `tcpPeerCollector` bean (takes bridge, manager, resolver, registry, config, nodeName, podIpResolver)
- Add `tcpPeerCollector` parameter to `metricsCollectorService` bean

MetricsCollectorService:
- Add `tcpPeerCollector: TcpPeerCollector` constructor parameter
- Add `"tcpPeer"` entries to intervalMap, overrideMap, allBpfCollectors, getEnabledCollectorCount
- Add tcp_peer maps to cleanupCgroupEntries (both 20B and 16B key maps need iteration)

### Task 8: E2E test assertions

**Files:**
- Modify: `e2e/e2e-test.sh`

Add TCP peer metric assertions (warn-only for minikube):
- `kpod_net_tcp_peer_connections_total{pod=~e2e-net.*} > 0`
- `kpod_net_tcp_peer_rtt_seconds{pod=~e2e-net.*}` exists

### Task 9: Helm values and Grafana dashboard

**Files:**
- Modify: `helm/kpod-metrics/values.yaml`
- Create: `helm/kpod-metrics/dashboards/tcp_peer.json`

values.yaml: Add tcpPeer documentation comments.
Dashboard: 2 panels — TCP Peer Connections (bar gauge by remote), Peer RTT (heatmap).

### Task 10: Commit and verify

Commit all changes. Verify Dockerfile includes tcp_peer.bpf.c. Verify config profiles include tcpPeer.
