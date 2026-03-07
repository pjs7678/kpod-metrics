# DNS Metrics Collector Design

## Overview

Add a `dns` BPF program that captures DNS query/response metrics per pod via kprobes on `udp_sendmsg`/`udp_recvmsg`, with kernel-side DNS header parsing and truncated QNAME extraction (first 32 bytes). Enabled in `standard` and `comprehensive` profiles.

## Decisions

- **Parsing location**: Kernel-side (approach A) — parse DNS header + truncated QNAME in BPF
- **Attachment**: kprobe on `udp_sendmsg` / `udp_recvmsg` (matches existing net program pattern)
- **Domain tracking**: Yes, LRU map capped at 1024 entries to limit cardinality
- **Profile**: Enabled in standard + comprehensive
- **DNS ports**: Multiple ports supported via BPF HASH set (default [53]), settable at runtime

## Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `kpod.dns.requests` | counter | namespace, pod, container, node, qtype | Total DNS queries sent |
| `kpod.dns.latency` | distribution summary | namespace, pod, container, node | Request-to-response latency (seconds) |
| `kpod.dns.errors` | counter | namespace, pod, container, node, rcode | Responses with non-zero rcode |
| `kpod.dns.top.domains` | counter | namespace, pod, container, node, domain | Per-domain query count (truncated QNAME) |

### Label Values

| qtype | Label |
|-------|-------|
| 1 | A |
| 28 | AAAA |
| 5 | CNAME |
| 33 | SRV |
| 12 | PTR |
| other | OTHER |

| rcode | Label |
|-------|-------|
| 1 | FORMERR |
| 2 | SERVFAIL |
| 3 | NXDOMAIN |
| 5 | REFUSED |
| other | OTHER |

## BPF Program

### Attachment Points

- `kprobe/udp_sendmsg` — intercept outgoing DNS queries (filter by configurable port)
- `kprobe/udp_recvmsg` — stash sockaddr for port check
- `kretprobe/udp_recvmsg` — intercept DNS responses, compute latency

### Maps

| Map | Type | Key | Value | Max Entries |
|-----|------|-----|-------|-------------|
| `dns_ports` | HASH | u16 (port) | u8 (1=present) | 8 |
| `dns_requests` | LRU_HASH | `dns_req_key` (cgroup_id + qtype) | `counter_value` | 10240 |
| `dns_latency` | LRU_HASH | `hist_key` (cgroup_id) | `hist_value` (27-slot log2) | 10240 |
| `dns_errors` | LRU_HASH | `dns_err_key` (cgroup_id + rcode) | `counter_value` | 10240 |
| `dns_domains` | LRU_HASH | `dns_domain_key` (cgroup_id + domain[32]) | `counter_value` | 1024 |
| `dns_inflight` | LRU_HASH | `dns_txid_key` (cgroup_id + txid) | u64 (timestamp_ns) | 4096 |

`dns_inflight` is internal only (request-response matching). Not read by the collector.

### Structs

```kotlin
object DnsReqKey : BpfStruct("dns_req_key") {
    val cgroupId by u64()
    val qtype by u16()
    val pad by u16(cName = "_pad1")
    val pad2 by u32(cName = "_pad2")
}

object DnsErrKey : BpfStruct("dns_err_key") {
    val cgroupId by u64()
    val rcode by u8()
    val pad by array(BpfScalar.U8, 7, cName = "_pad")
}

object DnsDomainKey : BpfStruct("dns_domain_key") {
    val cgroupId by u64()
    val domain by array(BpfScalar.U8, 32)
}

object DnsTxidKey : BpfStruct("dns_txid_key") {
    val cgroupId by u64()
    val txid by u16()
    val pad by u16(cName = "_pad1")
    val pad2 by u32(cName = "_pad2")
}
```

### BPF Logic

```
kprobe/udp_sendmsg:
  1. Extract dest port from msghdr -> sockaddr_in.sin_port
  2. Lookup dns_ports[port] -> if not found, return (not a DNS port)
  3. bpf_probe_read_user first 44 bytes from iov[0].iov_base
  4. Parse DNS header: txid (bytes 0-1), flags (2-3), qdcount (4-5)
  5. If QR bit set (response), return (we only track queries here)
  6. Parse QNAME at byte 12 (label-decode into domain[32])
  7. Extract qtype (2 bytes after QNAME terminator)
  8. Store timestamp in dns_inflight[cgroup_id + txid]
  9. Increment dns_requests[cgroup_id + qtype]
  10. Increment dns_domains[cgroup_id + domain]

kprobe/udp_recvmsg:
  1. Stash sockaddr pointer in per-cpu map (for kretprobe)

kretprobe/udp_recvmsg:
  1. Retrieve stashed sockaddr, extract source port
  2. Lookup dns_ports[port] -> if not found, return
  3. bpf_probe_read_user first 12 bytes (DNS header)
  4. Parse: txid, flags (QR must be 1), rcode (lower 4 bits)
  5. Lookup dns_inflight[cgroup_id + txid] -> start_ts
  6. If found: latency_ns = now - start_ts -> update dns_latency histogram
  7. Delete dns_inflight entry
  8. If rcode != 0: increment dns_errors[cgroup_id + rcode]
```

## Kotlin Collector

```kotlin
class DnsCollector(
    bridge, programManager, cgroupResolver, registry, config, nodeName
) {
    fun collect() {
        if (!config.extended.dns) return
        collectRequests()   // dns_requests -> kpod.dns.requests
        collectLatency()    // dns_latency  -> kpod.dns.latency
        collectErrors()     // dns_errors   -> kpod.dns.errors
        collectDomains()    // dns_domains  -> kpod.dns.top.domains
    }
}
```

Domain bytes decoded from null-terminated UTF-8 in the 32-byte array.

## Configuration

```kotlin
data class ExtendedProperties(
    // existing fields ...
    val dns: Boolean = false,
    val dnsPorts: List<Int> = listOf(53)
)
```

Profile defaults:
- minimal: dns = false
- standard: dns = true
- comprehensive: dns = true

Helm values:
```yaml
config:
  collectors:
    dns: true
    dnsPorts: [53, 5353]
```

DNS ports are injected into the BPF `dns_ports` HASH map at program load time by `BpfProgramManager`.
Each port is a u16 key with value u8(1). Up to 8 ports supported.

## Grafana Dashboard

New `dns.json` dashboard (or row in existing dashboard):
- DNS Query Rate: timeseries, `rate(kpod_dns_requests_total[5m])` by pod
- DNS Latency: heatmap, `kpod_dns_latency` histogram
- DNS Errors: stat + timeseries, `rate(kpod_dns_errors_total[5m])` by rcode
- Top Domains: table, `topk(10, sum by (domain) (rate(kpod_dns_top_domains_total[5m])))`

## Files to Create/Modify

| # | File | Action | ~Lines |
|---|------|--------|--------|
| 1 | `bpf/programs/DnsProgram.kt` | Create | 180 |
| 2 | `bpf/programs/Structs.kt` | Add DNS structs | +30 |
| 3 | `bpf/programs/GenerateBpf.kt` | Add dnsProgram | +1 |
| 4 | `collector/DnsCollector.kt` | Create | 120 |
| 5 | `config/MetricsProperties.kt` | Add dns/dnsPorts to Extended, Intervals, Overrides | +8 |
| 6 | `config/BpfAutoConfiguration.kt` | Register DnsCollector bean | +10 |
| 7 | `bpf/BpfProgramManager.kt` | Add dns to loadAll(), inject ports config | +12 |
| 7b | `bpf/BpfBridge.kt` | Add mapUpdate() wrapper | +5 |
| 7c | `jni/bpf_bridge.c` | Add nativeMapUpdate JNI function | +20 |
| 8 | `collector/MetricsCollectorService.kt` | Add DnsCollector | +3 |
| 9 | `helm/values.yaml` | Add dns/dnsPorts to collector comments | +3 |
| 10 | `helm/templates/configmap.yaml` | dns config propagation | +2 |
| 11 | `test/collector/DnsCollectorTest.kt` | Create | 100 |
| 12 | `helm/dashboards/dns.json` | Create Grafana dashboard | 200 |

## Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| iov parsing fragility across kernels | Validate first iov only; bail if iov_len < 44 |
| DNS-over-TCP missed | Out of scope for v1 — UDP covers 95%+ of cluster DNS |
| Domain cardinality explosion | LRU map capped at 1024 entries |
| DNS-over-HTTPS/DoT bypasses port 53 | Document as known limitation |
| kretprobe sockaddr access | Stash sockaddr in per-cpu map during kprobe entry |
| Non-standard DNS port | Configurable via dns_ports BPF HASH map, supports multiple ports (default [53]) |

## Scope Exclusions

- DNS-over-TCP (future enhancement)
- DNS-over-HTTPS / DNS-over-TLS
- EDNS0 parsing
- Full QNAME (limited to 32 bytes)
- DNSSEC validation status
