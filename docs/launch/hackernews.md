# Hacker News Post

## Title (80 char max)

```
Show HN: kpod-metrics – eBPF pod metrics for K8s, with BPF programs written in Kotlin
```

## URL

```
https://github.com/pjs7678/kpod-metrics
```

## First Comment (post immediately after submitting)

Hey HN, I built kpod-metrics because I was frustrated writing eBPF programs in C
for Kubernetes observability.

**The problem:** Getting per-pod kernel metrics (CPU scheduling latency, TCP
retransmits, syscall errors, disk I/O latency) in Kubernetes requires writing
eBPF C programs, a JNI bridge, and Kotlin/Java deserialization code — all kept
manually in sync. One struct field change means updating three places.

**The solution:** I created a Kotlin DSL for eBPF that generates all three from
a single definition:

```kotlin
val memProgram = ebpfProgram("mem") {
    val key = struct("counter_key") { u64("cgroup_id") }
    val oomKills = hashMap("oom_kills", key, BpfScalar.U64)

    tracepoint("oom", "mark_victim") {
        val cgId = getCurrentCgroupId()
        val ptr = mapLookupElem(oomKills, cgId)
        ifNonNull(ptr) { atomicIncrement(it) }
    }
}
```

This generates: (1) kernel-side C code, (2) type-safe Kotlin MapReader classes.
No manual ByteBuffer parsing. No struct offset mismatches.

**What kpod-metrics does:**

- DaemonSet that exports 50+ per-pod metrics to Prometheus
- eBPF: CPU runqueue latency, TCP RTT/retransmits/drops, OOM kills, syscall
  latency, block I/O latency, hardware IRQ latency
- Cgroup: disk I/O, network interface stats, filesystem, memory usage
- L7 protocol detection: HTTP, DNS, Redis, MySQL, Kafka, MongoDB
- Auto-discovered service topology from TCP peer data (zero config)
- ~256 Mi memory per node, tested up to 1,000 nodes / 100,000 pods

**Compared to Pixie/Hubble/Inspektor Gadget:**

- Lighter (256Mi vs Pixie's 2Gi)
- Prometheus-native (no separate UI/storage)
- Supports kernel 4.18+ (legacy mode) — most tools require 5.2+
- Type-safe BPF development in Kotlin instead of C

Try it:
```
helm repo add kpod-metrics https://pjs7678.github.io/kpod-metrics
helm install kpod-metrics kpod-metrics/kpod-metrics -n kpod-metrics --create-namespace
```

Docs: https://pjs7678.github.io/kpod-metrics

Feedback welcome — especially on the DSL design and which metrics/protocols
to add next.
