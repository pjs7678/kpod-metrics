package com.internal.kpodmetrics.collector

import io.micrometer.core.instrument.FunctionTimer
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import io.prometheus.metrics.model.registry.MultiCollector
import io.prometheus.metrics.model.snapshots.ClassicHistogramBuckets
import io.prometheus.metrics.model.snapshots.HistogramSnapshot
import io.prometheus.metrics.model.snapshots.HistogramSnapshot.HistogramDataPointSnapshot
import io.prometheus.metrics.model.snapshots.Labels
import io.prometheus.metrics.model.snapshots.MetricSnapshots
import io.prometheus.metrics.model.snapshots.Unit
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * Exports the kernel's per-event log2 latency histograms as real Prometheus histograms.
 *
 * The BPF programs bucket every event into `slots[log2(ns >> SLOT_SHIFT)]` (27 slots, see
 * histSlot in kotlin-ebpf-dsl and HIST_SLOT_SHIFT in the BPF generator): slot s holds values in
 * [2^(s+SHIFT), 2^(s+1+SHIFT)) ns, slot 0 also holds everything below 2^(1+SHIFT) ns ≈ 2 µs,
 * and slot 26 is a clamp for everything >= 2^36 ns ≈ 68.7 s. Collectors drain the maps every
 * cycle, so each observation here is a per-cycle delta that is accumulated into monotonic
 * bucket counters.
 *
 * Why not Micrometer DistributionSummary + publishPercentileHistogram: Micrometer has no
 * "record N events" API, so we could only record one aggregate per cycle — percentiles over
 * per-cycle averages are meaningless — or call record() once per kernel event (millions per
 * cycle for runqueue latency). Writing the kernel buckets directly is exact and O(slots).
 *
 * Bucket bounds are exact slot edges: `le = 2^(s+1+SHIFT) ns`. Each spec exports edges up to its
 * own [Spec.lastSlot]; slots above it (including the kernel clamp slot) only feed `+Inf`, so
 * histogram_quantile never reports a fabricated value above the last edge — it reports the
 * last edge, i.e. "at least this much", which is the honest answer the data supports.
 *
 * Exposition: registered on the Prometheus client registry as a MultiCollector, giving
 * `<name>_bucket{le}`, `<name>_count` (= events), `<name>_sum` (= total seconds).
 * OTLP has no hook for externally-computed buckets in Micrometer, so when an OTLP registry
 * is configured each series is mirrored there as a FunctionTimer (count + total time).
 */
class Log2Histograms(private val otlpRegistry: MeterRegistry? = null) : MultiCollector {

    /**
     * @param name Prometheus base name, must end in `_seconds`.
     * @param firstSlot first slot whose upper edge becomes a bucket; lower slots merge into it.
     * @param stride emit every n-th slot edge (coarser buckets, fewer series).
     * @param lastSlot last slot whose upper edge becomes a finite bucket; higher slots only
     *   reach `+Inf`. Lower it to drop edges a signal never realistically needs.
     */
    class Spec(
        val name: String,
        val help: String,
        val firstSlot: Int,
        val stride: Int = 1,
        val lastSlot: Int = LAST_FINITE_SLOT,
        val otlpName: String
    ) {
        init {
            require(name.endsWith("_seconds")) { "histogram name must end in _seconds: $name" }
            require(lastSlot in 0..LAST_FINITE_SLOT && firstSlot in 0..lastSlot && stride >= 1)
        }

        /** Slot indices whose upper edge is a finite `le`. Always ends at [lastSlot]. */
        val edgeSlots: IntArray = buildList {
            var s = firstSlot
            while (s < lastSlot) { add(s); s += stride }
            add(lastSlot)
        }.toIntArray()

        /** Finite upper bounds in seconds, followed by +Inf. */
        val upperBounds: DoubleArray = DoubleArray(edgeSlots.size + 1) { i ->
            if (i == edgeSlots.size) Double.POSITIVE_INFINITY else slotUpperEdgeNs(edgeSlots[i]) / 1e9
        }

        override fun toString() = name
    }

    private class Series(val labels: Labels) {
        val slots = LongArray(SLOTS)
        var sumNs: Long = 0
        var count: Long = 0
    }

    private val series = ConcurrentHashMap<Spec, ConcurrentHashMap<Tags, Series>>()
    private val specs = ConcurrentHashMap.newKeySet<Spec>()

    /** Register a spec so it is exported (with no data points) even before the first event. */
    fun register(spec: Spec): Spec {
        specs.add(spec)
        return spec
    }

    /**
     * Add one drained BPF histogram. Returns false (and records nothing) if the data is
     * implausible, e.g. a negative slot from a corrupted map read.
     */
    fun observe(spec: Spec, tags: Tags, slots: LongArray, sumNs: Long): Boolean {
        if (slots.size != SLOTS || slots.any { it < 0 } || sumNs < 0) return false
        val events = slots.sum()
        if (events == 0L) return true
        register(spec)
        val perSpec = series.computeIfAbsent(spec) { ConcurrentHashMap() }
        val s = perSpec.computeIfAbsent(tags) { t ->
            val created = Series(toLabels(t))
            otlpRegistry?.let { reg ->
                FunctionTimer.builder(spec.otlpName, created,
                    { synchronized(it) { it.count } },
                    { synchronized(it) { it.sumNs.toDouble() } },
                    TimeUnit.NANOSECONDS)
                    .tags(t)
                    .register(reg)
            }
            created
        }
        synchronized(s) {
            for (i in 0 until SLOTS) s.slots[i] += slots[i]
            // _count must equal the +Inf bucket, so derive it from the slots rather than the
            // separately-maintained BPF count field (they can differ by in-flight updates).
            s.count += events
            s.sumNs += sumNs
        }
        return true
    }

    fun removePod(podName: String, namespace: String) {
        for ((spec, perSpec) in series) {
            val stale = perSpec.keys.filter { tags ->
                tags.any { it.key == "pod" && it.value == podName } &&
                    tags.any { it.key == "namespace" && it.value == namespace }
            }
            for (t in stale) {
                perSpec.remove(t)
                otlpRegistry?.let { reg -> reg.find(spec.otlpName).tags(t).meters().forEach { reg.remove(it) } }
            }
        }
    }

    override fun collect(): MetricSnapshots {
        val builder = MetricSnapshots.builder()
        for (spec in specs) {
            val h = HistogramSnapshot.builder()
                .name(spec.name)
                .unit(Unit.SECONDS)
                .help(spec.help)
            for (s in series[spec]?.values.orEmpty()) {
                val counts: LongArray
                val sum: Double
                synchronized(s) {
                    counts = cumulativeBuckets(spec, s.slots)
                    sum = s.sumNs / 1e9
                }
                h.dataPoint(
                    HistogramDataPointSnapshot.builder()
                        .labels(s.labels)
                        .classicHistogramBuckets(ClassicHistogramBuckets.of(spec.upperBounds, toNonCumulative(counts)))
                        .sum(sum)
                        .build()
                )
            }
            builder.metricSnapshot(h.build())
        }
        return builder.build()
    }

    override fun getPrometheusNames(): List<String> = specs.map { it.name }

    internal fun seriesCount(spec: Spec): Int = series[spec]?.size ?: 0

    companion object {
        const val SLOTS = 27
        /** Slots are computed on `ns >> SLOT_SHIFT`. Must equal HIST_SLOT_SHIFT in the BPF generator. */
        const val SLOT_SHIFT = 10
        /** The last slot (26) is a clamp for >= 2^36 ns; slot 25 is the last with a real edge. */
        const val LAST_FINITE_SLOT = SLOTS - 2

        fun slotUpperEdgeNs(slot: Int): Double = Math.scalb(1.0, slot + 1 + SLOT_SHIFT)

        /** Cumulative counts per bucket of [spec] (finite edges, then +Inf). */
        internal fun cumulativeBuckets(spec: Spec, slots: LongArray): LongArray {
            val out = LongArray(spec.upperBounds.size)
            var running = 0L
            var slot = 0
            for ((i, edge) in spec.edgeSlots.withIndex()) {
                while (slot <= edge) running += slots[slot++]
                out[i] = running
            }
            while (slot < SLOTS) running += slots[slot++]
            out[out.size - 1] = running
            return out
        }

        /** client_java's ClassicHistogramBuckets takes per-bucket (non-cumulative) counts. */
        private fun toNonCumulative(cumulative: LongArray): LongArray =
            LongArray(cumulative.size) { i -> if (i == 0) cumulative[0] else cumulative[i] - cumulative[i - 1] }

        private fun toLabels(tags: Tags): Labels {
            val names = mutableListOf<String>()
            val values = mutableListOf<String>()
            tags.forEach { names.add(it.key); values.add(it.value) }
            return Labels.of(names, values)
        }

        // Specs for the BPF histograms. Edge of slot s = 2^(s+11) ns. first/last/stride are chosen
        // per domain to keep series low: values below the first edge merge into the first
        // bucket, values above the last edge only reach +Inf.
        val RUNQUEUE = Spec(
            "kpod_cpu_runqueue_latency_seconds", "Time tasks waited in the CPU run queue (per event, eBPF)",
            firstSlot = 0, lastSlot = 21, otlpName = "kpod.cpu.runqueue.latency" // 2 µs .. 4.3 s, 22 edges
        )
        val TCP_RTT = Spec(
            "kpod_net_tcp_rtt_seconds", "Smoothed TCP round-trip time per tcp_probe event (eBPF)",
            firstSlot = 3, lastSlot = 22, otlpName = "kpod.net.tcp.rtt" // 16 µs .. 8.6 s (srtt has µs resolution)
        )
        val SYSCALL = Spec(
            "kpod_syscall_latency_seconds", "Syscall latency per call (eBPF)",
            firstSlot = 0, stride = 2, lastSlot = 24, otlpName = "kpod.syscall.latency" // 2 µs .. 34 s, x4: 13 edges (× syscall label)
        )
        val DISK_IO = Spec(
            "kpod_disk_io_latency_seconds", "Block I/O latency per request, issue to completion (eBPF)",
            firstSlot = 3, lastSlot = 24, otlpName = "kpod.disk.io.latency" // 16 µs .. 34 s
        )
    }
}
