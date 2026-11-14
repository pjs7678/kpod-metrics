package com.internal.kpodmetrics.collector

import io.micrometer.core.instrument.FunctionCounter
import io.micrometer.core.instrument.Gauge
import io.micrometer.core.instrument.Meter
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import java.util.concurrent.ConcurrentHashMap

/**
 * Exports values that the kernel already accumulates (cgroup cpu.stat, io.stat,
 * /proc/net/dev, PSI totals, ...) as-is.
 *
 * Calling `Counter.increment(cumulativeValue)` every cycle — the previous approach —
 * double counts: after N cycles the counter holds ~N x the real total. Here the latest
 * raw value backs a [FunctionCounter], so Prometheus sees the kernel's own monotonic
 * counter and handles resets (container restart = new cgroup) via its normal
 * counter-reset logic. This matches how cAdvisor and coroot-node-agent export them.
 */
class CumulativeMeters(private val registry: MeterRegistry) {

    private data class Key(val name: String, val tags: Tags)

    private class Holder {
        @Volatile var value: Double = 0.0
    }

    private val counters = ConcurrentHashMap<Key, Holder>()
    private val gauges = ConcurrentHashMap<Key, Holder>()

    /** Set the current cumulative value of a monotonic counter. */
    fun counter(name: String, tags: Tags, value: Double, baseUnit: String? = null) {
        counters.computeIfAbsent(Key(name, tags)) {
            val holder = Holder()
            FunctionCounter.builder(name, holder) { it.value }
                .tags(tags)
                .apply { if (baseUnit != null) baseUnit(baseUnit) }
                .register(registry)
            holder
        }.value = value
    }

    fun counter(name: String, tags: Tags, value: Long, baseUnit: String? = null) =
        counter(name, tags, value.toDouble(), baseUnit)

    /** Set a gauge, or remove it when [value] is null (e.g. a limit that became unlimited). */
    fun gauge(name: String, tags: Tags, value: Double?, baseUnit: String? = null) {
        val key = Key(name, tags)
        if (value == null) {
            if (gauges.remove(key) != null) {
                registry.find(name).tags(tags).meters().forEach { registry.remove(it) }
            }
            return
        }
        gauges.computeIfAbsent(key) {
            val holder = Holder()
            Gauge.builder(name, holder) { it.value }
                .tags(tags)
                .apply { if (baseUnit != null) baseUnit(baseUnit) }
                .register(registry)
            holder
        }.value = value
    }

    /**
     * Forget all series for a pod. Must accompany registry-side meter removal
     * (MetricsCollectorService.cleanupPodMetrics), otherwise a recreated pod with the
     * same name would update a holder whose meter is no longer registered.
     */
    fun removePod(podName: String, namespace: String) {
        val match: (Key) -> Boolean = { key ->
            key.tags.any { it.key == "pod" && it.value == podName } &&
                key.tags.any { it.key == "namespace" && it.value == namespace }
        }
        for (store in listOf(counters, gauges)) {
            val stale = store.keys.filter(match)
            for (key in stale) {
                store.remove(key)
                registry.find(key.name).tags(key.tags).meters().forEach { m: Meter -> registry.remove(m) }
            }
        }
    }

    internal fun size(): Int = counters.size + gauges.size
}
