package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.Counter
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

class MemoryCgroupCollector(
    private val reader: CgroupReader,
    private val registry: MeterRegistry
) {
    private val log = LoggerFactory.getLogger(MemoryCgroupCollector::class.java)
    private val errorCounter: Counter = registry.counter("kpod.cgroup.read.errors", "collector", "memory")

    private data class GaugeKey(val pod: String, val ns: String, val container: String, val node: String)
    private val usageValues = ConcurrentHashMap<GaugeKey, AtomicLong>()
    private val peakValues = ConcurrentHashMap<GaugeKey, AtomicLong>()
    private val cacheValues = ConcurrentHashMap<GaugeKey, AtomicLong>()
    private val swapValues = ConcurrentHashMap<GaugeKey, AtomicLong>()

    fun collect(targets: List<PodCgroupTarget>) {
        for (target in targets) {
            try {
                val stat = reader.readMemoryStats(target.cgroupPath) ?: continue
                val key = GaugeKey(target.podName, target.namespace, target.containerName, target.nodeName)
                val tags = Tags.of(
                    "namespace", target.namespace,
                    "pod", target.podName,
                    "container", target.containerName,
                    "node", target.nodeName
                )
                getOrRegisterGauge(usageValues, key, "kpod.mem.cgroup.usage.bytes", tags).set(stat.usageBytes)
                getOrRegisterGauge(peakValues, key, "kpod.mem.cgroup.peak.bytes", tags).set(stat.peakBytes)
                getOrRegisterGauge(cacheValues, key, "kpod.mem.cgroup.cache.bytes", tags).set(stat.cacheBytes)
                getOrRegisterGauge(swapValues, key, "kpod.mem.cgroup.swap.bytes", tags).set(stat.swapBytes)
            } catch (e: Exception) {
                log.debug("Failed to read memory stats for pod {}/{}: {}", target.namespace, target.podName, e.message)
                errorCounter.increment()
            }
        }
    }

    private fun getOrRegisterGauge(
        store: ConcurrentHashMap<GaugeKey, AtomicLong>,
        key: GaugeKey, name: String, tags: Tags
    ): AtomicLong {
        return store.computeIfAbsent(key) { _ ->
            val value = AtomicLong(0)
            registry.gauge(name, tags, value) { it.toDouble() }
            value
        }
    }
}
