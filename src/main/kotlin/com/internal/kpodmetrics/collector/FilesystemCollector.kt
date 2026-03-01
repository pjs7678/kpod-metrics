package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.Counter
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory
import java.util.concurrent.atomic.AtomicLong

class FilesystemCollector(
    private val reader: CgroupReader,
    private val procRoot: String,
    private val registry: MeterRegistry
) {
    private val log = LoggerFactory.getLogger(FilesystemCollector::class.java)
    private val errorCounter: Counter = registry.counter("kpod.cgroup.read.errors", "collector", "filesystem")

    private data class GaugeKey(val pod: String, val ns: String, val container: String, val node: String, val mount: String)
    private val capacityValues = java.util.concurrent.ConcurrentHashMap<GaugeKey, AtomicLong>()
    private val usageValues = java.util.concurrent.ConcurrentHashMap<GaugeKey, AtomicLong>()
    private val availableValues = java.util.concurrent.ConcurrentHashMap<GaugeKey, AtomicLong>()

    fun collect(targets: List<PodCgroupTarget>) {
        for (target in targets) {
            try {
                val pid = reader.readInitPid(target.cgroupPath) ?: continue
                val stats = reader.readFilesystemStats(procRoot, pid)
                for (stat in stats) {
                    val key = GaugeKey(target.podName, target.namespace, target.containerName, target.nodeName, stat.mountPoint)
                    val tags = target.tags().and("mountpoint", stat.mountPoint)
                    getOrRegisterGauge(capacityValues, key, "kpod.fs.capacity.bytes", tags).set(stat.totalBytes)
                    getOrRegisterGauge(usageValues, key, "kpod.fs.usage.bytes", tags).set(stat.usedBytes)
                    getOrRegisterGauge(availableValues, key, "kpod.fs.available.bytes", tags).set(stat.availableBytes)
                }
            } catch (e: Exception) {
                log.debug("Failed to read filesystem stats for pod {}/{}: {}", target.namespace, target.podName, e.message)
                errorCounter.increment()
            }
        }
    }

    fun removeStaleEntries(podName: String, namespace: String) {
        capacityValues.keys.removeAll { it.pod == podName && it.ns == namespace }
        usageValues.keys.removeAll { it.pod == podName && it.ns == namespace }
        availableValues.keys.removeAll { it.pod == podName && it.ns == namespace }
    }

    private fun getOrRegisterGauge(
        store: java.util.concurrent.ConcurrentHashMap<GaugeKey, AtomicLong>,
        key: GaugeKey, name: String, tags: Tags
    ): AtomicLong {
        return store.computeIfAbsent(key) { _ ->
            val value = AtomicLong(0)
            registry.gauge(name, tags, value) { it.toDouble() }
            value
        }
    }
}
