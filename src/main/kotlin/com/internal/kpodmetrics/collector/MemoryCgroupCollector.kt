package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.Counter
import io.micrometer.core.instrument.MeterRegistry
import org.slf4j.LoggerFactory

class MemoryCgroupCollector(
    private val reader: CgroupReader,
    private val registry: MeterRegistry
) {
    private val log = LoggerFactory.getLogger(MemoryCgroupCollector::class.java)
    private val errorCounter: Counter = registry.counter("kpod.cgroup.read.errors", "collector", "memory")
    private val meters = CumulativeMeters(registry)

    fun collect(targets: List<PodCgroupTarget>) {
        for (target in targets) {
            try {
                val stat = reader.readMemoryStats(target.cgroupPath) ?: continue
                val tags = target.tags()
                meters.gauge("kpod.mem.cgroup.usage.bytes", tags, stat.usageBytes.toDouble())
                meters.gauge("kpod.mem.cgroup.peak.bytes", tags, stat.peakBytes.toDouble())
                meters.gauge("kpod.mem.cgroup.cache.bytes", tags, stat.cacheBytes.toDouble())
                meters.gauge("kpod.mem.cgroup.swap.bytes", tags, stat.swapBytes.toDouble())
                // RSS (anonymous memory) is what the OOM killer actually acts on; usage includes reclaimable page cache.
                meters.gauge("kpod.mem.cgroup.rss.bytes", tags, stat.rssBytes.toDouble())
                meters.gauge("kpod.mem.cgroup.limit.bytes", tags, stat.limitBytes?.toDouble())
            } catch (e: Exception) {
                log.debug("Failed to read memory stats for pod {}/{}: {}", target.namespace, target.podName, e.message)
                errorCounter.increment()
            }
        }
    }

    fun removeStaleEntries(podName: String, namespace: String) = meters.removePod(podName, namespace)
}
