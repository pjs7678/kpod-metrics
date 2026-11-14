package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.Counter
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory

class DiskIOCollector(
    private val reader: CgroupReader,
    private val registry: MeterRegistry
) {
    private val log = LoggerFactory.getLogger(DiskIOCollector::class.java)
    private val errorCounter: Counter = registry.counter("kpod.cgroup.read.errors", "collector", "diskIO")
    private val meters = CumulativeMeters(registry)

    fun collect(targets: List<PodCgroupTarget>) {
        for (target in targets) {
            try {
                val stats = reader.readDiskIO(target.cgroupPath)
                for (stat in stats) {
                    val device = "${stat.major}:${stat.minor}"
                    val tags = target.tags().and("device", device)
                    meters.counter("kpod.disk.read.bytes", tags, stat.readBytes)
                    meters.counter("kpod.disk.written.bytes", tags, stat.writeBytes)
                    meters.counter("kpod.disk.reads", tags, stat.reads)
                    meters.counter("kpod.disk.writes", tags, stat.writes)
                }
            } catch (e: Exception) {
                log.debug("Failed to read disk I/O for pod {}/{}: {}", target.namespace, target.podName, e.message)
                errorCounter.increment()
            }
        }
    }

    fun removeStaleEntries(podName: String, namespace: String) = meters.removePod(podName, namespace)
}
