package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.Counter
import io.micrometer.core.instrument.MeterRegistry
import org.slf4j.LoggerFactory

/**
 * Per-container CPU usage, CFS throttling and limit from cgroup cpu.stat / cpu.max
 * (v1: cpuacct.usage, cpu.stat, cpu.cfs_quota_us/period_us).
 *
 * Throttling is the signal eBPF runqueue latency cannot show: a pod can have an idle
 * CPU available and still stall because it exhausted its CFS quota in the period.
 * Inspired by coroot-node-agent's container_resources_cpu_* metrics.
 */
class CpuCgroupCollector(
    private val reader: CgroupReader,
    private val registry: MeterRegistry
) {
    private val log = LoggerFactory.getLogger(CpuCgroupCollector::class.java)
    private val errorCounter: Counter = registry.counter("kpod.cgroup.read.errors", "collector", "cpuCgroup")
    private val meters = CumulativeMeters(registry)

    fun collect(targets: List<PodCgroupTarget>) {
        for (target in targets) {
            try {
                val stat = reader.readCpuStats(target.cgroupPath) ?: continue
                val tags = target.tags()
                meters.counter("kpod.cpu.usage.seconds", tags, stat.usageSeconds, "seconds")
                meters.counter("kpod.cpu.throttled.seconds", tags, stat.throttledSeconds, "seconds")
                meters.counter("kpod.cpu.throttled.periods", tags, stat.throttledPeriods)
                meters.counter("kpod.cpu.periods", tags, stat.periods)
                meters.gauge("kpod.cpu.limit.cores", tags, stat.limitCores)
            } catch (e: Exception) {
                log.debug("Failed to read cpu stats for pod {}/{}: {}", target.namespace, target.podName, e.message)
                errorCounter.increment()
            }
        }
    }

    fun removeStaleEntries(podName: String, namespace: String) = meters.removePod(podName, namespace)
}
