package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.Counter
import io.micrometer.core.instrument.MeterRegistry
import org.slf4j.LoggerFactory

/**
 * Pressure Stall Information (cgroup v2, kernel 4.20+, CONFIG_PSI=y).
 *
 * `rate(kpod_pressure_stall_seconds_total{kind="some"}[5m])` = fraction of wall time in which
 * at least one task in the container was stalled on that resource; `full` = all non-idle
 * tasks were stalled simultaneously. This is the cgroup-native equivalent of coroot's
 * delay-accounting metrics (container_resources_cpu_delay / disk_delay), and is the most
 * direct "is this container slowed down by resource contention" signal available.
 */
class PressureCollector(
    private val reader: CgroupReader,
    private val registry: MeterRegistry
) {
    private val log = LoggerFactory.getLogger(PressureCollector::class.java)
    private val errorCounter: Counter = registry.counter("kpod.cgroup.read.errors", "collector", "pressure")
    private val meters = CumulativeMeters(registry)

    fun collect(targets: List<PodCgroupTarget>) {
        for (target in targets) {
            try {
                for (stat in reader.readPressure(target.cgroupPath)) {
                    val tags = target.tags().and("resource", stat.resource)
                    meters.counter("kpod.pressure.stall.seconds", tags.and("kind", "some"), stat.someSeconds, "seconds")
                    stat.fullSeconds?.let {
                        meters.counter("kpod.pressure.stall.seconds", tags.and("kind", "full"), it, "seconds")
                    }
                }
            } catch (e: Exception) {
                log.debug("Failed to read pressure for pod {}/{}: {}", target.namespace, target.podName, e.message)
                errorCounter.increment()
            }
        }
    }

    fun removeStaleEntries(podName: String, namespace: String) = meters.removePod(podName, namespace)
}
