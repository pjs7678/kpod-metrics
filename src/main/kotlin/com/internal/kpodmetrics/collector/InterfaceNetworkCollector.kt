package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.Counter
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory

class InterfaceNetworkCollector(
    private val reader: CgroupReader,
    private val procRoot: String,
    private val registry: MeterRegistry
) {
    private val log = LoggerFactory.getLogger(InterfaceNetworkCollector::class.java)
    private val errorCounter: Counter = registry.counter("kpod.cgroup.read.errors", "collector", "ifaceNet")
    private val meters = CumulativeMeters(registry)

    fun collect(targets: List<PodCgroupTarget>) {
        for (target in targets) {
            try {
                val pid = reader.readInitPid(target.cgroupPath) ?: continue
                val stats = reader.readNetworkStats(procRoot, pid)
                for (stat in stats) {
                    val tags = target.tags().and("interface", stat.interfaceName)
                    meters.counter("kpod.net.iface.rx.bytes", tags, stat.rxBytes)
                    meters.counter("kpod.net.iface.tx.bytes", tags, stat.txBytes)
                    meters.counter("kpod.net.iface.rx.packets", tags, stat.rxPackets)
                    meters.counter("kpod.net.iface.tx.packets", tags, stat.txPackets)
                    meters.counter("kpod.net.iface.rx.errors", tags, stat.rxErrors)
                    meters.counter("kpod.net.iface.tx.errors", tags, stat.txErrors)
                    meters.counter("kpod.net.iface.rx.drops", tags, stat.rxDrops)
                    meters.counter("kpod.net.iface.tx.drops", tags, stat.txDrops)
                }
            } catch (e: Exception) {
                log.debug("Failed to read network stats for pod {}/{}: {}", target.namespace, target.podName, e.message)
                errorCounter.increment()
            }
        }
    }

    fun removeStaleEntries(podName: String, namespace: String) = meters.removePod(podName, namespace)
}
