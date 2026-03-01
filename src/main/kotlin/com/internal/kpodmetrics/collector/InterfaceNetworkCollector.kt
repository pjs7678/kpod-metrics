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

    fun collect(targets: List<PodCgroupTarget>) {
        for (target in targets) {
            try {
                val pid = reader.readInitPid(target.cgroupPath) ?: continue
                val stats = reader.readNetworkStats(procRoot, pid)
                for (stat in stats) {
                    val tags = Tags.of(
                        "namespace", target.namespace,
                        "pod", target.podName,
                        "container", target.containerName,
                        "node", target.nodeName,
                        "interface", stat.interfaceName
                    )
                    registry.counter("kpod.net.iface.rx.bytes", tags).increment(stat.rxBytes.toDouble())
                    registry.counter("kpod.net.iface.tx.bytes", tags).increment(stat.txBytes.toDouble())
                    registry.counter("kpod.net.iface.rx.packets", tags).increment(stat.rxPackets.toDouble())
                    registry.counter("kpod.net.iface.tx.packets", tags).increment(stat.txPackets.toDouble())
                    registry.counter("kpod.net.iface.rx.errors", tags).increment(stat.rxErrors.toDouble())
                    registry.counter("kpod.net.iface.tx.errors", tags).increment(stat.txErrors.toDouble())
                    registry.counter("kpod.net.iface.rx.drops", tags).increment(stat.rxDrops.toDouble())
                    registry.counter("kpod.net.iface.tx.drops", tags).increment(stat.txDrops.toDouble())
                }
            } catch (e: Exception) {
                log.debug("Failed to read network stats for pod {}/{}: {}", target.namespace, target.podName, e.message)
                errorCounter.increment()
            }
        }
    }
}
