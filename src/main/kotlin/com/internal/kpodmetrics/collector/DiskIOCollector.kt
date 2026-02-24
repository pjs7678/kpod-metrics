package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags

class DiskIOCollector(
    private val reader: CgroupReader,
    private val registry: MeterRegistry
) {
    fun collect(targets: List<PodCgroupTarget>) {
        for (target in targets) {
            val stats = reader.readDiskIO(target.cgroupPath)
            for (stat in stats) {
                val device = "${stat.major}:${stat.minor}"
                val tags = Tags.of(
                    "namespace", target.namespace,
                    "pod", target.podName,
                    "container", target.containerName,
                    "node", target.nodeName,
                    "device", device
                )
                registry.counter("kpod.disk.read.bytes", tags).increment(stat.readBytes.toDouble())
                registry.counter("kpod.disk.written.bytes", tags).increment(stat.writeBytes.toDouble())
                registry.counter("kpod.disk.reads", tags).increment(stat.reads.toDouble())
                registry.counter("kpod.disk.writes", tags).increment(stat.writes.toDouble())
            }
        }
    }
}
