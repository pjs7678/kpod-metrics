package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.generated.SoftirqsMapReader
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.DistributionSummary
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory

class SoftirqsCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(SoftirqsCollector::class.java)

    companion object {
        private const val MAX_ENTRIES = 10240
    }

    fun collect() {
        if (!config.extended.softirqs) return

        val mapFd = programManager.getMapFd("softirqs", "softirq_latency")
        val entries = bridge.mapBatchLookupAndDelete(
            mapFd, SoftirqsMapReader.HistKeyLayout.SIZE,
            SoftirqsMapReader.HistValueLayout.SIZE, MAX_ENTRIES
        )
        entries.forEach { (keyBytes, valueBytes) ->
            val cgroupId = SoftirqsMapReader.HistKeyLayout.decodeCgroupId(keyBytes)
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@forEach

            val count = SoftirqsMapReader.HistValueLayout.decodeCount(valueBytes)
            val sumNs = SoftirqsMapReader.HistValueLayout.decodeSumNs(valueBytes)

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )

            if (count > 0) {
                DistributionSummary.builder("kpod.irq.sw.latency")
                    .tags(tags)
                    .baseUnit("seconds")
                    .register(registry)
                    .record(sumNs.toDouble() / 1_000_000_000.0)
            }
        }
    }
}
