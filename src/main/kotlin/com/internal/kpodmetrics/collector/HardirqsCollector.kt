package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.generated.HardirqsMapReader
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.DistributionSummary
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory

class HardirqsCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(HardirqsCollector::class.java)

    companion object {
        private const val MAX_ENTRIES = 10240
    }

    fun collect() {
        if (!config.extended.hardirqs) return
        collectLatency()
        collectCount()
    }

    private fun collectLatency() {
        val mapFd = programManager.getMapFd("hardirqs", "irq_latency")
        val entries = bridge.mapBatchLookupAndDelete(
            mapFd, HardirqsMapReader.HistKeyLayout.SIZE,
            HardirqsMapReader.HistValueLayout.SIZE, MAX_ENTRIES
        )
        entries.forEach { (keyBytes, valueBytes) ->
            val cgroupId = HardirqsMapReader.HistKeyLayout.decodeCgroupId(keyBytes)
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@forEach

            val count = HardirqsMapReader.HistValueLayout.decodeCount(valueBytes)
            val sumNs = HardirqsMapReader.HistValueLayout.decodeSumNs(valueBytes)

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )

            if (count > 0) {
                DistributionSummary.builder("kpod.irq.hw.latency")
                    .tags(tags)
                    .baseUnit("seconds")
                    .register(registry)
                    .record(sumNs.toDouble() / 1_000_000_000.0)
            }
        }
    }

    private fun collectCount() {
        val mapFd = programManager.getMapFd("hardirqs", "irq_count")
        val entries = bridge.mapBatchLookupAndDelete(
            mapFd, HardirqsMapReader.CgroupKeyLayout.SIZE,
            HardirqsMapReader.CounterLayout.SIZE, MAX_ENTRIES
        )
        entries.forEach { (keyBytes, valueBytes) ->
            val cgroupId = HardirqsMapReader.CgroupKeyLayout.decodeCgroupId(keyBytes)
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@forEach

            val count = HardirqsMapReader.CounterLayout.decodeCount(valueBytes)

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )

            registry.counter("kpod.irq.hw.count", tags).increment(count.toDouble())
        }
    }
}
