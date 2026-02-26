package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.generated.BiolatencyMapReader
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.DistributionSummary
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory

class BiolatencyCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(BiolatencyCollector::class.java)

    companion object {
        private const val MAX_ENTRIES = 10240
    }

    fun collect() {
        if (!config.extended.biolatency) return
        collectLatency()
        collectCount()
    }

    private fun collectLatency() {
        val mapFd = programManager.getMapFd("biolatency", "bio_latency")
        val entries = bridge.mapBatchLookupAndDelete(
            mapFd, BiolatencyMapReader.HistKeyLayout.SIZE,
            BiolatencyMapReader.HistValueLayout.SIZE, MAX_ENTRIES
        )
        entries.forEach { (keyBytes, valueBytes) ->
            val cgroupId = BiolatencyMapReader.HistKeyLayout.decodeCgroupId(keyBytes)
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@forEach

            val count = BiolatencyMapReader.HistValueLayout.decodeCount(valueBytes)
            val sumNs = BiolatencyMapReader.HistValueLayout.decodeSumNs(valueBytes)

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )

            if (count > 0) {
                DistributionSummary.builder("kpod.disk.io.latency")
                    .tags(tags)
                    .baseUnit("seconds")
                    .register(registry)
                    .record(sumNs.toDouble() / 1_000_000_000.0)
            }
        }
    }

    private fun collectCount() {
        val mapFd = programManager.getMapFd("biolatency", "bio_count")
        val entries = bridge.mapBatchLookupAndDelete(
            mapFd, BiolatencyMapReader.CgroupKeyLayout.SIZE,
            BiolatencyMapReader.CounterLayout.SIZE, MAX_ENTRIES
        )
        entries.forEach { (keyBytes, valueBytes) ->
            val cgroupId = BiolatencyMapReader.CgroupKeyLayout.decodeCgroupId(keyBytes)
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@forEach

            val count = BiolatencyMapReader.CounterLayout.decodeCount(valueBytes)

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )

            registry.counter("kpod.disk.io.requests", tags).increment(count.toDouble())
        }
    }
}
