package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import io.micrometer.core.instrument.DistributionSummary
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

class CpuSchedulingCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(CpuSchedulingCollector::class.java)

    companion object {
        private const val KEY_SIZE = 8
        private const val HIST_VALUE_SIZE = 232
        private const val COUNTER_VALUE_SIZE = 8
        private const val MAX_SLOTS = 27
        private const val MAX_ENTRIES = 10240
    }

    fun collect() {
        if (config.cpu.scheduling.enabled) {
            collectRunqueueLatency()
        }
        if (config.cpu.throttling.enabled) {
            collectContextSwitches()
        }
    }

    private fun collectRunqueueLatency() {
        val mapFd = programManager.getMapFd("cpu_sched", "runq_latency")
        collectMap(mapFd, KEY_SIZE, HIST_VALUE_SIZE) { keyBytes, valueBytes ->
            val cgroupId = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN).long
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@collectMap

            val buf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            val slots = LongArray(MAX_SLOTS) { buf.long }
            val count = buf.long
            val sumNs = buf.long

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )

            DistributionSummary.builder("kpod.cpu.runqueue.latency")
                .tags(tags)
                .baseUnit("seconds")
                .register(registry)
                .record(sumNs.toDouble() / 1_000_000_000.0)
        }
    }

    private fun collectContextSwitches() {
        val mapFd = programManager.getMapFd("cpu_sched", "ctx_switches")
        collectMap(mapFd, KEY_SIZE, COUNTER_VALUE_SIZE) { keyBytes, valueBytes ->
            val cgroupId = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN).long
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@collectMap

            val count = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN).long

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )

            registry.counter("kpod.cpu.context.switches", tags).increment(count.toDouble())
        }
    }

    private fun collectMap(
        mapFd: Int, keySize: Int, valueSize: Int,
        handler: (ByteArray, ByteArray) -> Unit
    ) {
        val entries = bridge.mapBatchLookupAndDelete(mapFd, keySize, valueSize, MAX_ENTRIES)
        entries.forEach { (key, value) -> handler(key, value) }
    }
}
