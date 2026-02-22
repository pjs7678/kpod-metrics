package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

class MemoryCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(MemoryCollector::class.java)

    companion object {
        private const val KEY_SIZE = 8
        private const val COUNTER_VALUE_SIZE = 8
    }

    fun collect() {
        if (config.memory.oom) {
            collectOomKills()
        }
        if (config.memory.pageFaults) {
            collectMajorFaults()
        }
    }

    private fun collectOomKills() {
        val mapFd = programManager.getMapFd("mem", "oom_kills")
        iterateMap(mapFd, KEY_SIZE, COUNTER_VALUE_SIZE) { keyBytes, valueBytes ->
            val cgroupId = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN).long
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@iterateMap

            val count = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN).long

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )

            registry.counter("kpod.mem.oom.kills", tags).increment(count.toDouble())
        }
    }

    private fun collectMajorFaults() {
        val mapFd = programManager.getMapFd("mem", "major_faults")
        iterateMap(mapFd, KEY_SIZE, COUNTER_VALUE_SIZE) { keyBytes, valueBytes ->
            val cgroupId = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN).long
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@iterateMap

            val count = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN).long

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )

            registry.counter("kpod.mem.major.page.faults", tags).increment(count.toDouble())
        }
    }

    private fun iterateMap(
        mapFd: Int, keySize: Int, valueSize: Int,
        handler: (ByteArray, ByteArray) -> Unit
    ) {
        var key: ByteArray? = null
        while (true) {
            val nextKey = bridge.mapGetNextKey(mapFd, key, keySize) ?: break
            val value = bridge.mapLookup(mapFd, nextKey, valueSize)
            if (value != null) {
                handler(nextKey, value)
            }
            key = nextKey
        }
    }
}
