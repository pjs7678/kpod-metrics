package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.DistributionSummary
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

class HttpCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String,
    private val podIpResolver: PodIpResolver
) {
    private val log = LoggerFactory.getLogger(HttpCollector::class.java)

    companion object {
        private const val MAX_ENTRIES = 10240

        // Struct sizes matching http.bpf.c
        // http_event_key: u64(cgroup_id) + u8(method) + u8(direction) + u16(status_code) + u32(_pad) = 16
        private const val EVENT_KEY_SIZE = 16
        // http_event_val: u64(count) = 8
        private const val EVENT_VALUE_SIZE = 8
        // http_latency_key: u64(cgroup_id) + u8(method) + u8(direction) + u16(_pad1) + u32(_pad2) = 16
        private const val LATENCY_KEY_SIZE = 16
        // hist_value: u64[27](slots) + u64(count) + u64(sum_ns) = 232
        private const val HIST_VALUE_SIZE = 232

        private val METHOD_NAMES = arrayOf(
            "UNKNOWN", "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"
        )

        fun methodName(method: Int): String =
            if (method in METHOD_NAMES.indices) METHOD_NAMES[method] else "UNKNOWN"

        fun directionLabel(direction: Int): String = when (direction) {
            0 -> "outbound"
            1 -> "inbound"
            else -> "unknown"
        }
    }

    fun collect() {
        if (!config.extended.http) return
        if (!programManager.isProgramLoaded("http")) return
        podIpResolver.refresh()
        collectEvents()
        collectLatency()
    }

    /** Iterate+lookup+delete: workaround for LRU_HASH batch ops returning 0 on some kernels */
    private fun mapIterateAndDelete(mapFd: Int, keySize: Int, valueSize: Int): List<Pair<ByteArray, ByteArray>> {
        val keys = mutableListOf<ByteArray>()
        var prevKey: ByteArray? = null
        while (true) {
            val nextKey = bridge.mapGetNextKey(mapFd, prevKey, keySize) ?: break
            keys.add(nextKey)
            prevKey = nextKey
        }
        val results = mutableListOf<Pair<ByteArray, ByteArray>>()
        for (k in keys) {
            val value = bridge.mapLookup(mapFd, k, valueSize)
            if (value != null) {
                results.add(k to value)
            }
            bridge.mapDelete(mapFd, k)
        }
        return results
    }

    private fun collectEvents() {
        val mapFd = programManager.getMapFd("http", "http_events")
        val entries = mapIterateAndDelete(mapFd, EVENT_KEY_SIZE, EVENT_VALUE_SIZE)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long           // offset 0: u64
            val method = buf.get().toInt() and 0xFF    // offset 8: u8
            val direction = buf.get().toInt() and 0xFF // offset 9: u8
            val statusCode = buf.short.toInt() and 0xFFFF // offset 10: u16
            // offset 12: u32 _pad (skip)

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue

            val valBuf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            val count = valBuf.long            // u64 count

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "method", methodName(method),
                "status_code", statusCode.toString(),
                "direction", directionLabel(direction)
            )
            registry.counter("kpod.http.requests", tags).increment(count.toDouble())
        }
    }

    private fun collectLatency() {
        val mapFd = programManager.getMapFd("http", "http_latency")
        val entries = mapIterateAndDelete(mapFd, LATENCY_KEY_SIZE, HIST_VALUE_SIZE)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long            // offset 0: u64
            val method = buf.get().toInt() and 0xFF    // offset 8: u8
            val direction = buf.get().toInt() and 0xFF // offset 9: u8
            // offset 10: u16 _pad1, offset 12: u32 _pad2 (skip)

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue

            val valBuf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            valBuf.position(27 * 8) // Skip histogram slots
            val count = valBuf.long
            val sumNs = valBuf.long

            if (count <= 0 || sumNs <= 0) continue

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "method", methodName(method),
                "direction", directionLabel(direction)
            )
            val avgLatencySeconds = (sumNs.toDouble() / count.toDouble()) / 1_000_000_000.0
            DistributionSummary.builder("kpod.http.request.duration")
                .tags(tags)
                .baseUnit("seconds")
                .register(registry)
                .record(avgLatencySeconds)
        }
    }
}
