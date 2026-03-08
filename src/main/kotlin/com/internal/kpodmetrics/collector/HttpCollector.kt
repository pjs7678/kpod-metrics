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
        private const val MAX_PATH_ENTRIES = 1024

        // Struct sizes matching http.bpf.c
        // http_event_key: u64 + u32 + u16 + u8 + u8 + u16 + u16 + u32 = 24
        private const val EVENT_KEY_SIZE = 24
        // http_event_val: u64 * 4 = 32
        private const val EVENT_VALUE_SIZE = 32
        // http_latency_key: u64 + u8 + u8[7] = 16
        private const val LATENCY_KEY_SIZE = 16
        // hist_value: u64[27] + u64 + u64 = 232
        private const val HIST_VALUE_SIZE = 232
        // http_path_key: u64 + u8 + u8[3] + u8[64] = 76
        private const val PATH_KEY_SIZE = 76
        // counter_value: u64 = 8
        private const val COUNTER_VALUE_SIZE = 8

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
        collectTopPaths()
    }

    private fun collectEvents() {
        val mapFd = programManager.getMapFd("http", "http_events")
        val entries = bridge.mapBatchLookupAndDelete(mapFd, EVENT_KEY_SIZE, EVENT_VALUE_SIZE, MAX_ENTRIES)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long
            val remoteIp4 = buf.int
            val remotePort = buf.short.toInt() and 0xFFFF
            val method = buf.get().toInt() and 0xFF
            val direction = buf.get().toInt() and 0xFF
            val statusCode = buf.short.toInt() and 0xFFFF

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue

            val valBuf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            val count = valBuf.long
            val latencySumNs = valBuf.long

            val remoteIpStr = TcpPeerCollector.ipToString(remoteIp4)
            val peerInfo = podIpResolver.resolve(remoteIpStr)

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "method", methodName(method),
                "status_code", statusCode.toString(),
                "remote_ip", remoteIpStr,
                "remote_port", remotePort.toString(),
                "direction", directionLabel(direction),
                "remote_pod", peerInfo?.podName ?: "",
                "remote_service", peerInfo?.serviceName ?: ""
            )
            registry.counter("kpod.http.requests", tags).increment(count.toDouble())
        }
    }

    private fun collectLatency() {
        val mapFd = programManager.getMapFd("http", "http_latency")
        val entries = bridge.mapBatchLookupAndDelete(mapFd, LATENCY_KEY_SIZE, HIST_VALUE_SIZE, MAX_ENTRIES)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long
            val method = buf.get().toInt() and 0xFF

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
                "method", methodName(method)
            )
            val avgLatencySeconds = (sumNs.toDouble() / count.toDouble()) / 1_000_000_000.0
            DistributionSummary.builder("kpod.http.request.duration")
                .tags(tags)
                .baseUnit("seconds")
                .register(registry)
                .record(avgLatencySeconds)
        }
    }

    private fun collectTopPaths() {
        val mapFd = programManager.getMapFd("http", "http_top_paths")
        val entries = bridge.mapBatchLookupAndDelete(mapFd, PATH_KEY_SIZE, COUNTER_VALUE_SIZE, MAX_PATH_ENTRIES)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long
            val method = buf.get().toInt() and 0xFF
            buf.position(buf.position() + 3) // skip _pad[3]
            val pathBytes = ByteArray(64)
            buf.get(pathBytes)

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue
            val nullIdx = pathBytes.indexOf(0.toByte())
            val path = if (nullIdx > 0) {
                String(pathBytes, 0, nullIdx, Charsets.UTF_8)
            } else if (nullIdx == 0) {
                "/"
            } else {
                String(pathBytes, Charsets.UTF_8)
            }
            val count = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN).long

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "method", methodName(method),
                "path", path
            )
            registry.counter("kpod.http.top.paths", tags).increment(count.toDouble())
        }
    }
}
