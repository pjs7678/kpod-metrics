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

class KafkaCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(KafkaCollector::class.java)

    companion object {
        private const val MAX_ENTRIES = 10240

        // kafka_event_key: u64(cgroupId) + u16(apiKey) + u8(direction) + u8(pad1) + u32(pad2) = 16
        private const val EVENT_KEY_SIZE = 16
        // counter_value: u64(count) = 8
        private const val EVENT_VALUE_SIZE = 8
        // kafka_latency_key: u64(cgroupId) + u16(apiKey) + u8(direction) + u8(pad1) + u32(pad2) = 16
        private const val LATENCY_KEY_SIZE = 16
        // hist_value: u64[27](slots) + u64(count) + u64(sum_ns) = 232
        private const val HIST_VALUE_SIZE = 232
        // kafka_err_key: u64(cgroupId) + u16(errCode) + u16(pad1) + u32(pad2) = 16
        private const val ERROR_KEY_SIZE = 16
        // counter_value: u64(count) = 8
        private const val ERROR_VALUE_SIZE = 8

        // Native Kafka API key values from the wire protocol
        private val API_KEY_NAMES = mapOf(
            0 to "Produce",
            1 to "Fetch",
            2 to "ListOffsets",
            3 to "Metadata",
            8 to "OffsetCommit",
            9 to "OffsetFetch",
            10 to "FindCoordinator",
            11 to "JoinGroup",
            12 to "Heartbeat",
            13 to "LeaveGroup",
            14 to "SyncGroup",
            18 to "ApiVersions",
            19 to "CreateTopics",
            20 to "DeleteTopics",
            0xFFFF to "Other"
        )

        fun apiKeyName(apiKey: Int): String =
            API_KEY_NAMES[apiKey] ?: "Unknown($apiKey)"

        fun directionLabel(direction: Int): String = when (direction) {
            0 -> "client"
            1 -> "server"
            else -> "unknown"
        }
    }

    fun collect() {
        if (!config.extended.kafka) return
        if (!programManager.isProgramLoaded("kafka")) return
        collectEvents()
        collectLatency()
        collectErrors()
    }

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
        val mapFd = programManager.getMapFd("kafka", "kafka_events")
        val entries = mapIterateAndDelete(mapFd, EVENT_KEY_SIZE, EVENT_VALUE_SIZE)
        if (entries.isNotEmpty()) {
            log.info("Kafka events map has {} entries", entries.size)
        }
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long                              // offset 0: u64
            val apiKey = buf.short.toInt() and 0xFFFF            // offset 8: u16
            val direction = buf.get().toInt() and 0xFF           // offset 10: u8
            // offset 11: u8 pad1, offset 12: u32 pad2 (skip)

            val podInfo = cgroupResolver.resolve(cgroupId)
            if (podInfo == null) {
                val valBuf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
                val cnt = valBuf.long
                log.info("Kafka event: cgroup={} api_key={} dir={} count={}",
                    cgroupId, apiKeyName(apiKey), directionLabel(direction), cnt)
                val tags = Tags.of(
                    "namespace", "_unresolved",
                    "pod", "_unresolved",
                    "container", "_unresolved",
                    "node", nodeName,
                    "api_key", apiKeyName(apiKey),
                    "direction", directionLabel(direction)
                )
                registry.counter("kpod.kafka.requests", tags).increment(cnt.toDouble())
                continue
            }

            val valBuf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            val count = valBuf.long

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "api_key", apiKeyName(apiKey),
                "direction", directionLabel(direction)
            )
            registry.counter("kpod.kafka.requests", tags).increment(count.toDouble())
        }
    }

    private fun collectLatency() {
        val mapFd = programManager.getMapFd("kafka", "kafka_latency")
        val entries = mapIterateAndDelete(mapFd, LATENCY_KEY_SIZE, HIST_VALUE_SIZE)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long                              // offset 0: u64
            val apiKey = buf.short.toInt() and 0xFFFF            // offset 8: u16
            val direction = buf.get().toInt() and 0xFF           // offset 10: u8
            // offset 11: u8 pad1, offset 12: u32 pad2 (skip)

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
                "api_key", apiKeyName(apiKey),
                "direction", directionLabel(direction)
            )
            val avgLatencySeconds = (sumNs.toDouble() / count.toDouble()) / 1_000_000_000.0
            DistributionSummary.builder("kpod.kafka.request.duration")
                .tags(tags)
                .baseUnit("seconds")
                .register(registry)
                .record(avgLatencySeconds)
        }
    }

    private fun collectErrors() {
        val mapFd = programManager.getMapFd("kafka", "kafka_errors")
        val entries = mapIterateAndDelete(mapFd, ERROR_KEY_SIZE, ERROR_VALUE_SIZE)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long                              // offset 0: u64
            val errCode = buf.short.toInt() and 0xFFFF           // offset 8: u16
            // offset 10: u16 pad1, offset 12: u32 pad2 (skip)

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue

            val valBuf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            val count = valBuf.long

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "error_code", errCode.toString()
            )
            registry.counter("kpod.kafka.errors", tags).increment(count.toDouble())
        }
    }
}
