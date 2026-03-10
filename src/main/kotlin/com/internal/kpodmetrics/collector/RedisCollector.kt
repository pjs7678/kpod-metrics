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

class RedisCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(RedisCollector::class.java)

    companion object {
        private const val MAX_ENTRIES = 10240

        // redis_event_key: u64(cgroup_id) + u8(command) + u8(direction) + u16(pad1) + u32(pad2) = 16
        private const val EVENT_KEY_SIZE = 16
        // counter_value: u64(count) = 8
        private const val EVENT_VALUE_SIZE = 8
        // redis_latency_key: u64(cgroup_id) + u8(command) + u8(direction) + u16(pad1) + u32(pad2) = 16
        private const val LATENCY_KEY_SIZE = 16
        // hist_value: u64[27](slots) + u64(count) + u64(sum_ns) = 232
        private const val HIST_VALUE_SIZE = 232
        // redis_err_key: u64(cgroup_id) + u8(err_type) + u8[7](pad) = 16
        private const val ERROR_KEY_SIZE = 16
        // counter_value: u64(count) = 8
        private const val ERROR_VALUE_SIZE = 8

        private val COMMAND_NAMES = arrayOf(
            "UNKNOWN", "GET", "SET", "DEL", "HGET", "HSET",
            "LPUSH", "RPUSH", "SADD", "ZADD", "EXPIRE", "INCR", "OTHER"
        )

        private val ERROR_NAMES = arrayOf(
            "UNKNOWN", "ERR", "WRONGTYPE", "MOVED", "OTHER"
        )

        fun commandName(command: Int): String =
            if (command in COMMAND_NAMES.indices) COMMAND_NAMES[command] else "UNKNOWN"

        fun errorName(errType: Int): String =
            if (errType in ERROR_NAMES.indices) ERROR_NAMES[errType] else "UNKNOWN"

        fun directionLabel(direction: Int): String = when (direction) {
            0 -> "client"
            1 -> "server"
            else -> "unknown"
        }
    }

    fun collect() {
        if (!config.extended.redis) return
        if (!programManager.isProgramLoaded("redis")) return
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
        val mapFd = programManager.getMapFd("redis", "redis_events")
        val entries = mapIterateAndDelete(mapFd, EVENT_KEY_SIZE, EVENT_VALUE_SIZE)
        if (entries.isNotEmpty()) {
            log.info("Redis events map has {} entries", entries.size)
        }
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long                        // offset 0: u64
            val command = buf.get().toInt() and 0xFF       // offset 8: u8
            val direction = buf.get().toInt() and 0xFF     // offset 9: u8
            // offset 10: u16 pad1, offset 12: u32 pad2 (skip)

            val podInfo = cgroupResolver.resolve(cgroupId)
            if (podInfo == null) {
                val valBuf2 = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
                val cnt = valBuf2.long
                log.info("Redis event: cgroup={} cmd={} dir={} count={}",
                    cgroupId, commandName(command), directionLabel(direction), cnt)
                val tags = Tags.of(
                    "namespace", "_unresolved",
                    "pod", "_unresolved",
                    "container", "_unresolved",
                    "node", nodeName,
                    "command", commandName(command),
                    "direction", directionLabel(direction)
                )
                registry.counter("kpod.redis.requests", tags).increment(cnt.toDouble())
                continue
            }

            val valBuf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            val count = valBuf.long

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "command", commandName(command),
                "direction", directionLabel(direction)
            )
            registry.counter("kpod.redis.requests", tags).increment(count.toDouble())
        }
    }

    private fun collectLatency() {
        val mapFd = programManager.getMapFd("redis", "redis_latency")
        val entries = mapIterateAndDelete(mapFd, LATENCY_KEY_SIZE, HIST_VALUE_SIZE)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long                        // offset 0: u64
            val command = buf.get().toInt() and 0xFF       // offset 8: u8
            val direction = buf.get().toInt() and 0xFF     // offset 9: u8
            // offset 10: u16 pad1, offset 12: u32 pad2 (skip)

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
                "command", commandName(command),
                "direction", directionLabel(direction)
            )
            val avgLatencySeconds = (sumNs.toDouble() / count.toDouble()) / 1_000_000_000.0
            DistributionSummary.builder("kpod.redis.request.duration")
                .tags(tags)
                .baseUnit("seconds")
                .register(registry)
                .record(avgLatencySeconds)
        }
    }

    private fun collectErrors() {
        val mapFd = programManager.getMapFd("redis", "redis_errors")
        val entries = mapIterateAndDelete(mapFd, ERROR_KEY_SIZE, ERROR_VALUE_SIZE)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long                        // offset 0: u64
            val errType = buf.get().toInt() and 0xFF       // offset 8: u8
            // offset 9: 7 bytes pad (skip)

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue

            val valBuf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            val count = valBuf.long

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "error_type", errorName(errType)
            )
            registry.counter("kpod.redis.errors", tags).increment(count.toDouble())
        }
    }
}
