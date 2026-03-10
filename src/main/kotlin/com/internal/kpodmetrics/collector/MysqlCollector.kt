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

class MysqlCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(MysqlCollector::class.java)

    companion object {
        private const val MAX_ENTRIES = 10240

        // mysql_event_key: u64(cgroup_id) + u8(command) + u8(stmt_type) + u8(direction) + u8(pad1) + u32(pad2) = 16
        private const val EVENT_KEY_SIZE = 16
        // counter_value: u64(count) = 8
        private const val EVENT_VALUE_SIZE = 8
        // mysql_latency_key: u64(cgroup_id) + u8(command) + u8(stmt_type) + u8(direction) + u8(pad1) + u32(pad2) = 16
        private const val LATENCY_KEY_SIZE = 16
        // hist_value: u64[27](slots) + u64(count) + u64(sum_ns) = 232
        private const val HIST_VALUE_SIZE = 232
        // mysql_err_key: u64(cgroup_id) + u16(err_code) + u16(pad1) + u32(pad2) = 16
        private const val ERROR_KEY_SIZE = 16
        // counter_value: u64(count) = 8
        private const val ERROR_VALUE_SIZE = 8

        private val COMMAND_NAMES = mapOf(
            0x03 to "COM_QUERY",
            0x16 to "COM_STMT_PREPARE",
            0x17 to "COM_STMT_EXECUTE",
            0x0e to "COM_PING",
            0x01 to "COM_QUIT",
            0x02 to "COM_INIT_DB"
        )

        private val STMT_TYPE_NAMES = arrayOf(
            "UNKNOWN", "SELECT", "INSERT", "UPDATE", "DELETE", "BEGIN", "COMMIT", "OTHER"
        )

        fun commandName(command: Int): String =
            COMMAND_NAMES[command] ?: "UNKNOWN(0x${command.toString(16)})"

        fun stmtTypeName(stmtType: Int): String =
            if (stmtType in STMT_TYPE_NAMES.indices) STMT_TYPE_NAMES[stmtType] else "UNKNOWN"

        fun directionLabel(direction: Int): String = when (direction) {
            0 -> "client"
            1 -> "server"
            else -> "unknown"
        }
    }

    fun collect() {
        if (!config.extended.mysql) return
        if (!programManager.isProgramLoaded("mysql")) return
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
        val mapFd = programManager.getMapFd("mysql", "mysql_events")
        val entries = mapIterateAndDelete(mapFd, EVENT_KEY_SIZE, EVENT_VALUE_SIZE)
        if (entries.isNotEmpty()) {
            log.info("MySQL events map has {} entries", entries.size)
        }
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long                        // offset 0: u64
            val command = buf.get().toInt() and 0xFF       // offset 8: u8
            val stmtType = buf.get().toInt() and 0xFF      // offset 9: u8
            val direction = buf.get().toInt() and 0xFF     // offset 10: u8
            // offset 11: u8 pad1, offset 12: u32 pad2 (skip)

            val podInfo = cgroupResolver.resolve(cgroupId)
            if (podInfo == null) {
                // Debug: emit metric even without pod resolution to verify BPF capture
                val valBuf2 = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
                val cnt = valBuf2.long
                log.info("MySQL event: cgroup={} cmd={} stmt={} dir={} count={}",
                    cgroupId, commandName(command), stmtTypeName(stmtType),
                    directionLabel(direction), cnt)
                val tags = Tags.of(
                    "namespace", "_unresolved",
                    "pod", "_unresolved",
                    "container", "_unresolved",
                    "node", nodeName,
                    "command", commandName(command),
                    "stmt_type", stmtTypeName(stmtType),
                    "direction", directionLabel(direction)
                )
                registry.counter("kpod.mysql.requests", tags).increment(cnt.toDouble())
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
                "stmt_type", stmtTypeName(stmtType),
                "direction", directionLabel(direction)
            )
            registry.counter("kpod.mysql.requests", tags).increment(count.toDouble())
        }
    }

    private fun collectLatency() {
        val mapFd = programManager.getMapFd("mysql", "mysql_latency")
        val entries = mapIterateAndDelete(mapFd, LATENCY_KEY_SIZE, HIST_VALUE_SIZE)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long                        // offset 0: u64
            val command = buf.get().toInt() and 0xFF       // offset 8: u8
            val stmtType = buf.get().toInt() and 0xFF      // offset 9: u8
            val direction = buf.get().toInt() and 0xFF     // offset 10: u8
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
                "command", commandName(command),
                "stmt_type", stmtTypeName(stmtType),
                "direction", directionLabel(direction)
            )
            val avgLatencySeconds = (sumNs.toDouble() / count.toDouble()) / 1_000_000_000.0
            DistributionSummary.builder("kpod.mysql.request.duration")
                .tags(tags)
                .baseUnit("seconds")
                .register(registry)
                .record(avgLatencySeconds)
        }
    }

    private fun collectErrors() {
        val mapFd = programManager.getMapFd("mysql", "mysql_errors")
        val entries = mapIterateAndDelete(mapFd, ERROR_KEY_SIZE, ERROR_VALUE_SIZE)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long                        // offset 0: u64
            val errCode = buf.short.toInt() and 0xFFFF     // offset 8: u16
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
            registry.counter("kpod.mysql.errors", tags).increment(count.toDouble())
        }
    }
}
