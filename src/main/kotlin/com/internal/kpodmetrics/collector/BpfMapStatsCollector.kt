package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

class BpfMapStatsCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val registry: MeterRegistry
) {
    private val log = LoggerFactory.getLogger(BpfMapStatsCollector::class.java)

    companion object {
        private const val MAP_STAT_ENTRIES = 0
        private const val MAP_STAT_UPDATE_ERRORS = 1
        private const val MAP_STAT_MAX = 2
        private const val MAX_ENTRIES = 10240
        private const val STAT_VALUE_SIZE = 8 // sizeof(__s64)

        private val STATS_MAPS = listOf(
            "cpu_sched" to "ctx_switches_stats",
            "cpu_sched" to "runq_latency_stats",
            "mem" to "oom_kills_stats",
            "mem" to "major_faults_stats",
            "net" to "tcp_stats_map_stats",
            "net" to "rtt_hist_stats",
            "syscall" to "syscall_stats_map_stats"
        )
    }

    fun collect() {
        for ((program, statsMap) in STATS_MAPS) {
            if (!programManager.isProgramLoaded(program)) continue
            try {
                collectMapStats(program, statsMap)
            } catch (e: Exception) {
                log.debug("Failed to collect stats from {}/{}: {}", program, statsMap, e.message)
            }
        }
    }

    private fun collectMapStats(program: String, statsMap: String) {
        val mapFd = programManager.getMapFd(program, statsMap)
        val mapName = statsMap.removeSuffix("_stats")
        val tags = Tags.of("map", mapName)

        for (statIdx in 0 until MAP_STAT_MAX) {
            val key = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(statIdx).array()
            val value = bridge.mapLookupPercpuSum(mapFd, key, STAT_VALUE_SIZE) ?: continue

            when (statIdx) {
                MAP_STAT_ENTRIES ->
                    registry.gauge("kpod.bpf.map.entries", tags, value) { it.toDouble() }
                MAP_STAT_UPDATE_ERRORS ->
                    registry.counter("kpod.bpf.map.update.errors.total", tags).increment(
                        value.toDouble().coerceAtLeast(0.0)
                    )
            }
        }

        registry.gauge("kpod.bpf.map.capacity", tags, MAX_ENTRIES) { it.toDouble() }
    }
}
