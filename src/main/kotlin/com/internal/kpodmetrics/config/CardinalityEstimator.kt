package com.internal.kpodmetrics.config

import org.slf4j.LoggerFactory

class CardinalityEstimator(
    private val config: ResolvedConfig,
    private val warnThreshold: Long = 100_000
) {
    private val log = LoggerFactory.getLogger(CardinalityEstimator::class.java)

    data class Estimate(
        val totalSeries: Long,
        val breakdown: Map<String, Long>
    )

    fun estimateAndLog(estimatedPods: Int = 100) {
        val estimate = estimate(estimatedPods)
        log.info(
            "Cardinality estimate for {} pods: ~{} metric series (breakdown: {})",
            estimatedPods, estimate.totalSeries, estimate.breakdown
        )
        if (estimate.totalSeries > warnThreshold) {
            log.warn(
                "Estimated cardinality ({}) exceeds warning threshold ({}). " +
                    "Consider using 'minimal' or 'standard' profile, or disabling collectors via kpod.collectors.*",
                estimate.totalSeries, warnThreshold
            )
        }
    }

    fun estimate(podCount: Int): Estimate {
        val breakdown = mutableMapOf<String, Long>()

        // CPU: runqueue_latency histogram (buckets * pods) + context_switches counter
        if (config.cpu.scheduling.enabled) {
            val buckets = config.cpu.scheduling.histogramBuckets.size + 3L // +sum, +count, +inf
            breakdown["cpu"] = (buckets + 1) * podCount
        }

        // Network: TCP counters (retransmits, connections, bytes, drops) + RTT histogram
        if (config.network.tcp.enabled) {
            val rttBuckets = config.network.tcp.rttHistogramBuckets.size + 3L
            breakdown["network"] = (4 + rttBuckets) * podCount
        }

        // Syscall: count + errors + latency histogram per syscall per pod
        if (config.syscall.enabled) {
            val syscallCount = config.syscall.trackedSyscalls.size.toLong().coerceAtLeast(1)
            val latBuckets = config.syscall.latencyHistogramBuckets.size + 3L
            breakdown["syscall"] = (2 + latBuckets) * syscallCount * podCount
        }

        // Extended BCC tools: ~2-4 series per pod each
        val ext = config.extended
        if (ext.biolatency) breakdown["biolatency"] = 2L * podCount
        if (ext.cachestat) breakdown["cachestat"] = 4L * podCount
        if (ext.tcpdrop) breakdown["tcpdrop"] = 2L * podCount
        if (ext.hardirqs) breakdown["hardirqs"] = 2L * podCount
        if (ext.softirqs) breakdown["softirqs"] = 2L * podCount
        if (ext.execsnoop) breakdown["execsnoop"] = 3L * podCount

        // Cgroup collectors: per-device/interface/mount multipliers
        val cg = config.cgroup
        if (cg.diskIO) breakdown["diskIO"] = 4L * podCount * 2 // 2 devices avg
        if (cg.interfaceNetwork) breakdown["ifaceNet"] = 8L * podCount * 2 // 2 interfaces avg
        if (cg.filesystem) breakdown["filesystem"] = 3L * podCount * 2 // 2 mounts avg

        // Self-monitoring: fixed ~20 series
        breakdown["selfMonitoring"] = 20L

        return Estimate(
            totalSeries = breakdown.values.sum(),
            breakdown = breakdown
        )
    }
}
