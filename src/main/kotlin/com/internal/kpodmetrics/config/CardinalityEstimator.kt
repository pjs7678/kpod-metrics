package com.internal.kpodmetrics.config

import com.internal.kpodmetrics.collector.Log2Histograms
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

        // Histograms from kernel log2 buckets: le buckets (incl. +Inf) + _sum + _count
        fun histSeries(spec: Log2Histograms.Spec) = spec.upperBounds.size + 2L

        // CPU: runqueue_latency histogram + context_switches counter
        if (config.cpu.scheduling.enabled) {
            breakdown["cpu"] = (histSeries(Log2Histograms.RUNQUEUE) + 1) * podCount
        }

        // Network: TCP counters (retransmits, connections) + RTT histogram
        if (config.network.tcp.enabled) {
            breakdown["network"] = (2 + histSeries(Log2Histograms.TCP_RTT)) * podCount
        }

        // Syscall: count + errors + latency histogram per syscall per pod
        if (config.syscall.enabled) {
            val syscallCount = config.syscall.trackedSyscalls.size.toLong().coerceAtLeast(1)
            breakdown["syscall"] = (2 + histSeries(Log2Histograms.SYSCALL)) * syscallCount * podCount
        }

        // Extended BCC tools: ~2-4 series per pod each
        val ext = config.extended
        if (ext.biolatency) breakdown["biolatency"] = histSeries(Log2Histograms.DISK_IO) * podCount
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
        if (cg.memory) breakdown["memory"] = 6L * podCount
        if (cg.cpu) breakdown["cpuCgroup"] = 5L * podCount
        if (cg.pressure) breakdown["pressure"] = 6L * podCount // cpu/memory/io x some/full
        if (cg.appType) breakdown["appType"] = 1L * podCount

        // Self-monitoring: fixed ~20 series
        breakdown["selfMonitoring"] = 20L

        return Estimate(
            totalSeries = breakdown.values.sum(),
            breakdown = breakdown
        )
    }
}
