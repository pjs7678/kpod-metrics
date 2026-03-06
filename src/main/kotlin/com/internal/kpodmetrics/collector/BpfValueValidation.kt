package com.internal.kpodmetrics.collector

import org.slf4j.Logger

/**
 * Validates BPF latency values crossing the kernel/user boundary.
 * Detects corrupted data from torn reads or atomic race conditions in BPF maps.
 */
object BpfValueValidation {
    // 60 seconds in nanoseconds — any average latency above this is likely corrupted
    private const val MAX_REASONABLE_AVG_NS = 60_000_000_000L

    /**
     * Returns true if the latency value pair is valid.
     * Checks: non-negative, average within reasonable bounds.
     */
    fun isValidLatency(count: Long, sumNs: Long, log: Logger, collector: String): Boolean {
        if (count < 0 || sumNs < 0) {
            log.debug("{}: skipping negative BPF value (count={}, sumNs={})", collector, count, sumNs)
            return false
        }
        if (count > 0 && sumNs / count > MAX_REASONABLE_AVG_NS) {
            log.debug("{}: skipping unreasonable avg latency (count={}, sumNs={}, avg={}ns)",
                collector, count, sumNs, sumNs / count)
            return false
        }
        return true
    }

    /**
     * Returns true if the counter value is valid (non-negative).
     */
    fun isValidCounter(value: Long, log: Logger, collector: String): Boolean {
        if (value < 0) {
            log.debug("{}: skipping negative counter value ({})", collector, value)
            return false
        }
        return true
    }
}
