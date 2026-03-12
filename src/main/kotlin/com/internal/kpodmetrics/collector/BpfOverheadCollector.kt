package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory
import java.util.concurrent.ConcurrentHashMap

/**
 * Collects BPF program overhead metrics:
 * - kpod.bpf.program.run.time.ns{program} — cumulative in-kernel CPU time (counter)
 * - kpod.bpf.program.run.count{program} — invocation count (counter)
 *
 * Requires kernel 5.1+ with /proc/sys/kernel/bpf_stats_enabled=1.
 * On older kernels, values will be 0 (harmless).
 */
class BpfOverheadCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val registry: MeterRegistry
) {
    private val log = LoggerFactory.getLogger(BpfOverheadCollector::class.java)

    // Track previous values to emit monotonic deltas as counters
    private val prevRunTime = ConcurrentHashMap<String, Long>()
    private val prevRunCnt = ConcurrentHashMap<String, Long>()

    fun collect() {
        for (name in programManager.getLoadedProgramNames()) {
            try {
                collectProgram(name)
            } catch (e: Exception) {
                log.debug("Failed to get stats for BPF program {}: {}", name, e.message)
            }
        }
    }

    private fun collectProgram(name: String) {
        val handle = programManager.getHandle(name) ?: return
        val stats = bridge.getProgStats(handle) ?: return
        val runTimeNs = stats[0]
        val runCnt = stats[1]

        val tags = Tags.of("program", name)

        // Emit as counters (monotonically increasing)
        val prevTime = prevRunTime.put(name, runTimeNs) ?: 0L
        val prevCnt = prevRunCnt.put(name, runCnt) ?: 0L

        val timeDelta = (runTimeNs - prevTime).coerceAtLeast(0)
        val cntDelta = (runCnt - prevCnt).coerceAtLeast(0)

        if (timeDelta > 0) {
            registry.counter("kpod.bpf.program.run.time.ns", tags).increment(timeDelta.toDouble())
        }
        if (cntDelta > 0) {
            registry.counter("kpod.bpf.program.run.count", tags).increment(cntDelta.toDouble())
        }
    }
}
