package com.internal.kpodmetrics.bpf.programs

import com.internal.kpodmetrics.collector.Log2Histograms
import dev.ebpf.dsl.api.generateC
import dev.ebpf.dsl.api.validate
import dev.ebpf.dsl.tools.biolatency
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The BPF side buckets on ns >> HIST_SLOT_SHIFT and Log2Histograms derives `le` edges from
 * SLOT_SHIFT. If they diverge, every exported quantile is off by a power of two — silently.
 */
class HistogramSlotShiftTest {

    @Test
    fun `exporter and BPF generator agree on the slot shift`() {
        assertEquals(HIST_SLOT_SHIFT, Log2Histograms.SLOT_SHIFT)
    }

    @Test
    fun `every exported latency histogram buckets shifted nanoseconds`() {
        val programs = mapOf(
            "cpu_sched" to cpuSchedProgram,
            "net" to netProgram,
            "syscall" to syscallProgram,
            "biolatency" to biolatency(slotShift = HIST_SLOT_SHIFT),
        )
        for ((name, prog) in programs) {
            assertTrue(prog.validate().errors.isEmpty(), "$name validates")
            val slotLines = prog.generateC().lines()
                .filter { Regex("""__u32 slot2? = log2l\(""").containsMatchIn(it) }
            assertTrue(slotLines.isNotEmpty(), "$name has histogram slot computations")
            for (line in slotLines) {
                assertTrue(line.contains(">> ${HIST_SLOT_SHIFT}U"), "$name buckets unshifted ns: ${line.trim()}")
            }
        }
    }
}
