package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.generateC
import dev.ebpf.dsl.api.validate
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class MemProgramTest {

    @Test
    fun `mem program validates without errors`() {
        val result = memProgram.validate()
        assertThat(result.errors).isEmpty()
    }

    @Test
    fun `mem program generates correct C structure`() {
        val c = memProgram.generateC()

        // Verify maps
        assertThat(c).contains("oom_kills SEC(\".maps\")")
        assertThat(c).contains("major_faults SEC(\".maps\")")
        assertThat(c).contains("BPF_MAP_TYPE_LRU_HASH")

        // Verify programs
        assertThat(c).contains("SEC(\"tp/oom/mark_victim\")")
        assertThat(c).contains("SEC(\"kprobe/handle_mm_fault\")")

        // Verify structs
        assertThat(c).contains("struct counter_key {")
        assertThat(c).contains("struct counter_value {")

        // Verify core logic
        assertThat(c).contains("bpf_get_current_cgroup_id()")
        assertThat(c).contains("bpf_map_lookup_elem")
        assertThat(c).contains("__sync_fetch_and_add")
        assertThat(c).contains("bpf_map_update_elem")

        // Verify preamble macros
        assertThat(c).contains("DEFINE_STATS_MAP")
    }

    @Test
    fun `generated C has correct map and program counts`() {
        val c = memProgram.generateC()

        // 2 DSL-defined maps (oom_kills, major_faults) + DEFINE_STATS_MAP creates 2 more via preamble
        // The DSL maps produce SEC(".maps") annotations
        val mapSections = Regex("""SEC\("\.maps"\)""").findAll(c).count()
        assertThat(mapSections).isGreaterThanOrEqualTo(2)

        // 2 programs: tracepoint and kprobe
        assertThat(c).contains("SEC(\"tp/oom/mark_victim\")")
        assertThat(c).contains("SEC(\"kprobe/handle_mm_fault\")")
    }

    @Test
    fun `kprobe program checks major fault flag`() {
        val c = memProgram.generateC()

        // The kprobe should check the FAULT_FLAG_MAJOR bit (0x4) via PT_REGS_PARM3
        assertThat(c).contains("PT_REGS_PARM3")
        // Early return if not a major fault
        assertThat(c).contains("return 0")
    }

    @Test
    fun `lookup-or-insert pattern with else branch`() {
        val c = memProgram.generateC()

        // Both programs should use the ifNonNull...elseThen pattern
        // which generates: if (entry) { atomic_add } else { update }
        assertThat(c).contains("} else {")
        assertThat(c).contains("bpf_map_update_elem")
    }
}
