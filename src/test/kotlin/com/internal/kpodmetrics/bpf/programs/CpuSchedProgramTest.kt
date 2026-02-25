package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.generateC
import dev.ebpf.dsl.api.validate
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class CpuSchedProgramTest {

    @Test
    fun `cpu_sched program validates without errors`() {
        val result = cpuSchedProgram.validate()
        assertThat(result.errors).isEmpty()
    }


    @Test
    fun `cpu_sched program generates correct map definitions`() {
        val c = cpuSchedProgram.generateC()

        // wakeup_ts: HASH map with scalar key/value
        assertThat(c).contains("wakeup_ts SEC(\".maps\")")
        assertThat(c).contains("BPF_MAP_TYPE_HASH")

        // runq_latency: LRU_HASH map with struct key/value
        assertThat(c).contains("runq_latency SEC(\".maps\")")
        assertThat(c).contains("BPF_MAP_TYPE_LRU_HASH")

        // ctx_switches: LRU_HASH map with struct key/value
        assertThat(c).contains("ctx_switches SEC(\".maps\")")
    }

    @Test
    fun `wakeup_ts map has scalar key and value types`() {
        val c = cpuSchedProgram.generateC()

        // The wakeup_ts map should use scalar types (__u32 key, __u64 value)
        // Find the wakeup_ts map definition block
        val wakeupBlock = c.substringBefore("wakeup_ts SEC")
            .substringAfterLast("struct {")
        assertThat(wakeupBlock).contains("__type(key, __u32)")
        assertThat(wakeupBlock).contains("__type(value, __u64)")
    }

    @Test
    fun `cpu_sched program generates correct program sections`() {
        val c = cpuSchedProgram.generateC()

        assertThat(c).contains("SEC(\"tp/sched/sched_wakeup\")")
        assertThat(c).contains("SEC(\"tp/sched/sched_switch\")")
    }

    @Test
    fun `sched_wakeup program reads pid and stores timestamp`() {
        val c = cpuSchedProgram.generateC()

        // Should read ctx->pid via raw expression
        assertThat(c).contains("trace_event_raw_sched_wakeup_template")
        // Should call bpf_ktime_get_ns()
        assertThat(c).contains("bpf_ktime_get_ns()")
        // Should update wakeup_ts map
        assertThat(c).contains("bpf_map_update_elem(&wakeup_ts")
    }

    @Test
    fun `sched_switch program uses cgroup_id and context switch counting`() {
        val c = cpuSchedProgram.generateC()

        // Should get cgroup id
        assertThat(c).contains("bpf_get_current_cgroup_id()")
        // Should lookup and atomically increment ctx_switches
        assertThat(c).contains("bpf_map_lookup_elem(&ctx_switches")
        assertThat(c).contains("__sync_fetch_and_add")
    }

    @Test
    fun `sched_switch program handles wakeup timestamp lookup and deletion`() {
        val c = cpuSchedProgram.generateC()

        // Should lookup in wakeup_ts
        assertThat(c).contains("bpf_map_lookup_elem(&wakeup_ts")
        // Should delete from wakeup_ts after reading
        assertThat(c).contains("bpf_map_delete_elem(&wakeup_ts")
    }

    @Test
    fun `sched_switch program computes run queue latency histogram`() {
        val c = cpuSchedProgram.generateC()

        // Should use log2l for histogram slot computation
        assertThat(c).contains("log2l")
        // Should lookup runq_latency map
        assertThat(c).contains("bpf_map_lookup_elem(&runq_latency")
        // Should update runq_latency map (in else branch)
        assertThat(c).contains("bpf_map_update_elem(&runq_latency")
    }

    @Test
    fun `preamble contains stats map definitions`() {
        val c = cpuSchedProgram.generateC()

        assertThat(c).contains("DEFINE_STATS_MAP(runq_latency)")
        assertThat(c).contains("DEFINE_STATS_MAP(ctx_switches)")
    }

    @Test
    fun `generated C has correct map and program counts`() {
        val c = cpuSchedProgram.generateC()

        // 3 DSL-defined maps (wakeup_ts, runq_latency, ctx_switches)
        val mapSections = Regex("""SEC\("\.maps"\)""").findAll(c).count()
        assertThat(mapSections).isGreaterThanOrEqualTo(3)

        // 2 programs
        assertThat(c).contains("SEC(\"tp/sched/sched_wakeup\")")
        assertThat(c).contains("SEC(\"tp/sched/sched_switch\")")
    }

    @Test
    fun `sched_switch reads next_pid from context`() {
        val c = cpuSchedProgram.generateC()

        // Should access next_pid from the sched_switch tracepoint context
        assertThat(c).contains("next_pid")
        assertThat(c).contains("trace_event_raw_sched_switch")
    }

    @Test
    fun `lookup-or-insert pattern with else branch for both maps`() {
        val c = cpuSchedProgram.generateC()

        // Both ctx_switches and runq_latency should use if/else pattern
        assertThat(c).contains("} else {")
        assertThat(c).contains("bpf_map_update_elem")
    }
}
