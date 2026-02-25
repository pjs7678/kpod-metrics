package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.generateC
import dev.ebpf.dsl.api.validate
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SyscallProgramTest {

    @Test
    fun `syscall program validates without errors`() {
        val result = syscallProgram.validate()
        assertThat(result.errors).isEmpty()
    }

    @Test
    fun `syscall program generates correct map definitions`() {
        val c = syscallProgram.generateC()

        // syscall_start: HASH map with scalar key/value
        assertThat(c).contains("syscall_start SEC(\".maps\")")
        assertThat(c).contains("BPF_MAP_TYPE_HASH")

        // syscall_nr_map: HASH map with scalar key/value
        assertThat(c).contains("syscall_nr_map SEC(\".maps\")")

        // syscall_stats (name <=15 chars): LRU_HASH map with struct key/value
        assertThat(c).contains("syscall_stats SEC(\".maps\")")
        assertThat(c).contains("BPF_MAP_TYPE_LRU_HASH")

        // trk_syscalls (tracked_syscalls shortened for 15-char BPF limit): HASH map
        assertThat(c).contains("trk_syscalls SEC(\".maps\")")
    }

    @Test
    fun `syscall_start map has scalar u64 key and u64 value`() {
        val c = syscallProgram.generateC()

        val startBlock = c.substringBefore("syscall_start SEC")
            .substringAfterLast("struct {")
        assertThat(startBlock).contains("__type(key, __u64)")
        assertThat(startBlock).contains("__type(value, __u64)")
    }

    @Test
    fun `syscall_nr_map has scalar u64 key and u32 value`() {
        val c = syscallProgram.generateC()

        val nrBlock = c.substringBefore("syscall_nr_map SEC")
            .substringAfterLast("struct {")
        assertThat(nrBlock).contains("__type(key, __u64)")
        assertThat(nrBlock).contains("__type(value, __u32)")
    }

    @Test
    fun `tracked_syscalls map has scalar u32 key and u8 value`() {
        val c = syscallProgram.generateC()

        val trackedBlock = c.substringBefore("trk_syscalls SEC")
            .substringAfterLast("struct {")
        assertThat(trackedBlock).contains("__type(key, __u32)")
        assertThat(trackedBlock).contains("__type(value, __u8)")
    }

    @Test
    fun `syscall_key struct has correct fields`() {
        val c = syscallProgram.generateC()

        assertThat(c).contains("struct syscall_key {")
        assertThat(c).contains("__u64 cgroup_id;")
        assertThat(c).contains("__u32 syscall_nr;")
        assertThat(c).contains("__u32 _pad;")
    }

    @Test
    fun `syscall_stats struct has correct fields`() {
        val c = syscallProgram.generateC()

        assertThat(c).contains("struct syscall_stats {")
        assertThat(c).contains("__u64 count;")
        assertThat(c).contains("__u64 error_count;")
        assertThat(c).contains("__u64 latency_sum_ns;")
        assertThat(c).contains("__u64 latency_slots[27];")
    }

    @Test
    fun `syscall program generates raw tracepoint sections`() {
        val c = syscallProgram.generateC()

        assertThat(c).contains("SEC(\"raw_tp/sys_enter\")")
        assertThat(c).contains("SEC(\"raw_tp/sys_exit\")")
    }

    @Test
    fun `sys_enter reads syscall_nr from context args`() {
        val c = syscallProgram.generateC()

        // Should read syscall_nr via raw expression
        assertThat(c).contains("ctx->args[1]")
    }

    @Test
    fun `sys_enter checks tracked_syscalls map`() {
        val c = syscallProgram.generateC()

        assertThat(c).contains("bpf_map_lookup_elem(&trk_syscalls")
    }

    @Test
    fun `sys_enter stores timestamp in syscall_start`() {
        val c = syscallProgram.generateC()

        assertThat(c).contains("bpf_ktime_get_ns()")
        assertThat(c).contains("bpf_map_update_elem(&syscall_start")
    }

    @Test
    fun `sys_enter stores syscall_nr in syscall_nr_map`() {
        val c = syscallProgram.generateC()

        assertThat(c).contains("bpf_map_update_elem(&syscall_nr_map")
    }

    @Test
    fun `sys_exit uses pid_tgid for lookups`() {
        val c = syscallProgram.generateC()

        assertThat(c).contains("bpf_get_current_pid_tgid()")
    }

    @Test
    fun `sys_exit reads return value from context`() {
        val c = syscallProgram.generateC()

        // Should read ret via raw expression casting ctx->args[1]
        assertThat(c).contains("(long)ctx->args[1]")
    }

    @Test
    fun `sys_exit looks up syscall_start and syscall_nr_map`() {
        val c = syscallProgram.generateC()

        assertThat(c).contains("bpf_map_lookup_elem(&syscall_start")
        assertThat(c).contains("bpf_map_lookup_elem(&syscall_nr_map")
    }

    @Test
    fun `sys_exit looks up and updates syscall_stats`() {
        val c = syscallProgram.generateC()

        assertThat(c).contains("bpf_map_lookup_elem(&syscall_stats")
        assertThat(c).contains("__sync_fetch_and_add")
    }

    @Test
    fun `sys_exit computes latency histogram slot`() {
        val c = syscallProgram.generateC()

        assertThat(c).contains("log2l")
        assertThat(c).contains("MAX_SLOTS")
    }

    @Test
    fun `sys_exit deletes from syscall_start and syscall_nr_map`() {
        val c = syscallProgram.generateC()

        assertThat(c).contains("bpf_map_delete_elem(&syscall_start")
        assertThat(c).contains("bpf_map_delete_elem(&syscall_nr_map")
    }

    @Test
    fun `sys_exit uses cgroup_id for stats key`() {
        val c = syscallProgram.generateC()

        assertThat(c).contains("bpf_get_current_cgroup_id()")
    }

    @Test
    fun `sys_exit has lookup-or-insert pattern with else branch for stats`() {
        val c = syscallProgram.generateC()

        // Should use the ifNonNull...elseThen pattern
        assertThat(c).contains("} else {")
        assertThat(c).contains("bpf_map_update_elem(&syscall_stats")
    }

    @Test
    fun `preamble contains stats map definition`() {
        val c = syscallProgram.generateC()

        assertThat(c).contains("DEFINE_STATS_MAP(syscall_stats_map)")
    }

    @Test
    fun `generated C has correct map and program counts`() {
        val c = syscallProgram.generateC()

        // 4 scalar maps + 1 struct map = 5 DSL-defined maps
        val mapSections = Regex("""SEC\("\.maps"\)""").findAll(c).count()
        assertThat(mapSections).isGreaterThanOrEqualTo(5)

        // 2 programs
        assertThat(c).contains("SEC(\"raw_tp/sys_enter\")")
        assertThat(c).contains("SEC(\"raw_tp/sys_exit\")")
    }
}
