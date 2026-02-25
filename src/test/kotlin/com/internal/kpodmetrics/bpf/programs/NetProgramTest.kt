package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.generateC
import dev.ebpf.dsl.api.validate
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class NetProgramTest {

    @Test
    fun `net program validates without errors`() {
        val result = netProgram.validate()
        assertThat(result.errors).isEmpty()
    }

    @Test
    fun `net program generates correct map definitions`() {
        val c = netProgram.generateC()

        // tcp_stats_map: LRU_HASH map
        assertThat(c).contains("tcp_stats_map SEC(\".maps\")")
        assertThat(c).contains("BPF_MAP_TYPE_LRU_HASH")

        // rtt_hist: LRU_HASH map
        assertThat(c).contains("rtt_hist SEC(\".maps\")")
    }

    @Test
    fun `net program generates all five program sections`() {
        val c = netProgram.generateC()

        assertThat(c).contains("SEC(\"kprobe/tcp_sendmsg\")")
        assertThat(c).contains("SEC(\"kprobe/tcp_recvmsg\")")
        assertThat(c).contains("SEC(\"tp/tcp/tcp_retransmit_skb\")")
        assertThat(c).contains("SEC(\"tp/sock/inet_sock_set_state\")")
        assertThat(c).contains("SEC(\"tp/tcp/tcp_probe\")")
    }

    @Test
    fun `tcp_stats struct has six fields`() {
        val c = netProgram.generateC()

        assertThat(c).contains("struct tcp_stats {")
        assertThat(c).contains("bytes_sent")
        assertThat(c).contains("bytes_received")
        assertThat(c).contains("retransmits")
        assertThat(c).contains("connections")
        assertThat(c).contains("rtt_sum_us")
        assertThat(c).contains("rtt_count")
    }

    @Test
    fun `kprobe programs use PT_REGS_PARM3 for argument access`() {
        val c = netProgram.generateC()

        // Both tcp_sendmsg and tcp_recvmsg use PT_REGS_PARM3
        assertThat(c).contains("PT_REGS_PARM3(ctx)")
    }

    @Test
    fun `tcp_probe program uses log2l for histogram`() {
        val c = netProgram.generateC()

        assertThat(c).contains("log2l")
    }

    @Test
    fun `net program uses core BPF helpers`() {
        val c = netProgram.generateC()

        assertThat(c).contains("bpf_map_lookup_elem")
        assertThat(c).contains("__sync_fetch_and_add")
        assertThat(c).contains("bpf_map_update_elem")
    }

    @Test
    fun `inet_sock_set_state reads newstate from context`() {
        val c = netProgram.generateC()

        assertThat(c).contains("trace_event_raw_inet_sock_set_state")
        assertThat(c).contains("newstate")
    }

    @Test
    fun `tcp_probe reads srtt from context`() {
        val c = netProgram.generateC()

        assertThat(c).contains("trace_event_raw_tcp_probe")
        assertThat(c).contains("srtt")
    }

    @Test
    fun `preamble contains stats map definitions`() {
        val c = netProgram.generateC()

        assertThat(c).contains("DEFINE_STATS_MAP(tcp_stats_map)")
        assertThat(c).contains("DEFINE_STATS_MAP(rtt_hist)")
    }

    @Test
    fun `generated C has correct map and program counts`() {
        val c = netProgram.generateC()

        // 2 DSL-defined maps (tcp_stats_map, rtt_hist)
        val mapSections = Regex("""SEC\("\.maps"\)""").findAll(c).count()
        assertThat(mapSections).isGreaterThanOrEqualTo(2)

        // 5 programs
        assertThat(c).contains("SEC(\"kprobe/tcp_sendmsg\")")
        assertThat(c).contains("SEC(\"kprobe/tcp_recvmsg\")")
        assertThat(c).contains("SEC(\"tp/tcp/tcp_retransmit_skb\")")
        assertThat(c).contains("SEC(\"tp/sock/inet_sock_set_state\")")
        assertThat(c).contains("SEC(\"tp/tcp/tcp_probe\")")
    }

    @Test
    fun `lookup-or-insert pattern with else branch`() {
        val c = netProgram.generateC()

        // Programs should use the ifNonNull...elseThen pattern
        assertThat(c).contains("} else {")
        assertThat(c).contains("bpf_map_update_elem")
    }

    @Test
    fun `programs use cgroup id for map keys`() {
        val c = netProgram.generateC()

        assertThat(c).contains("bpf_get_current_cgroup_id()")
    }
}
