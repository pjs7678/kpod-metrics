package com.internal.kpodmetrics.bpf

import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AttachPermissionDiagnosisTest {
    // CapEff observed in the chart's non-privileged pod: NET_ADMIN, SYS_RESOURCE, PERFMON, BPF
    private val chartCaps = 0xc001001000L
    private val withSysAdmin = chartCaps or (1L shl 21)
    private val denied = mapOf(
        "cpu_sched" to "Failed to attach program 'tp_sched_sched_wakeup': Permission denied",
        "net" to "Failed to attach program 'kprobe_tcp_sendmsg': Permission denied",
    )

    @Test
    fun `Ubuntu paranoid level without SYS_ADMIN names the sysctl fix`() {
        val msg = AttachPermissionDiagnosis.diagnose(denied, paranoid = 4, capEff = chartCaps)
        assertNotNull(msg)
        assertTrue(msg!!.contains("perf_event_paranoid=4"), msg)
        assertTrue(msg.contains("kernel.perf_event_paranoid=2"), msg)
        assertTrue(msg.contains("cpu_sched, net"), msg)
    }

    @Test
    fun `paranoid at or below 2 points elsewhere`() {
        val msg = AttachPermissionDiagnosis.diagnose(denied, paranoid = 2, capEff = chartCaps)!!
        assertTrue(msg.contains("seccomp/AppArmor"), msg)
        assertTrue(!msg.contains("set kernel.perf_event_paranoid=2"), msg)
    }

    @Test
    fun `SYS_ADMIN present means paranoid is not the cause`() {
        val msg = AttachPermissionDiagnosis.diagnose(denied, paranoid = 4, capEff = withSysAdmin)!!
        assertTrue(msg.contains("CAP_SYS_ADMIN=true"), msg)
    }

    @Test
    fun `non-permission failures are not misdiagnosed`() {
        assertNull(AttachPermissionDiagnosis.diagnose(
            mapOf("http" to "Failed to load object: Invalid argument"), paranoid = 4, capEff = chartCaps))
        assertNull(AttachPermissionDiagnosis.diagnose(emptyMap(), paranoid = 4, capEff = chartCaps))
    }

    @Test
    fun `unreadable inputs still produce a hint`() {
        val msg = AttachPermissionDiagnosis.diagnose(denied, paranoid = null, capEff = null)!!
        assertTrue(msg.contains("unknown"), msg)
    }
}
