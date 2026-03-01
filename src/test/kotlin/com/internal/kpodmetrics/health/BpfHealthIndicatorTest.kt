package com.internal.kpodmetrics.health

import com.internal.kpodmetrics.bpf.BpfProgramManager
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Test
import org.springframework.boot.actuate.health.Status
import kotlin.test.assertEquals

class BpfHealthIndicatorTest {

    @Test
    fun `reports UP when no programs failed`() {
        val manager = mockk<BpfProgramManager>()
        every { manager.failedPrograms } returns emptySet()

        val indicator = BpfHealthIndicator(manager)
        val health = indicator.health()

        assertEquals(Status.UP, health.status)
    }

    @Test
    fun `reports DOWN when programs failed`() {
        val manager = mockk<BpfProgramManager>()
        every { manager.failedPrograms } returns setOf("cpu_sched", "net")

        val indicator = BpfHealthIndicator(manager)
        val health = indicator.health()

        assertEquals(Status.DOWN, health.status)
        @Suppress("UNCHECKED_CAST")
        val failed = health.details["failedPrograms"] as Set<String>
        assertEquals(setOf("cpu_sched", "net"), failed)
    }
}
