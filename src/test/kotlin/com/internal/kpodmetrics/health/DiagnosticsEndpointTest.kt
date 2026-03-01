package com.internal.kpodmetrics.health

import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.collector.MetricsCollectorService
import com.internal.kpodmetrics.config.*
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Test
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DiagnosticsEndpointTest {

    private val service = mockk<MetricsCollectorService>()

    @Test
    fun `returns diagnostics with BPF info`() {
        val manager = mockk<BpfProgramManager>()
        every { service.getLastSuccessfulCycle() } returns Instant.now()
        every { service.isShuttingDown() } returns false
        every { manager.failedPrograms } returns emptySet()
        every { manager.isProgramLoaded("cpu_sched") } returns true
        every { manager.isProgramLoaded("net") } returns true
        every { manager.isProgramLoaded("syscall") } returns false
        every { manager.isProgramLoaded("biolatency") } returns false
        every { manager.isProgramLoaded("cachestat") } returns false
        every { manager.isProgramLoaded("tcpdrop") } returns true
        every { manager.isProgramLoaded("hardirqs") } returns false
        every { manager.isProgramLoaded("softirqs") } returns false
        every { manager.isProgramLoaded("execsnoop") } returns true

        val config = ResolvedConfig(
            cpu = CpuProperties(),
            network = NetworkProperties(),
            syscall = SyscallProperties(enabled = false),
            extended = ExtendedProperties(tcpdrop = true, execsnoop = true)
        )

        val endpoint = DiagnosticsEndpoint(service, manager, config)
        val result = endpoint.diagnostics()

        assertNotNull(result["uptime"])
        assertNotNull(result["lastCollectionCycle"])
        assertEquals(false, result["shuttingDown"])

        @Suppress("UNCHECKED_CAST")
        val bpf = result["bpf"] as Map<String, Any>
        assertEquals(true, bpf["available"])
        assertEquals(true, bpf["healthy"])
    }

    @Test
    fun `returns diagnostics without BPF manager`() {
        every { service.getLastSuccessfulCycle() } returns null
        every { service.isShuttingDown() } returns false

        val config = ResolvedConfig(
            cpu = CpuProperties(),
            network = NetworkProperties(),
            syscall = SyscallProperties()
        )

        val endpoint = DiagnosticsEndpoint(service, null, config)
        val result = endpoint.diagnostics()

        @Suppress("UNCHECKED_CAST")
        val bpf = result["bpf"] as Map<String, Any>
        assertEquals(false, bpf["available"])
    }

    @Test
    fun `enabled collectors reflects config`() {
        every { service.getLastSuccessfulCycle() } returns null
        every { service.isShuttingDown() } returns false

        val config = ResolvedConfig(
            cpu = CpuProperties(scheduling = SchedulingProperties(enabled = true)),
            network = NetworkProperties(tcp = TcpProperties(enabled = false)),
            syscall = SyscallProperties(enabled = true),
            extended = ExtendedProperties(biolatency = true)
        )

        val endpoint = DiagnosticsEndpoint(service, null, config)
        val result = endpoint.diagnostics()

        @Suppress("UNCHECKED_CAST")
        val collectors = result["enabledCollectors"] as Map<String, Boolean>
        assertTrue(collectors["cpu"]!!)
        assertEquals(false, collectors["network"])
        assertTrue(collectors["syscall"]!!)
        assertTrue(collectors["biolatency"]!!)
    }
}
