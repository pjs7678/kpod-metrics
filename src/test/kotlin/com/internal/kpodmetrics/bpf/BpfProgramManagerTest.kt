package com.internal.kpodmetrics.bpf

import com.internal.kpodmetrics.config.*
import io.mockk.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach

class BpfProgramManagerTest {

    private lateinit var bridge: BpfBridge
    private lateinit var manager: BpfProgramManager

    @BeforeEach
    fun setup() {
        bridge = mockk(relaxed = true)
    }

    @Test
    fun `loads only enabled programs based on profile`() {
        val config = MetricsProperties(profile = "minimal").resolveProfile()
        manager = BpfProgramManager(bridge, "/test/bpf", config)

        every { bridge.openObject(any()) } returns 1L
        every { bridge.loadObject(any()) } returns 0
        every { bridge.attachAll(any()) } returns 0

        manager.loadAll()

        verify { bridge.openObject("/test/bpf/cpu_sched.bpf.o") }
        verify(exactly = 0) { bridge.openObject("/test/bpf/net.bpf.o") }
        verify(exactly = 0) { bridge.openObject("/test/bpf/syscall.bpf.o") }
    }

    @Test
    fun `standard profile loads cpu, network, extended tools`() {
        val config = MetricsProperties(profile = "standard").resolveProfile()
        manager = BpfProgramManager(bridge, "/test/bpf", config)

        every { bridge.openObject(any()) } returns 1L
        every { bridge.loadObject(any()) } returns 0
        every { bridge.attachAll(any()) } returns 0

        manager.loadAll()

        verify { bridge.openObject("/test/bpf/cpu_sched.bpf.o") }
        verify { bridge.openObject("/test/bpf/net.bpf.o") }
        verify { bridge.openObject("/test/bpf/tcpdrop.bpf.o") }
        verify { bridge.openObject("/test/bpf/execsnoop.bpf.o") }
        verify(exactly = 0) { bridge.openObject("/test/bpf/syscall.bpf.o") }
    }

    @Test
    fun `destroyAll cleans up all loaded programs`() {
        val config = MetricsProperties(profile = "standard").resolveProfile()
        manager = BpfProgramManager(bridge, "/test/bpf", config)

        every { bridge.openObject(any()) } returnsMany listOf(1L, 2L, 3L, 4L)
        every { bridge.loadObject(any()) } returns 0
        every { bridge.attachAll(any()) } returns 0

        manager.loadAll()
        manager.destroyAll()

        verify { bridge.destroyObject(1L) }
        verify { bridge.destroyObject(2L) }
        verify { bridge.destroyObject(3L) }
        verify { bridge.destroyObject(4L) }
    }

    @Test
    fun `getMapFd delegates to bridge with correct handle`() {
        val config = MetricsProperties(profile = "minimal").resolveProfile()
        manager = BpfProgramManager(bridge, "/test/bpf", config)

        every { bridge.openObject("/test/bpf/cpu_sched.bpf.o") } returns 42L
        every { bridge.loadObject(42L) } returns 0
        every { bridge.attachAll(42L) } returns 0
        every { bridge.getMapFd(42L, "runq_latency") } returns 7

        manager.loadAll()
        val fd = manager.getMapFd("cpu_sched", "runq_latency")

        assertEquals(7, fd)
    }
}
