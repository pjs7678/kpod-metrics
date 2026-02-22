package com.internal.kpodmetrics.config

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.TestPropertySource

@SpringBootTest
@TestPropertySource(properties = [
    "kpod.profile=standard",
    "kpod.node-name=test-node",
    "kpod.poll-interval=15000",
    "kpod.bpf.enabled=false"
])
class MetricsPropertiesTest {

    @Autowired
    lateinit var props: MetricsProperties

    @Test
    fun `standard profile enables cpu, network, memory but not syscall`() {
        val resolved = props.resolveProfile()
        assertTrue(resolved.cpu.scheduling.enabled)
        assertTrue(resolved.cpu.throttling.enabled)
        assertTrue(resolved.network.tcp.enabled)
        assertTrue(resolved.memory.oom)
        assertTrue(resolved.memory.pageFaults)
        assertTrue(resolved.memory.cgroupStats)
        assertFalse(resolved.syscall.enabled)
    }

    @Test
    fun `minimal profile enables only cpu scheduling, throttling, oom, cgroup stats`() {
        val resolved = props.resolveProfile(override = "minimal")
        assertTrue(resolved.cpu.scheduling.enabled)
        assertTrue(resolved.cpu.throttling.enabled)
        assertFalse(resolved.network.tcp.enabled)
        assertTrue(resolved.memory.oom)
        assertFalse(resolved.memory.pageFaults)
        assertTrue(resolved.memory.cgroupStats)
        assertFalse(resolved.syscall.enabled)
    }

    @Test
    fun `comprehensive profile enables everything including syscall`() {
        val resolved = props.resolveProfile(override = "comprehensive")
        assertTrue(resolved.cpu.scheduling.enabled)
        assertTrue(resolved.network.tcp.enabled)
        assertTrue(resolved.memory.oom)
        assertTrue(resolved.syscall.enabled)
        assertTrue(resolved.syscall.trackedSyscalls.isNotEmpty())
    }

    @Test
    fun `poll interval is bound correctly`() {
        assertEquals(15000L, props.pollInterval)
    }

    @Test
    fun `node name is bound correctly`() {
        assertEquals("test-node", props.nodeName)
    }
}
