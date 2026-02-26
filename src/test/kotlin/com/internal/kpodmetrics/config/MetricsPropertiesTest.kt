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
    fun `standard profile enables cpu, network but not syscall`() {
        val resolved = props.resolveProfile()
        assertTrue(resolved.cpu.scheduling.enabled)
        assertTrue(resolved.cpu.throttling.enabled)
        assertTrue(resolved.network.tcp.enabled)
        assertFalse(resolved.syscall.enabled)
        assertTrue(resolved.extended.tcpdrop)
        assertTrue(resolved.extended.execsnoop)
    }

    @Test
    fun `minimal profile enables only cpu scheduling and throttling`() {
        val resolved = props.resolveProfile(override = "minimal")
        assertTrue(resolved.cpu.scheduling.enabled)
        assertTrue(resolved.cpu.throttling.enabled)
        assertFalse(resolved.network.tcp.enabled)
        assertFalse(resolved.syscall.enabled)
        assertFalse(resolved.extended.biolatency)
    }

    @Test
    fun `comprehensive profile enables everything including syscall and all extended tools`() {
        val resolved = props.resolveProfile(override = "comprehensive")
        assertTrue(resolved.cpu.scheduling.enabled)
        assertTrue(resolved.network.tcp.enabled)
        assertTrue(resolved.syscall.enabled)
        assertTrue(resolved.syscall.trackedSyscalls.isNotEmpty())
        assertTrue(resolved.extended.biolatency)
        assertTrue(resolved.extended.cachestat)
        assertTrue(resolved.extended.tcpdrop)
        assertTrue(resolved.extended.hardirqs)
        assertTrue(resolved.extended.softirqs)
        assertTrue(resolved.extended.execsnoop)
    }

    @Test
    fun `poll interval is bound correctly`() {
        assertEquals(15000L, props.pollInterval)
    }

    @Test
    fun `node name is bound correctly`() {
        assertEquals("test-node", props.nodeName)
    }

    @Test
    fun `standard profile enables diskIO, interfaceNet, and filesystem cgroup collectors`() {
        val resolved = props.resolveProfile()
        assertTrue(resolved.cgroup.diskIO)
        assertTrue(resolved.cgroup.interfaceNetwork)
        assertTrue(resolved.cgroup.filesystem)
    }

    @Test
    fun `minimal profile enables only diskIO cgroup collector`() {
        val resolved = props.resolveProfile(override = "minimal")
        assertTrue(resolved.cgroup.diskIO)
        assertFalse(resolved.cgroup.interfaceNetwork)
        assertFalse(resolved.cgroup.filesystem)
    }

    @Test
    fun `comprehensive profile enables all cgroup collectors`() {
        val resolved = props.resolveProfile(override = "comprehensive")
        assertTrue(resolved.cgroup.diskIO)
        assertTrue(resolved.cgroup.interfaceNetwork)
        assertTrue(resolved.cgroup.filesystem)
    }
}
