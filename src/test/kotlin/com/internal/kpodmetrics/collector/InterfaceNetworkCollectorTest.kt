package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.model.CgroupVersion
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText

class InterfaceNetworkCollectorTest {
    @TempDir
    lateinit var tempDir: Path
    private lateinit var registry: SimpleMeterRegistry

    @BeforeEach
    fun setUp() { registry = SimpleMeterRegistry() }

    @Test
    fun `collects interface network metrics from proc net dev`() {
        val containerDir = tempDir.resolve("cgroup/container1")
        containerDir.createDirectories()
        containerDir.resolve("cgroup.procs").writeText("42\n")
        val procDir = tempDir.resolve("proc/42/net")
        procDir.createDirectories()
        procDir.resolve("dev").writeText(
            "Inter-|   Receive                                                |  Transmit\n" +
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
            "  eth0: 9876543    5432    1    2    0     0          0         0  1111111    3333    0    1    0     0       0          0\n"
        )
        val reader = CgroupReader(CgroupVersion.V2)
        val collector = InterfaceNetworkCollector(reader, tempDir.resolve("proc").toString(), registry)
        val targets = listOf(PodCgroupTarget("nginx-pod", "default", "nginx",
            containerDir.toString(), "test-node"))
        collector.collect(targets)

        val rxBytes = registry.counter("kpod.net.iface.rx.bytes",
            "namespace", "default", "pod", "nginx-pod", "container", "nginx",
            "node", "test-node", "interface", "eth0")
        assertEquals(9876543.0, rxBytes.count())

        val txPackets = registry.counter("kpod.net.iface.tx.packets",
            "namespace", "default", "pod", "nginx-pod", "container", "nginx",
            "node", "test-node", "interface", "eth0")
        assertEquals(3333.0, txPackets.count())
    }

    @Test
    fun `skips container when PID not found`() {
        val containerDir = tempDir.resolve("cgroup/container2")
        containerDir.createDirectories()
        val reader = CgroupReader(CgroupVersion.V2)
        val collector = InterfaceNetworkCollector(reader, tempDir.resolve("proc").toString(), registry)
        val targets = listOf(PodCgroupTarget("no-pid-pod", "default", "ghost",
            containerDir.toString(), "test-node"))
        collector.collect(targets)
        assertTrue(registry.meters.isEmpty())
    }
}
