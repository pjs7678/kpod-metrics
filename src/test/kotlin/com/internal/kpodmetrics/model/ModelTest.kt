package com.internal.kpodmetrics.model

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class ModelTest {
    @Test
    fun `CgroupVersion enum has V1 and V2`() {
        assertEquals(2, CgroupVersion.entries.size)
        assertNotNull(CgroupVersion.V1)
        assertNotNull(CgroupVersion.V2)
    }

    @Test
    fun `DiscoveredPod holds pod metadata with containers`() {
        val containers = listOf(ContainerInfo("nginx", "abc123def456"))
        val pod = DiscoveredPod(
            uid = "12345678-1234-1234-1234-123456789abc",
            name = "nginx-7b4f5d8c9-x2k4p",
            namespace = "default",
            qosClass = QosClass.BURSTABLE,
            containers = containers
        )
        assertEquals("nginx-7b4f5d8c9-x2k4p", pod.name)
        assertEquals(QosClass.BURSTABLE, pod.qosClass)
        assertEquals(1, pod.containers.size)
        assertEquals("nginx", pod.containers[0].name)
    }

    @Test
    fun `PodCgroupTarget holds resolved collection target`() {
        val target = PodCgroupTarget(
            podName = "nginx-pod",
            namespace = "default",
            containerName = "nginx",
            cgroupPath = "/sys/fs/cgroup/kubepods.slice/...",
            nodeName = "node-1"
        )
        assertEquals("nginx", target.containerName)
        assertEquals("node-1", target.nodeName)
    }
}
