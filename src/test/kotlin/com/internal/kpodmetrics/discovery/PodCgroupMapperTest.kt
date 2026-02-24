package com.internal.kpodmetrics.discovery

import com.internal.kpodmetrics.cgroup.CgroupPathResolver
import com.internal.kpodmetrics.model.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.createDirectories

class PodCgroupMapperTest {
    @TempDir
    lateinit var tempDir: Path

    @Test
    fun `maps pods to cgroup targets for v2`() {
        val uid = "12345678-1234-1234-1234-123456789abc"
        val escapedUid = uid.replace("-", "_")
        val containerId = "abc123def456"
        val podDir = tempDir.resolve("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod${escapedUid}.slice")
        podDir.createDirectories()
        podDir.resolve("cri-containerd-${containerId}.scope").createDirectories()

        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val provider = object : PodProvider {
            override fun getDiscoveredPods(): Map<String, DiscoveredPod> = mapOf(
                uid to DiscoveredPod(uid, "nginx-pod", "default", QosClass.BURSTABLE,
                    listOf(ContainerInfo("nginx", containerId)))
            )
        }

        val mapper = PodCgroupMapper(provider, resolver, "test-node")
        val targets = mapper.resolve()
        assertEquals(1, targets.size)
        assertEquals("nginx-pod", targets[0].podName)
        assertEquals("nginx", targets[0].containerName)
        assertEquals("test-node", targets[0].nodeName)
    }

    @Test
    fun `skips pods with no matching cgroup path`() {
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val provider = object : PodProvider {
            override fun getDiscoveredPods(): Map<String, DiscoveredPod> = mapOf(
                "uid-1" to DiscoveredPod("uid-1", "ghost-pod", "default", QosClass.BURSTABLE,
                    listOf(ContainerInfo("ghost", "nonexistent")))
            )
        }
        val mapper = PodCgroupMapper(provider, resolver, "test-node")
        assertTrue(mapper.resolve().isEmpty())
    }

    @Test
    fun `matches container ID by prefix`() {
        val uid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        val escapedUid = uid.replace("-", "_")
        val fullContainerId = "abc123def456789012345678"
        val podDir = tempDir.resolve("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod${escapedUid}.slice")
        podDir.createDirectories()
        // Cgroup dir uses truncated container ID
        podDir.resolve("cri-containerd-abc123def456.scope").createDirectories()

        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val provider = object : PodProvider {
            override fun getDiscoveredPods(): Map<String, DiscoveredPod> = mapOf(
                uid to DiscoveredPod(uid, "app-pod", "production", QosClass.BURSTABLE,
                    listOf(ContainerInfo("app", fullContainerId)))
            )
        }
        val mapper = PodCgroupMapper(provider, resolver, "test-node")
        val targets = mapper.resolve()
        assertEquals(1, targets.size)
        assertEquals("app", targets[0].containerName)
    }
}
