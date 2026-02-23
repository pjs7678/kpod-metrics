package com.internal.kpodmetrics.cgroup

import com.internal.kpodmetrics.model.CgroupVersion
import com.internal.kpodmetrics.model.QosClass
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.createDirectories

class CgroupPathResolverTest {
    @TempDir
    lateinit var tempDir: Path

    @Test
    fun `v2 resolves Burstable pod path with systemd style`() {
        val uid = "12345678-1234-1234-1234-123456789abc"
        val escapedUid = uid.replace("-", "_")
        val podDir = tempDir.resolve("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod${escapedUid}.slice")
        podDir.createDirectories()
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val path = resolver.resolvePodPath(uid, QosClass.BURSTABLE)
        assertNotNull(path)
        assertTrue(path!!.endsWith("kubepods-burstable-pod${escapedUid}.slice"))
    }

    @Test
    fun `v2 resolves Guaranteed pod path`() {
        val uid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        val escapedUid = uid.replace("-", "_")
        val podDir = tempDir.resolve("kubepods.slice/kubepods-pod${escapedUid}.slice")
        podDir.createDirectories()
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val path = resolver.resolvePodPath(uid, QosClass.GUARANTEED)
        assertNotNull(path)
    }

    @Test
    fun `v2 resolves BestEffort pod path`() {
        val uid = "11111111-2222-3333-4444-555555555555"
        val escapedUid = uid.replace("-", "_")
        val podDir = tempDir.resolve("kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod${escapedUid}.slice")
        podDir.createDirectories()
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val path = resolver.resolvePodPath(uid, QosClass.BEST_EFFORT)
        assertNotNull(path)
    }

    @Test
    fun `v2 falls back to kubelet_slice style`() {
        val uid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        val escapedUid = uid.replace("-", "_")
        val podDir = tempDir.resolve("kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod${escapedUid}.slice")
        podDir.createDirectories()
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val path = resolver.resolvePodPath(uid, QosClass.GUARANTEED)
        assertNotNull(path)
    }

    @Test
    fun `v2 returns null for non-existent pod`() {
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        assertNull(resolver.resolvePodPath("nonexistent-uid", QosClass.BURSTABLE))
    }

    @Test
    fun `v2 lists container directories`() {
        val uid = "12345678-1234-1234-1234-123456789abc"
        val escapedUid = uid.replace("-", "_")
        val podDir = tempDir.resolve("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod${escapedUid}.slice")
        podDir.createDirectories()
        podDir.resolve("cri-containerd-abc123.scope").createDirectories()
        podDir.resolve("cri-containerd-def456.scope").createDirectories()
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val containers = resolver.listContainerPaths(podDir.toString())
        assertEquals(2, containers.size)
        assertTrue(containers.any { it.containerId == "abc123" })
        assertTrue(containers.any { it.containerId == "def456" })
    }

    @Test
    fun `v1 resolves Burstable pod path`() {
        val uid = "12345678-1234-1234-1234-123456789abc"
        val podDir = tempDir.resolve("blkio/kubepods/burstable/pod${uid}")
        podDir.createDirectories()
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V1)
        val path = resolver.resolvePodPath(uid, QosClass.BURSTABLE, "blkio")
        assertNotNull(path)
        assertTrue(path!!.endsWith("pod${uid}"))
    }

    @Test
    fun `v1 resolves Guaranteed pod path`() {
        val uid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        val podDir = tempDir.resolve("blkio/kubepods/pod${uid}")
        podDir.createDirectories()
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V1)
        val path = resolver.resolvePodPath(uid, QosClass.GUARANTEED, "blkio")
        assertNotNull(path)
    }
}
