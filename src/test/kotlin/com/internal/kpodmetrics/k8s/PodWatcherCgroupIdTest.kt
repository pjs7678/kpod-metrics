package com.internal.kpodmetrics.k8s

import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.PodInfo
import com.internal.kpodmetrics.cgroup.CgroupPathResolver
import com.internal.kpodmetrics.config.CgroupProperties
import com.internal.kpodmetrics.config.MetricsProperties
import com.internal.kpodmetrics.model.CgroupVersion
import com.internal.kpodmetrics.model.QosClass
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import kotlin.io.path.createDirectories

/**
 * Cgroup IDs must resolve from the host cgroup tree alone. Before, resolution depended on
 * /proc/<pid>/cgroup paths that are namespace-relative inside the agent's container, so on
 * containerd/Docker with cgroup v2 every container was dropped and all BPF metrics were empty.
 */
class PodWatcherCgroupIdTest {
    @TempDir
    lateinit var root: Path

    private fun inode(p: Path) = Regex("ino=(\\d+)")
        .find(Files.readAttributes(p, BasicFileAttributes::class.java).fileKey().toString())!!
        .groupValues[1].toLong()

    private fun watcher() = PodWatcher(
        mockk(relaxed = true), CgroupResolver(),
        MetricsProperties(cgroup = CgroupProperties(root = root.toString())),
        registry = null,
        pathResolver = CgroupPathResolver(root.toString(), CgroupVersion.V2)
    )

    @Test
    fun `resolves cgroupfs driver layout used by Docker and k3s`() {
        val uid = "9a8a0cea-c387-4224-a7f3-ffa24db80175"
        val id = "34c4df632b16a329f7c3c702c87eaf182b0ab3d942b08a4b3cb189020a4f6659"
        val dir = root.resolve("kubepods/burstable/pod$uid/$id").createDirectories()
        val got = watcher().resolveCgroupId(PodInfo(uid, id, "ns", "p", "c"), QosClass.BURSTABLE)
        assertEquals(inode(dir), got)
    }

    @Test
    fun `resolves systemd driver layout used by containerd even with a wrong QoS hint`() {
        val uid = "12345678-1234-1234-1234-123456789abc"
        val id = "abc123def456"
        val dir = root.resolve("kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod${uid.replace("-", "_")}.slice/cri-containerd-$id.scope")
            .createDirectories()
        val got = watcher().resolveCgroupId(PodInfo(uid, id, "ns", "p", "c"), QosClass.GUARANTEED)
        assertEquals(inode(dir), got)
    }

    @Test
    fun `unknown container resolves to null`() {
        assertNull(watcher().resolveCgroupId(PodInfo("nope", "deadbeef", "ns", "p", "c"), QosClass.BURSTABLE))
    }
}
