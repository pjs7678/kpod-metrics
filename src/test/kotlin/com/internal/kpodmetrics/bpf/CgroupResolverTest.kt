package com.internal.kpodmetrics.bpf

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class CgroupResolverTest {

    @Test
    fun `parse systemd cgroup path for burstable pod`() {
        val path = "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/" +
            "kubepods-burstable-pod1234abcd.slice/" +
            "cri-containerd-deadbeef5678.scope"
        val info = CgroupResolver.parseCgroupPath(path)
        assertNotNull(info)
        assertEquals("1234abcd", info!!.podUid)
        assertEquals("deadbeef5678", info.containerId)
    }

    @Test
    fun `parse cgroupfs cgroup path for guaranteed pod`() {
        val path = "/sys/fs/cgroup/kubepods/pod1234-abcd-efgh-5678/container123abc"
        val info = CgroupResolver.parseCgroupPath(path)
        assertNotNull(info)
        assertEquals("1234-abcd-efgh-5678", info!!.podUid)
        assertEquals("container123abc", info.containerId)
    }

    @Test
    fun `parse systemd cgroup path for besteffort pod`() {
        val path = "/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/" +
            "kubepods-besteffort-podaabbccdd.slice/" +
            "cri-containerd-11223344.scope"
        val info = CgroupResolver.parseCgroupPath(path)
        assertNotNull(info)
        assertEquals("aabbccdd", info!!.podUid)
        assertEquals("11223344", info.containerId)
    }

    @Test
    fun `non-kubernetes cgroup path returns null`() {
        val path = "/sys/fs/cgroup/user.slice/user-1000.slice"
        val info = CgroupResolver.parseCgroupPath(path)
        assertNull(info)
    }

    @Test
    fun `register and resolve pod info by cgroup id`() {
        val resolver = CgroupResolver()
        val podInfo = PodInfo(
            podUid = "1234",
            containerId = "abcd",
            namespace = "default",
            podName = "nginx-xyz",
            containerName = "nginx"
        )
        resolver.register(42L, podInfo)
        val resolved = resolver.resolve(42L)
        assertEquals(podInfo, resolved)
    }

    @Test
    fun `resolve returns null for unknown cgroup id`() {
        val resolver = CgroupResolver()
        assertNull(resolver.resolve(999L))
    }
}
