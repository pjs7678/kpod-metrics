package com.internal.kpodmetrics.k8s

import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.PodInfo
import com.internal.kpodmetrics.config.FilterProperties
import com.internal.kpodmetrics.config.MetricsProperties
import com.internal.kpodmetrics.discovery.PodProvider
import com.internal.kpodmetrics.model.QosClass
import io.fabric8.kubernetes.api.model.ContainerStatusBuilder
import io.fabric8.kubernetes.api.model.PodBuilder
import io.fabric8.kubernetes.api.model.PodStatusBuilder
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class PodWatcherTest {

    @Test
    fun `extractPodInfos returns PodInfo for each container`() {
        val pod = PodBuilder()
            .withNewMetadata()
                .withName("nginx-abc")
                .withNamespace("default")
                .withUid("pod-uid-123")
            .endMetadata()
            .withNewSpec()
                .addNewContainer().withName("nginx").endContainer()
                .addNewContainer().withName("sidecar").endContainer()
            .endSpec()
            .withStatus(PodStatusBuilder()
                .withContainerStatuses(
                    ContainerStatusBuilder()
                        .withName("nginx")
                        .withContainerID("containerd://aabbccdd1122")
                        .build(),
                    ContainerStatusBuilder()
                        .withName("sidecar")
                        .withContainerID("containerd://eeff33445566")
                        .build()
                )
                .build())
            .build()

        val infos = PodWatcher.extractPodInfos(pod)

        assertEquals(2, infos.size)
        assertEquals("nginx", infos[0].containerName)
        assertEquals("aabbccdd1122", infos[0].containerId)
        assertEquals("default", infos[0].namespace)
        assertEquals("nginx-abc", infos[0].podName)
        assertEquals("sidecar", infos[1].containerName)
    }

    @Test
    fun `shouldWatch respects namespace filter`() {
        val filter = FilterProperties(
            excludeNamespaces = listOf("kube-system", "kube-public")
        )
        assertTrue(PodWatcher.shouldWatch("default", filter))
        assertFalse(PodWatcher.shouldWatch("kube-system", filter))
    }

    @Test
    fun `shouldWatch with namespace allowlist`() {
        val filter = FilterProperties(
            namespaces = listOf("production", "staging")
        )
        assertTrue(PodWatcher.shouldWatch("production", filter))
        assertFalse(PodWatcher.shouldWatch("default", filter))
    }

    @Test
    fun `parseCgroupPathFromProc extracts cgroup v2 path`() {
        val content = "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc123.slice/cri-containerd-def456.scope\n"
        val path = PodWatcher.parseCgroupPathFromProc(content)
        assertEquals(
            "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc123.slice/cri-containerd-def456.scope",
            path
        )
    }

    @Test
    fun `parseCgroupPathFromProc handles cgroup v1 format`() {
        val content = """
            12:pids:/kubepods/burstable/podabc123/def456
            11:devices:/kubepods/burstable/podabc123/def456
            0::/
        """.trimIndent()
        val path = PodWatcher.parseCgroupPathFromProc(content)
        // Should prefer the v2 line (0::/) but since it has no kubepods, it will fall back
        // Actually "0::/" is v2 with root path. The v1 kubepods line should be picked.
        assertEquals("/kubepods/burstable/podabc123/def456", path)
    }

    @Test
    fun `parseCgroupPathFromProc returns null for empty content`() {
        assertNull(PodWatcher.parseCgroupPathFromProc(""))
    }

    @Test
    fun `parseCgroupPathFromProc prefers cgroup v2 with kubepods`() {
        val content = """
            11:devices:/kubepods/burstable/podabc123/def456
            0::/kubepods.slice/kubepods-burstable.slice/cri-containerd-xyz.scope
        """.trimIndent()
        val path = PodWatcher.parseCgroupPathFromProc(content)
        // Should return the v2 path (starts with 0::)
        assertEquals("/kubepods.slice/kubepods-burstable.slice/cri-containerd-xyz.scope", path)
    }

    @Test
    fun `toDiscoveredPod converts fabric8 Pod to DiscoveredPod`() {
        val pod = PodBuilder()
            .withNewMetadata()
                .withName("nginx-abc")
                .withNamespace("default")
                .withUid("pod-uid-123")
            .endMetadata()
            .withNewSpec()
                .addNewContainer().withName("nginx").endContainer()
            .endSpec()
            .withStatus(PodStatusBuilder()
                .withQosClass("Burstable")
                .withContainerStatuses(
                    ContainerStatusBuilder()
                        .withName("nginx")
                        .withContainerID("containerd://aabbccdd1122")
                        .build()
                )
                .build())
            .build()

        val discovered = PodWatcher.toDiscoveredPod(pod)
        assertNotNull(discovered)
        assertEquals("pod-uid-123", discovered!!.uid)
        assertEquals("nginx-abc", discovered.name)
        assertEquals("default", discovered.namespace)
        assertEquals(QosClass.BURSTABLE, discovered.qosClass)
        assertEquals(1, discovered.containers.size)
        assertEquals("nginx", discovered.containers[0].name)
        assertEquals("aabbccdd1122", discovered.containers[0].containerId)
    }

    @Test
    fun `PodWatcher implements PodProvider`() {
        val resolver = CgroupResolver()
        val props = MetricsProperties(nodeName = "test-node")
        val client = io.mockk.mockk<io.fabric8.kubernetes.client.KubernetesClient>(relaxed = true)
        val watcher = PodWatcher(client, resolver, props)
        assertTrue(watcher is PodProvider)
        assertTrue(watcher.getDiscoveredPods().isEmpty())
    }
}
