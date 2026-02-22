package com.internal.kpodmetrics.k8s

import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.PodInfo
import com.internal.kpodmetrics.config.FilterProperties
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
}
