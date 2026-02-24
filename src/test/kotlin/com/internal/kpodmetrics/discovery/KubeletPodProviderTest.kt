package com.internal.kpodmetrics.discovery

import com.internal.kpodmetrics.model.QosClass
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class KubeletPodProviderTest {

    private val sampleResponse = """
    {
      "items": [
        {
          "metadata": { "uid": "uid-1", "name": "nginx-abc", "namespace": "default" },
          "status": {
            "qosClass": "Burstable",
            "containerStatuses": [
              { "name": "nginx", "containerID": "containerd://abc123" }
            ]
          }
        },
        {
          "metadata": { "uid": "uid-2", "name": "redis-xyz", "namespace": "cache" },
          "status": {
            "qosClass": "Guaranteed",
            "containerStatuses": [
              { "name": "redis", "containerID": "containerd://def456" }
            ]
          }
        }
      ]
    }
    """.trimIndent()

    @Test
    fun `parsePodListJson parses kubelet response`() {
        val pods = KubeletPodProvider.parsePodListJson(sampleResponse)
        assertEquals(2, pods.size)
        val nginx = pods["uid-1"]!!
        assertEquals("nginx-abc", nginx.name)
        assertEquals("default", nginx.namespace)
        assertEquals(QosClass.BURSTABLE, nginx.qosClass)
        assertEquals(1, nginx.containers.size)
        assertEquals("nginx", nginx.containers[0].name)
        assertEquals("abc123", nginx.containers[0].containerId)

        val redis = pods["uid-2"]!!
        assertEquals(QosClass.GUARANTEED, redis.qosClass)
    }

    @Test
    fun `parsePodListJson handles missing fields gracefully`() {
        val json = """{"items": [{"metadata": {}, "status": {}}]}"""
        val pods = KubeletPodProvider.parsePodListJson(json)
        assertTrue(pods.isEmpty())
    }

    @Test
    fun `reconcile removes stale pods`() {
        val provider = KubeletPodProvider("10.0.0.1", 10250, 30)
        val first = KubeletPodProvider.parsePodListJson(sampleResponse)
        provider.reconcile(first)
        assertEquals(2, provider.getDiscoveredPods().size)

        val second = KubeletPodProvider.parsePodListJson("""
            {"items": [{"metadata": {"uid": "uid-1", "name": "nginx-abc", "namespace": "default"},
            "status": {"qosClass": "Burstable", "containerStatuses": [{"name": "nginx", "containerID": "containerd://abc123"}]}}]}
        """.trimIndent())
        provider.reconcile(second)
        assertEquals(1, provider.getDiscoveredPods().size)
        assertNotNull(provider.getDiscoveredPods()["uid-1"])
        assertNull(provider.getDiscoveredPods()["uid-2"])
    }
}
