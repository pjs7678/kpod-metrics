package com.internal.kpodmetrics.collector

import io.fabric8.kubernetes.api.model.*
import io.fabric8.kubernetes.client.KubernetesClient
import io.fabric8.kubernetes.client.dsl.MixedOperation
import io.fabric8.kubernetes.client.dsl.NonNamespaceOperation
import io.mockk.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class PodIpResolverTest {

    private lateinit var client: KubernetesClient
    private lateinit var resolver: PodIpResolver

    @BeforeEach
    fun setup() {
        client = mockk(relaxed = true)
        resolver = PodIpResolver(client)

        val pod = Pod().apply {
            metadata = ObjectMeta().apply {
                name = "my-pod"
                namespace = "default"
            }
            status = PodStatus().apply {
                podIP = "10.0.0.1"
            }
        }

        val podList = PodList().apply {
            items = listOf(pod)
        }

        val svc = Service().apply {
            metadata = ObjectMeta().apply {
                name = "my-svc"
                namespace = "default"
            }
            spec = ServiceSpec().apply {
                clusterIP = "10.96.0.1"
            }
        }

        val svcList = ServiceList().apply {
            items = listOf(svc)
        }

        val podOp = mockk<MixedOperation<Pod, PodList, *, *>>(relaxed = true)
        val podNsOp = mockk<NonNamespaceOperation<Pod, PodList, *>>(relaxed = true)
        every { client.pods() } returns podOp
        every { podOp.inAnyNamespace() } returns podNsOp
        every { podNsOp.list() } returns podList

        val svcOp = mockk<MixedOperation<Service, ServiceList, *, *>>(relaxed = true)
        val svcNsOp = mockk<NonNamespaceOperation<Service, ServiceList, *>>(relaxed = true)
        every { client.services() } returns svcOp
        every { svcOp.inAnyNamespace() } returns svcNsOp
        every { svcNsOp.list() } returns svcList
    }

    @Test
    fun `resolve returns PeerInfo for known pod IP after refresh`() {
        resolver.refresh()

        val result = resolver.resolve("10.0.0.1")
        assertNotNull(result)
        assertEquals("my-pod", result!!.podName)
        assertEquals("default", result.namespace)
        assertNull(result.serviceName)
    }

    @Test
    fun `resolve returns null for unknown IP`() {
        resolver.refresh()

        val result = resolver.resolve("192.168.1.1")
        assertNull(result)
    }

    @Test
    fun `resolve returns PeerInfo for service ClusterIP after refresh`() {
        resolver.refresh()

        val result = resolver.resolve("10.96.0.1")
        assertNotNull(result)
        assertEquals("my-svc", result!!.serviceName)
        assertEquals("default", result.namespace)
        assertNull(result.podName)
    }

    @Test
    fun `resolve returns null before refresh is called`() {
        val result = resolver.resolve("10.0.0.1")
        assertNull(result)
    }
}
