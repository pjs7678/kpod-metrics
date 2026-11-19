package com.internal.kpodmetrics.collector

import io.fabric8.kubernetes.api.model.*
import io.fabric8.kubernetes.client.KubernetesClient
import io.fabric8.kubernetes.client.dsl.MixedOperation
import io.fabric8.kubernetes.client.dsl.NonNamespaceOperation
import io.fabric8.kubernetes.client.dsl.PodResource
import io.fabric8.kubernetes.client.dsl.ServiceResource
import io.fabric8.kubernetes.client.informers.SharedIndexInformer
import io.mockk.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.CompletableFuture

class PodIpResolverTest {

    private lateinit var client: KubernetesClient
    private lateinit var podNsOp: NonNamespaceOperation<Pod, PodList, PodResource>
    private lateinit var svcNsOp: NonNamespaceOperation<Service, ServiceList, ServiceResource<Service>>
    private lateinit var resolver: PodIpResolver

    private fun pod(name: String, ip: String?, hostNetwork: Boolean = false, phase: String = "Running") = Pod().apply {
        metadata = ObjectMeta().apply { this.name = name; namespace = "default" }
        spec = PodSpec().apply { this.hostNetwork = hostNetwork }
        status = PodStatus().apply { podIP = ip; this.phase = phase }
    }

    private fun svc(name: String, ip: String) = Service().apply {
        metadata = ObjectMeta().apply { this.name = name; namespace = "default" }
        spec = ServiceSpec().apply { clusterIP = ip }
    }

    @BeforeEach
    fun setup() {
        client = mockk(relaxed = true)
        val podOp = mockk<MixedOperation<Pod, PodList, PodResource>>(relaxed = true)
        podNsOp = mockk(relaxed = true)
        every { client.pods() } returns podOp
        every { podOp.inAnyNamespace() } returns podNsOp
        val svcOp = mockk<MixedOperation<Service, ServiceList, ServiceResource<Service>>>(relaxed = true)
        svcNsOp = mockk(relaxed = true)
        every { client.services() } returns svcOp
        every { svcOp.inAnyNamespace() } returns svcNsOp
        resolver = PodIpResolver(client)
    }

    @Test
    fun `maps pod and service IPs from informer events`() {
        resolver.onPod(null, pod("my-pod", "10.0.0.1"))
        resolver.onService(null, svc("my-svc", "10.96.0.1"))

        assertEquals(PeerInfo(podName = "my-pod", namespace = "default"), resolver.resolve("10.0.0.1"))
        assertEquals(PeerInfo(serviceName = "my-svc", namespace = "default"), resolver.resolve("10.96.0.1"))
        assertNull(resolver.resolve("192.168.1.1"))
    }

    @Test
    fun `follows IP changes and deletions`() {
        val pending = pod("p", null)
        val running = pod("p", "10.0.0.5")
        resolver.onPod(null, pending)
        assertEquals(0 to 0, resolver.size())
        resolver.onPod(pending, running)
        assertEquals("p", resolver.resolve("10.0.0.5")?.podName)
        resolver.onPod(running, null)
        assertNull(resolver.resolve("10.0.0.5"))
    }

    @Test
    fun `deleting an old pod does not evict a new pod that reused its IP`() {
        val old = pod("old", "10.0.0.7")
        resolver.onPod(null, old)
        resolver.onPod(null, pod("new", "10.0.0.7"))
        resolver.onPod(old, null) // late delete event for the old pod
        assertEquals("new", resolver.resolve("10.0.0.7")?.podName)
    }

    @Test
    fun `skips hostNetwork and finished pods and headless services`() {
        resolver.onPod(null, pod("hostnet", "192.168.5.1", hostNetwork = true))
        resolver.onPod(null, pod("done", "10.0.0.9", phase = "Succeeded"))
        resolver.onService(null, svc("headless", "None"))
        assertEquals(0 to 0, resolver.size())
    }

    @Test
    fun `refresh starts each informer once and never lists`() {
        val podInformer = mockk<SharedIndexInformer<Pod>>(relaxed = true)
        val svcInformer = mockk<SharedIndexInformer<Service>>(relaxed = true)
        every { podNsOp.runnableInformer(any()) } returns podInformer
        every { svcNsOp.runnableInformer(any()) } returns svcInformer
        every { podInformer.addEventHandler(any()) } returns podInformer
        every { svcInformer.addEventHandler(any()) } returns svcInformer
        every { podInformer.start() } returns CompletableFuture.completedFuture(null)
        every { svcInformer.start() } returns CompletableFuture.completedFuture(null)

        repeat(5) { resolver.refresh() }

        verify(exactly = 1) { podInformer.start() }
        verify(exactly = 1) { svcInformer.start() }
        verify(exactly = 0) { podNsOp.list() }
        verify(exactly = 0) { svcNsOp.list() }
        resolver.close()
        verify { podInformer.stop() }
    }

    @Test
    fun `a failing services informer does not prevent pod resolution`() {
        val podInformer = mockk<SharedIndexInformer<Pod>>(relaxed = true)
        every { podNsOp.runnableInformer(any()) } returns podInformer
        every { podInformer.addEventHandler(any()) } returns podInformer
        every { podInformer.start() } returns CompletableFuture.completedFuture(null)
        every { svcNsOp.runnableInformer(any()) } throws RuntimeException("services is forbidden")

        resolver.refresh()
        resolver.onPod(null, pod("my-pod", "10.0.0.1"))
        assertEquals("my-pod", resolver.resolve("10.0.0.1")?.podName)
    }
}
