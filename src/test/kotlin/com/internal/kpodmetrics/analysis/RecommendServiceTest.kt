package com.internal.kpodmetrics.analysis

import io.fabric8.kubernetes.client.KubernetesClient
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class RecommendServiceTest {

    private val pyroscopeClient = mockk<PyroscopeClient>()
    private val kubernetesClient = mockk<KubernetesClient>(relaxed = true)
    private val registry = SimpleMeterRegistry()
    private val service = RecommendService(pyroscopeClient, kubernetesClient, registry)

    @Test
    fun `cpu recommendation from millicores`() {
        val millicores = listOf(50.0, 60.0, 70.0, 80.0, 90.0, 100.0, 110.0, 120.0, 130.0, 200.0)
        val current = RecommendService.CurrentResources(
            cpuRequest = "500m", cpuLimit = "1000m",
            memRequest = null, memLimit = null
        )

        val rec = service.computeCpuRecommendation(millicores, current, 95)

        assertNotNull(rec)
        assertEquals("cpu", rec.resource)
        assertEquals(SizingVerdict.OVER_PROVISIONED, rec.verdict)
        assertTrue(rec.recommended.request.endsWith("m"))
        assertTrue(rec.recommended.limit.endsWith("m"))
    }

    @Test
    fun `cpu recommendation without current resources`() {
        val millicores = listOf(100.0, 200.0, 300.0, 400.0, 500.0)

        val rec = service.computeCpuRecommendation(millicores, null, 95)

        assertNotNull(rec)
        assertEquals(SizingVerdict.UNDER_PROVISIONED, rec.verdict)
        assertNull(rec.current)
    }

    @Test
    fun `cpu recommendation returns null for empty data`() {
        val rec = service.computeCpuRecommendation(emptyList(), null, 95)
        assertNull(rec)
    }

    @Test
    fun `memory recommendation from allocation rates`() {
        val rates = List(20) { (128.0 * 1024 * 1024) + it * 1024 * 1024 } // ~128-148Mi
        val current = RecommendService.CurrentResources(
            cpuRequest = null, cpuLimit = null,
            memRequest = "64Mi", memLimit = "128Mi"
        )

        val rec = service.computeMemoryRecommendation(rates, current, 95)

        assertNotNull(rec)
        assertEquals("memory", rec.resource)
        assertEquals(SizingVerdict.UNDER_PROVISIONED, rec.verdict)
    }

    @Test
    fun `memory recommendation returns null for empty data`() {
        val rec = service.computeMemoryRecommendation(emptyList(), null, 95)
        assertNull(rec)
    }

    @Test
    fun `right-sized verdict when current matches recommendation`() {
        val millicores = listOf(90.0, 95.0, 100.0, 105.0, 110.0)
        val current = RecommendService.CurrentResources(
            cpuRequest = "100m", cpuLimit = "150m",
            memRequest = null, memLimit = null
        )

        val rec = service.computeCpuRecommendation(millicores, current, 95)

        assertNotNull(rec)
        assertEquals(SizingVerdict.RIGHT_SIZED, rec.verdict)
    }

    @Test
    fun `parseMillicores handles different formats`() {
        assertEquals(500L, RecommendService.parseMillicores("500m"))
        assertEquals(1000L, RecommendService.parseMillicores("1"))
        assertEquals(2000L, RecommendService.parseMillicores("2"))
        assertEquals(0L, RecommendService.parseMillicores("invalid"))
    }

    @Test
    fun `parseBytes handles K8s resource formats`() {
        assertEquals(1024L * 1024 * 1024, RecommendService.parseBytes("1Gi"))
        assertEquals(256L * 1024 * 1024, RecommendService.parseBytes("256Mi"))
        assertEquals(512L * 1024, RecommendService.parseBytes("512Ki"))
        assertEquals(0L, RecommendService.parseBytes("invalid"))
    }

    @Test
    fun `formatBytes produces K8s-style output`() {
        assertEquals("1Gi", RecommendService.formatBytes(1024L * 1024 * 1024))
        assertEquals("256Mi", RecommendService.formatBytes(256L * 1024 * 1024))
        assertEquals("512Ki", RecommendService.formatBytes(512L * 1024))
        assertEquals("100", RecommendService.formatBytes(100))
    }

    @Test
    fun `parseTimeExpr handles relative expressions`() {
        val now = 1700000000L
        assertEquals(now, RecommendEndpoint.parseTimeExpr("now", now))
        assertEquals(now - 1800, RecommendEndpoint.parseTimeExpr("now-30m", now))
        assertEquals(now - 3600, RecommendEndpoint.parseTimeExpr("now-1h", now))
        assertEquals(now - 86400, RecommendEndpoint.parseTimeExpr("now-1d", now))
        assertEquals(now - 60, RecommendEndpoint.parseTimeExpr("now-60s", now))
    }

    @Test
    fun `parseTimeExpr handles epoch seconds`() {
        val now = 1700000000L
        assertEquals(1699999000L, RecommendEndpoint.parseTimeExpr("1699999000", now))
    }

    @Test
    fun `recommend returns report with no data`() {
        every { pyroscopeClient.queryProfile(any(), any(), any()) } returns null
        every { kubernetesClient.pods() } returns mockk(relaxed = true)

        val report = service.recommend("myapp", "default", 1700000000, 1700001800, 95)

        assertEquals("myapp", report.app)
        assertEquals("default", report.namespace)
        assertTrue(report.recommendations.isEmpty())
        assertNull(report.kubectlPatch)
        assertTrue(report.summary.contains("Insufficient"))
    }
}
