package com.internal.kpodmetrics.analysis

import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class RecommendEndpointTest {

    private val recommendService = mockk<RecommendService>()
    private val endpoint = RecommendEndpoint(recommendService)

    @Test
    fun `recommend delegates to RecommendService with parsed parameters`() {
        val report = RecommendReport(
            app = "myapp", namespace = "prod",
            timeRange = "test", confidence = 95,
            recommendations = emptyList(), kubectlPatch = null,
            summary = "No data"
        )
        every { recommendService.recommend(any(), any(), any(), any(), any()) } returns report

        val result = endpoint.recommend("myapp", "now-30m", "now", 95, "prod")

        assertNotNull(result)
        assertEquals("myapp", result.app)
        verify { recommendService.recommend("myapp", "prod", any(), any(), 95) }
    }

    @Test
    fun `recommend uses defaults when optional parameters are null`() {
        val report = RecommendReport(
            app = "app1", namespace = "default",
            timeRange = "test", confidence = 95,
            recommendations = emptyList(), kubectlPatch = null,
            summary = "OK"
        )
        every { recommendService.recommend(any(), any(), any(), any(), any()) } returns report

        val result = endpoint.recommend("app1", null, null, null, null)

        assertNotNull(result)
        verify { recommendService.recommend("app1", "default", any(), any(), 95) }
    }

    @Test
    fun `recommend clamps confidence to valid range`() {
        val report = RecommendReport(
            app = "app1", namespace = "default",
            timeRange = "test", confidence = 100,
            recommendations = emptyList(), kubectlPatch = null,
            summary = "OK"
        )
        every { recommendService.recommend(any(), any(), any(), any(), any()) } returns report

        endpoint.recommend("app1", null, null, 150, null)
        verify { recommendService.recommend("app1", "default", any(), any(), 100) }

        endpoint.recommend("app1", null, null, -5, null)
        verify { recommendService.recommend("app1", "default", any(), any(), 1) }
    }

    @Test
    fun `parseTimeExpr handles now`() {
        val now = 1700000000L
        assertEquals(now, RecommendEndpoint.parseTimeExpr("now", now))
    }

    @Test
    fun `parseTimeExpr handles relative expressions`() {
        val now = 1700000000L
        assertEquals(now - 3600, RecommendEndpoint.parseTimeExpr("now-1h", now))
        assertEquals(now - 1800, RecommendEndpoint.parseTimeExpr("now-30m", now))
        assertEquals(now - 60, RecommendEndpoint.parseTimeExpr("now-60s", now))
        assertEquals(now - 172800, RecommendEndpoint.parseTimeExpr("now-2d", now))
    }

    @Test
    fun `parseTimeExpr handles epoch seconds`() {
        val now = 1700000000L
        assertEquals(1699999000, RecommendEndpoint.parseTimeExpr("1699999000", now))
    }

    @Test
    fun `parseTimeExpr rejects invalid expressions`() {
        val ex = assertThrows<IllegalArgumentException> {
            RecommendEndpoint.parseTimeExpr("yesterday", 1700000000L)
        }
        assertTrue(ex.message!!.contains("Invalid time expression"))
    }

    @Test
    fun `validateLabel accepts valid labels`() {
        assertEquals("myapp", RecommendEndpoint.validateLabel("myapp"))
        assertEquals("my-app.v2", RecommendEndpoint.validateLabel("my-app.v2"))
        assertEquals("a", RecommendEndpoint.validateLabel("a"))
    }

    @Test
    fun `validateLabel rejects invalid labels`() {
        assertThrows<IllegalArgumentException> {
            RecommendEndpoint.validateLabel("")
        }
        assertThrows<IllegalArgumentException> {
            RecommendEndpoint.validateLabel("-invalid")
        }
        assertThrows<IllegalArgumentException> {
            RecommendEndpoint.validateLabel("has spaces")
        }
    }
}
