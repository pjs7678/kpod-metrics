package com.internal.kpodmetrics.analysis

import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class AnomalyEndpointTest {

    private val anomalyService = mockk<AnomalyService>()
    private val endpoint = AnomalyEndpoint(anomalyService)

    @Test
    fun `detect delegates to AnomalyService with parsed parameters`() {
        val report = AnomalyReport(
            app = "myapp", namespace = "prod",
            timeRange = "test", sensitivity = "medium",
            healthScore = 85, severity = Severity.INFO,
            timelines = emptyList(), crossCorrelations = emptyList(),
            problemStartedAt = null, summary = "Healthy"
        )
        every { anomalyService.detect(any(), any(), any(), any(), any()) } returns report

        val result = endpoint.detect("myapp", "now-1h", "now", "medium", "prod")

        assertNotNull(result)
        assertEquals("myapp", result.app)
        assertEquals("prod", result.namespace)
        verify { anomalyService.detect("myapp", "prod", any(), any(), "medium") }
    }

    @Test
    fun `detect uses defaults when optional parameters are null`() {
        val report = AnomalyReport(
            app = "app1", namespace = "default",
            timeRange = "test", sensitivity = "medium",
            healthScore = 100, severity = Severity.INFO,
            timelines = emptyList(), crossCorrelations = emptyList(),
            problemStartedAt = null, summary = "OK"
        )
        every { anomalyService.detect(any(), any(), any(), any(), any()) } returns report

        val result = endpoint.detect("app1", null, null, null, null)

        assertNotNull(result)
        verify { anomalyService.detect("app1", "default", any(), any(), "medium") }
    }

    @Test
    fun `validateSensitivity accepts low medium high`() {
        assertEquals("low", AnomalyEndpoint.validateSensitivity("low"))
        assertEquals("medium", AnomalyEndpoint.validateSensitivity("medium"))
        assertEquals("high", AnomalyEndpoint.validateSensitivity("high"))
    }

    @Test
    fun `validateSensitivity rejects invalid values`() {
        val ex = assertThrows<IllegalArgumentException> {
            AnomalyEndpoint.validateSensitivity("extreme")
        }
        assertEquals(true, ex.message!!.contains("Invalid sensitivity"))
    }
}
