package com.internal.kpodmetrics.health

import com.internal.kpodmetrics.collector.MetricsCollectorService
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Test
import org.springframework.boot.actuate.health.Status
import java.time.Instant
import kotlin.test.assertEquals

class CollectionHealthIndicatorTest {

    private val service = mockk<MetricsCollectorService>()

    @Test
    fun `reports UNKNOWN before first collection cycle`() {
        every { service.getLastSuccessfulCycle() } returns null

        val indicator = CollectionHealthIndicator(service, 30000)
        val health = indicator.health()

        assertEquals(Status.UNKNOWN, health.status)
    }

    @Test
    fun `reports UP when last cycle is recent`() {
        every { service.getLastSuccessfulCycle() } returns Instant.now().minusSeconds(10)

        val indicator = CollectionHealthIndicator(service, 30000)
        val health = indicator.health()

        assertEquals(Status.UP, health.status)
    }

    @Test
    fun `reports DOWN when last cycle is stale`() {
        // 3x poll interval = 90s threshold, set last cycle to 120s ago
        every { service.getLastSuccessfulCycle() } returns Instant.now().minusSeconds(120)

        val indicator = CollectionHealthIndicator(service, 30000)
        val health = indicator.health()

        assertEquals(Status.DOWN, health.status)
    }
}
