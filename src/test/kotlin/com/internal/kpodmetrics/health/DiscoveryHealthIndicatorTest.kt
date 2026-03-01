package com.internal.kpodmetrics.health

import com.internal.kpodmetrics.discovery.PodProvider
import com.internal.kpodmetrics.model.DiscoveredPod
import com.internal.kpodmetrics.model.QosClass
import org.junit.jupiter.api.Test
import org.springframework.boot.actuate.health.Status
import java.time.Duration
import java.time.Instant
import kotlin.test.assertEquals

class DiscoveryHealthIndicatorTest {

    private fun providerWith(pods: Map<String, DiscoveredPod>) = object : PodProvider {
        override fun getDiscoveredPods(): Map<String, DiscoveredPod> = pods
    }

    @Test
    fun `reports UP when pods are discovered`() {
        val pod = DiscoveredPod("uid1", "nginx", "default", QosClass.BURSTABLE, emptyList())
        val indicator = DiscoveryHealthIndicator(providerWith(mapOf("uid1" to pod)))
        val health = indicator.health()
        assertEquals(Status.UP, health.status)
        assertEquals(1, health.details["discoveredPods"])
    }

    @Test
    fun `reports UNKNOWN during grace period with no pods`() {
        val indicator = DiscoveryHealthIndicator(
            providerWith(emptyMap()),
            startTime = Instant.now(),
            gracePeriod = Duration.ofMinutes(5)
        )
        val health = indicator.health()
        assertEquals(Status.UNKNOWN, health.status)
    }

    @Test
    fun `reports DOWN after grace period with no pods`() {
        val indicator = DiscoveryHealthIndicator(
            providerWith(emptyMap()),
            startTime = Instant.now().minus(Duration.ofMinutes(10)),
            gracePeriod = Duration.ofSeconds(60)
        )
        val health = indicator.health()
        assertEquals(Status.DOWN, health.status)
    }
}
