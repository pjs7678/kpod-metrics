package com.internal.kpodmetrics.health

import com.internal.kpodmetrics.discovery.PodProvider
import org.springframework.boot.actuate.health.Health
import org.springframework.boot.actuate.health.HealthIndicator
import java.time.Duration
import java.time.Instant

class DiscoveryHealthIndicator(
    private val podProvider: PodProvider,
    private val startTime: Instant = Instant.now(),
    private val gracePeriod: Duration = Duration.ofSeconds(60)
) : HealthIndicator {

    override fun health(): Health {
        val podCount = podProvider.getDiscoveredPods().size
        val uptime = Duration.between(startTime, Instant.now())

        return when {
            podCount > 0 -> Health.up()
                .withDetail("discoveredPods", podCount)
                .build()
            uptime < gracePeriod -> Health.unknown()
                .withDetail("reason", "Waiting for pod discovery")
                .withDetail("uptimeSeconds", uptime.seconds)
                .withDetail("gracePeriodSeconds", gracePeriod.seconds)
                .build()
            else -> Health.down()
                .withDetail("reason", "No pods discovered after grace period")
                .withDetail("uptimeSeconds", uptime.seconds)
                .build()
        }
    }
}
