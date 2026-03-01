package com.internal.kpodmetrics.health

import com.internal.kpodmetrics.collector.MetricsCollectorService
import org.springframework.boot.actuate.health.Health
import org.springframework.boot.actuate.health.HealthIndicator
import java.time.Duration
import java.time.Instant

class CollectionHealthIndicator(
    private val collectorService: MetricsCollectorService,
    private val pollIntervalMs: Long
) : HealthIndicator {

    override fun health(): Health {
        val lastCycle = collectorService.getLastSuccessfulCycle()
            ?: return Health.unknown().withDetail("reason", "No collection cycle completed yet").build()

        val staleness = Duration.between(lastCycle, Instant.now())
        val threshold = Duration.ofMillis(pollIntervalMs * 3)

        return if (staleness < threshold) {
            Health.up()
                .withDetail("lastCycle", lastCycle.toString())
                .withDetail("stalenessMs", staleness.toMillis())
                .build()
        } else {
            Health.down()
                .withDetail("lastCycle", lastCycle.toString())
                .withDetail("stalenessMs", staleness.toMillis())
                .withDetail("thresholdMs", threshold.toMillis())
                .build()
        }
    }
}
