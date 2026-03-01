package com.internal.kpodmetrics.health

import com.internal.kpodmetrics.collector.MetricsCollectorService
import org.springframework.boot.actuate.health.Health
import org.springframework.boot.actuate.health.HealthIndicator

class CollectorConfigHealthIndicator(
    private val collectorService: MetricsCollectorService
) : HealthIndicator {

    override fun health(): Health {
        val count = collectorService.getEnabledCollectorCount()
        return if (count > 0) {
            Health.up()
                .withDetail("enabledCollectors", count)
                .build()
        } else {
            Health.down()
                .withDetail("reason", "All collectors are disabled — no metrics will be collected")
                .withDetail("enabledCollectors", 0)
                .build()
        }
    }
}
