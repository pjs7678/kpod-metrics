package com.internal.kpodmetrics.health

import com.internal.kpodmetrics.collector.*
import com.internal.kpodmetrics.config.CollectorOverrides
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import io.mockk.mockk
import org.junit.jupiter.api.Test
import org.springframework.boot.actuate.health.Status
import kotlin.test.assertEquals

class CollectorConfigHealthIndicatorTest {

    private fun buildService(overrides: CollectorOverrides = CollectorOverrides()): MetricsCollectorService {
        return MetricsCollectorService(
            cpuCollector = mockk(relaxed = true),
            netCollector = mockk(relaxed = true),
            syscallCollector = mockk(relaxed = true),
            biolatencyCollector = mockk(relaxed = true),
            cachestatCollector = mockk(relaxed = true),
            tcpdropCollector = mockk(relaxed = true),
            hardirqsCollector = mockk(relaxed = true),
            softirqsCollector = mockk(relaxed = true),
            execsnoopCollector = mockk(relaxed = true),
            registry = SimpleMeterRegistry(),
            collectorOverrides = overrides
        )
    }

    @Test
    fun `reports UP when collectors are enabled`() {
        val service = buildService()
        val indicator = CollectorConfigHealthIndicator(service)
        val health = indicator.health()
        assertEquals(Status.UP, health.status)
        assertEquals(9, health.details["enabledCollectors"])
        service.close()
    }

    @Test
    fun `reports DOWN when all collectors are disabled`() {
        val overrides = CollectorOverrides(
            cpu = false, network = false, syscall = false,
            biolatency = false, cachestat = false, tcpdrop = false,
            hardirqs = false, softirqs = false, execsnoop = false
        )
        val service = buildService(overrides)
        val indicator = CollectorConfigHealthIndicator(service)
        val health = indicator.health()
        assertEquals(Status.DOWN, health.status)
        assertEquals(0, health.details["enabledCollectors"])
        service.close()
    }
}
