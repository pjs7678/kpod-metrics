package com.internal.kpodmetrics

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.ApplicationContext
import org.springframework.test.context.TestPropertySource
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.assertFalse

@SpringBootTest
@TestPropertySource(properties = [
    "kpod.node-name=test-node",
    "kpod.bpf.enabled=false"
])
class KpodMetricsApplicationTest {

    @Autowired
    private lateinit var context: ApplicationContext

    @Test
    fun contextLoads() {
    }

    @Test
    fun `BPF-dependent beans are not created when BPF disabled`() {
        assertFalse(context.containsBean("metricsCollectorService"))
        assertFalse(context.containsBean("collectorConfigHealthIndicator"))
    }

    @Test
    fun `OTLP registry is not created when disabled`() {
        assertFalse(context.containsBean("otlpMeterRegistry"))
    }

    @Test
    fun `discovery health indicator is always created`() {
        assertTrue(context.containsBean("discoveryHealthIndicator"))
    }
}

@SpringBootTest
@TestPropertySource(properties = [
    "kpod.node-name=test-node",
    "kpod.bpf.enabled=false",
    "kpod.otlp.enabled=true",
    "kpod.otlp.endpoint=http://localhost:4318/v1/metrics"
])
class KpodMetricsOtlpEnabledTest {

    @Autowired
    private lateinit var context: ApplicationContext

    @Test
    fun `context loads with OTLP enabled`() {
        assertTrue(context.containsBean("otlpMeterRegistry"))
    }
}
