package com.internal.kpodmetrics

import com.internal.kpodmetrics.collector.Log2Histograms
import io.micrometer.core.instrument.Tags
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry
import io.micrometer.registry.otlp.OtlpMeterRegistry
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.ApplicationContext
import org.springframework.test.context.TestPropertySource
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.assertFalse
import kotlin.test.assertEquals

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

/** With metrics export enabled (off by default in tests), as in production. */
@SpringBootTest
@AutoConfigureObservability
@TestPropertySource(properties = [
    "kpod.node-name=test-node",
    "kpod.bpf.enabled=false"
])
class KpodMetricsPrometheusExportTest {

    @Autowired
    private lateinit var context: ApplicationContext

    @Test
    fun `BPF latency histograms are exposed on the Prometheus scrape`() {
        val histograms = context.getBean(Log2Histograms::class.java)
        val slots = LongArray(Log2Histograms.SLOTS).also { it[18] = 7 }
        histograms.observe(Log2Histograms.SYSCALL,
            Tags.of("namespace", "ns", "pod", "ctx-test", "container", "c", "node", "n", "syscall", "read"),
            slots, 7L * 300_000)
        val text = context.getBean(PrometheusMeterRegistry::class.java).scrape()
        assertTrue(text.contains("# TYPE kpod_syscall_latency_seconds histogram"), text.take(500))
        assertTrue(text.contains("""kpod_syscall_latency_seconds_bucket{container="c",namespace="ns",node="n",pod="ctx-test",syscall="read",le="+Inf"} 7"""))
        assertTrue(text.contains("jvm_"), "Micrometer meters still present alongside")
        histograms.removePod("ctx-test", "ns")
    }

    @Test
    fun `no OTLP registry is auto-configured when kpod OTLP is disabled`() {
        // Spring Boot's own OTLP export would otherwise push to localhost:4318 every minute
        assertTrue(context.getBeansOfType(OtlpMeterRegistry::class.java).isEmpty())
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

    @Test
    fun `BPF latency histograms are mirrored to OTLP as timers`() {
        val histograms = context.getBean(Log2Histograms::class.java)
        histograms.observe(Log2Histograms.RUNQUEUE,
            Tags.of("namespace", "ns", "pod", "otlp-test", "container", "c", "node", "n"),
            LongArray(Log2Histograms.SLOTS).also { it[12] = 3 }, 3L * 5_000)
        val otlp = context.getBean(OtlpMeterRegistry::class.java)
        assertEquals(3.0, otlp.get("kpod.cpu.runqueue.latency").tag("pod", "otlp-test").functionTimer().count())
        histograms.removePod("otlp-test", "ns")
    }
}
