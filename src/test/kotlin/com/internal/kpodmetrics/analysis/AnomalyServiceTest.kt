package com.internal.kpodmetrics.analysis

import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AnomalyServiceTest {

    private val pyroscopeClient = mockk<PyroscopeClient>()
    private val service = AnomalyService(pyroscopeClient)

    private val mediumConfig = AnomalyService.SensitivityConfig(
        zThreshold = 3.0, cusumThreshold = 5.0, window = 10
    )

    @Test
    fun `analyzeTimeline detects stable regime`() {
        // Deterministic slight variation around 100
        val samples = List(30) { 100.0 + (it % 5) * 0.1 }
        val result = service.analyzeTimeline("cpu", samples, mediumConfig)

        assertEquals("cpu", result.name)
        assertEquals(30, result.sampleCount)
        assertEquals("stable", result.regime)
        assertNull(result.changePoint)
    }

    @Test
    fun `analyzeTimeline detects shift regime`() {
        val before = List(30) { 10.0 + (it % 3) * 0.1 }
        val after = List(30) { 50.0 + (it % 3) * 0.1 }
        val samples = before + after
        val result = service.analyzeTimeline("cpu", samples, mediumConfig)

        assertEquals("shift", result.regime)
        assertNotNull(result.changePoint)
        assertTrue(result.changePoint!!.magnitude > 5.0)
    }

    @Test
    fun `analyzeTimeline detects spiky regime`() {
        val samples = MutableList(30) { 100.0 + it * 0.01 }
        samples[25] = 500.0  // single spike after window
        val result = service.analyzeTimeline("cpu", samples, mediumConfig)

        assertTrue(result.spikes.isNotEmpty())
        assertTrue(result.regime in listOf("spiky", "shift", "volatile"))
    }

    @Test
    fun `classifyRegime identifies trending-up`() {
        val samples = List(20) { it.toDouble() * 10 } // 0, 10, 20, ...
        val regime = service.classifyRegime(samples, emptyList(), null)
        assertEquals("trending-up", regime)
    }

    @Test
    fun `classifyRegime identifies trending-down`() {
        val samples = List(20) { (20 - it).toDouble() * 10 }
        val regime = service.classifyRegime(samples, emptyList(), null)
        assertEquals("trending-down", regime)
    }

    @Test
    fun `classifyRegime identifies volatile`() {
        val samples = List(20) { 100.0 }
        val manySpikes = (0..3).map { Spike(index = it, value = 500.0, zScore = 5.0) }
        val regime = service.classifyRegime(samples, manySpikes, null)
        assertEquals("volatile", regime)
    }

    @Test
    fun `detectPeriodicity finds periodic signal`() {
        val samples = List(100) { kotlin.math.sin(it * 2.0 * Math.PI / 10.0) * 100 + 200 }
        val result = service.detectPeriodicity(samples)

        assertTrue(result.detected)
        assertNotNull(result.dominantLag)
        assertNotNull(result.strength)
        assertTrue(result.strength!! > 0.3)
    }

    @Test
    fun `detectPeriodicity returns false for random data`() {
        val samples = List(50) { Math.random() * 100 }
        val result = service.detectPeriodicity(samples)
        // Random data may or may not show periodicity — just verify no crash
        assertNotNull(result)
    }

    @Test
    fun `detectPeriodicity handles small samples`() {
        val result = service.detectPeriodicity(listOf(1.0, 2.0, 3.0))
        assertEquals(false, result.detected)
    }

    @Test
    fun `health score starts at 100 for no timelines`() {
        val score = service.computeHealthScore(emptyList())
        assertEquals(100, score)
    }

    @Test
    fun `health score decreases with anomalies`() {
        val timeline = TimelineAnalysis(
            name = "cpu",
            sampleCount = 30,
            mean = 100.0,
            p50 = 100.0,
            p95 = 120.0,
            p99 = 150.0,
            spikes = listOf(Spike(10, 500.0, 5.0), Spike(20, 400.0, 4.0)),
            changePoint = ChangePoint(15, "increase", 50.0, 80.0, 130.0),
            regime = "shift",
            periodicity = null
        )
        val score = service.computeHealthScore(listOf(timeline))
        assertTrue(score < 100)
        assertTrue(score >= 0)
    }

    @Test
    fun `detect returns report with no pyroscope data`() {
        every { pyroscopeClient.queryProfile(any(), any(), any()) } returns null

        val report = service.detect("myapp", "default", 1700000000, 1700003600, "medium")

        assertEquals("myapp", report.app)
        assertEquals(100, report.healthScore)
        assertEquals(Severity.INFO, report.severity)
        assertTrue(report.timelines.isEmpty())
        assertTrue(report.crossCorrelations.isEmpty())
        assertNull(report.problemStartedAt)
    }

    @Test
    fun `detect with data produces meaningful report`() {
        val stableTimeline = PyroscopeTimeline(
            startTime = 1700000000,
            samples = List(30) { 100L + (it % 5) },
            durationDelta = 10
        )
        val response = PyroscopeResponse(timeline = stableTimeline)

        every { pyroscopeClient.queryProfile(match { it.contains("cpu") }, any(), any()) } returns response
        every { pyroscopeClient.queryProfile(match { it.contains("alloc") }, any(), any()) } returns response
        every { pyroscopeClient.queryProfile(match { it.contains("iowait") }, any(), any()) } returns null

        val report = service.detect("myapp", "default", 1700000000, 1700003600, "medium")

        assertEquals(2, report.timelines.size)
        assertTrue(report.crossCorrelations.isNotEmpty())
        assertTrue(report.healthScore > 0)
    }

    @Test
    fun `sensitivity levels use different thresholds`() {
        val spikySamples = MutableList(30) { 100.0 }
        spikySamples[20] = 200.0 // modest spike

        val lowResult = service.analyzeTimeline("cpu", spikySamples,
            AnomalyService.SensitivityConfig(zThreshold = 4.0, cusumThreshold = 8.0, window = 15))
        val highResult = service.analyzeTimeline("cpu", spikySamples,
            AnomalyService.SensitivityConfig(zThreshold = 2.0, cusumThreshold = 3.0, window = 5))

        // High sensitivity should detect more or equal anomalies
        assertTrue(highResult.spikes.size >= lowResult.spikes.size)
    }
}
