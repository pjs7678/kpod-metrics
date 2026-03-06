package com.internal.kpodmetrics.analysis

import org.junit.jupiter.api.Test
import kotlin.math.abs
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TimeSeriesStatsTest {

    @Test
    fun `percentile on sorted list`() {
        val data = listOf(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0)
        assertEquals(1.0, TimeSeriesStats.percentile(data, 0.0))
        assertEquals(10.0, TimeSeriesStats.percentile(data, 100.0))
        assertTrue(abs(TimeSeriesStats.percentile(data, 50.0) - 5.5) < 0.01)
    }

    @Test
    fun `percentile on empty list returns zero`() {
        assertEquals(0.0, TimeSeriesStats.percentile(emptyList(), 50.0))
    }

    @Test
    fun `percentile on single element`() {
        assertEquals(42.0, TimeSeriesStats.percentile(listOf(42.0), 99.0))
    }

    @Test
    fun `rolling mean and std`() {
        val data = listOf(1.0, 2.0, 3.0, 4.0, 5.0)
        val (means, stds) = TimeSeriesStats.rollingMeanStd(data, 3)
        assertEquals(3, means.size)
        assertEquals(2.0, means[0])
        assertEquals(3.0, means[1])
        assertEquals(4.0, means[2])
        assertTrue(stds.all { it > 0 })
    }

    @Test
    fun `rolling mean std returns empty for insufficient data`() {
        val (means, stds) = TimeSeriesStats.rollingMeanStd(listOf(1.0), 3)
        assertTrue(means.isEmpty())
        assertTrue(stds.isEmpty())
    }

    @Test
    fun `z-score spikes detects outliers`() {
        // Use slight variation so std > 0
        val data = MutableList(20) { 10.0 + it * 0.01 }
        data.add(100.0) // spike
        val spikes = TimeSeriesStats.zScoreSpikes(data, 10, 2.0)
        assertTrue(spikes.isNotEmpty())
        assertEquals(20, spikes.last().index)
    }

    @Test
    fun `z-score spikes returns empty for flat data`() {
        val data = List(30) { 5.0 }
        val spikes = TimeSeriesStats.zScoreSpikes(data, 10, 2.0)
        assertTrue(spikes.isEmpty())
    }

    @Test
    fun `cusum detects change point`() {
        val before = List(50) { 10.0 + (it % 3) * 0.1 }
        val after = List(50) { 30.0 + (it % 3) * 0.1 }
        val data = before + after
        val cp = TimeSeriesStats.cusumChangePoint(data, 0.5, 3.0)
        assertNotNull(cp)
        assertTrue(cp.magnitude > 5.0, "Expected significant magnitude, got ${cp.magnitude}")
    }

    @Test
    fun `cusum returns null for stable data`() {
        val data = List(100) { 5.0 }
        assertNull(TimeSeriesStats.cusumChangePoint(data))
    }

    @Test
    fun `autocorrelation of periodic signal`() {
        // Sine wave has autocorrelation peak at period
        val data = List(100) { kotlin.math.sin(it * 2.0 * Math.PI / 10.0) }
        val acf = TimeSeriesStats.autocorrelation(data, 20)
        assertTrue(acf.isNotEmpty())
        // Lag 10 should be close to 1.0 (full period)
        assertTrue(acf[9] > 0.8, "Expected high autocorrelation at lag 10, got ${acf[9]}")
    }

    @Test
    fun `pearson correlation of identical series`() {
        val a = listOf(1.0, 2.0, 3.0, 4.0, 5.0)
        val r = TimeSeriesStats.pearsonCorrelation(a, a)
        assertTrue(abs(r - 1.0) < 0.001)
    }

    @Test
    fun `pearson correlation of inverse series`() {
        val a = listOf(1.0, 2.0, 3.0, 4.0, 5.0)
        val b = listOf(5.0, 4.0, 3.0, 2.0, 1.0)
        val r = TimeSeriesStats.pearsonCorrelation(a, b)
        assertTrue(abs(r + 1.0) < 0.001)
    }

    @Test
    fun `pearson correlation of uncorrelated series`() {
        val r = TimeSeriesStats.pearsonCorrelation(listOf(1.0), listOf(2.0))
        assertEquals(0.0, r)
    }
}
