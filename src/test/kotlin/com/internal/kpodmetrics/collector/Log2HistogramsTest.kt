package com.internal.kpodmetrics.collector

import io.micrometer.core.instrument.Tags
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import io.micrometer.prometheusmetrics.PrometheusConfig
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class Log2HistogramsTest {
    private lateinit var prom: PrometheusMeterRegistry
    private lateinit var hist: Log2Histograms
    private val tags = Tags.of("namespace", "ns", "pod", "p", "container", "c", "node", "n")

    @BeforeEach
    fun setUp() {
        prom = PrometheusMeterRegistry(PrometheusConfig.DEFAULT)
        hist = Log2Histograms()
        prom.prometheusRegistry.register(hist)
    }

    private fun slots(vararg pairs: Pair<Int, Long>) = LongArray(Log2Histograms.SLOTS).also { a ->
        pairs.forEach { (s, c) -> a[s] += c }
    }

    /** Parse `<name>_bucket{...,le="x"} v` lines for one series into (le, cumulative count). */
    private fun buckets(text: String, name: String): List<Pair<Double, Double>> =
        text.lines().filter { it.startsWith("${name}_bucket{") }.map { line ->
            val le = Regex("""le="([^"]+)"""").find(line)!!.groupValues[1]
            (if (le == "+Inf") Double.POSITIVE_INFINITY else le.toDouble()) to line.substringAfterLast(' ').toDouble()
        }

    /** Prometheus' histogram_quantile (promql/quantile.go bucketQuantile), classic buckets. */
    private fun histogramQuantile(q: Double, b: List<Pair<Double, Double>>): Double {
        val total = b.last().second
        val rank = q * total
        val i = b.indexOfFirst { it.second >= rank }
        if (b[i].first.isInfinite()) return b[b.size - 2].first
        val (lowerBound, lowerCount) = if (i == 0) 0.0 to 0.0 else b[i - 1]
        val (upper, count) = b[i]
        return lowerBound + (upper - lowerBound) * ((rank - lowerCount) / (count - lowerCount))
    }

    @Test
    fun `exposes a classic Prometheus histogram with exact log2 slot edges`() {
        // slot 20 = [2^20, 2^21) ns ≈ [1.05 ms, 2.10 ms)
        hist.observe(Log2Histograms.RUNQUEUE, tags, slots(20 to 90L, 23 to 10L), sumNs = 150_000_000)
        val text = prom.scrape()

        assertTrue(text.contains("# TYPE kpod_cpu_runqueue_latency_seconds histogram"), text)
        val b = buckets(text, "kpod_cpu_runqueue_latency_seconds")
        assertEquals(Math.scalb(1.0, 10) / 1e9, b.first().first, 1e-15, "first edge 2^10 ns")
        assertEquals(Math.scalb(1.0, 26) / 1e9, b[b.size - 2].first, 1e-15, "last finite edge 2^26 ns")
        assertTrue(b.last().first.isInfinite())
        assertEquals(18, b.size)
        // cumulative and monotonic
        assertTrue(b.zipWithNext().all { (x, y) -> y.second >= x.second })
        assertEquals(0.0, b.first { it.first < Math.scalb(1.0, 20) / 1e9 }.second)
        assertEquals(90.0, b.first { it.first == Math.scalb(1.0, 21) / 1e9 }.second)
        assertEquals(100.0, b.last().second)

        assertTrue(text.contains("""kpod_cpu_runqueue_latency_seconds_count{container="c",namespace="ns",node="n",pod="p"} 100"""), text)
        assertTrue(text.contains("""kpod_cpu_runqueue_latency_seconds_sum{container="c",namespace="ns",node="n",pod="p"} 0.15"""), text)

        // p50 falls inside the slot-20 bucket, p95 inside slot 23 = [8.4 ms, 16.8 ms)
        val p50 = histogramQuantile(0.5, b)
        assertTrue(p50 in 1.048e-3..2.098e-3, "p50=$p50")
        val p95 = histogramQuantile(0.95, b)
        assertTrue(p95 in 8.38e-3..16.78e-3, "p95=$p95")
    }

    @Test
    fun `accumulates drained per-cycle deltas into monotonic counters`() {
        repeat(3) { hist.observe(Log2Histograms.RUNQUEUE, tags, slots(15 to 5L), sumNs = 5 * 40_000) }
        val b = buckets(prom.scrape(), "kpod_cpu_runqueue_latency_seconds")
        assertEquals(15.0, b.last().second)
    }

    @Test
    fun `clamp slot only feeds +Inf so quantiles never exceed the last real edge`() {
        hist.observe(Log2Histograms.DISK_IO, tags, slots(26 to 10L), sumNs = 10L * 500_000_000)
        val b = buckets(prom.scrape(), "kpod_disk_io_latency_seconds")
        assertEquals(0.0, b[b.size - 2].second, "no finite bucket contains clamped events")
        assertEquals(10.0, b.last().second)
        assertEquals(Math.scalb(1.0, 26) / 1e9, histogramQuantile(0.99, b), 1e-12)
    }

    @Test
    fun `values below the first edge are counted in the first bucket`() {
        hist.observe(Log2Histograms.TCP_RTT, tags, slots(0 to 1L, 5 to 2L, 13 to 3L), sumNs = 0)
        val b = buckets(prom.scrape(), "kpod_net_tcp_rtt_seconds")
        assertEquals(Math.scalb(1.0, 14) / 1e9, b.first().first, 1e-15)
        assertEquals(6.0, b.first().second)
    }

    @Test
    fun `stride produces coarser but still exact edges ending at the last finite slot`() {
        val edges = Log2Histograms.SYSCALL.edgeSlots.toList()
        assertEquals(listOf(9, 11, 13, 15, 17, 19, 21, 23, 25), edges)
        val cum = Log2Histograms.cumulativeBuckets(Log2Histograms.SYSCALL, slots(10 to 1L, 12 to 1L, 26 to 1L))
        // slot 10 ≤ edge slot 11, slot 12 ≤ edge slot 13
        assertArrayEquals(longArrayOf(0, 1, 2, 2, 2, 2, 2, 2, 2, 3), cum)
    }

    @Test
    fun `rejects corrupted reads and ignores empty ones`() {
        val bad = slots(3 to 1L).also { it[4] = -1 }
        assertFalse(hist.observe(Log2Histograms.RUNQUEUE, tags, bad, 10))
        assertFalse(hist.observe(Log2Histograms.RUNQUEUE, tags, LongArray(5), 10))
        assertTrue(hist.observe(Log2Histograms.RUNQUEUE, tags, LongArray(Log2Histograms.SLOTS), 0))
        assertEquals(0, hist.seriesCount(Log2Histograms.RUNQUEUE))
    }

    @Test
    fun `coexists with Micrometer meters in the same scrape and removes deleted pods`() {
        prom.counter("kpod.net.tcp.retransmits", tags).increment()
        hist.observe(Log2Histograms.TCP_RTT, tags, slots(14 to 1L), 20_000)
        val other = Tags.of("namespace", "ns", "pod", "q", "container", "c", "node", "n")
        hist.observe(Log2Histograms.TCP_RTT, other, slots(14 to 1L), 20_000)
        val text = prom.scrape()
        assertTrue(text.contains("kpod_net_tcp_retransmits_total"))
        assertTrue(text.contains("""pod="q""""))

        hist.removePod("q", "ns")
        assertFalse(prom.scrape().contains("""pod="q""""))
        assertEquals(1, hist.seriesCount(Log2Histograms.TCP_RTT))
    }

    @Test
    fun `mirrors series to OTLP as a timer with true event count and total time`() {
        val otlp = SimpleMeterRegistry()
        val h = Log2Histograms(otlp)
        h.observe(Log2Histograms.RUNQUEUE, tags, slots(20 to 4L), sumNs = 4_000_000)
        h.observe(Log2Histograms.RUNQUEUE, tags, slots(20 to 6L), sumNs = 6_000_000)
        val timer = otlp.get("kpod.cpu.runqueue.latency").functionTimer()
        assertEquals(10.0, timer.count())
        assertEquals(0.01, timer.totalTime(java.util.concurrent.TimeUnit.SECONDS), 1e-12)
        h.removePod("p", "ns")
        assertNull(otlp.find("kpod.cpu.runqueue.latency").functionTimer())
    }
}
