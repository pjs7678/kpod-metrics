package com.internal.kpodmetrics.analysis

import org.slf4j.LoggerFactory
import java.time.Instant

class AnomalyService(
    private val pyroscopeClient: PyroscopeClient
) {
    private val log = LoggerFactory.getLogger(AnomalyService::class.java)

    companion object {
        private val SENSITIVITY_THRESHOLDS = mapOf(
            "low" to SensitivityConfig(zThreshold = 4.0, cusumThreshold = 8.0, window = 15),
            "medium" to SensitivityConfig(zThreshold = 3.0, cusumThreshold = 5.0, window = 10),
            "high" to SensitivityConfig(zThreshold = 2.0, cusumThreshold = 3.0, window = 5)
        )
    }

    internal data class SensitivityConfig(
        val zThreshold: Double,
        val cusumThreshold: Double,
        val window: Int
    )

    fun detect(app: String, namespace: String, from: Long, until: Long, sensitivity: String): AnomalyReport {
        val config = SENSITIVITY_THRESHOLDS[sensitivity] ?: SENSITIVITY_THRESHOLDS["medium"]!!

        val timelines = mutableListOf<TimelineAnalysis>()
        val timelineSamples = mutableMapOf<String, List<Double>>()

        // Query Pyroscope profiles
        val escNs = RecommendService.escapeLabelValue(namespace)
        val escApp = RecommendService.escapeLabelValue(app)
        val profiles = mapOf(
            "cpu" to "kpod.cpu{namespace=$escNs,app=$escApp}",
            "alloc" to "kpod.alloc{namespace=$escNs,app=$escApp}",
            "iowait" to "kpod.iowait{namespace=$escNs,app=$escApp}"
        )

        for ((name, query) in profiles) {
            val response = pyroscopeClient.queryProfile(query, from, until)
            val timeline = response?.timeline
            if (timeline != null && timeline.samples.isNotEmpty()) {
                val samples = timeline.samples.map { it.toDouble() }
                timelineSamples[name] = samples
                timelines.add(analyzeTimeline(name, samples, config))
            }
        }

        // Cross-profile correlations
        val correlations = computeCrossCorrelations(timelineSamples)

        // Health score
        val healthScore = computeHealthScore(timelines)
        val severity = when {
            healthScore < 30 -> Severity.CRITICAL
            healthScore < 70 -> Severity.WARNING
            else -> Severity.INFO
        }

        // Problem start detection
        val problemStartedAt = detectProblemStart(timelines, from, until)

        val summary = generateSummary(timelines, correlations, healthScore)

        return AnomalyReport(
            app = app,
            namespace = namespace,
            timeRange = "${Instant.ofEpochSecond(from)} to ${Instant.ofEpochSecond(until)}",
            sensitivity = sensitivity,
            healthScore = healthScore,
            severity = severity,
            timelines = timelines,
            crossCorrelations = correlations,
            problemStartedAt = problemStartedAt,
            summary = summary
        )
    }

    internal fun analyzeTimeline(name: String, samples: List<Double>, config: SensitivityConfig): TimelineAnalysis {
        val sorted = samples.sorted()
        val mean = samples.average()
        val p50 = TimeSeriesStats.percentile(sorted, 50.0)
        val p95 = TimeSeriesStats.percentile(sorted, 95.0)
        val p99 = TimeSeriesStats.percentile(sorted, 99.0)

        val spikes = TimeSeriesStats.zScoreSpikes(samples, config.window, config.zThreshold)
        val changePoint = TimeSeriesStats.cusumChangePoint(samples, 0.5, config.cusumThreshold)
        val regime = classifyRegime(samples, spikes, changePoint)
        val periodicity = detectPeriodicity(samples)

        return TimelineAnalysis(
            name = name,
            sampleCount = samples.size,
            mean = mean,
            p50 = p50,
            p95 = p95,
            p99 = p99,
            spikes = spikes,
            changePoint = changePoint,
            regime = regime,
            periodicity = periodicity
        )
    }

    internal fun classifyRegime(
        samples: List<Double>,
        spikes: List<Spike>,
        changePoint: ChangePoint?
    ): String {
        if (changePoint != null) return "shift"
        if (spikes.size > samples.size * 0.1) return "volatile"
        if (spikes.isNotEmpty()) return "spiky"

        // Check trend
        if (samples.size >= 4) {
            val firstHalf = samples.subList(0, samples.size / 2).average()
            val secondHalf = samples.subList(samples.size / 2, samples.size).average()
            val mean = samples.average()
            if (mean > 0 && kotlin.math.abs(secondHalf - firstHalf) / mean > 0.2) {
                return if (secondHalf > firstHalf) "trending-up" else "trending-down"
            }
        }
        return "stable"
    }

    internal fun detectPeriodicity(samples: List<Double>): PeriodicityResult {
        if (samples.size < 10) return PeriodicityResult(detected = false, dominantLag = null, strength = null)

        val maxLag = (samples.size / 3).coerceAtMost(50)
        val acf = TimeSeriesStats.autocorrelation(samples, maxLag)
        if (acf.isEmpty()) return PeriodicityResult(detected = false, dominantLag = null, strength = null)

        // Find peak autocorrelation (skip lag 1-2 which are often trivially high)
        val searchStart = 2.coerceAtMost(acf.size - 1)
        var maxAcf = 0.0
        var maxLagIndex = -1
        for (i in searchStart until acf.size) {
            if (acf[i] > maxAcf) {
                maxAcf = acf[i]
                maxLagIndex = i
            }
        }

        val detected = maxAcf > 0.3
        return PeriodicityResult(
            detected = detected,
            dominantLag = if (detected) maxLagIndex + 1 else null,
            strength = if (detected) maxAcf else null
        )
    }

    private fun computeCrossCorrelations(timelineSamples: Map<String, List<Double>>): List<CrossCorrelation> {
        val keys = timelineSamples.keys.toList()
        val correlations = mutableListOf<CrossCorrelation>()
        for (i in keys.indices) {
            for (j in i + 1 until keys.size) {
                val a = timelineSamples[keys[i]]!!
                val b = timelineSamples[keys[j]]!!
                val r = TimeSeriesStats.pearsonCorrelation(a, b)
                val interpretation = when {
                    r > 0.7 -> "strong positive correlation — likely related"
                    r > 0.3 -> "moderate positive correlation"
                    r < -0.7 -> "strong negative correlation — inverse relationship"
                    r < -0.3 -> "moderate negative correlation"
                    else -> "weak/no correlation — likely independent"
                }
                correlations.add(CrossCorrelation(
                    seriesA = keys[i],
                    seriesB = keys[j],
                    coefficient = r,
                    interpretation = interpretation
                ))
            }
        }
        return correlations
    }

    internal fun computeHealthScore(timelines: List<TimelineAnalysis>): Int {
        if (timelines.isEmpty()) return 100
        var score = 100
        for (tl in timelines) {
            // Deduct for spikes
            score -= (tl.spikes.size * 3).coerceAtMost(20)
            // Deduct for change point
            if (tl.changePoint != null) score -= 15
            // Deduct for volatile regime
            when (tl.regime) {
                "volatile" -> score -= 20
                "shift" -> score -= 15
                "trending-up" -> score -= 10
                "spiky" -> score -= 5
            }
        }
        return score.coerceIn(0, 100)
    }

    private fun detectProblemStart(timelines: List<TimelineAnalysis>, from: Long, until: Long): String? {
        val changePoints = timelines.mapNotNull { it.changePoint }
        if (changePoints.isEmpty()) return null

        // Use earliest change point
        val earliest = changePoints.minBy { it.index }
        val totalSamples = timelines.maxOf { it.sampleCount }
        if (totalSamples == 0) return null

        val timespan = until - from
        val estimatedEpoch = from + (earliest.index.toLong() * timespan / totalSamples)
        return Instant.ofEpochSecond(estimatedEpoch).toString()
    }

    private fun generateSummary(
        timelines: List<TimelineAnalysis>,
        correlations: List<CrossCorrelation>,
        healthScore: Int
    ): String {
        if (timelines.isEmpty()) return "No profiling data available. Ensure Pyroscope is configured."

        val parts = mutableListOf<String>()
        parts.add("Health score: $healthScore/100.")

        for (tl in timelines) {
            val issues = mutableListOf<String>()
            if (tl.spikes.isNotEmpty()) issues.add("${tl.spikes.size} spike(s)")
            if (tl.changePoint != null) issues.add("${tl.changePoint.direction} shift detected")
            if (tl.regime != "stable") issues.add("regime: ${tl.regime}")
            if (issues.isNotEmpty()) {
                parts.add("${tl.name}: ${issues.joinToString(", ")}")
            }
        }

        val strongCorrelations = correlations.filter { kotlin.math.abs(it.coefficient) > 0.7 }
        if (strongCorrelations.isNotEmpty()) {
            parts.add("Correlated: ${strongCorrelations.joinToString { "${it.seriesA}<->${it.seriesB}" }}")
        }

        return parts.joinToString(" ")
    }
}
