package com.internal.kpodmetrics.analysis

import kotlin.math.pow
import kotlin.math.sqrt

object TimeSeriesStats {

    fun percentile(sorted: List<Double>, pct: Double): Double {
        if (sorted.isEmpty()) return 0.0
        if (sorted.size == 1) return sorted[0]
        val rank = (pct / 100.0) * (sorted.size - 1)
        val lower = rank.toInt()
        val upper = (lower + 1).coerceAtMost(sorted.size - 1)
        val frac = rank - lower
        return sorted[lower] + frac * (sorted[upper] - sorted[lower])
    }

    fun rollingMeanStd(samples: List<Double>, window: Int): Pair<List<Double>, List<Double>> {
        if (samples.size < window) return Pair(emptyList(), emptyList())
        val means = mutableListOf<Double>()
        val stds = mutableListOf<Double>()
        for (i in 0..samples.size - window) {
            val w = samples.subList(i, i + window)
            val mean = w.average()
            val variance = w.sumOf { (it - mean).pow(2) } / window
            means.add(mean)
            stds.add(sqrt(variance))
        }
        return Pair(means, stds)
    }

    fun zScoreSpikes(samples: List<Double>, window: Int, threshold: Double): List<Spike> {
        if (samples.size < window + 1) return emptyList()
        val spikes = mutableListOf<Spike>()
        val (means, stds) = rollingMeanStd(samples, window)
        for (i in window until samples.size) {
            val mean = means[i - window]
            val std = stds[i - window]
            if (std > 0) {
                val z = (samples[i] - mean) / std
                if (z > threshold) {
                    spikes.add(Spike(index = i, value = samples[i], zScore = z))
                }
            }
        }
        return spikes
    }

    fun cusumChangePoint(
        samples: List<Double>,
        slackFactor: Double = 0.5,
        threshold: Double = 5.0
    ): ChangePoint? {
        if (samples.size < 2) return null
        val mean = samples.average()
        val std = sqrt(samples.sumOf { (it - mean).pow(2) } / samples.size)
        if (std == 0.0) return null

        val slack = slackFactor * std
        var cusumPos = 0.0
        var cusumNeg = 0.0

        for (i in samples.indices) {
            cusumPos = maxOf(0.0, cusumPos + samples[i] - mean - slack)
            cusumNeg = maxOf(0.0, cusumNeg - samples[i] + mean - slack)
            if (cusumPos > threshold * std || cusumNeg > threshold * std) {
                val direction = if (cusumPos > cusumNeg) "increase" else "decrease"
                val beforeMean = if (i > 0) samples.subList(0, i).average() else mean
                val afterMean = if (i < samples.size - 1) samples.subList(i, samples.size).average() else mean
                return ChangePoint(
                    index = i,
                    direction = direction,
                    magnitude = kotlin.math.abs(afterMean - beforeMean),
                    beforeMean = beforeMean,
                    afterMean = afterMean
                )
            }
        }
        return null
    }

    fun autocorrelation(samples: List<Double>, maxLag: Int): List<Double> {
        if (samples.size < 2) return emptyList()
        val mean = samples.average()
        val variance = samples.sumOf { (it - mean).pow(2) }
        if (variance == 0.0) return List(maxLag.coerceAtMost(samples.size - 1)) { 0.0 }

        val effectiveMaxLag = maxLag.coerceAtMost(samples.size - 1)
        return (1..effectiveMaxLag).map { lag ->
            var sum = 0.0
            for (i in 0 until samples.size - lag) {
                sum += (samples[i] - mean) * (samples[i + lag] - mean)
            }
            sum / variance
        }
    }

    fun pearsonCorrelation(a: List<Double>, b: List<Double>): Double {
        val n = minOf(a.size, b.size)
        if (n < 2) return 0.0
        val meanA = a.take(n).average()
        val meanB = b.take(n).average()
        var sumAB = 0.0
        var sumA2 = 0.0
        var sumB2 = 0.0
        for (i in 0 until n) {
            val da = a[i] - meanA
            val db = b[i] - meanB
            sumAB += da * db
            sumA2 += da * da
            sumB2 += db * db
        }
        val denom = sqrt(sumA2 * sumB2)
        return if (denom == 0.0) 0.0 else sumAB / denom
    }
}
