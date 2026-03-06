package com.internal.kpodmetrics.analysis

// --- TimeSeriesStats models ---

data class Spike(
    val index: Int,
    val value: Double,
    val zScore: Double
)

data class ChangePoint(
    val index: Int,
    val direction: String,
    val magnitude: Double,
    val beforeMean: Double,
    val afterMean: Double
)

// --- Pyroscope models ---

data class PyroscopeTimeline(
    val startTime: Long,
    val samples: List<Long>,
    val durationDelta: Long
)

data class PyroscopeResponse(
    val timeline: PyroscopeTimeline?
)

// --- Recommend models ---

enum class SizingVerdict { OVER_PROVISIONED, UNDER_PROVISIONED, RIGHT_SIZED }

data class ResourceRecommendation(
    val resource: String,
    val current: ResourceSpec?,
    val recommended: ResourceSpec,
    val verdict: SizingVerdict,
    val detail: String
)

data class ResourceSpec(
    val request: String,
    val limit: String
)

data class RecommendReport(
    val app: String,
    val namespace: String,
    val timeRange: String,
    val confidence: Int,
    val recommendations: List<ResourceRecommendation>,
    val kubectlPatch: String?,
    val summary: String
)

// --- Anomaly models ---

enum class Severity { INFO, WARNING, CRITICAL }

data class TimelineAnalysis(
    val name: String,
    val sampleCount: Int,
    val mean: Double,
    val p50: Double,
    val p95: Double,
    val p99: Double,
    val spikes: List<Spike>,
    val changePoint: ChangePoint?,
    val regime: String,
    val periodicity: PeriodicityResult?
)

data class PeriodicityResult(
    val detected: Boolean,
    val dominantLag: Int?,
    val strength: Double?
)

data class CrossCorrelation(
    val seriesA: String,
    val seriesB: String,
    val coefficient: Double,
    val interpretation: String
)

data class AnomalyReport(
    val app: String,
    val namespace: String,
    val timeRange: String,
    val sensitivity: String,
    val healthScore: Int,
    val severity: Severity,
    val timelines: List<TimelineAnalysis>,
    val crossCorrelations: List<CrossCorrelation>,
    val problemStartedAt: String?,
    val summary: String
)
