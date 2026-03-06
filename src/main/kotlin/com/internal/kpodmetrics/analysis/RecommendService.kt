package com.internal.kpodmetrics.analysis

import io.fabric8.kubernetes.client.KubernetesClient
import io.micrometer.core.instrument.MeterRegistry
import org.slf4j.LoggerFactory
import java.time.Instant

class RecommendService(
    private val pyroscopeClient: PyroscopeClient,
    private val kubernetesClient: KubernetesClient,
    private val registry: MeterRegistry
) {
    private val log = LoggerFactory.getLogger(RecommendService::class.java)

    fun recommend(app: String, namespace: String, from: Long, until: Long, confidence: Int): RecommendReport {
        val cpuTimeline = queryCpuTimeline(app, namespace, from, until)
        val memTimeline = queryMemTimeline(app, namespace, from, until)
        val currentResources = getCurrentResources(app, namespace)
        val recommendations = mutableListOf<ResourceRecommendation>()

        val cpuRec = computeCpuRecommendation(cpuTimeline, currentResources, confidence)
        if (cpuRec != null) recommendations.add(cpuRec)

        val memRec = computeMemoryRecommendation(memTimeline, currentResources, confidence)
        if (memRec != null) recommendations.add(memRec)

        val diskRec = computeFromRegistry(app, namespace, "kpod.disk.io.bytes", "disk-io")
        if (diskRec != null) recommendations.add(diskRec)

        val kubectlPatch = generateKubectlPatch(app, namespace, recommendations)
        val summary = generateSummary(recommendations)

        return RecommendReport(
            app = app,
            namespace = namespace,
            timeRange = "${Instant.ofEpochSecond(from)} to ${Instant.ofEpochSecond(until)}",
            confidence = confidence,
            recommendations = recommendations,
            kubectlPatch = kubectlPatch,
            summary = summary
        )
    }

    private fun queryCpuTimeline(app: String, namespace: String, from: Long, until: Long): List<Double> {
        val query = "kpod.cpu{namespace=$namespace,app=$app}"
        val response = pyroscopeClient.queryProfile(query, from, until)
        val timeline = response?.timeline ?: return emptyList()
        if (timeline.durationDelta <= 0) return emptyList()
        return timeline.samples.map { ticks ->
            (ticks.toDouble() / timeline.durationDelta) * 1000.0
        }
    }

    private fun queryMemTimeline(app: String, namespace: String, from: Long, until: Long): List<Double> {
        val query = "kpod.alloc{namespace=$namespace,app=$app}"
        val response = pyroscopeClient.queryProfile(query, from, until)
        val timeline = response?.timeline ?: return emptyList()
        if (timeline.durationDelta <= 0) return emptyList()
        return timeline.samples.map { bytes ->
            bytes.toDouble() / timeline.durationDelta
        }
    }

    internal fun computeCpuRecommendation(
        millicores: List<Double>,
        current: CurrentResources?,
        confidence: Int
    ): ResourceRecommendation? {
        if (millicores.isEmpty()) return null
        val sorted = millicores.sorted()
        val p50 = TimeSeriesStats.percentile(sorted, 50.0)
        val pConf = TimeSeriesStats.percentile(sorted, confidence.toDouble())
        val headroom = 1.15

        val requestMillis = p50.toLong().coerceAtLeast(10)
        val limitMillis = (pConf * headroom).toLong().coerceAtLeast(requestMillis)

        val recommended = ResourceSpec(
            request = "${requestMillis}m",
            limit = "${limitMillis}m"
        )

        val verdict = if (current?.cpuRequest != null) {
            val currentReqMillis = parseMillicores(current.cpuRequest)
            when {
                currentReqMillis > limitMillis * 1.5 -> SizingVerdict.OVER_PROVISIONED
                currentReqMillis < requestMillis * 0.8 -> SizingVerdict.UNDER_PROVISIONED
                else -> SizingVerdict.RIGHT_SIZED
            }
        } else {
            SizingVerdict.UNDER_PROVISIONED
        }

        return ResourceRecommendation(
            resource = "cpu",
            current = current?.let { ResourceSpec(it.cpuRequest ?: "unset", it.cpuLimit ?: "unset") },
            recommended = recommended,
            verdict = verdict,
            detail = "p50=${requestMillis}m, p${confidence}=${pConf.toLong()}m (${millicores.size} samples)"
        )
    }

    internal fun computeMemoryRecommendation(
        allocRates: List<Double>,
        current: CurrentResources?,
        confidence: Int
    ): ResourceRecommendation? {
        if (allocRates.isEmpty()) return null
        val sorted = allocRates.sorted()
        val p50 = TimeSeriesStats.percentile(sorted, 50.0)
        val pConf = TimeSeriesStats.percentile(sorted, confidence.toDouble())
        val headroom = 1.20

        val requestBytes = p50.toLong().coerceAtLeast(64 * 1024 * 1024)
        val limitBytes = (pConf * headroom).toLong().coerceAtLeast(requestBytes)

        val recommended = ResourceSpec(
            request = formatBytes(requestBytes),
            limit = formatBytes(limitBytes)
        )

        val verdict = if (current?.memRequest != null) {
            val currentReqBytes = parseBytes(current.memRequest)
            when {
                currentReqBytes > limitBytes * 1.5 -> SizingVerdict.OVER_PROVISIONED
                currentReqBytes < requestBytes * 0.8 -> SizingVerdict.UNDER_PROVISIONED
                else -> SizingVerdict.RIGHT_SIZED
            }
        } else {
            SizingVerdict.UNDER_PROVISIONED
        }

        return ResourceRecommendation(
            resource = "memory",
            current = current?.let { ResourceSpec(it.memRequest ?: "unset", it.memLimit ?: "unset") },
            recommended = recommended,
            verdict = verdict,
            detail = "p50=${formatBytes(p50.toLong())}, p${confidence}=${formatBytes(pConf.toLong())} (${allocRates.size} samples)"
        )
    }

    private fun computeFromRegistry(app: String, namespace: String, metricName: String, resource: String): ResourceRecommendation? {
        val meters = registry.find(metricName).tag("pod", app).tag("namespace", namespace).meters()
        if (meters.isEmpty()) return null
        val values = meters.flatMap { m -> m.measure().map { it.value } }.filter { it > 0 }
        if (values.isEmpty()) return null

        val sorted = values.sorted()
        val p50 = TimeSeriesStats.percentile(sorted, 50.0)
        val p95 = TimeSeriesStats.percentile(sorted, 95.0)

        return ResourceRecommendation(
            resource = resource,
            current = null,
            recommended = ResourceSpec(
                request = formatBytes(p50.toLong()),
                limit = formatBytes(p95.toLong())
            ),
            verdict = SizingVerdict.RIGHT_SIZED,
            detail = "p50=${formatBytes(p50.toLong())}, p95=${formatBytes(p95.toLong())} from micrometer"
        )
    }

    internal data class CurrentResources(
        val cpuRequest: String?,
        val cpuLimit: String?,
        val memRequest: String?,
        val memLimit: String?
    )

    private fun getCurrentResources(app: String, namespace: String): CurrentResources? {
        return try {
            // Try multiple label conventions: app, app.kubernetes.io/name, app.kubernetes.io/component
            for (label in APP_LABELS) {
                val pods = kubernetesClient.pods().inNamespace(namespace)
                    .withLabel(label, app).list().items
                val pod = pods.firstOrNull() ?: continue
                val container = pod.spec?.containers?.firstOrNull() ?: continue
                val resources = container.resources ?: return CurrentResources(null, null, null, null)
                return CurrentResources(
                    cpuRequest = resources.requests?.get("cpu")?.toString(),
                    cpuLimit = resources.limits?.get("cpu")?.toString(),
                    memRequest = resources.requests?.get("memory")?.toString(),
                    memLimit = resources.limits?.get("memory")?.toString()
                )
            }
            null
        } catch (e: Exception) {
            log.warn("Failed to query K8s for pod resources: {}", e.message)
            null
        }
    }

    private fun generateKubectlPatch(app: String, namespace: String, recs: List<ResourceRecommendation>): String? {
        if (recs.isEmpty()) return null
        val cpuRec = recs.find { it.resource == "cpu" }
        val memRec = recs.find { it.resource == "memory" }
        if (cpuRec == null && memRec == null) return null

        val parts = mutableListOf<String>()
        cpuRec?.let {
            parts.add("requests.cpu=${it.recommended.request}")
            parts.add("limits.cpu=${it.recommended.limit}")
        }
        memRec?.let {
            parts.add("requests.memory=${it.recommended.request}")
            parts.add("limits.memory=${it.recommended.limit}")
        }
        val resourcePatch = parts.joinToString(",")
        return "kubectl -n $namespace set resources deployment/$app -c $app --$resourcePatch"
    }

    private fun generateSummary(recs: List<ResourceRecommendation>): String {
        if (recs.isEmpty()) return "Insufficient data for recommendations. Ensure Pyroscope is configured and workload is active."
        val verdicts = recs.map { "${it.resource}: ${it.verdict.name.lowercase().replace('_', '-')}" }
        return verdicts.joinToString("; ")
    }

    companion object {
        val APP_LABELS = listOf("app", "app.kubernetes.io/name", "app.kubernetes.io/component")

        internal fun parseMillicores(value: String): Long {
            return when {
                value.endsWith("m") -> value.removeSuffix("m").toLongOrNull() ?: 0
                else -> (value.toDoubleOrNull()?.times(1000))?.toLong() ?: 0
            }
        }

        internal fun parseBytes(value: String): Long {
            return when {
                value.endsWith("Gi") -> (value.removeSuffix("Gi").toDoubleOrNull()?.times(1024 * 1024 * 1024))?.toLong() ?: 0
                value.endsWith("Mi") -> (value.removeSuffix("Mi").toDoubleOrNull()?.times(1024 * 1024))?.toLong() ?: 0
                value.endsWith("Ki") -> (value.removeSuffix("Ki").toDoubleOrNull()?.times(1024))?.toLong() ?: 0
                else -> value.toLongOrNull() ?: 0
            }
        }

        internal fun formatBytes(bytes: Long): String {
            return when {
                bytes >= 1024 * 1024 * 1024 -> "${bytes / (1024 * 1024 * 1024)}Gi"
                bytes >= 1024 * 1024 -> "${bytes / (1024 * 1024)}Mi"
                bytes >= 1024 -> "${bytes / 1024}Ki"
                else -> "${bytes}"
            }
        }
    }
}
