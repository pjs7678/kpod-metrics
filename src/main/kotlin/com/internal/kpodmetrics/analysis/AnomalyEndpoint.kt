package com.internal.kpodmetrics.analysis

import org.springframework.boot.actuate.endpoint.annotation.Endpoint
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation
import org.springframework.boot.actuate.endpoint.annotation.Selector
import org.springframework.lang.Nullable
import java.time.Instant

@Endpoint(id = "kpodAnomaly")
class AnomalyEndpoint(
    private val anomalyService: AnomalyService
) {
    @ReadOperation
    fun detect(
        @Selector app: String,
        @Nullable from: String?,
        @Nullable until: String?,
        @Nullable sensitivity: String?,
        @Nullable namespace: String?
    ): AnomalyReport {
        val now = Instant.now().epochSecond
        val fromEpoch = RecommendEndpoint.parseTimeExpr(from ?: "now-1h", now)
        val untilEpoch = RecommendEndpoint.parseTimeExpr(until ?: "now", now)
        val sens = sensitivity ?: "medium"
        val ns = namespace ?: "default"

        return anomalyService.detect(app, ns, fromEpoch, untilEpoch, sens)
    }
}
