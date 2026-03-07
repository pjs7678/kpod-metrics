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
        val sens = validateSensitivity(sensitivity ?: "medium")
        val ns = RecommendEndpoint.validateLabel(namespace ?: "default")
        val validApp = RecommendEndpoint.validateLabel(app)

        return anomalyService.detect(validApp, ns, fromEpoch, untilEpoch, sens)
    }

    companion object {
        private val VALID_SENSITIVITIES = setOf("low", "medium", "high")

        internal fun validateSensitivity(value: String): String {
            require(value in VALID_SENSITIVITIES) {
                "Invalid sensitivity: '$value'. Must be one of: ${VALID_SENSITIVITIES.joinToString()}"
            }
            return value
        }
    }
}
