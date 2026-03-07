package com.internal.kpodmetrics.analysis

import org.springframework.boot.actuate.endpoint.annotation.Endpoint
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation
import org.springframework.boot.actuate.endpoint.annotation.Selector
import org.springframework.lang.Nullable
import java.time.Instant

@Endpoint(id = "kpodRecommend")
class RecommendEndpoint(
    private val recommendService: RecommendService
) {
    @ReadOperation
    fun recommend(
        @Selector app: String,
        @Nullable from: String?,
        @Nullable until: String?,
        @Nullable confidence: Int?,
        @Nullable namespace: String?
    ): RecommendReport {
        if (!rateLimiter.tryAcquire()) {
            throw IllegalStateException("Too many concurrent recommendation requests. Try again later.")
        }
        try {
            val now = Instant.now().epochSecond
            val fromEpoch = parseTimeExpr(from ?: "now-30m", now)
            val untilEpoch = parseTimeExpr(until ?: "now", now)
            val conf = (confidence ?: 95).coerceIn(1, 100)
            val ns = validateLabel(namespace ?: "default")
            val validApp = validateLabel(app)

            return recommendService.recommend(validApp, ns, fromEpoch, untilEpoch, conf)
        } finally {
            rateLimiter.release()
        }
    }

    companion object {
        private val rateLimiter = java.util.concurrent.Semaphore(3) // max 3 concurrent requests
        private val LABEL_PATTERN = Regex("""^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,61}[a-zA-Z0-9])?$""")

        internal fun validateLabel(value: String): String {
            require(value.isNotBlank() && LABEL_PATTERN.matches(value)) {
                "Invalid label value: '$value'. Must be 1-63 alphanumeric chars, dashes, dots, or underscores."
            }
            return value
        }

        internal fun parseTimeExpr(expr: String, nowEpoch: Long): Long {
            if (expr == "now") return nowEpoch
            val match = Regex("""^now-(\d+)([smhd])$""").matchEntire(expr)
            if (match != null) {
                val amount = match.groupValues[1].toLong()
                val unit = match.groupValues[2]
                val seconds = when (unit) {
                    "s" -> amount
                    "m" -> amount * 60
                    "h" -> amount * 3600
                    "d" -> amount * 86400
                    else -> 0
                }
                return nowEpoch - seconds
            }
            val epoch = expr.toLongOrNull()
            require(epoch != null) { "Invalid time expression: '$expr'. Use 'now', 'now-30m', or epoch seconds." }
            return epoch
        }
    }
}
