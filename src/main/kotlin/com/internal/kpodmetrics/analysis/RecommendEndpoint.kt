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
        val now = Instant.now().epochSecond
        val fromEpoch = parseTimeExpr(from ?: "now-30m", now)
        val untilEpoch = parseTimeExpr(until ?: "now", now)
        val conf = confidence ?: 95
        val ns = namespace ?: "default"

        return recommendService.recommend(app, ns, fromEpoch, untilEpoch, conf)
    }

    companion object {
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
            // Try as epoch seconds
            return expr.toLongOrNull() ?: nowEpoch
        }
    }
}
