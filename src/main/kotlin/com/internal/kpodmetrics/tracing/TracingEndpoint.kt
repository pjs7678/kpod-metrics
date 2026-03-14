package com.internal.kpodmetrics.tracing

import com.internal.kpodmetrics.config.ProtocolTracingConfig
import org.springframework.boot.actuate.endpoint.annotation.Endpoint
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation
import org.springframework.boot.actuate.endpoint.annotation.WriteOperation
import org.springframework.lang.Nullable

@Endpoint(id = "kpodTracing")
class TracingEndpoint(
    private val tracingConfigManager: TracingConfigManager,
    private val spanCollector: SpanCollector
) {

    @ReadOperation
    fun read(): Map<String, Any?> {
        val state = tracingConfigManager.getState()
        return mapOf(
            "enabled" to state.enabled,
            "source" to state.source,
            "collecting" to spanCollector.isRunning(),
            "spansExported" to spanCollector.getSpansExported(),
            "spansDropped" to spanCollector.getSpansDropped(),
            "protocols" to mapOf(
                "http" to mapOf(
                    "enabled" to state.http.enabled,
                    "thresholdMs" to state.http.thresholdMs
                ),
                "redis" to mapOf(
                    "enabled" to state.redis.enabled,
                    "thresholdMs" to state.redis.thresholdMs
                ),
                "mysql" to mapOf(
                    "enabled" to state.mysql.enabled,
                    "thresholdMs" to state.mysql.thresholdMs
                )
            )
        )
    }

    @WriteOperation
    fun write(
        @Nullable enabled: Boolean?,
        @Nullable httpEnabled: Boolean?,
        @Nullable httpThresholdMs: Long?,
        @Nullable redisEnabled: Boolean?,
        @Nullable redisThresholdMs: Long?,
        @Nullable mysqlEnabled: Boolean?,
        @Nullable mysqlThresholdMs: Long?
    ): Map<String, Any?> {
        val current = tracingConfigManager.getState()

        val newState = current.copy(
            enabled = enabled ?: current.enabled,
            http = ProtocolTracingConfig(
                enabled = httpEnabled ?: current.http.enabled,
                thresholdMs = httpThresholdMs ?: current.http.thresholdMs
            ),
            redis = ProtocolTracingConfig(
                enabled = redisEnabled ?: current.redis.enabled,
                thresholdMs = redisThresholdMs ?: current.redis.thresholdMs
            ),
            mysql = ProtocolTracingConfig(
                enabled = mysqlEnabled ?: current.mysql.enabled,
                thresholdMs = mysqlThresholdMs ?: current.mysql.thresholdMs
            )
        )

        tracingConfigManager.updateFromApi(newState)

        // Start or stop the span collector based on enabled state
        if (newState.enabled && !spanCollector.isRunning()) {
            spanCollector.start()
        } else if (!newState.enabled && spanCollector.isRunning()) {
            spanCollector.stop()
        }

        return read()
    }
}
