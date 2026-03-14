package com.internal.kpodmetrics.tracing

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.config.MetricsProperties
import com.internal.kpodmetrics.config.ProtocolTracingConfig
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.atomic.AtomicReference

data class TracingState(
    val enabled: Boolean = false,
    val http: ProtocolTracingConfig = ProtocolTracingConfig(thresholdMs = 200),
    val redis: ProtocolTracingConfig = ProtocolTracingConfig(thresholdMs = 10),
    val mysql: ProtocolTracingConfig = ProtocolTracingConfig(thresholdMs = 200),
    val source: String = "configmap"
)

class TracingConfigManager(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val props: MetricsProperties
) {
    private val log = LoggerFactory.getLogger(TracingConfigManager::class.java)
    private val currentState = AtomicReference(
        TracingState(
            enabled = props.tracing.enabled,
            http = props.tracing.http,
            redis = props.tracing.redis,
            mysql = props.tracing.mysql,
            source = "configmap"
        )
    )

    companion object {
        private const val TRACING_CONFIG_MAP = "tracing_config"
        // TracingConfig struct: u32 enabled + u32 pad + u64 threshold_ns = 16 bytes
        private const val TRACING_CONFIG_SIZE = 16

        private val PROTOCOL_PROGRAMS = mapOf(
            "http" to "http",
            "redis" to "redis",
            "mysql" to "mysql"
        )
    }

    fun getState(): TracingState = currentState.get()

    fun updateFromApi(state: TracingState) {
        val updated = state.copy(source = "api")
        currentState.set(updated)
        applyCurrentConfig()
        log.info("Tracing config updated via API: enabled={}, http={}, redis={}, mysql={}",
            updated.enabled, updated.http, updated.redis, updated.mysql)
    }

    fun applyCurrentConfig() {
        val state = currentState.get()
        for ((protocol, programName) in PROTOCOL_PROGRAMS) {
            val protocolConfig = when (protocol) {
                "http" -> state.http
                "redis" -> state.redis
                "mysql" -> state.mysql
                else -> continue
            }
            val enabled = state.enabled && protocolConfig.enabled
            applyProtocol(programName, enabled, protocolConfig.thresholdMs)
        }
    }

    fun applyProtocol(programName: String, enabled: Boolean, thresholdMs: Long) {
        if (!programManager.isProgramLoaded(programName)) {
            log.debug("Program '{}' not loaded, skipping tracing config", programName)
            return
        }
        try {
            val handle = programManager.getHandle(programName) ?: return
            val mapFd = bridge.getMapFd(handle, TRACING_CONFIG_MAP)
            if (mapFd < 0) {
                log.warn("Map '{}' not found in program '{}'", TRACING_CONFIG_MAP, programName)
                return
            }

            // Key: u32 index 0
            val key = ByteBuffer.allocate(4)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putInt(0)
                .array()

            // Value: u32 enabled + u32 pad + u64 threshold_ns
            val thresholdNs = thresholdMs * 1_000_000L
            val value = ByteBuffer.allocate(TRACING_CONFIG_SIZE)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putInt(if (enabled) 1 else 0)
                .putInt(0) // pad
                .putLong(thresholdNs)
                .array()

            bridge.mapUpdate(mapFd, key, value)
            log.debug("Tracing config applied to '{}': enabled={}, thresholdMs={}",
                programName, enabled, thresholdMs)
        } catch (e: Exception) {
            log.warn("Failed to apply tracing config to '{}': {}", programName, e.message)
        }
    }
}
