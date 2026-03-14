package com.internal.kpodmetrics.tracing

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.config.MetricsProperties
import io.opentelemetry.api.common.AttributeKey
import io.opentelemetry.api.common.Attributes
import io.opentelemetry.api.trace.SpanKind
import io.opentelemetry.api.trace.StatusCode
import io.opentelemetry.sdk.OpenTelemetrySdk
import io.opentelemetry.sdk.common.CompletableResultCode
import io.opentelemetry.sdk.trace.SdkTracerProvider
import io.opentelemetry.sdk.trace.export.BatchSpanProcessor
import io.opentelemetry.exporter.otlp.trace.OtlpGrpcSpanExporter
import io.opentelemetry.sdk.resources.Resource
import io.opentelemetry.sdk.trace.data.SpanData
import org.slf4j.LoggerFactory
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.time.Instant
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class SpanCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val tracingConfigManager: TracingConfigManager,
    private val props: MetricsProperties,
    private val otlpEndpoint: String
) {
    private val log = LoggerFactory.getLogger(SpanCollector::class.java)
    private val running = AtomicBoolean(false)
    private var pollingThread: Thread? = null
    private val spansExported = AtomicLong(0)
    private val spansDropped = AtomicLong(0)

    private var otelSdk: OpenTelemetrySdk? = null
    private var tracerProvider: SdkTracerProvider? = null

    companion object {
        const val SPAN_EVENT_SIZE = 104
        private const val RING_BUF_MAP = "span_events"
        private const val MAX_EVENTS_PER_POLL = 256
        private const val POLL_INTERVAL_MS = 100L

        // Protocol constants
        const val PROTO_HTTP = 1
        const val PROTO_REDIS = 2
        const val PROTO_MYSQL = 3

        // HTTP methods
        private val HTTP_METHODS = arrayOf(
            "UNKNOWN", "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"
        )

        // Redis commands
        private val REDIS_COMMANDS = arrayOf(
            "UNKNOWN", "GET", "SET", "DEL", "HGET", "HSET",
            "LPUSH", "RPUSH", "SADD", "ZADD", "EXPIRE", "INCR", "OTHER"
        )

        // MySQL statements
        private val MYSQL_STMTS = arrayOf(
            "UNKNOWN", "SELECT", "INSERT", "UPDATE", "DELETE",
            "BEGIN", "COMMIT", "OTHER"
        )
    }

    fun isRunning(): Boolean = running.get()
    fun getSpansExported(): Long = spansExported.get()
    fun getSpansDropped(): Long = spansDropped.get()

    @Synchronized
    fun start() {
        if (running.get()) {
            log.info("SpanCollector already running")
            return
        }
        if (otlpEndpoint.isBlank()) {
            log.warn("Cannot start SpanCollector: no OTLP endpoint configured")
            return
        }

        val exporter = OtlpGrpcSpanExporter.builder()
            .setEndpoint(otlpEndpoint)
            .build()

        val resource = Resource.builder()
            .put("service.name", "kpod-metrics")
            .put("host.name", props.nodeName)
            .build()

        tracerProvider = SdkTracerProvider.builder()
            .setResource(resource)
            .addSpanProcessor(BatchSpanProcessor.builder(exporter).build())
            .build()

        otelSdk = OpenTelemetrySdk.builder()
            .setTracerProvider(tracerProvider!!)
            .build()

        running.set(true)
        tracingConfigManager.applyCurrentConfig()

        pollingThread = Thread.ofVirtual().name("span-collector").start {
            pollLoop()
        }
        log.info("SpanCollector started, exporting to {}", otlpEndpoint)
    }

    @Synchronized
    fun stop() {
        if (!running.get()) return
        running.set(false)
        pollingThread?.join(5000)
        pollingThread = null

        // Disable tracing in BPF programs
        val state = tracingConfigManager.getState()
        tracingConfigManager.updateFromApi(state.copy(enabled = false))

        try {
            tracerProvider?.shutdown()?.join(10, TimeUnit.SECONDS)
        } catch (e: Exception) {
            log.warn("Error shutting down tracer provider: {}", e.message)
        }
        otelSdk = null
        tracerProvider = null
        log.info("SpanCollector stopped. Exported={}, Dropped={}", spansExported.get(), spansDropped.get())
    }

    private fun pollLoop() {
        val ringBuffers = mutableMapOf<String, Long>() // programName -> rbPtr
        try {
            // Initialize ring buffers for loaded tracing programs
            for (programName in listOf("http", "redis", "mysql")) {
                if (!programManager.isProgramLoaded(programName)) continue
                try {
                    val handle = programManager.getHandle(programName) ?: continue
                    val mapFd = bridge.getMapFd(handle, RING_BUF_MAP)
                    if (mapFd < 0) {
                        log.warn("Ring buffer map '{}' not found in program '{}'", RING_BUF_MAP, programName)
                        continue
                    }
                    val rbPtr = bridge.ringBufNew(mapFd)
                    if (rbPtr == 0L) {
                        log.warn("Failed to create ring buffer for program '{}'", programName)
                        continue
                    }
                    ringBuffers[programName] = rbPtr
                    log.info("Ring buffer initialized for program '{}'", programName)
                } catch (e: Exception) {
                    log.warn("Failed to initialize ring buffer for '{}': {}", programName, e.message)
                }
            }

            if (ringBuffers.isEmpty()) {
                log.warn("No ring buffers available, SpanCollector stopping")
                running.set(false)
                return
            }

            while (running.get()) {
                var totalEvents = 0
                for ((programName, rbPtr) in ringBuffers) {
                    try {
                        val rawData = bridge.ringBufPoll(rbPtr, MAX_EVENTS_PER_POLL, SPAN_EVENT_SIZE)
                            ?: continue
                        val eventCount = rawData.size / SPAN_EVENT_SIZE
                        for (i in 0 until eventCount) {
                            val offset = i * SPAN_EVENT_SIZE
                            processSpanEvent(rawData, offset)
                        }
                        totalEvents += eventCount
                    } catch (e: Exception) {
                        log.debug("Error polling ring buffer for '{}': {}", programName, e.message)
                    }
                }
                if (totalEvents == 0) {
                    Thread.sleep(POLL_INTERVAL_MS)
                }
            }
        } finally {
            // Free ring buffers
            for ((programName, rbPtr) in ringBuffers) {
                try {
                    bridge.ringBufFree(rbPtr)
                    log.debug("Ring buffer freed for program '{}'", programName)
                } catch (e: Exception) {
                    log.warn("Error freeing ring buffer for '{}': {}", programName, e.message)
                }
            }
        }
    }

    private fun processSpanEvent(data: ByteArray, offset: Int) {
        val buf = ByteBuffer.wrap(data, offset, SPAN_EVENT_SIZE).order(ByteOrder.LITTLE_ENDIAN)

        // Parse struct fields
        val tsNs = buf.long           // u64 offset 0
        val latencyNs = buf.long      // u64 offset 8
        val cgroupId = buf.long       // u64 offset 16
        val dstIp = buf.int           // u32 offset 24
        val dstPort = buf.short.toInt() and 0xFFFF  // u16 offset 28
        val srcPort = buf.short.toInt() and 0xFFFF  // u16 offset 30
        val protocol = buf.get().toInt() and 0xFF   // u8 offset 32
        val method = buf.get().toInt() and 0xFF     // u8 offset 33
        val statusCode = buf.short.toInt() and 0xFFFF // u16 offset 34
        val direction = buf.get().toInt() and 0xFF  // u8 offset 36
        // 3 bytes padding at offset 37
        buf.get(); buf.get(); buf.get()
        // 64 bytes urlPath at offset 40
        val urlPathBytes = ByteArray(64)
        buf.get(urlPathBytes)
        val urlPath = String(urlPathBytes, Charsets.US_ASCII).trimEnd('\u0000')

        // Resolve pod info
        val podInfo = cgroupResolver.resolve(cgroupId)

        val tracer = otelSdk?.getTracer("kpod-metrics") ?: run {
            spansDropped.incrementAndGet()
            return
        }

        val spanName = buildSpanName(protocol, method, urlPath)
        val spanBuilder = tracer.spanBuilder(spanName)
            .setSpanKind(if (direction == 0) SpanKind.SERVER else SpanKind.CLIENT)
            .setStartTimestamp(tsNs, TimeUnit.NANOSECONDS)

        // Add attributes
        val attrsBuilder = Attributes.builder()

        // Network attributes
        val ipBytes = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(dstIp).array()
        val ipStr = InetAddress.getByAddress(ipBytes).hostAddress
        attrsBuilder.put(AttributeKey.stringKey("net.peer.ip"), ipStr)
        attrsBuilder.put(AttributeKey.longKey("net.peer.port"), dstPort.toLong())
        attrsBuilder.put(AttributeKey.longKey("net.host.port"), srcPort.toLong())

        // Pod attributes
        if (podInfo != null) {
            attrsBuilder.put(AttributeKey.stringKey("k8s.pod.name"), podInfo.podName)
            attrsBuilder.put(AttributeKey.stringKey("k8s.namespace.name"), podInfo.namespace)
            attrsBuilder.put(AttributeKey.stringKey("k8s.container.name"), podInfo.containerName)
            attrsBuilder.put(AttributeKey.stringKey("k8s.pod.uid"), podInfo.podUid)
        }
        attrsBuilder.put(AttributeKey.longKey("kpod.cgroup.id"), cgroupId)

        // Protocol-specific attributes
        when (protocol) {
            PROTO_HTTP -> {
                val httpMethod = HTTP_METHODS.getOrElse(method) { "UNKNOWN" }
                attrsBuilder.put(AttributeKey.stringKey("http.method"), httpMethod)
                attrsBuilder.put(AttributeKey.longKey("http.status_code"), statusCode.toLong())
                if (urlPath.isNotEmpty()) {
                    attrsBuilder.put(AttributeKey.stringKey("http.target"), urlPath)
                }
            }
            PROTO_REDIS -> {
                val cmd = REDIS_COMMANDS.getOrElse(method) { "UNKNOWN" }
                attrsBuilder.put(AttributeKey.stringKey("db.system"), "redis")
                attrsBuilder.put(AttributeKey.stringKey("db.operation"), cmd)
                if (urlPath.isNotEmpty()) {
                    attrsBuilder.put(AttributeKey.stringKey("db.statement"), urlPath)
                }
            }
            PROTO_MYSQL -> {
                val stmt = MYSQL_STMTS.getOrElse(method) { "UNKNOWN" }
                attrsBuilder.put(AttributeKey.stringKey("db.system"), "mysql")
                attrsBuilder.put(AttributeKey.stringKey("db.operation"), stmt)
                if (urlPath.isNotEmpty()) {
                    attrsBuilder.put(AttributeKey.stringKey("db.statement"), urlPath)
                }
            }
        }

        attrsBuilder.put(AttributeKey.longKey("kpod.latency.ns"), latencyNs)
        val latencyMs = latencyNs / 1_000_000.0
        attrsBuilder.put(AttributeKey.doubleKey("kpod.latency.ms"), latencyMs)

        val span = spanBuilder.setAllAttributes(attrsBuilder.build()).startSpan()

        // Set status based on protocol
        when (protocol) {
            PROTO_HTTP -> {
                if (statusCode >= 400) {
                    span.setStatus(StatusCode.ERROR)
                }
            }
        }

        val endTimeNs = tsNs + latencyNs
        span.end(endTimeNs, TimeUnit.NANOSECONDS)
        spansExported.incrementAndGet()
    }

    private fun buildSpanName(protocol: Int, method: Int, urlPath: String): String {
        return when (protocol) {
            PROTO_HTTP -> {
                val httpMethod = HTTP_METHODS.getOrElse(method) { "UNKNOWN" }
                if (urlPath.isNotEmpty()) "$httpMethod $urlPath" else httpMethod
            }
            PROTO_REDIS -> {
                val cmd = REDIS_COMMANDS.getOrElse(method) { "UNKNOWN" }
                "REDIS $cmd"
            }
            PROTO_MYSQL -> {
                val stmt = MYSQL_STMTS.getOrElse(method) { "UNKNOWN" }
                "MYSQL $stmt"
            }
            else -> "UNKNOWN"
        }
    }
}
