package com.internal.kpodmetrics.bpf.programs

import com.internal.kpodmetrics.tracing.SpanCollector
import dev.ebpf.dsl.api.generateC
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * span_event is defined twice: as C in COMMON_PREAMBLE (used by the raw()-heavy L7 programs)
 * and as the DSL struct SpanEvent; SpanCollector decodes SPAN_EVENT_SIZE-byte records.
 * They drifted once (url_path missing from the C copy): http failed to compile and the
 * Redis/MySQL/Kafka/Mongo programs emitted 40-byte records that userspace read as 104.
 */
class SpanEventLayoutTest {

    private val expectedFields = listOf(
        "ts_ns", "latency_ns", "cgroup_id", "dst_ip", "dst_port", "src_port",
        "protocol", "method", "status_code", "direction", "pad", "url_path",
    )

    @Test
    fun `DSL struct size matches what SpanCollector decodes`() {
        assertEquals(SpanCollector.SPAN_EVENT_SIZE, SpanEvent.sizeBytes)
    }

    @Test
    fun `every span-emitting program defines span_event with the full layout`() {
        val programs = mapOf(
            "http" to httpProgram, "redis" to redisProgram, "mysql" to mysqlProgram,
            "kafka" to kafkaProgram, "mongo" to mongoProgram,
        )
        for ((name, prog) in programs) {
            val c = prog.generateC()
            val defs = Regex("""struct span_event \{([^}]*)\};""").findAll(c).toList()
            assertEquals(1, defs.size, "$name: exactly one span_event definition")
            val fields = defs[0].groupValues[1].lines()
                .map { it.substringBefore("//").trim() }
                .filter { it.endsWith(";") }
                .map { it.removeSuffix(";").substringAfterLast(' ').substringBefore('[') }
            assertEquals(expectedFields, fields, "$name: span_event fields")
            assertEquals(true, defs[0].value.contains("url_path[64]"), "$name: url_path is 64 bytes")
        }
    }
}
