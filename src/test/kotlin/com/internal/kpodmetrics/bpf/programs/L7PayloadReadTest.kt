package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.generateC
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression tests for HTTP status codes never being recorded (dogfooding: every request had
 * status_code="0" and 400+ requests sat unmatched in http_inflight).
 */
class L7PayloadReadTest {
    private val programs = mapOf(
        "http" to httpProgram, "redis" to redisProgram, "mysql" to mysqlProgram,
        "kafka" to kafkaProgram, "mongo" to mongoProgram,
    )

    /** Mirrors the generated C: clamp, then mask with MAX_PAYLOAD - 1 (the verifier bound). */
    private fun bytesRead(len: Int, max: Int, clampTo: Int) = minOf(len, clampTo) and (max - 1)

    @Test
    fun `old clamp read zero bytes for any payload of at least MAX_PAYLOAD`() {
        // nginx response headers are ~150+ bytes; MAX_PAYLOAD for http is 128
        assertEquals(0, bytesRead(160, 128, clampTo = 128))
        assertEquals(127, bytesRead(160, 128, clampTo = 127))
    }

    @Test
    fun `no program clamps to MAX_PAYLOAD before masking`() {
        for ((name, prog) in programs) {
            val c = prog.generateC()
            assertFalse(c.contains("to_read = MAX_PAYLOAD;"), "$name still clamps to MAX_PAYLOAD (masked to 0)")
            assertTrue(c.contains("if (to_read > MAX_PAYLOAD - 1) to_read = MAX_PAYLOAD - 1;"), name)
        }
    }

    /** Stash map name and the kretprobe's minimum-length check, per program. */
    private val recvStash = mapOf(
        "http" to ("http_recv_stash" to "ret < 8"), "redis" to ("redis_rcv_stash" to "ret < 3"),
        "mysql" to ("mysql_rcv_stash" to "ret < 5"), "kafka" to ("kafka_rcv_stash" to "ret < 12"),
        "mongo" to ("mongo_rcv_stash" to "ret < 21"),
    )

    @Test
    fun `recv reads the buffer captured at entry, keyed by thread`() {
        for ((name, prog) in programs) {
            val (stash, lenCheck) = recvStash.getValue(name)
            val c = prog.generateC()
            val exit = Regex("""int kretprobe_tcp_recvmsg\(.*?\n\}""", RegexOption.DOT_MATCHES_ALL).find(c)!!.value
            assertFalse(exit.contains("read_first_iov"), "$name: msg_iter has advanced by return; must not re-read it")
            assertTrue(exit.contains("bpf_probe_read_user(buf, to_read, iov_base)"), name)
            assertTrue(exit.contains("if (to_read > iov_len)"), "$name: read must stay within the first iovec")
            assertTrue(exit.contains("bpf_get_current_pid_tgid()"), "$name: stash keyed by thread, not per-CPU")
            val del = exit.indexOf("bpf_map_delete_elem(&$stash")
            assertTrue(del in 0 until exit.indexOf(lenCheck), "$name: stash consumed before the length check")
            assertFalse(
                Regex("""PERCPU_ARRAY\);[^}]*struct $stash\)""").containsMatchIn(c),
                "$name: per-CPU stash is overwritten while a recv sleeps",
            )
        }
    }
}
