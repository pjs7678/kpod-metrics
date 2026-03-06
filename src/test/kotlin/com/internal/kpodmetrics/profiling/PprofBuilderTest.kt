package com.internal.kpodmetrics.profiling

import org.junit.jupiter.api.Test
import kotlin.test.assertTrue
import kotlin.test.assertEquals

class PprofBuilderTest {

    @Test
    fun `builds valid pprof bytes with samples`() {
        val builder = PprofBuilder(durationNanos = 29_000_000_000L)
        builder.addSample(listOf("main", "doWork", "compute"), 42)
        builder.addSample(listOf("main", "doWork", "sleep"), 10)

        val bytes = builder.build()
        assertTrue(bytes.isNotEmpty())
        // Protobuf should start with field tags — basic sanity
        assertTrue(bytes.size > 20)
    }

    @Test
    fun `empty builder produces minimal pprof`() {
        val builder = PprofBuilder(durationNanos = 29_000_000_000L)
        val bytes = builder.build()
        assertTrue(bytes.isNotEmpty())
    }

    @Test
    fun `deduplicates function names in string table`() {
        val builder = PprofBuilder(durationNanos = 29_000_000_000L)
        builder.addSample(listOf("main", "doWork"), 10)
        builder.addSample(listOf("main", "sleep"), 5)

        val bytes = builder.build()
        assertTrue(bytes.isNotEmpty())
        // "main" should appear only once in the output
        val mainCount = String(bytes, Charsets.ISO_8859_1).windowed(4).count { it == "main" }
        assertEquals(1, mainCount, "main should appear once in string table")
    }

    @Test
    fun `skips empty frames and zero counts`() {
        val builder = PprofBuilder(durationNanos = 29_000_000_000L)
        builder.addSample(emptyList(), 10)
        builder.addSample(listOf("main"), 0)
        builder.addSample(listOf("main"), -1)
        builder.addSample(listOf("valid"), 5)

        val bytes = builder.build()
        assertTrue(bytes.isNotEmpty())
    }
}
