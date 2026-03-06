package com.internal.kpodmetrics.profiling

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class KallsymsResolverTest {

    @Test
    fun `resolves kernel address to symbol`() {
        val resolver = KallsymsResolver.fromLines(listOf(
            "ffffffff81000000 T _stext",
            "ffffffff81000100 T cpu_startup_entry",
            "ffffffff81000200 T do_idle"
        ))
        assertEquals("cpu_startup_entry", resolver.resolve(0xffffffff81000100u.toLong()))
        assertEquals("cpu_startup_entry", resolver.resolve(0xffffffff81000150u.toLong()))
        assertEquals("do_idle", resolver.resolve(0xffffffff81000200u.toLong()))
    }

    @Test
    fun `returns null for address below first symbol`() {
        val resolver = KallsymsResolver.fromLines(listOf(
            "ffffffff81000000 T _stext"
        ))
        assertNull(resolver.resolve(0x1000L))
    }

    @Test
    fun `skips zero addresses and malformed lines`() {
        val resolver = KallsymsResolver.fromLines(listOf(
            "0000000000000000 T invalid_at_zero",
            "not_a_hex T bad_line",
            "ffffffff81000000 T valid_symbol"
        ))
        assertEquals("valid_symbol", resolver.resolve(0xffffffff81000000u.toLong()))
    }

    @Test
    fun `handles tab-separated module names`() {
        val resolver = KallsymsResolver.fromLines(listOf(
            "ffffffff81000000 T symbol_name\t[module_name]"
        ))
        assertEquals("symbol_name", resolver.resolve(0xffffffff81000000u.toLong()))
    }
}
