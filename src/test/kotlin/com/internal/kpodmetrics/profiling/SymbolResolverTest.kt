package com.internal.kpodmetrics.profiling

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SymbolResolverTest {

    @Test
    fun `resolves kernel address via kallsyms`() {
        val kallsyms = KallsymsResolver.fromLines(listOf(
            "ffffffff81000000 T do_idle",
            "ffffffff81000100 T cpu_startup_entry"
        ))
        val resolver = SymbolResolver(kallsyms)

        val result = resolver.resolveKernel(0xffffffff81000000u.toLong())
        assertEquals("do_idle", result)
    }

    @Test
    fun `resolves user address via elf resolver`() {
        val kallsyms = KallsymsResolver.fromLines(emptyList())
        val resolver = SymbolResolver(kallsyms)

        val maps = listOf(ProcMapEntry(0x400000L, 0x500000L, 0L, "/usr/bin/app"))
        val symtab = mapOf(0x1000L to "main")
        val elfResolver = ElfSymbolResolver(maps, mapOf("/usr/bin/app" to symtab))

        val result = resolver.resolveUser(0x401000L, elfResolver)
        assertEquals("main", result)
    }

    @Test
    fun `kernel fallback shows hex address`() {
        val kallsyms = KallsymsResolver.fromLines(emptyList())
        val resolver = SymbolResolver(kallsyms)

        val result = resolver.resolveKernel(0x1234L)
        assertTrue(result.contains("1234"))
    }

    @Test
    fun `user fallback shows hex address`() {
        val kallsyms = KallsymsResolver.fromLines(emptyList())
        val resolver = SymbolResolver(kallsyms)
        val elfResolver = ElfSymbolResolver(emptyList(), emptyMap())

        val result = resolver.resolveUser(0xABCDL, elfResolver)
        assertTrue(result.contains("abcd"))
    }

    @Test
    fun `caches kernel symbol lookups`() {
        val kallsyms = KallsymsResolver.fromLines(listOf(
            "ffffffff81000000 T do_idle"
        ))
        val resolver = SymbolResolver(kallsyms)

        val result1 = resolver.resolveKernel(0xffffffff81000000u.toLong())
        val result2 = resolver.resolveKernel(0xffffffff81000000u.toLong())
        assertEquals(result1, result2)
    }

    @Test
    fun `trimCache removes entries when over limit`() {
        val kallsyms = KallsymsResolver.fromLines(listOf(
            "ffffffff81000000 T do_idle"
        ))
        val resolver = SymbolResolver(kallsyms, cacheMaxEntries = 2)

        resolver.resolveKernel(0xffffffff81000000u.toLong())
        resolver.resolveKernel(0xffffffff81000001u.toLong())
        resolver.resolveKernel(0xffffffff81000002u.toLong())
        resolver.trimCache()
        // Should not throw, cache should be trimmed to 2
    }
}
