package com.internal.kpodmetrics.profiling

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class ElfSymbolResolverTest {

    @Test
    fun `resolves address via proc maps and simulated symtab`() {
        val maps = listOf(
            ProcMapEntry(0x400000L, 0x500000L, 0L, "/usr/bin/myapp")
        )
        val symtab = mapOf(
            0x1000L to "main",
            0x2000L to "doWork"
        )
        val resolver = ElfSymbolResolver(maps, mapOf("/usr/bin/myapp" to symtab))

        assertEquals("main", resolver.resolve(0x401000L))
        assertEquals("doWork", resolver.resolve(0x402000L))
    }

    @Test
    fun `returns binary+offset for unknown symbol`() {
        val maps = listOf(
            ProcMapEntry(0x400000L, 0x500000L, 0L, "/usr/bin/myapp")
        )
        val resolver = ElfSymbolResolver(maps, emptyMap())
        val result = resolver.resolve(0x401000L)
        assertNotNull(result)
        assertEquals("[/usr/bin/myapp+0x1000]", result)
    }

    @Test
    fun `returns null for unmapped address`() {
        val maps = listOf(
            ProcMapEntry(0x400000L, 0x500000L, 0L, "/usr/bin/myapp")
        )
        val resolver = ElfSymbolResolver(maps, emptyMap())
        assertNull(resolver.resolve(0x600000L))
    }

    @Test
    fun `parseProcMaps parses executable mappings`() {
        val lines = listOf(
            "00400000-00500000 r-xp 00000000 08:01 12345 /usr/bin/myapp",
            "00600000-00601000 rw-p 00200000 08:01 12345 /usr/bin/myapp",
            "7fff00000000-7fff00001000 r-xp 00000000 00:00 0 [vdso]"
        )
        val maps = ElfSymbolResolver.parseProcMaps(lines)
        assertEquals(1, maps.size)
        assertEquals(0x400000L, maps[0].start)
        assertEquals(0x500000L, maps[0].end)
        assertEquals("/usr/bin/myapp", maps[0].pathname)
    }

    @Test
    fun `resolves with file offset from mapping`() {
        val maps = listOf(
            ProcMapEntry(0x7f0000L, 0x7f1000L, 0x5000L, "/lib/libc.so")
        )
        val symtab = mapOf(0x5100L to "printf")
        val resolver = ElfSymbolResolver(maps, mapOf("/lib/libc.so" to symtab))
        assertEquals("printf", resolver.resolve(0x7f0100L))
    }
}
