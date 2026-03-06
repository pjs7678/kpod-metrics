package com.internal.kpodmetrics.profiling

import java.util.TreeMap

data class ProcMapEntry(
    val start: Long,
    val end: Long,
    val fileOffset: Long,
    val pathname: String
)

class ElfSymbolResolver(
    private val maps: List<ProcMapEntry>,
    private val symtabs: Map<String, Map<Long, String>>
) {
    // Pre-build TreeMaps for symbol tables for efficient floor lookups
    private val sortedSymtabs: Map<String, TreeMap<Long, String>> = symtabs.mapValues { (_, syms) ->
        TreeMap(syms)
    }

    companion object {
        fun parseProcMaps(lines: List<String>): List<ProcMapEntry> {
            return lines.mapNotNull { line ->
                val parts = line.trim().split(Regex("\\s+"), limit = 6)
                if (parts.size < 6) return@mapNotNull null
                if (!parts[1].contains('x')) return@mapNotNull null
                val (startStr, endStr) = parts[0].split("-")
                val start = startStr.toLongOrNull(16) ?: return@mapNotNull null
                val end = endStr.toLongOrNull(16) ?: return@mapNotNull null
                val offset = parts[2].toLongOrNull(16) ?: 0L
                val pathname = parts[5]
                if (pathname.startsWith("[")) return@mapNotNull null
                ProcMapEntry(start, end, offset, pathname)
            }
        }
    }

    fun resolve(addr: Long): String? {
        val mapping = maps.find { addr in it.start until it.end } ?: return null
        val fileOffset = addr - mapping.start + mapping.fileOffset
        val symtab = sortedSymtabs[mapping.pathname]
        if (symtab != null) {
            val symbol = symtab.floorEntry(fileOffset)
            if (symbol != null) return symbol.value
        }
        return "[${mapping.pathname}+0x${fileOffset.toString(16)}]"
    }
}
