package com.internal.kpodmetrics.profiling

import java.io.File
import java.util.TreeMap

class KallsymsResolver private constructor(
    private val symbols: TreeMap<Long, String>
) {
    companion object {
        fun fromFile(path: String = "/proc/kallsyms"): KallsymsResolver {
            return fromLines(File(path).readLines())
        }

        fun fromLines(lines: List<String>): KallsymsResolver {
            val symbols = TreeMap<Long, String>()
            for (line in lines) {
                val parts = line.split(Regex("\\s+")).filter { it.isNotEmpty() }
                if (parts.size < 3) continue
                // Parse as unsigned long, then convert to signed long to handle kernel addresses
                val addr = parts[0].toULongOrNull(16)?.toLong() ?: continue
                if (addr == 0L) continue
                val name = parts[2].substringBefore('\t')
                symbols[addr] = name
            }
            return KallsymsResolver(symbols)
        }
    }

    fun resolve(addr: Long): String? {
        // If the requested address is positive and all our symbols are negative (kernel space),
        // the address is definitely outside our range
        if (addr >= 0 && symbols.isEmpty()) return null
        if (addr >= 0 && symbols.firstKey() < 0) return null

        val entry = symbols.floorEntry(addr) ?: return null
        return entry.value
    }
}
