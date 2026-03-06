package com.internal.kpodmetrics.profiling

import org.slf4j.LoggerFactory
import java.io.File
import java.util.concurrent.ConcurrentHashMap

class SymbolResolver(
    private val kallsyms: KallsymsResolver,
    private val cacheMaxEntries: Int = 50000
) {
    private val log = LoggerFactory.getLogger(SymbolResolver::class.java)
    private val userResolverCache = ConcurrentHashMap<Int, ElfSymbolResolver>()
    private val symbolCache = ConcurrentHashMap<Long, String>()

    fun resolveKernel(addr: Long): String {
        return symbolCache.getOrPut(addr) {
            kallsyms.resolve(addr) ?: "[kernel+0x${addr.toULong().toString(16)}]"
        }
    }

    fun resolveUser(addr: Long, elfResolver: ElfSymbolResolver): String {
        return elfResolver.resolve(addr) ?: "[unknown+0x${addr.toULong().toString(16)}]"
    }

    fun getOrCreateElfResolver(tgid: Int): ElfSymbolResolver? {
        return userResolverCache.getOrPut(tgid) {
            try {
                val mapsLines = File("/proc/$tgid/maps").readLines()
                val maps = ElfSymbolResolver.parseProcMaps(mapsLines)
                ElfSymbolResolver(maps, emptyMap())
            } catch (e: Exception) {
                log.debug("Cannot read /proc/{}/maps: {}", tgid, e.message)
                return null
            }
        }
    }

    fun evictProcess(tgid: Int) {
        userResolverCache.remove(tgid)
    }

    fun trimCache() {
        if (symbolCache.size > cacheMaxEntries) {
            val toRemove = symbolCache.size - cacheMaxEntries
            symbolCache.keys.take(toRemove).forEach { symbolCache.remove(it) }
        }
    }
}
