package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.generated.CachestatMapReader
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory

class CachestatCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(CachestatCollector::class.java)

    companion object {
        private const val MAX_ENTRIES = 10240
    }

    fun collect() {
        if (!config.extended.cachestat) return

        val mapFd = programManager.getMapFd("cachestat", "cache_stats")
        val entries = bridge.mapBatchLookupAndDelete(
            mapFd, CachestatMapReader.CgroupKeyLayout.SIZE,
            CachestatMapReader.CacheStatsLayout.SIZE, MAX_ENTRIES
        )
        entries.forEach { (keyBytes, valueBytes) ->
            val cgroupId = CachestatMapReader.CgroupKeyLayout.decodeCgroupId(keyBytes)
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@forEach

            val accesses = CachestatMapReader.CacheStatsLayout.decodeAccesses(valueBytes)
            val additions = CachestatMapReader.CacheStatsLayout.decodeAdditions(valueBytes)
            val dirtied = CachestatMapReader.CacheStatsLayout.decodeDirtied(valueBytes)
            val bufDirtied = CachestatMapReader.CacheStatsLayout.decodeBufDirtied(valueBytes)

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )

            registry.counter("kpod.mem.cache.accesses", tags).increment(accesses.toDouble())
            registry.counter("kpod.mem.cache.additions", tags).increment(additions.toDouble())
            registry.counter("kpod.mem.cache.dirtied", tags).increment(dirtied.toDouble())
            registry.counter("kpod.mem.cache.buf.dirtied", tags).increment(bufDirtied.toDouble())
        }
    }
}
