package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.generated.VfsstatMapReader
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory

class VfsstatCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(VfsstatCollector::class.java)

    companion object {
        private const val MAX_ENTRIES = 10240
    }

    fun collect() {
        if (!config.extended.vfsstat) return

        val mapFd = programManager.getMapFd("vfsstat", "vfs_stats")
        val entries = bridge.mapBatchLookupAndDelete(
            mapFd, VfsstatMapReader.CgroupKeyLayout.SIZE,
            VfsstatMapReader.VfsStatsLayout.SIZE, MAX_ENTRIES
        )
        entries.forEach { (keyBytes, valueBytes) ->
            val cgroupId = VfsstatMapReader.CgroupKeyLayout.decodeCgroupId(keyBytes)
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@forEach

            val reads = VfsstatMapReader.VfsStatsLayout.decodeReads(valueBytes)
            val writes = VfsstatMapReader.VfsStatsLayout.decodeWrites(valueBytes)
            val opens = VfsstatMapReader.VfsStatsLayout.decodeOpens(valueBytes)
            val fsyncs = VfsstatMapReader.VfsStatsLayout.decodeFsyncs(valueBytes)

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )

            registry.counter("kpod.vfs.reads", tags).increment(reads.toDouble())
            registry.counter("kpod.vfs.writes", tags).increment(writes.toDouble())
            registry.counter("kpod.vfs.opens", tags).increment(opens.toDouble())
            registry.counter("kpod.vfs.fsyncs", tags).increment(fsyncs.toDouble())
        }
    }
}
