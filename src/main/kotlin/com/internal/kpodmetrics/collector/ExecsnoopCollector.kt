package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.generated.ExecsnoopMapReader
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory

class ExecsnoopCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(ExecsnoopCollector::class.java)

    companion object {
        private const val MAX_ENTRIES = 10240
    }

    fun collect() {
        if (!config.extended.execsnoop) return

        val mapFd = programManager.getMapFd("execsnoop", "exec_stats")
        val entries = bridge.mapBatchLookupAndDelete(
            mapFd, ExecsnoopMapReader.CgroupKeyLayout.SIZE,
            ExecsnoopMapReader.ExecStatsLayout.SIZE, MAX_ENTRIES
        )
        entries.forEach { (keyBytes, valueBytes) ->
            val cgroupId = ExecsnoopMapReader.CgroupKeyLayout.decodeCgroupId(keyBytes)
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@forEach

            val execs = ExecsnoopMapReader.ExecStatsLayout.decodeExecs(valueBytes)
            val exits = ExecsnoopMapReader.ExecStatsLayout.decodeExits(valueBytes)
            val forks = ExecsnoopMapReader.ExecStatsLayout.decodeForks(valueBytes)

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )

            registry.counter("kpod.proc.execs", tags).increment(execs.toDouble())
            registry.counter("kpod.proc.exits", tags).increment(exits.toDouble())
            registry.counter("kpod.proc.forks", tags).increment(forks.toDouble())
        }
    }
}
