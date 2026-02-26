package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.generated.TcpdropMapReader
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory

class TcpdropCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(TcpdropCollector::class.java)

    companion object {
        private const val MAX_ENTRIES = 10240
    }

    fun collect() {
        if (!config.extended.tcpdrop) return

        val mapFd = programManager.getMapFd("tcpdrop", "tcp_drops")
        val entries = bridge.mapBatchLookupAndDelete(
            mapFd, TcpdropMapReader.CgroupKeyLayout.SIZE,
            TcpdropMapReader.CounterLayout.SIZE, MAX_ENTRIES
        )
        entries.forEach { (keyBytes, valueBytes) ->
            val cgroupId = TcpdropMapReader.CgroupKeyLayout.decodeCgroupId(keyBytes)
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@forEach

            val count = TcpdropMapReader.CounterLayout.decodeCount(valueBytes)

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )

            registry.counter("kpod.net.tcp.drops", tags).increment(count.toDouble())
        }
    }
}
