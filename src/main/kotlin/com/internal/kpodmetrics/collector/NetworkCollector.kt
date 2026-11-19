package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.generated.NetMapReader
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory

class NetworkCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String,
    private val histograms: Log2Histograms = Log2Histograms()
) {
    private val log = LoggerFactory.getLogger(NetworkCollector::class.java)

    companion object {
        private const val MAX_ENTRIES = 10240
    }

    fun collect() {
        if (config.network.tcp.enabled) {
            collectTcpStats()
            collectRttHistogram()
        }
    }

    private fun collectTcpStats() {
        val mapFd = programManager.getMapFd("net", "tcp_stats_map")
        collectMap(mapFd, NetMapReader.CounterKeyLayout.SIZE, NetMapReader.TcpStatsLayout.SIZE) { keyBytes, valueBytes ->
            val cgroupId = NetMapReader.CounterKeyLayout.decodeCgroupId(keyBytes)
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@collectMap

            // bytes_sent/bytes_received omitted — cAdvisor already provides
            // container_network_transmit/receive_bytes_total
            val retransmits = NetMapReader.TcpStatsLayout.decodeRetransmits(valueBytes)
            val connections = NetMapReader.TcpStatsLayout.decodeConnections(valueBytes)

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )

            registry.counter("kpod.net.tcp.retransmits", tags).increment(retransmits.toDouble())
            registry.counter("kpod.net.tcp.connections", tags).increment(connections.toDouble())
        }
    }

    /**
     * RTT distribution from the per-event rtt_hist map (tcp_probe). The tcp_stats rtt_sum/rtt_count
     * fields carry the same events without buckets, so RTT is exported only from here.
     */
    private fun collectRttHistogram() {
        val mapFd = programManager.getMapFd("net", "rtt_hist")
        collectMap(mapFd, NetMapReader.HistKeyLayout.SIZE, NetMapReader.HistValueLayout.SIZE) { keyBytes, valueBytes ->
            val cgroupId = NetMapReader.HistKeyLayout.decodeCgroupId(keyBytes)
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@collectMap
            val count = NetMapReader.HistValueLayout.decodeCount(valueBytes)
            val sumNs = NetMapReader.HistValueLayout.decodeSumNs(valueBytes)
            if (!BpfValueValidation.isValidLatency(count, sumNs, log, "net_rtt")) return@collectMap

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )
            histograms.observe(Log2Histograms.TCP_RTT, tags, NetMapReader.HistValueLayout.decodeSlotsArray(valueBytes), sumNs)
        }
    }

    private fun collectMap(
        mapFd: Int, keySize: Int, valueSize: Int,
        handler: (ByteArray, ByteArray) -> Unit
    ) {
        val entries = bridge.mapBatchLookupAndDelete(mapFd, keySize, valueSize, MAX_ENTRIES)
        entries.forEach { (key, value) -> handler(key, value) }
    }
}
