package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.DistributionSummary
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

class NetworkCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(NetworkCollector::class.java)

    companion object {
        private const val KEY_SIZE = 8
        private const val TCP_STATS_VALUE_SIZE = 48
        private const val MAX_ENTRIES = 10240
    }

    fun collect() {
        if (config.network.tcp.enabled) {
            collectTcpStats()
        }
    }

    private fun collectTcpStats() {
        val mapFd = programManager.getMapFd("net", "tcp_stats_map")
        collectMap(mapFd, KEY_SIZE, TCP_STATS_VALUE_SIZE) { keyBytes, valueBytes ->
            val cgroupId = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN).long
            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@collectMap

            val buf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            val bytesSent = buf.long
            val bytesReceived = buf.long
            val retransmits = buf.long
            val connections = buf.long
            val rttSumUs = buf.long
            val rttCount = buf.long

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )

            registry.counter("kpod.net.tcp.bytes.sent", tags).increment(bytesSent.toDouble())
            registry.counter("kpod.net.tcp.bytes.received", tags).increment(bytesReceived.toDouble())
            registry.counter("kpod.net.tcp.retransmits", tags).increment(retransmits.toDouble())
            registry.counter("kpod.net.tcp.connections", tags).increment(connections.toDouble())

            if (rttCount > 0) {
                val avgRttSeconds = (rttSumUs.toDouble() / rttCount.toDouble()) / 1_000_000.0
                DistributionSummary.builder("kpod.net.tcp.rtt")
                    .tags(tags)
                    .baseUnit("seconds")
                    .register(registry)
                    .record(avgRttSeconds)
            }
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
