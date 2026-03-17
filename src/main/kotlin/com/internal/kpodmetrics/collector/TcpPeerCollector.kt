package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.config.ResolvedConfig
import com.internal.kpodmetrics.topology.ConnectionRecord
import com.internal.kpodmetrics.topology.RttRecord
import com.internal.kpodmetrics.topology.TopologyAggregator
import io.micrometer.core.instrument.DistributionSummary
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

class TcpPeerCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String,
    private val podIpResolver: PodIpResolver,
    private val topologyAggregator: TopologyAggregator? = null
) {
    private val log = LoggerFactory.getLogger(TcpPeerCollector::class.java)

    companion object {
        private const val MAX_ENTRIES = 10240
        private const val CONN_KEY_SIZE = 20   // u64 + u32 + u16 + u8 + u8
        private const val CONN_VALUE_SIZE = 8  // u64
        private const val RTT_KEY_SIZE = 16    // u64 + u32 + u16 + u16
        private const val RTT_VALUE_SIZE = 232 // u64[27] + u64 + u64

        fun ipToString(ip: Int): String {
            return "${ip and 0xFF}.${(ip shr 8) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 24) and 0xFF}"
        }

        fun directionLabel(direction: Byte): String = when (direction.toInt()) {
            0 -> "client"
            1 -> "server"
            else -> "unknown"
        }
    }

    fun collect() {
        if (!config.extended.tcpPeer) return
        if (!programManager.isProgramLoaded("tcp_peer")) return
        podIpResolver.refresh()
        collectConnections()
        collectRtt()
        topologyAggregator?.advanceWindow()
    }

    private fun collectConnections() {
        val mapFd = programManager.getMapFd("tcp_peer", "tcp_peer_conns")
        val entries = bridge.mapBatchLookupAndDelete(mapFd, CONN_KEY_SIZE, CONN_VALUE_SIZE, MAX_ENTRIES)
        val records = mutableListOf<ConnectionRecord>()
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long
            val remoteIp4 = buf.int
            val remotePort = buf.short.toInt() and 0xFFFF
            val direction = buf.get()

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue
            val count = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN).long

            val remoteIpStr = ipToString(remoteIp4)
            val peerInfo = podIpResolver.resolve(remoteIpStr)

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "remote_ip", remoteIpStr,
                "remote_port", remotePort.toString(),
                "direction", directionLabel(direction),
                "remote_pod", peerInfo?.podName ?: "",
                "remote_service", peerInfo?.serviceName ?: ""
            )
            registry.counter("kpod.net.tcp.peer.connections", tags).increment(count.toDouble())

            if (topologyAggregator != null) {
                val srcService = deriveServiceName(podInfo.podName)
                val dstId: String
                val dstName: String
                val dstNamespace: String?
                val dstType: String

                if (peerInfo?.serviceName != null) {
                    dstId = "${peerInfo.namespace}/${peerInfo.serviceName}"
                    dstName = peerInfo.serviceName
                    dstNamespace = peerInfo.namespace
                    dstType = "service"
                } else if (peerInfo?.podName != null) {
                    val derivedService = deriveServiceName(peerInfo.podName)
                    dstId = "${peerInfo.namespace}/$derivedService"
                    dstName = derivedService
                    dstNamespace = peerInfo.namespace
                    dstType = "service"
                } else {
                    dstId = "external:${remoteIpStr}:${remotePort}"
                    dstName = "external:${remoteIpStr}:${remotePort}"
                    dstNamespace = null
                    dstType = "external"
                }

                records.add(ConnectionRecord(
                    srcNamespace = podInfo.namespace,
                    srcPod = podInfo.podName,
                    srcService = srcService,
                    dstId = dstId,
                    dstName = dstName,
                    dstNamespace = dstNamespace,
                    dstType = dstType,
                    requestCount = count,
                    rttSumUs = 0,
                    rttCount = 0,
                    direction = directionLabel(direction),
                    remotePort = remotePort
                ))
            }
        }
        topologyAggregator?.ingest(records)
    }

    private fun deriveServiceName(podName: String): String {
        return podName
            .replace(Regex("-[a-f0-9]{5,10}-[a-z0-9]{5}$"), "")  // deployment-hash-hash
            .replace(Regex("-[0-9]+$"), "")                         // statefulset-N
    }

    private fun collectRtt() {
        val mapFd = programManager.getMapFd("tcp_peer", "tcp_peer_rtt")
        val entries = bridge.mapBatchLookupAndDelete(mapFd, RTT_KEY_SIZE, RTT_VALUE_SIZE, MAX_ENTRIES)
        val rttRecords = mutableListOf<RttRecord>()
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long
            val remoteIp4 = buf.int
            val remotePort = buf.short.toInt() and 0xFFFF

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue

            val valBuf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            // Read 27 histogram slots
            val histogram = LongArray(TopologyAggregator.RTT_HISTOGRAM_SLOTS)
            for (i in histogram.indices) {
                histogram[i] = valBuf.long
            }
            val count = valBuf.long
            val sumUs = valBuf.long

            if (count <= 0 || sumUs <= 0) continue

            val remoteIpStr = ipToString(remoteIp4)
            val peerInfo = podIpResolver.resolve(remoteIpStr)

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "remote_ip", remoteIpStr,
                "remote_port", remotePort.toString(),
                "remote_pod", peerInfo?.podName ?: "",
                "remote_service", peerInfo?.serviceName ?: ""
            )

            val avgRttSeconds = (sumUs.toDouble() / count.toDouble()) / 1_000_000.0
            DistributionSummary.builder("kpod.net.tcp.peer.rtt")
                .tags(tags)
                .baseUnit("seconds")
                .register(registry)
                .record(avgRttSeconds)

            // Feed RTT + histogram into topology aggregator
            if (topologyAggregator != null) {
                val srcService = deriveServiceName(podInfo.podName)
                val dstId = if (peerInfo?.serviceName != null) {
                    "${peerInfo.namespace}/${peerInfo.serviceName}"
                } else if (peerInfo?.podName != null) {
                    "${peerInfo.namespace}/${deriveServiceName(peerInfo.podName)}"
                } else {
                    "external:${remoteIpStr}:${remotePort}"
                }
                rttRecords.add(RttRecord(
                    srcService = srcService,
                    dstId = dstId,
                    rttSumUs = sumUs,
                    rttCount = count,
                    histogram = histogram
                ))
            }
        }
        topologyAggregator?.ingestRtt(rttRecords)
    }
}
