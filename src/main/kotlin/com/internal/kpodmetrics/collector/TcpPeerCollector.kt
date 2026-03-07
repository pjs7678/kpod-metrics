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

class TcpPeerCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String,
    private val podIpResolver: PodIpResolver
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
    }

    private fun collectConnections() {
        val mapFd = programManager.getMapFd("tcp_peer", "tcp_peer_conns")
        val entries = bridge.mapBatchLookupAndDelete(mapFd, CONN_KEY_SIZE, CONN_VALUE_SIZE, MAX_ENTRIES)
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
        }
    }

    private fun collectRtt() {
        val mapFd = programManager.getMapFd("tcp_peer", "tcp_peer_rtt")
        val entries = bridge.mapBatchLookupAndDelete(mapFd, RTT_KEY_SIZE, RTT_VALUE_SIZE, MAX_ENTRIES)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long
            val remoteIp4 = buf.int
            val remotePort = buf.short.toInt() and 0xFFFF

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue

            val valBuf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            // Skip 27 histogram slots (27 * 8 = 216 bytes)
            valBuf.position(27 * 8)
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
        }
    }
}
