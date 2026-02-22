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

class SyscallCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(SyscallCollector::class.java)

    companion object {
        private const val KEY_SIZE = 16
        private const val VALUE_SIZE = 240
        private const val MAX_SLOTS = 27

        private val SYSCALL_NAMES = mapOf(
            0 to "read", 1 to "write", 2 to "open", 3 to "close",
            42 to "connect", 43 to "accept", 44 to "sendto", 45 to "recvfrom",
            46 to "sendmsg", 47 to "recvmsg", 232 to "epoll_wait",
            257 to "openat", 288 to "accept4", 202 to "futex"
        )
    }

    fun collect() {
        if (config.syscall.enabled) {
            collectSyscallStats()
        }
    }

    private fun collectSyscallStats() {
        val mapFd = programManager.getMapFd("syscall", "syscall_stats_map")
        iterateMap(mapFd, KEY_SIZE, VALUE_SIZE) { keyBytes, valueBytes ->
            val keyBuf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = keyBuf.long
            val syscallNr = keyBuf.int
            // skip padding
            keyBuf.int

            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@iterateMap

            val syscallName = SYSCALL_NAMES[syscallNr] ?: "syscall_$syscallNr"

            val valueBuf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            val count = valueBuf.long
            val errorCount = valueBuf.long
            val latencySumNs = valueBuf.long
            // skip latency_slots (27 u64s) - not needed for summary metrics

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "syscall", syscallName
            )

            registry.counter("kpod.syscall.count", tags).increment(count.toDouble())
            registry.counter("kpod.syscall.errors", tags).increment(errorCount.toDouble())

            if (count > 0) {
                val avgLatencySeconds = (latencySumNs.toDouble() / count.toDouble()) / 1_000_000_000.0
                DistributionSummary.builder("kpod.syscall.latency")
                    .tags(tags)
                    .baseUnit("seconds")
                    .register(registry)
                    .record(avgLatencySeconds)
            }
        }
    }

    private fun iterateMap(
        mapFd: Int, keySize: Int, valueSize: Int,
        handler: (ByteArray, ByteArray) -> Unit
    ) {
        var key: ByteArray? = null
        while (true) {
            val nextKey = bridge.mapGetNextKey(mapFd, key, keySize) ?: break
            val value = bridge.mapLookup(mapFd, nextKey, valueSize)
            if (value != null) {
                handler(nextKey, value)
            }
            key = nextKey
        }
    }
}
