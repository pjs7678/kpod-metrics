package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.generated.SyscallMapReader
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory

class SyscallCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String,
    private val histograms: Log2Histograms = Log2Histograms()
) {
    private val log = LoggerFactory.getLogger(SyscallCollector::class.java)

    companion object {
        private const val MAX_ENTRIES = 10240

        private val SYSCALLS = com.internal.kpodmetrics.bpf.SyscallTable.forArch()
    }

    fun collect() {
        if (config.syscall.enabled) {
            collectSyscallStats()
        }
    }

    private fun collectSyscallStats() {
        val mapFd = programManager.getMapFd("syscall", "syscall_stats")
        collectMap(mapFd, SyscallMapReader.SyscallKeyLayout.SIZE, SyscallMapReader.SyscallStatsLayout.SIZE) { keyBytes, valueBytes ->
            val cgroupId = SyscallMapReader.SyscallKeyLayout.decodeCgroupId(keyBytes)
            val syscallNr = SyscallMapReader.SyscallKeyLayout.decodeSyscallNr(keyBytes)

            val podInfo = cgroupResolver.resolve(cgroupId) ?: return@collectMap

            val syscallName = SYSCALLS.nameOf(syscallNr)

            val count = SyscallMapReader.SyscallStatsLayout.decodeCount(valueBytes)
            val errorCount = SyscallMapReader.SyscallStatsLayout.decodeErrorCount(valueBytes)
            val latencySumNs = SyscallMapReader.SyscallStatsLayout.decodeLatencySumNs(valueBytes)
            if (!BpfValueValidation.isValidLatency(count, latencySumNs, log, "syscall")) return@collectMap

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "syscall", syscallName
            )

            registry.counter("kpod.syscall.count", tags).increment(count.toDouble())
            registry.counter("kpod.syscall.errors", tags).increment(errorCount.toDouble())

            histograms.observe(
                Log2Histograms.SYSCALL, tags,
                SyscallMapReader.SyscallStatsLayout.decodeLatencySlotsArray(valueBytes), latencySumNs
            )
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
