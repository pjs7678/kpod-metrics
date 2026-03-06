package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.PodInfo
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

data class StackSample(
    val tgid: Int,
    val kernelStackIps: LongArray,
    val userStackIps: LongArray,
    val count: Long
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is StackSample) return false
        return tgid == other.tgid &&
            kernelStackIps.contentEquals(other.kernelStackIps) &&
            userStackIps.contentEquals(other.userStackIps) &&
            count == other.count
    }

    override fun hashCode(): Int {
        var result = tgid
        result = 31 * result + kernelStackIps.contentHashCode()
        result = 31 * result + userStackIps.contentHashCode()
        result = 31 * result + count.hashCode()
        return result
    }
}

class CpuProfileCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val maxStackDepth: Int = 128
) {
    private val log = LoggerFactory.getLogger(CpuProfileCollector::class.java)

    companion object {
        private const val MAX_ENTRIES = 65536
        private const val PROFILE_KEY_SIZE = 20  // u64 + u32 + i32 + i32
        private const val PROFILE_VALUE_SIZE = 8 // u64
    }

    fun collect(): Map<PodInfo, List<StackSample>> {
        val countsFd = programManager.getMapFd("cpu_profile", "profile_counts")
        val stacksFd = programManager.getMapFd("cpu_profile", "stack_traces")

        val entries = bridge.mapBatchLookupAndDelete(countsFd, PROFILE_KEY_SIZE, PROFILE_VALUE_SIZE, MAX_ENTRIES)
        if (entries.isEmpty()) return emptyMap()

        val stackCache = HashMap<Int, LongArray>()
        val result = HashMap<PodInfo, MutableList<StackSample>>()

        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long
            val tgid = buf.int
            val kernStackId = buf.int
            val userStackId = buf.int
            val count = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN).long

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue
            if (count <= 0) continue

            val kernIps = if (kernStackId >= 0) {
                stackCache.getOrPut(kernStackId) { readStack(stacksFd, kernStackId) }
            } else LongArray(0)

            val userIps = if (userStackId >= 0) {
                stackCache.getOrPut(userStackId) { readStack(stacksFd, userStackId) }
            } else LongArray(0)

            result.getOrPut(podInfo) { mutableListOf() }
                .add(StackSample(tgid, kernIps, userIps, count))
        }

        log.debug(
            "Collected {} profile entries for {} pods ({} unique stacks)",
            entries.size, result.size, stackCache.size
        )
        return result
    }

    private fun readStack(stacksFd: Int, stackId: Int): LongArray {
        val key = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(stackId).array()
        val valueSize = maxStackDepth * 8
        val raw = bridge.mapLookup(stacksFd, key, valueSize) ?: return LongArray(0)

        val buf = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN)
        val ips = mutableListOf<Long>()
        while (buf.remaining() >= 8) {
            val ip = buf.long
            if (ip == 0L) break
            ips.add(ip)
        }
        return ips.toLongArray()
    }
}
