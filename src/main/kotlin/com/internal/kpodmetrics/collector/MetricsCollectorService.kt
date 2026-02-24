package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.discovery.PodCgroupMapper
import com.internal.kpodmetrics.model.PodCgroupTarget
import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.Scheduled
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class MetricsCollectorService(
    private val cpuCollector: CpuSchedulingCollector,
    private val netCollector: NetworkCollector,
    private val memCollector: MemoryCollector,
    private val syscallCollector: SyscallCollector,
    private val diskIOCollector: DiskIOCollector? = null,
    private val ifaceNetCollector: InterfaceNetworkCollector? = null,
    private val fsCollector: FilesystemCollector? = null,
    private val podCgroupMapper: PodCgroupMapper? = null,
    private val bridge: BpfBridge? = null,
    private val programManager: BpfProgramManager? = null,
    private val cgroupResolver: CgroupResolver? = null,
    private val bpfMapStatsCollector: BpfMapStatsCollector? = null
) {
    private val log = LoggerFactory.getLogger(MetricsCollectorService::class.java)
    private val vtExecutor: ExecutorService = Executors.newVirtualThreadPerTaskExecutor()
    private val vtDispatcher = vtExecutor.asCoroutineDispatcher()

    @Scheduled(fixedDelayString = "\${kpod.poll-interval:30000}")
    fun collect() = runBlocking(vtDispatcher) {
        val bpfCollectors = listOfNotNull(
            "cpu" to cpuCollector::collect,
            "network" to netCollector::collect,
            "memory" to memCollector::collect,
            "syscall" to syscallCollector::collect,
            bpfMapStatsCollector?.let { "bpfMapStats" to it::collect }
        )

        val targets = try {
            podCgroupMapper?.resolve() ?: emptyList()
        } catch (e: Exception) {
            log.error("Failed to resolve cgroup targets: {}", e.message, e)
            emptyList()
        }

        val cgroupCollectors = listOfNotNull(
            diskIOCollector?.let { "diskIO" to { it.collect(targets) } },
            ifaceNetCollector?.let { "ifaceNet" to { it.collect(targets) } },
            fsCollector?.let { "filesystem" to { it.collect(targets) } }
        )

        (bpfCollectors + cgroupCollectors).map { (name, collectFn) ->
            launch {
                try {
                    collectFn()
                } catch (e: Exception) {
                    log.error("Collector '{}' failed: {}", name, e.message, e)
                }
            }
        }.joinAll()

        cgroupResolver?.pruneGraceCache()
    }

    /**
     * Cleans up BPF map entries for a deleted pod's cgroup ID.
     * Iterates all relevant BPF maps and deletes entries matching the cgroup ID.
     */
    fun cleanupCgroupEntries(cgroupId: Long) {
        if (bridge == null || programManager == null) return

        val maps8ByteKey = listOf(
            "cpu_sched" to "runq_latency",
            "cpu_sched" to "ctx_switches",
            "mem" to "oom_kills",
            "mem" to "major_faults",
            "net" to "tcp_stats_map",
            "net" to "rtt_hist"
        )

        val key8 = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(cgroupId).array()

        for ((program, mapName) in maps8ByteKey) {
            if (!programManager.isProgramLoaded(program)) continue
            try {
                val fd = programManager.getMapFd(program, mapName)
                bridge.mapDelete(fd, key8)
            } catch (_: Exception) {
                // Map entry may not exist; ignore
            }
        }

        // syscall_stats_map has 16-byte keys (cgroup_id + syscall_nr + padding)
        // We cannot efficiently delete all syscall entries for a cgroup without iterating
        if (programManager.isProgramLoaded("syscall")) {
            try {
                val fd = programManager.getMapFd("syscall", "syscall_stats_map")
                val keysToDelete = mutableListOf<ByteArray>()
                var prevKey: ByteArray? = null
                while (true) {
                    val nextKey = bridge.mapGetNextKey(fd, prevKey, 16) ?: break
                    val keyCgroupId = ByteBuffer.wrap(nextKey).order(ByteOrder.LITTLE_ENDIAN).long
                    if (keyCgroupId == cgroupId) {
                        keysToDelete.add(nextKey)
                    }
                    prevKey = nextKey
                }
                for (k in keysToDelete) {
                    bridge.mapDelete(fd, k)
                }
            } catch (_: Exception) {
                // Ignore errors
            }
        }
    }

    fun close() {
        vtDispatcher.close()
        vtExecutor.close()
    }
}
