package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.discovery.PodCgroupMapper
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.Counter
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Timer
import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.Scheduled
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference

class MetricsCollectorService(
    private val cpuCollector: CpuSchedulingCollector,
    private val netCollector: NetworkCollector,
    private val syscallCollector: SyscallCollector,
    private val biolatencyCollector: BiolatencyCollector,
    private val cachestatCollector: CachestatCollector,
    private val tcpdropCollector: TcpdropCollector,
    private val hardirqsCollector: HardirqsCollector,
    private val softirqsCollector: SoftirqsCollector,
    private val execsnoopCollector: ExecsnoopCollector,
    private val diskIOCollector: DiskIOCollector? = null,
    private val ifaceNetCollector: InterfaceNetworkCollector? = null,
    private val fsCollector: FilesystemCollector? = null,
    private val podCgroupMapper: PodCgroupMapper? = null,
    private val bridge: BpfBridge? = null,
    private val programManager: BpfProgramManager? = null,
    private val cgroupResolver: CgroupResolver? = null,
    private val bpfMapStatsCollector: BpfMapStatsCollector? = null,
    private val registry: MeterRegistry? = null
) {
    private val log = LoggerFactory.getLogger(MetricsCollectorService::class.java)
    private val vtExecutor: ExecutorService = Executors.newVirtualThreadPerTaskExecutor()
    private val vtDispatcher = vtExecutor.asCoroutineDispatcher()

    private val cycleTimer: Timer? = registry?.timer("kpod.collection.cycle.duration")
    private val collectorTimers = ConcurrentHashMap<String, Timer>()
    private val collectorErrors = ConcurrentHashMap<String, Counter>()
    private val lastSuccessfulCycle = AtomicReference<Instant?>(null)

    fun getLastSuccessfulCycle(): Instant? = lastSuccessfulCycle.get()

    private fun collectorTimer(name: String): Timer =
        collectorTimers.computeIfAbsent(name) {
            Timer.builder("kpod.collector.duration")
                .tag("collector", name)
                .register(registry!!)
        }

    private fun collectorErrorCounter(name: String): Counter =
        collectorErrors.computeIfAbsent(name) {
            Counter.builder("kpod.collector.errors.total")
                .tag("collector", name)
                .register(registry!!)
        }

    @Scheduled(fixedDelayString = "\${kpod.poll-interval:30000}")
    fun collect() = runBlocking(vtDispatcher) {
        val cycleSample = cycleTimer?.let { Timer.start() }

        val bpfCollectors = listOfNotNull(
            "cpu" to cpuCollector::collect,
            "network" to netCollector::collect,
            "syscall" to syscallCollector::collect,
            "biolatency" to biolatencyCollector::collect,
            "cachestat" to cachestatCollector::collect,
            "tcpdrop" to tcpdropCollector::collect,
            "hardirqs" to hardirqsCollector::collect,
            "softirqs" to softirqsCollector::collect,
            "execsnoop" to execsnoopCollector::collect,
            bpfMapStatsCollector?.let { "bpfMapStats" to it::collect }
        )

        val targets = try {
            podCgroupMapper?.resolve() ?: emptyList()
        } catch (e: Exception) {
            log.error("Failed to resolve cgroup targets: {}", e.message, e)
            emptyList()
        }

        registry?.gauge("kpod.discovery.pods.total", targets.size)

        val cgroupCollectors = listOfNotNull(
            diskIOCollector?.let { "diskIO" to { it.collect(targets) } },
            ifaceNetCollector?.let { "ifaceNet" to { it.collect(targets) } },
            fsCollector?.let { "filesystem" to { it.collect(targets) } }
        )

        (bpfCollectors + cgroupCollectors).map { (name, collectFn) ->
            launch {
                try {
                    if (registry != null) {
                        collectorTimer(name).record { collectFn() }
                    } else {
                        collectFn()
                    }
                } catch (e: Exception) {
                    log.error("Collector '{}' failed: {}", name, e.message, e)
                    if (registry != null) collectorErrorCounter(name).increment()
                }
            }
        }.joinAll()

        cgroupResolver?.pruneGraceCache()
        lastSuccessfulCycle.set(Instant.now())
        cycleSample?.stop(cycleTimer!!)
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
            "net" to "tcp_stats_map",
            "net" to "rtt_hist",
            // BCC-style tool maps (all keyed by cgroup_key or hist_key = 8 bytes)
            "biolatency" to "bio_latency",
            "cachestat" to "cache_stats",
            "tcpdrop" to "tcp_drops",
            "hardirqs" to "irq_latency",
            "hardirqs" to "irq_count",
            "softirqs" to "softirq_latency",
            "execsnoop" to "exec_stats"
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
