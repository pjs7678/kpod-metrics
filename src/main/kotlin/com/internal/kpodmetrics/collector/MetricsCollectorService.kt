package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.config.CollectorOverrides
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
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
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
    private val memCollector: MemoryCgroupCollector? = null,
    private val podCgroupMapper: PodCgroupMapper? = null,
    private val bridge: BpfBridge? = null,
    private val programManager: BpfProgramManager? = null,
    private val cgroupResolver: CgroupResolver? = null,
    private val bpfMapStatsCollector: BpfMapStatsCollector? = null,
    private val registry: MeterRegistry? = null,
    private val collectionTimeoutMs: Long = 20000,
    private val collectorOverrides: CollectorOverrides = CollectorOverrides()
) {
    private val log = LoggerFactory.getLogger(MetricsCollectorService::class.java)
    private val vtExecutor: ExecutorService = Executors.newVirtualThreadPerTaskExecutor()
    private val vtDispatcher = vtExecutor.asCoroutineDispatcher()

    private val shuttingDown = AtomicBoolean(false)
    private val collecting = AtomicBoolean(false)
    private val cycleTimer: Timer? = registry?.timer("kpod.collection.cycle.duration")
    private val timeoutCounter: Counter? = registry?.counter("kpod.collection.timeouts.total")
    private val collectorTimers = ConcurrentHashMap<String, Timer>()
    private val collectorErrors = ConcurrentHashMap<String, Counter>()
    private val lastSuccessfulCycle = AtomicReference<Instant?>(null)

    private val overrideMap: Map<String, Boolean?> = mapOf(
        "cpu" to collectorOverrides.cpu,
        "network" to collectorOverrides.network,
        "syscall" to collectorOverrides.syscall,
        "biolatency" to collectorOverrides.biolatency,
        "cachestat" to collectorOverrides.cachestat,
        "tcpdrop" to collectorOverrides.tcpdrop,
        "hardirqs" to collectorOverrides.hardirqs,
        "softirqs" to collectorOverrides.softirqs,
        "execsnoop" to collectorOverrides.execsnoop,
        "diskIO" to collectorOverrides.diskIO,
        "ifaceNet" to collectorOverrides.ifaceNet,
        "filesystem" to collectorOverrides.filesystem,
        "memory" to collectorOverrides.memory
    )

    private fun isCollectorEnabled(name: String): Boolean = overrideMap[name] ?: true

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

    @Scheduled(fixedDelayString = "\${kpod.poll-interval:30000}", initialDelayString = "\${kpod.initial-delay:10000}")
    fun collect() = runBlocking(vtDispatcher) {
        if (shuttingDown.get()) return@runBlocking
        if (!collecting.compareAndSet(false, true)) {
            log.warn("Collection cycle skipped: previous cycle still running")
            return@runBlocking
        }
        try {
            collectInternal()
        } finally {
            collecting.set(false)
        }
    }

    private suspend fun collectInternal() {
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
        ).filter { isCollectorEnabled(it.first) }

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
            fsCollector?.let { "filesystem" to { it.collect(targets) } },
            memCollector?.let { "memory" to { it.collect(targets) } }
        ).filter { isCollectorEnabled(it.first) }

        val completed = withTimeoutOrNull(collectionTimeoutMs) {
            (bpfCollectors + cgroupCollectors).map { (name, collectFn) ->
                launch {
                    try {
                        if (registry != null) {
                            collectorTimer(name).record(Runnable { collectFn() })
                        } else {
                            collectFn()
                        }
                    } catch (e: Exception) {
                        log.error("Collector '{}' failed: {}", name, e.message, e)
                        if (registry != null) collectorErrorCounter(name).increment()
                    }
                }
            }.joinAll()
        }

        if (completed == null) {
            log.warn("Collection cycle timed out after {}ms", collectionTimeoutMs)
            timeoutCounter?.increment()
        }

        cgroupResolver?.pruneGraceCache()
        lastSuccessfulCycle.set(Instant.now())
        cycleSample?.stop(cycleTimer!!)
    }

    fun isShuttingDown(): Boolean = shuttingDown.get()

    /**
     * Removes Micrometer meters for a deleted pod to prevent cardinality growth.
     */
    fun cleanupPodMetrics(podName: String, namespace: String) {
        if (registry == null) return
        val metersToRemove = registry.meters.filter { meter ->
            val tags = meter.id.tags
            tags.any { it.key == "pod" && it.value == podName } &&
            tags.any { it.key == "namespace" && it.value == namespace }
        }
        for (meter in metersToRemove) {
            registry.remove(meter)
        }
        if (metersToRemove.isNotEmpty()) {
            log.debug("Removed {} stale meters for pod {}/{}", metersToRemove.size, namespace, podName)
        }

        // Clean gauge stores in cgroup collectors
        fsCollector?.removeStaleEntries(podName, namespace)
        memCollector?.removeStaleEntries(podName, namespace)
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
        shuttingDown.set(true)
        // Wait for in-flight collection cycle to drain
        val deadline = System.currentTimeMillis() + collectionTimeoutMs
        while (collecting.get() && System.currentTimeMillis() < deadline) {
            Thread.sleep(100)
        }
        if (collecting.get()) {
            log.warn("Shutdown: collection cycle did not drain within {}ms", collectionTimeoutMs)
        }
        vtExecutor.shutdown()
        vtExecutor.awaitTermination(5, TimeUnit.SECONDS)
        vtDispatcher.close()
    }
}
