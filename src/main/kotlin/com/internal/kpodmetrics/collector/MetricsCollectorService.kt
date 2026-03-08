package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.config.CollectorIntervals
import com.internal.kpodmetrics.config.CollectorOverrides
import com.internal.kpodmetrics.discovery.PodCgroupMapper
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.Counter
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Timer
import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.Scheduled
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
    private val dnsCollector: DnsCollector,
    private val tcpPeerCollector: TcpPeerCollector,
    private val httpCollector: HttpCollector,
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
    private val collectorOverrides: CollectorOverrides = CollectorOverrides(),
    private val collectorIntervals: CollectorIntervals = CollectorIntervals(),
    private val basePollIntervalMs: Long = 29000,
    private val startupJitterMs: Long = 0,
    private val profilingPipeline: com.internal.kpodmetrics.profiling.ProfilingPipeline? = null
) {
    private val log = LoggerFactory.getLogger(MetricsCollectorService::class.java)
    private val vtExecutor: ExecutorService = Executors.newVirtualThreadPerTaskExecutor()
    private val vtDispatcher = vtExecutor.asCoroutineDispatcher()

    private val shuttingDown = AtomicBoolean(false)
    private val collecting = AtomicBoolean(false)
    private val firstRun = AtomicBoolean(true)
    private val cycleTimer: Timer? = registry?.timer("kpod.collection.cycle.duration")
    private val timeoutCounter: Counter? = registry?.counter("kpod.collection.timeouts.total")
    private val collectorTimers = ConcurrentHashMap<String, Timer>()
    private val collectorErrors = ConcurrentHashMap<String, Counter>()
    private val collectorSkips = ConcurrentHashMap<String, Counter>()
    private val lastSuccessfulCycle = AtomicReference<Instant?>(null)
    private val lastCollectorRun = ConcurrentHashMap<String, Instant>()
    private val lastCollectorError = ConcurrentHashMap<String, String>()

    private val intervalMap: Map<String, Long?> = mapOf(
        "cpu" to collectorIntervals.cpu,
        "network" to collectorIntervals.network,
        "syscall" to collectorIntervals.syscall,
        "biolatency" to collectorIntervals.biolatency,
        "cachestat" to collectorIntervals.cachestat,
        "tcpdrop" to collectorIntervals.tcpdrop,
        "hardirqs" to collectorIntervals.hardirqs,
        "softirqs" to collectorIntervals.softirqs,
        "execsnoop" to collectorIntervals.execsnoop,
        "dns" to collectorIntervals.dns,
        "tcpPeer" to collectorIntervals.tcpPeer,
        "http" to collectorIntervals.http,
        "diskIO" to collectorIntervals.diskIO,
        "ifaceNet" to collectorIntervals.ifaceNet,
        "filesystem" to collectorIntervals.filesystem,
        "memory" to collectorIntervals.memory
    )

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
        "dns" to collectorOverrides.dns,
        "tcpPeer" to collectorOverrides.tcpPeer,
        "http" to collectorOverrides.http,
        "diskIO" to collectorOverrides.diskIO,
        "ifaceNet" to collectorOverrides.ifaceNet,
        "filesystem" to collectorOverrides.filesystem,
        "memory" to collectorOverrides.memory
    )

    private fun isCollectorEnabled(name: String): Boolean = overrideMap[name] ?: true

    private fun shouldRunCollector(name: String): Boolean {
        if (!isCollectorEnabled(name)) return false
        val interval = intervalMap[name] ?: return true
        val lastRun = lastCollectorRun[name] ?: return true
        return java.time.Duration.between(lastRun, Instant.now()).toMillis() >= interval
    }

    private fun markCollectorRun(name: String) {
        lastCollectorRun[name] = Instant.now()
    }

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

    private fun collectorSkipCounter(name: String): Counter =
        collectorSkips.computeIfAbsent(name) {
            Counter.builder("kpod.collector.skipped.total")
                .tag("collector", name)
                .register(registry!!)
        }

    @Scheduled(fixedDelayString = "\${kpod.poll-interval:29000}", initialDelayString = "\${kpod.initial-delay:10000}")
    fun collect() = runBlocking(vtDispatcher) {
        if (shuttingDown.get()) return@runBlocking
        // Startup jitter: delay the first cycle by a random amount to prevent
        // thundering herd when all DaemonSet pods start simultaneously
        if (firstRun.compareAndSet(true, false) && startupJitterMs > 0) {
            val jitter = java.util.concurrent.ThreadLocalRandom.current().nextLong(startupJitterMs)
            if (jitter > 0) {
                log.info("Applying startup jitter: {}ms", jitter)
                delay(jitter)
            }
        }
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

        val allBpfCollectors = listOfNotNull(
            "cpu" to cpuCollector::collect,
            "network" to netCollector::collect,
            "syscall" to syscallCollector::collect,
            "biolatency" to biolatencyCollector::collect,
            "cachestat" to cachestatCollector::collect,
            "tcpdrop" to tcpdropCollector::collect,
            "hardirqs" to hardirqsCollector::collect,
            "softirqs" to softirqsCollector::collect,
            "execsnoop" to execsnoopCollector::collect,
            "dns" to dnsCollector::collect,
            "tcpPeer" to tcpPeerCollector::collect,
            "http" to httpCollector::collect,
            bpfMapStatsCollector?.let { "bpfMapStats" to it::collect }
        )
        val bpfCollectors = allBpfCollectors.filter { (name, _) ->
            val run = shouldRunCollector(name)
            if (!run && isCollectorEnabled(name) && registry != null) {
                collectorSkipCounter(name).increment()
            }
            run
        }

        val targets = try {
            podCgroupMapper?.resolve() ?: emptyList()
        } catch (e: Exception) {
            log.error("Failed to resolve cgroup targets: {}", e.message, e)
            emptyList()
        }

        registry?.gauge("kpod.discovery.pods.total", targets.size)

        val allCgroupCollectors = listOfNotNull(
            diskIOCollector?.let { "diskIO" to { it.collect(targets) } },
            ifaceNetCollector?.let { "ifaceNet" to { it.collect(targets) } },
            fsCollector?.let { "filesystem" to { it.collect(targets) } },
            memCollector?.let { "memory" to { it.collect(targets) } }
        )
        val cgroupCollectors = allCgroupCollectors.filter { (name, _) ->
            val run = shouldRunCollector(name)
            if (!run && isCollectorEnabled(name) && registry != null) {
                collectorSkipCounter(name).increment()
            }
            run
        }

        val completed = withTimeoutOrNull(collectionTimeoutMs) {
            (bpfCollectors + cgroupCollectors).map { (name, collectFn) ->
                launch {
                    try {
                        if (registry != null) {
                            collectorTimer(name).record(Runnable { collectFn() })
                        } else {
                            collectFn()
                        }
                        markCollectorRun(name)
                    } catch (e: Exception) {
                        log.error("Collector '{}' failed: {}", name, e.message, e)
                        lastCollectorError[name] = "${Instant.now()} ${e.message}"
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

        // Run profiling pipeline (collect → resolve → pprof → push)
        profilingPipeline?.let { pipeline ->
            try {
                pipeline.collect()
            } catch (e: Exception) {
                log.warn("Profiling pipeline failed: {}", e.message)
            }
        }

        lastSuccessfulCycle.set(Instant.now())
        cycleSample?.stop(cycleTimer!!)
    }

    fun isShuttingDown(): Boolean = shuttingDown.get()

    fun getLastCollectorErrors(): Map<String, String> = lastCollectorError.toMap()

    fun getEnabledCollectorCount(): Int {
        val bpfCount = listOf("cpu", "network", "syscall", "biolatency", "cachestat",
            "tcpdrop", "hardirqs", "softirqs", "execsnoop", "dns", "tcpPeer", "http").count { isCollectorEnabled(it) }
        val cgroupCount = listOfNotNull(
            diskIOCollector?.let { "diskIO" },
            ifaceNetCollector?.let { "ifaceNet" },
            fsCollector?.let { "filesystem" },
            memCollector?.let { "memory" }
        ).count { isCollectorEnabled(it) }
        return bpfCount + cgroupCount
    }

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
     * Handles BPF map cleanup when a pod's cgroup is deleted.
     *
     * All BPF data maps use LRU_HASH and are fully drained every collection cycle
     * via batchLookupAndDelete. Explicit per-key deletion is unnecessary because:
     * 1. Batch lookup-and-delete atomically reads and removes ALL entries each ~29s cycle
     * 2. LRU eviction automatically reclaims slots under memory pressure
     * 3. CgroupResolver's grace cache ensures in-flight metrics are still attributed
     *
     * Previously this method iterated all 21+ maps performing per-key JNI deletions,
     * including expensive getNextKey loops for compound-key maps (syscall, dns, tcp_peer).
     * In high-churn environments this caused significant JNI overhead on every pod deletion.
     */
    fun cleanupCgroupEntries(cgroupId: Long) {
        log.debug("Pod cgroup {} deleted; stale BPF entries will drain on next collection cycle", cgroupId)
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
