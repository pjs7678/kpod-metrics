package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.discovery.PodCgroupMapper
import com.internal.kpodmetrics.model.PodCgroupTarget
import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.Scheduled
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
    private val podCgroupMapper: PodCgroupMapper? = null
) {
    private val log = LoggerFactory.getLogger(MetricsCollectorService::class.java)
    private val vtExecutor: ExecutorService = Executors.newVirtualThreadPerTaskExecutor()
    private val vtDispatcher = vtExecutor.asCoroutineDispatcher()

    @Scheduled(fixedDelayString = "\${kpod.poll-interval:15000}")
    fun collect() = runBlocking(vtDispatcher) {
        val bpfCollectors = listOf(
            "cpu" to cpuCollector::collect,
            "network" to netCollector::collect,
            "memory" to memCollector::collect,
            "syscall" to syscallCollector::collect
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
    }

    fun close() {
        vtDispatcher.close()
        vtExecutor.close()
    }
}
