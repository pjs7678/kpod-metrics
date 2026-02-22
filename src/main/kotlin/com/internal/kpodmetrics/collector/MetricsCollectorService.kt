package com.internal.kpodmetrics.collector

import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.Scheduled
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class MetricsCollectorService(
    private val cpuCollector: CpuSchedulingCollector,
    private val netCollector: NetworkCollector,
    private val memCollector: MemoryCollector,
    private val syscallCollector: SyscallCollector
) {
    private val log = LoggerFactory.getLogger(MetricsCollectorService::class.java)
    private val vtExecutor: ExecutorService = Executors.newVirtualThreadPerTaskExecutor()
    private val vtDispatcher = vtExecutor.asCoroutineDispatcher()

    @Scheduled(fixedDelayString = "\${kpod.poll-interval:15000}")
    fun collect() = runBlocking(vtDispatcher) {
        val collectors = listOf(
            "cpu" to cpuCollector::collect,
            "network" to netCollector::collect,
            "memory" to memCollector::collect,
            "syscall" to syscallCollector::collect
        )

        collectors.map { (name, collectFn) ->
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
