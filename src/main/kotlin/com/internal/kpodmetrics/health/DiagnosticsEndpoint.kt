package com.internal.kpodmetrics.health

import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.collector.MetricsCollectorService
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.MeterRegistry
import org.springframework.boot.actuate.endpoint.annotation.Endpoint
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation
import java.time.Duration
import java.time.Instant

@Endpoint(id = "kpodDiagnostics")
class DiagnosticsEndpoint(
    private val collectorService: MetricsCollectorService,
    private val programManager: BpfProgramManager?,
    private val config: ResolvedConfig,
    private val registry: MeterRegistry? = null,
    private val startTime: Instant = Instant.now()
) {

    companion object {
        val BPF_METRIC_MAP = mapOf(
            "cpu_sched" to listOf("kpod.cpu.context.switches"),
            "net" to listOf("kpod.net.tcp.connections"),
            "syscall" to listOf("kpod.syscall.count"),
            "biolatency" to listOf("kpod.disk.io.latency"),
            "cachestat" to listOf("kpod.mem.cache.accesses"),
            "tcpdrop" to listOf("kpod.net.tcp.drops"),
            "hardirqs" to listOf("kpod.irq.hw.count"),
            "softirqs" to listOf("kpod.irq.sw.count"),
            "execsnoop" to listOf("kpod.exec.count")
        )
    }

    @ReadOperation
    fun diagnostics(): Map<String, Any?> {
        val lastCycle = collectorService.getLastSuccessfulCycle()
        val uptime = Duration.between(startTime, Instant.now())

        return mapOf(
            "uptime" to "${uptime.toHours()}h ${uptime.toMinutesPart()}m ${uptime.toSecondsPart()}s",
            "uptimeSeconds" to uptime.seconds,
            "lastCollectionCycle" to lastCycle?.toString(),
            "shuttingDown" to collectorService.isShuttingDown(),
            "enabledCollectorCount" to collectorService.getEnabledCollectorCount(),
            "lastCollectorErrors" to collectorService.getLastCollectorErrors(),
            "bpf" to bpfDiagnostics(),
            "enabledCollectors" to enabledCollectors(),
            "profile" to profileSummary(),
            "metricHealth" to metricHealth(),
            "monitoredPods" to monitoredPodCount(),
            "overhead" to overhead(),
            "recommendations" to recommendations()
        )
    }

    private fun bpfDiagnostics(): Map<String, Any> {
        if (programManager == null) {
            return mapOf("available" to false)
        }
        val failed = programManager.failedPrograms
        return mapOf(
            "available" to true,
            "loadedPrograms" to allExpectedPrograms().filter { programManager.isProgramLoaded(it) },
            "failedPrograms" to failed,
            "healthy" to failed.isEmpty()
        )
    }

    private fun allExpectedPrograms(): List<String> {
        val programs = mutableListOf<String>()
        if (config.cpu.scheduling.enabled || config.cpu.throttling.enabled) programs.add("cpu_sched")
        if (config.network.tcp.enabled) programs.add("net")
        if (config.syscall.enabled) programs.add("syscall")
        if (config.extended.biolatency) programs.add("biolatency")
        if (config.extended.cachestat) programs.add("cachestat")
        if (config.extended.tcpdrop) programs.add("tcpdrop")
        if (config.extended.hardirqs) programs.add("hardirqs")
        if (config.extended.softirqs) programs.add("softirqs")
        if (config.extended.execsnoop) programs.add("execsnoop")
        return programs
    }

    private fun enabledCollectors(): Map<String, Boolean> = mapOf(
        "cpu" to (config.cpu.scheduling.enabled || config.cpu.throttling.enabled),
        "network" to config.network.tcp.enabled,
        "syscall" to config.syscall.enabled,
        "biolatency" to config.extended.biolatency,
        "cachestat" to config.extended.cachestat,
        "tcpdrop" to config.extended.tcpdrop,
        "hardirqs" to config.extended.hardirqs,
        "softirqs" to config.extended.softirqs,
        "execsnoop" to config.extended.execsnoop,
        "diskIO" to config.cgroup.diskIO,
        "ifaceNet" to config.cgroup.interfaceNetwork,
        "filesystem" to config.cgroup.filesystem,
        "memory" to config.cgroup.memory
    )

    private fun profileSummary(): Map<String, Any> = mapOf(
        "cpuEnabled" to (config.cpu.scheduling.enabled || config.cpu.throttling.enabled),
        "networkEnabled" to config.network.tcp.enabled,
        "syscallEnabled" to config.syscall.enabled,
        "extendedCollectors" to listOfNotNull(
            if (config.extended.biolatency) "biolatency" else null,
            if (config.extended.cachestat) "cachestat" else null,
            if (config.extended.tcpdrop) "tcpdrop" else null,
            if (config.extended.hardirqs) "hardirqs" else null,
            if (config.extended.softirqs) "softirqs" else null,
            if (config.extended.execsnoop) "execsnoop" else null
        ),
        "cgroupCollectors" to listOfNotNull(
            if (config.cgroup.diskIO) "diskIO" else null,
            if (config.cgroup.interfaceNetwork) "ifaceNet" else null,
            if (config.cgroup.filesystem) "filesystem" else null,
            if (config.cgroup.memory) "memory" else null
        )
    )

    private fun metricHealth(): Map<String, Any> {
        if (registry == null) return mapOf("available" to false)
        val expected = allExpectedPrograms()
        val producing = mutableListOf<String>()
        val silent = mutableListOf<String>()
        for (prog in expected) {
            val metricNames = BPF_METRIC_MAP[prog] ?: continue
            val hasMetric = metricNames.any { name ->
                registry.find(name).meters().isNotEmpty()
            }
            if (hasMetric) producing.add(prog) else silent.add(prog)
        }
        return mapOf(
            "available" to true,
            "producingMetrics" to producing,
            "silentPrograms" to silent,
            "healthy" to silent.isEmpty()
        )
    }

    private fun monitoredPodCount(): Int {
        if (registry == null) return 0
        val podTags = mutableSetOf<String>()
        for (metricNames in BPF_METRIC_MAP.values) {
            for (metricName in metricNames) {
                for (meter in registry.find(metricName).meters()) {
                    val podTag = meter.id.getTag("pod")
                    if (podTag != null) podTags.add(podTag)
                }
            }
        }
        return podTags.size
    }

    private fun overhead(): Map<String, Any?> {
        if (registry == null) return mapOf("available" to false)
        return mapOf(
            "available" to true,
            "jvmCpuUsage" to gaugeValue("process.cpu.usage"),
            "jvmMemoryUsedBytes" to gaugeValue("jvm.memory.used"),
            "jvmGcPauseSecondsTotal" to timerTotalTime("jvm.gc.pause"),
            "jvmThreadsLive" to gaugeValue("jvm.threads.live")
        )
    }

    private fun gaugeValue(name: String): Double? {
        return registry?.find(name)?.meters()?.firstOrNull()?.let { meter ->
            meter.measure().firstOrNull()?.value
        }
    }

    private fun timerTotalTime(name: String): Double? {
        return registry?.find(name)?.meters()?.sumOf { meter ->
            meter.measure().sumOf { it.value }
        }
    }

    private fun recommendations(): List<String> {
        val recs = mutableListOf<String>()
        val errors = collectorService.getLastCollectorErrors()
        if (errors.isNotEmpty()) {
            recs.add("${errors.size} collector(s) have errors: ${errors.keys.joinToString()}")
        }
        if (programManager != null && programManager.failedPrograms.isNotEmpty()) {
            recs.add("BPF programs failed to load: ${programManager.failedPrograms.joinToString()}. Check kernel support.")
        }
        if (registry != null) {
            val expected = allExpectedPrograms()
            val silent = expected.filter { prog ->
                val metricNames = BPF_METRIC_MAP[prog] ?: return@filter false
                metricNames.none { name -> registry.find(name).meters().isNotEmpty() }
            }
            if (silent.isNotEmpty()) {
                recs.add("Programs loaded but not producing metrics: ${silent.joinToString()}. Workload may be idle.")
            }
        }
        return recs
    }
}
