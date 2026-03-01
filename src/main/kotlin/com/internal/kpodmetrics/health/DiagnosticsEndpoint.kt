package com.internal.kpodmetrics.health

import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.collector.MetricsCollectorService
import com.internal.kpodmetrics.config.ResolvedConfig
import org.springframework.boot.actuate.endpoint.annotation.Endpoint
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation
import java.time.Duration
import java.time.Instant

@Endpoint(id = "kpodDiagnostics")
class DiagnosticsEndpoint(
    private val collectorService: MetricsCollectorService,
    private val programManager: BpfProgramManager?,
    private val config: ResolvedConfig,
    private val startTime: Instant = Instant.now()
) {

    @ReadOperation
    fun diagnostics(): Map<String, Any?> {
        val lastCycle = collectorService.getLastSuccessfulCycle()
        val uptime = Duration.between(startTime, Instant.now())

        return mapOf(
            "uptime" to "${uptime.toHours()}h ${uptime.toMinutesPart()}m ${uptime.toSecondsPart()}s",
            "uptimeSeconds" to uptime.seconds,
            "lastCollectionCycle" to lastCycle?.toString(),
            "shuttingDown" to collectorService.isShuttingDown(),
            "bpf" to bpfDiagnostics(),
            "enabledCollectors" to enabledCollectors(),
            "profile" to profileSummary()
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
        "filesystem" to config.cgroup.filesystem
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
            if (config.cgroup.filesystem) "filesystem" else null
        )
    )
}
