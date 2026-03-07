package com.internal.kpodmetrics.bpf

import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Timer
import org.slf4j.LoggerFactory
import java.util.concurrent.atomic.AtomicInteger

class BpfProgramManager(
    private val bridge: BpfBridge,
    private val programDir: String,
    private val config: ResolvedConfig,
    private val registry: MeterRegistry? = null
) {
    private val log = LoggerFactory.getLogger(BpfProgramManager::class.java)
    private val loadedPrograms = mutableMapOf<String, Long>()
    private val _failedPrograms = mutableSetOf<String>()
    val failedPrograms: Set<String> get() = _failedPrograms.toSet()

    private val loadedCount = AtomicInteger(0)
    private val failedCount = AtomicInteger(0)
    private val resolvedProgramDir: String = detectProgramDir(programDir)

    init {
        registry?.gauge("kpod.bpf.programs.loaded", loadedCount)
        registry?.gauge("kpod.bpf.programs.failed", failedCount)
    }

    private fun detectProgramDir(baseDir: String): String {
        val btfPath = "/sys/kernel/btf/vmlinux"
        val coreDir = "$baseDir/core"
        val legacyDir = "$baseDir/legacy"
        return if (java.io.File(btfPath).exists() && java.io.File(coreDir).isDirectory) {
            log.info("Kernel BTF detected, using CO-RE BPF programs from {}", coreDir)
            coreDir
        } else if (java.io.File(legacyDir).isDirectory) {
            log.info("No kernel BTF, using legacy BPF programs from {}", legacyDir)
            legacyDir
        } else {
            log.warn("No core/ or legacy/ subdirectory found, falling back to {}", baseDir)
            baseDir
        }
    }

    fun loadAll() {
        if (config.cpu.scheduling.enabled || config.cpu.throttling.enabled) {
            tryLoadProgram("cpu_sched")
        }
        if (config.network.tcp.enabled) {
            tryLoadProgram("net")
        }
        // mem program removed — oom_kills and major_faults duplicate cAdvisor
        if (config.syscall.enabled) {
            tryLoadProgram("syscall")
        }

        // BCC-style tools from kotlin-ebpf-dsl
        val ext = config.extended
        if (ext.biolatency) tryLoadProgram("biolatency")
        if (ext.cachestat) tryLoadProgram("cachestat")
        if (ext.tcpdrop) tryLoadProgram("tcpdrop")
        if (ext.hardirqs) tryLoadProgram("hardirqs")
        if (ext.softirqs) tryLoadProgram("softirqs")
        if (ext.execsnoop) tryLoadProgram("execsnoop")
        if (ext.dns) tryLoadProgram("dns")
        if (ext.tcpPeer) tryLoadProgram("tcp_peer")

        loadedCount.set(loadedPrograms.size)
        failedCount.set(_failedPrograms.size)
        log.info("Loaded {} BPF programs: {}{}",
            loadedPrograms.size, loadedPrograms.keys,
            if (_failedPrograms.isNotEmpty()) ", failed: $_failedPrograms" else "")
    }

    private fun tryLoadProgram(name: String) {
        try {
            val path = "$resolvedProgramDir/$name.bpf.o"
            log.info("Loading BPF program: {}", path)
            val sample = registry?.let { Timer.start() }
            val handle = bridge.openObject(path)
            bridge.loadObject(handle)
            bridge.attachAll(handle)
            loadedPrograms[name] = handle
            sample?.stop(Timer.builder("kpod.bpf.program.load.duration")
                .tag("program", name)
                .register(registry!!))
        } catch (e: Exception) {
            log.warn("Failed to load BPF program '{}': {}", name, e.message)
            _failedPrograms.add(name)
        }
    }

    fun loadCpuProfile(sampleFreq: Int) {
        try {
            val path = "$resolvedProgramDir/cpu_profile.bpf.o"
            log.info("Loading CPU profile BPF program: {}", path)
            val sample = registry?.let { Timer.start() }
            val handle = bridge.openObject(path)
            bridge.loadObject(handle)
            val cpuCount = bridge.perfEventAttach(handle, "cpu_profile", sampleFreq)
            loadedPrograms["cpu_profile"] = handle
            sample?.stop(Timer.builder("kpod.bpf.program.load.duration")
                .tag("program", "cpu_profile")
                .register(registry!!))
            loadedCount.set(loadedPrograms.size)
            log.info("CPU profile BPF program attached to {} CPUs at {}Hz", cpuCount, sampleFreq)
        } catch (e: Exception) {
            log.warn("Failed to load CPU profile BPF program: {}", e.message)
            _failedPrograms.add("cpu_profile")
            failedCount.set(_failedPrograms.size)
        }
    }

    fun destroyAll() {
        loadedPrograms.forEach { (name, handle) ->
            try {
                bridge.destroyObject(handle)
                log.info("Destroyed BPF program: {}", name)
            } catch (e: Exception) {
                log.warn("Failed to destroy BPF program {}: {}", name, e.message)
            }
        }
        loadedPrograms.clear()
    }

    fun getMapFd(programName: String, mapName: String): Int {
        val handle = loadedPrograms[programName]
            ?: throw BpfMapException("Program not loaded: $programName")
        return bridge.getMapFd(handle, mapName)
    }

    fun isProgramLoaded(name: String): Boolean = loadedPrograms.containsKey(name)

    fun configureDnsPorts(ports: List<Int>) {
        if (!isProgramLoaded("dns")) return
        val mapFd = getMapFd("dns", "dns_ports")
        for (port in ports) {
            val keyBytes = java.nio.ByteBuffer.allocate(8)
                .order(java.nio.ByteOrder.LITTLE_ENDIAN)
                .putShort(port.toShort())
                .putShort(0)  // _pad1
                .putInt(0)    // _pad2
                .array()
            val valueBytes = java.nio.ByteBuffer.allocate(8)
                .order(java.nio.ByteOrder.LITTLE_ENDIAN)
                .put(1.toByte())  // enabled
                .put(ByteArray(7))  // _pad
                .array()
            bridge.mapUpdate(mapFd, keyBytes, valueBytes)
        }
        log.info("DNS port filter configured: {}", ports)
    }
}
