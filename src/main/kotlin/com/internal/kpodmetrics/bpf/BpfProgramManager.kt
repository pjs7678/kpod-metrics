package com.internal.kpodmetrics.bpf

import com.internal.kpodmetrics.config.ResolvedConfig
import org.slf4j.LoggerFactory

class BpfProgramManager(
    private val bridge: BpfBridge,
    private val programDir: String,
    private val config: ResolvedConfig
) {
    private val log = LoggerFactory.getLogger(BpfProgramManager::class.java)
    private val loadedPrograms = mutableMapOf<String, Long>()
    private val resolvedProgramDir: String = detectProgramDir(programDir)

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
            loadProgram("cpu_sched")
        }
        if (config.network.tcp.enabled) {
            loadProgram("net")
        }
        // mem program removed — oom_kills and major_faults duplicate cAdvisor
        if (config.syscall.enabled) {
            loadProgram("syscall")
        }

        // BCC-style tools from kotlin-ebpf-dsl
        val ext = config.extended
        if (ext.biolatency) loadProgram("biolatency")
        if (ext.cachestat) loadProgram("cachestat")
        if (ext.tcpdrop) loadProgram("tcpdrop")
        if (ext.hardirqs) loadProgram("hardirqs")
        if (ext.softirqs) loadProgram("softirqs")
        if (ext.execsnoop) loadProgram("execsnoop")

        log.info("Loaded {} BPF programs: {}", loadedPrograms.size, loadedPrograms.keys)
    }

    private fun loadProgram(name: String) {
        val path = "$resolvedProgramDir/$name.bpf.o"
        log.info("Loading BPF program: {}", path)
        val handle = bridge.openObject(path)
        bridge.loadObject(handle)
        bridge.attachAll(handle)
        loadedPrograms[name] = handle
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
}
