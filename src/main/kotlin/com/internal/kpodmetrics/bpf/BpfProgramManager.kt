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

    fun loadAll() {
        if (config.cpu.scheduling.enabled || config.cpu.throttling.enabled) {
            loadProgram("cpu_sched")
        }
        if (config.network.tcp.enabled) {
            loadProgram("net")
        }
        if (config.memory.oom || config.memory.pageFaults) {
            loadProgram("mem")
        }
        if (config.syscall.enabled) {
            loadProgram("syscall")
        }
        log.info("Loaded {} BPF programs: {}", loadedPrograms.size, loadedPrograms.keys)
    }

    private fun loadProgram(name: String) {
        val path = "$programDir/$name.bpf.o"
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
