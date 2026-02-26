package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.OutputConfig
import dev.ebpf.dsl.api.emit
import dev.ebpf.dsl.api.validate
import dev.ebpf.dsl.tools.*

fun main() {
    val programs = listOf(
        // Custom programs
        memProgram, cpuSchedProgram, netProgram, syscallProgram,
        // BCC-style tools from kotlin-ebpf-dsl
        biolatency(), cachestat(), tcpdrop(),
        hardirqs(), softirqs(), execsnoop()
    )

    // Validate all programs
    programs.forEach { prog ->
        val result = prog.validate()
        if (result.errors.isNotEmpty()) {
            System.err.println("Validation failed for ${prog.name}:")
            result.errors.forEach { System.err.println("  ERROR [${it.code}]: ${it.message}") }
            System.exit(1)
        }
        result.warnings.forEach { println("  WARNING [${it.code}]: ${it.message}") }
    }

    // Emit C + Kotlin
    val config = OutputConfig(
        cDir = "build/generated/bpf",
        kotlinDir = "build/generated/kotlin",
        kotlinPackage = "com.internal.kpodmetrics.bpf.generated",
        bridgeImport = "com.internal.kpodmetrics.bpf.BpfBridge"
    )
    programs.forEach { it.emit(config) }

    println("Generated ${programs.size} BPF programs")
    programs.forEach { println("  - ${it.name}") }
}
