package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.OutputConfig
import dev.ebpf.dsl.api.emit
import dev.ebpf.dsl.api.generateC
import dev.ebpf.dsl.api.validate
import dev.ebpf.dsl.tools.*
import java.io.File

fun main() {
    val programs = listOf(
        // Custom programs
        cpuSchedProgram, netProgram, syscallProgram, dnsProgram, httpProgram,
        cpuProfileProgram, tcpPeerProgram,
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
    // DNS and HTTP programs use raw() heavily; their generated Kotlin MapReaders
    // have type mismatches (shared value types across maps with different key shapes).
    // The existing collectors use the raw JNI bridge, so we only need the C output.
    val cOnlyPrograms = setOf("dns", "http", "cpu_profile", "tcp_peer")
    programs.forEach { prog ->
        if (prog.name in cOnlyPrograms) {
            val cFile = File(config.cDir, "${prog.name}.bpf.c")
            cFile.parentFile.mkdirs()
            cFile.writeText(prog.generateC())
        } else {
            prog.emit(config)
        }
    }

    println("Generated ${programs.size} BPF programs")
    programs.forEach { println("  - ${it.name}") }
}
