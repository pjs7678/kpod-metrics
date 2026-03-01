package com.internal.kpodmetrics.health

import com.internal.kpodmetrics.bpf.BpfProgramManager
import org.springframework.boot.actuate.health.Health
import org.springframework.boot.actuate.health.HealthIndicator

class BpfHealthIndicator(
    private val programManager: BpfProgramManager
) : HealthIndicator {

    override fun health(): Health {
        val failed = programManager.failedPrograms
        val builder = if (failed.isEmpty()) {
            Health.up()
        } else {
            Health.down().withDetail("failedPrograms", failed)
        }
        return builder.build()
    }
}
