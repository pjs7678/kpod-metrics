package com.internal.kpodmetrics.collector

import io.mockk.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.BeforeEach

class MetricsCollectorServiceTest {

    private lateinit var cpuCollector: CpuSchedulingCollector
    private lateinit var netCollector: NetworkCollector
    private lateinit var memCollector: MemoryCollector
    private lateinit var syscallCollector: SyscallCollector
    private lateinit var service: MetricsCollectorService

    @BeforeEach
    fun setup() {
        cpuCollector = mockk(relaxed = true)
        netCollector = mockk(relaxed = true)
        memCollector = mockk(relaxed = true)
        syscallCollector = mockk(relaxed = true)
        service = MetricsCollectorService(cpuCollector, netCollector, memCollector, syscallCollector)
    }

    @Test
    fun `collect calls all enabled collectors`() {
        service.collect()
        verify { cpuCollector.collect() }
        verify { netCollector.collect() }
        verify { memCollector.collect() }
        verify { syscallCollector.collect() }
    }

    @Test
    fun `collector failure does not stop other collectors`() {
        every { netCollector.collect() } throws RuntimeException("boom")
        service.collect()
        verify { cpuCollector.collect() }
        verify { memCollector.collect() }
        verify { syscallCollector.collect() }
    }
}
