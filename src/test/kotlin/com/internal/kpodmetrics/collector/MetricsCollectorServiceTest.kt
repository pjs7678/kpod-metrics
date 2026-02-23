package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.discovery.PodCgroupMapper
import com.internal.kpodmetrics.model.PodCgroupTarget
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

    @Test
    fun `collect runs cgroup collectors with resolved targets`() {
        val diskIOCollector = mockk<DiskIOCollector>(relaxed = true)
        val ifaceNetCollector = mockk<InterfaceNetworkCollector>(relaxed = true)
        val fsCollector = mockk<FilesystemCollector>(relaxed = true)
        val mapper = mockk<PodCgroupMapper>()
        val targets = listOf(PodCgroupTarget("pod", "ns", "c", "/cg", "node"))
        every { mapper.resolve() } returns targets

        val serviceWithCgroup = MetricsCollectorService(
            cpuCollector, netCollector, memCollector, syscallCollector,
            diskIOCollector, ifaceNetCollector, fsCollector, mapper
        )
        serviceWithCgroup.collect()

        verify { diskIOCollector.collect(targets) }
        verify { ifaceNetCollector.collect(targets) }
        verify { fsCollector.collect(targets) }
        serviceWithCgroup.close()
    }
}
