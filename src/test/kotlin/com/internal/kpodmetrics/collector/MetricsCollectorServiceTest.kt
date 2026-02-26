package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.discovery.PodCgroupMapper
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.mockk.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.BeforeEach

class MetricsCollectorServiceTest {

    private lateinit var cpuCollector: CpuSchedulingCollector
    private lateinit var netCollector: NetworkCollector
    private lateinit var syscallCollector: SyscallCollector
    private lateinit var biolatencyCollector: BiolatencyCollector
    private lateinit var cachestatCollector: CachestatCollector
    private lateinit var tcpdropCollector: TcpdropCollector
    private lateinit var hardirqsCollector: HardirqsCollector
    private lateinit var softirqsCollector: SoftirqsCollector
    private lateinit var execsnoopCollector: ExecsnoopCollector
    private lateinit var service: MetricsCollectorService

    @BeforeEach
    fun setup() {
        cpuCollector = mockk(relaxed = true)
        netCollector = mockk(relaxed = true)
        syscallCollector = mockk(relaxed = true)
        biolatencyCollector = mockk(relaxed = true)
        cachestatCollector = mockk(relaxed = true)
        tcpdropCollector = mockk(relaxed = true)
        hardirqsCollector = mockk(relaxed = true)
        softirqsCollector = mockk(relaxed = true)
        execsnoopCollector = mockk(relaxed = true)
        service = MetricsCollectorService(
            cpuCollector, netCollector, syscallCollector,
            biolatencyCollector, cachestatCollector,
            tcpdropCollector, hardirqsCollector, softirqsCollector, execsnoopCollector
        )
    }

    @Test
    fun `collect calls all enabled collectors`() {
        service.collect()
        verify { cpuCollector.collect() }
        verify { netCollector.collect() }
        verify { syscallCollector.collect() }
        verify { biolatencyCollector.collect() }
        verify { cachestatCollector.collect() }
        verify { tcpdropCollector.collect() }
        verify { hardirqsCollector.collect() }
        verify { softirqsCollector.collect() }
        verify { execsnoopCollector.collect() }
    }

    @Test
    fun `collector failure does not stop other collectors`() {
        every { netCollector.collect() } throws RuntimeException("boom")
        service.collect()
        verify { cpuCollector.collect() }
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
            cpuCollector, netCollector, syscallCollector,
            biolatencyCollector, cachestatCollector,
            tcpdropCollector, hardirqsCollector, softirqsCollector, execsnoopCollector,
            diskIOCollector, ifaceNetCollector, fsCollector, mapper
        )
        serviceWithCgroup.collect()

        verify { diskIOCollector.collect(targets) }
        verify { ifaceNetCollector.collect(targets) }
        verify { fsCollector.collect(targets) }
        serviceWithCgroup.close()
    }
}
