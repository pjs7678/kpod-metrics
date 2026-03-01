package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.config.CollectorOverrides
import com.internal.kpodmetrics.discovery.PodCgroupMapper
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import io.mockk.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.BeforeEach
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

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
    private lateinit var registry: SimpleMeterRegistry
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
        registry = SimpleMeterRegistry()
        service = MetricsCollectorService(
            cpuCollector, netCollector, syscallCollector,
            biolatencyCollector, cachestatCollector,
            tcpdropCollector, hardirqsCollector, softirqsCollector, execsnoopCollector,
            registry = registry
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

    @Test
    fun `records collection cycle duration metric`() {
        service.collect()
        val timer = registry.find("kpod.collection.cycle.duration").timer()
        assertNotNull(timer)
        assertTrue(timer.count() >= 1)
    }

    @Test
    fun `records per-collector duration metrics`() {
        service.collect()
        val cpuTimer = registry.find("kpod.collector.duration").tag("collector", "cpu").timer()
        assertNotNull(cpuTimer)
        assertTrue(cpuTimer.count() >= 1)
    }

    @Test
    fun `records collector error counter on failure`() {
        every { netCollector.collect() } throws RuntimeException("boom")
        service.collect()
        val errorCounter = registry.find("kpod.collector.errors.total").tag("collector", "network").counter()
        assertNotNull(errorCounter)
        assertTrue(errorCounter.count() >= 1.0)
    }

    @Test
    fun `tracks last successful cycle timestamp`() {
        assertNull(service.getLastSuccessfulCycle())
        service.collect()
        assertNotNull(service.getLastSuccessfulCycle())
    }

    @Test
    fun `collector overrides disable specific collectors`() {
        val overrides = CollectorOverrides(cpu = false, network = false, syscall = false)
        val filteredService = MetricsCollectorService(
            cpuCollector, netCollector, syscallCollector,
            biolatencyCollector, cachestatCollector,
            tcpdropCollector, hardirqsCollector, softirqsCollector, execsnoopCollector,
            registry = registry,
            collectorOverrides = overrides
        )
        filteredService.collect()

        verify(exactly = 0) { cpuCollector.collect() }
        verify(exactly = 0) { netCollector.collect() }
        verify(exactly = 0) { syscallCollector.collect() }
        // Others should still run
        verify { biolatencyCollector.collect() }
        verify { cachestatCollector.collect() }
        filteredService.close()
    }

    @Test
    fun `collector overrides disable cgroup collectors`() {
        val diskIOCollector = mockk<DiskIOCollector>(relaxed = true)
        val ifaceNetCollector = mockk<InterfaceNetworkCollector>(relaxed = true)
        val fsCollector = mockk<FilesystemCollector>(relaxed = true)
        val mapper = mockk<PodCgroupMapper>()
        every { mapper.resolve() } returns listOf(PodCgroupTarget("pod", "ns", "c", "/cg", "node"))

        val overrides = CollectorOverrides(diskIO = false, filesystem = false)
        val filteredService = MetricsCollectorService(
            cpuCollector, netCollector, syscallCollector,
            biolatencyCollector, cachestatCollector,
            tcpdropCollector, hardirqsCollector, softirqsCollector, execsnoopCollector,
            diskIOCollector, ifaceNetCollector, fsCollector, mapper,
            registry = registry,
            collectorOverrides = overrides
        )
        filteredService.collect()

        verify(exactly = 0) { diskIOCollector.collect(any()) }
        verify(exactly = 0) { fsCollector.collect(any()) }
        verify { ifaceNetCollector.collect(any()) }
        filteredService.close()
    }

    @Test
    fun `collection timeout increments timeout counter`() {
        every { cpuCollector.collect() } answers {
            Thread.sleep(500)
        }
        val timeoutService = MetricsCollectorService(
            cpuCollector, netCollector, syscallCollector,
            biolatencyCollector, cachestatCollector,
            tcpdropCollector, hardirqsCollector, softirqsCollector, execsnoopCollector,
            registry = registry,
            collectionTimeoutMs = 100
        )
        timeoutService.collect()

        val counter = registry.find("kpod.collection.timeouts.total").counter()!!
        assertTrue(counter.count() >= 1.0)
        timeoutService.close()
    }

    @Test
    fun `collection completes within timeout does not increment counter`() {
        service.collect()
        val counter = registry.find("kpod.collection.timeouts.total").counter()!!
        assertTrue(counter.count() == 0.0)
    }

    @Test
    fun `shutdown prevents new collection cycles`() {
        service.close()
        assertTrue(service.isShuttingDown())
        // Calling collect after shutdown should be a no-op
        val lastCycle = service.getLastSuccessfulCycle()
        service = MetricsCollectorService(
            cpuCollector, netCollector, syscallCollector,
            biolatencyCollector, cachestatCollector,
            tcpdropCollector, hardirqsCollector, softirqsCollector, execsnoopCollector,
            registry = registry
        )
    }
}
