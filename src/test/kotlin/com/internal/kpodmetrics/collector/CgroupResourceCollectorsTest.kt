package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.model.CgroupVersion
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText

class CgroupResourceCollectorsTest {
    @TempDir
    lateinit var tempDir: Path
    private lateinit var registry: SimpleMeterRegistry

    @BeforeEach
    fun setUp() { registry = SimpleMeterRegistry() }

    private fun target(dir: Path, pod: String = "p") =
        PodCgroupTarget(pod, "ns", "c", dir.toString(), "node")

    // --- regression: cumulative kernel counters must not be re-added every cycle ---

    @Test
    fun `disk counters reflect cumulative value instead of summing every cycle`() {
        val dir = tempDir.resolve("disk").createDirectories()
        val collector = DiskIOCollector(CgroupReader(CgroupVersion.V2), registry)
        dir.resolve("io.stat").writeText("8:0 rbytes=1000 wbytes=0 rios=1 wios=0\n")
        collector.collect(listOf(target(dir)))
        dir.resolve("io.stat").writeText("8:0 rbytes=1500 wbytes=0 rios=2 wios=0\n")
        collector.collect(listOf(target(dir)))
        collector.collect(listOf(target(dir)))

        val read = registry.get("kpod.disk.read.bytes").tag("pod", "p").functionCounter()
        assertEquals(1500.0, read.count(), "old behavior would report 1000+1500+1500=4000")
    }

    @Test
    fun `removePod unregisters meters so a recreated pod re-registers cleanly`() {
        val dir = tempDir.resolve("disk2").createDirectories()
        dir.resolve("io.stat").writeText("8:0 rbytes=10 wbytes=0 rios=1 wios=0\n")
        val collector = DiskIOCollector(CgroupReader(CgroupVersion.V2), registry)
        collector.collect(listOf(target(dir)))
        collector.removeStaleEntries("p", "ns")
        assertNull(registry.find("kpod.disk.read.bytes").tag("pod", "p").functionCounter())

        dir.resolve("io.stat").writeText("8:0 rbytes=3 wbytes=0 rios=1 wios=0\n")
        collector.collect(listOf(target(dir)))
        assertEquals(3.0, registry.get("kpod.disk.read.bytes").tag("pod", "p").functionCounter().count())
    }

    // --- CPU ---

    @Test
    fun `cpu v2 usage throttling and limit`() {
        val dir = tempDir.resolve("cpu").createDirectories()
        dir.resolve("cpu.stat").writeText(
            "usage_usec 2500000\nuser_usec 2000000\nsystem_usec 500000\n" +
                "nr_periods 100\nnr_throttled 25\nthrottled_usec 750000\n"
        )
        dir.resolve("cpu.max").writeText("50000 100000\n")
        CpuCgroupCollector(CgroupReader(CgroupVersion.V2), registry).collect(listOf(target(dir)))

        assertEquals(2.5, registry.get("kpod.cpu.usage.seconds").functionCounter().count(), 1e-9)
        assertEquals(0.75, registry.get("kpod.cpu.throttled.seconds").functionCounter().count(), 1e-9)
        assertEquals(25.0, registry.get("kpod.cpu.throttled.periods").functionCounter().count())
        assertEquals(100.0, registry.get("kpod.cpu.periods").functionCounter().count())
        assertEquals(0.5, registry.get("kpod.cpu.limit.cores").gauge().value(), 1e-9)
    }

    @Test
    fun `cpu limit gauge is absent when unlimited and removed when limit is lifted`() {
        val dir = tempDir.resolve("cpu-unl").createDirectories()
        dir.resolve("cpu.stat").writeText("usage_usec 1\nnr_periods 0\nnr_throttled 0\nthrottled_usec 0\n")
        dir.resolve("cpu.max").writeText("200000 100000\n")
        val collector = CpuCgroupCollector(CgroupReader(CgroupVersion.V2), registry)
        collector.collect(listOf(target(dir)))
        assertEquals(2.0, registry.get("kpod.cpu.limit.cores").gauge().value(), 1e-9)

        // in-place pod resize (K8s 1.33+) can lift the limit
        dir.resolve("cpu.max").writeText("max 100000\n")
        collector.collect(listOf(target(dir)))
        assertNull(registry.find("kpod.cpu.limit.cores").gauge())
    }

    @Test
    fun `cpu v1 reads sibling cpu,cpuacct hierarchy from a blkio target path`() {
        val root = tempDir.resolve("v1")
        val blkio = root.resolve("blkio/kubepods/podX/ctr").createDirectories()
        val cpu = root.resolve("cpu,cpuacct/kubepods/podX/ctr").createDirectories()
        cpu.resolve("cpuacct.usage").writeText("3000000000\n")
        cpu.resolve("cpu.stat").writeText("nr_periods 10\nnr_throttled 4\nthrottled_time 2000000000\n")
        cpu.resolve("cpu.cfs_quota_us").writeText("150000\n")
        cpu.resolve("cpu.cfs_period_us").writeText("100000\n")
        CpuCgroupCollector(CgroupReader(CgroupVersion.V1), registry).collect(listOf(target(blkio)))

        assertEquals(3.0, registry.get("kpod.cpu.usage.seconds").functionCounter().count(), 1e-9)
        assertEquals(2.0, registry.get("kpod.cpu.throttled.seconds").functionCounter().count(), 1e-9)
        assertEquals(1.5, registry.get("kpod.cpu.limit.cores").gauge().value(), 1e-9)
    }

    // --- Memory additions ---

    @Test
    fun `memory v2 exports rss and limit, omits limit when max`() {
        val dir = tempDir.resolve("mem").createDirectories()
        dir.resolve("memory.current").writeText("100\n")
        dir.resolve("memory.stat").writeText("anon 70\nactive_file 20\ninactive_file 10\n")
        dir.resolve("memory.max").writeText("1073741824\n")
        val collector = MemoryCgroupCollector(CgroupReader(CgroupVersion.V2), registry)
        collector.collect(listOf(target(dir)))
        assertEquals(70.0, registry.get("kpod.mem.cgroup.rss.bytes").gauge().value())
        assertEquals(1073741824.0, registry.get("kpod.mem.cgroup.limit.bytes").gauge().value())

        dir.resolve("memory.max").writeText("max\n")
        collector.collect(listOf(target(dir)))
        assertNull(registry.find("kpod.mem.cgroup.limit.bytes").gauge())
    }

    @Test
    fun `memory v1 treats page-counter-max as unlimited`() {
        val dir = tempDir.resolve("memv1").createDirectories()
        dir.resolve("memory.usage_in_bytes").writeText("100\n")
        dir.resolve("memory.limit_in_bytes").writeText("9223372036854771712\n")
        dir.resolve("memory.stat").writeText("total_cache 10\ntotal_rss 80\n")
        MemoryCgroupCollector(CgroupReader(CgroupVersion.V1), registry).collect(listOf(target(dir)))
        assertEquals(80.0, registry.get("kpod.mem.cgroup.rss.bytes").gauge().value())
        assertNull(registry.find("kpod.mem.cgroup.limit.bytes").gauge())
    }

    // --- PSI ---

    @Test
    fun `pressure exports some and full stall seconds per resource`() {
        val dir = tempDir.resolve("psi").createDirectories()
        dir.resolve("cpu.pressure").writeText(
            "some avg10=1.00 avg60=0.50 avg300=0.10 total=4000000\n"
        )
        dir.resolve("memory.pressure").writeText(
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=1500000\n" +
                "full avg10=0.00 avg60=0.00 avg300=0.00 total=500000\n"
        )
        PressureCollector(CgroupReader(CgroupVersion.V2), registry).collect(listOf(target(dir)))

        fun stall(resource: String, kind: String) = registry.find("kpod.pressure.stall.seconds")
            .tag("resource", resource).tag("kind", kind).functionCounter()
        assertEquals(4.0, stall("cpu", "some")!!.count(), 1e-9)
        assertNull(stall("cpu", "full"), "older kernels have no cpu full line")
        assertEquals(1.5, stall("memory", "some")!!.count(), 1e-9)
        assertEquals(0.5, stall("memory", "full")!!.count(), 1e-9)
        assertNull(stall("io", "some"), "missing io.pressure is skipped")
    }

    @Test
    fun `pressure is a no-op on cgroup v1`() {
        val dir = tempDir.resolve("psi1").createDirectories()
        dir.resolve("cpu.pressure").writeText("some avg10=0 avg60=0 avg300=0 total=1\n")
        PressureCollector(CgroupReader(CgroupVersion.V1), registry).collect(listOf(target(dir)))
        assertNull(registry.find("kpod.pressure.stall.seconds").functionCounter())
    }
}
