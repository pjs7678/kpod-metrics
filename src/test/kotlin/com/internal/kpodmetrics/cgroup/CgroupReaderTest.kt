package com.internal.kpodmetrics.cgroup

import com.internal.kpodmetrics.model.CgroupVersion
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText

class CgroupReaderTest {
    @TempDir
    lateinit var tempDir: Path

    @Test
    fun `v2 reads io_stat with multiple devices`() {
        val containerDir = tempDir.resolve("container1")
        containerDir.createDirectories()
        containerDir.resolve("io.stat").writeText(
            "8:0 rbytes=1048576 wbytes=524288 rios=100 wios=50 dbytes=0 dios=0\n" +
            "8:16 rbytes=2097152 wbytes=0 rios=200 wios=0 dbytes=0 dios=0\n"
        )
        val reader = CgroupReader(CgroupVersion.V2)
        val stats = reader.readDiskIO(containerDir.toString())
        assertEquals(2, stats.size)
        val sda = stats.find { it.major == 8 && it.minor == 0 }!!
        assertEquals(1048576L, sda.readBytes)
        assertEquals(524288L, sda.writeBytes)
        assertEquals(100L, sda.reads)
        assertEquals(50L, sda.writes)
    }

    @Test
    fun `v2 returns empty list when io_stat missing`() {
        val containerDir = tempDir.resolve("container2")
        containerDir.createDirectories()
        val reader = CgroupReader(CgroupVersion.V2)
        assertTrue(reader.readDiskIO(containerDir.toString()).isEmpty())
    }

    @Test
    fun `v1 reads blkio throttle files`() {
        val containerDir = tempDir.resolve("container3")
        containerDir.createDirectories()
        containerDir.resolve("blkio.throttle.io_service_bytes").writeText(
            "8:0 Read 1048576\n8:0 Write 524288\n8:0 Sync 0\n8:0 Async 0\n8:0 Total 1572864\n"
        )
        containerDir.resolve("blkio.throttle.io_serviced").writeText(
            "8:0 Read 100\n8:0 Write 50\n8:0 Sync 0\n8:0 Async 0\n8:0 Total 150\n"
        )
        val reader = CgroupReader(CgroupVersion.V1)
        val stats = reader.readDiskIO(containerDir.toString())
        assertEquals(1, stats.size)
        assertEquals(1048576L, stats[0].readBytes)
        assertEquals(524288L, stats[0].writeBytes)
    }

    @Test
    fun `reads proc net dev`() {
        val procDir = tempDir.resolve("123/net")
        procDir.createDirectories()
        procDir.resolve("dev").writeText(
            "Inter-|   Receive                                                |  Transmit\n" +
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
            "  eth0: 9876543    5432    1    2    0     0          0         0  1111111    3333    0    1    0     0       0          0\n"
        )
        val reader = CgroupReader(CgroupVersion.V2)
        val stats = reader.readNetworkStats(tempDir.toString(), 123)
        assertEquals(1, stats.size)
        val eth0 = stats[0]
        assertEquals("eth0", eth0.interfaceName)
        assertEquals(9876543L, eth0.rxBytes)
        assertEquals(5432L, eth0.rxPackets)
        assertEquals(1L, eth0.rxErrors)
        assertEquals(2L, eth0.rxDrops)
        assertEquals(1111111L, eth0.txBytes)
        assertEquals(3333L, eth0.txPackets)
        assertEquals(1L, eth0.txDrops)
    }

    @Test
    fun `v2 reads init pid from cgroup_procs`() {
        val containerDir = tempDir.resolve("container4")
        containerDir.createDirectories()
        containerDir.resolve("cgroup.procs").writeText("12345\n12346\n")
        val reader = CgroupReader(CgroupVersion.V2)
        assertEquals(12345, reader.readInitPid(containerDir.toString()))
    }

    @Test
    fun `v1 reads init pid from tasks`() {
        val containerDir = tempDir.resolve("container5")
        containerDir.createDirectories()
        containerDir.resolve("tasks").writeText("99999\n99998\n")
        val reader = CgroupReader(CgroupVersion.V1)
        assertEquals(99999, reader.readInitPid(containerDir.toString()))
    }

    @Test
    fun `returns null pid when file is empty`() {
        val containerDir = tempDir.resolve("container6")
        containerDir.createDirectories()
        containerDir.resolve("cgroup.procs").writeText("")
        val reader = CgroupReader(CgroupVersion.V2)
        assertNull(reader.readInitPid(containerDir.toString()))
    }

    @Test
    fun `parseMountInfoLine extracts overlay mount`() {
        val reader = CgroupReader(CgroupVersion.V2)
        val result = reader.parseMountInfoLine(
            "22 1 0:21 / / rw,relatime shared:1 - overlay overlay rw,lowerdir=/lower"
        )
        assertNotNull(result)
        assertEquals("/", result!!.first)
        assertEquals("overlay", result.second)
    }

    @Test
    fun `parseMountInfoLine filters proc filesystem`() {
        val reader = CgroupReader(CgroupVersion.V2)
        assertNull(reader.parseMountInfoLine(
            "35 22 0:22 / /proc rw,nosuid,nodev,noexec - proc proc rw"
        ))
    }

    @Test
    fun `parseMountInfoLine filters tmpfs filesystem`() {
        val reader = CgroupReader(CgroupVersion.V2)
        assertNull(reader.parseMountInfoLine(
            "40 22 0:23 / /dev/shm rw,nosuid,nodev - tmpfs tmpfs rw"
        ))
    }

    @Test
    fun `readFilesystemStats reads overlay mount and returns stats`() {
        val procDir = tempDir.resolve("42")
        procDir.createDirectories()
        procDir.resolve("mountinfo").writeText(
            "22 1 0:21 / / rw,relatime - overlay overlay rw\n" +
            "35 22 0:22 / /proc rw,nosuid - proc proc rw\n"
        )
        procDir.resolve("root").createDirectories()
        val reader = CgroupReader(CgroupVersion.V2)
        val stats = reader.readFilesystemStats(tempDir.toString(), 42)
        assertEquals(1, stats.size)
        assertEquals("/", stats[0].mountPoint)
        assertTrue(stats[0].totalBytes > 0)
    }
}
