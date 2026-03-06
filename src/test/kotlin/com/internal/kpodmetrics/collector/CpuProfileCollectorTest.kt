package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.PodInfo
import io.mockk.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CpuProfileCollectorTest {

    private lateinit var bridge: BpfBridge
    private lateinit var programManager: BpfProgramManager
    private lateinit var cgroupResolver: CgroupResolver
    private lateinit var collector: CpuProfileCollector

    @BeforeEach
    fun setup() {
        bridge = mockk(relaxed = true)
        programManager = mockk(relaxed = true)
        cgroupResolver = CgroupResolver()
        collector = CpuProfileCollector(bridge, programManager, cgroupResolver)
    }

    @Test
    fun `collect drains profile_counts and groups by pod`() {
        val cgroupId = 12345L
        cgroupResolver.register(cgroupId, PodInfo("uid1", "cid1", "default", "myapp", "main"))
        every { programManager.getMapFd("cpu_profile", "profile_counts") } returns 10
        every { programManager.getMapFd("cpu_profile", "stack_traces") } returns 11

        val key = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(cgroupId).putInt(100).putInt(1).putInt(2).array()
        val value = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(50).array()
        every { bridge.mapBatchLookupAndDelete(10, 20, 8, any()) } returns listOf(key to value)

        val stackVal1 = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(0xFFFF_1234L).putLong(0xFFFF_5678L).array()
        val stackVal2 = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(0x0040_1000L).array()

        every { bridge.mapLookup(11, any(), any()) } answers {
            val keyArg = secondArg<ByteArray>()
            val stackId = ByteBuffer.wrap(keyArg).order(ByteOrder.LITTLE_ENDIAN).int
            when (stackId) {
                1 -> stackVal1
                2 -> stackVal2
                else -> null
            }
        }

        val profiles = collector.collect()

        assertEquals(1, profiles.size)
        val podProfile = profiles.entries.first()
        assertEquals("myapp", podProfile.key.podName)
        assertEquals(1, podProfile.value.size)
        assertEquals(50L, podProfile.value[0].count)
        assertEquals(2, podProfile.value[0].kernelStackIps.size)
        assertEquals(1, podProfile.value[0].userStackIps.size)
    }

    @Test
    fun `collect skips unresolved cgroups`() {
        every { programManager.getMapFd("cpu_profile", "profile_counts") } returns 10
        every { programManager.getMapFd("cpu_profile", "stack_traces") } returns 11

        val key = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(99999L).putInt(100).putInt(1).putInt(2).array()
        val value = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(10).array()
        every { bridge.mapBatchLookupAndDelete(10, 20, 8, any()) } returns listOf(key to value)

        val profiles = collector.collect()
        assertTrue(profiles.isEmpty())
    }

    @Test
    fun `collect handles empty map`() {
        every { programManager.getMapFd("cpu_profile", "profile_counts") } returns 10
        every { programManager.getMapFd("cpu_profile", "stack_traces") } returns 11
        every { bridge.mapBatchLookupAndDelete(10, 20, 8, any()) } returns emptyList()

        val profiles = collector.collect()
        assertTrue(profiles.isEmpty())
    }

    @Test
    fun `collect skips entries with zero or negative count`() {
        val cgroupId = 42L
        cgroupResolver.register(cgroupId, PodInfo("uid2", "cid2", "prod", "worker", "app"))
        every { programManager.getMapFd("cpu_profile", "profile_counts") } returns 10
        every { programManager.getMapFd("cpu_profile", "stack_traces") } returns 11

        val key = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(cgroupId).putInt(200).putInt(3).putInt(4).array()
        val value = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(0).array()
        every { bridge.mapBatchLookupAndDelete(10, 20, 8, any()) } returns listOf(key to value)

        val profiles = collector.collect()
        assertTrue(profiles.isEmpty())
    }

    @Test
    fun `collect handles negative stack ids as empty stacks`() {
        val cgroupId = 77L
        cgroupResolver.register(cgroupId, PodInfo("uid3", "cid3", "test", "svc", "main"))
        every { programManager.getMapFd("cpu_profile", "profile_counts") } returns 10
        every { programManager.getMapFd("cpu_profile", "stack_traces") } returns 11

        // kernStackId = -1 (no kernel stack), userStackId = -1 (no user stack)
        val key = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(cgroupId).putInt(300).putInt(-1).putInt(-1).array()
        val value = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(5).array()
        every { bridge.mapBatchLookupAndDelete(10, 20, 8, any()) } returns listOf(key to value)

        val profiles = collector.collect()

        assertEquals(1, profiles.size)
        val sample = profiles.values.first().first()
        assertEquals(0, sample.kernelStackIps.size)
        assertEquals(0, sample.userStackIps.size)
        assertEquals(5L, sample.count)
    }

    @Test
    fun `collect deduplicates stack lookups via cache`() {
        val cgroupId = 55L
        cgroupResolver.register(cgroupId, PodInfo("uid4", "cid4", "default", "app", "main"))
        every { programManager.getMapFd("cpu_profile", "profile_counts") } returns 10
        every { programManager.getMapFd("cpu_profile", "stack_traces") } returns 11

        // Two entries sharing the same kern stack id = 5
        val key1 = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(cgroupId).putInt(400).putInt(5).putInt(-1).array()
        val value1 = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(3).array()

        val key2 = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(cgroupId).putInt(401).putInt(5).putInt(-1).array()
        val value2 = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(7).array()

        every { bridge.mapBatchLookupAndDelete(10, 20, 8, any()) } returns listOf(key1 to value1, key2 to value2)

        val stackIps = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(0xC000_0001L).putLong(0L).array()
        every { bridge.mapLookup(11, any(), any()) } returns stackIps

        val profiles = collector.collect()

        assertEquals(1, profiles.size)
        assertEquals(2, profiles.values.first().size)
        // Stack 5 should only be looked up once due to caching
        verify(exactly = 1) { bridge.mapLookup(11, any(), any()) }
    }

    @Test
    fun `collect aggregates multiple pods correctly`() {
        val cgroup1 = 100L
        val cgroup2 = 200L
        cgroupResolver.register(cgroup1, PodInfo("uid5", "cid5", "ns1", "pod1", "c1"))
        cgroupResolver.register(cgroup2, PodInfo("uid6", "cid6", "ns2", "pod2", "c2"))
        every { programManager.getMapFd("cpu_profile", "profile_counts") } returns 10
        every { programManager.getMapFd("cpu_profile", "stack_traces") } returns 11

        val key1 = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(cgroup1).putInt(500).putInt(-1).putInt(-1).array()
        val value1 = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(1).array()

        val key2 = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(cgroup2).putInt(600).putInt(-1).putInt(-1).array()
        val value2 = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(2).array()

        every { bridge.mapBatchLookupAndDelete(10, 20, 8, any()) } returns listOf(key1 to value1, key2 to value2)

        val profiles = collector.collect()

        assertEquals(2, profiles.size)
        val podNames = profiles.keys.map { it.podName }.toSet()
        assertTrue(podNames.contains("pod1"))
        assertTrue(podNames.contains("pod2"))
    }
}
