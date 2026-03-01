package com.internal.kpodmetrics.config

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CardinalityEstimatorTest {

    @Test
    fun `minimal profile has low cardinality`() {
        val config = ResolvedConfig(
            cpu = CpuProperties(scheduling = SchedulingProperties(enabled = true)),
            network = NetworkProperties(tcp = TcpProperties(enabled = false)),
            syscall = SyscallProperties(enabled = false),
            cgroup = CgroupCollectorProperties(diskIO = true, interfaceNetwork = false, filesystem = false)
        )
        val estimator = CardinalityEstimator(config)
        val estimate = estimator.estimate(50)

        assertTrue(estimate.totalSeries < 10_000, "Minimal profile should be well under 10k series")
        assertTrue(estimate.breakdown.containsKey("cpu"))
        assertEquals(null, estimate.breakdown["network"])
    }

    @Test
    fun `comprehensive profile has higher cardinality`() {
        val config = ResolvedConfig(
            cpu = CpuProperties(scheduling = SchedulingProperties(enabled = true)),
            network = NetworkProperties(tcp = TcpProperties(enabled = true)),
            syscall = SyscallProperties(
                enabled = true,
                trackedSyscalls = DEFAULT_TRACKED_SYSCALLS
            ),
            extended = ExtendedProperties(
                biolatency = true, cachestat = true,
                tcpdrop = true, hardirqs = true, softirqs = true, execsnoop = true
            ),
            cgroup = CgroupCollectorProperties(diskIO = true, interfaceNetwork = true, filesystem = true)
        )
        val estimator = CardinalityEstimator(config)
        val estimate = estimator.estimate(200)

        assertTrue(estimate.totalSeries > 10_000, "Comprehensive at 200 pods should exceed 10k")
        assertTrue(estimate.breakdown.containsKey("syscall"))
        assertTrue(estimate.breakdown.containsKey("biolatency"))
    }

    @Test
    fun `estimate scales linearly with pod count`() {
        val config = ResolvedConfig(
            cpu = CpuProperties(),
            network = NetworkProperties(),
            syscall = SyscallProperties(enabled = false)
        )
        val estimator = CardinalityEstimator(config)
        val est50 = estimator.estimate(50)
        val est100 = estimator.estimate(100)

        // Should roughly double (minus fixed selfMonitoring component)
        val ratio = est100.totalSeries.toDouble() / est50.totalSeries.toDouble()
        assertTrue(ratio > 1.8 && ratio < 2.1, "Cardinality should scale roughly linearly, got ratio=$ratio")
    }
}
