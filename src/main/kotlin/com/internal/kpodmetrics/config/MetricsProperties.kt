package com.internal.kpodmetrics.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "kpod")
data class MetricsProperties(
    val profile: String = "standard",
    val pollInterval: Long = 30000,
    val collectionTimeout: Long = 20000,
    val nodeName: String = "unknown",
    val cpu: CpuProperties = CpuProperties(),
    val network: NetworkProperties = NetworkProperties(),
    val memory: MemoryProperties = MemoryProperties(),
    val syscall: SyscallProperties = SyscallProperties(),
    val extended: ExtendedProperties = ExtendedProperties(),
    val collectors: CollectorOverrides = CollectorOverrides(),
    val filter: FilterProperties = FilterProperties(),
    val bpf: BpfProperties = BpfProperties(),
    val discovery: DiscoveryProperties = DiscoveryProperties(),
    val cgroup: CgroupProperties = CgroupProperties()
) {
    fun resolveProfile(override: String? = null): ResolvedConfig {
        return when (override ?: profile) {
            "minimal" -> ResolvedConfig(
                cpu = CpuProperties(
                    scheduling = SchedulingProperties(enabled = true),
                    throttling = ThrottlingProperties(enabled = true)
                ),
                network = NetworkProperties(tcp = TcpProperties(enabled = false)),
                syscall = SyscallProperties(enabled = false),
                extended = ExtendedProperties(),
                cgroup = CgroupCollectorProperties(diskIO = true, interfaceNetwork = false, filesystem = false)
            )
            "standard" -> ResolvedConfig(
                cpu = CpuProperties(
                    scheduling = SchedulingProperties(enabled = true),
                    throttling = ThrottlingProperties(enabled = true)
                ),
                network = NetworkProperties(tcp = TcpProperties(enabled = true)),
                syscall = SyscallProperties(enabled = false),
                extended = ExtendedProperties(tcpdrop = true, execsnoop = true),
                cgroup = CgroupCollectorProperties(diskIO = true, interfaceNetwork = true, filesystem = true)
            )
            "comprehensive" -> ResolvedConfig(
                cpu = CpuProperties(
                    scheduling = SchedulingProperties(enabled = true),
                    throttling = ThrottlingProperties(enabled = true)
                ),
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
            "custom" -> ResolvedConfig(cpu = cpu, network = network, syscall = syscall, extended = extended, cgroup = CgroupCollectorProperties())
            else -> throw IllegalArgumentException("Unknown profile: ${override ?: profile}")
        }
    }
}

data class ResolvedConfig(
    val cpu: CpuProperties,
    val network: NetworkProperties,
    val syscall: SyscallProperties,
    val extended: ExtendedProperties = ExtendedProperties(),
    val cgroup: CgroupCollectorProperties = CgroupCollectorProperties()
)

data class CpuProperties(
    val scheduling: SchedulingProperties = SchedulingProperties(),
    val throttling: ThrottlingProperties = ThrottlingProperties()
)

data class SchedulingProperties(
    val enabled: Boolean = true,
    val histogramBuckets: List<Double> = listOf(0.000001, 0.00001, 0.0001, 0.001, 0.01, 0.1, 1.0)
)

data class ThrottlingProperties(
    val enabled: Boolean = true
)

data class NetworkProperties(
    val tcp: TcpProperties = TcpProperties()
)

data class TcpProperties(
    val enabled: Boolean = true,
    val rttHistogramBuckets: List<Double> = listOf(0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5),
    val connectionLatencyBuckets: List<Double> = listOf(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0)
)

data class MemoryProperties(
    val oom: Boolean = true,
    val pageFaults: Boolean = true,
    val cgroupStats: Boolean = true
)

data class SyscallProperties(
    val enabled: Boolean = false,
    val trackedSyscalls: List<String> = emptyList(),
    val latencyHistogramBuckets: List<Double> = listOf(0.000001, 0.00001, 0.0001, 0.001, 0.01, 0.1)
)

data class FilterProperties(
    val namespaces: List<String> = emptyList(),
    val excludeNamespaces: List<String> = listOf("kube-system", "kube-public"),
    val labelSelector: String = ""
)

data class BpfProperties(
    val enabled: Boolean = true,
    val programDir: String = "/app/bpf"
)

data class DiscoveryProperties(
    val mode: String = "informer",
    val kubeletPollInterval: Long = 30,
    val nodeIp: String = ""
)

data class CgroupProperties(
    val root: String = "/host/sys/fs/cgroup",
    val procRoot: String = "/host/proc"
)

data class ExtendedProperties(
    val biolatency: Boolean = false,
    val cachestat: Boolean = false,
    val tcpdrop: Boolean = false,
    val hardirqs: Boolean = false,
    val softirqs: Boolean = false,
    val execsnoop: Boolean = false
)

data class CgroupCollectorProperties(
    val diskIO: Boolean = true,
    val interfaceNetwork: Boolean = true,
    val filesystem: Boolean = true
)

data class CollectorOverrides(
    val cpu: Boolean? = null,
    val network: Boolean? = null,
    val syscall: Boolean? = null,
    val biolatency: Boolean? = null,
    val cachestat: Boolean? = null,
    val tcpdrop: Boolean? = null,
    val hardirqs: Boolean? = null,
    val softirqs: Boolean? = null,
    val execsnoop: Boolean? = null,
    val diskIO: Boolean? = null,
    val ifaceNet: Boolean? = null,
    val filesystem: Boolean? = null
)

val DEFAULT_TRACKED_SYSCALLS = listOf(
    "read", "write", "openat", "close", "connect",
    "accept4", "sendto", "recvfrom", "epoll_wait", "futex"
)
