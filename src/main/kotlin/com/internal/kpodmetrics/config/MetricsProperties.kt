package com.internal.kpodmetrics.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "kpod")
data class MetricsProperties(
    val profile: String = "standard",
    val pollInterval: Long = 15000,
    val nodeName: String = "unknown",
    val cpu: CpuProperties = CpuProperties(),
    val network: NetworkProperties = NetworkProperties(),
    val memory: MemoryProperties = MemoryProperties(),
    val syscall: SyscallProperties = SyscallProperties(),
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
                memory = MemoryProperties(oom = true, pageFaults = false, cgroupStats = true),
                syscall = SyscallProperties(enabled = false),
                cgroup = CgroupCollectorProperties(diskIO = true, interfaceNetwork = false, filesystem = false)
            )
            "standard" -> ResolvedConfig(
                cpu = CpuProperties(
                    scheduling = SchedulingProperties(enabled = true),
                    throttling = ThrottlingProperties(enabled = true)
                ),
                network = NetworkProperties(tcp = TcpProperties(enabled = true)),
                memory = MemoryProperties(oom = true, pageFaults = true, cgroupStats = true),
                syscall = SyscallProperties(enabled = false),
                cgroup = CgroupCollectorProperties(diskIO = true, interfaceNetwork = true, filesystem = true)
            )
            "comprehensive" -> ResolvedConfig(
                cpu = CpuProperties(
                    scheduling = SchedulingProperties(enabled = true),
                    throttling = ThrottlingProperties(enabled = true)
                ),
                network = NetworkProperties(tcp = TcpProperties(enabled = true)),
                memory = MemoryProperties(oom = true, pageFaults = true, cgroupStats = true),
                syscall = SyscallProperties(
                    enabled = true,
                    trackedSyscalls = DEFAULT_TRACKED_SYSCALLS
                ),
                cgroup = CgroupCollectorProperties(diskIO = true, interfaceNetwork = true, filesystem = true)
            )
            "custom" -> ResolvedConfig(cpu = cpu, network = network, memory = memory, syscall = syscall, cgroup = CgroupCollectorProperties())
            else -> throw IllegalArgumentException("Unknown profile: ${override ?: profile}")
        }
    }
}

data class ResolvedConfig(
    val cpu: CpuProperties,
    val network: NetworkProperties,
    val memory: MemoryProperties,
    val syscall: SyscallProperties,
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

data class CgroupCollectorProperties(
    val diskIO: Boolean = true,
    val interfaceNetwork: Boolean = true,
    val filesystem: Boolean = true
)

val DEFAULT_TRACKED_SYSCALLS = listOf(
    "read", "write", "openat", "close", "connect",
    "accept4", "sendto", "recvfrom", "epoll_wait", "futex"
)
