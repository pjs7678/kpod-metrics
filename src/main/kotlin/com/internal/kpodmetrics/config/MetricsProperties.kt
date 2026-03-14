package com.internal.kpodmetrics.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "kpod")
data class MetricsProperties(
    val profile: String = "standard",
    val pollInterval: Long = 29000,
    val collectionTimeout: Long = 20000,
    val initialDelay: Long = 10000,
    val startupJitter: Long = 5000,
    val nodeName: String = "unknown",
    val clusterName: String = "",
    val cpu: CpuProperties = CpuProperties(),
    val network: NetworkProperties = NetworkProperties(),
    val memory: MemoryProperties = MemoryProperties(),
    val syscall: SyscallProperties = SyscallProperties(),
    val extended: ExtendedProperties = ExtendedProperties(),
    val collectors: CollectorOverrides = CollectorOverrides(),
    val collectorIntervals: CollectorIntervals = CollectorIntervals(),
    val filter: FilterProperties = FilterProperties(),
    val bpf: BpfProperties = BpfProperties(),
    val discovery: DiscoveryProperties = DiscoveryProperties(),
    val cgroup: CgroupProperties = CgroupProperties(),
    val otlp: OtlpProperties = OtlpProperties(),
    val profiling: ProfilingProperties = ProfilingProperties(),
    val tracing: TracingProperties = TracingProperties()
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
                cgroup = CgroupCollectorProperties(diskIO = true, interfaceNetwork = false, filesystem = false, memory = true)
            )
            "standard" -> ResolvedConfig(
                cpu = CpuProperties(
                    scheduling = SchedulingProperties(enabled = true),
                    throttling = ThrottlingProperties(enabled = true)
                ),
                network = NetworkProperties(tcp = TcpProperties(enabled = true)),
                syscall = SyscallProperties(enabled = false),
                extended = ExtendedProperties(tcpdrop = true, execsnoop = true, dns = true, tcpPeer = true, http = true, redis = true, mysql = true),
                cgroup = CgroupCollectorProperties(diskIO = true, interfaceNetwork = true, filesystem = true, memory = true)
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
                    tcpdrop = true, hardirqs = true, softirqs = true, execsnoop = true,
                    dns = true, tcpPeer = true, http = true,
                    redis = true, mysql = true
                ),
                cgroup = CgroupCollectorProperties(diskIO = true, interfaceNetwork = true, filesystem = true, memory = true)
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
    val labelSelector: String = "",
    val includeLabels: List<String> = listOf("app", "app.kubernetes.io/name", "app.kubernetes.io/component"),
    val scrubLabelValues: List<String> = listOf(".*password.*", ".*secret.*", ".*token.*", ".*credential.*", ".*api.key.*")
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

data class OtlpProperties(
    val enabled: Boolean = false,
    val endpoint: String = "http://localhost:4318/v1/metrics",
    val headers: Map<String, String> = emptyMap(),
    val step: Long = 60000
)

data class ProtocolTracingConfig(
    val enabled: Boolean = true,
    val thresholdMs: Long = 100
)

data class TracingProperties(
    val enabled: Boolean = false,
    val http: ProtocolTracingConfig = ProtocolTracingConfig(thresholdMs = 200),
    val redis: ProtocolTracingConfig = ProtocolTracingConfig(thresholdMs = 10),
    val mysql: ProtocolTracingConfig = ProtocolTracingConfig(thresholdMs = 200),
    val otlpEndpoint: String = "",
    val ringBufferSizeKb: Int = 256
)

data class ExtendedProperties(
    val biolatency: Boolean = false,
    val cachestat: Boolean = false,
    val tcpdrop: Boolean = false,
    val hardirqs: Boolean = false,
    val softirqs: Boolean = false,
    val execsnoop: Boolean = false,
    val dns: Boolean = false,
    val dnsPorts: List<Int> = listOf(53),
    val tcpPeer: Boolean = false,
    val http: Boolean = false,
    val httpPorts: List<Int> = listOf(80, 8080, 8443),
    val redis: Boolean = false,
    val redisPorts: List<Int> = listOf(6379),
    val mysql: Boolean = false,
    val mysqlPorts: List<Int> = listOf(3306)
)

data class CgroupCollectorProperties(
    val diskIO: Boolean = true,
    val interfaceNetwork: Boolean = true,
    val filesystem: Boolean = true,
    val memory: Boolean = true
)

data class CollectorIntervals(
    val cpu: Long? = null,
    val network: Long? = null,
    val syscall: Long? = null,
    val biolatency: Long? = null,
    val cachestat: Long? = null,
    val tcpdrop: Long? = null,
    val hardirqs: Long? = null,
    val softirqs: Long? = null,
    val execsnoop: Long? = null,
    val dns: Long? = null,
    val tcpPeer: Long? = null,
    val http: Long? = null,
    val redis: Long? = null,
    val mysql: Long? = null,
    val diskIO: Long? = null,
    val ifaceNet: Long? = null,
    val filesystem: Long? = null,
    val memory: Long? = null
)

data class ProfilingProperties(
    val enabled: Boolean = false,
    val cpu: CpuProfilingProperties = CpuProfilingProperties(),
    val pyroscope: PyroscopeProperties = PyroscopeProperties(),
    val symbolCacheMaxEntries: Int = 50000
)

data class CpuProfilingProperties(
    val enabled: Boolean = true,
    val frequency: Int = 99,
    val stackDepth: Int = 128
)

data class PyroscopeProperties(
    val endpoint: String = "http://pyroscope:4040",
    val tenantId: String = "",
    val authToken: String = "",
    val renderPath: String = ""
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
    val dns: Boolean? = null,
    val tcpPeer: Boolean? = null,
    val http: Boolean? = null,
    val redis: Boolean? = null,
    val mysql: Boolean? = null,
    val diskIO: Boolean? = null,
    val ifaceNet: Boolean? = null,
    val filesystem: Boolean? = null,
    val memory: Boolean? = null
)

val DEFAULT_TRACKED_SYSCALLS = listOf(
    "read", "write", "openat", "close", "connect",
    "accept4", "sendto", "recvfrom", "epoll_wait", "futex"
)
