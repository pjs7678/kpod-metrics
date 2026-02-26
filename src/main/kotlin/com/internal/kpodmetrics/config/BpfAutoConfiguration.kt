package com.internal.kpodmetrics.config

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.cgroup.CgroupPathResolver
import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.cgroup.CgroupVersionDetector
import com.internal.kpodmetrics.collector.*
import com.internal.kpodmetrics.discovery.KubeletPodProvider
import com.internal.kpodmetrics.discovery.PodCgroupMapper
import com.internal.kpodmetrics.discovery.PodProvider
import com.internal.kpodmetrics.k8s.PodWatcher
import io.fabric8.kubernetes.client.KubernetesClient
import io.fabric8.kubernetes.client.KubernetesClientBuilder
import io.micrometer.core.instrument.MeterRegistry
import jakarta.annotation.PreDestroy
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.event.ContextRefreshedEvent
import org.springframework.context.event.EventListener
import java.util.Optional

@Configuration
@EnableConfigurationProperties(MetricsProperties::class)
class BpfAutoConfiguration(private val props: MetricsProperties) {

    private val log = LoggerFactory.getLogger(BpfAutoConfiguration::class.java)
    private var programManager: BpfProgramManager? = null
    private var podWatcherInstance: PodWatcher? = null
    private var metricsCollectorServiceInstance: MetricsCollectorService? = null
    private var kubeletPodProviderInstance: KubeletPodProvider? = null

    @Bean
    fun resolvedConfig(): ResolvedConfig = props.resolveProfile()

    @Bean
    fun cgroupResolver(): CgroupResolver = CgroupResolver()

    @Bean
    fun kubernetesClient(): KubernetesClient = KubernetesClientBuilder().build()

    @Bean
    fun podWatcher(kubernetesClient: KubernetesClient, cgroupResolver: CgroupResolver): PodWatcher {
        val watcher = PodWatcher(kubernetesClient, cgroupResolver, props)
        this.podWatcherInstance = watcher
        return watcher
    }

    @Bean
    @ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
    fun bpfBridge(): BpfBridge {
        BpfBridge.loadLibrary()
        return BpfBridge()
    }

    @Bean
    @ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
    fun bpfProgramManager(bridge: BpfBridge, config: ResolvedConfig): BpfProgramManager {
        val manager = BpfProgramManager(bridge, props.bpf.programDir, config)
        this.programManager = manager
        return manager
    }

    @Bean
    @ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
    fun cpuSchedulingCollector(
        bridge: BpfBridge,
        manager: BpfProgramManager,
        resolver: CgroupResolver,
        registry: MeterRegistry,
        config: ResolvedConfig
    ) = CpuSchedulingCollector(bridge, manager, resolver, registry, config, props.nodeName)

    @Bean
    @ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
    fun networkCollector(
        bridge: BpfBridge,
        manager: BpfProgramManager,
        resolver: CgroupResolver,
        registry: MeterRegistry,
        config: ResolvedConfig
    ) = NetworkCollector(bridge, manager, resolver, registry, config, props.nodeName)

    @Bean
    @ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
    fun memoryCollector(
        bridge: BpfBridge,
        manager: BpfProgramManager,
        resolver: CgroupResolver,
        registry: MeterRegistry,
        config: ResolvedConfig
    ) = MemoryCollector(bridge, manager, resolver, registry, config, props.nodeName)

    @Bean
    @ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
    fun bpfMapStatsCollector(
        bridge: BpfBridge,
        manager: BpfProgramManager,
        registry: MeterRegistry
    ) = BpfMapStatsCollector(bridge, manager, registry)

    @Bean
    @ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
    fun syscallCollector(
        bridge: BpfBridge,
        manager: BpfProgramManager,
        resolver: CgroupResolver,
        registry: MeterRegistry,
        config: ResolvedConfig
    ) = SyscallCollector(bridge, manager, resolver, registry, config, props.nodeName)

    // --- BCC-style tool collectors ---

    @Bean
    @ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
    fun biolatencyCollector(
        bridge: BpfBridge,
        manager: BpfProgramManager,
        resolver: CgroupResolver,
        registry: MeterRegistry,
        config: ResolvedConfig
    ) = BiolatencyCollector(bridge, manager, resolver, registry, config, props.nodeName)

    @Bean
    @ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
    fun cachestatCollector(
        bridge: BpfBridge,
        manager: BpfProgramManager,
        resolver: CgroupResolver,
        registry: MeterRegistry,
        config: ResolvedConfig
    ) = CachestatCollector(bridge, manager, resolver, registry, config, props.nodeName)

    @Bean
    @ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
    fun tcpdropCollector(
        bridge: BpfBridge,
        manager: BpfProgramManager,
        resolver: CgroupResolver,
        registry: MeterRegistry,
        config: ResolvedConfig
    ) = TcpdropCollector(bridge, manager, resolver, registry, config, props.nodeName)

    @Bean
    @ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
    fun hardirqsCollector(
        bridge: BpfBridge,
        manager: BpfProgramManager,
        resolver: CgroupResolver,
        registry: MeterRegistry,
        config: ResolvedConfig
    ) = HardirqsCollector(bridge, manager, resolver, registry, config, props.nodeName)

    @Bean
    @ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
    fun softirqsCollector(
        bridge: BpfBridge,
        manager: BpfProgramManager,
        resolver: CgroupResolver,
        registry: MeterRegistry,
        config: ResolvedConfig
    ) = SoftirqsCollector(bridge, manager, resolver, registry, config, props.nodeName)

    @Bean
    @ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
    fun execsnoopCollector(
        bridge: BpfBridge,
        manager: BpfProgramManager,
        resolver: CgroupResolver,
        registry: MeterRegistry,
        config: ResolvedConfig
    ) = ExecsnoopCollector(bridge, manager, resolver, registry, config, props.nodeName)

    // --- Cgroup infrastructure beans ---

    @Bean
    fun cgroupVersionDetector(): CgroupVersionDetector =
        CgroupVersionDetector(props.cgroup.root)

    @Bean
    fun cgroupReader(detector: CgroupVersionDetector): CgroupReader =
        CgroupReader(detector.detect())

    @Bean
    fun cgroupPathResolver(detector: CgroupVersionDetector): CgroupPathResolver =
        CgroupPathResolver(props.cgroup.root, detector.detect())

    @Bean
    fun podProvider(podWatcher: PodWatcher): PodProvider {
        if (props.discovery.mode == "kubelet") {
            val provider = KubeletPodProvider(
                props.discovery.nodeIp,
                10250,
                props.discovery.kubeletPollInterval
            )
            this.kubeletPodProviderInstance = provider
            return provider
        }
        return podWatcher
    }

    @Bean
    fun podCgroupMapper(podProvider: PodProvider, resolver: CgroupPathResolver): PodCgroupMapper =
        PodCgroupMapper(podProvider, resolver, props.nodeName)

    // --- Cgroup-based collectors (conditionally created) ---

    @Bean
    fun diskIOCollector(reader: CgroupReader, registry: MeterRegistry, config: ResolvedConfig): DiskIOCollector? {
        if (!config.cgroup.diskIO) return null
        return DiskIOCollector(reader, registry)
    }

    @Bean
    fun interfaceNetworkCollector(reader: CgroupReader, registry: MeterRegistry, config: ResolvedConfig): InterfaceNetworkCollector? {
        if (!config.cgroup.interfaceNetwork) return null
        return InterfaceNetworkCollector(reader, props.cgroup.procRoot, registry)
    }

    @Bean
    fun filesystemCollector(reader: CgroupReader, registry: MeterRegistry, config: ResolvedConfig): FilesystemCollector? {
        if (!config.cgroup.filesystem) return null
        return FilesystemCollector(reader, props.cgroup.procRoot, registry)
    }

    // --- Aggregated service ---

    @Bean
    @ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
    fun metricsCollectorService(
        cpuCollector: CpuSchedulingCollector,
        netCollector: NetworkCollector,
        memCollector: MemoryCollector,
        syscallCollector: SyscallCollector,
        biolatencyCollector: BiolatencyCollector,
        cachestatCollector: CachestatCollector,
        tcpdropCollector: TcpdropCollector,
        hardirqsCollector: HardirqsCollector,
        softirqsCollector: SoftirqsCollector,
        execsnoopCollector: ExecsnoopCollector,
        diskIOCollector: Optional<DiskIOCollector>,
        ifaceNetCollector: Optional<InterfaceNetworkCollector>,
        fsCollector: Optional<FilesystemCollector>,
        podCgroupMapper: PodCgroupMapper,
        bridge: BpfBridge,
        manager: BpfProgramManager,
        cgroupResolver: CgroupResolver,
        bpfMapStatsCollector: BpfMapStatsCollector
    ): MetricsCollectorService {
        val service = MetricsCollectorService(
            cpuCollector, netCollector, memCollector, syscallCollector,
            biolatencyCollector, cachestatCollector,
            tcpdropCollector, hardirqsCollector, softirqsCollector, execsnoopCollector,
            diskIOCollector.orElse(null),
            ifaceNetCollector.orElse(null),
            fsCollector.orElse(null),
            podCgroupMapper,
            bridge,
            manager,
            cgroupResolver,
            bpfMapStatsCollector
        )
        this.metricsCollectorServiceInstance = service
        return service
    }

    @EventListener(ContextRefreshedEvent::class)
    fun onStartup() {
        programManager?.let {
            log.info("Loading BPF programs from {}", props.bpf.programDir)
            try {
                it.loadAll()
                log.info("BPF programs loaded successfully")
            } catch (e: Exception) {
                log.warn("BPF program loading failed (kernel may not support tracing); cgroup collectors will still run: {}", e.message)
            }
        }
        podWatcherInstance?.let { watcher ->
            metricsCollectorServiceInstance?.let { service ->
                watcher.setOnPodDeletedCallback { cgroupId ->
                    service.cleanupCgroupEntries(cgroupId)
                }
            }
            try {
                watcher.start()
            } catch (e: Exception) {
                log.warn("Failed to start PodWatcher (K8s API may be unavailable): {}", e.message)
            }
        }
        kubeletPodProviderInstance?.let {
            try {
                it.start()
            } catch (e: Exception) {
                log.warn("Failed to start KubeletPodProvider: {}", e.message)
            }
        }
    }

    @PreDestroy
    fun onShutdown() {
        podWatcherInstance?.stop()
        kubeletPodProviderInstance?.stop()
        metricsCollectorServiceInstance?.close()
        programManager?.let {
            log.info("Destroying BPF programs")
            it.destroyAll()
        }
    }
}
