package com.internal.kpodmetrics.config

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.collector.*
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

@Configuration
@EnableConfigurationProperties(MetricsProperties::class)
class BpfAutoConfiguration(private val props: MetricsProperties) {

    private val log = LoggerFactory.getLogger(BpfAutoConfiguration::class.java)
    private var programManager: BpfProgramManager? = null
    private var podWatcherInstance: PodWatcher? = null
    private var metricsCollectorServiceInstance: MetricsCollectorService? = null

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
    fun syscallCollector(
        bridge: BpfBridge,
        manager: BpfProgramManager,
        resolver: CgroupResolver,
        registry: MeterRegistry,
        config: ResolvedConfig
    ) = SyscallCollector(bridge, manager, resolver, registry, config, props.nodeName)

    @Bean
    @ConditionalOnProperty("kpod.bpf.enabled", havingValue = "true", matchIfMissing = true)
    fun metricsCollectorService(
        cpuCollector: CpuSchedulingCollector,
        netCollector: NetworkCollector,
        memCollector: MemoryCollector,
        syscallCollector: SyscallCollector
    ): MetricsCollectorService {
        val service = MetricsCollectorService(cpuCollector, netCollector, memCollector, syscallCollector)
        this.metricsCollectorServiceInstance = service
        return service
    }

    @EventListener(ContextRefreshedEvent::class)
    fun onStartup() {
        programManager?.let {
            log.info("Loading BPF programs from {}", props.bpf.programDir)
            it.loadAll()
            log.info("BPF programs loaded successfully")
        }
        podWatcherInstance?.let {
            try {
                it.start()
            } catch (e: Exception) {
                log.warn("Failed to start PodWatcher (K8s API may be unavailable): {}", e.message)
            }
        }
    }

    @PreDestroy
    fun onShutdown() {
        podWatcherInstance?.stop()
        metricsCollectorServiceInstance?.close()
        programManager?.let {
            log.info("Destroying BPF programs")
            it.destroyAll()
        }
    }
}
