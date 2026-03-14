package com.internal.kpodmetrics.config

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.collector.CpuProfileCollector
import com.internal.kpodmetrics.profiling.KallsymsResolver
import com.internal.kpodmetrics.profiling.ProfilingPipeline
import com.internal.kpodmetrics.profiling.PyroscopePusher
import com.internal.kpodmetrics.profiling.SymbolResolver
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
@EnableConfigurationProperties(MetricsProperties::class)
@ConditionalOnProperty("kpod.profiling.enabled", havingValue = "true")
class ProfilingConfiguration(private val props: MetricsProperties) {

    @Bean
    fun cpuProfileCollector(
        bridge: BpfBridge,
        manager: BpfProgramManager,
        resolver: CgroupResolver
    ) = CpuProfileCollector(bridge, manager, resolver, props.profiling.cpu.stackDepth)

    @Bean
    fun kallsymsResolver(): KallsymsResolver = KallsymsResolver.fromFile()

    @Bean
    fun symbolResolver(kallsyms: KallsymsResolver) =
        SymbolResolver(kallsyms, props.profiling.symbolCacheMaxEntries)

    @Bean
    fun pyroscopePusher() = PyroscopePusher(
        endpoint = props.profiling.pyroscope.endpoint,
        tenantId = props.profiling.pyroscope.tenantId,
        authToken = props.profiling.pyroscope.authToken,
        sampleRate = props.profiling.cpu.frequency
    )

    @Bean
    fun profilingPipeline(
        cpuProfileCollector: CpuProfileCollector,
        symbolResolver: SymbolResolver,
        pusher: PyroscopePusher
    ) = ProfilingPipeline(
        cpuProfileCollector, symbolResolver, pusher, props.nodeName,
        props.pollInterval * 1_000_000, // convert ms to nanos
        props.profiling.cpu.frequency
    )
}
