package com.internal.kpodmetrics.config

import com.internal.kpodmetrics.analysis.AnomalyEndpoint
import com.internal.kpodmetrics.analysis.AnomalyService
import com.internal.kpodmetrics.analysis.PyroscopeClient
import com.internal.kpodmetrics.analysis.RecommendEndpoint
import com.internal.kpodmetrics.analysis.RecommendService
import io.fabric8.kubernetes.client.KubernetesClient
import io.micrometer.core.instrument.MeterRegistry
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
@EnableConfigurationProperties(MetricsProperties::class)
@ConditionalOnProperty("kpod.profiling.enabled", havingValue = "true")
class AnalysisConfiguration(private val props: MetricsProperties) {

    @Bean
    fun pyroscopeClient() = PyroscopeClient(
        endpoint = props.profiling.pyroscope.endpoint,
        tenantId = props.profiling.pyroscope.tenantId,
        authToken = props.profiling.pyroscope.authToken,
        renderPath = props.profiling.pyroscope.renderPath
    )

    @Bean
    fun recommendService(
        pyroscopeClient: PyroscopeClient,
        kubernetesClient: KubernetesClient,
        registry: MeterRegistry
    ) = RecommendService(pyroscopeClient, kubernetesClient, registry)

    @Bean
    fun recommendEndpoint(recommendService: RecommendService) =
        RecommendEndpoint(recommendService)

    @Bean
    fun anomalyService(pyroscopeClient: PyroscopeClient) =
        AnomalyService(pyroscopeClient)

    @Bean
    fun anomalyEndpoint(anomalyService: AnomalyService) =
        AnomalyEndpoint(anomalyService)
}
