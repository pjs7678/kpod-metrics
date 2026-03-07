package com.internal.kpodmetrics.config

import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.cgroup.CgroupPathResolver
import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.cgroup.CgroupVersionDetector
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
@EnableConfigurationProperties(MetricsProperties::class)
class CgroupConfiguration(private val props: MetricsProperties) {
    @Bean
    fun cgroupResolver(): CgroupResolver = CgroupResolver()

    @Bean
    fun cgroupVersionDetector(): CgroupVersionDetector =
        CgroupVersionDetector(props.cgroup.root)

    @Bean
    fun cgroupReader(detector: CgroupVersionDetector): CgroupReader =
        CgroupReader(detector.detect())

    @Bean
    fun cgroupPathResolver(detector: CgroupVersionDetector): CgroupPathResolver =
        CgroupPathResolver(props.cgroup.root, detector.detect())
}
