package com.internal.kpodmetrics.config

import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Configuration

@Configuration
@EnableConfigurationProperties(MetricsProperties::class)
class BpfAutoConfiguration
