package com.internal.kpodmetrics

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.scheduling.annotation.EnableScheduling

@SpringBootApplication
@EnableScheduling
class KpodMetricsApplication

fun main(args: Array<String>) {
    runApplication<KpodMetricsApplication>(*args)
}
