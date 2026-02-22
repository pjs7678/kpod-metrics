package com.internal.kpodmetrics

import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.TestPropertySource

@SpringBootTest
@TestPropertySource(properties = [
    "kpod.node-name=test-node",
    "kpod.bpf.enabled=false"
])
class KpodMetricsApplicationTest {

    @Test
    fun contextLoads() {
    }
}
