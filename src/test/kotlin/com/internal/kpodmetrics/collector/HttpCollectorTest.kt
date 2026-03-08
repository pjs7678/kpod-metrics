package com.internal.kpodmetrics.collector

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class HttpCollectorTest {

    @Test
    fun `methodName returns correct names`() {
        assertEquals("GET", HttpCollector.methodName(1))
        assertEquals("POST", HttpCollector.methodName(2))
        assertEquals("PUT", HttpCollector.methodName(3))
        assertEquals("DELETE", HttpCollector.methodName(4))
        assertEquals("PATCH", HttpCollector.methodName(5))
        assertEquals("HEAD", HttpCollector.methodName(6))
        assertEquals("UNKNOWN", HttpCollector.methodName(0))
        assertEquals("UNKNOWN", HttpCollector.methodName(99))
    }

    @Test
    fun `directionLabel returns correct labels`() {
        assertEquals("outbound", HttpCollector.directionLabel(0))
        assertEquals("inbound", HttpCollector.directionLabel(1))
        assertEquals("unknown", HttpCollector.directionLabel(99))
    }
}
