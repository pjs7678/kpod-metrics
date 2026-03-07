package com.internal.kpodmetrics.collector

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class TcpPeerCollectorTest {

    @Test
    fun `ipToString converts network byte order IPv4 correctly`() {
        // 10.96.0.1 → bytes: 10, 96, 0, 1 → little-endian u32: 0x0100600A
        val ip = 0x0100600A
        assertEquals("10.96.0.1", TcpPeerCollector.ipToString(ip))
    }

    @Test
    fun `ipToString converts loopback`() {
        val ip = 0x0100007F // 127.0.0.1
        assertEquals("127.0.0.1", TcpPeerCollector.ipToString(ip))
    }

    @Test
    fun `ipToString converts all zeros`() {
        assertEquals("0.0.0.0", TcpPeerCollector.ipToString(0))
    }

    @Test
    fun `directionLabel returns correct labels`() {
        assertEquals("client", TcpPeerCollector.directionLabel(0))
        assertEquals("server", TcpPeerCollector.directionLabel(1))
        assertEquals("unknown", TcpPeerCollector.directionLabel(2))
    }
}
