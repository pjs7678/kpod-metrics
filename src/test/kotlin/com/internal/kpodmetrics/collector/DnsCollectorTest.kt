package com.internal.kpodmetrics.collector

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class DnsCollectorTest {

    @Test
    fun `qtypeName returns known type names`() {
        assertEquals("A", DnsCollector.qtypeName(1))
        assertEquals("AAAA", DnsCollector.qtypeName(28))
        assertEquals("CNAME", DnsCollector.qtypeName(5))
        assertEquals("SRV", DnsCollector.qtypeName(33))
        assertEquals("PTR", DnsCollector.qtypeName(12))
    }

    @Test
    fun `qtypeName returns OTHER for unknown types`() {
        assertEquals("OTHER", DnsCollector.qtypeName(255))
        assertEquals("OTHER", DnsCollector.qtypeName(0))
        assertEquals("OTHER", DnsCollector.qtypeName(6))
    }

    @Test
    fun `rcodeName returns known rcode names`() {
        assertEquals("FORMERR", DnsCollector.rcodeName(1))
        assertEquals("SERVFAIL", DnsCollector.rcodeName(2))
        assertEquals("NXDOMAIN", DnsCollector.rcodeName(3))
        assertEquals("REFUSED", DnsCollector.rcodeName(5))
    }

    @Test
    fun `rcodeName returns OTHER for unknown rcodes`() {
        assertEquals("OTHER", DnsCollector.rcodeName(0))
        assertEquals("OTHER", DnsCollector.rcodeName(4))
        assertEquals("OTHER", DnsCollector.rcodeName(15))
    }
}
