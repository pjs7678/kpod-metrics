package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.bpf.BpfBridge
import com.internal.kpodmetrics.bpf.BpfProgramManager
import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.config.ResolvedConfig
import io.micrometer.core.instrument.DistributionSummary
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder

class DnsCollector(
    private val bridge: BpfBridge,
    private val programManager: BpfProgramManager,
    private val cgroupResolver: CgroupResolver,
    private val registry: MeterRegistry,
    private val config: ResolvedConfig,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(DnsCollector::class.java)
    // Track unique domains to prevent cardinality explosion (Beyla #2219, Kepler #2366)
    private val knownDomains = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    companion object {
        private const val MAX_ENTRIES = 10240
        private const val MAX_DOMAIN_ENTRIES = 1024
        private const val MAX_UNIQUE_DOMAINS = 200

        // Struct sizes matching dns.bpf.c
        private const val DNS_REQ_KEY_SIZE = 16       // u64 + u16 + u16 + u32
        private const val DNS_ERR_KEY_SIZE = 16       // u64 + u8 + u8[7]
        private const val DNS_DOMAIN_KEY_SIZE = 40    // u64 + u8[32]
        private const val HIST_KEY_SIZE = 8           // u64
        private const val HIST_VALUE_SIZE = 232       // u64[27] + u64 + u64
        private const val COUNTER_VALUE_SIZE = 8      // u64

        private val QTYPE_NAMES = mapOf(
            1.toShort() to "A",
            28.toShort() to "AAAA",
            5.toShort() to "CNAME",
            33.toShort() to "SRV",
            12.toShort() to "PTR"
        )

        private val RCODE_NAMES = mapOf(
            1.toByte() to "FORMERR",
            2.toByte() to "SERVFAIL",
            3.toByte() to "NXDOMAIN",
            5.toByte() to "REFUSED"
        )

        fun qtypeName(qtype: Short): String = QTYPE_NAMES[qtype] ?: "OTHER"
        fun rcodeName(rcode: Byte): String = RCODE_NAMES[rcode] ?: "OTHER"
    }

    fun collect() {
        if (!config.extended.dns) return
        if (!programManager.isProgramLoaded("dns")) return
        collectRequests()
        collectLatency()
        collectErrors()
        collectDomains()
    }

    private fun collectRequests() {
        val mapFd = programManager.getMapFd("dns", "dns_requests")
        val entries = bridge.mapBatchLookupAndDelete(mapFd, DNS_REQ_KEY_SIZE, COUNTER_VALUE_SIZE, MAX_ENTRIES)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long
            val qtype = buf.short

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue
            val count = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN).long

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "qtype", qtypeName(qtype)
            )
            registry.counter("kpod.dns.requests", tags).increment(count.toDouble())
        }
    }

    private fun collectLatency() {
        val mapFd = programManager.getMapFd("dns", "dns_latency")
        val entries = bridge.mapBatchLookupAndDelete(mapFd, HIST_KEY_SIZE, HIST_VALUE_SIZE, MAX_ENTRIES)
        for ((keyBytes, valueBytes) in entries) {
            val cgroupId = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN).long
            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue

            val valBuf = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN)
            // Skip 27 histogram slots (27 * 8 = 216 bytes)
            valBuf.position(27 * 8)
            val count = valBuf.long
            val sumNs = valBuf.long

            if (count <= 0 || sumNs <= 0) continue

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName
            )
            DistributionSummary.builder("kpod.dns.latency")
                .tags(tags)
                .baseUnit("seconds")
                .register(registry)
                .record(sumNs.toDouble() / 1_000_000_000.0)
        }
    }

    private fun collectErrors() {
        val mapFd = programManager.getMapFd("dns", "dns_errors")
        val entries = bridge.mapBatchLookupAndDelete(mapFd, DNS_ERR_KEY_SIZE, COUNTER_VALUE_SIZE, MAX_ENTRIES)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long
            val rcode = buf.get()  // u8

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue
            val count = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN).long

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "rcode", rcodeName(rcode)
            )
            registry.counter("kpod.dns.errors", tags).increment(count.toDouble())
        }
    }

    private fun collectDomains() {
        val mapFd = programManager.getMapFd("dns", "dns_domains")
        val entries = bridge.mapBatchLookupAndDelete(mapFd, DNS_DOMAIN_KEY_SIZE, COUNTER_VALUE_SIZE, MAX_DOMAIN_ENTRIES)
        for ((keyBytes, valueBytes) in entries) {
            val buf = ByteBuffer.wrap(keyBytes).order(ByteOrder.LITTLE_ENDIAN)
            val cgroupId = buf.long
            val domainBytes = ByteArray(32)
            buf.get(domainBytes)

            val podInfo = cgroupResolver.resolve(cgroupId) ?: continue
            // Decode null-terminated UTF-8 domain
            val nullIdx = domainBytes.indexOf(0.toByte())
            val domain = if (nullIdx > 0) {
                String(domainBytes, 0, nullIdx, Charsets.UTF_8)
            } else if (nullIdx == 0) {
                "unknown"
            } else {
                String(domainBytes, Charsets.UTF_8)
            }
            val count = ByteBuffer.wrap(valueBytes).order(ByteOrder.LITTLE_ENDIAN).long

            // Cap unique domains to prevent cardinality explosion
            val cappedDomain = if (knownDomains.contains(domain) || knownDomains.size < MAX_UNIQUE_DOMAINS) {
                knownDomains.add(domain)
                domain
            } else {
                "other"
            }

            val tags = Tags.of(
                "namespace", podInfo.namespace,
                "pod", podInfo.podName,
                "container", podInfo.containerName,
                "node", nodeName,
                "domain", cappedDomain
            )
            registry.counter("kpod.dns.top.domains", tags).increment(count.toDouble())
        }
    }
}
