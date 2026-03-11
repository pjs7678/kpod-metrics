package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

// ── DNS-specific structs ─────────────────────────────────────────────

object DnsPortKey : BpfStruct("dns_port_key") {
    val port by u16()
    val pad1 by u16()
    val pad2 by u32()
}

object DnsPortVal : BpfStruct("dns_port_val") {
    val enabled by u8()
    val pad by array(BpfScalar.U8, 7)
}

object DnsReqKey : BpfStruct("dns_req_key") {
    val cgroupId by u64()
    val qtype by u16()
    val pad1 by u16()
    val pad2 by u32()
}

object DnsErrKey : BpfStruct("dns_err_key") {
    val cgroupId by u64()
    val rcode by u8()
    val pad by array(BpfScalar.U8, 7)
}

object DnsDomainKey : BpfStruct("dns_domain_key") {
    val cgroupId by u64()
    val domain by array(BpfScalar.U8, 32)
}

object DnsInflightKey : BpfStruct("dns_inflight_key") {
    val cgroupId by u64()
    val txid by u16()
    val pad1 by u16()
    val pad2 by u32()
}

object TsValue : BpfStruct("ts_value") {
    val ts by u64()
}

object DnsRecvStash : BpfStruct("dns_recv_stash") {
    val msghdrPtr by u64()
    val cgroupId by u64()
}

// ── DNS preamble ─────────────────────────────────────────────────────

private val DNS_PREAMBLE = """
#include <bpf/bpf_endian.h>

#define MAX_DNS_PACKET 44
#define MAX_DOMAIN_LEN 32
#define MAX_LABEL_LEN 63

$COMMON_PREAMBLE

DEFINE_STATS_MAP(dns_ports)
DEFINE_STATS_MAP(dns_requests)
DEFINE_STATS_MAP(dns_latency)
DEFINE_STATS_MAP(dns_errors)
DEFINE_STATS_MAP(dns_domains)
DEFINE_STATS_MAP(dns_inflight)
DEFINE_STATS_MAP(dns_recv_stash)

static __always_inline int read_ptr(void **dst, void *src) {
    return bpf_probe_read_kernel(dst, sizeof(void *), src);
}

static __always_inline int read_u16(void *dst, void *src) {
    return bpf_probe_read_kernel(dst, sizeof(__u16), src);
}
""".trimIndent()

// Helper functions that reference struct types must go in the postamble
// (emitted after struct/map definitions, before programs).
private val DNS_POSTAMBLE = """
static __always_inline void inc_counter(void *map, void *key)
{
    struct counter_value *val = bpf_map_lookup_elem(map, key);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
    } else {
        struct counter_value one = { .count = 1 };
        bpf_map_update_elem(map, key, &one, BPF_NOEXIST);
    }
}
""".trimIndent()

// ── DNS program ──────────────────────────────────────────────────────

@Suppress("DEPRECATION")
val dnsProgram = ebpf("dns") {
    license("GPL")
    targetKernel("5.5")

    preamble(DNS_PREAMBLE)
    postamble(DNS_POSTAMBLE)

    // ── Maps ─────────────────────────────────────────────────────────
    val dnsPorts by hashMap(DnsPortKey, DnsPortVal, maxEntries = 8)
    val dnsRequests by lruHashMap(DnsReqKey, CounterValue, maxEntries = 10240)
    val dnsLatency by lruHashMap(HistKey, HistValue, maxEntries = 10240)
    val dnsErrors by lruHashMap(DnsErrKey, CounterValue, maxEntries = 10240)
    val dnsDomains by lruHashMap(DnsDomainKey, CounterValue, maxEntries = 1024)
    val dnsInflight by lruHashMap(DnsInflightKey, TsValue, maxEntries = 4096)
    val dnsRecvStash by percpuArray(DnsRecvStash, maxEntries = 1)

    // ── kprobe/udp_sendmsg ───────────────────────────────────────────
    kprobe("udp_sendmsg") {
        // Read msg_name → dest port → check port filter → read iov → read DNS packet
        // Heavy pointer chasing requires raw C for correct types
        val msg = declareVar("msg", raw("(__u64)PT_REGS_PARM2(ctx)", BpfScalar.U64))

        // Read dest port via pointer chasing
        declareVar("msg_name", raw("""({
    void *_p = NULL;
    read_ptr(&_p, &((struct msghdr *)msg)->msg_name);
    (__u64)_p;
})""", BpfScalar.U64))
        declareVar("dport", raw("""({
    __u16 _d = 0;
    read_u16(&_d, (void *)((char *)msg_name + 2));
    __builtin_bswap16(_d);
})""", BpfScalar.U16))

        // Check if this port is a DNS port
        val portKey = stackVar(DnsPortKey) {
            it[DnsPortKey.port] = raw("dport", BpfScalar.U16)
        }
        ifThen(dnsPorts.lookup(portKey) eq literal(0, BpfScalar.U64)) {
            returnValue(literal(0, BpfScalar.S32))
        }

        // Read iov_base and iov_len
        declareVar("iov_base", raw("""({
    struct iovec *_iov;
    bpf_probe_read_kernel(&_iov, sizeof(_iov), &((struct msghdr *)msg)->msg_iter.__iov);
    struct iovec _e;
    bpf_probe_read_kernel(&_e, sizeof(_e), _iov);
    if (_e.iov_len < 17) return 0;
    (__u64)_e.iov_base;
})""", BpfScalar.U64))

        // Read DNS packet into stack buffer
        val pkt = probeReadBuf(raw("(void *)iov_base", BpfScalar.U64), 44)

        // Parse DNS header
        val txid = declareVar("txid", pkt.u16be(0))
        val flags = declareVar("flags", pkt.u16be(2))

        // QR bit = skip responses
        ifThen(flags and literal(0x8000, BpfScalar.U16) ne literal(0, BpfScalar.U16)) {
            returnValue(literal(0, BpfScalar.S32))
        }

        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())

        // QNAME decoding + domain tracking + qtype extraction
        // Uses a single flat loop over packet bytes (max 32) instead of nested
        // label*char loops (16*63=1008) to stay within BPF verifier complexity limits.
        // Writes directly into dns_domain_key.domain to save 32 bytes of stack.
        declareVar("qtype", raw("""({
    struct dns_domain_key dk = { .cgroup_id = cgroup_id };
    __u32 pkt_off = 12, dom_off = 0, remain = 0;
    #pragma unroll
    for (int i = 0; i < MAX_DNS_PACKET - 12; i++) {
        if (pkt_off >= MAX_DNS_PACKET) break;
        __u8 b = (__u8)__buf_0[pkt_off];
        if (remain == 0) {
            if (b == 0) { pkt_off++; break; }
            if (b > MAX_LABEL_LEN) break;
            remain = b;
            if (dom_off > 0 && dom_off < MAX_DOMAIN_LEN) dk.domain[dom_off++] = '.';
        } else {
            if (dom_off < MAX_DOMAIN_LEN) dk.domain[dom_off++] = b;
            remain--;
        }
        pkt_off++;
    }
    __u16 _qt = 0;
    if (pkt_off + 1 < MAX_DNS_PACKET)
        _qt = ((__u16)((__u8)__buf_0[pkt_off]) << 8) | ((__u8)__buf_0[pkt_off + 1]);
    inc_counter(&dns_domains, &dk);
    _qt;
})""", BpfScalar.U16))

        // Store inflight timestamp
        val txidKey = stackVar(DnsInflightKey) {
            it[DnsInflightKey.cgroupId] = cgroupId
            it[DnsInflightKey.txid] = txid
        }
        val tsVal = stackVar(TsValue) {
            it[TsValue.ts] = ktimeGetNs()
        }
        dnsInflight.update(txidKey, tsVal, flags = BPF_NOEXIST)

        // Increment dns_requests
        val reqKey = stackVar(DnsReqKey) {
            it[DnsReqKey.cgroupId] = cgroupId
            it[DnsReqKey.qtype] = raw("qtype", BpfScalar.U16)
        }
        declareVar("_inc", raw("(inc_counter(&dns_requests, &${(reqKey.expr as BpfExpr.VarRef).variable.name}), (__s32)0)", BpfScalar.S32))

        returnValue(literal(0, BpfScalar.S32))
    }

    // ── kprobe/udp_recvmsg ───────────────────────────────────────────
    kprobe("udp_recvmsg") {
        val zero = declareVar("zero", literal(0, BpfScalar.U32))
        val stash = dnsRecvStash.lookup(zero)
        ifNonNull(stash) { _ ->
            declareVar("_set", raw("(entry_0->msghdr_ptr = (__u64)PT_REGS_PARM2(ctx), entry_0->cgroup_id = bpf_get_current_cgroup_id(), (__s32)0)", BpfScalar.S32))
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    // ── kretprobe/udp_recvmsg ────────────────────────────────────────
    kretprobe("udp_recvmsg") {
        val ret = declareVar("ret", kretprobeReturnValue(BpfScalar.S64))
        ifThen(ret lt literal(12, BpfScalar.S64)) {
            returnValue(literal(0, BpfScalar.S32))
        }

        val zero = declareVar("zero", literal(0, BpfScalar.U32))
        val stash = dnsRecvStash.lookup(zero)
        ifNonNull(stash) { s ->
            val msg = declareVar("msg", raw("entry_0->msghdr_ptr", BpfScalar.U64))
            val cgroupId = declareVar("cgroup_id", raw("entry_0->cgroup_id", BpfScalar.U64))

            // Read source port
            declareVar("sport", raw("""({
    void *_mn = NULL;
    read_ptr(&_mn, &((struct msghdr *)msg)->msg_name);
    __u16 _sp = 0;
    read_u16(&_sp, (void *)((char *)_mn + 2));
    __builtin_bswap16(_sp);
})""", BpfScalar.U16))

            // Check DNS port
            val portKey = stackVar(DnsPortKey) {
                it[DnsPortKey.port] = raw("sport", BpfScalar.U16)
            }
            ifThen(dnsPorts.lookup(portKey) eq literal(0, BpfScalar.U64)) {
                returnValue(literal(0, BpfScalar.S32))
            }

            // Read DNS header via iov
            declareVar("iov_base", raw("""({
    struct iovec *_iov;
    bpf_probe_read_kernel(&_iov, sizeof(_iov), &((struct msghdr *)msg)->msg_iter.__iov);
    struct iovec _e;
    bpf_probe_read_kernel(&_e, sizeof(_e), _iov);
    (__u64)_e.iov_base;
})""", BpfScalar.U64))

            val hdr = probeReadBuf(raw("(void *)iov_base", BpfScalar.U64), 12)
            val txid = declareVar("txid", hdr.u16be(0))
            val flags = declareVar("flags", hdr.u16be(2))

            // QR bit must be 1 (response)
            ifThen(flags and literal(0x8000, BpfScalar.U16) eq literal(0, BpfScalar.U16)) {
                returnValue(literal(0, BpfScalar.S32))
            }

            // Lookup inflight request
            val txidKey = stackVar(DnsInflightKey) {
                it[DnsInflightKey.cgroupId] = cgroupId
                it[DnsInflightKey.txid] = txid
            }
            val tsVal = dnsInflight.lookup(txidKey)
            ifNonNull(tsVal) { ts ->
                val now = declareVar("now", ktimeGetNs())
                val latencyNs = declareVar("latency_ns", now - raw("entry_3->ts", BpfScalar.U64))

                // Latency histogram
                val hkey = stackVar(HistKey) {
                    it[HistKey.cgroupId] = cgroupId
                }
                val hist = dnsLatency.lookup(hkey)
                ifNonNull(hist) { h ->
                    val slot = declareVar("slot", histSlot(latencyNs, 27))
                    h[HistValue.slots].at(slot).atomicAdd(literal(1u, BpfScalar.U64))
                    h[HistValue.count].atomicAdd(literal(1u, BpfScalar.U64))
                    h[HistValue.sumNs].atomicAdd(latencyNs)
                }.elseThen {
                    val slot2 = declareVar("slot2", histSlot(latencyNs, 27))
                    val newHist = stackVar(HistValue) {
                        it[HistValue.count] = literal(1u, BpfScalar.U64)
                        it[HistValue.sumNs] = latencyNs
                    }
                    declareVar("_arr", raw("(${(newHist.expr as BpfExpr.VarRef).variable.name}.slots[slot2] = 1ULL, (__s32)0)", BpfScalar.S32))
                    dnsLatency.update(hkey, newHist, flags = BPF_NOEXIST)
                }

                dnsInflight.delete(txidKey)
            }

            // Error counter
            val rcode = declareVar("rcode", flags and literal(0x000F, BpfScalar.U16))
            ifThen(rcode ne literal(0, BpfScalar.U16)) {
                val errKey = stackVar(DnsErrKey) {
                    it[DnsErrKey.cgroupId] = cgroupId
                    it[DnsErrKey.rcode] = cast(rcode, BpfScalar.U8)
                }
                declareVar("_inc_e", raw("(inc_counter(&dns_errors, &${(errKey.expr as BpfExpr.VarRef).variable.name}), (__s32)0)", BpfScalar.S32))
            }
        }

        returnValue(literal(0, BpfScalar.S32))
    }
}
