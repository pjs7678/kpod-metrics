package com.internal.kpodmetrics.bpf.programs

/**
 * C helpers shared by programs that attribute softirq-context TCP events to the owning socket.
 * Requires `struct flow_key` (FlowKey) to be defined, i.e. used by a map in the program.
 */
internal val SOCK_FLOW_HELPERS = """
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* Local IPv4 4-tuple of a socket (also valid for IPv4-mapped AF_INET6 sockets). */
static __always_inline int kpod_flow_from_sk(struct sock *sk, struct flow_key *k)
{
    __u16 dport_be = 0;
    if (bpf_probe_read(&k->saddr, sizeof(k->saddr), &sk->__sk_common.skc_rcv_saddr) < 0) return -1;
    if (bpf_probe_read(&k->daddr, sizeof(k->daddr), &sk->__sk_common.skc_daddr) < 0) return -1;
    if (bpf_probe_read(&k->sport, sizeof(k->sport), &sk->__sk_common.skc_num) < 0) return -1;
    if (bpf_probe_read(&dport_be, sizeof(dport_be), &sk->__sk_common.skc_dport) < 0) return -1;
    k->dport = __builtin_bswap16(dport_be);
    if (!k->saddr || !k->daddr || !k->sport || !k->dport) return -1;
    return 0;
}

/*
 * IPv4 address from a tracepoint sockaddr_in / sockaddr_in6 buffer (tcp_probe). The first four
 * bytes are family + port, not the address: reading them as the IP produced remote_ip values
 * like 10.0.131.136 (= AF_INET6, port 33672). IPv4-mapped IPv6 (dual-stack sockets) is unwrapped;
 * native IPv6 is not supported (returns -1).
 */
static __always_inline int kpod_sockaddr_v4(const void *sa, __u32 *ip)
{
    __u16 family = 0;
    if (bpf_probe_read(&family, sizeof(family), sa) < 0) return -1;
    if (family == AF_INET)
        return bpf_probe_read(ip, 4, (const __u8 *)sa + 4) < 0 ? -1 : 0;
    if (family == AF_INET6) {
        __u32 w[3] = {};
        if (bpf_probe_read(w, sizeof(w), (const __u8 *)sa + 8) < 0) return -1;
        /* ::ffff:a.b.c.d -> bytes 00..00 ff ff; 0xffff0000 is that word read little-endian */
        if (w[0] == 0 && w[1] == 0 && w[2] == 0xffff0000U)
            return bpf_probe_read(ip, 4, (const __u8 *)sa + 20) < 0 ? -1 : 0;
    }
    return -1;
}
"""
