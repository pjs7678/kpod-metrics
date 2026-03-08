/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * compat_vmlinux.h — Minimal vmlinux.h replacement for legacy (non-CO-RE) builds.
 *
 * Defines only the tracepoint context structs actually used by kpod-metrics
 * BPF programs. These layouts are derived from stable kernel tracepoint format
 * files (/sys/kernel/tracing/events/<category>/<event>/format) and are
 * consistent across kernel 4.18 through 6.x.
 *
 * IMPORTANT: This header intentionally does NOT use preserve_access_index.
 * Without that attribute, clang won't generate CO-RE relocations, so libbpf
 * won't require kernel BTF (/sys/kernel/btf/vmlinux) at load time.
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

/* Standard BPF scalar types */
typedef unsigned char __u8;
typedef short unsigned int __u16;
typedef unsigned int __u32;
typedef long long unsigned int __u64;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef int __kernel_pid_t;
typedef __kernel_pid_t pid_t;

/* Signed types */
typedef int __s32;
typedef long long int __s64;
typedef __s32 s32;
typedef __s64 s64;

/* Size types */
typedef long unsigned int __kernel_size_t;
typedef __kernel_size_t size_t;

/* Network byte-order types */
typedef __u16 __be16;
typedef __u32 __be32;

/* Forward declaration for cpu_profile.bpf.c (only used as opaque pointer) */
struct bpf_perf_event_data;

/* --- Raw tracepoint args (used by syscall.bpf.c: raw_tp/sys_enter, raw_tp/sys_exit) --- */
struct bpf_raw_tracepoint_args {
    __u64 args[0];
};

/* --- pt_regs (used by all kprobe programs) ---
 * Architecture-specific register layout. The __TARGET_ARCH_* define is passed
 * by clang via -D in the Dockerfile. Field names use kernel-style short names
 * (di, si, dx, etc.) because __VMLINUX_H__ is defined, which makes
 * bpf_tracing.h select the short-name PT_REGS_PARM* macros. */

#if defined(__TARGET_ARCH_arm64)

struct user_pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};

struct pt_regs {
    union {
        struct user_pt_regs user_regs;
        struct {
            __u64 regs[31];
            __u64 sp;
            __u64 pc;
            __u64 pstate;
        };
    };
    __u64 orig_x0;
    __s32 syscallno;
    __u32 unused2;
};

#elif defined(__TARGET_ARCH_x86)

struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};

#else
#error "Unsupported architecture: define __TARGET_ARCH_arm64 or __TARGET_ARCH_x86"
#endif

/* --- Socket structs (used by tcp_peer.bpf.c) ---
 * Layout matches kernel 4.18-5.1 and is stable through 6.x.
 * Three consecutive unions: addr (8B) + hash (4B) + port (4B). */

struct sock_common {
    union {
        struct {
            __be32 skc_daddr;      /* offset 0 */
            __be32 skc_rcv_saddr;  /* offset 4 */
        };
    };
    union {
        __u32 skc_hash;            /* offset 8 */
    };
    union {
        struct {
            __be16 skc_dport;      /* offset 12 */
            __u16 skc_num;         /* offset 14 */
        };
    };
};

struct sock {
    struct sock_common __sk_common;
};

/* --- I/O vector structs (used by dns.bpf.c) ---
 * iov_iter layout for kernel 4.18-5.1: int type (4B) + padding (4B) +
 * iov_offset (8B) + count (8B) + __iov (8B) → __iov at offset 24.
 * On 6.x kernels, __iov is at offset 16 (CO-RE handles this via BTF). */

struct iovec {
    void *iov_base;
    __kernel_size_t iov_len;
};

struct iov_iter {
    int type;
    __kernel_size_t iov_offset;
    __kernel_size_t count;
    union {
        const struct iovec *__iov;
    };
};

struct msghdr {
    void *msg_name;
    int msg_namelen;
    int _pad;
    struct iov_iter msg_iter;
};

/* Tracepoint common header */
struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

/* --- Scheduler tracepoints (used by cpu_sched.bpf.c) --- */

struct trace_event_raw_sched_wakeup_template {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	int target_cpu;
	char __data[0];
};

struct trace_event_raw_sched_switch {
	struct trace_entry ent;
	char prev_comm[16];
	pid_t prev_pid;
	int prev_prio;
	long int prev_state;
	char next_comm[16];
	pid_t next_pid;
	int next_prio;
	char __data[0];
};

/* --- Network tracepoints (used by net.bpf.c) --- */

struct trace_event_raw_inet_sock_set_state {
	struct trace_entry ent;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
	char __data[0];
};

struct trace_event_raw_tcp_probe {
	struct trace_entry ent;
	const void *skaddr;
	__u8 saddr[28];
	__u8 daddr[28];
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u32 mark;
	__u16 data_len;
	__u32 snd_nxt;
	__u32 snd_una;
	__u32 snd_cwnd;
	__u32 ssthresh;
	__u32 snd_wnd;
	__u32 srtt;
	__u32 rcv_wnd;
	__u64 sock_cookie;
	char __data[0];
};

#endif /* __VMLINUX_H__ */
