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
