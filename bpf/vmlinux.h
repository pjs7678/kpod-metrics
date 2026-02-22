// vmlinux.h - Kernel type definitions for CO-RE eBPF programs
//
// Generate from a Linux host with BTF support:
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
//
// Requirements: Linux kernel 5.8+ with CONFIG_DEBUG_INFO_BTF=y
//
// This file must be generated on or for the target kernel architecture.
// For x86_64, generate on any x86_64 Linux host with BTF enabled.
//
// DO NOT commit the generated file (it's ~5MB). Add to .gitignore.
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

// This is a placeholder. Replace with the real vmlinux.h before building.
#error "vmlinux.h must be generated from a Linux host. See comments above."

#endif /* __VMLINUX_H__ */
