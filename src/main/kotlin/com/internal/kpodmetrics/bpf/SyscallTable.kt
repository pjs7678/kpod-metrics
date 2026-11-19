package com.internal.kpodmetrics.bpf

/**
 * Syscall numbers for the architectures kpod ships on. Used both to fill the BPF program's
 * trk_syscalls filter (name -> number) and to label results (number -> name).
 */
class SyscallTable(private val byNumber: Map<Int, String>, aliases: Map<String, String> = emptyMap()) {
    private val byName: Map<String, Int> = byNumber.entries.associate { (k, v) -> v to k } +
        aliases.mapNotNull { (alias, target) -> byNumberName(target)?.let { alias to it } }

    private fun byNumberName(name: String): Int? = byNumber.entries.firstOrNull { it.value == name }?.key

    fun nameOf(nr: Int): String = byNumber[nr] ?: "syscall_$nr"
    fun numberOf(name: String): Int? = byName[name]

    companion object {
        val X86_64 = SyscallTable(mapOf(
            0 to "read", 1 to "write", 2 to "open", 3 to "close",
            42 to "connect", 43 to "accept", 44 to "sendto", 45 to "recvfrom",
            46 to "sendmsg", 47 to "recvmsg", 232 to "epoll_wait", 281 to "epoll_pwait",
            257 to "openat", 288 to "accept4", 202 to "futex"
        ))

        // arm64 uses the generic table: no epoll_wait (libc calls epoll_pwait), no open/accept.
        val ARM64 = SyscallTable(mapOf(
            56 to "openat", 57 to "close", 63 to "read", 64 to "write",
            198 to "socket", 200 to "bind", 203 to "connect", 202 to "accept",
            206 to "sendto", 207 to "recvfrom", 211 to "sendmsg", 212 to "recvmsg",
            22 to "epoll_pwait", 242 to "accept4", 98 to "futex"
        ), aliases = mapOf("epoll_wait" to "epoll_pwait"))

        fun forArch(arch: String = System.getProperty("os.arch") ?: ""): SyscallTable =
            if (arch == "aarch64" || arch == "arm64") ARM64 else X86_64
    }
}
