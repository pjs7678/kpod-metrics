package com.internal.kpodmetrics.bpf

import java.io.File

/**
 * Explains the most common production BPF failure: kprobe/tracepoint attach returning
 * EACCES ("Permission denied") from perf_event_open although the container has CAP_BPF and
 * CAP_PERFMON.
 *
 * Upstream kernels let CAP_PERFMON open perf events up to perf_event_paranoid=2. Ubuntu and
 * Debian kernels carry a patch adding level 3/4 (Ubuntu 24.04 ships 4) at which
 * perf_event_open requires CAP_SYS_ADMIN. The chart's non-privileged mode then loads every
 * program but attaches none of them, and the pod still looks healthy.
 */
object AttachPermissionDiagnosis {

    private const val CAP_SYS_ADMIN_BIT = 21

    /**
     * @param failures program -> last error message
     * @param paranoid kernel.perf_event_paranoid, null if unreadable
     * @param capEff effective capability mask of this process, null if unreadable
     * @return an actionable message, or null if the failures are not permission problems
     *   this explains
     */
    fun diagnose(failures: Map<String, String>, paranoid: Int?, capEff: Long?): String? {
        val denied = failures.filterValues { it.contains("Permission denied", ignoreCase = true) }.keys
        if (denied.isEmpty()) return null
        val hasSysAdmin = capEff != null && (capEff shr CAP_SYS_ADMIN_BIT) and 1L == 1L
        val programs = denied.sorted().joinToString()
        return if (paranoid != null && paranoid > 2 && !hasSysAdmin) {
            "BPF attach denied for [$programs]: kernel.perf_event_paranoid=$paranoid on this node, and " +
                "above 2 (Ubuntu/Debian kernels) perf_event_open requires CAP_SYS_ADMIN — CAP_PERFMON is " +
                "not enough. Fix one of: set kernel.perf_event_paranoid=2 on the nodes (sysctl, e.g. via " +
                "node bootstrap), or install with securityContext.privileged=true."
        } else {
            "BPF attach denied for [$programs] (perf_event_paranoid=${paranoid ?: "unknown"}, " +
                "CAP_SYS_ADMIN=${if (capEff == null) "unknown" else hasSysAdmin}). Check the container's " +
                "capabilities (BPF, PERFMON), its seccomp/AppArmor profile, and kernel lockdown."
        }
    }

    fun readParanoid(procRoot: String = "/proc"): Int? =
        runCatching { File("$procRoot/sys/kernel/perf_event_paranoid").readText().trim().toInt() }.getOrNull()

    /** CapEff of the current process, from /proc/self/status. */
    fun readCapEff(): Long? = runCatching {
        File("/proc/self/status").readLines()
            .first { it.startsWith("CapEff:") }
            .substringAfter(':').trim().toLong(16)
    }.getOrNull()
}
