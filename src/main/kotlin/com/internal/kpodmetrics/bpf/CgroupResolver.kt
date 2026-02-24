package com.internal.kpodmetrics.bpf

import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

data class PodInfo(
    val podUid: String,
    val containerId: String,
    val namespace: String = "",
    val podName: String = "",
    val containerName: String = ""
)

data class CgroupContainerInfo(
    val podUid: String,
    val containerId: String
)

data class GraceCacheEntry(val podInfo: PodInfo, val deletedAt: Instant)

class CgroupResolver {
    private val cache = ConcurrentHashMap<Long, PodInfo>()
    private val graceCache = ConcurrentHashMap<Long, GraceCacheEntry>()

    companion object {
        private val SYSTEMD_PATTERN = Regex(
            "kubepods-(?:burstable|besteffort|guaranteed)-pod([a-f0-9]+)\\.slice/" +
            "cri-containerd-([a-f0-9]+)\\.scope$"
        )

        private val CGROUPFS_PATTERN = Regex(
            "kubepods/(?:burstable/|besteffort/)?pod([a-z0-9-]+)/([a-z0-9]+)$"
        )

        fun parseCgroupPath(path: String): CgroupContainerInfo? {
            SYSTEMD_PATTERN.find(path)?.let { match ->
                return CgroupContainerInfo(
                    podUid = match.groupValues[1],
                    containerId = match.groupValues[2]
                )
            }
            CGROUPFS_PATTERN.find(path)?.let { match ->
                return CgroupContainerInfo(
                    podUid = match.groupValues[1],
                    containerId = match.groupValues[2]
                )
            }
            return null
        }
    }

    fun register(cgroupId: Long, podInfo: PodInfo) {
        cache[cgroupId] = podInfo
    }

    fun resolve(cgroupId: Long): PodInfo? = cache[cgroupId] ?: graceCache[cgroupId]?.podInfo

    fun evict(cgroupId: Long) {
        cache.remove(cgroupId)
    }

    fun onPodDeleted(cgroupId: Long) {
        val podInfo = cache.remove(cgroupId) ?: return
        graceCache[cgroupId] = GraceCacheEntry(podInfo, Instant.now())
    }

    fun pruneGraceCache() {
        val cutoff = Instant.now().minusSeconds(5)
        graceCache.entries.removeIf { it.value.deletedAt.isBefore(cutoff) }
    }

    fun size(): Int = cache.size
}
