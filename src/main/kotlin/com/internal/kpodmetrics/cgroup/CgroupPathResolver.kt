package com.internal.kpodmetrics.cgroup

import com.internal.kpodmetrics.model.CgroupVersion
import com.internal.kpodmetrics.model.QosClass
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

data class ContainerCgroup(
    val containerId: String,
    val path: String
)

class CgroupPathResolver(
    private val cgroupRoot: String,
    private val version: CgroupVersion
) {
    fun resolvePodPath(podUid: String, qosClass: QosClass, subsystem: String? = null): String? {
        val path = when (version) {
            CgroupVersion.V2 -> resolveV2PodPath(podUid, qosClass)
            CgroupVersion.V1 -> resolveV1PodPath(podUid, qosClass, subsystem ?: "blkio")
        }
        return if (Files.isDirectory(path)) path.toString() else null
    }

    fun listContainerPaths(podCgroupPath: String): List<ContainerCgroup> {
        val podDir = Paths.get(podCgroupPath)
        if (!Files.isDirectory(podDir)) return emptyList()
        return Files.list(podDir).use { stream ->
            stream.filter { Files.isDirectory(it) }
                .map { dir ->
                    val dirName = dir.fileName.toString()
                    val containerId = extractContainerId(dirName)
                    ContainerCgroup(containerId = containerId, path = dir.toString())
                }
                .toList()
        }
    }

    private fun resolveV2PodPath(podUid: String, qosClass: QosClass): Path {
        val escapedUid = podUid.replace("-", "_")

        val systemdPath = when (qosClass) {
            QosClass.GUARANTEED -> Paths.get(cgroupRoot, "kubepods.slice", "kubepods-pod${escapedUid}.slice")
            QosClass.BURSTABLE -> Paths.get(cgroupRoot, "kubepods.slice", "kubepods-burstable.slice", "kubepods-burstable-pod${escapedUid}.slice")
            QosClass.BEST_EFFORT -> Paths.get(cgroupRoot, "kubepods.slice", "kubepods-besteffort.slice", "kubepods-besteffort-pod${escapedUid}.slice")
        }
        if (Files.isDirectory(systemdPath)) return systemdPath

        val kubeletSlicePath = when (qosClass) {
            QosClass.GUARANTEED -> Paths.get(cgroupRoot, "kubelet.slice", "kubelet-kubepods.slice", "kubelet-kubepods-pod${escapedUid}.slice")
            QosClass.BURSTABLE -> Paths.get(cgroupRoot, "kubelet.slice", "kubelet-kubepods.slice", "kubelet-kubepods-burstable.slice", "kubelet-kubepods-burstable-pod${escapedUid}.slice")
            QosClass.BEST_EFFORT -> Paths.get(cgroupRoot, "kubelet.slice", "kubelet-kubepods.slice", "kubelet-kubepods-besteffort.slice", "kubelet-kubepods-besteffort-pod${escapedUid}.slice")
        }
        if (Files.isDirectory(kubeletSlicePath)) return kubeletSlicePath

        return when (qosClass) {
            QosClass.GUARANTEED -> Paths.get(cgroupRoot, "kubepods", "pod${podUid}")
            QosClass.BURSTABLE -> Paths.get(cgroupRoot, "kubepods", "burstable", "pod${podUid}")
            QosClass.BEST_EFFORT -> Paths.get(cgroupRoot, "kubepods", "besteffort", "pod${podUid}")
        }
    }

    private fun resolveV1PodPath(podUid: String, qosClass: QosClass, subsystem: String): Path {
        return when (qosClass) {
            QosClass.GUARANTEED -> Paths.get(cgroupRoot, subsystem, "kubepods", "pod${podUid}")
            QosClass.BURSTABLE -> Paths.get(cgroupRoot, subsystem, "kubepods", "burstable", "pod${podUid}")
            QosClass.BEST_EFFORT -> Paths.get(cgroupRoot, subsystem, "kubepods", "besteffort", "pod${podUid}")
        }
    }

    private fun extractContainerId(dirName: String): String {
        return dirName
            .removePrefix("cri-containerd-")
            .removePrefix("docker-")
            .removePrefix("crio-")
            .removeSuffix(".scope")
    }
}
