package com.internal.kpodmetrics.discovery

import com.internal.kpodmetrics.cgroup.CgroupPathResolver
import com.internal.kpodmetrics.model.PodCgroupTarget
import org.slf4j.LoggerFactory

class PodCgroupMapper(
    private val podProvider: PodProvider,
    private val pathResolver: CgroupPathResolver,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(PodCgroupMapper::class.java)

    fun resolve(): List<PodCgroupTarget> {
        val targets = mutableListOf<PodCgroupTarget>()
        for ((_, pod) in podProvider.getDiscoveredPods()) {
            val podPath = pathResolver.resolvePodPath(pod.uid, pod.qosClass) ?: continue
            val containerCgroups = pathResolver.listContainerPaths(podPath)
            for (container in pod.containers) {
                val matchedCgroup = containerCgroups.find { cg ->
                    cg.containerId == container.containerId ||
                    container.containerId.startsWith(cg.containerId) ||
                    cg.containerId.startsWith(container.containerId)
                }
                if (matchedCgroup != null) {
                    targets.add(PodCgroupTarget(
                        podName = pod.name, namespace = pod.namespace,
                        containerName = container.name, cgroupPath = matchedCgroup.path,
                        nodeName = nodeName
                    ))
                } else {
                    log.debug("No cgroup match for container {} in pod {}", container.name, pod.name)
                }
            }
        }
        return targets
    }
}
