package com.internal.kpodmetrics.discovery

import com.internal.kpodmetrics.cgroup.CgroupPathResolver
import com.internal.kpodmetrics.model.PodCgroupTarget
import org.slf4j.LoggerFactory

class PodCgroupMapper(
    private val podProvider: PodProvider,
    private val pathResolver: CgroupPathResolver,
    private val nodeName: String,
    private val includeLabels: List<String> = emptyList(),
    private val scrubLabelValues: List<Regex> = emptyList()
) {
    private val log = LoggerFactory.getLogger(PodCgroupMapper::class.java)

    companion object {
        private const val REDACTED = "REDACTED"
    }

    fun resolve(): List<PodCgroupTarget> {
        val targets = mutableListOf<PodCgroupTarget>()
        for ((_, pod) in podProvider.getDiscoveredPods()) {
            val podPath = pathResolver.resolvePodPath(pod.uid, pod.qosClass) ?: continue
            val containerCgroups = pathResolver.listContainerPaths(podPath)
            // Every pod gets every included key ("" when absent): Prometheus requires one tag-key
            // set per meter name, and Micrometer silently rejects any meter whose keys differ from
            // the first registration, so a pod with a different label subset lost its metrics.
            // An empty label value is equivalent to an absent label in PromQL.
            val filteredLabels = includeLabels.associateWith { pod.labels[it] ?: "" }
            val scrubbedLabels = scrubLabels(filteredLabels)
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
                        nodeName = nodeName, labels = scrubbedLabels
                    ))
                } else {
                    log.debug("No cgroup match for container {} in pod {}", container.name, pod.name)
                }
            }
        }
        return targets
    }

    private fun scrubLabels(labels: Map<String, String>): Map<String, String> {
        if (scrubLabelValues.isEmpty()) return labels
        return labels.mapValues { (key, value) ->
            if (value.isNotEmpty() && scrubLabelValues.any { it.containsMatchIn(key) }) {
                REDACTED
            } else {
                value
            }
        }
    }
}
