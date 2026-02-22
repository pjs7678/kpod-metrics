package com.internal.kpodmetrics.k8s

import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.PodInfo
import com.internal.kpodmetrics.config.FilterProperties
import io.fabric8.kubernetes.api.model.Pod
import org.slf4j.LoggerFactory

class PodWatcher(
    private val cgroupResolver: CgroupResolver,
    private val filter: FilterProperties,
    private val nodeName: String
) {
    private val log = LoggerFactory.getLogger(PodWatcher::class.java)

    companion object {
        fun extractPodInfos(pod: Pod): List<PodInfo> {
            val metadata = pod.metadata
            val statuses = pod.status?.containerStatuses ?: return emptyList()

            return statuses.mapNotNull { status ->
                val rawId = status.containerID ?: return@mapNotNull null
                val containerId = rawId.substringAfter("://")
                PodInfo(
                    podUid = metadata.uid,
                    containerId = containerId,
                    namespace = metadata.namespace,
                    podName = metadata.name,
                    containerName = status.name
                )
            }
        }

        fun shouldWatch(namespace: String, filter: FilterProperties): Boolean {
            if (filter.namespaces.isNotEmpty()) {
                return namespace in filter.namespaces
            }
            return namespace !in filter.excludeNamespaces
        }
    }
}
