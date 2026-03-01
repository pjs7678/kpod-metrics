package com.internal.kpodmetrics.model

import io.micrometer.core.instrument.Tags

data class PodCgroupTarget(
    val podName: String,
    val namespace: String,
    val containerName: String,
    val cgroupPath: String,
    val nodeName: String,
    val labels: Map<String, String> = emptyMap()
) {
    fun baseTags(): Tags = Tags.of(
        "namespace", namespace,
        "pod", podName,
        "container", containerName,
        "node", nodeName
    )

    fun tags(): Tags {
        var tags = baseTags()
        for ((key, value) in labels) {
            val sanitized = key.replace('.', '_').replace('/', '_')
            tags = tags.and("label_$sanitized", value)
        }
        return tags
    }
}
