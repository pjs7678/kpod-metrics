package com.internal.kpodmetrics.model

enum class QosClass { GUARANTEED, BURSTABLE, BEST_EFFORT }

data class ContainerInfo(
    val name: String,
    val containerId: String,
    val restartCount: Int = 0
)

data class DiscoveredPod(
    val uid: String,
    val name: String,
    val namespace: String,
    val qosClass: QosClass,
    val containers: List<ContainerInfo>,
    val labels: Map<String, String> = emptyMap()
)
