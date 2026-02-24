package com.internal.kpodmetrics.model

enum class QosClass { GUARANTEED, BURSTABLE, BEST_EFFORT }

data class ContainerInfo(
    val name: String,
    val containerId: String
)

data class DiscoveredPod(
    val uid: String,
    val name: String,
    val namespace: String,
    val qosClass: QosClass,
    val containers: List<ContainerInfo>
)
