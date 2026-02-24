package com.internal.kpodmetrics.model

data class PodCgroupTarget(
    val podName: String,
    val namespace: String,
    val containerName: String,
    val cgroupPath: String,
    val nodeName: String
)
