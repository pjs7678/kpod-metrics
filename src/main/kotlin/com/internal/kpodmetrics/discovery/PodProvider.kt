package com.internal.kpodmetrics.discovery

import com.internal.kpodmetrics.model.DiscoveredPod

interface PodProvider {
    fun getDiscoveredPods(): Map<String, DiscoveredPod>
}
