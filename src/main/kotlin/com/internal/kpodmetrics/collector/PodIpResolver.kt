package com.internal.kpodmetrics.collector

import io.fabric8.kubernetes.client.KubernetesClient
import org.slf4j.LoggerFactory
import java.util.concurrent.ConcurrentHashMap

data class PeerInfo(
    val podName: String? = null,
    val namespace: String? = null,
    val serviceName: String? = null
)

class PodIpResolver(private val client: KubernetesClient) {
    private val log = LoggerFactory.getLogger(PodIpResolver::class.java)
    private val cache = ConcurrentHashMap<String, PeerInfo>()

    fun resolve(ip: String): PeerInfo? = cache[ip]

    fun refresh() {
        try {
            val newMap = ConcurrentHashMap<String, PeerInfo>()

            // Map podIP -> PeerInfo(podName, namespace)
            val pods = client.pods().inAnyNamespace().list().items
            for (pod in pods) {
                val ip = pod.status?.podIP ?: continue
                val name = pod.metadata?.name ?: continue
                val namespace = pod.metadata?.namespace ?: continue
                newMap[ip] = PeerInfo(podName = name, namespace = namespace)
            }

            // Map clusterIP -> PeerInfo(serviceName, namespace)
            val services = client.services().inAnyNamespace().list().items
            for (svc in services) {
                val clusterIP = svc.spec?.clusterIP ?: continue
                if (clusterIP == "None") continue
                val name = svc.metadata?.name ?: continue
                val namespace = svc.metadata?.namespace ?: continue
                newMap[clusterIP] = PeerInfo(serviceName = name, namespace = namespace)
            }

            cache.clear()
            cache.putAll(newMap)
            log.debug("PodIpResolver refreshed: {} pod IPs, {} service IPs",
                pods.count { it.status?.podIP != null },
                services.count { val ip = it.spec?.clusterIP; ip != null && ip != "None" })
        } catch (e: Exception) {
            log.warn("Failed to refresh PodIpResolver cache: {}", e.message)
        }
    }
}
