package com.internal.kpodmetrics.discovery

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.internal.kpodmetrics.model.ContainerInfo
import com.internal.kpodmetrics.model.DiscoveredPod
import com.internal.kpodmetrics.model.QosClass
import org.slf4j.LoggerFactory
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class KubeletPodProvider(
    private val nodeIp: String,
    private val kubeletPort: Int = 10250,
    private val pollIntervalSeconds: Long = 30
) : PodProvider {
    private val log = LoggerFactory.getLogger(KubeletPodProvider::class.java)
    private val pods = ConcurrentHashMap<String, DiscoveredPod>()
    private var scheduler: ScheduledExecutorService? = null
    private val httpClient: HttpClient = buildInsecureClient()

    override fun getDiscoveredPods(): Map<String, DiscoveredPod> =
        java.util.Collections.unmodifiableMap(HashMap(pods))

    fun start() {
        if (nodeIp.isBlank()) {
            log.warn("NODE_IP not set, kubelet pod polling disabled")
            return
        }
        scheduler = Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "kubelet-pod-poller").apply { isDaemon = true }
        }
        scheduler!!.scheduleWithFixedDelay(::poll, 0, pollIntervalSeconds, TimeUnit.SECONDS)
        log.info("Started kubelet pod polling on {}:{} every {}s", nodeIp, kubeletPort, pollIntervalSeconds)
    }

    fun stop() {
        scheduler?.shutdownNow()
    }

    internal fun poll() {
        try {
            val token = readServiceAccountToken()
            val url = "https://$nodeIp:$kubeletPort/pods"
            val requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .GET()
            if (token.isNotBlank()) {
                requestBuilder.header("Authorization", "Bearer $token")
            }
            val response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString())
            if (response.statusCode() != 200) {
                log.warn("Kubelet /pods returned {}", response.statusCode())
                return
            }
            val parsed = parsePodListJson(response.body())
            reconcile(parsed)
        } catch (e: Exception) {
            log.error("Failed to poll kubelet /pods: {}", e.message, e)
        }
    }

    internal fun reconcile(freshPods: Map<String, DiscoveredPod>) {
        pods.keys.removeAll { it !in freshPods.keys }
        pods.putAll(freshPods)
    }

    private fun readServiceAccountToken(): String {
        return try {
            java.io.File("/var/run/secrets/kubernetes.io/serviceaccount/token").readText()
        } catch (_: Exception) { "" }
    }

    private fun buildInsecureClient(): HttpClient {
        val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, SecureRandom())
        return HttpClient.newBuilder()
            .sslContext(sslContext)
            .connectTimeout(Duration.ofSeconds(10))
            .build()
    }

    companion object {
        private val mapper = jacksonObjectMapper()

        fun parsePodListJson(json: String): Map<String, DiscoveredPod> {
            val podList = mapper.readValue<KubeletPodList>(json)
            val result = mutableMapOf<String, DiscoveredPod>()
            for (item in podList.items) {
                val uid = item.metadata?.uid ?: continue
                val name = item.metadata.name ?: continue
                val namespace = item.metadata.namespace ?: "default"
                val qosClass = when (item.status?.qosClass) {
                    "Guaranteed" -> QosClass.GUARANTEED
                    "BestEffort" -> QosClass.BEST_EFFORT
                    else -> QosClass.BURSTABLE
                }
                val containers = (item.status?.containerStatuses ?: emptyList()).mapNotNull { cs ->
                    val cName = cs.name ?: return@mapNotNull null
                    val rawId = cs.containerID ?: return@mapNotNull null
                    ContainerInfo(cName, rawId.substringAfter("://"))
                }
                result[uid] = DiscoveredPod(uid, name, namespace, qosClass, containers, item.metadata.labels ?: emptyMap())
            }
            return result
        }
    }
}

@JsonIgnoreProperties(ignoreUnknown = true)
data class KubeletPodList(val items: List<KubeletPod> = emptyList())

@JsonIgnoreProperties(ignoreUnknown = true)
data class KubeletPod(val metadata: KubeletPodMeta? = null, val status: KubeletPodStatus? = null)

@JsonIgnoreProperties(ignoreUnknown = true)
data class KubeletPodMeta(val uid: String? = null, val name: String? = null, val namespace: String? = null, val labels: Map<String, String>? = null)

@JsonIgnoreProperties(ignoreUnknown = true)
data class KubeletPodStatus(val qosClass: String? = null, val containerStatuses: List<KubeletContainerStatus>? = null)

@JsonIgnoreProperties(ignoreUnknown = true)
data class KubeletContainerStatus(val name: String? = null, val containerID: String? = null)
