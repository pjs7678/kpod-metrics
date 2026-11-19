package com.internal.kpodmetrics.collector

import io.fabric8.kubernetes.api.model.HasMetadata
import io.fabric8.kubernetes.api.model.Pod
import io.fabric8.kubernetes.api.model.Service
import io.fabric8.kubernetes.client.KubernetesClient
import io.fabric8.kubernetes.client.informers.ResourceEventHandler
import io.fabric8.kubernetes.client.informers.SharedIndexInformer
import org.slf4j.LoggerFactory
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

data class PeerInfo(
    val podName: String? = null,
    val namespace: String? = null,
    val serviceName: String? = null
)

/**
 * Maps cluster IPs to the pod or Service that owns them, for peer attribution.
 *
 * Backed by watch-based informers (one initial LIST each, then a WATCH stream). The previous
 * implementation re-LISTed every pod and Service in the cluster on every collection cycle, from
 * every node and from two collectors: ~4 cluster-wide LISTs per node per 30 s, which at a few
 * hundred nodes is a self-inflicted API-server load problem. It also ran on the collection
 * thread, so an unreachable API server stalled the whole cycle (BPF metrics included) into its
 * timeout, and a single failure (e.g. RBAC on services) discarded the pod map too.
 *
 * Pods and Services are independent: either can fail (and keeps retrying with backoff) without
 * affecting the other. hostNetwork pods are skipped: they share the node IP, so the mapping
 * would name an arbitrary pod.
 */
class PodIpResolver(
    private val client: KubernetesClient,
    private val resyncMs: Long = 10 * 60_000L,
    registry: io.micrometer.core.instrument.MeterRegistry? = null
) : AutoCloseable {
    private val log = LoggerFactory.getLogger(PodIpResolver::class.java)

    private val podIps = ConcurrentHashMap<String, PeerInfo>()
    private val serviceIps = ConcurrentHashMap<String, PeerInfo>()
    private val started = AtomicBoolean(false)
    private val informers = mutableListOf<SharedIndexInformer<*>>()
    private val warned = ConcurrentHashMap.newKeySet<String>()

    init {
        registry?.let { reg ->
            reg.gauge("kpod.peer.resolver.entries", io.micrometer.core.instrument.Tags.of("kind", "pod"), podIps) { it.size.toDouble() }
            reg.gauge("kpod.peer.resolver.entries", io.micrometer.core.instrument.Tags.of("kind", "service"), serviceIps) { it.size.toDouble() }
        }
    }

    fun resolve(ip: String): PeerInfo? = podIps[ip] ?: serviceIps[ip]

    /** Starts the informers on first call; afterwards a no-op. Never blocks on the API server. */
    fun refresh() {
        if (!started.compareAndSet(false, true)) return
        start("pods") {
            client.pods().inAnyNamespace().runnableInformer(resyncMs)
                .addEventHandler(handler(::onPod))
        }
        start("services") {
            client.services().inAnyNamespace().runnableInformer(resyncMs)
                .addEventHandler(handler(::onService))
        }
    }

    private fun start(kind: String, build: () -> SharedIndexInformer<*>) {
        try {
            val informer = build()
            informer.exceptionHandler { _, t ->
                // Log the first failure per kind at WARN (e.g. RBAC 403), then keep retrying quietly.
                if (warned.add(kind)) log.warn("PodIpResolver {} watch failing, retrying: {}", kind, t.message)
                else log.debug("PodIpResolver {} watch failing: {}", kind, t.message)
                true
            }
            informer.start().whenComplete { _, t ->
                if (t == null) {
                    warned.remove(kind)
                    log.info("PodIpResolver {} informer synced: {} pod IPs, {} service IPs", kind, podIps.size, serviceIps.size)
                }
            }
            synchronized(informers) { informers.add(informer) }
        } catch (e: Exception) {
            log.warn("PodIpResolver could not start {} informer: {}", kind, e.message)
        }
    }

    private fun <T : HasMetadata> handler(apply: (old: T?, new: T?) -> Unit) = object : ResourceEventHandler<T> {
        override fun onAdd(obj: T) = apply(null, obj)
        override fun onUpdate(oldObj: T, newObj: T) = apply(oldObj, newObj)
        override fun onDelete(obj: T, deletedFinalStateUnknown: Boolean) = apply(obj, null)
    }

    internal fun onPod(old: Pod?, new: Pod?) {
        old?.let { o -> podIp(o)?.let { ip -> podIps.remove(ip, peer(o)) } }
        new?.let { n -> podIp(n)?.let { ip -> podIps[ip] = peer(n) } }
    }

    internal fun onService(old: Service?, new: Service?) {
        old?.let { o -> clusterIp(o)?.let { ip -> serviceIps.remove(ip, service(o)) } }
        new?.let { n -> clusterIp(n)?.let { ip -> serviceIps[ip] = service(n) } }
    }

    private fun podIp(p: Pod): String? {
        if (p.spec?.hostNetwork == true) return null
        if (p.status?.phase == "Succeeded" || p.status?.phase == "Failed") return null // IP may be reused
        return p.status?.podIP?.takeIf { it.isNotEmpty() }
    }

    private fun clusterIp(s: Service): String? =
        s.spec?.clusterIP?.takeIf { it.isNotEmpty() && it != "None" }

    private fun peer(p: Pod) = PeerInfo(podName = p.metadata?.name, namespace = p.metadata?.namespace)
    private fun service(s: Service) = PeerInfo(serviceName = s.metadata?.name, namespace = s.metadata?.namespace)

    internal fun size(): Pair<Int, Int> = podIps.size to serviceIps.size

    override fun close() {
        synchronized(informers) {
            informers.forEach { runCatching { it.stop() } }
            informers.clear()
        }
    }
}
