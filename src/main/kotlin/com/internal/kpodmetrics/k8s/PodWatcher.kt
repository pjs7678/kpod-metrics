package com.internal.kpodmetrics.k8s

import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.PodInfo
import com.internal.kpodmetrics.cgroup.CgroupPathResolver
import com.internal.kpodmetrics.model.CgroupVersion
import com.internal.kpodmetrics.config.FilterProperties
import com.internal.kpodmetrics.config.MetricsProperties
import com.internal.kpodmetrics.discovery.PodProvider
import com.internal.kpodmetrics.model.ContainerInfo
import com.internal.kpodmetrics.model.DiscoveredPod
import com.internal.kpodmetrics.model.QosClass
import io.fabric8.kubernetes.api.model.Pod
import io.fabric8.kubernetes.client.KubernetesClient
import io.fabric8.kubernetes.client.Watch
import io.fabric8.kubernetes.client.Watcher
import io.fabric8.kubernetes.client.WatcherException
import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

class PodWatcher(
    private val kubernetesClient: KubernetesClient,
    private val cgroupResolver: CgroupResolver,
    private val properties: MetricsProperties,
    private val registry: MeterRegistry? = null,
    private val pathResolver: CgroupPathResolver? = null
) : PodProvider {
    private val log = LoggerFactory.getLogger(PodWatcher::class.java)
    private var watch: Watch? = null
    private val discoveredPods = ConcurrentHashMap<String, DiscoveredPod>()
    private val podCgroupIds = ConcurrentHashMap<String, MutableSet<Long>>()
    private var onPodDeletedCallback: ((Long) -> Unit)? = null
    private var onPodRemovedCallback: ((podName: String, namespace: String) -> Unit)? = null
    // Gauge stores for container restart counts: key = "namespace/pod/container"
    private val restartGauges = ConcurrentHashMap<String, AtomicLong>()
    private val containerCgroupCache = ConcurrentHashMap<String, Long>()

    override fun getDiscoveredPods(): Map<String, DiscoveredPod> =
        discoveredPods.toMap()

    fun setOnPodDeletedCallback(callback: (Long) -> Unit) {
        this.onPodDeletedCallback = callback
    }

    fun setOnPodRemovedCallback(callback: (podName: String, namespace: String) -> Unit) {
        this.onPodRemovedCallback = callback
    }

    fun start() {
        val nodeName = properties.nodeName
        if (nodeName.isBlank() || nodeName == "unknown") {
            log.warn("Node name not configured (kpod.node-name); PodWatcher will not start")
            return
        }

        val filter = properties.filter
        log.info("Starting PodWatcher on node '{}'", nodeName)

        // Initial list of running pods on this node
        val pods = kubernetesClient.pods()
            .inAnyNamespace()
            .withField("spec.nodeName", nodeName)
            .list()
            .items

        var registered = 0
        for (pod in pods) {
            if (shouldWatch(pod.metadata.namespace, pod.metadata.labels ?: emptyMap(), filter)) {
                registered += registerPod(pod)
            }
        }
        log.info("Initial pod scan complete: {} pods found, {} containers registered", pods.size, registered)
        if (registered == 0 && pods.any { !it.status?.containerStatuses.isNullOrEmpty() }) {
            log.warn("No container cgroup IDs resolved for {} running pods: BPF metrics cannot be attributed " +
                "to pods. Check that the host cgroup v2 tree is mounted at kpod.cgroup.root ({}) and that " +
                "container directories exist under its kubepods hierarchy.", pods.size, properties.cgroup.root)
        }

        // Watch for changes
        watch = kubernetesClient.pods()
            .inAnyNamespace()
            .withField("spec.nodeName", nodeName)
            .watch(object : Watcher<Pod> {
                override fun eventReceived(action: Watcher.Action, pod: Pod) {
                    when (action) {
                        Watcher.Action.ADDED, Watcher.Action.MODIFIED -> {
                            if (shouldWatch(pod.metadata.namespace, pod.metadata.labels ?: emptyMap(), filter)) {
                                registerPod(pod)
                            }
                        }
                        Watcher.Action.DELETED -> {
                            log.debug(
                                "Pod deleted: {}/{}", pod.metadata.namespace, pod.metadata.name
                            )
                            pod.metadata?.let { meta ->
                                // Clear cgroup cache for this pod's containers
                                pod.status?.containerStatuses?.forEach { cs ->
                                    cs.containerID?.substringAfterLast("://")?.let { containerCgroupCache.remove(it) }
                                }
                                meta.uid?.let { uid ->
                                    discoveredPods.remove(uid)
                                    podCgroupIds.remove(uid)?.forEach { cgroupId ->
                                        cgroupResolver.onPodDeleted(cgroupId)
                                        onPodDeletedCallback?.invoke(cgroupId)
                                    }
                                }
                                val name = meta.name
                                val ns = meta.namespace
                                if (name != null && ns != null) {
                                    onPodRemovedCallback?.invoke(name, ns)
                                    removeRestartGauges(name, ns)
                                }
                            }
                        }
                        else -> {}
                    }
                }

                override fun onClose(cause: WatcherException?) {
                    if (cause != null) {
                        log.warn("Pod watch closed with error, reconnect is handled by fabric8", cause)
                    } else {
                        log.info("Pod watch closed normally")
                    }
                }
            })

        log.info("Pod watch established on node '{}'", nodeName)
    }

    fun stop() {
        watch?.close()
        watch = null
        log.info("PodWatcher stopped")
    }

    /**
     * Registers all containers from a pod into the CgroupResolver,
     * and tracks the pod as a DiscoveredPod for cgroup-based collectors.
     * Returns the number of containers successfully registered.
     */
    private fun registerPod(pod: Pod): Int {
        val podInfos = extractPodInfos(pod)
        val podUid = pod.metadata?.uid
        val qos = toDiscoveredPod(pod)?.qosClass
        var count = 0
        for (info in podInfos) {
            val cgroupId = resolveCgroupId(info, qos) ?: continue
            cgroupResolver.register(cgroupId, info)
            if (podUid != null) {
                podCgroupIds.getOrPut(podUid) { ConcurrentHashMap.newKeySet() }.add(cgroupId)
            }
            count++
        }
        if (podInfos.isNotEmpty() && count == 0) {
            log.debug(
                "Pod {}/{}: {} containers found but no cgroup IDs resolved (containers may still be starting)",
                pod.metadata.namespace, pod.metadata.name, podInfos.size
            )
        }

        // Track as DiscoveredPod for cgroup-based collectors
        toDiscoveredPod(pod)?.let { discovered ->
            discoveredPods[discovered.uid] = discovered
            updateRestartGauges(discovered)
        }

        return count
    }

    /**
     * Resolves the cgroup ID for a container: the inode number of its cgroup v2 directory, which
     * is what bpf_get_current_cgroup_id() returns.
     *
     * Primary: locate the container directory under the *host* cgroup root (kpod.cgroup.root,
     * /host/sys/fs/cgroup) with the same resolver the cgroup-file collectors use, and stat it.
     *
     * The previous approach (scan every /host/proc/<pid>/cgroup for the container ID, then stat
     * the path under the container's own /sys/fs/cgroup) resolved nothing whenever the agent ran
     * in a private cgroup namespace — the default for containerd and Docker on cgroup v2: the
     * /proc path is relative to the reader's namespace ("/../../kubepods/...") and the agent's
     * /sys/fs/cgroup is its own subtree. Every BPF metric was then silently dropped. It also read
     * every process's cgroup file per container. It remains only as a fallback.
     */
    internal fun resolveCgroupId(podInfo: PodInfo, qos: QosClass? = null): Long? {
        val containerId = podInfo.containerId
        if (containerId.isBlank()) return null

        containerCgroupCache[containerId]?.let { return it }

        resolveViaCgroupFs(podInfo, qos)?.let { inode ->
            containerCgroupCache[containerId] = inode
            return inode
        }

        // Try /host/proc first (mounted from host in DaemonSet), fall back to /proc
        val procDir = sequenceOf(Path.of("/host/proc"), Path.of("/proc"))
            .firstOrNull { Files.isDirectory(it) }
            ?: return null

        try {
            Files.list(procDir).use { stream ->
                for (entry in stream) {
                    if (!entry.fileName.toString().all { it.isDigit() }) continue
                    val cgroupFile = entry.resolve("cgroup")
                    if (!Files.exists(cgroupFile)) continue

                    val content = try {
                        Files.readString(cgroupFile)
                    } catch (_: Exception) {
                        continue
                    }

                    if (!content.contains(containerId)) continue

                    // Found a process in this container; extract the cgroup path. A path with ".."
                    // is relative to our own cgroup namespace and cannot be located reliably.
                    val cgroupPath = parseCgroupPathFromProc(content) ?: continue
                    if (cgroupPath.contains("..")) continue
                    val fullPath = Path.of(properties.cgroup.root).resolve(cgroupPath.removePrefix("/"))
                    if (!Files.isDirectory(fullPath)) continue

                    val inode = inodeOf(fullPath)
                    if (inode != null) {
                        log.debug(
                            "Resolved cgroup ID {} for container {} (pod {}/{})",
                            inode, containerId, podInfo.namespace, podInfo.podName
                        )
                        containerCgroupCache[containerId] = inode
                        return inode
                    }
                }
            }
        } catch (e: Exception) {
            log.debug("Failed to resolve cgroup ID for container {}: {}", containerId, e.message)
        }
        return null
    }

    private fun resolveViaCgroupFs(podInfo: PodInfo, qos: QosClass?): Long? {
        val resolver = pathResolver ?: return null
        if (resolver.version != CgroupVersion.V2) return null // BPF cgroup ids are v2 ids
        val classes = listOfNotNull(qos) + QosClass.entries.filter { it != qos }
        for (q in classes) {
            val podPath = resolver.resolvePodPath(podInfo.podUid, q) ?: continue
            val match = resolver.listContainerPaths(podPath).firstOrNull { cg ->
                cg.containerId == podInfo.containerId ||
                    podInfo.containerId.startsWith(cg.containerId) ||
                    cg.containerId.startsWith(podInfo.containerId)
            } ?: continue
            return inodeOf(Path.of(match.path))
        }
        return null
    }

    private fun inodeOf(path: Path): Long? = try {
        // fileKey format: "(dev=XXX,ino=YYY)"
        val key = Files.readAttributes(path, BasicFileAttributes::class.java).fileKey()?.toString()
        key?.let { Regex("ino=(\\d+)").find(it)?.groupValues?.get(1)?.toLongOrNull() }
    } catch (_: Exception) {
        null
    }

    private fun updateRestartGauges(pod: DiscoveredPod) {
        if (registry == null) return
        for (container in pod.containers) {
            val key = "${pod.namespace}/${pod.name}/${container.name}"
            val gauge = restartGauges.computeIfAbsent(key) { k ->
                val ref = AtomicLong(0)
                registry.gauge(
                    "kpod.container.restarts",
                    Tags.of("namespace", pod.namespace, "pod", pod.name, "container", container.name),
                    ref
                )
                ref
            }
            gauge.set(container.restartCount.toLong())
        }
    }

    fun removeRestartGauges(podName: String, namespace: String) {
        if (registry == null) return
        val prefix = "$namespace/$podName/"
        val keysToRemove = restartGauges.keys.filter { it.startsWith(prefix) }
        for (key in keysToRemove) {
            restartGauges.remove(key)
        }
    }

    companion object {
        /**
         * Parses the cgroup path from /proc/<pid>/cgroup content.
         * Looks for the cgroup v2 unified hierarchy (line starting with "0::") or
         * falls back to any line containing "kubepods".
         */
        internal fun parseCgroupPathFromProc(content: String): String? {
            for (line in content.lines()) {
                // cgroup v2: "0::/kubepods.slice/..."
                if (line.startsWith("0::")) {
                    val path = line.removePrefix("0::")
                    if (path.length > 1 && path.contains("kubepods")) return path
                }
            }
            // Fallback: find any kubepods line (cgroup v1)
            for (line in content.lines()) {
                if (line.contains("kubepods")) {
                    val path = line.substringAfterLast(":")
                    if (path.isNotBlank()) return path
                }
            }
            return null
        }

        fun toDiscoveredPod(pod: Pod): DiscoveredPod? {
            val metadata = pod.metadata ?: return null
            val uid = metadata.uid ?: return null
            val status = pod.status ?: return null

            val qosClass = when (status.qosClass?.uppercase()) {
                "GUARANTEED" -> QosClass.GUARANTEED
                "BURSTABLE" -> QosClass.BURSTABLE
                "BESTEFFORT" -> QosClass.BEST_EFFORT
                else -> QosClass.BEST_EFFORT
            }

            val containers = (status.containerStatuses ?: emptyList()).mapNotNull { cs ->
                val rawId = cs.containerID ?: return@mapNotNull null
                ContainerInfo(
                    name = cs.name,
                    containerId = rawId.substringAfter("://"),
                    restartCount = cs.restartCount ?: 0
                )
            }

            return DiscoveredPod(
                uid = uid,
                name = metadata.name ?: return null,
                namespace = metadata.namespace ?: return null,
                qosClass = qosClass,
                containers = containers,
                labels = metadata.labels ?: emptyMap()
            )
        }

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

        fun shouldWatch(namespace: String, podLabels: Map<String, String>, filter: FilterProperties): Boolean {
            if (filter.namespaces.isNotEmpty() && namespace !in filter.namespaces) {
                return false
            }
            if (filter.namespaces.isEmpty() && namespace in filter.excludeNamespaces) {
                return false
            }
            if (filter.labelSelector.isNotBlank()) {
                return matchesLabelSelector(podLabels, filter.labelSelector)
            }
            return true
        }

        /**
         * Matches a simple comma-separated label selector.
         * Supports: key=value, key!=value, key (exists)
         */
        internal fun matchesLabelSelector(labels: Map<String, String>, selector: String): Boolean {
            val terms = selector.split(",").map { it.trim() }.filter { it.isNotEmpty() }
            return terms.all { term ->
                when {
                    "!=" in term -> {
                        val (key, value) = term.split("!=", limit = 2)
                        labels[key.trim()] != value.trim()
                    }
                    "=" in term -> {
                        val (key, value) = term.split("=", limit = 2)
                        labels[key.trim()] == value.trim()
                    }
                    else -> labels.containsKey(term.trim())
                }
            }
        }
    }
}
