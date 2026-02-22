package com.internal.kpodmetrics.k8s

import com.internal.kpodmetrics.bpf.CgroupResolver
import com.internal.kpodmetrics.bpf.PodInfo
import com.internal.kpodmetrics.config.FilterProperties
import com.internal.kpodmetrics.config.MetricsProperties
import io.fabric8.kubernetes.api.model.Pod
import io.fabric8.kubernetes.client.KubernetesClient
import io.fabric8.kubernetes.client.Watch
import io.fabric8.kubernetes.client.Watcher
import io.fabric8.kubernetes.client.WatcherException
import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes

class PodWatcher(
    private val kubernetesClient: KubernetesClient,
    private val cgroupResolver: CgroupResolver,
    private val properties: MetricsProperties
) {
    private val log = LoggerFactory.getLogger(PodWatcher::class.java)
    private var watch: Watch? = null

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
            if (shouldWatch(pod.metadata.namespace, filter)) {
                registered += registerPod(pod)
            }
        }
        log.info("Initial pod scan complete: {} pods found, {} containers registered", pods.size, registered)

        // Watch for changes
        watch = kubernetesClient.pods()
            .inAnyNamespace()
            .withField("spec.nodeName", nodeName)
            .watch(object : Watcher<Pod> {
                override fun eventReceived(action: Watcher.Action, pod: Pod) {
                    when (action) {
                        Watcher.Action.ADDED, Watcher.Action.MODIFIED -> {
                            if (shouldWatch(pod.metadata.namespace, filter)) {
                                registerPod(pod)
                            }
                        }
                        Watcher.Action.DELETED -> {
                            log.debug(
                                "Pod deleted: {}/{}", pod.metadata.namespace, pod.metadata.name
                            )
                            // Cgroup entries become stale but will not match new BPF events;
                            // a periodic eviction could be added later if memory is a concern.
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
     * Registers all containers from a pod into the CgroupResolver.
     * Returns the number of containers successfully registered.
     */
    private fun registerPod(pod: Pod): Int {
        val podInfos = extractPodInfos(pod)
        var count = 0
        for (info in podInfos) {
            val cgroupId = resolveCgroupId(info) ?: continue
            cgroupResolver.register(cgroupId, info)
            count++
        }
        if (podInfos.isNotEmpty() && count == 0) {
            log.debug(
                "Pod {}/{}: {} containers found but no cgroup IDs resolved (containers may still be starting)",
                pod.metadata.namespace, pod.metadata.name, podInfos.size
            )
        }
        return count
    }

    /**
     * Resolves the cgroup ID (inode number of the cgroupfs directory) for a container.
     *
     * Scans /host/proc/<pid>/cgroup (or /proc/<pid>/cgroup when not in a container) to find
     * a process belonging to the given container ID, then stats the corresponding cgroupfs
     * directory to obtain its inode number, which is the value returned by bpf_get_current_cgroup_id().
     */
    internal fun resolveCgroupId(podInfo: PodInfo): Long? {
        val containerId = podInfo.containerId
        if (containerId.isBlank()) return null

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

                    // Found a process in this container; extract the cgroup path
                    val cgroupPath = parseCgroupPathFromProc(content) ?: continue
                    val fullPath = Path.of("/sys/fs/cgroup").resolve(cgroupPath.removePrefix("/"))
                    if (!Files.isDirectory(fullPath)) continue

                    val attrs = Files.readAttributes(fullPath, BasicFileAttributes::class.java)
                    val fileKey = attrs.fileKey()?.toString() ?: return null
                    // fileKey format: "(dev=XXX,ino=YYY)"
                    val inoMatch = Regex("ino=(\\d+)").find(fileKey)
                    val inode = inoMatch?.groupValues?.get(1)?.toLongOrNull()
                    if (inode != null) {
                        log.debug(
                            "Resolved cgroup ID {} for container {} (pod {}/{})",
                            inode, containerId, podInfo.namespace, podInfo.podName
                        )
                        return inode
                    }
                }
            }
        } catch (e: Exception) {
            log.debug("Failed to resolve cgroup ID for container {}: {}", containerId, e.message)
        }
        return null
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
