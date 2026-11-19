package com.internal.kpodmetrics.discovery

import com.internal.kpodmetrics.cgroup.CgroupPathResolver
import com.internal.kpodmetrics.model.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.createDirectories

class PodCgroupMapperTest {
    @TempDir
    lateinit var tempDir: Path

    @Test
    fun `maps pods to cgroup targets for v2`() {
        val uid = "12345678-1234-1234-1234-123456789abc"
        val escapedUid = uid.replace("-", "_")
        val containerId = "abc123def456"
        val podDir = tempDir.resolve("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod${escapedUid}.slice")
        podDir.createDirectories()
        podDir.resolve("cri-containerd-${containerId}.scope").createDirectories()

        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val provider = object : PodProvider {
            override fun getDiscoveredPods(): Map<String, DiscoveredPod> = mapOf(
                uid to DiscoveredPod(uid, "nginx-pod", "default", QosClass.BURSTABLE,
                    listOf(ContainerInfo("nginx", containerId)))
            )
        }

        val mapper = PodCgroupMapper(provider, resolver, "test-node")
        val targets = mapper.resolve()
        assertEquals(1, targets.size)
        assertEquals("nginx-pod", targets[0].podName)
        assertEquals("nginx", targets[0].containerName)
        assertEquals("test-node", targets[0].nodeName)
    }

    @Test
    fun `skips pods with no matching cgroup path`() {
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val provider = object : PodProvider {
            override fun getDiscoveredPods(): Map<String, DiscoveredPod> = mapOf(
                "uid-1" to DiscoveredPod("uid-1", "ghost-pod", "default", QosClass.BURSTABLE,
                    listOf(ContainerInfo("ghost", "nonexistent")))
            )
        }
        val mapper = PodCgroupMapper(provider, resolver, "test-node")
        assertTrue(mapper.resolve().isEmpty())
    }

    @Test
    fun `scrubs label values matching sensitive patterns`() {
        val uid = "cccccccc-dddd-eeee-ffff-111111111111"
        val escapedUid = uid.replace("-", "_")
        val containerId = "scrub123"
        val podDir = tempDir.resolve("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod${escapedUid}.slice")
        podDir.createDirectories()
        podDir.resolve("cri-containerd-${containerId}.scope").createDirectories()

        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val provider = object : PodProvider {
            override fun getDiscoveredPods(): Map<String, DiscoveredPod> = mapOf(
                uid to DiscoveredPod(uid, "app-pod", "default", QosClass.BURSTABLE,
                    listOf(ContainerInfo("app", containerId)),
                    labels = mapOf(
                        "app" to "myapp",
                        "db-password" to "hunter2",
                        "api-token" to "tok_abc123",
                        "version" to "v1.2.3"
                    ))
            )
        }
        val scrubPatterns = listOf(".*password.*", ".*token.*").map { it.toRegex(RegexOption.IGNORE_CASE) }
        val mapper = PodCgroupMapper(provider, resolver, "test-node",
            includeLabels = listOf("app", "db-password", "api-token", "version"),
            scrubLabelValues = scrubPatterns)
        val targets = mapper.resolve()
        assertEquals(1, targets.size)
        val labels = targets[0].labels
        assertEquals("myapp", labels["app"])
        assertEquals("REDACTED", labels["db-password"])
        assertEquals("REDACTED", labels["api-token"])
        assertEquals("v1.2.3", labels["version"])
    }

    @Test
    fun `no scrubbing when patterns empty`() {
        val uid = "dddddddd-eeee-ffff-0000-222222222222"
        val escapedUid = uid.replace("-", "_")
        val containerId = "noscrub456"
        val podDir = tempDir.resolve("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod${escapedUid}.slice")
        podDir.createDirectories()
        podDir.resolve("cri-containerd-${containerId}.scope").createDirectories()

        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val provider = object : PodProvider {
            override fun getDiscoveredPods(): Map<String, DiscoveredPod> = mapOf(
                uid to DiscoveredPod(uid, "app-pod", "default", QosClass.BURSTABLE,
                    listOf(ContainerInfo("app", containerId)),
                    labels = mapOf("db-password" to "hunter2"))
            )
        }
        val mapper = PodCgroupMapper(provider, resolver, "test-node",
            includeLabels = listOf("db-password"))
        val targets = mapper.resolve()
        assertEquals("hunter2", targets[0].labels["db-password"])
    }

    @Test
    fun `matches container ID by prefix`() {
        val uid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        val escapedUid = uid.replace("-", "_")
        val fullContainerId = "abc123def456789012345678"
        val podDir = tempDir.resolve("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod${escapedUid}.slice")
        podDir.createDirectories()
        // Cgroup dir uses truncated container ID
        podDir.resolve("cri-containerd-abc123def456.scope").createDirectories()

        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val provider = object : PodProvider {
            override fun getDiscoveredPods(): Map<String, DiscoveredPod> = mapOf(
                uid to DiscoveredPod(uid, "app-pod", "production", QosClass.BURSTABLE,
                    listOf(ContainerInfo("app", fullContainerId)))
            )
        }
        val mapper = PodCgroupMapper(provider, resolver, "test-node")
        val targets = mapper.resolve()
        assertEquals(1, targets.size)
        assertEquals("app", targets[0].containerName)
    }

    @Test
    fun `pods with different label subsets get identical tag keys and all register in Prometheus`() {
        val pods = listOf(
            Triple("aaaaaaaa-0000-0000-0000-000000000001", "c1", mapOf("app" to "web")),
            Triple("aaaaaaaa-0000-0000-0000-000000000002", "c2",
                mapOf("app" to "op", "app.kubernetes.io/name" to "operator", "app.kubernetes.io/component" to "ctl")),
            Triple("aaaaaaaa-0000-0000-0000-000000000003", "c3", emptyMap()),
        )
        for ((uid, cid, _) in pods) {
            val podDir = tempDir.resolve("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod${uid.replace("-", "_")}.slice")
            podDir.createDirectories()
            podDir.resolve("cri-containerd-$cid.scope").createDirectories()
        }
        val resolver = CgroupPathResolver(tempDir.toString(), CgroupVersion.V2)
        val provider = object : PodProvider {
            override fun getDiscoveredPods(): Map<String, DiscoveredPod> = pods.associate { (uid, cid, labels) ->
                uid to DiscoveredPod(uid, "pod-$cid", "default", QosClass.BURSTABLE,
                    listOf(ContainerInfo("main", cid)), labels = labels)
            }
        }
        val mapper = PodCgroupMapper(provider, resolver, "n",
            includeLabels = listOf("app", "app.kubernetes.io/name", "app.kubernetes.io/component"),
            scrubLabelValues = listOf(Regex(".*component.*")))
        val targets = mapper.resolve()
        assertEquals(3, targets.size)
        val keySets = targets.map { t -> t.tags().map { it.key }.toSet() }.toSet()
        assertEquals(1, keySets.size, "one tag-key set across pods: $keySets")
        // absent label stays empty (not REDACTED) even when its key matches a scrub pattern
        assertEquals("", targets.first { it.podName == "pod-c3" }.labels["app.kubernetes.io/component"])

        val prom = io.micrometer.prometheusmetrics.PrometheusMeterRegistry(io.micrometer.prometheusmetrics.PrometheusConfig.DEFAULT)
        targets.forEach { prom.counter("kpod.test.bytes", it.tags()).increment() }
        val text = prom.scrape()
        for (p in listOf("pod-c1", "pod-c2", "pod-c3")) assertTrue(text.contains("pod=\"$p\""), "$p exported:\n$text")
    }
}
