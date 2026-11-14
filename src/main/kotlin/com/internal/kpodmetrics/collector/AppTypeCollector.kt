package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.Counter
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Tags
import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.Paths
import java.util.concurrent.ConcurrentHashMap

/**
 * Detects what software runs in each container from process command lines and exports
 * `kpod.container.application{application="postgres"} 1`.
 *
 * Lets dashboards/alerts select "all Redis instances" regardless of image name or pod labels,
 * and lets L7 metrics be cross-checked against what is actually listening.
 * Inspired by coroot-node-agent's container_application_type.
 *
 * Only /proc/<pid>/cmdline is read: it is world-readable, whereas /proc/<pid>/exe would
 * need CAP_SYS_PTRACE, which the default (non-privileged) DaemonSet does not have.
 */
class AppTypeCollector(
    private val reader: CgroupReader,
    private val procRoot: String,
    private val registry: MeterRegistry,
    private val maxPidsPerContainer: Int = 64
) {
    private val log = LoggerFactory.getLogger(AppTypeCollector::class.java)
    private val errorCounter: Counter = registry.counter("kpod.cgroup.read.errors", "collector", "appType")
    private val meters = CumulativeMeters(registry)

    /** Last exported application set per container tag set, to drop types that disappeared. */
    private val lastSeen = ConcurrentHashMap<Tags, Set<String>>()

    fun collect(targets: List<PodCgroupTarget>) {
        for (target in targets) {
            try {
                val pids = reader.readPids(target.cgroupPath, maxPidsPerContainer)
                if (pids.isEmpty()) continue
                val apps = pids.mapNotNull { readCmdline(it)?.let(::detect) }.toSortedSet()
                val tags = target.tags()
                val previous = lastSeen.put(tags, apps) ?: emptySet()
                for (gone in previous - apps) {
                    meters.gauge(METRIC, tags.and("application", gone), null)
                }
                for (app in apps) {
                    meters.gauge(METRIC, tags.and("application", app), 1.0)
                }
            } catch (e: Exception) {
                log.debug("Failed to detect app type for pod {}/{}: {}", target.namespace, target.podName, e.message)
                errorCounter.increment()
            }
        }
    }

    fun removeStaleEntries(podName: String, namespace: String) {
        meters.removePod(podName, namespace)
        lastSeen.keys.removeIf { tags ->
            tags.any { it.key == "pod" && it.value == podName } &&
                tags.any { it.key == "namespace" && it.value == namespace }
        }
    }

    private fun readCmdline(pid: Int): List<String>? = try {
        val bytes = Files.readAllBytes(Paths.get(procRoot, pid.toString(), "cmdline"))
        if (bytes.isEmpty()) null // kernel threads / zombies
        else String(bytes, Charsets.UTF_8).split('\u0000').filter { it.isNotEmpty() }
    } catch (_: Exception) {
        null // process exited between listing and reading
    }

    companion object {
        const val METRIC = "kpod.container.application"

        private val JAVA_APPS = listOf(
            "kafka.Kafka" to "kafka",
            "org.elasticsearch." to "elasticsearch",
            "org.opensearch." to "opensearch",
            "org.apache.zookeeper." to "zookeeper",
            "org.apache.cassandra." to "cassandra",
            "org.apache.catalina." to "tomcat",
            "io.confluent." to "kafka",
        )

        private val BINARY_APPS = mapOf(
            "postgres" to "postgres", "postmaster" to "postgres",
            "mysqld" to "mysql", "mariadbd" to "mysql",
            "redis-server" to "redis", "valkey-server" to "valkey", "keydb-server" to "keydb",
            "mongod" to "mongodb", "mongos" to "mongodb",
            "memcached" to "memcached",
            "nginx" to "nginx", "envoy" to "envoy", "haproxy" to "haproxy", "traefik" to "traefik",
            "clickhouse-server" to "clickhouse",
            "etcd" to "etcd", "coredns" to "coredns",
            "node" to "nodejs", "dotnet" to "dotnet", "ruby" to "ruby",
            "php-fpm" to "php", "php" to "php",
            "nats-server" to "nats", "pgbouncer" to "pgbouncer",
            "prometheus" to "prometheus",
        )

        /** Returns a normalized application name, or null if the process is not recognized. */
        internal fun detect(argv: List<String>): String? {
            if (argv.isEmpty()) return null
            // Some daemons rewrite argv[0] into a single space-separated title (e.g. "postgres: checkpointer").
            val arg0 = argv[0].substringBefore(' ').removeSuffix(":")
            val name = arg0.substringAfterLast('/')

            if (name == "java") {
                val joined = argv.drop(1).joinToString(" ")
                return JAVA_APPS.firstOrNull { (marker, _) -> joined.contains(marker) }?.second ?: "java"
            }
            if (name == "beam.smp" || name == "beam") {
                return if (argv.any { it.contains("rabbit") }) "rabbitmq" else "erlang"
            }
            if (name == "clickhouse" && argv.getOrNull(1) == "server") return "clickhouse"
            if (name.startsWith("python")) return "python"
            if (name.startsWith("php-fpm")) return "php"
            return BINARY_APPS[name]
        }
    }
}
