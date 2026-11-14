package com.internal.kpodmetrics.collector

import com.internal.kpodmetrics.cgroup.CgroupReader
import com.internal.kpodmetrics.model.CgroupVersion
import com.internal.kpodmetrics.model.PodCgroupTarget
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText

class AppTypeCollectorTest {
    @TempDir
    lateinit var tempDir: Path

    private fun detect(vararg argv: String) = AppTypeCollector.detect(argv.toList())

    @Test
    fun `detects common server processes`() {
        assertEquals("postgres", detect("/usr/lib/postgresql/16/bin/postgres", "-D", "/data"))
        assertEquals("postgres", detect("postgres: checkpointer "))
        assertEquals("nginx", detect("nginx: master process nginx -g daemon off;"))
        assertEquals("redis", detect("redis-server *:6379"))
        assertEquals("mysql", detect("mysqld", "--user=mysql"))
        assertEquals("mongodb", detect("mongod", "--bind_ip_all"))
        assertEquals("python", detect("/usr/local/bin/python3.12", "app.py"))
        assertEquals("nodejs", detect("node", "server.js"))
        assertEquals("clickhouse", detect("/usr/bin/clickhouse", "server"))
        assertNull(detect("/bin/sh", "-c", "sleep 1000"))
        assertNull(detect())
    }

    @Test
    fun `classifies JVM and BEAM workloads by main class`() {
        assertEquals("kafka", detect("/opt/java/bin/java", "-Xmx1G", "-cp", "/opt/kafka/libs/*", "kafka.Kafka", "server.properties"))
        assertEquals("elasticsearch", detect("java", "org.elasticsearch.bootstrap.Elasticsearch"))
        assertEquals("java", detect("java", "-jar", "app.jar"))
        assertEquals("rabbitmq", detect("/usr/lib/erlang/erts-14/bin/beam.smp", "--", "-s", "rabbit", "boot"))
    }

    @Test
    fun `exports one gauge per detected app and drops apps that disappear`() {
        val registry = SimpleMeterRegistry()
        val proc = tempDir.resolve("proc")
        fun proc(pid: Int, vararg argv: String) {
            proc.resolve("$pid").createDirectories()
            Files.write(proc.resolve("$pid/cmdline"), argv.joinToString("\u0000", postfix = "\u0000").toByteArray())
        }
        proc(10, "nginx: master process nginx")
        proc(11, "nginx: worker process")
        proc(12, "/usr/bin/envoy", "-c", "/etc/envoy.yaml")
        proc(13) // kernel thread / zombie: empty cmdline
        val cg = tempDir.resolve("cg").createDirectories()
        cg.resolve("cgroup.procs").writeText("10\n11\n12\n13\n999\n") // 999 exited

        val collector = AppTypeCollector(CgroupReader(CgroupVersion.V2), proc.toString(), registry)
        val target = PodCgroupTarget("web", "ns", "c", cg.toString(), "node")
        collector.collect(listOf(target))

        val apps = registry.find(AppTypeCollector.METRIC).gauges().map { it.id.getTag("application") }.toSet()
        assertEquals(setOf("nginx", "envoy"), apps)

        cg.resolve("cgroup.procs").writeText("10\n")
        collector.collect(listOf(target))
        val after = registry.find(AppTypeCollector.METRIC).gauges().map { it.id.getTag("application") }.toSet()
        assertEquals(setOf("nginx"), after)
    }
}
