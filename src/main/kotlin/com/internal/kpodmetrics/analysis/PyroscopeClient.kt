package com.internal.kpodmetrics.analysis

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.slf4j.LoggerFactory
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

class PyroscopeClient(
    private val endpoint: String,
    private val tenantId: String = "",
    private val authToken: String = "",
    private val renderPath: String = "",
    private val client: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .build()
) {
    private val log = LoggerFactory.getLogger(PyroscopeClient::class.java)
    private val mapper = jacksonObjectMapper()

    // Grafana Pyroscope uses /pyroscope/render, standalone uses /render
    private val renderPaths = if (renderPath.isNotBlank()) {
        listOf(renderPath)
    } else {
        listOf("/pyroscope/render", "/render")
    }
    @Volatile private var resolvedRenderPath: String? = null

    /**
     * Query Pyroscope render API for a timeline.
     *
     * @param query Pyroscope query, e.g. "kpod.cpu{namespace=default,pod=myapp}"
     * @param from epoch seconds start
     * @param until epoch seconds end
     * @return parsed response with timeline, or null on failure
     */
    fun queryProfile(query: String, from: Long, until: Long): PyroscopeResponse? {
        val encodedQuery = URLEncoder.encode(query, Charsets.UTF_8)

        // Use cached path if already resolved, otherwise try each candidate
        val pathsToTry = resolvedRenderPath?.let { listOf(it) } ?: renderPaths

        for (path in pathsToTry) {
            val url = "$endpoint$path?query=$encodedQuery&from=$from&until=$until&format=json"
            val result = doGet(url)
            if (result != null) {
                if (resolvedRenderPath == null) {
                    resolvedRenderPath = path
                    log.info("Pyroscope render path resolved to {}", path)
                }
                return parseResponse(result)
            }
        }
        log.warn("Pyroscope query failed on all render paths ({}) for query: {}", renderPaths, query)
        return null
    }

    private fun doGet(url: String): String? {
        val requestBuilder = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofSeconds(10))
            .GET()

        if (tenantId.isNotBlank()) {
            requestBuilder.header("X-Scope-OrgID", tenantId)
        }
        if (authToken.isNotBlank()) {
            requestBuilder.header("Authorization", "Bearer $authToken")
        }

        return try {
            val response = client.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString())
            if (response.statusCode() in 200..299) {
                response.body()
            } else {
                log.debug("Pyroscope render returned {} for {}", response.statusCode(), url)
                null
            }
        } catch (e: Exception) {
            log.debug("Pyroscope request failed for {}: {}", url, e.message)
            null
        }
    }

    internal fun parseResponse(json: String): PyroscopeResponse? {
        return try {
            val root = mapper.readTree(json)
            val timelineNode = root.get("timeline") ?: return PyroscopeResponse(timeline = null)
            val timeline = parseTimeline(timelineNode) ?: return PyroscopeResponse(timeline = null)
            PyroscopeResponse(timeline = timeline)
        } catch (e: Exception) {
            log.warn("Failed to parse Pyroscope response: {}", e.message)
            null
        }
    }

    private fun parseTimeline(node: JsonNode): PyroscopeTimeline? {
        val startTime = node.get("startTime")?.asLong() ?: return null
        val durationDelta = node.get("durationDelta")?.asLong() ?: return null
        val samplesNode = node.get("samples") ?: return null
        if (!samplesNode.isArray) return null
        val samples = (0 until samplesNode.size()).map { samplesNode[it].asLong() }
        return PyroscopeTimeline(
            startTime = startTime,
            samples = samples,
            durationDelta = durationDelta
        )
    }
}
