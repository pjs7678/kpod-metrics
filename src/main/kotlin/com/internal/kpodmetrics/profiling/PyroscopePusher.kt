package com.internal.kpodmetrics.profiling

import org.slf4j.LoggerFactory
import java.io.ByteArrayOutputStream
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.zip.GZIPOutputStream

class PyroscopePusher(
    private val endpoint: String,
    private val tenantId: String = "",
    private val authToken: String = "",
    private val sampleRate: Int = 99,
    private val client: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .build()
) {
    private val log = LoggerFactory.getLogger(PyroscopePusher::class.java)

    /**
     * Push a pprof profile to Pyroscope.
     *
     * @param pprofBytes raw (uncompressed) pprof protobuf bytes
     * @param appName application name with labels, e.g. "kpod.cpu{namespace=default,pod=myapp}"
     * @param fromEpochSeconds start of the profiling window
     * @param untilEpochSeconds end of the profiling window
     */
    fun push(pprofBytes: ByteArray, appName: String, fromEpochSeconds: Long, untilEpochSeconds: Long) {
        val gzipped = gzip(pprofBytes)

        val encodedName = URLEncoder.encode(appName, Charsets.UTF_8)
        val url = "$endpoint/ingest?name=$encodedName&sampleRate=$sampleRate" +
            "&from=$fromEpochSeconds&until=$untilEpochSeconds&format=pprof"

        val requestBuilder = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/x-protobuf")
            .header("Content-Encoding", "gzip")
            .POST(HttpRequest.BodyPublishers.ofByteArray(gzipped))

        if (tenantId.isNotBlank()) {
            requestBuilder.header("X-Scope-OrgID", tenantId)
        }
        if (authToken.isNotBlank()) {
            requestBuilder.header("Authorization", "Bearer $authToken")
        }

        try {
            val response = client.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString())
            if (response.statusCode() in 200..299) {
                log.debug("Pushed profile to Pyroscope: {} ({} bytes gzipped)", appName, gzipped.size)
            } else {
                log.warn("Pyroscope ingest returned {}: {}", response.statusCode(), response.body())
            }
        } catch (e: Exception) {
            log.warn("Failed to push profile to Pyroscope: {}", e.message)
        }
    }

    private fun gzip(data: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream()
        GZIPOutputStream(baos).use { it.write(data) }
        return baos.toByteArray()
    }
}
