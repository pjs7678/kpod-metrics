package com.internal.kpodmetrics.profiling

import org.junit.jupiter.api.Test
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import io.mockk.*
import kotlin.test.assertTrue
import kotlin.test.assertEquals

class PyroscopePusherTest {

    @Test
    fun `push sends gzip-compressed pprof to Pyroscope endpoint`() {
        val client = mockk<HttpClient>()
        val response = mockk<HttpResponse<String>>()
        every { response.statusCode() } returns 200
        every { response.body() } returns "OK"
        every { client.send(any<HttpRequest>(), any<HttpResponse.BodyHandler<String>>()) } returns response

        val pusher = PyroscopePusher(
            endpoint = "http://pyroscope:4040",
            client = client
        )

        pusher.push(
            pprofBytes = "test-data".toByteArray(),
            appName = "kpod.cpu{namespace=default,pod=myapp}",
            fromEpochSeconds = 1000L,
            untilEpochSeconds = 1029L
        )

        val slot = slot<HttpRequest>()
        verify { client.send(capture(slot), any<HttpResponse.BodyHandler<String>>()) }

        val request = slot.captured
        assertTrue(request.uri().toString().contains("/ingest"))
        assertTrue(request.uri().toString().contains("format=pprof"))
        assertTrue(request.uri().toString().contains("sampleRate=99"))
        assertEquals("application/x-protobuf", request.headers().firstValue("Content-Type").orElse(""))
        assertEquals("gzip", request.headers().firstValue("Content-Encoding").orElse(""))
    }

    @Test
    fun `push includes tenant header when configured`() {
        val client = mockk<HttpClient>()
        val response = mockk<HttpResponse<String>>()
        every { response.statusCode() } returns 200
        every { response.body() } returns "OK"
        every { client.send(any<HttpRequest>(), any<HttpResponse.BodyHandler<String>>()) } returns response

        val pusher = PyroscopePusher(
            endpoint = "http://pyroscope:4040",
            tenantId = "my-tenant",
            client = client
        )

        pusher.push("data".toByteArray(), "kpod.cpu{}", 1000L, 1029L)

        val slot = slot<HttpRequest>()
        verify { client.send(capture(slot), any<HttpResponse.BodyHandler<String>>()) }
        assertEquals("my-tenant", slot.captured.headers().firstValue("X-Scope-OrgID").orElse(""))
    }

    @Test
    fun `push includes auth header when configured`() {
        val client = mockk<HttpClient>()
        val response = mockk<HttpResponse<String>>()
        every { response.statusCode() } returns 200
        every { response.body() } returns "OK"
        every { client.send(any<HttpRequest>(), any<HttpResponse.BodyHandler<String>>()) } returns response

        val pusher = PyroscopePusher(
            endpoint = "http://pyroscope:4040",
            authToken = "my-secret-token",
            client = client
        )

        pusher.push("data".toByteArray(), "kpod.cpu{}", 1000L, 1029L)

        val slot = slot<HttpRequest>()
        verify { client.send(capture(slot), any<HttpResponse.BodyHandler<String>>()) }
        assertEquals("Bearer my-secret-token", slot.captured.headers().firstValue("Authorization").orElse(""))
    }

    @Test
    fun `push does not throw on HTTP error`() {
        val client = mockk<HttpClient>()
        val response = mockk<HttpResponse<String>>()
        every { response.statusCode() } returns 500
        every { response.body() } returns "Internal Server Error"
        every { client.send(any<HttpRequest>(), any<HttpResponse.BodyHandler<String>>()) } returns response

        val pusher = PyroscopePusher(endpoint = "http://pyroscope:4040", client = client)
        // Should not throw
        pusher.push("data".toByteArray(), "kpod.cpu{}", 1000L, 1029L)
    }

    @Test
    fun `push does not throw on connection error`() {
        val client = mockk<HttpClient>()
        every { client.send(any<HttpRequest>(), any<HttpResponse.BodyHandler<String>>()) } throws
            java.net.ConnectException("Connection refused")

        val pusher = PyroscopePusher(endpoint = "http://pyroscope:4040", client = client)
        // Should not throw
        pusher.push("data".toByteArray(), "kpod.cpu{}", 1000L, 1029L)
    }
}
