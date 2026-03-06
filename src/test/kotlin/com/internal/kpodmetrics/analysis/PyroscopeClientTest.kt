package com.internal.kpodmetrics.analysis

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class PyroscopeClientTest {

    private val client = PyroscopeClient(endpoint = "http://localhost:4040")

    @Test
    fun `parses valid pyroscope response with timeline`() {
        val json = """
        {
            "timeline": {
                "startTime": 1700000000,
                "durationDelta": 10,
                "samples": [100, 200, 150, 300, 250]
            },
            "flamebearer": {}
        }
        """.trimIndent()

        val response = client.parseResponse(json)
        assertNotNull(response)
        assertNotNull(response.timeline)
        assertEquals(1700000000L, response.timeline!!.startTime)
        assertEquals(10L, response.timeline!!.durationDelta)
        assertEquals(5, response.timeline!!.samples.size)
        assertEquals(100L, response.timeline!!.samples[0])
        assertEquals(300L, response.timeline!!.samples[3])
    }

    @Test
    fun `parses response with no timeline`() {
        val json = """{"flamebearer": {}}"""
        val response = client.parseResponse(json)
        assertNotNull(response)
        assertNull(response.timeline)
    }

    @Test
    fun `parses response with empty samples`() {
        val json = """
        {
            "timeline": {
                "startTime": 1700000000,
                "durationDelta": 10,
                "samples": []
            }
        }
        """.trimIndent()

        val response = client.parseResponse(json)
        assertNotNull(response)
        assertNotNull(response.timeline)
        assertEquals(0, response.timeline!!.samples.size)
    }

    @Test
    fun `handles malformed json gracefully`() {
        val response = client.parseResponse("not json")
        assertNull(response)
    }

    @Test
    fun `handles missing required timeline fields`() {
        val json = """{"timeline": {"startTime": 1700000000}}"""
        val response = client.parseResponse(json)
        assertNotNull(response)
        assertNull(response.timeline)
    }
}
