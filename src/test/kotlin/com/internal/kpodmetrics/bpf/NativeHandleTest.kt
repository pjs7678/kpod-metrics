package com.internal.kpodmetrics.bpf

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.assertThrows

class NativeHandleTest {

    @Test
    fun `register and validate handle`() {
        val registry = HandleRegistry()
        val handle = registry.register(0xDEADBEEFL)
        assertTrue(registry.isValid(handle))
    }

    @Test
    fun `invalidated handle is rejected`() {
        val registry = HandleRegistry()
        val handle = registry.register(0xDEADBEEFL)
        registry.invalidate(handle)
        assertFalse(registry.isValid(handle))
    }

    @Test
    fun `resolve returns native pointer for valid handle`() {
        val registry = HandleRegistry()
        val handle = registry.register(0xDEADBEEFL)
        assertEquals(0xDEADBEEFL, registry.resolve(handle))
    }

    @Test
    fun `resolve throws for invalidated handle`() {
        val registry = HandleRegistry()
        val handle = registry.register(0xDEADBEEFL)
        registry.invalidate(handle)
        assertThrows<BpfException> { registry.resolve(handle) }
    }

    @Test
    fun `concurrent register and resolve is safe`() {
        val registry = HandleRegistry()
        val handles = (1L..1000L).map { registry.register(it) }
        handles.parallelStream().forEach { h ->
            assertTrue(registry.isValid(h))
        }
    }
}
