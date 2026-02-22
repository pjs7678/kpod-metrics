package com.internal.kpodmetrics.bpf

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

class HandleRegistry {
    private val counter = AtomicLong(0)
    private val handles = ConcurrentHashMap<Long, Long>()

    fun register(nativePointer: Long): Long {
        val id = counter.incrementAndGet()
        handles[id] = nativePointer
        return id
    }

    fun isValid(handleId: Long): Boolean = handles.containsKey(handleId)

    fun resolve(handleId: Long): Long {
        return handles[handleId]
            ?: throw BpfHandleException("Invalid or stale handle: $handleId")
    }

    fun invalidate(handleId: Long) {
        handles.remove(handleId)
    }
}
