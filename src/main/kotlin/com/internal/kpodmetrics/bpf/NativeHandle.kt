package com.internal.kpodmetrics.bpf

import org.slf4j.LoggerFactory
import java.lang.ref.Cleaner
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

class HandleRegistry {
    private val counter = AtomicLong(0)
    private val handles = ConcurrentHashMap<Long, Long>()
    private val cleanables = ConcurrentHashMap<Long, Cleaner.Cleanable>()

    fun register(nativePointer: Long, destroyFn: ((Long) -> Unit)? = null): Long {
        val id = counter.incrementAndGet()
        handles[id] = nativePointer
        if (destroyFn != null) {
            val cleanable = CLEANER.register(Object()) {
                if (handles.remove(id) != null) {
                    LOG.debug("Cleaner releasing leaked native handle {} (ptr={})", id, nativePointer)
                    destroyFn(nativePointer)
                }
            }
            cleanables[id] = cleanable
        }
        return id
    }

    fun isValid(handleId: Long): Boolean = handles.containsKey(handleId)

    fun resolve(handleId: Long): Long {
        return handles[handleId]
            ?: throw BpfHandleException("Invalid or stale handle: $handleId")
    }

    fun invalidate(handleId: Long) {
        handles.remove(handleId)
        cleanables.remove(handleId)?.clean()
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(HandleRegistry::class.java)
        private val CLEANER = Cleaner.create()
    }
}
