package com.internal.kpodmetrics.bpf

import org.slf4j.LoggerFactory

class BpfBridge {
    private val log = LoggerFactory.getLogger(BpfBridge::class.java)
    private val handleRegistry = HandleRegistry()

    companion object {
        private var loaded = false

        fun loadLibrary() {
            if (!loaded) {
                System.loadLibrary("kpod_bpf")
                loaded = true
            }
        }
    }

    // --- JNI native declarations ---

    @Throws(BpfLoadException::class)
    private external fun nativeOpenObject(path: String): Long

    @Throws(BpfLoadException::class)
    private external fun nativeLoadObject(ptr: Long): Int

    @Throws(BpfLoadException::class)
    private external fun nativeAttachAll(ptr: Long): Int

    private external fun nativeDestroyObject(ptr: Long)

    private external fun nativeGetMapFd(objPtr: Long, mapName: String): Int

    @Throws(BpfMapException::class)
    private external fun nativeMapLookup(mapFd: Int, key: ByteArray, valueSize: Int): ByteArray?

    private external fun nativeMapGetNextKey(mapFd: Int, key: ByteArray?, keySize: Int): ByteArray?

    private external fun nativeMapDelete(mapFd: Int, key: ByteArray)

    // --- Public API wrapping JNI with handle safety ---

    fun openObject(path: String): Long {
        val ptr = nativeOpenObject(path)
        return handleRegistry.register(ptr)
    }

    fun loadObject(handle: Long): Int {
        val ptr = handleRegistry.resolve(handle)
        return nativeLoadObject(ptr)
    }

    fun attachAll(handle: Long): Int {
        val ptr = handleRegistry.resolve(handle)
        return nativeAttachAll(ptr)
    }

    fun destroyObject(handle: Long) {
        val ptr = handleRegistry.resolve(handle)
        handleRegistry.invalidate(handle)
        nativeDestroyObject(ptr)
    }

    fun getMapFd(handle: Long, mapName: String): Int {
        val ptr = handleRegistry.resolve(handle)
        return nativeGetMapFd(ptr, mapName)
    }

    fun mapLookup(mapFd: Int, key: ByteArray, valueSize: Int): ByteArray? {
        return nativeMapLookup(mapFd, key, valueSize)
    }

    fun mapGetNextKey(mapFd: Int, key: ByteArray?, keySize: Int): ByteArray? {
        return nativeMapGetNextKey(mapFd, key, keySize)
    }

    fun mapDelete(mapFd: Int, key: ByteArray) {
        nativeMapDelete(mapFd, key)
    }

    fun <T> withBpfObject(path: String, block: (Long) -> T): T {
        val handle = openObject(path)
        try {
            return block(handle)
        } finally {
            try {
                destroyObject(handle)
            } catch (e: Exception) {
                log.warn("Failed to destroy BPF object: {}", e.message)
            }
        }
    }
}
