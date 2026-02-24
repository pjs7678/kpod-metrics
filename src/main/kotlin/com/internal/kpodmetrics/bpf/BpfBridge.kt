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

    private external fun nativeGetNumPossibleCpus(): Int

    private external fun nativeMapBatchLookupAndDelete(
        mapFd: Int, keys: ByteArray, values: ByteArray,
        keySize: Int, valueSize: Int, maxBatch: Int
    ): Int

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

    fun getNumPossibleCpus(): Int = nativeGetNumPossibleCpus()

    /**
     * Lookup a PERCPU_ARRAY element and sum values across all CPUs.
     * Returns the sum as a Long, or null if lookup fails.
     */
    fun mapLookupPercpuSum(mapFd: Int, key: ByteArray, valueSize: Int): Long? {
        val numCpus = getNumPossibleCpus()
        val totalSize = numCpus * valueSize
        val rawBytes = nativeMapLookup(mapFd, key, totalSize) ?: return null
        val buf = java.nio.ByteBuffer.wrap(rawBytes).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        var sum = 0L
        for (i in 0 until numCpus) {
            sum += buf.long
        }
        return sum
    }

    /**
     * Batch lookup-and-delete: atomically reads and removes up to maxEntries from a BPF map.
     * Returns a list of (key, value) pairs.
     * Falls back to legacy iterate+lookup+delete if batch is not supported.
     */
    fun mapBatchLookupAndDelete(
        mapFd: Int, keySize: Int, valueSize: Int, maxEntries: Int
    ): List<Pair<ByteArray, ByteArray>> {
        val keysArray = ByteArray(maxEntries * keySize)
        val valuesArray = ByteArray(maxEntries * valueSize)

        val count = nativeMapBatchLookupAndDelete(mapFd, keysArray, valuesArray, keySize, valueSize, maxEntries)

        if (count == -2) {
            // Batch not supported, fall back to legacy path
            return legacyLookupAndDelete(mapFd, keySize, valueSize)
        }
        if (count <= 0) return emptyList()

        val results = ArrayList<Pair<ByteArray, ByteArray>>(count)
        for (i in 0 until count) {
            val key = keysArray.copyOfRange(i * keySize, (i + 1) * keySize)
            val value = valuesArray.copyOfRange(i * valueSize, (i + 1) * valueSize)
            results.add(key to value)
        }
        return results
    }

    private fun legacyLookupAndDelete(mapFd: Int, keySize: Int, valueSize: Int): List<Pair<ByteArray, ByteArray>> {
        val keys = mutableListOf<ByteArray>()
        var prevKey: ByteArray? = null
        while (true) {
            val nextKey = mapGetNextKey(mapFd, prevKey, keySize) ?: break
            keys.add(nextKey)
            prevKey = nextKey
        }
        val results = mutableListOf<Pair<ByteArray, ByteArray>>()
        for (k in keys) {
            val value = mapLookup(mapFd, k, valueSize)
            if (value != null) {
                results.add(k to value)
            }
            mapDelete(mapFd, k)
        }
        return results
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
