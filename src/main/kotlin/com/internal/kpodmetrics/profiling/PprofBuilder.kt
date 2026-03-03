package com.internal.kpodmetrics.profiling

import com.google.protobuf.CodedOutputStream
import java.io.ByteArrayOutputStream

/**
 * Builds a pprof Profile protobuf from resolved stack samples.
 * See: https://github.com/google/pprof/blob/main/proto/profile.proto
 */
class PprofBuilder(
    private val durationNanos: Long,
    private val periodNanos: Long = 10_101_010L // 1/99 Hz in nanos
) {
    private val stringTable = mutableListOf("") // index 0 must be ""
    private val stringIndex = mutableMapOf("" to 0L)
    private val functions = mutableListOf<FunctionEntry>()
    private val functionIndex = mutableMapOf<String, Long>() // name -> id
    private val locations = mutableListOf<LocationEntry>()
    private val locationIndex = mutableMapOf<Long, Long>() // unique key -> id
    private val samples = mutableListOf<SampleEntry>()

    private data class FunctionEntry(val id: Long, val nameIdx: Long, val sysNameIdx: Long, val filenameIdx: Long)
    private data class LocationEntry(val id: Long, val address: Long, val functionId: Long)
    private data class SampleEntry(val locationIds: List<Long>, val count: Long)

    private fun internString(s: String): Long {
        return stringIndex.getOrPut(s) {
            val idx = stringTable.size.toLong()
            stringTable.add(s)
            idx
        }
    }

    private fun getOrCreateFunction(name: String): Long {
        return functionIndex.getOrPut(name) {
            val id = (functions.size + 1).toLong()
            val nameIdx = internString(name)
            functions.add(FunctionEntry(id, nameIdx, nameIdx, internString("")))
            id
        }
    }

    private fun getOrCreateLocation(functionName: String, address: Long): Long {
        // Use function name as the dedup key (address is informational)
        val key = functionName.hashCode().toLong() xor address
        return locationIndex.getOrPut(key) {
            val id = (locations.size + 1).toLong()
            val funcId = getOrCreateFunction(functionName)
            locations.add(LocationEntry(id, address, funcId))
            id
        }
    }

    /**
     * Add a resolved stack sample.
     * @param frames list of function names from leaf to root
     * @param count number of times this stack was observed
     */
    fun addSample(frames: List<String>, count: Long) {
        if (frames.isEmpty() || count <= 0) return
        val locationIds = frames.map { name -> getOrCreateLocation(name, 0) }
        samples.add(SampleEntry(locationIds, count))
    }

    /**
     * Build the pprof Profile protobuf bytes.
     */
    fun build(): ByteArray {
        val baos = ByteArrayOutputStream()
        val cos = CodedOutputStream.newInstance(baos)

        // sample_type (field 1): {type: "cpu", unit: "nanoseconds"}
        val cpuIdx = internString("cpu")
        val nanosIdx = internString("nanoseconds")
        writeEmbeddedMessage(cos, 1) { inner ->
            inner.writeInt64(1, cpuIdx)
            inner.writeInt64(2, nanosIdx)
        }

        // samples (field 2)
        for (sample in samples) {
            writeEmbeddedMessage(cos, 2) { inner ->
                // location_ids (packed repeated uint64, field 1)
                if (sample.locationIds.isNotEmpty()) {
                    val packed = ByteArrayOutputStream()
                    val packedCos = CodedOutputStream.newInstance(packed)
                    for (locId in sample.locationIds) {
                        packedCos.writeUInt64NoTag(locId)
                    }
                    packedCos.flush()
                    inner.writeByteArray(1, packed.toByteArray())
                }
                // values (packed repeated int64, field 2)
                val valuePacked = ByteArrayOutputStream()
                val valueCos = CodedOutputStream.newInstance(valuePacked)
                valueCos.writeInt64NoTag(sample.count)
                valueCos.flush()
                inner.writeByteArray(2, valuePacked.toByteArray())
            }
        }

        // locations (field 4)
        for (loc in locations) {
            writeEmbeddedMessage(cos, 4) { inner ->
                inner.writeUInt64(1, loc.id)
                if (loc.address != 0L) inner.writeUInt64(3, loc.address)
                // line (field 4, embedded)
                writeEmbeddedMessage(inner, 4) { lineInner ->
                    lineInner.writeUInt64(1, loc.functionId)
                }
            }
        }

        // functions (field 5)
        for (func in functions) {
            writeEmbeddedMessage(cos, 5) { inner ->
                inner.writeUInt64(1, func.id)
                inner.writeInt64(2, func.nameIdx)
                inner.writeInt64(3, func.sysNameIdx)
                inner.writeInt64(4, func.filenameIdx)
            }
        }

        // string_table (field 6)
        for (s in stringTable) {
            cos.writeString(6, s)
        }

        // time_nanos (field 9)
        cos.writeInt64(9, System.currentTimeMillis() * 1_000_000)

        // duration_nanos (field 10)
        cos.writeInt64(10, durationNanos)

        // period_type (field 11): {type: "cpu", unit: "nanoseconds"}
        writeEmbeddedMessage(cos, 11) { inner ->
            inner.writeInt64(1, cpuIdx)
            inner.writeInt64(2, nanosIdx)
        }

        // period (field 12)
        cos.writeInt64(12, periodNanos)

        cos.flush()
        return baos.toByteArray()
    }

    private fun writeEmbeddedMessage(cos: CodedOutputStream, fieldNumber: Int, writer: (CodedOutputStream) -> Unit) {
        val innerBaos = ByteArrayOutputStream()
        val innerCos = CodedOutputStream.newInstance(innerBaos)
        writer(innerCos)
        innerCos.flush()
        cos.writeByteArray(fieldNumber, innerBaos.toByteArray())
    }
}
