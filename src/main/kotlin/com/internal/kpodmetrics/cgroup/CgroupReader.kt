package com.internal.kpodmetrics.cgroup

import com.internal.kpodmetrics.model.CgroupVersion
import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.Paths

data class DiskIOStat(
    val major: Int, val minor: Int,
    val readBytes: Long, val writeBytes: Long,
    val reads: Long, val writes: Long
)

data class NetworkStat(
    val interfaceName: String,
    val rxBytes: Long, val rxPackets: Long, val rxErrors: Long, val rxDrops: Long,
    val txBytes: Long, val txPackets: Long, val txErrors: Long, val txDrops: Long
)

data class FilesystemStat(
    val mountPoint: String,
    val totalBytes: Long,
    val usedBytes: Long,
    val availableBytes: Long
)

class CgroupReader(private val version: CgroupVersion) {
    private val log = LoggerFactory.getLogger(CgroupReader::class.java)

    fun readDiskIO(containerCgroupPath: String): List<DiskIOStat> {
        return when (version) {
            CgroupVersion.V2 -> readDiskIOV2(containerCgroupPath)
            CgroupVersion.V1 -> readDiskIOV1(containerCgroupPath)
        }
    }

    fun readInitPid(containerCgroupPath: String): Int? {
        val fileName = when (version) {
            CgroupVersion.V2 -> "cgroup.procs"
            CgroupVersion.V1 -> "tasks"
        }
        val file = Paths.get(containerCgroupPath, fileName)
        if (!Files.exists(file)) return null
        return try {
            Files.readAllLines(file)
                .firstOrNull { it.isNotBlank() }
                ?.trim()?.toIntOrNull()
        } catch (e: Exception) {
            log.warn("Failed to read PID from {}: {}", file, e.message)
            null
        }
    }

    fun readNetworkStats(procRoot: String, pid: Int): List<NetworkStat> {
        val netDev = Paths.get(procRoot, pid.toString(), "net", "dev")
        if (!Files.exists(netDev)) return emptyList()
        return try {
            Files.readAllLines(netDev)
                .drop(2)
                .filter { it.contains(":") }
                .mapNotNull { parseNetDevLine(it) }
        } catch (e: Exception) {
            log.warn("Failed to read network stats for PID {}: {}", pid, e.message)
            emptyList()
        }
    }

    fun readFilesystemStats(procRoot: String, pid: Int): List<FilesystemStat> {
        val mountInfo = Paths.get(procRoot, pid.toString(), "mountinfo")
        if (!Files.exists(mountInfo)) return emptyList()
        return try {
            Files.readAllLines(mountInfo)
                .mapNotNull { parseMountInfoLine(it) }
                .mapNotNull { (mountPoint, _) ->
                    try {
                        val resolvedPath = Paths.get(procRoot, pid.toString(), "root", mountPoint.removePrefix("/"))
                        if (!Files.exists(resolvedPath)) return@mapNotNull null
                        val store = Files.getFileStore(resolvedPath)
                        val total = store.totalSpace
                        val available = store.usableSpace
                        FilesystemStat(mountPoint, total, total - available, available)
                    } catch (e: Exception) {
                        log.debug("Skipping mount {}: {}", mountPoint, e.message)
                        null
                    }
                }
        } catch (e: Exception) {
            log.warn("Failed to read filesystem stats for PID {}: {}", pid, e.message)
            emptyList()
        }
    }

    internal fun parseMountInfoLine(line: String): Pair<String, String>? {
        val parts = line.trim().split("\\s+".toRegex())
        val separatorIndex = parts.indexOf("-")
        if (separatorIndex < 0 || separatorIndex + 1 >= parts.size) return null
        if (parts.size < 5) return null
        val mountPoint = parts[4]
        val fsType = parts[separatorIndex + 1]
        val realFilesystems = setOf("overlay", "ext4", "xfs", "btrfs")
        if (fsType !in realFilesystems) return null
        return mountPoint to fsType
    }

    private fun readDiskIOV2(containerCgroupPath: String): List<DiskIOStat> {
        val ioStat = Paths.get(containerCgroupPath, "io.stat")
        if (!Files.exists(ioStat)) return emptyList()
        return try {
            Files.readAllLines(ioStat)
                .filter { it.isNotBlank() }
                .mapNotNull { parseIOStatV2Line(it) }
        } catch (e: Exception) {
            log.warn("Failed to read io.stat from {}: {}", containerCgroupPath, e.message)
            emptyList()
        }
    }

    private fun parseIOStatV2Line(line: String): DiskIOStat? {
        val parts = line.trim().split("\\s+".toRegex())
        if (parts.size < 2) return null
        val deviceParts = parts[0].split(":")
        if (deviceParts.size != 2) return null
        val kvMap = parts.drop(1).mapNotNull {
            val kv = it.split("=")
            if (kv.size == 2) kv[0] to kv[1].toLongOrNull() else null
        }.toMap()
        return DiskIOStat(
            major = deviceParts[0].toIntOrNull() ?: return null,
            minor = deviceParts[1].toIntOrNull() ?: return null,
            readBytes = kvMap["rbytes"] ?: 0L,
            writeBytes = kvMap["wbytes"] ?: 0L,
            reads = kvMap["rios"] ?: 0L,
            writes = kvMap["wios"] ?: 0L
        )
    }

    private fun readDiskIOV1(containerCgroupPath: String): List<DiskIOStat> {
        val bytesFile = Paths.get(containerCgroupPath, "blkio.throttle.io_service_bytes")
        val opsFile = Paths.get(containerCgroupPath, "blkio.throttle.io_serviced")
        if (!Files.exists(bytesFile) || !Files.exists(opsFile)) return emptyList()
        return try {
            val bytesMap = parseBlkioV1(Files.readAllLines(bytesFile))
            val opsMap = parseBlkioV1(Files.readAllLines(opsFile))
            val devices = bytesMap.keys union opsMap.keys
            devices.mapNotNull { device ->
                val bytes = bytesMap[device] ?: emptyMap()
                val ops = opsMap[device] ?: emptyMap()
                val deviceParts = device.split(":")
                if (deviceParts.size != 2) return@mapNotNull null
                DiskIOStat(
                    major = deviceParts[0].toIntOrNull() ?: return@mapNotNull null,
                    minor = deviceParts[1].toIntOrNull() ?: return@mapNotNull null,
                    readBytes = bytes["Read"] ?: 0L, writeBytes = bytes["Write"] ?: 0L,
                    reads = ops["Read"] ?: 0L, writes = ops["Write"] ?: 0L
                )
            }
        } catch (e: Exception) {
            log.warn("Failed to read blkio stats: {}", e.message)
            emptyList()
        }
    }

    private fun parseBlkioV1(lines: List<String>): Map<String, Map<String, Long>> {
        val result = mutableMapOf<String, MutableMap<String, Long>>()
        for (line in lines) {
            val parts = line.trim().split("\\s+".toRegex())
            if (parts.size != 3) continue
            val device = parts[0]; val op = parts[1]; val value = parts[2].toLongOrNull() ?: continue
            if (op == "Total" || op == "Sync" || op == "Async") continue
            result.getOrPut(device) { mutableMapOf() }[op] = value
        }
        return result
    }

    private fun parseNetDevLine(line: String): NetworkStat? {
        val colonIndex = line.indexOf(':')
        if (colonIndex < 0) return null
        val iface = line.substring(0, colonIndex).trim()
        val values = line.substring(colonIndex + 1).trim().split("\\s+".toRegex())
        if (values.size < 16) return null
        return NetworkStat(
            interfaceName = iface,
            rxBytes = values[0].toLongOrNull() ?: 0L,
            rxPackets = values[1].toLongOrNull() ?: 0L,
            rxErrors = values[2].toLongOrNull() ?: 0L,
            rxDrops = values[3].toLongOrNull() ?: 0L,
            txBytes = values[8].toLongOrNull() ?: 0L,
            txPackets = values[9].toLongOrNull() ?: 0L,
            txErrors = values[10].toLongOrNull() ?: 0L,
            txDrops = values[11].toLongOrNull() ?: 0L
        )
    }
}
