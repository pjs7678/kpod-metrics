package com.internal.kpodmetrics.cgroup

import com.internal.kpodmetrics.model.CgroupVersion
import java.nio.file.Files
import java.nio.file.Paths

class CgroupVersionDetector(private val cgroupRoot: String) {
    fun detect(): CgroupVersion {
        val controllersFile = Paths.get(cgroupRoot, "cgroup.controllers")
        return if (Files.exists(controllersFile)) CgroupVersion.V2 else CgroupVersion.V1
    }
}
