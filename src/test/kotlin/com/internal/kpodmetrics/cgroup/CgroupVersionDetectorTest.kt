package com.internal.kpodmetrics.cgroup

import com.internal.kpodmetrics.model.CgroupVersion
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.createFile

class CgroupVersionDetectorTest {
    @TempDir
    lateinit var tempDir: Path

    @Test
    fun `detects cgroup v2 when cgroup_controllers file exists`() {
        tempDir.resolve("cgroup.controllers").createFile()
        val detector = CgroupVersionDetector(tempDir.toString())
        assertEquals(CgroupVersion.V2, detector.detect())
    }

    @Test
    fun `detects cgroup v1 when cgroup_controllers file does not exist`() {
        val detector = CgroupVersionDetector(tempDir.toString())
        assertEquals(CgroupVersion.V1, detector.detect())
    }
}
