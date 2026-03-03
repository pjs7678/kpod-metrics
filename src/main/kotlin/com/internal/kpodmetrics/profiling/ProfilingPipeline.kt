package com.internal.kpodmetrics.profiling

import com.internal.kpodmetrics.bpf.PodInfo
import com.internal.kpodmetrics.collector.CpuProfileCollector
import com.internal.kpodmetrics.collector.StackSample
import org.slf4j.LoggerFactory

class ProfilingPipeline(
    private val collector: CpuProfileCollector,
    private val symbolResolver: SymbolResolver,
    private val pusher: PyroscopePusher,
    private val nodeName: String,
    private val durationNanos: Long,
    private val sampleFrequency: Int = 99
) {
    private val log = LoggerFactory.getLogger(ProfilingPipeline::class.java)
    private val periodNanos = 1_000_000_000L / sampleFrequency

    fun collect() {
        val profiles = collector.collect()
        if (profiles.isEmpty()) return

        val now = System.currentTimeMillis() / 1000
        val from = now - (durationNanos / 1_000_000_000)

        for ((podInfo, samples) in profiles) {
            try {
                val pprofBytes = buildPprof(podInfo, samples)
                val appName = "kpod.cpu{namespace=${podInfo.namespace},pod=${podInfo.podName},node=$nodeName}"
                pusher.push(pprofBytes, appName, from, now)
            } catch (e: Exception) {
                log.warn("Failed to build/push profile for pod {}/{}: {}",
                    podInfo.namespace, podInfo.podName, e.message)
            }
        }

        symbolResolver.trimCache()
    }

    private fun buildPprof(podInfo: PodInfo, samples: List<StackSample>): ByteArray {
        val builder = PprofBuilder(durationNanos, periodNanos)

        for (sample in samples) {
            val frames = mutableListOf<String>()

            // User stack (leaf to root)
            val elfResolver = symbolResolver.getOrCreateElfResolver(sample.tgid)
            for (ip in sample.userStackIps) {
                val name = if (elfResolver != null) {
                    symbolResolver.resolveUser(ip, elfResolver)
                } else {
                    "[unknown+0x${ip.toULong().toString(16)}]"
                }
                frames.add(name)
            }

            // Kernel stack (leaf to root)
            for (ip in sample.kernelStackIps) {
                frames.add(symbolResolver.resolveKernel(ip))
            }

            builder.addSample(frames, sample.count)
        }

        return builder.build()
    }
}
