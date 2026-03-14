package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

object SpanEvent : BpfStruct("span_event") {
    val tsNs by u64()
    val latencyNs by u64()
    val cgroupId by u64()
    val dstIp by u32()
    val dstPort by u16()
    val srcPort by u16()
    val protocol by u8()
    val method by u8()
    val statusCode by u16()
    val direction by u8()
    val pad by array(BpfScalar.U8, 3)
    val urlPath by array(BpfScalar.U8, 64)
}

object TracingConfig : BpfStruct("tracing_config") {
    val enabled by u32()
    val pad by u32()
    val thresholdNs by u64()
}
