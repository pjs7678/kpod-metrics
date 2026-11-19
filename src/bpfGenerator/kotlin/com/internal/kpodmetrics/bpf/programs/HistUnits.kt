package com.internal.kpodmetrics.bpf.programs

import dev.ebpf.dsl.api.ExprHandle
import dev.ebpf.dsl.api.ProgramBodyBuilder
import dev.ebpf.dsl.types.BpfScalar

/**
 * Latency histograms bucket on `ns >> HIST_SLOT_SHIFT` rather than raw nanoseconds.
 *
 * histSlot() has 27 slots and clamps at slot 26. On raw ns that clamp is 2^26 ns ≈ 67 ms,
 * so every slow disk request, long run-queue wait or WAN round trip collapsed into one
 * "≥ 67 ms" bucket. Shifting by 10 moves the clamp to 2^36 ns ≈ 68.7 s and the first edge to
 * 2^11 ns ≈ 2 µs, which still resolves everything these signals care about.
 *
 * The map value layout is unchanged; sum_ns stays in nanoseconds.
 * Must equal Log2Histograms.SLOT_SHIFT (asserted in tests).
 */
const val HIST_SLOT_SHIFT = 10

/** Generated-C expression for the value histSlot() should bucket. */
fun ProgramBodyBuilder.histUnits(ns: ExprHandle): ExprHandle = ns shr literal(HIST_SLOT_SHIFT, BpfScalar.U32)
