/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * bench_gf16.c - throughput of the GF(2^16) region multiply (the RLNC recode
 * / decode axpy over the network-coding field).
 *
 * As for gf256, the "before" is the scalar fallback:
 * ICHOR_FORCE_BACKEND=gf16:scalar versus the default SSSE3 vpshufb backend.
 * Throughput is reported in bytes/s (2 bytes per element).
 */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>

#include <ichor/gf16.h>

#include "bench_util.h"

#define GF16_REGION_ELEMS (1u << 15)
#define GF16_REGION_BYTES (GF16_REGION_ELEMS * 2u)
#define GF16_ITERS (1u << 8)

int
main(void)
{
    static uint16_t dst[GF16_REGION_ELEMS];
    static uint16_t src[GF16_REGION_ELEMS];
    ichor_gf16_region_fn mul = ichor_gf16_mul_region_resolve();
    ichor_gf16_region_fn mac = ichor_gf16_muladd_region_resolve();
    bench_stats_t s;
    volatile uint16_t sink = 0;

    for (size_t i = 0; i < GF16_REGION_ELEMS; i++)
        src[i] = (uint16_t)(i * 2654435761u);

    printf("GF(2^16) backend=%s  (%u elems/region)\n",
           ichor_gf16_backend_name(), GF16_REGION_ELEMS);

    BENCH_MEASURE(s, BENCH_SAMPLES, BENCH_WARMUP, GF16_ITERS, {
        mul(dst, src, 0xa53f, GF16_REGION_ELEMS);
        sink ^= dst[0];
    });
    bench_print_mbps("mul_region", s, (double)GF16_REGION_BYTES);

    BENCH_MEASURE(s, BENCH_SAMPLES, BENCH_WARMUP, GF16_ITERS, {
        mac(dst, src, 0xa53f, GF16_REGION_ELEMS);
        sink ^= dst[0];
    });
    bench_print_mbps("muladd_region", s, (double)GF16_REGION_BYTES);

    (void)sink;
    return 0;
}
