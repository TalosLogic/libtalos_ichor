/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * bench_gf256.c - throughput of the GF(2^8) region multiply (the Reed-Solomon
 * encode / RLNC recode axpy).
 *
 * gf256 is a primitive with no prior revision, so its "before" is its own
 * scalar fallback: ICHOR_FORCE_BACKEND=gf256:scalar versus the default SSSE3
 * vpshufb backend, on one host.  Uses the resolved function pointers so the
 * timed loop measures the kernel, not the per-call dispatch.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>

#include <ichor/gf256.h>

#include "bench_util.h"

#define GF256_REGION_BYTES (1u << 16)
#define GF256_ITERS (1u << 8)

int
main(void)
{
    static uint8_t dst[GF256_REGION_BYTES];
    static uint8_t src[GF256_REGION_BYTES];
    ichor_gf256_region_fn mul = ichor_gf256_mul_region_resolve();
    ichor_gf256_region_fn mac = ichor_gf256_muladd_region_resolve();
    bench_stats_t s;
    volatile uint8_t sink = 0;

    for (size_t i = 0; i < GF256_REGION_BYTES; i++)
        src[i] = (uint8_t)i;

    printf("GF(2^8)  backend=%s  (%u bytes/region)\n",
           ichor_gf256_backend_name(), GF256_REGION_BYTES);

    BENCH_MEASURE(s, BENCH_SAMPLES, BENCH_WARMUP, GF256_ITERS, {
        mul(dst, src, 0xd7, GF256_REGION_BYTES);
        sink ^= dst[0];
    });
    bench_print_mbps("mul_region", s, (double)GF256_REGION_BYTES);

    BENCH_MEASURE(s, BENCH_SAMPLES, BENCH_WARMUP, GF256_ITERS, {
        mac(dst, src, 0xd7, GF256_REGION_BYTES);
        sink ^= dst[0];
    });
    bench_print_mbps("muladd_region", s, (double)GF256_REGION_BYTES);

    (void)sink;
    return 0;
}
