/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * bench_clmul.c - carry-less multiply throughput: single 64x64 vs the 2-wide
 * ichor_clmul64_x2.
 *
 * This is a throughput-bound loop of independent products (the shape of
 * schoolbook / Karatsuba gf2x, where products issue back to back with no
 * reduction between them).  Both loops run in one process, so the
 * single-vs-x2 ratio is a within-run comparison free of cross-run frequency
 * noise.
 *
 * A calling library cannot inline this primitive: the hardware backends are
 * separately compiled, instruction-set-gated translation units reached
 * through a runtime-dispatched function pointer, so every product is an
 * indirect call that cannot be inlined into the caller.  The 2-wide entry's
 * value is that it folds two products into one such call, halving that
 * unavoidable per-call overhead over pair-shaped work; this bench measures
 * that gain.  The backend name is printed so the host self-reports which
 * backend resolved (pclmul / pmull / scalar).
 */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>

#include <ichor/clmul.h>

#include "bench_util.h"

#define CLMUL_N 4096 /* products per sample block (even) */
#define CLMUL_ITERS 4096

int
main(void)
{
    static uint64_t a[CLMUL_N], b[CLMUL_N];
    ichor_clmul64_fn mul = ichor_clmul64_resolve();
    ichor_clmul64_x2_fn mul_x2 = ichor_clmul64_x2_resolve();
    bench_stats_t s1, s2;
    volatile uint64_t sink = 0;
    uint64_t rng = 0xabcdef0123456789ull;

    for (size_t i = 0; i < CLMUL_N; i++) {
        rng = rng * 6364136223846793005ull + 1442695040888963407ull;
        a[i] = rng;
        rng = rng * 6364136223846793005ull + 1442695040888963407ull;
        b[i] = rng;
    }

    printf("clmul  backend=%s  (%u products/iter)\n",
           ichor_clmul_backend_name(), CLMUL_N);

    BENCH_MEASURE(s1, BENCH_SAMPLES, BENCH_WARMUP, CLMUL_ITERS, {
        uint64_t acc = 0;
        uint64_t lo;
        uint64_t hi;
        for (size_t i = 0; i < CLMUL_N; i++) {
            mul(a[i], b[i], &lo, &hi);
            acc ^= lo ^ hi;
        }
        sink ^= acc;
    });
    bench_print_opns("single", s1, (double)CLMUL_N);

    BENCH_MEASURE(s2, BENCH_SAMPLES, BENCH_WARMUP, CLMUL_ITERS, {
        uint64_t acc = 0;
        uint64_t lo[2];
        uint64_t hi[2];
        for (size_t i = 0; i < CLMUL_N; i += 2) {
            mul_x2(a[i], b[i], a[i + 1], b[i + 1], lo, hi);
            acc ^= lo[0] ^ hi[0] ^ lo[1] ^ hi[1];
        }
        sink ^= acc;
    });
    bench_print_opns("x2", s2, (double)CLMUL_N);

    if (s2.median > 0.0)
        printf("  x2 speedup vs single (median): %.2fx\n",
               s1.median / s2.median);

    (void)sink;
    return 0;
}
