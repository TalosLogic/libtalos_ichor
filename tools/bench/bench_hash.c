/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * bench_hash.c - throughput of the FIPS 202 sponge (SHA3-256 and
 * SHAKE-128/256).
 *
 * The permutation is a single-sponge Keccak-f[1600], runtime-dispatched: the
 * ARMv8.2 SHA-3 kernel on an aarch64 host that has it, else the portable
 * scalar permutation (the printed backend name self-reports which).  Force the
 * scalar path with ICHOR_FORCE_BACKEND=keccak:scalar to compare within a build.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ichor/hash.h>

#include "bench_util.h"

#define HASH_IN_BYTES 4096
#define HASH_OUT_BYTES 4096
#define HASH_ITERS (1u << 8)

int
main(void)
{
    uint8_t in[HASH_IN_BYTES];
    uint8_t out[HASH_OUT_BYTES];
    uint8_t digest[32];
    ichor_hash_ctx_t ctx;
    bench_stats_t s;
    volatile uint8_t sink = 0;

    for (size_t i = 0; i < sizeof(in); i++)
        in[i] = (uint8_t)i;

#ifdef ICHOR_BENCH_HAVE_KECCAK_NAME
    printf("FIPS202  keccak-f backend=%s\n", ichor_keccak_f1600_backend_name());
#else
    printf("FIPS202  keccak-f backend=soft (scalar Keccak-f[1600])\n");
#endif

    BENCH_MEASURE(s, BENCH_SAMPLES, BENCH_WARMUP, HASH_ITERS, {
        ichor_sha3_256(digest, in, sizeof(in));
        sink ^= digest[0];
    });
    bench_print_mbps("sha3_256 absorb", s, (double)HASH_IN_BYTES);

    BENCH_MEASURE(s, BENCH_SAMPLES, BENCH_WARMUP, HASH_ITERS, {
        ichor_shake128_init(&ctx);
        ichor_shake128_absorb(&ctx, in, sizeof(in));
        ichor_shake128_squeeze(&ctx, out, sizeof(out));
        sink ^= out[0];
    });
    bench_print_mbps("shake128 squeeze", s, (double)HASH_OUT_BYTES);

    BENCH_MEASURE(s, BENCH_SAMPLES, BENCH_WARMUP, HASH_ITERS, {
        ichor_shake256_init(&ctx);
        ichor_shake256_absorb(&ctx, in, sizeof(in));
        ichor_shake256_squeeze(&ctx, out, sizeof(out));
        sink ^= out[0];
    });
    bench_print_mbps("shake256 squeeze", s, (double)HASH_OUT_BYTES);

    (void)sink;
    return 0;
}
