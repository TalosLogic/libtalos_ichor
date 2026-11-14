/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * bench_keccak_x4.c - throughput of the 4-way batched SHAKE, and a direct
 * comparison against AES-CTR for the GGM-tree node-expansion workload.
 *
 * Two questions:
 *   1. Bulk x4 SHAKE throughput vs the single-sponge baseline (run bench_hash
 *      alongside for the 1-wide number; this program prints the 4-wide one).
 *   2. Is 4-way Keccak faster than AES-CTR at producing the GGM pseudorandom
 *      bytes?  The GGM tree expands each node with PRG(seed; 2*lambda) and
 *      this codebase backs that PRG with AES-CTR (a fresh key schedule per
 *      node, then 2*lambda bits of keystream).  The honest unit is therefore
 *      "produce 2*lambda bytes from a lambda-byte seed, per node", counting
 *      the per-node AES key expansion that GGM really pays.  The Keccak side
 *      does four nodes at once: absorb the lambda-byte seed, squeeze 2*lambda.
 *
 * Backend is runtime-selected; force it with ICHOR_FORCE_BACKEND=keccak:scalar
 * to measure the portable path on an AVX2 host.  AES backend likewise via
 * aes:aesni / aes:vaes / aes:bitsliced.  Methodology: see bench_util.h (min is
 * intrinsic cost; compare only within one invocation).
 */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ichor/aes.h>
#include <ichor/hash.h>

#include "bench_util.h"

#define BULK_OUT 4096u
#define BULK_ITERS (1u << 8)
#define GGM_NODES 4u /* one Keccak-x4 batch worth of nodes */
#define GGM_ITERS (1u << 12)

/* Bulk x4 SHAKE: four independent 4096-byte squeezes per call. */
static void
bench_bulk(int variant)
{
    static uint8_t in[4][256];
    static uint8_t out[4][BULK_OUT];
    const uint8_t *cin[4];
    uint8_t *cout[4];
    bench_stats_t s;
    volatile uint8_t sink = 0;
    char label[32];

    for (int l = 0; l < 4; l++) {
        for (size_t i = 0; i < sizeof(in[l]); i++)
            in[l][i] = (uint8_t)(i + l);
        cin[l] = in[l];
        cout[l] = out[l];
    }

    if (variant == 128) {
        BENCH_MEASURE(s, BENCH_SAMPLES, BENCH_WARMUP, BULK_ITERS, {
            ichor_shake128_x4(cout, BULK_OUT, cin, sizeof(in[0]));
            sink ^= out[0][0];
        });
        snprintf(label, sizeof(label), "shake128_x4 bulk");
    } else {
        BENCH_MEASURE(s, BENCH_SAMPLES, BENCH_WARMUP, BULK_ITERS, {
            ichor_shake256_x4(cout, BULK_OUT, cin, sizeof(in[0]));
            sink ^= out[0][0];
        });
        snprintf(label, sizeof(label), "shake256_x4 bulk");
    }
    /* Four lanes of BULK_OUT bytes produced per call. */
    bench_print_mbps(label, s, (double)(4u * BULK_OUT));
    (void)sink;
}

/*
 * GGM node expansion: produce 2*lambda bytes per node from a lambda-byte seed.
 * AES side pays a per-node key schedule (as GGM does); Keccak side batches 4.
 */
static void
bench_ggm(int lambda)
{
    int keybits = lambda; /* 128 or 256 */
    size_t seed_bytes = (size_t)lambda / 8;
    size_t out_bytes = 2 * seed_bytes; /* 2*lambda bits */
    unsigned nblocks = (unsigned)(out_bytes / 16);
    int variant = lambda; /* SHAKE-128 for 128, SHAKE-256 for 256 */

    uint8_t seed[4][32];
    uint8_t ctr[4][64]; /* counter blocks (<= 4 blocks) */
    uint8_t aes_out[4][64];
    uint8_t kec_out[4][64];
    const uint8_t *cin[4];
    uint8_t *cout[4];
    bench_stats_t s_aes, s_kec;
    volatile uint8_t sink = 0;

    for (int l = 0; l < 4; l++) {
        for (size_t i = 0; i < seed_bytes; i++)
            seed[l][i] = (uint8_t)(0x11 * l + i);
        memset(ctr[l], 0, sizeof(ctr[l]));
        cin[l] = seed[l];
        cout[l] = kec_out[l];
    }

    printf("  -- GGM node expand: 2*lambda=%zu bytes/node, lambda=%d --\n",
           out_bytes, lambda);

    /* AES-CTR: fresh key schedule per node + keystream, 4 nodes serially. */
    BENCH_MEASURE(s_aes, BENCH_SAMPLES, BENCH_WARMUP, GGM_ITERS, {
        for (unsigned b = 0; b < GGM_NODES; b++) {
            ichor_aes_ctx_t actx;
            ichor_aes_key_expand(&actx, seed[b], keybits);
            ichor_aes_encrypt_wide(&actx, aes_out[b], ctr[b], nblocks);
        }
        sink ^= aes_out[0][0];
    });
    bench_print_opns("aes-ctr per node", s_aes, (double)GGM_NODES);
    bench_print_mbps("aes-ctr per node", s_aes,
                     (double)(GGM_NODES * out_bytes));

    /* Keccak x4: 4 nodes in one batched permutation. */
    if (variant == 128) {
        BENCH_MEASURE(s_kec, BENCH_SAMPLES, BENCH_WARMUP, GGM_ITERS, {
            ichor_shake128_x4(cout, out_bytes, cin, seed_bytes);
            sink ^= kec_out[0][0];
        });
    } else {
        BENCH_MEASURE(s_kec, BENCH_SAMPLES, BENCH_WARMUP, GGM_ITERS, {
            ichor_shake256_x4(cout, out_bytes, cin, seed_bytes);
            sink ^= kec_out[0][0];
        });
    }
    bench_print_opns("keccak-x4 per node", s_kec, (double)GGM_NODES);
    bench_print_mbps("keccak-x4 per node", s_kec,
                     (double)(GGM_NODES * out_bytes));
    (void)sink;
}

int
main(void)
{
    printf("KECCAK-x4  backend=%s\n", ichor_keccak_x4_backend_name());
    printf("AES        backend=%s\n", ichor_aes_backend_name());

    bench_bulk(128);
    bench_bulk(256);

    bench_ggm(128);
    bench_ggm(256);

    return 0;
}
