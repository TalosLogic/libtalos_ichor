/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * bench_aes.c - throughput of the AES block cipher and its batch entry
 * points.
 *
 * Measures the single-block encrypt, the legacy four-block encrypt_x4, and
 * (where the running ichor exposes it) the width-agnostic encrypt_wide at
 * every batch width 1..ICHOR_AES_WIDE_MAX.  The encrypt_wide section is
 * compiled only when ICHOR_AES_WIDE_MAX is defined, so this file also builds
 * against revisions of ichor that predate the wide API: there it reports the
 * single-block and x4 numbers, which is exactly the "before" side of the
 * batch-AES comparison.
 *
 * Set ICHOR_FORCE_BACKEND (needs -DICHOR_ENABLE_FORCE_BACKEND=ON) to pin the
 * backend, e.g. ICHOR_FORCE_BACKEND=aes:aesni versus aes:vaes, to compare
 * AES-NI (serial) against VAES (several YMM chains) on one host.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ichor/aes.h>

#include "bench_util.h"

/*
 * Buffers must hold the widest batch even on a revision that predates the
 * wide API (where ICHOR_AES_WIDE_MAX is not defined); x4 needs four blocks.
 */
#ifdef ICHOR_AES_WIDE_MAX
#define ICHOR_AES_WIDE_MAX_FALLBACK ICHOR_AES_WIDE_MAX
#else
#define ICHOR_AES_WIDE_MAX_FALLBACK 8
#endif

#define AES_ITERS_1 (1u << 18)
#define AES_ITERS_BATCH (1u << 16)

static void
bench_key_bits(int key_bits)
{
    _Alignas(16) uint8_t in[16 * ICHOR_AES_WIDE_MAX_FALLBACK];
    _Alignas(16) uint8_t out[16 * ICHOR_AES_WIDE_MAX_FALLBACK];
    uint8_t key[32];
    bench_stats_t s;
    ichor_aes_ctx_t ctx;
    volatile uint8_t sink = 0;

    for (int i = 0; i < 32; i++)
        key[i] = (uint8_t)(0x40 + i);
    for (size_t i = 0; i < sizeof(in); i++)
        in[i] = (uint8_t)i;

    if (ichor_aes_key_expand(&ctx, key, key_bits) != 0) {
        printf("  AES-%d key_expand failed\n", key_bits);
        return;
    }

    printf("AES-%d  backend=%s\n", key_bits, ichor_aes_backend_name());

    BENCH_MEASURE(s, BENCH_SAMPLES, BENCH_WARMUP, AES_ITERS_1, {
        ichor_aes_encrypt(&ctx, out, in);
        sink ^= out[0];
    });
    bench_print_mbps("encrypt x1", s, 16.0);
    bench_print_opns("encrypt x1", s, 1.0);

    BENCH_MEASURE(s, BENCH_SAMPLES, BENCH_WARMUP, AES_ITERS_BATCH, {
        ichor_aes_encrypt_x4(&ctx, out, in);
        sink ^= out[0];
    });
    bench_print_mbps("encrypt_x4", s, 16.0 * 4.0);
    bench_print_opns("encrypt_x4", s, 4.0);

#ifdef ICHOR_AES_WIDE_MAX
    for (unsigned n = 1; n <= ICHOR_AES_WIDE_MAX; n++) {
        char label[32];
        snprintf(label, sizeof(label), "encrypt_wide n=%u", n);
        BENCH_MEASURE(s, BENCH_SAMPLES, BENCH_WARMUP, AES_ITERS_BATCH, {
            ichor_aes_encrypt_wide(&ctx, out, in, n);
            sink ^= out[0];
        });
        bench_print_mbps(label, s, 16.0 * (double)n);
        bench_print_opns(label, s, (double)n);
    }
#else
    printf("  (encrypt_wide absent in this ichor revision)\n");
#endif

    ichor_aes_ctx_clear(&ctx);
    (void)sink;
}

#ifdef ICHOR_AES_HAVE_MULTIKEY
/*
 * Multi-key batch: n blocks each under its own key.  This is the shape the
 * GGM tree / any per-stream mode actually produces, so it is the number that
 * matters for those consumers (vs encrypt_wide's single-key keystream).
 */
static void
bench_multikey(int key_bits)
{
    _Alignas(16) uint8_t blocks[16 * ICHOR_AES_WIDE_MAX];
    ichor_aes_ctx_t ctxs[ICHOR_AES_WIDE_MAX];
    const ichor_aes_ctx_t *ctxp[ICHOR_AES_WIDE_MAX];
    uint8_t *outp[ICHOR_AES_WIDE_MAX];
    const uint8_t *inp[ICHOR_AES_WIDE_MAX];
    uint8_t key[32];
    bench_stats_t s;
    volatile uint8_t sink = 0;

    for (size_t i = 0; i < sizeof(blocks); i++)
        blocks[i] = (uint8_t)i;
    for (unsigned b = 0; b < ICHOR_AES_WIDE_MAX; b++) {
        for (int j = 0; j < 32; j++)
            key[j] = (uint8_t)(0x11 * (b + 1) + j);
        if (ichor_aes_key_expand(&ctxs[b], key, key_bits) != 0)
            return;
        ctxp[b] = &ctxs[b];
        inp[b] = blocks + 16 * b;
        outp[b] = blocks + 16 * b;
    }

    printf("AES-%d multikey  backend=%s\n", key_bits, ichor_aes_backend_name());
    for (unsigned n = 1; n <= ICHOR_AES_WIDE_MAX; n++) {
        char label[32];
        snprintf(label, sizeof(label), "multikey n=%u", n);
        BENCH_MEASURE(s, BENCH_SAMPLES, BENCH_WARMUP, AES_ITERS_BATCH, {
            ichor_aes_encrypt_multikey(ctxp, outp, inp, n);
            sink ^= blocks[0];
        });
        bench_print_mbps(label, s, 16.0 * (double)n);
        bench_print_opns(label, s, (double)n);
    }

    for (unsigned b = 0; b < ICHOR_AES_WIDE_MAX; b++)
        ichor_aes_ctx_clear(&ctxs[b]);
    (void)sink;
}
#endif /* ICHOR_AES_HAVE_MULTIKEY */

int
main(void)
{
    bench_key_bits(128);
    printf("\n");
    bench_key_bits(256);
#ifdef ICHOR_AES_HAVE_MULTIKEY
    printf("\n");
    bench_multikey(128);
    printf("\n");
    bench_multikey(256);
#endif
    return 0;
}
