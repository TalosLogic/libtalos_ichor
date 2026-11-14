/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_keccak_x4.c - 4-way batched SHAKE (ichor_shake128_x4 / _x4).
 *
 * The x4 API is an optimization, not a new hash, so the oracle is the
 * single-sponge ichor_shake128 / ichor_shake256 already validated by test_hash
 * against the NIST vectors.  For each (inlen, outlen) the test feeds four
 * distinct inputs through the x4 call and requires each lane to equal the
 * corresponding single-sponge hash exactly.
 *
 * The CTest profiles run this on both the default backend (AVX2 on a capable
 * host) and ICHOR_FORCE_BACKEND=keccak:scalar (the portable 4x serial path),
 * so a single host validates both backends.  Lengths span the sponge-rate
 * boundaries (0, < rate, = rate, multi-block) and non-8-byte-aligned sizes so
 * the absorb / pad / squeeze plumbing is exercised at every edge.
 */

#include "hash.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_count = 0;
static int pass_count = 0;

/* Deterministic per-lane filler so the four inputs differ. */
static void
fill(uint8_t *buf, size_t len, unsigned lane, unsigned salt)
{
    uint32_t s = 0x9e3779b9u ^ (lane * 0x85ebca6bu) ^ (salt * 0xc2b2ae35u);
    for (size_t i = 0; i < len; i++) {
        s = s * 1664525u + 1013904223u;
        buf[i] = (uint8_t)(s >> 24);
    }
}

/* Run one (inlen, outlen) case for the given variant (128 or 256). */
static void
check_case(int variant, size_t inlen, size_t outlen)
{
    uint8_t *in[4], *out[4], *ref;
    const uint8_t *cin[4];
    uint8_t *cout[4];
    int ok = 1;

    test_count++;

    ref = malloc(outlen ? outlen : 1);
    for (int l = 0; l < 4; l++) {
        in[l] = malloc(inlen ? inlen : 1);
        out[l] = malloc(outlen ? outlen : 1);
        if (!in[l] || !out[l] || !ref) {
            fprintf(stderr, "alloc failed\n");
            exit(2);
        }
        fill(in[l], inlen, (unsigned)l, (unsigned)(inlen ^ outlen));
        cin[l] = in[l];
        cout[l] = out[l];
    }

    if (variant == 128)
        ichor_shake128_x4(cout, outlen, cin, inlen);
    else
        ichor_shake256_x4(cout, outlen, cin, inlen);

    for (int l = 0; l < 4 && ok; l++) {
        ichor_hash_ctx_t ctx;
        if (variant == 128) {
            ichor_shake128_init(&ctx);
            (void)ichor_shake128_absorb(&ctx, in[l], inlen);
            ichor_shake128_squeeze(&ctx, ref, outlen);
        } else {
            ichor_shake256_init(&ctx);
            (void)ichor_shake256_absorb(&ctx, in[l], inlen);
            ichor_shake256_squeeze(&ctx, ref, outlen);
        }
        if (outlen && memcmp(ref, out[l], outlen) != 0)
            ok = 0;
    }

    if (ok)
        pass_count++;
    else
        printf("  FAIL: shake%d_x4 inlen=%zu outlen=%zu\n", variant, inlen,
               outlen);

    for (int l = 0; l < 4; l++) {
        free(in[l]);
        free(out[l]);
    }
    free(ref);
}

int
main(void)
{
    /* Boundaries around both rates (SHAKE-128 = 168, SHAKE-256 = 136) plus
     * non-aligned sizes and multi-block inputs/outputs. */
    static const size_t inlens[] = {0,   1,   7,   8,   135, 136, 137,
                                    167, 168, 169, 200, 272, 337, 1000};
    static const size_t outlens[] = {1,   7,   32,  64,  136,
                                     168, 200, 272, 337, 512};
    size_t ni = sizeof(inlens) / sizeof(inlens[0]);
    size_t no = sizeof(outlens) / sizeof(outlens[0]);

    printf("test_keccak_x4: 4-way SHAKE (backend: %s)\n",
           ichor_keccak_x4_backend_name());

    for (size_t a = 0; a < ni; a++)
        for (size_t b = 0; b < no; b++) {
            check_case(128, inlens[a], outlens[b]);
            check_case(256, inlens[a], outlens[b]);
        }

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
