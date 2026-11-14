/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf256_gfni.c - GFNI GF(2^8) region multiply (poly 0x11B).
 *
 * GF2P8MULB multiplies two byte vectors in GF(2^8) under the fixed AES /
 * Rijndael polynomial 0x11B, which is exactly this primitive's field, so the
 * region multiply is one instruction per 32 bytes: broadcast the scalar a to
 * all lanes and multiply.  No nibble tables, no split.  Compiled with
 * -mgfni -mavx2 per-TU (the 256-bit form is a VEX AVX2 encoding); empty object
 * when ICHOR_HAVE_GF256_GFNI is not defined.  Needs GFNI + AVX2 (no AES-NI).
 *
 * GF2P8MULB is a fixed-latency, data-independent instruction and the broadcast
 * multiplier is public, so the pass is constant-time in both a and the data.
 */

#ifdef ICHOR_HAVE_GF256_GFNI

#include "gf256_dispatch.h"

#include <immintrin.h>

static void
gf256_region_gfni(uint8_t *dst, const uint8_t *src, uint8_t a, size_t n,
                  int accumulate)
{
    __m256i va = _mm256_set1_epi8((char)a);
    size_t i = 0;

    for (; i + 32 <= n; i += 32) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(src + i));
        __m256i p = _mm256_gf2p8mul_epi8(va, v);
        if (accumulate)
            p = _mm256_xor_si256(
                p, _mm256_loadu_si256((const __m256i *)(dst + i)));
        _mm256_storeu_si256((__m256i *)(dst + i), p);
    }
    for (; i < n; i++) {
        uint8_t p = ichor_gf256_mul_scalar(a, src[i]);
        if (accumulate)
            dst[i] ^= p;
        else
            dst[i] = p;
    }
}

static void
gf256_mul_region_gfni(uint8_t *dst, const uint8_t *src, uint8_t a, size_t n)
{
    gf256_region_gfni(dst, src, a, n, 0);
}

static void
gf256_muladd_region_gfni(uint8_t *dst, const uint8_t *src, uint8_t a, size_t n)
{
    gf256_region_gfni(dst, src, a, n, 1);
}

const ichor_gf256_ops_t ichor_gf256_ops_gfni = {
    .mul_region = gf256_mul_region_gfni,
    .muladd_region = gf256_muladd_region_gfni,
    .backend_tag = ICHOR_GF256_BACKEND_GFNI,
    .name = "gfni",
};

#else /* !ICHOR_HAVE_GF256_GFNI */

/* ISO C forbids an empty translation unit; give the guarded-out build a single
 * harmless declaration. */
typedef int ichor_gf256_gfni_translation_unit_not_empty;

#endif /* ICHOR_HAVE_GF256_GFNI */
