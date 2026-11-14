/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf256_avx2.c - Split-nibble vpshufb GF(2^8) region multiply, AVX2 width.
 *
 * Identical algorithm to gf256_ssse3.c, widened from 16 to 32 bytes per
 * iteration: the two 16-entry nibble tables are broadcast to both 128-bit
 * lanes of a YMM and _mm256_shuffle_epi8 does the lookups 32 lanes at a time.
 * Compiled with -mavx2 -mssse3 -msse2 per-TU; empty object when
 * ICHOR_HAVE_GF256_AVX2 is not defined.  Needs AVX2 only (no AES-NI / GFNI).
 *
 * The tables are built with the constant-time scalar multiply and the YMM
 * shuffles are fixed-latency register lookups, so the pass is constant-time
 * in both the multiplier a and the data, exactly as the SSSE3 backend is.
 */

#ifdef ICHOR_HAVE_GF256_AVX2

#include "gf256_dispatch.h"

#include <immintrin.h>

static void
gf256_build_tables(uint8_t a, uint8_t lo[16], uint8_t hi[16])
{
    int j;

    for (j = 0; j < 16; j++) {
        lo[j] = ichor_gf256_mul_scalar(a, (uint8_t)j);
        hi[j] = ichor_gf256_mul_scalar(a, (uint8_t)(j << 4));
    }
}

static void
gf256_region_avx2(uint8_t *dst, const uint8_t *src, uint8_t a, size_t n,
                  int accumulate)
{
    uint8_t lo[16], hi[16];
    gf256_build_tables(a, lo, hi);

    __m256i tlo =
        _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *)lo));
    __m256i thi =
        _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *)hi));
    __m256i m0f = _mm256_set1_epi8(0x0f);
    size_t i = 0;

    for (; i + 32 <= n; i += 32) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(src + i));
        __m256i vl = _mm256_and_si256(v, m0f);
        __m256i vh = _mm256_and_si256(_mm256_srli_epi16(v, 4), m0f);
        __m256i p = _mm256_xor_si256(_mm256_shuffle_epi8(tlo, vl),
                                     _mm256_shuffle_epi8(thi, vh));
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
gf256_mul_region_avx2(uint8_t *dst, const uint8_t *src, uint8_t a, size_t n)
{
    gf256_region_avx2(dst, src, a, n, 0);
}

static void
gf256_muladd_region_avx2(uint8_t *dst, const uint8_t *src, uint8_t a, size_t n)
{
    gf256_region_avx2(dst, src, a, n, 1);
}

const ichor_gf256_ops_t ichor_gf256_ops_avx2 = {
    .mul_region = gf256_mul_region_avx2,
    .muladd_region = gf256_muladd_region_avx2,
    .backend_tag = ICHOR_GF256_BACKEND_AVX2,
    .name = "avx2",
};

#else /* !ICHOR_HAVE_GF256_AVX2 */

/* ISO C forbids an empty translation unit; give the guarded-out build a single
 * harmless declaration. */
typedef int ichor_gf256_avx2_translation_unit_not_empty;

#endif /* ICHOR_HAVE_GF256_AVX2 */
