/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf256_ssse3.c - Split-nibble vpshufb GF(2^8) region multiply (poly 0x11B).
 *
 * Compiled with -mssse3 -msse2 per-TU; the rest of the library does not
 * require those flags.  This file compiles to an empty object when
 * ICHOR_HAVE_GF256_SSSE3 is not defined.
 *
 * For a fixed multiplier a, the product a (x) v of a whole 16-byte vector v
 * is computed from two 16-entry tables indexed by v's nibbles, because the
 * field multiply is GF(2)-linear in v:
 *   a (x) v = a (x) (v_lo + (v_hi << 4)) = (a (x) v_lo) ^ (a (x) (v_hi << 4))
 * lo[j] = a (x) j and hi[j] = a (x) (j<<4) are built once per region; the
 * two _mm_shuffle_epi8 lookups are register shuffles indexed by data nibbles
 * (fixed latency, no memory index), so the pass is constant-time in both a
 * (the table build uses the constant-time scalar multiply) and the data.
 */

#ifdef ICHOR_HAVE_GF256_SSSE3

#include "gf256_dispatch.h"

#include <emmintrin.h> /* SSE2: and/xor/load/store, _mm_srli_epi16 */
#include <tmmintrin.h> /* SSSE3: _mm_shuffle_epi8                  */

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
gf256_mul_region_ssse3(uint8_t *dst, const uint8_t *src, uint8_t a, size_t n)
{
    uint8_t lo[16], hi[16];
    gf256_build_tables(a, lo, hi);

    __m128i tlo = _mm_loadu_si128((const __m128i *)lo);
    __m128i thi = _mm_loadu_si128((const __m128i *)hi);
    __m128i m0f = _mm_set1_epi8(0x0f);
    size_t i = 0;

    for (; i + 16 <= n; i += 16) {
        __m128i v = _mm_loadu_si128((const __m128i *)(src + i));
        __m128i vl = _mm_and_si128(v, m0f);
        __m128i vh = _mm_and_si128(_mm_srli_epi16(v, 4), m0f);
        __m128i p =
            _mm_xor_si128(_mm_shuffle_epi8(tlo, vl), _mm_shuffle_epi8(thi, vh));
        _mm_storeu_si128((__m128i *)(dst + i), p);
    }
    for (; i < n; i++)
        dst[i] = ichor_gf256_mul_scalar(a, src[i]);
}

static void
gf256_muladd_region_ssse3(uint8_t *dst, const uint8_t *src, uint8_t a, size_t n)
{
    uint8_t lo[16], hi[16];
    gf256_build_tables(a, lo, hi);

    __m128i tlo = _mm_loadu_si128((const __m128i *)lo);
    __m128i thi = _mm_loadu_si128((const __m128i *)hi);
    __m128i m0f = _mm_set1_epi8(0x0f);
    size_t i = 0;

    for (; i + 16 <= n; i += 16) {
        __m128i v = _mm_loadu_si128((const __m128i *)(src + i));
        __m128i d = _mm_loadu_si128((const __m128i *)(dst + i));
        __m128i vl = _mm_and_si128(v, m0f);
        __m128i vh = _mm_and_si128(_mm_srli_epi16(v, 4), m0f);
        __m128i p =
            _mm_xor_si128(_mm_shuffle_epi8(tlo, vl), _mm_shuffle_epi8(thi, vh));
        _mm_storeu_si128((__m128i *)(dst + i), _mm_xor_si128(d, p));
    }
    for (; i < n; i++)
        dst[i] ^= ichor_gf256_mul_scalar(a, src[i]);
}

const ichor_gf256_ops_t ichor_gf256_ops_ssse3 = {
    .mul_region = gf256_mul_region_ssse3,
    .muladd_region = gf256_muladd_region_ssse3,
    .backend_tag = ICHOR_GF256_BACKEND_SSSE3,
    .name = "ssse3",
};

#else /* !ICHOR_HAVE_GF256_SSSE3 */

/* ISO C forbids an empty translation unit, and -Wpedantic / -Werror reject
 * one; give the guarded-out build a single harmless declaration. */
typedef int ichor_gf256_ssse3_translation_unit_not_empty;

#endif /* ICHOR_HAVE_GF256_SSSE3 */
