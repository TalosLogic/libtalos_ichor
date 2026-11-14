/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf16_avx2_common.h - Shared AVX2 de/interleave for the 256-bit GF(2^16)
 * GFNI region-multiply backend (gf16_gfni.c).
 *
 * A GF(2^16) region is an array of little-endian uint16, so each element
 * occupies two interleaved bytes (low, high).  The 256-bit backend works on
 * byte PLANES: a low-byte plane and a high-byte plane, 32 elements (64 bytes)
 * per iteration.  gf16_deint256 gathers the two planes from 32 interleaved
 * elements; gf16_int256 scatters product planes back to interleaved uint16.
 *
 * Only AVX2 intrinsics are used (the including TU is built -mgfni -mavx2).
 * Not part of the public API.  (A vpshufb AVX2 gf16 backend once shared this
 * header too, but it was dropped: the lane-crossing permutes below cost more
 * than the widening saves for the table-lookup path; GFNI's cheaper affine
 * math absorbs them, so only it still earns the 256-bit layout.)
 */

#ifndef ICHOR_GF16_AVX2_COMMON_H
#define ICHOR_GF16_AVX2_COMMON_H

#include <immintrin.h>
#include <stdint.h>

/*
 * Deinterleave 32 little-endian uint16 at s (64 bytes) into a low-byte plane
 * and a high-byte plane (32 bytes each, element order preserved).  pshufb is
 * per-128-lane, so each half-shuffle leaves the 8 wanted bytes in qwords 0 and
 * 2; permute4x64 packs those two qwords low, and permute2x128 joins the two
 * YMMs into one 32-byte plane.
 */
static inline void
gf16_deint256(const uint8_t *s, __m256i *lo_out, __m256i *hi_out)
{
    const __m256i EV =
        _mm256_setr_epi8(0, 2, 4, 6, 8, 10, 12, 14, -128, -128, -128, -128,
                         -128, -128, -128, -128, 0, 2, 4, 6, 8, 10, 12, 14,
                         -128, -128, -128, -128, -128, -128, -128, -128);
    const __m256i OD =
        _mm256_setr_epi8(1, 3, 5, 7, 9, 11, 13, 15, -128, -128, -128, -128,
                         -128, -128, -128, -128, 1, 3, 5, 7, 9, 11, 13, 15,
                         -128, -128, -128, -128, -128, -128, -128, -128);
    __m256i a = _mm256_loadu_si256((const __m256i *)s);        /* e0..e15  */
    __m256i b = _mm256_loadu_si256((const __m256i *)(s + 32)); /* e16..e31 */
    __m256i al = _mm256_shuffle_epi8(a, EV);
    __m256i bl = _mm256_shuffle_epi8(b, EV);
    __m256i ah = _mm256_shuffle_epi8(a, OD);
    __m256i bh = _mm256_shuffle_epi8(b, OD);

    al = _mm256_permute4x64_epi64(al, _MM_SHUFFLE(3, 1, 2, 0));
    bl = _mm256_permute4x64_epi64(bl, _MM_SHUFFLE(3, 1, 2, 0));
    ah = _mm256_permute4x64_epi64(ah, _MM_SHUFFLE(3, 1, 2, 0));
    bh = _mm256_permute4x64_epi64(bh, _MM_SHUFFLE(3, 1, 2, 0));

    *lo_out = _mm256_permute2x128_si256(al, bl, 0x20);
    *hi_out = _mm256_permute2x128_si256(ah, bh, 0x20);
}

/*
 * Interleave low/high product byte planes back to 32 little-endian uint16 at
 * d.  When accumulate != 0 the result is XORed into d (muladd).
 */
static inline void
gf16_int256(uint8_t *d, __m256i plo, __m256i phi, int accumulate)
{
    __m256i ul =
        _mm256_unpacklo_epi8(plo, phi); /* lane0 e0..7,  lane1 e16..23 */
    __m256i uh =
        _mm256_unpackhi_epi8(plo, phi); /* lane0 e8..15, lane1 e24..31 */
    __m256i a = _mm256_permute2x128_si256(ul, uh, 0x20); /* e0..e15  */
    __m256i b = _mm256_permute2x128_si256(ul, uh, 0x31); /* e16..e31 */

    if (accumulate) {
        a = _mm256_xor_si256(a, _mm256_loadu_si256((const __m256i *)d));
        b = _mm256_xor_si256(b, _mm256_loadu_si256((const __m256i *)(d + 32)));
    }
    _mm256_storeu_si256((__m256i *)d, a);
    _mm256_storeu_si256((__m256i *)(d + 32), b);
}

#endif /* ICHOR_GF16_AVX2_COMMON_H */
