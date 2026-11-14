/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl_avx2.c - AVX2 Groestl permutation without GFNI.
 *
 * Widens the P and Q permutations into YMM lanes (see grostl_avx2_impl.h).
 * The S-box has no 256-bit form on this ISA (aesenclast is AES-NI / 128-bit),
 * so SubBytes splits the YMM into its two 128-bit halves, applies the AES S-box
 * via aesenclast with a zero round key (which also inserts an AES ShiftRows),
 * recombines, and undoes the ShiftRows with one YMM pshufb; ShiftBytes,
 * MixBytes, and AddRoundConstant run full-width on the YMM.  Requires AVX2 and
 * AES-NI; compiled to an empty object otherwise.
 */

#if defined(ICHOR_HAVE_GROSTL_AVX2) && defined(ICHOR_HAVE_AES_NI)

#include <immintrin.h>

/*
 * AES S-box over all 32 bytes: aesenclast(half, 0) applies S-box + ShiftRows to
 * each 128-bit half, then the YMM pshufb with the forward ShiftRows permutation
 * (broadcast to both lanes) recovers S(byte) for every byte independent of its
 * lane position.
 */
static inline __m256i
grostl_avx2_sbox(__m256i x)
{
    __m128i lo =
        _mm_aesenclast_si128(_mm256_castsi256_si128(x), _mm_setzero_si128());
    __m128i hi = _mm_aesenclast_si128(_mm256_extracti128_si256(x, 1),
                                      _mm_setzero_si128());
    __m256i t = _mm256_set_m128i(hi, lo);
    const __m256i sr =
        _mm256_setr_epi8(0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3,
                         0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3);
    return _mm256_shuffle_epi8(t, sr);
}

#define GROSTL_AVX2_SBOX(x) grostl_avx2_sbox(x)

#include "grostl_avx2_impl.h"

const ichor_grostl_ops_t ichor_grostl_ops_avx2 = {
    /* Lone single permutations use the efficient 128-bit AES-NI entries. */
    .p512 = grostl_aesni_p512,
    .q512 = grostl_aesni_q512,
    .p1024 = grostl_aesni_p1024,
    .q1024 = grostl_aesni_q1024,
    /* The hot compression path runs P and Q together in YMM. */
    .pq512 = ga_pq512,
    .pq1024 = ga_pq1024,
    .name = "avx2",
};

#else /* !(ICHOR_HAVE_GROSTL_AVX2 && ICHOR_HAVE_AES_NI) */

/* ISO C forbids an empty translation unit; give the guarded-out build one
 * harmless declaration. */
typedef int ichor_grostl_avx2_translation_unit_not_empty;

#endif /* ICHOR_HAVE_GROSTL_AVX2 && ICHOR_HAVE_AES_NI */
