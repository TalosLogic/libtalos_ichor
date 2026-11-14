/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl_avx2_gfni.c - AVX2 + GFNI Groestl permutation.
 *
 * Identical to grostl_avx2.c except for SubBytes: GFNI's GF2P8AFFINEINVQB
 * computes the AES S-box (GF(2^8) inverse followed by the AES affine) directly
 * on all 32 bytes in one instruction, with no ShiftRows artifact to undo.  The
 * affine matrix 0xF1E3C78F1F3E7CF8 and constant 0x63 are the standard GFNI
 * encoding of the AES forward S-box.  Requires GFNI + AVX2.
 */

#if defined(ICHOR_HAVE_GROSTL_AVX2_GFNI) && defined(ICHOR_HAVE_AES_NI)

#include <immintrin.h>

/* AES forward S-box via GFNI: inverse-then-affine in one op, all 32 bytes. */
static inline __m256i
grostl_gfni_sbox(__m256i x)
{
    return _mm256_gf2p8affineinv_epi64_epi8(
        x, _mm256_set1_epi64x((long long)0xF1E3C78F1F3E7CF8ULL), 0x63);
}

#define GROSTL_AVX2_SBOX(x) grostl_gfni_sbox(x)

#include "grostl_avx2_impl.h"

const ichor_grostl_ops_t ichor_grostl_ops_avx2_gfni = {
    /* Lone single permutations use the efficient 128-bit AES-NI entries. */
    .p512 = grostl_aesni_p512,
    .q512 = grostl_aesni_q512,
    .p1024 = grostl_aesni_p1024,
    .q1024 = grostl_aesni_q1024,
    /* The hot compression path runs P and Q together in YMM with a GFNI S-box. */
    .pq512 = ga_pq512,
    .pq1024 = ga_pq1024,
    .name = "avx2gfni",
};

#else /* !(ICHOR_HAVE_GROSTL_AVX2_GFNI && ICHOR_HAVE_AES_NI) */

/* ISO C forbids an empty translation unit; give the guarded-out build one
 * harmless declaration. */
typedef int ichor_grostl_avx2_gfni_translation_unit_not_empty;

#endif /* ICHOR_HAVE_GROSTL_AVX2_GFNI && ICHOR_HAVE_AES_NI */
