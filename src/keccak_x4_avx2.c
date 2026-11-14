/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * keccak_x4_avx2.c - AVX2 4-way Keccak-f[1600] permutation.
 *
 * Runs four independent Keccak sponges in lockstep, one per 64-bit lane of a
 * 256-bit YMM register.  The 1600-bit state of the four sponges is held as 25
 * YMM words: word i carries lane i of all four sponges (st[i][0..3]).  The
 * round structure mirrors the single-sponge keccak_f1600 in hash.c (FIPS 202
 * Sections 3.2.1-3.2.5, 24 rounds of theta/rho/pi/chi/iota); every scalar 64-bit
 * operation becomes the corresponding 4-lane YMM operation.
 *
 * chi uses VPANDN: _mm256_andnot_si256(a, b) computes (~a) & b, which is exactly
 * the (~B[x+1] & B[x+2]) term.  AVX2 has no vector rotate, so rho/theta rotates
 * are a left shift ORed with a right shift (variable-count VPSLLQ/VPSRLQ via a
 * scalar count in an XMM).
 *
 * Built -mavx2; compiled in only when HAVE_KECCAK_X4_AVX2 (see CMakeLists.txt).
 * The whole translation unit is guarded by ICHOR_HAVE_KECCAK_X4_AVX2 so it is
 * an empty object on a build without the AVX2 flag (matching gf256_avx2.c).
 * Not part of the public API: the ichor_shake*_x4 front-end in keccak_x4.c
 * dispatches to it.
 */

#ifdef ICHOR_HAVE_KECCAK_X4_AVX2

#include <immintrin.h>
#include <stdint.h>

/* Keccak-f[1600] round constants (FIPS 202 Section 3.2.5). */
static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
    0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

/* Rotation offsets for rho (FIPS 202 Table 2), indexed ROT[x + 5*y]. */
static const unsigned ROT[25] = {
    0,  1,  62, 28, 27, 36, 44, 6,  55, 20, 3,  10, 43,
    25, 39, 41, 45, 15, 21, 8,  18, 2,  61, 56, 14,
};

/* 4-lane rotate-left by r in [0, 63].  r == 0 (lane (0,0)) returns x: a 64-bit
 * shift by 64 is undefined and VPSRLQ by 64 yields zero, so the zero case is
 * handled explicitly. */
static inline __m256i
rol64_x4(__m256i x, unsigned r)
{
    r &= 63u;
    if (r == 0)
        return x;
    __m128i ls = _mm_cvtsi32_si128((int)r);
    __m128i rs = _mm_cvtsi32_si128((int)(64u - r));
    return _mm256_or_si256(_mm256_sll_epi64(x, ls), _mm256_srl_epi64(x, rs));
}

void
ichor_keccak_f1600_x4_avx2(uint64_t st[25][4])
{
    __m256i A[25];
    int i, x, y, round;

    for (i = 0; i < 25; i++)
        A[i] = _mm256_loadu_si256((const __m256i *)st[i]);

    for (round = 0; round < 24; round++) {
        __m256i C[5], D[5], B[25];

        /* theta */
        for (x = 0; x < 5; x++)
            C[x] = _mm256_xor_si256(
                _mm256_xor_si256(_mm256_xor_si256(A[x], A[x + 5]),
                                 _mm256_xor_si256(A[x + 10], A[x + 15])),
                A[x + 20]);

        for (x = 0; x < 5; x++)
            D[x] =
                _mm256_xor_si256(C[(x + 4) % 5], rol64_x4(C[(x + 1) % 5], 1));

        for (i = 0; i < 25; i++)
            A[i] = _mm256_xor_si256(A[i], D[i % 5]);

        /* rho and pi combined */
        for (y = 0; y < 5; y++)
            for (x = 0; x < 5; x++)
                B[y + 5 * ((2 * x + 3 * y) % 5)] =
                    rol64_x4(A[x + 5 * y], ROT[x + 5 * y]);

        /* chi */
        for (y = 0; y < 5; y++) {
            int base = 5 * y;
            for (x = 0; x < 5; x++)
                A[base + x] = _mm256_xor_si256(
                    B[base + x], _mm256_andnot_si256(B[base + (x + 1) % 5],
                                                     B[base + (x + 2) % 5]));
        }

        /* iota */
        A[0] = _mm256_xor_si256(A[0], _mm256_set1_epi64x((long long)RC[round]));
    }

    for (i = 0; i < 25; i++)
        _mm256_storeu_si256((__m256i *)st[i], A[i]);
}

#else /* !ICHOR_HAVE_KECCAK_X4_AVX2 */

/* ISO C forbids an empty translation unit; give the guarded-out build a single
 * harmless declaration. */
typedef int ichor_keccak_x4_translation_unit_not_empty;

#endif /* ICHOR_HAVE_KECCAK_X4_AVX2 */
