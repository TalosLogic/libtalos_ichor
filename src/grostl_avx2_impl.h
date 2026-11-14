/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl_avx2_impl.h - shared 256-bit Groestl P+Q permutation, included by the
 * AVX2 backends (grostl_avx2.c and grostl_avx2_gfni.c).
 *
 * A Groestl compression runs one P and one Q permutation on independent,
 * equal-size states.  This kernel advances both at once in YMM lanes: row i of
 * P lives in the low 128 bits of register r[i], row i of Q in the high 128.
 * SubBytes and MixBytes are identical in both lanes; ShiftBytes and
 * AddRoundConstant differ between P and Q, which is expressed as per-128-lane
 * pshufb masks and per-lane XOR constants (the low lane carries the P value,
 * the high lane the Q value).  The round structure and the MixBytes / xtime
 * formulas are the byte-exact lift of the verified 128-bit grostl_aesni.c.
 *
 * The including TU supplies the S-box as a macro GROSTL_AVX2_SBOX(ymm) -> ymm
 * (one GF2P8AFFINEINVQB with GFNI, or split-lane aesenclast + pshufb without),
 * and is compiled with its own ISA flags.  Everything here is `static`, so each
 * TU gets a private copy with no cross-TU symbol collision.
 *
 * Constant-time: no secret-dependent branch, no secret-indexed access; xtime is
 * branchless, and every pshufb mask / round constant is a fixed public value.
 */

#ifndef ICHOR_GROSTL_AVX2_IMPL_H
#define ICHOR_GROSTL_AVX2_IMPL_H

#include <immintrin.h>

#include "grostl_dispatch.h"
#include "util.h"

#ifndef GROSTL_AVX2_SBOX
#error "include grostl_avx2_impl.h only after defining GROSTL_AVX2_SBOX(ymm)"
#endif

/* ShiftBytes amounts (columns each row is cyclically shifted left). */
static const uint8_t GA_SHIFT_P512[GROSTL_ROWS] = {0, 1, 2, 3, 4, 5, 6, 7};
static const uint8_t GA_SHIFT_Q512[GROSTL_ROWS] = {1, 3, 5, 7, 0, 2, 4, 6};
static const uint8_t GA_SHIFT_P1024[GROSTL_ROWS] = {0, 1, 2, 3, 4, 5, 6, 11};
static const uint8_t GA_SHIFT_Q1024[GROSTL_ROWS] = {1, 3, 5, 11, 0, 2, 4, 6};

/* GF(2^8) multiply-by-x on 32 bytes in parallel, field 0x11b, branchless. */
static inline __m256i
ga_xtime(__m256i x)
{
    __m256i doubled = _mm256_add_epi8(x, x);
    __m256i hibit = _mm256_cmpgt_epi8(_mm256_setzero_si256(), x);
    return _mm256_xor_si256(doubled,
                            _mm256_and_si256(hibit, _mm256_set1_epi8(0x1b)));
}

/*
 * Transpose P and Q column-major states into the eight row registers.  State
 * byte (row i, col c) is at state[i + GROSTL_ROWS * c]; r[i] low lane holds
 * P's row i in its low `columns` bytes, high lane holds Q's row i.
 */
static inline void
ga_load_rows(__m256i r[GROSTL_ROWS], const uint8_t *p, const uint8_t *q,
             int columns)
{
    for (int i = 0; i < GROSTL_ROWS; i++) {
        uint8_t tmp[32] = {0};
        for (int c = 0; c < columns; c++) {
            tmp[c] = p[i + GROSTL_ROWS * c];
            tmp[16 + c] = q[i + GROSTL_ROWS * c];
        }
        r[i] = _mm256_loadu_si256((const __m256i *)tmp);
    }
}

static inline void
ga_store_rows(uint8_t *p, uint8_t *q, const __m256i r[GROSTL_ROWS], int columns)
{
    for (int i = 0; i < GROSTL_ROWS; i++) {
        uint8_t tmp[32];
        _mm256_storeu_si256((__m256i *)tmp, r[i]);
        for (int c = 0; c < columns; c++) {
            p[i + GROSTL_ROWS * c] = tmp[c];
            q[i + GROSTL_ROWS * c] = tmp[16 + c];
        }
    }
}

/*
 * Lockstep P+Q permutation.  shift_p / shift_q are the per-row ShiftBytes
 * amounts for each permutation.
 */
static inline void
ga_permute(uint8_t *p, uint8_t *q, int columns, int rounds,
           const uint8_t shift_p[GROSTL_ROWS],
           const uint8_t shift_q[GROSTL_ROWS])
{
    __m128i ff = _mm_set1_epi8((char)0xff);
    __m128i zero = _mm_setzero_si128();
    __m128i base_pc;
    __m256i sb[GROSTL_ROWS];
    __m256i r[GROSTL_ROWS];

    /* Per-column AddRoundConstant term (c << 4) in the low `columns` lanes. */
    {
        uint8_t tmp[16] = {0};
        for (int c = 0; c < columns; c++)
            tmp[c] = (uint8_t)(c << 4);
        base_pc = _mm_loadu_si128((const __m128i *)tmp);
    }

    /* Per-row ShiftBytes masks: low lane uses shift_p[i], high lane shift_q[i].
     * output col c <- input col (c + shift) % columns; high bytes 0x80 zero. */
    for (int i = 0; i < GROSTL_ROWS; i++) {
        uint8_t m[32];
        for (int c = 0; c < 16; c++) {
            m[c] = (c < columns) ? (uint8_t)((c + shift_p[i]) % columns) : 0x80;
            m[16 + c] =
                (c < columns) ? (uint8_t)((c + shift_q[i]) % columns) : 0x80;
        }
        sb[i] = _mm256_loadu_si256((const __m256i *)m);
    }

    ga_load_rows(r, p, q, columns);

    for (int round = 0; round < rounds; round++) {
        __m128i rc = _mm_set1_epi8((char)round);
        __m128i p_arc0 =
            _mm_xor_si128(base_pc, rc); /* P row0: (c<<4) ^ round */

        /* AddRoundConstant.  P touches only row 0; Q flips every row (0xff)
         * and folds (c<<4)^round into row 7. */
        r[0] = _mm256_xor_si256(r[0], _mm256_set_m128i(ff, p_arc0));
        for (int i = 1; i < GROSTL_ROWS - 1; i++)
            r[i] = _mm256_xor_si256(r[i], _mm256_set_m128i(ff, zero));
        r[GROSTL_ROWS - 1] =
            _mm256_xor_si256(r[GROSTL_ROWS - 1],
                             _mm256_set_m128i(_mm_xor_si128(ff, p_arc0), zero));

        /* SubBytes (identical in both lanes). */
        for (int i = 0; i < GROSTL_ROWS; i++)
            r[i] = GROSTL_AVX2_SBOX(r[i]);

        /* ShiftBytes (per-lane). */
        for (int i = 0; i < GROSTL_ROWS; i++)
            r[i] = _mm256_shuffle_epi8(r[i], sb[i]);

        /* MixBytes: out_i = 2(r_i ^ r_{i+1}) ^ 3(r_{i+2} ^ r_{i+5})
         *                 ^ 4 r_{i+3} ^ 5(r_{i+4} ^ r_{i+6}) ^ 7 r_{i+7}. */
        __m256i x2[GROSTL_ROWS];
        __m256i x4[GROSTL_ROWS];
        __m256i out[GROSTL_ROWS];
        for (int i = 0; i < GROSTL_ROWS; i++) {
            x2[i] = ga_xtime(r[i]);
            x4[i] = ga_xtime(x2[i]);
        }
        for (int i = 0; i < GROSTL_ROWS; i++) {
            int i1 = (i + 1) & 7;
            int i2 = (i + 2) & 7;
            int i3 = (i + 3) & 7;
            int i4 = (i + 4) & 7;
            int i5 = (i + 5) & 7;
            int i6 = (i + 6) & 7;
            int i7 = (i + 7) & 7;
            __m256i m2 = _mm256_xor_si256(x2[i], x2[i1]);
            __m256i m3 = _mm256_xor_si256(_mm256_xor_si256(r[i2], x2[i2]),
                                          _mm256_xor_si256(r[i5], x2[i5]));
            __m256i m4 = x4[i3];
            __m256i m5 = _mm256_xor_si256(_mm256_xor_si256(r[i4], x4[i4]),
                                          _mm256_xor_si256(r[i6], x4[i6]));
            __m256i m7 =
                _mm256_xor_si256(r[i7], _mm256_xor_si256(x2[i7], x4[i7]));
            out[i] =
                _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(m2, m3),
                                                  _mm256_xor_si256(m4, m5)),
                                 m7);
        }
        for (int i = 0; i < GROSTL_ROWS; i++)
            r[i] = out[i];
    }

    ga_store_rows(p, q, r, columns);
}

/* Combined P+Q entry points for the ops table. */
static void
ga_pq512(uint8_t p[GROSTL_STATE_BYTES_256], uint8_t q[GROSTL_STATE_BYTES_256])
{
    ga_permute(p, q, GROSTL_COLS_256, GROSTL_ROUNDS_256, GA_SHIFT_P512,
               GA_SHIFT_Q512);
}

static void
ga_pq1024(uint8_t p[GROSTL_STATE_BYTES_512], uint8_t q[GROSTL_STATE_BYTES_512])
{
    ga_permute(p, q, GROSTL_COLS_512, GROSTL_ROUNDS_512, GA_SHIFT_P1024,
               GA_SHIFT_Q1024);
}

/*
 * The lone single-permutation entries (output-transform Omega's P, and the
 * separate-p/q path) are NOT provided here: the ops table points them at the
 * efficient 128-bit grostl_aesni_* functions, which avoids a wasted YMM lane
 * and a second transpose.  This header provides only the widened P+Q kernel.
 */

#endif /* ICHOR_GROSTL_AVX2_IMPL_H */
