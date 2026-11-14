/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl_aesni.c - x86 AES-NI + SSSE3 Groestl permutations (full SIMD round).
 *
 * Compiled only when ICHOR_HAVE_AES_NI is defined; the entire file is
 * guarded so a build without AES-NI compiles this TU to an empty object.
 *
 * The whole round runs in vector registers.  The 8x8 (Groestl-256) or 8x16
 * (Groestl-512) state is transposed once into eight "row" registers r0..r7,
 * where r_i holds row i across all columns.  Each round then runs entirely on
 * those registers and the state is transposed back only at the end:
 *
 *   AddRoundConstant: a vector XOR of a round/column-dependent constant.
 *   SubBytes:         _mm_aesenclast_si128 with a zero round key applies the
 *                     AES S-box (and an AES ShiftRows), then _mm_shuffle_epi8
 *                     with SHIFT_ROWS_MASK undoes the ShiftRows, so every byte
 *                     is replaced by S(byte) independent of its row meaning.
 *   ShiftBytes:       a per-row _mm_shuffle_epi8 cyclic byte rotate.
 *   MixBytes:         the circulant GF(2^8) column mix expressed as register
 *                     combinations with a branchless xtime.
 *
 * Constant-time: no secret-dependent branches and no secret-indexed memory
 * access.  xtime is branchless (a sign-mask select of the 0x1b reduction), and
 * every pshufb mask / round constant is a fixed public value.
 */

#ifdef ICHOR_HAVE_AES_NI

#include <tmmintrin.h> /* SSSE3 _mm_shuffle_epi8 (pshufb) */
#include <wmmintrin.h> /* AES-NI _mm_aesenclast_si128 */

#include "grostl_dispatch.h"

/* ================================================================
 * ShiftBytes amounts (columns each row is cyclically shifted left).
 * ================================================================ */

static const uint8_t SHIFT_P512[GROSTL_ROWS] = {0, 1, 2, 3, 4, 5, 6, 7};
static const uint8_t SHIFT_Q512[GROSTL_ROWS] = {1, 3, 5, 7, 0, 2, 4, 6};
static const uint8_t SHIFT_P1024[GROSTL_ROWS] = {0, 1, 2, 3, 4, 5, 6, 11};
static const uint8_t SHIFT_Q1024[GROSTL_ROWS] = {1, 3, 5, 11, 0, 2, 4, 6};

/*
 * Forward AES ShiftRows sigma, used as a pshufb mask to undo the ShiftRows
 * that _mm_aesenclast_si128 inserts: out[j] = result[SHIFT_ROWS_MASK[j]]
 * recovers S(input[j]) for every j, so the trick works on any 16-byte
 * register regardless of what its bytes mean here.
 */
static const uint8_t SHIFT_ROWS_MASK[16] = {
    0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3,
};

/* ================================================================
 * Vector helpers.
 * ================================================================ */

static inline __m128i
grostl_sbox_block_aesni(__m128i x, __m128i shift_rows_mask)
{
    __m128i sub_then_shift = _mm_aesenclast_si128(x, _mm_setzero_si128());
    return _mm_shuffle_epi8(sub_then_shift, shift_rows_mask);
}

/*
 * GF(2^8) multiply-by-x (xtime) on 16 bytes in parallel, field 0x11b.
 *   doubled = x << 1 (per byte, via add)
 *   reduce where bit 7 was set: _mm_cmpgt_epi8(0, x) is 0xff for x < 0 signed,
 *   i.e. exactly where bit 7 is set; AND with 0x1b and XOR in.
 * Branchless and data-independent.
 */
static inline __m128i
gf_xtime_vec(__m128i x)
{
    __m128i doubled = _mm_add_epi8(x, x);
    __m128i hibit = _mm_cmpgt_epi8(_mm_setzero_si128(), x);
    return _mm_xor_si128(doubled, _mm_and_si128(hibit, _mm_set1_epi8(0x1b)));
}

/* ================================================================
 * Transpose between the column-major state and the row registers.
 *
 * State byte (row i, col c) lives at state[i + GROSTL_ROWS * c].  r_i holds
 * the `columns` bytes of row i in its low lanes (the remaining lanes are
 * zeroed on load and ignored on store).
 * ================================================================ */

static inline void
load_rows(__m128i r[GROSTL_ROWS], const uint8_t *state, int columns)
{
    for (int i = 0; i < GROSTL_ROWS; i++) {
        uint8_t tmp[16] = {0};
        for (int c = 0; c < columns; c++)
            tmp[c] = state[i + GROSTL_ROWS * c];
        r[i] = _mm_loadu_si128((const __m128i *)tmp);
    }
}

static inline void
store_rows(uint8_t *state, const __m128i r[GROSTL_ROWS], int columns)
{
    for (int i = 0; i < GROSTL_ROWS; i++) {
        uint8_t tmp[16];
        _mm_storeu_si128((__m128i *)tmp, r[i]);
        for (int c = 0; c < columns; c++)
            state[i + GROSTL_ROWS * c] = tmp[c];
    }
}

/* ================================================================
 * Generic permutation.
 * ================================================================ */

static void
grostl_simd_permute(uint8_t *state, int columns, int rounds,
                    const uint8_t shift[GROSTL_ROWS], int is_q)
{
    __m128i sr_mask = _mm_loadu_si128((const __m128i *)SHIFT_ROWS_MASK);
    __m128i base_pc;
    __m128i sb[GROSTL_ROWS];
    __m128i r[GROSTL_ROWS];

    /* Per-column AddRoundConstant term (c << 4) in the low `columns` lanes. */
    {
        uint8_t tmp[16] = {0};
        for (int c = 0; c < columns; c++)
            tmp[c] = (uint8_t)(c << 4);
        base_pc = _mm_loadu_si128((const __m128i *)tmp);
    }

    /* Per-row ShiftBytes pshufb masks: output col c <- input col (c+shift)%N. */
    for (int i = 0; i < GROSTL_ROWS; i++) {
        uint8_t m[16];
        for (int c = 0; c < columns; c++)
            m[c] = (uint8_t)((c + shift[i]) % columns);
        for (int c = columns; c < 16; c++)
            m[c] = 0x80; /* high bit set zeroes the lane */
        sb[i] = _mm_loadu_si128((const __m128i *)m);
    }

    load_rows(r, state, columns);

    for (int round = 0; round < rounds; round++) {
        __m128i rc = _mm_set1_epi8((char)round);

        /* AddRoundConstant. */
        if (!is_q) {
            r[0] = _mm_xor_si128(r[0], _mm_xor_si128(base_pc, rc));
        } else {
            __m128i ff = _mm_set1_epi8((char)0xff);
            for (int i = 0; i < GROSTL_ROWS - 1; i++)
                r[i] = _mm_xor_si128(r[i], ff);
            r[GROSTL_ROWS - 1] =
                _mm_xor_si128(r[GROSTL_ROWS - 1],
                              _mm_xor_si128(ff, _mm_xor_si128(base_pc, rc)));
        }

        /* SubBytes. */
        for (int i = 0; i < GROSTL_ROWS; i++)
            r[i] = grostl_sbox_block_aesni(r[i], sr_mask);

        /* ShiftBytes. */
        for (int i = 0; i < GROSTL_ROWS; i++)
            r[i] = _mm_shuffle_epi8(r[i], sb[i]);

        /* MixBytes: out_i = 2(r_i ^ r_{i+1}) ^ 3(r_{i+2} ^ r_{i+5})
         *                 ^ 4 r_{i+3} ^ 5(r_{i+4} ^ r_{i+6}) ^ 7 r_{i+7}. */
        __m128i x2[GROSTL_ROWS];
        __m128i x4[GROSTL_ROWS];
        __m128i out[GROSTL_ROWS];
        for (int i = 0; i < GROSTL_ROWS; i++) {
            x2[i] = gf_xtime_vec(r[i]);
            x4[i] = gf_xtime_vec(x2[i]);
        }
        for (int i = 0; i < GROSTL_ROWS; i++) {
            int i1 = (i + 1) & 7;
            int i2 = (i + 2) & 7;
            int i3 = (i + 3) & 7;
            int i4 = (i + 4) & 7;
            int i5 = (i + 5) & 7;
            int i6 = (i + 6) & 7;
            int i7 = (i + 7) & 7;
            __m128i m2 = _mm_xor_si128(x2[i], x2[i1]);
            __m128i m3 = _mm_xor_si128(_mm_xor_si128(r[i2], x2[i2]),
                                       _mm_xor_si128(r[i5], x2[i5]));
            __m128i m4 = x4[i3];
            __m128i m5 = _mm_xor_si128(_mm_xor_si128(r[i4], x4[i4]),
                                       _mm_xor_si128(r[i6], x4[i6]));
            __m128i m7 = _mm_xor_si128(r[i7], _mm_xor_si128(x2[i7], x4[i7]));
            out[i] = _mm_xor_si128(
                _mm_xor_si128(_mm_xor_si128(m2, m3), _mm_xor_si128(m4, m5)),
                m7);
        }
        for (int i = 0; i < GROSTL_ROWS; i++)
            r[i] = out[i];
    }

    store_rows(state, r, columns);
}

/* ================================================================
 * Permutation entry points.
 * ================================================================ */

/*
 * Non-static: the AVX2 / AVX2+GFNI backends reuse these efficient 128-bit
 * single-permutation entries for the lone output-transform (Omega) P, rather
 * than running a wasteful YMM P+Q with a dummy lane.  Declared in
 * grostl_dispatch.h.
 */
void
grostl_aesni_p512(uint8_t *state)
{
    grostl_simd_permute(state, GROSTL_COLS_256, GROSTL_ROUNDS_256, SHIFT_P512,
                        0);
}

void
grostl_aesni_q512(uint8_t *state)
{
    grostl_simd_permute(state, GROSTL_COLS_256, GROSTL_ROUNDS_256, SHIFT_Q512,
                        1);
}

void
grostl_aesni_p1024(uint8_t *state)
{
    grostl_simd_permute(state, GROSTL_COLS_512, GROSTL_ROUNDS_512, SHIFT_P1024,
                        0);
}

void
grostl_aesni_q1024(uint8_t *state)
{
    grostl_simd_permute(state, GROSTL_COLS_512, GROSTL_ROUNDS_512, SHIFT_Q1024,
                        1);
}

/* ================================================================
 * Ops table.
 * ================================================================ */

const ichor_grostl_ops_t ichor_grostl_ops_aesni = {
    .p512 = grostl_aesni_p512,
    .q512 = grostl_aesni_q512,
    .p1024 = grostl_aesni_p1024,
    .q1024 = grostl_aesni_q1024,
    .name = "aesni",
};

#else /* !ICHOR_HAVE_AES_NI */

/* ISO C forbids an empty translation unit, and -Wpedantic / -Werror reject
 * one; give the guarded-out build a single harmless declaration. */
typedef int ichor_grostl_aesni_translation_unit_not_empty;

#endif /* ICHOR_HAVE_AES_NI */
