/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl_armv8.c - ARMv8 Crypto Extension + NEON Groestl permutations
 * (full SIMD round).
 *
 * Compiled only when ICHOR_HAVE_ARMV8_AES is defined; the entire file is
 * guarded so a build without ARMv8 Crypto Extension compiles this TU to an
 * empty object.
 *
 * The whole round runs in vector registers, mirroring the x86 grostl_aesni.c.
 * The 8x8 (Groestl-256) or 8x16 (Groestl-512) state is transposed once into
 * eight "row" registers r0..r7, where r_i holds row i across all columns, and
 * transposed back only at the end:
 *
 *   AddRoundConstant: a vector XOR of a round/column-dependent constant.
 *   SubBytes:         vaeseq_u8 with a zero key applies the AES S-box (and an
 *                     AES ShiftRows), then vqtbl1q_u8 with SHIFT_ROWS_MASK
 *                     undoes the ShiftRows, so every byte becomes S(byte)
 *                     independent of its row meaning.
 *   ShiftBytes:       a per-row vqtbl1q_u8 cyclic byte rotate.
 *   MixBytes:         the circulant GF(2^8) column mix expressed as register
 *                     combinations with a branchless xtime.
 *
 * Constant-time: no secret-dependent branches and no secret-indexed memory
 * access.  xtime is branchless (a sign-mask select of the 0x1b reduction), and
 * every table-lookup mask / round constant is a fixed public value.
 */

#ifdef ICHOR_HAVE_ARMV8_AES

#include <arm_neon.h>

#include "grostl_dispatch.h"

/* ================================================================
 * ShiftBytes amounts (columns each row is cyclically shifted left).
 * ================================================================ */

static const uint8_t SHIFT_P512[GROSTL_ROWS] = {0, 1, 2, 3, 4, 5, 6, 7};
static const uint8_t SHIFT_Q512[GROSTL_ROWS] = {1, 3, 5, 7, 0, 2, 4, 6};
static const uint8_t SHIFT_P1024[GROSTL_ROWS] = {0, 1, 2, 3, 4, 5, 6, 11};
static const uint8_t SHIFT_Q1024[GROSTL_ROWS] = {1, 3, 5, 11, 0, 2, 4, 6};

/*
 * Forward AES ShiftRows sigma, used as a vqtbl1q_u8 mask to undo the ShiftRows
 * that vaeseq_u8 inserts: out[j] = result[SHIFT_ROWS_MASK[j]] recovers
 * S(input[j]) for every j, so the trick works on any 16-byte register
 * regardless of what its bytes mean here.
 */
static const uint8_t SHIFT_ROWS_MASK[16] = {
    0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3,
};

/* ================================================================
 * Vector helpers.
 * ================================================================ */

static inline uint8x16_t
grostl_sbox_block_armv8(uint8x16_t x, uint8x16_t shift_rows_mask)
{
    uint8x16_t sub_then_shift = vaeseq_u8(x, vdupq_n_u8(0));
    return vqtbl1q_u8(sub_then_shift, shift_rows_mask);
}

/*
 * GF(2^8) multiply-by-x (xtime) on 16 bytes in parallel, field 0x11b.
 *   doubled = x << 1 (per byte)
 *   reduce where bit 7 was set: an arithmetic right shift by 7 broadcasts the
 *   high bit of each byte to 0xff (set) or 0x00 (clear); AND with 0x1b and
 *   XOR in.  Branchless and data-independent.
 */
static inline uint8x16_t
gf_xtime_vec(uint8x16_t x)
{
    uint8x16_t sign =
        vreinterpretq_u8_s8(vshrq_n_s8(vreinterpretq_s8_u8(x), 7));
    return veorq_u8(vshlq_n_u8(x, 1), vandq_u8(sign, vdupq_n_u8(0x1b)));
}

/* ================================================================
 * Transpose between the column-major state and the row registers.
 *
 * State byte (row i, col c) lives at state[i + GROSTL_ROWS * c].  r_i holds
 * the `columns` bytes of row i in its low lanes (the remaining lanes are
 * zeroed on load and ignored on store).
 * ================================================================ */

static inline void
load_rows(uint8x16_t r[GROSTL_ROWS], const uint8_t *state, int columns)
{
    for (int i = 0; i < GROSTL_ROWS; i++) {
        uint8_t tmp[16] = {0};
        for (int c = 0; c < columns; c++)
            tmp[c] = state[i + GROSTL_ROWS * c];
        r[i] = vld1q_u8(tmp);
    }
}

static inline void
store_rows(uint8_t *state, const uint8x16_t r[GROSTL_ROWS], int columns)
{
    for (int i = 0; i < GROSTL_ROWS; i++) {
        uint8_t tmp[16];
        vst1q_u8(tmp, r[i]);
        for (int c = 0; c < columns; c++)
            state[i + GROSTL_ROWS * c] = tmp[c];
    }
}

/* ================================================================
 * Generic permutation.
 * ================================================================ */

static void
grostl_neon_permute(uint8_t *state, int columns, int rounds,
                    const uint8_t shift[GROSTL_ROWS], int is_q)
{
    uint8x16_t sr_mask = vld1q_u8(SHIFT_ROWS_MASK);
    uint8x16_t base_pc;
    uint8x16_t sb[GROSTL_ROWS];
    uint8x16_t r[GROSTL_ROWS];

    /* Per-column AddRoundConstant term (c << 4) in the low `columns` lanes. */
    {
        uint8_t tmp[16] = {0};
        for (int c = 0; c < columns; c++)
            tmp[c] = (uint8_t)(c << 4);
        base_pc = vld1q_u8(tmp);
    }

    /* Per-row ShiftBytes masks: output col c <- input col (c+shift)%N. */
    for (int i = 0; i < GROSTL_ROWS; i++) {
        uint8_t m[16];
        for (int c = 0; c < columns; c++)
            m[c] = (uint8_t)((c + shift[i]) % columns);
        for (int c = columns; c < 16; c++)
            m[c] = 0x80; /* high bit set zeroes the lane */
        sb[i] = vld1q_u8(m);
    }

    load_rows(r, state, columns);

    for (int round = 0; round < rounds; round++) {
        uint8x16_t rc = vdupq_n_u8((uint8_t)round);

        /* AddRoundConstant. */
        if (!is_q) {
            r[0] = veorq_u8(r[0], veorq_u8(base_pc, rc));
        } else {
            uint8x16_t ff = vdupq_n_u8(0xff);
            for (int i = 0; i < GROSTL_ROWS - 1; i++)
                r[i] = veorq_u8(r[i], ff);
            r[GROSTL_ROWS - 1] = veorq_u8(r[GROSTL_ROWS - 1],
                                          veorq_u8(ff, veorq_u8(base_pc, rc)));
        }

        /* SubBytes. */
        for (int i = 0; i < GROSTL_ROWS; i++)
            r[i] = grostl_sbox_block_armv8(r[i], sr_mask);

        /* ShiftBytes. */
        for (int i = 0; i < GROSTL_ROWS; i++)
            r[i] = vqtbl1q_u8(r[i], sb[i]);

        /* MixBytes: out_i = 2(r_i ^ r_{i+1}) ^ 3(r_{i+2} ^ r_{i+5})
         *                 ^ 4 r_{i+3} ^ 5(r_{i+4} ^ r_{i+6}) ^ 7 r_{i+7}. */
        uint8x16_t x2[GROSTL_ROWS];
        uint8x16_t x4[GROSTL_ROWS];
        uint8x16_t out[GROSTL_ROWS];
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
            uint8x16_t m2 = veorq_u8(x2[i], x2[i1]);
            uint8x16_t m3 =
                veorq_u8(veorq_u8(r[i2], x2[i2]), veorq_u8(r[i5], x2[i5]));
            uint8x16_t m4 = x4[i3];
            uint8x16_t m5 =
                veorq_u8(veorq_u8(r[i4], x4[i4]), veorq_u8(r[i6], x4[i6]));
            uint8x16_t m7 = veorq_u8(r[i7], veorq_u8(x2[i7], x4[i7]));
            out[i] = veorq_u8(veorq_u8(veorq_u8(m2, m3), veorq_u8(m4, m5)), m7);
        }
        for (int i = 0; i < GROSTL_ROWS; i++)
            r[i] = out[i];
    }

    store_rows(state, r, columns);
}

/* ================================================================
 * Permutation entry points.
 * ================================================================ */

static void
grostl_armv8_p512(uint8_t *state)
{
    grostl_neon_permute(state, GROSTL_COLS_256, GROSTL_ROUNDS_256, SHIFT_P512,
                        0);
}

static void
grostl_armv8_q512(uint8_t *state)
{
    grostl_neon_permute(state, GROSTL_COLS_256, GROSTL_ROUNDS_256, SHIFT_Q512,
                        1);
}

static void
grostl_armv8_p1024(uint8_t *state)
{
    grostl_neon_permute(state, GROSTL_COLS_512, GROSTL_ROUNDS_512, SHIFT_P1024,
                        0);
}

static void
grostl_armv8_q1024(uint8_t *state)
{
    grostl_neon_permute(state, GROSTL_COLS_512, GROSTL_ROUNDS_512, SHIFT_Q1024,
                        1);
}

/* ================================================================
 * Ops table.
 * ================================================================ */

const ichor_grostl_ops_t ichor_grostl_ops_armv8 = {
    .p512 = grostl_armv8_p512,
    .q512 = grostl_armv8_q512,
    .p1024 = grostl_armv8_p1024,
    .q1024 = grostl_armv8_q1024,
    .name = "armv8",
};

#else /* !ICHOR_HAVE_ARMV8_AES */

/* ISO C forbids an empty translation unit, and -Wpedantic / -Werror reject
 * one; give the guarded-out build a single harmless declaration. */
typedef int ichor_grostl_armv8_translation_unit_not_empty;

#endif /* ICHOR_HAVE_ARMV8_AES */
