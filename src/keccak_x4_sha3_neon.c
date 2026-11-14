/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * keccak_x4_sha3_neon.c - 4-way batched Keccak-f[1600] using the ARMv8.2 SHA-3
 * extension (FEAT_SHA3: EOR3, RAX1, BCAX, XAR).
 *
 * This is the two-lanes-per-register packing of the single-sponge SHA-3 kernel
 * (keccak_sha3_neon.c): each 128-bit vector holds two independent sponges (one
 * per 64-bit lane), so the fused SHA-3 instructions run at full vector width
 * instead of the single-sponge kernel's half.  The 4-way batch is two such
 * packed permutations: sponges {0,1} in one pass, {2,3} in the next.
 *
 * The round itself is byte-identical to the single-sponge kernel; only the
 * state load/store (two sponges packed from the st[lane][sponge] layout) and
 * iota (the round constant is broadcast to both lanes) differ.  Selected at
 * runtime on aarch64 hosts that advertise SHA3 (ICHOR_CPU_SHA3); the NIST
 * SHAKE-128/256 KATs in test_keccak_x4 cover it against the serial fallback.
 *
 * Compiled with the +sha3 arch flag per-TU; compiles to an empty object when
 * ICHOR_HAVE_KECCAK_X4_SHA3 is not defined.  Constant-time: branch-free, no
 * data-dependent indexing.
 */

#ifdef ICHOR_HAVE_KECCAK_X4_SHA3

#include "keccak_x4_dispatch.h"

#include <arm_neon.h>

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

/* See keccak_sha3_neon.c: XAR computes ROR(a ^ b, imm) and rho is a left
 * rotate by rot, so imm = (64 - rot) & 63 (rot == 0 gives identity). */
#define XAR_IMM(rot) ((64 - (rot)) & 63)
#define RHOPI(dst, src, dx, rot) B[dst] = vxarq_u64(A[src], D[dx], XAR_IMM(rot))

/*
 * Permute two independent sponges held one per 64-bit lane of A[0..24].
 * Identical to the single-sponge round; iota broadcasts the round constant to
 * both lanes so each sponge gets its own copy.
 */
static void
permute_pair(uint64x2_t A[25])
{
    for (int round = 0; round < 24; round++) {
        uint64x2_t C[5], D[5], B[25];

        /* theta: column parity C[x] = xor of the five lanes in column x. */
        for (int x = 0; x < 5; x++)
            C[x] = veor3q_u64(veor3q_u64(A[x], A[x + 5], A[x + 10]), A[x + 15],
                              A[x + 20]);

        /* theta: D[x] = C[x-1] ^ ROL(C[x+1], 1). */
        for (int x = 0; x < 5; x++)
            D[x] = vrax1q_u64(C[(x + 4) % 5], C[(x + 1) % 5]);

        /* theta D-xor + rho + pi, one XAR per lane (see RHOPI). */
        RHOPI(0, 0, 0, 0);
        RHOPI(10, 1, 1, 1);
        RHOPI(20, 2, 2, 62);
        RHOPI(5, 3, 3, 28);
        RHOPI(15, 4, 4, 27);
        RHOPI(16, 5, 0, 36);
        RHOPI(1, 6, 1, 44);
        RHOPI(11, 7, 2, 6);
        RHOPI(21, 8, 3, 55);
        RHOPI(6, 9, 4, 20);
        RHOPI(7, 10, 0, 3);
        RHOPI(17, 11, 1, 10);
        RHOPI(2, 12, 2, 43);
        RHOPI(12, 13, 3, 25);
        RHOPI(22, 14, 4, 39);
        RHOPI(23, 15, 0, 41);
        RHOPI(8, 16, 1, 45);
        RHOPI(18, 17, 2, 15);
        RHOPI(3, 18, 3, 21);
        RHOPI(13, 19, 4, 8);
        RHOPI(14, 20, 0, 18);
        RHOPI(24, 21, 1, 2);
        RHOPI(9, 22, 2, 61);
        RHOPI(19, 23, 3, 56);
        RHOPI(4, 24, 4, 14);

        /* chi: A[row+x] = B0 ^ (~B1 & B2) = BCAX(B0, B2, B1). */
        for (int y = 0; y < 5; y++) {
            int base = 5 * y;
            for (int x = 0; x < 5; x++)
                A[base + x] = vbcaxq_u64(B[base + x], B[base + (x + 2) % 5],
                                         B[base + (x + 1) % 5]);
        }

        /* iota: both sponges xor RC[round] into lane 0 of their state. */
        A[0] = veorq_u64(A[0], vdupq_n_u64(RC[round]));
    }
}

/*
 * 4-way Keccak-f[1600]: permute four sponges in place.  The state is held as
 * st[lane][sponge]; st[i] is a contiguous four-sponge row, so sponges {0,1}
 * load as the low uint64x2_t and {2,3} as the high one.  Two packed passes.
 */
void
ichor_keccak_f1600_x4_sha3(uint64_t st[25][4])
{
    for (int pair = 0; pair < 2; pair++) {
        uint64x2_t A[25];

        for (int i = 0; i < 25; i++)
            A[i] = vld1q_u64(&st[i][2 * pair]);

        permute_pair(A);

        for (int i = 0; i < 25; i++)
            vst1q_u64(&st[i][2 * pair], A[i]);
    }
}

#undef RHOPI
#undef XAR_IMM

#else /* !ICHOR_HAVE_KECCAK_X4_SHA3 */

/* ISO C forbids an empty translation unit, and -Wpedantic / -Werror reject
 * one; give the guarded-out build a single harmless declaration. */
typedef int ichor_keccak_x4_sha3_translation_unit_not_empty;

#endif /* ICHOR_HAVE_KECCAK_X4_SHA3 */
