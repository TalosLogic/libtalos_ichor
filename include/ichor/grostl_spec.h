/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl_spec.h - Grostl-256 / Grostl-512 constants in spec-canonical form.
 *
 * The fixed constants of the Grostl hash function as defined in the Grostl
 * specification (Groestl.pdf) with the round-3 tweaks (Round3Mods.pdf).
 * Published, like aes_spec.h, so that a consumer building its own Grostl
 * realization - the in-circuit permutation gadget in libtalos_voleith, or
 * the software opener-KDF in libtalos_syndrome - has one clean-room,
 * spec-cited reference instead of transcribing from the specification.
 * ichor's software path (ichor_grostl256 / the compress-node primitives)
 * is the byte-exact oracle a consumer validates its realization against.
 *
 * These constants match, byte for byte, what ichor's own permutations
 * compute (src/grostl_core.h); they are the authoritative statement of the
 * generation rules that code applies.  Constants only: no code, no linkable
 * symbols, no ABI.  Array-valued constants are brace-enclosed initializer
 * macros (..._INIT), materialized by the consumer in one place.
 *
 * STATE BYTE ORDER.  The permutation state is an 8-row by N-column matrix
 * of bytes, stored column-major: the byte at row r, column c lives at
 * linear index (r + 8*c).  Every rule below is written in (row, column)
 * terms; a consumer must fix the same column-major layout to match ichor
 * and the Grostl test vectors.
 *
 * Grostl-256: N = 8 columns (512-bit state), 10 rounds, 64-byte block,
 *             32-byte digest.
 * Grostl-512: N = 16 columns (1024-bit state), 14 rounds, 128-byte block,
 *             64-byte digest.
 *
 * The field is GF(2^8) with the AES reducing polynomial 0x11b, and
 * SubBytes is the AES S-box; see aes_spec.h (ICHOR_AES_SBOX_INIT) and
 * ICHOR_AES_FIELD_REDUCE.  This header does not restate them.
 *
 * Section references are to the Grostl specification (round-3 version).
 */

#ifndef ICHOR_GROSTL_SPEC_H
#define ICHOR_GROSTL_SPEC_H

/* ================================================================
 * State geometry and round counts - Grostl spec SS3.2, SS3.3.
 * ================================================================ */

#define ICHOR_GROSTL_ROWS 8

#define ICHOR_GROSTL256_COLS 8
#define ICHOR_GROSTL256_STATE_BYTES 64
#define ICHOR_GROSTL256_BLOCK_BYTES 64
#define ICHOR_GROSTL256_DIGEST_BYTES 32
#define ICHOR_GROSTL256_ROUNDS 10

#define ICHOR_GROSTL512_COLS 16
#define ICHOR_GROSTL512_STATE_BYTES 128
#define ICHOR_GROSTL512_BLOCK_BYTES 128
#define ICHOR_GROSTL512_DIGEST_BYTES 64
#define ICHOR_GROSTL512_ROUNDS 14

/* ================================================================
 * Round function - Grostl spec SS3.4.
 *
 * Each round of a permutation is, applied in this order:
 *
 *     R = MixBytes o ShiftBytes o SubBytes o AddRoundConstant
 *
 * i.e. AddRoundConstant first, then SubBytes (the AES S-box, byte-wise),
 * then ShiftBytes, then MixBytes.
 *
 * COMPRESSION.  The Grostl compression of chaining value h with message
 * block m is
 *
 *     f(h, m) = P(h ^ m) ^ Q(m) ^ h
 *
 * where P and Q are the two permutations (same round function, different
 * ShiftBytes vectors and round constants, below).
 *
 * OUTPUT TRANSFORM.  omega(x) = trunc_n( P(x) ^ x ), truncated to the
 * trailing n bytes of the state (last 32 for Grostl-256, last 64 for
 * Grostl-512).
 *
 * STANDARD IV.  The initial chaining value is the state whose bytes are
 * the big-endian encoding of the digest length in bits (0x...0100 for
 * Grostl-256, 0x...0200 for Grostl-512).  A fixed-input node hash instead
 * supplies its own public IV in place of this one.
 * ================================================================ */

/* ================================================================
 * AddRoundConstant - Grostl spec SS3.4.1 (round-3 constants).
 *
 * Written over the column-major state; c indexes columns, `round` is the
 * 0-based round number.
 *
 * P: only row 0 is altered.  For each column c,
 *        state(0, c) ^= (c << 4) ^ round.
 *    Rows 1..7 are unchanged.
 *
 * Q: rows 0..6 are complemented, and row 7 carries the counter.  For
 *    each column c,
 *        state(r, c) ^= 0xff                      for r in 0..6,
 *        state(7, c) ^= 0xff ^ (c << 4) ^ round.
 *
 * These are generation rules, not tables (the constant depends on the
 * round and column), so no ..._INIT macro is given; a consumer applies
 * the two rules directly.
 * ================================================================ */

/* ================================================================
 * ShiftBytes - Grostl spec SS3.4.3 (round-3 SS2.1.1 / SS2.2.1).
 *
 * Row r is cyclically rotated left by shift[r] columns.  P and Q use
 * different vectors, and the wide (1024-bit) state uses a different last
 * entry to span its 16 columns.
 * ================================================================ */

#define ICHOR_GROSTL256_SHIFT_P_INIT                                           \
    {                                                                          \
        0, 1, 2, 3, 4, 5, 6, 7                                                 \
    }
#define ICHOR_GROSTL256_SHIFT_Q_INIT                                           \
    {                                                                          \
        1, 3, 5, 7, 0, 2, 4, 6                                                 \
    }
#define ICHOR_GROSTL512_SHIFT_P_INIT                                           \
    {                                                                          \
        0, 1, 2, 3, 4, 5, 6, 11                                                \
    }
#define ICHOR_GROSTL512_SHIFT_Q_INIT                                           \
    {                                                                          \
        1, 3, 5, 11, 0, 2, 4, 6                                                \
    }

/* ================================================================
 * MixBytes - Grostl spec SS3.4.4.
 *
 * Each state column is left-multiplied over GF(2^8) by the 8x8 circulant
 * matrix B = circ(02, 02, 03, 04, 05, 03, 05, 07): row 0 is the vector
 * below, and row i is row 0 rotated right by i.
 *
 * ICHOR_GROSTL_MIXBYTES_ROW_INIT is that first row.  The multipliers are
 * {02, 03, 04, 05, 07}, all over the AES field (ICHOR_AES_FIELD_REDUCE).
 * ================================================================ */

#define ICHOR_GROSTL_MIXBYTES_ROW_INIT                                         \
    {                                                                          \
        0x02, 0x02, 0x03, 0x04, 0x05, 0x03, 0x05, 0x07                         \
    }

#endif /* ICHOR_GROSTL_SPEC_H */
