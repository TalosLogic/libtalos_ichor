/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_spec.h - FIPS-197 AES constants in spec-canonical form.
 *
 * The fixed, standardized constants of the AES / Rijndael cipher as
 * defined in FIPS-197.  They are published here so that a consumer
 * building its own AES realization has one spec-cited reference and need
 * not transcribe them from the standard by hand.  The motivating consumer
 * is the in-circuit AES gadget in libtalos_voleith, which lays the round
 * function down as GF(2) gates rather than calling ichor's software; the
 * software opener-KDF in libtalos_syndrome is the other.
 *
 * The values are representation-independent: they are identical whether
 * the S-box is realized as a lookup table, as GF(2^8) inversion followed
 * by the affine map, or as a bitsliced boolean circuit (the form ichor's
 * own constant-time backend uses).  Only the *materialized* S-box differs
 * between those forms; its definition does not.  ichor's software path
 * (ichor_aes_encrypt) is the byte-exact oracle a consumer validates its
 * own realization against.
 *
 * This header defines constants only: no code, no linkable symbols, no
 * ABI.  Array-valued constants are exposed as brace-enclosed initializer
 * macros (..._INIT) so a consumer materializes them into storage of its
 * own choosing, in exactly one place, with no unused-variable or
 * one-definition-rule hazard from wide inclusion:
 *
 *     static const uint8_t sbox[256] = ICHOR_AES_SBOX_INIT;
 *
 * Only the forward (encryption) direction is provided.  ichor is
 * encrypt-only, and every talos consumer (AES-CTR, AES-DM, Grostl
 * SubBytes) needs the forward S-box alone; the inverse S-box and
 * InvMixColumns are deliberately omitted.
 *
 * Section references are to FIPS-197 (2001).
 */

#ifndef ICHOR_AES_SPEC_H
#define ICHOR_AES_SPEC_H

/* ================================================================
 * Field GF(2^8) - FIPS-197 SS4.2.
 *
 * Reducing polynomial m(x) = x^8 + x^4 + x^3 + x + 1.
 *   ICHOR_AES_FIELD_MODULUS is the full 9-bit value 0x11b.
 *   ICHOR_AES_FIELD_REDUCE  is its low 8 bits 0x1b, the constant XORed
 *   into (b << 1) by xtime() when b's high bit is set.
 *
 * Grostl uses this same field; see grostl_spec.h.
 * ================================================================ */

#define ICHOR_AES_FIELD_MODULUS 0x11b
#define ICHOR_AES_FIELD_REDUCE 0x1b

/* ================================================================
 * State and key geometry - FIPS-197 SS5, Fig. 4.
 *
 * Nb is fixed at 4 (128-bit block).  Nk / Nr vary with key size.
 * ================================================================ */

#define ICHOR_AES_BLOCK_BYTES 16
#define ICHOR_AES_NB 4 /* state columns (32-bit words) */

#define ICHOR_AES_NK_128 4 /* key words */
#define ICHOR_AES_NK_192 6
#define ICHOR_AES_NK_256 8

#define ICHOR_AES_NR_128 10 /* rounds */
#define ICHOR_AES_NR_192 12
#define ICHOR_AES_NR_256 14

/* ================================================================
 * SubBytes S-box - FIPS-197 SS5.1.1.
 *
 * S(x) = affine(inv(x)), where inv(x) is the multiplicative inverse of x
 * in GF(2^8) with inv(0) defined as 0, and affine is the fixed GF(2)
 * affine map below.  The 256-byte table is one materialization of that
 * definition, indexed by the input byte:
 *
 *     static const uint8_t sbox[256] = ICHOR_AES_SBOX_INIT;
 *     y = sbox[x];
 *
 * A gate-level consumer that computes inv(x) in the field and applies the
 * affine map need not use the table at all; it is provided for table-based
 * consumers and as a validation vector (S(0x00) = 0x63, S(0x01) = 0x7c).
 * ================================================================ */

/* clang-format off */
#define ICHOR_AES_SBOX_INIT {                                            \
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,                      \
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,                      \
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,                      \
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,                      \
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,                      \
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,                      \
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,                      \
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,                      \
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,                      \
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,                      \
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,                      \
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,                      \
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,                      \
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,                      \
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,                      \
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,                      \
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,                      \
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,                      \
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,                      \
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,                      \
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,                      \
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,                      \
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,                      \
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,                      \
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,                      \
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,                      \
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,                      \
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,                      \
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,                      \
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,                      \
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,                      \
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
/* clang-format on */

/* ================================================================
 * S-box affine map - FIPS-197 SS5.1.1, eq. (5.1).
 *
 * Applied to the multiplicative inverse b = inv(x), each output bit is
 *
 *   b'_i = b_i ^ b_{i+4} ^ b_{i+5} ^ b_{i+6} ^ b_{i+7} ^ c_i   (i mod 8)
 *
 * with the constant vector c = 0x63.  Equivalently, output byte
 * y = (M . b) ^ c over GF(2), where M is the 8x8 circulant whose first
 * row is 0xf1 and whose row i is the first row rotated left by i.
 *
 * ICHOR_AES_SBOX_AFFINE_MATRIX_INIT gives the eight row masks: row i is
 * indexed by output bit i, and bit j of the mask (bit 0 = LSB) is set iff
 * input bit j contributes to output bit i.  ICHOR_AES_SBOX_AFFINE_CONST
 * is c.
 * ================================================================ */

#define ICHOR_AES_SBOX_AFFINE_CONST 0x63
#define ICHOR_AES_SBOX_AFFINE_MATRIX_INIT                                      \
    {                                                                          \
        0xf1, 0xe3, 0xc7, 0x8f, 0x1f, 0x3e, 0x7c, 0xf8                         \
    }

/* ================================================================
 * Round constants Rcon - FIPS-197 SS5.2.
 *
 * Rcon[i] = x^(i-1) in GF(2^8), used in the key expansion.  The array
 * below is 1-indexed material as Rcon[1..10]; index it by (round - 1).
 * Ten entries cover AES-128 (the deepest schedule); AES-192 uses the
 * first eight, AES-256 the first seven.
 * ================================================================ */

#define ICHOR_AES_RCON_INIT                                                    \
    {                                                                          \
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36             \
    }

/* ================================================================
 * ShiftRows - FIPS-197 SS5.1.2.
 *
 * Row r of the state is cyclically shifted left by r bytes; the offsets
 * are {0, 1, 2, 3} for the four rows of the 128-bit state.
 * ================================================================ */

#define ICHOR_AES_SHIFTROWS_OFFSETS_INIT                                       \
    {                                                                          \
        0, 1, 2, 3                                                             \
    }

/* ================================================================
 * MixColumns - FIPS-197 SS5.1.3.
 *
 * Each state column is multiplied over GF(2^8) by the fixed polynomial
 * a(x) = {03}x^3 + {01}x^2 + {01}x + {02}, i.e. left-multiplied by the
 * 4x4 circulant matrix whose first row is {02, 03, 01, 01}:
 *
 *     02 03 01 01
 *     01 02 03 01
 *     01 01 02 03
 *     03 01 01 02
 *
 * ICHOR_AES_MIXCOLUMNS_ROW_INIT is that first row; row i is it rotated
 * right by i.  (The InvMixColumns matrix {0e,0b,0d,09} is not provided:
 * ichor is encrypt-only.)
 * ================================================================ */

#define ICHOR_AES_MIXCOLUMNS_ROW_INIT                                          \
    {                                                                          \
        0x02, 0x03, 0x01, 0x01                                                 \
    }

#endif /* ICHOR_AES_SPEC_H */
