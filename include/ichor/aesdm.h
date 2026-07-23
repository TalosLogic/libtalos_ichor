/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aesdm.h - Davies-Meyer single-block-length compression over AES-128.
 *
 * Implements one iteration of the Davies-Meyer compression `f` only.
 * As with hirose.h, the framing built on top of `f` - fixed IV, the
 * message-padding rule, the multi-block absorb, and any
 * domain-separation constants - is deliberately left to the consumer.
 * Two consumers exist in the talos family: the in-circuit Merkle /
 * opener-KDF gadgets in libtalos_voleith, and the software opener-KDF in
 * libtalos_syndrome (Argus).  Keeping the bare primitive here lets one
 * byte-exact reference serve both sides of the circuit/software boundary.
 *
 * In Davies-Meyer the message block is fed into the cipher *key* and the
 * chaining value is the plaintext, so the output digest width equals the
 * AES block size (128 bits).  At λ=128 that is exactly the DEM-key width
 * the opener KDF needs; the 256-bit case uses Grøstl-256 (grostl.h)
 * instead, since AES-DM cannot reach a 256-bit output.  (The Hirose
 * double-block-length construction in hirose.h is no longer used by the
 * talos consumers.)
 *
 * Note on the related-key caveat: because the message enters the key
 * schedule, a chosen-related-key adversary with an output oracle is the
 * theoretical concern for Davies-Meyer over AES.  In the talos opener-KDF
 * role the message is a random, secret, high-entropy value and the output
 * is never revealed, so no such oracle exists; the construction relies
 * only on PRF / one-wayness on a random input, which this provides.
 */

#ifndef ICHOR_AESDM_H
#define ICHOR_AESDM_H

#include <stdint.h>
#include <stddef.h>

/*
 * ichor_aesdm_iteration - one Davies-Meyer compression iteration `f`.
 *
 * Given a 128-bit chaining value H_in and a 128-bit message block M,
 * computes:
 *
 *     K       = M                        (128-bit AES-128 key)
 *     H_out   = AES_K(H_in) XOR H_in
 *
 * H_in, M:  16-byte input blocks.
 * H_out:    16-byte output block (may alias either input).
 *
 * Constant-time with respect to both inputs (provided the AES backend is
 * constant-time: AES-NI, ARMv8 Crypto, or bitsliced).
 */
void ichor_aesdm_iteration(const uint8_t H_in[16], const uint8_t M[16],
                           uint8_t H_out[16]);

/*
 * Incremental multi-block AES-DM hash.
 *
 * The framing around the bare `f` iteration - fixed IV, block buffering,
 * padding - packaged so the two talos consumers (the software opener-KDF
 * in libtalos_syndrome and the witness builder in libtalos_voleith) share
 * one byte-exact reference instead of each re-deriving the block loop.
 * There is no output transformation: the 128-bit digest is simply the
 * final chaining value, so this covers the λ=128 opener-KDF extractor.
 *
 * Message blocks key successive Davies-Meyer iterations under the chaining
 * value seeded at init, exactly as ichor_aesdm_iteration does per block.
 * The absorbed data (e.g. the support of a fixed-weight error) is secret;
 * the block count and padding are fixed by the public message length, so
 * the sequence is constant-time with respect to the data.
 */
typedef struct ichor_aesdm_ctx {
    uint8_t h[16];   /* chaining value */
    uint8_t buf[16]; /* partial-block buffer */
    size_t buf_len;  /* bytes currently held in buf */
} ichor_aesdm_ctx_t;

/*
 * Initialize with the 16-byte chaining IV.  The IV is public and, for the
 * opener-KDF role, carries domain separation.
 */
void ichor_aesdm_init_iv(ichor_aesdm_ctx_t *ctx, const uint8_t iv[16]);

/*
 * Absorb len bytes.  May be called repeatedly; equivalent to absorbing
 * the concatenation.  data may be NULL when len == 0.
 */
void ichor_aesdm_absorb(ichor_aesdm_ctx_t *ctx, const uint8_t *data,
                        size_t len);

/*
 * Finalize with zero padding only (no 0x80, no length): the final partial
 * block is zero-filled and run through one more iteration, and the 16-byte
 * chaining value is written to out.  An exact-block-multiple message adds
 * no extra block.  Sound only for a fixed input length under a given IV /
 * domain, exactly as ichor_grostl_finalize_fixed; the counterpart MD
 * padding is not provided for AES-DM because no talos consumer needs it.
 * (An empty message returns the IV unchanged.)
 */
void ichor_aesdm_finalize_fixed(ichor_aesdm_ctx_t *ctx, uint8_t out[16]);

/*
 * Securely zero the context.  Call after the last use of a context that
 * absorbed secret material.
 */
void ichor_aesdm_clear(ichor_aesdm_ctx_t *ctx);

#endif /* ICHOR_AESDM_H */
