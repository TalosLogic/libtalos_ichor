/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl.h - Grøstl-256 and Grøstl-512 hash functions.
 *
 * Clean-room implementation from the Grøstl specification (Groestl.pdf,
 * with the round-3 modifications in Round3Mods.pdf).  No code is taken
 * from the reference implementation.
 *
 * Grøstl-256:
 *   internal state    : 8 x 8 byte matrix (512 bits)
 *   output            : 32 bytes (256 bits)
 *   block size        : 64 bytes
 *   rounds            : 10 per permutation
 *
 * Grøstl-512:
 *   internal state    : 8 x 16 byte matrix (1024 bits)
 *   output            : 64 bytes (512 bits)
 *   block size        : 128 bytes
 *   rounds            : 14 per permutation
 *
 * Constant-time by construction: the SubBytes step uses the bitsliced
 * AES S-box exposed by aes_ct64.h (no table lookups indexed by secret
 * state); MixBytes is straight-line GF(2^8) arithmetic with no tables;
 * ShiftBytes, AddRoundConstant, and padding are data-independent
 * permutations and constants.
 */

#ifndef ICHOR_GROSTL_H
#define ICHOR_GROSTL_H

#include <stdint.h>
#include <stddef.h>

/*
 * Incremental hashing context.  Holds the chaining state, an
 * accumulating message-block buffer, and metadata identifying which
 * Grøstl variant is in use.
 *
 * Fields beyond the public read of state_bytes / output_bytes /
 * rounds / columns are implementation detail; do not depend on the
 * layout in caller code.
 *
 * Single context type for both variants, matching the SHAKE
 * convention in hash.h.  Discriminated by state_bytes (64 for
 * Grøstl-256, 128 for Grøstl-512); set by the corresponding init
 * function and never changed thereafter.
 */
typedef struct ichor_grostl_ctx {
    uint8_t state[128];   /* chaining variable (column-major) */
    uint8_t buf[128];     /* accumulating message-block buffer */
    uint64_t block_count; /* full message blocks compressed so far */
    size_t state_bytes;   /* 64 (Grøstl-256) or 128 (Grøstl-512) */
    size_t output_bytes;  /* 32 (Grøstl-256) or 64 (Grøstl-512) */
    size_t buf_len;       /* bytes currently held in buf */
    int rounds;           /* 10 (Grøstl-256) or 14 (Grøstl-512) */
    int columns;          /* 8 (Grøstl-256) or 16 (Grøstl-512) */
} ichor_grostl_ctx_t;

/*
 * One-shot Grøstl-256: hash msg_len bytes of input into a 32-byte
 * digest.  msg may be NULL when msg_len == 0.  Equivalent to init +
 * absorb + finalize, with secure cleanup on return.
 */
void ichor_grostl256(uint8_t out[32], const uint8_t *msg, size_t msg_len);

/*
 * One-shot Grøstl-512: hash msg_len bytes of input into a 64-byte
 * digest.  msg may be NULL when msg_len == 0.
 */
void ichor_grostl512(uint8_t out[64], const uint8_t *msg, size_t msg_len);

/*
 * Initialize an incremental Grøstl-256 context.  Sets the chaining
 * value to the standard 256-bit IV (the 512-bit big-endian
 * representation of the output bit length, 256).
 */
void ichor_grostl256_init(ichor_grostl_ctx_t *ctx);

/*
 * Initialize an incremental Grøstl-512 context.  Sets the chaining
 * value to the standard 512-bit IV (the 1024-bit big-endian
 * representation of the output bit length, 512).
 */
void ichor_grostl512_init(ichor_grostl_ctx_t *ctx);

/*
 * Initialize an incremental context with a caller-supplied chaining
 * value in place of the standard length-encoding IV.  Geometry (state
 * width, round count, digest width) is set as for the matching
 * ichor_grostl{256,512}_init; only the initial chaining value differs.
 *
 * Intended for fixed-input, fixed-IV, single-purpose hashes where the IV
 * carries domain separation - paired with ichor_grostl_finalize_fixed
 * below.  iv is 64 bytes for the 256-bit context, 128 bytes for the
 * 512-bit context.
 */
void ichor_grostl256_init_iv(ichor_grostl_ctx_t *ctx, const uint8_t iv[64]);
void ichor_grostl512_init_iv(ichor_grostl_ctx_t *ctx, const uint8_t iv[128]);

/*
 * Absorb len bytes of message data into the context.  May be called
 * any number of times before finalize; equivalent to absorbing a
 * single concatenation of all absorbed buffers.  data may be NULL
 * when len == 0.
 */
void ichor_grostl_absorb(ichor_grostl_ctx_t *ctx, const uint8_t *data,
                         size_t len);

/*
 * Finalize the hash.  Applies Grøstl padding, runs the final
 * compression, runs the output transformation, and writes
 * ctx->output_bytes bytes to out.  The context is left in a
 * terminated state and must not be absorbed into again; reset by
 * calling ichor_grostl_clear followed by another init.
 */
void ichor_grostl_finalize(ichor_grostl_ctx_t *ctx, uint8_t *out);

/*
 * Finalize with zero padding only: no 0x80 marker and no length field.
 * The final partial block is zero-filled to the block boundary, the last
 * compression is run, then the output transformation omega, writing
 * ctx->output_bytes bytes to out.  A message that is an exact multiple of
 * the block size adds no extra block, and a partial tail is absorbed in
 * place - so the block (and thus in-circuit) count is the minimum the
 * message requires, unlike ichor_grostl_finalize whose 0x80 + 8-byte
 * length can force one more compression.
 *
 * Sound only for a FIXED input length under a given IV / domain: with the
 * length neither encoded nor delimited, zero padding is injective only
 * across inputs of one fixed length.  The caller must guarantee that
 * (which a fixed-format packed message satisfies).  Length-extension and
 * cross-length collisions do not apply to such a fixed-length, fixed-IV,
 * single-purpose hash.  Pair with ichor_grostl{256,512}_init_iv.
 *
 * As with ichor_grostl_finalize, the context is left terminated and must
 * be re-initialized before reuse.  (An empty message - nothing absorbed -
 * hashes a single zero block, but the intended use never passes one.)
 */
void ichor_grostl_finalize_fixed(ichor_grostl_ctx_t *ctx, uint8_t *out);

/*
 * Securely zero all data in the context.  Call after the last use of
 * a context that has absorbed secret material.  Safe to call at any
 * point in the absorb / finalize sequence.
 */
void ichor_grostl_clear(ichor_grostl_ctx_t *ctx);

/*
 * Fixed-input single-compression node hashes.
 *
 * Compute H = Omega(f(iv, block)): one Grøstl compression of a single
 * full-width block under a caller-supplied chaining value iv, followed by
 * the Grøstl output transformation Omega, truncated to the node width.
 * No Merkle-Damgård padding is applied: the input is exactly one block of
 * fixed width, so the padding (0x80 + length) does no security work and is
 * omitted, which keeps the cost at a single compression.  Domain separation
 * between leaf and internal-node hashing is the caller's responsibility and
 * is carried entirely by iv (use distinct iv values).
 *
 * iv is NOT the standard Grøstl init IV; it is the fixed public chaining
 * value chosen by the node-hash construction.  These functions back the
 * grostl256_fixed / grostl512_fixed node-hash circuits and exist so the
 * software oracle and the in-circuit builder share one definition.
 *
 * grostl256_compress_node: 64-byte iv, 64-byte block, 32-byte output.
 * grostl512_compress_node: 128-byte iv, 128-byte block, 64-byte output.
 *
 * Return 0 on success, negative on a NULL argument.  The full-hash API
 * (ichor_grostl256 etc.) is unaffected.
 */
int ichor_grostl256_compress_node(const uint8_t iv[64], const uint8_t block[64],
                                  uint8_t out[32]);
int ichor_grostl512_compress_node(const uint8_t iv[128],
                                  const uint8_t block[128], uint8_t out[64]);

/*
 * Return a short string naming the active SubBytes backend: "aesni",
 * "armv8", or "soft".  Triggers dispatch initialization if not yet done.
 */
const char *ichor_grostl_backend_name(void);

/*
 * Report whether the active Grøstl backend is the best this CPU can run or a
 * software fallback (host has hardware AES but the accelerated backend was not
 * compiled in).  Declared in <ichor/backend.h>; see that header for the
 * ichor_backend_health_t values and the aggregate ichor_backend_report().
 */

/*
 * Reset the dispatch table to uninitialized, forcing reselection on the
 * next Grøstl call.  Use only in tests, in combination with
 * ichor_cpu_features_override(), to cycle through backends.
 *
 * Test-only: compiled in only under ICHOR_ENABLE_FORCE_BACKEND (see
 * CMakeLists.txt) and absent from a release / vendored build.
 */
#ifdef ICHOR_ENABLE_FORCE_BACKEND
void ichor_grostl_dispatch_reset(void);
#endif

#endif /* ICHOR_GROSTL_H */
