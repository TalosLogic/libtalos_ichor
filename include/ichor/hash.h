/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * hash.h - SHA-3-256, SHAKE-128, SHAKE-256 (FIPS 202)
 *
 * Implements the Keccak-based hash functions from FIPS 202:
 *   - SHA3-256:  fixed 32-byte digest
 *   - SHAKE-128: extendable-output function, 128-bit security
 *   - SHAKE-256: extendable-output function, 256-bit security
 *
 * All functions use the Keccak-f[1600] permutation (24 rounds) with the
 * sponge construction from FIPS 202.
 *
 * Incremental API (init/absorb/squeeze) is provided for SHAKE, which is
 * needed for streaming transcript / KDF construction. SHA3-256 has both
 * incremental and one-shot interfaces.
 */

#ifndef ICHOR_HASH_H
#define ICHOR_HASH_H

#include <stdint.h>
#include <stddef.h>

/*
 * Error codes returned by the absorb interface.  0 on success, negative on
 * failure, matching the library-wide convention.
 */
#define ICHOR_HASH_ERR_FINALIZED                                               \
    (-1) /* absorb attempted after squeeze/finalize */

/* Keccak sponge context - shared by all SHA-3/SHAKE variants */
typedef struct {
    uint64_t state[25]; /* 1600-bit Keccak state as 25 lanes */
    size_t
        rate; /* rate in bytes (168 for SHAKE-128, 136 for SHAKE-256/SHA3-256) */
    size_t absorbed; /* bytes absorbed in current block (0..rate-1) */
    uint8_t
        suffix; /* domain separation + first pad bit (0x06 for SHA-3, 0x1f for SHAKE) */
    int finalized; /* nonzero after finalize/squeeze has been called */
} ichor_hash_ctx_t;

/*
 * SHA3-256: one-shot interface
 *
 * out:  32-byte output buffer for the digest
 * data: input data
 * len:  input length in bytes
 */
void ichor_sha3_256(uint8_t out[32], const uint8_t *data, size_t len);

/*
 * SHA3-256: incremental interface
 */
void ichor_sha3_256_init(ichor_hash_ctx_t *ctx);
/* Returns 0 on success, ICHOR_HASH_ERR_FINALIZED if called after finalize. */
int ichor_sha3_256_absorb(ichor_hash_ctx_t *ctx, const uint8_t *data,
                          size_t len);
void ichor_sha3_256_finalize(ichor_hash_ctx_t *ctx, uint8_t out[32]);

/*
 * SHAKE-128: incremental interface
 *
 * Call init, then absorb (one or more times), then squeeze (one or more times).
 * Once squeeze is called, no further absorb calls are allowed: a post-squeeze
 * absorb returns ICHOR_HASH_ERR_FINALIZED and leaves the state untouched
 * rather than silently corrupting the output.
 */
void ichor_shake128_init(ichor_hash_ctx_t *ctx);
/* Returns 0 on success, ICHOR_HASH_ERR_FINALIZED if called after squeeze. */
int ichor_shake128_absorb(ichor_hash_ctx_t *ctx, const uint8_t *data,
                          size_t len);
void ichor_shake128_squeeze(ichor_hash_ctx_t *ctx, uint8_t *out, size_t len);

/*
 * Absorb a 32-bit value into a SHAKE-128 context as four little-endian
 * bytes.  Convenience wrapper used by canonical serialization paths
 * (proof header fingerprints, etc.) where every length / operand /
 * counter is encoded in u32_le and absorbed individually.
 */
int ichor_shake128_absorb_u32_le(ichor_hash_ctx_t *ctx, uint32_t v);

/*
 * Absorb a 64-bit value into a SHAKE-128 context as eight little-endian
 * bytes.  Same canonical-serialization use case as the u32_le helper
 * for fields that need the wider range (lengths, counts, depths).
 */
int ichor_shake128_absorb_u64_le(ichor_hash_ctx_t *ctx, uint64_t v);

/*
 * SHAKE-256: incremental interface
 *
 * Same usage pattern as SHAKE-128.
 */
void ichor_shake256_init(ichor_hash_ctx_t *ctx);
/* Returns 0 on success, ICHOR_HASH_ERR_FINALIZED if called after squeeze. */
int ichor_shake256_absorb(ichor_hash_ctx_t *ctx, const uint8_t *data,
                          size_t len);
void ichor_shake256_squeeze(ichor_hash_ctx_t *ctx, uint8_t *out, size_t len);

/*
 * SHAKE-256 little-endian integer absorbers - same shape as the
 * SHAKE-128 helpers above.  Return 0 on success, ICHOR_HASH_ERR_FINALIZED
 * if called after squeeze.
 */
int ichor_shake256_absorb_u32_le(ichor_hash_ctx_t *ctx, uint32_t v);
int ichor_shake256_absorb_u64_le(ichor_hash_ctx_t *ctx, uint64_t v);

/*
 * Securely zero all state in ctx.
 *
 * Call after the final squeeze when the context has absorbed secret data
 * (e.g. VOLE keys, commitment seeds) so that the sponge state is not
 * left in memory.
 */
void ichor_hash_ctx_clear(ichor_hash_ctx_t *ctx);

/*
 * Human-readable name of the single-sponge Keccak-f[1600] permutation backend
 * selected for the running CPU (for tests / benchmarks / health reporting):
 * the ARMv8.2 SHA-3 kernel on an aarch64 host that has it, else the portable
 * scalar permutation.  Resolves on first use.
 */
const char *ichor_keccak_f1600_backend_name(void);

/*
 * ---- 4-way batched SHAKE (AVX2, scalar fallback) ----
 *
 * Runs four INDEPENDENT SHAKE sponges in lockstep over one Keccak-f[1600]x4
 * permutation, the standard N-way batched Keccak layout (one sponge per 64-bit
 * lane of a 256-bit register).  This is a throughput primitive for callers that
 * have four independent same-length hashes to compute at once; it is additive
 * and does not change the single-sponge API above.
 *
 * One-shot only (no incremental x4 context): the four inputs share one length
 * `inlen`, and the four outputs share one length `outlen`.  That matches the
 * batchable consumer (the per-tree commitment hash, whose concatenated inputs
 * are equal-length within a tree-size class).  Lane L reads from in[L][0..inlen)
 * and writes to out[L][0..outlen); the four in/out pointers must not alias.
 *
 * Backend selection is runtime (AVX2 if present, else a portable scalar
 * fallback that is byte-identical to four serial ichor_shakeN runs).  The
 * output of lane L equals ichor_shake128/256(out[L], in[L], inlen) exactly.
 */
void ichor_shake128_x4(uint8_t *const out[4], size_t outlen,
                       const uint8_t *const in[4], size_t inlen);
void ichor_shake256_x4(uint8_t *const out[4], size_t outlen,
                       const uint8_t *const in[4], size_t inlen);

/* Active Keccak-f[1600]x4 backend (for tests / benchmarks / health reporting). */
typedef enum {
    ICHOR_KECCAK_X4_BACKEND_AVX2 = 1,  /* x86_64 AVX2 4-lane permutation */
    ICHOR_KECCAK_X4_BACKEND_NEON_SHA3, /* aarch64 FEAT_SHA3 2x2-lane packed */
    ICHOR_KECCAK_X4_BACKEND_SCALAR     /* portable 4x serial permutation */
} ichor_keccak_x4_backend_t;

ichor_keccak_x4_backend_t ichor_keccak_x4_backend(void);
const char *ichor_keccak_x4_backend_name(void);

#endif /* ICHOR_HASH_H */
