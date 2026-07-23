/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes.h - AES-128/192/256 block cipher (encrypt only).
 *
 * Implements the forward cipher and key expansion from FIPS 197, plus a
 * CTR-mode keystream (ichor_aes_ctr) built on it.  No inverse cipher is
 * provided: the CTR-mode PRG/DRBG and KDF consumers in the talos libraries
 * need the forward direction only.
 *
 * Backend selection happens at runtime via a function-pointer dispatch
 * table populated on first use from ichor_cpu_features().  Priority:
 *   1. AES-NI         (x86_64; ICHOR_HAVE_AES_NI compiled in).
 *   2. ARMv8 Crypto   (aarch64; ICHOR_HAVE_ARMV8_AES compiled in).
 *   3. Bitsliced      (portable constant-time; always compiled in).
 *
 * All three backends are constant-time.  ICHOR_FORCE_BACKEND (env
 * var) can pin a specific backend for testing; see core/cpu.h.
 */

#ifndef ICHOR_AES_H
#define ICHOR_AES_H

#include <stdint.h>
#include <stddef.h>

/*
 * Size of the round-key storage array in ichor_aes_ctx_t.
 *
 * Must be large enough for every compiled-in backend:
 *   AES-NI / ARMv8:  15 round keys * 16 bytes = 240 bytes.
 *   Bitsliced:       15 rounds * 8 bit-planes * 8 bytes = 960 bytes.
 *
 * 960 bytes is the union-of-max.  AES-NI and ARMv8 backends use only
 * the first 240 bytes; the remaining 720 bytes are unused in those
 * paths.  At most a handful of contexts exist per proof session so the
 * overhead (~2 KB total) is invisible against the working-set size.
 */
#define ICHOR_AES_CTX_STORAGE_BYTES 960

/*
 * AES key context.
 *
 * A single layout used by all backends.  The interpretation of
 * storage[] is backend-specific:
 *   AES-NI / ARMv8: storage[0..239] holds the expanded round-key table
 *                   (up to 15 * 16 bytes of uint8_t round keys).
 *   Bitsliced:      storage[0..959] holds uint64_t[15][8] bit-plane
 *                   round keys.
 *
 * The backend_tag field records which backend last called key_expand
 * on this context.  Useful for round-key inspection in tests.
 *
 * The _Alignas(16) ensures that AES-NI backends can cast storage to
 * __m128i * and use aligned MOVDQA loads/stores without faulting.
 * It also satisfies the uint64_t alignment requirement for the
 * bitsliced backend.
 */
typedef struct {
    _Alignas(16) uint8_t storage[ICHOR_AES_CTX_STORAGE_BYTES];
    int nr;
    uint8_t backend_tag; /* ICHOR_AES_BACKEND_* value */
} ichor_aes_ctx_t;

/*
 * Expands the cipher key into round keys.
 *
 * key:      pointer to the cipher key (16, 24, or 32 bytes).
 * key_bits: 128, 192, or 256.
 *
 * Returns 0 on success, -1 if key_bits is invalid.
 */
int ichor_aes_key_expand(ichor_aes_ctx_t *ctx, const uint8_t *key,
                         int key_bits);

/*
 * Encrypts a single 16-byte block using the expanded key schedule.
 * out and in may alias.
 */
void ichor_aes_encrypt(const ichor_aes_ctx_t *ctx, uint8_t out[16],
                       const uint8_t in[16]);

/*
 * Encrypts four consecutive 16-byte blocks under the same key.
 *
 * out[0..63] and in[0..63] are four consecutive blocks (block b
 * occupies bytes 16*b .. 16*b+15).  out and in may alias.
 *
 * The bitsliced backend services this with a single 4-block engine
 * call (4x faster than four single-block encrypts); the AES-NI
 * backend falls back to four chained single-block encrypts.
 */
void ichor_aes_encrypt_x4(const ichor_aes_ctx_t *ctx, uint8_t out[64],
                          const uint8_t in[64]);

/*
 * CTR-mode keystream over the forward cipher, with an explicit
 * nonce / counter split.
 *
 * The counter block is nonce[0..11] (fixed for the whole call) followed by
 * a 32-bit big-endian block counter in bytes 12..15, starting at ctr0.
 * Only the 4-byte counter is incremented, so the carry can never reach the
 * nonce region: two calls with distinct nonces never share keystream.
 *
 * For each block b: keystream = AES(ctx, nonce || be32(ctr0 + b)).  If in
 * is non-NULL, out[i] = in[i] ^ keystream[i] over len bytes (encrypt or
 * decrypt); if in is NULL, out receives the raw keystream (PRG /
 * one-time-pad use).  len need not be a multiple of 16; the final block is
 * truncated.  out and in may alias.
 *
 * Returns 0 on success, or -1 without writing out if the request would
 * exhaust the 32-bit counter (ctr0 + ceil(len / 16) > 2^32).  This caps a
 * single (key, nonce) pair at 2^32 blocks (64 GiB) and fails closed rather
 * than carrying into the nonce or silently reusing keystream.
 *
 * Constant-time with respect to the key and the data: the counter
 * increment is branchless, the underlying cipher is constant-time, and the
 * block count depends only on the public len and ctr0.
 */
int ichor_aes_ctr(const ichor_aes_ctx_t *ctx, uint8_t *out, const uint8_t *in,
                  size_t len, const uint8_t nonce[12], uint32_t ctr0);

/*
 * Securely zero all key material in ctx.  Call after the last use
 * of a context holding a secret key.
 */
void ichor_aes_ctx_clear(ichor_aes_ctx_t *ctx);

/*
 * Identifies the AES backend currently selected by the dispatch table.
 * On the first call, triggers dispatch initialization (reads
 * ichor_cpu_features()).
 */
typedef enum {
    ICHOR_AES_BACKEND_AESNI = 1,
    ICHOR_AES_BACKEND_ARMV8 = 2,
    ICHOR_AES_BACKEND_BITSLICED = 3,
} ichor_aes_backend_t;

ichor_aes_backend_t ichor_aes_backend(void);

/*
 * Returns a static human-readable description of the active
 * backend.  Caller does not free.
 */
const char *ichor_aes_backend_name(void);

/*
 * Whether the active backend is optimal for this CPU or a software fallback
 * (host has hardware AES but the accelerated backend was not compiled in) is
 * reported by ichor_aes_backend_health() in <ichor/backend.h>.
 */

/*
 * Initialise the AES dispatch table if it has not been set yet.
 * Selects the highest-priority compiled-in backend whose required
 * feature bits are present in ichor_cpu_features().  Also emits
 * the lean-build notice when applicable.  Called lazily by every
 * public forwarder; may be called explicitly by tests.
 *
 * DO NOT call this in production code.
 */
void ichor_aes_dispatch_init(void);

/*
 * Reset the AES dispatch table to NULL so the next forwarder call
 * re-runs ichor_aes_dispatch_init().  Used by the test suite to
 * cycle through backends via ichor_cpu_features_override().
 *
 * Test-only: compiled in only under ICHOR_ENABLE_FORCE_BACKEND (see
 * CMakeLists.txt) and absent from a release / vendored build.
 */
#ifdef ICHOR_ENABLE_FORCE_BACKEND
void ichor_aes_dispatch_reset(void);
#endif

#endif /* ICHOR_AES_H */
