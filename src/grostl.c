/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl.c - Groestl-256 and Groestl-512: dispatch coordinator and public API.
 *
 * Clean-room implementation from the Groestl specification (Groestl.pdf SS3)
 * with the round-3 modifications applied (Round3Mods.pdf SS2).  No code is
 * copied from the reference implementation.
 *
 * State representation:
 *   Flat byte array in column-major order: byte (r + ROWS*c) lives at row r,
 *   column c.  ROWS = 8 always; columns = 8 (Groestl-256) or 16 (Groestl-512).
 *
 * Dispatch:
 *   The four permutations (P512, Q512, P1024, Q1024) differ only in their
 *   SubBytes implementation.  Each backend TU (grostl_aesni.c, grostl_armv8.c,
 *   grostl_soft.c) defines a complete set of four permutation functions and an
 *   ops table.  ichor_grostl_ops is selected on first use via a CAS guard
 *   inside compress_block, which is always reached before output_transform_*.
 *
 * Constant-time:
 *   No table lookups indexed by secret state in any path.  The dispatch
 *   decision is on public CPU-feature bits only.
 */

#include "grostl.h"
#include "grostl_dispatch.h"
#include "backend.h"
#include "cpu.h"
#include "util.h"
#include <stdatomic.h>
#include <string.h>

/* ================================================================
 * Dispatch: one-shot CAS init.  Priority: AES-NI > ARMv8 > soft.
 * ================================================================ */

_Atomic(const ichor_grostl_ops_t *) ichor_grostl_ops = NULL;

void
ichor_grostl_dispatch_init(void)
{
    if (atomic_load_explicit(&ichor_grostl_ops, memory_order_acquire) != NULL)
        return;

    const ichor_grostl_ops_t *pick = NULL;

    /* feat is consulted only by the hardware backends; a lean build with none
     * compiled in selects the software path unconditionally and never reads
     * it. */
#if defined(ICHOR_HAVE_AES_NI) || defined(ICHOR_HAVE_ARMV8_AES)
    uint32_t feat = ichor_cpu_features();
#ifdef ICHOR_HAVE_AES_NI
    if (pick == NULL && (feat & ICHOR_CPU_AES_NI))
        pick = &ichor_grostl_ops_aesni;
#endif
#ifdef ICHOR_HAVE_ARMV8_AES
    if (pick == NULL && (feat & ICHOR_CPU_ARMV8_AES))
        pick = &ichor_grostl_ops_armv8;
#endif
#endif /* any hardware Grostl backend */

    if (pick == NULL)
        pick = &ichor_grostl_ops_soft;

    const ichor_grostl_ops_t *expected = NULL;
    atomic_compare_exchange_strong_explicit(&ichor_grostl_ops, &expected, pick,
                                            memory_order_release,
                                            memory_order_acquire);
}

#ifdef ICHOR_ENABLE_FORCE_BACKEND
/* Test-only hook: clears the cached ops pointer
 * so the next call re-selects a backend.  Compiled out of release /
 * vendored builds (see ICHOR_ENABLE_FORCE_BACKEND in CMakeLists.txt). */
void
ichor_grostl_dispatch_reset(void)
{
    atomic_store_explicit(&ichor_grostl_ops, NULL, memory_order_release);
}
#endif /* ICHOR_ENABLE_FORCE_BACKEND */

const char *
ichor_grostl_backend_name(void)
{
    if (atomic_load_explicit(&ichor_grostl_ops, memory_order_acquire) == NULL)
        ichor_grostl_dispatch_init();
    return atomic_load_explicit(&ichor_grostl_ops, memory_order_acquire)->name;
}

/*
 * Backend health (backend.h): FALLBACK iff the host advertises a hardware AES
 * feature (Grøstl SubBytes reuses the AES S-box) but the active backend is the
 * "soft" path, i.e. the accelerated backend was not compiled into this build.
 */
ichor_backend_health_t
ichor_grostl_backend_health(void)
{
    uint32_t feat = ichor_cpu_features();
    if (strcmp(ichor_grostl_backend_name(), "soft") == 0 &&
        (feat & (ICHOR_CPU_AES_NI | ICHOR_CPU_ARMV8_AES)))
        return ICHOR_BACKEND_FALLBACK;
    return ICHOR_BACKEND_OPTIMAL;
}

/* ================================================================
 * Compression function f(h, m) = P(h XOR m) XOR Q(m) XOR h (spec SS3.2).
 * ================================================================ */

static void
compress_512(uint8_t h[GROSTL_STATE_BYTES_256],
             const uint8_t m[GROSTL_STATE_BYTES_256])
{
    uint8_t p_in[GROSTL_STATE_BYTES_256];
    uint8_t q_in[GROSTL_STATE_BYTES_256];

    for (size_t i = 0; i < GROSTL_STATE_BYTES_256; i++) {
        p_in[i] = (uint8_t)(h[i] ^ m[i]);
        q_in[i] = m[i];
    }

    ichor_grostl_ops->p512(p_in);
    ichor_grostl_ops->q512(q_in);

    for (size_t i = 0; i < GROSTL_STATE_BYTES_256; i++)
        h[i] ^= (uint8_t)(p_in[i] ^ q_in[i]);

    ichor_secure_zero(p_in, sizeof(p_in));
    ichor_secure_zero(q_in, sizeof(q_in));
}

static void
compress_1024(uint8_t h[GROSTL_STATE_BYTES_512],
              const uint8_t m[GROSTL_STATE_BYTES_512])
{
    uint8_t p_in[GROSTL_STATE_BYTES_512];
    uint8_t q_in[GROSTL_STATE_BYTES_512];

    for (size_t i = 0; i < GROSTL_STATE_BYTES_512; i++) {
        p_in[i] = (uint8_t)(h[i] ^ m[i]);
        q_in[i] = m[i];
    }

    ichor_grostl_ops->p1024(p_in);
    ichor_grostl_ops->q1024(q_in);

    for (size_t i = 0; i < GROSTL_STATE_BYTES_512; i++)
        h[i] ^= (uint8_t)(p_in[i] ^ q_in[i]);

    ichor_secure_zero(p_in, sizeof(p_in));
    ichor_secure_zero(q_in, sizeof(q_in));
}

static void
compress_block(ichor_grostl_ctx_t *ctx, const uint8_t *block)
{
    if (atomic_load_explicit(&ichor_grostl_ops, memory_order_acquire) == NULL)
        ichor_grostl_dispatch_init();

    if (ctx->state_bytes == GROSTL_STATE_BYTES_256)
        compress_512(ctx->state, block);
    else
        compress_1024(ctx->state, block);
}

/* ================================================================
 * Output transformation Omega(x) = trunc_n(P(x) XOR x) (spec SS3.3).
 *
 * Dispatch is already initialized by compress_block, which is always
 * called in ichor_grostl_finalize before output_transform_*.
 * ================================================================ */

static void
output_transform_256(uint8_t state[GROSTL_STATE_BYTES_256])
{
    uint8_t temp[GROSTL_STATE_BYTES_256];

    memcpy(temp, state, GROSTL_STATE_BYTES_256);
    ichor_grostl_ops->p512(temp);
    for (size_t i = 0; i < GROSTL_STATE_BYTES_256; i++)
        state[i] ^= temp[i];

    ichor_secure_zero(temp, sizeof(temp));
}

static void
output_transform_512(uint8_t state[GROSTL_STATE_BYTES_512])
{
    uint8_t temp[GROSTL_STATE_BYTES_512];

    memcpy(temp, state, GROSTL_STATE_BYTES_512);
    ichor_grostl_ops->p1024(temp);
    for (size_t i = 0; i < GROSTL_STATE_BYTES_512; i++)
        state[i] ^= temp[i];

    ichor_secure_zero(temp, sizeof(temp));
}

/* ================================================================
 * Public API: init.
 *
 * IV per spec SS3.5: the l-bit big-endian representation of n.
 * Groestl-256 (l=512, n=256): 56 zero bytes then 0x01 0x00 at bytes 62-63.
 * Groestl-512 (l=1024, n=512): 120 zero bytes then 0x02 0x00 at bytes 126-127.
 * ================================================================ */

void
ichor_grostl256_init(ichor_grostl_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state_bytes = GROSTL_STATE_BYTES_256;
    ctx->output_bytes = 32;
    ctx->rounds = GROSTL_ROUNDS_256;
    ctx->columns = GROSTL_COLS_256;
    ctx->state[62] = 0x01;
}

void
ichor_grostl512_init(ichor_grostl_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state_bytes = GROSTL_STATE_BYTES_512;
    ctx->output_bytes = 64;
    ctx->rounds = GROSTL_ROUNDS_512;
    ctx->columns = GROSTL_COLS_512;
    ctx->state[126] = 0x02;
}

/* ================================================================
 * Public API: init with a caller-supplied IV.
 *
 * Identical to the standard init except the chaining value is seeded
 * from iv instead of the length-encoding constant.  For fixed-input,
 * domain-separated hashing; pair with ichor_grostl_finalize_fixed.
 * ================================================================ */

void
ichor_grostl256_init_iv(ichor_grostl_ctx_t *ctx, const uint8_t iv[64])
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state_bytes = GROSTL_STATE_BYTES_256;
    ctx->output_bytes = 32;
    ctx->rounds = GROSTL_ROUNDS_256;
    ctx->columns = GROSTL_COLS_256;
    memcpy(ctx->state, iv, GROSTL_STATE_BYTES_256);
}

void
ichor_grostl512_init_iv(ichor_grostl_ctx_t *ctx, const uint8_t iv[128])
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state_bytes = GROSTL_STATE_BYTES_512;
    ctx->output_bytes = 64;
    ctx->rounds = GROSTL_ROUNDS_512;
    ctx->columns = GROSTL_COLS_512;
    memcpy(ctx->state, iv, GROSTL_STATE_BYTES_512);
}

/* ================================================================
 * Public API: absorb.
 * ================================================================ */

void
ichor_grostl_absorb(ichor_grostl_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t block_size = ctx->state_bytes;
    size_t offset = 0;

    if (ctx->buf_len > 0) {
        size_t space = block_size - ctx->buf_len;
        size_t take = (len < space) ? len : space;
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        offset += take;
        if (ctx->buf_len == block_size) {
            compress_block(ctx, ctx->buf);
            ctx->block_count++;
            ctx->buf_len = 0;
        }
    }

    while (len - offset >= block_size) {
        compress_block(ctx, data + offset);
        ctx->block_count++;
        offset += block_size;
    }

    if (offset < len) {
        size_t rem = len - offset;
        memcpy(ctx->buf, data + offset, rem);
        ctx->buf_len = rem;
    }
}

/* ================================================================
 * Public API: finalize.
 *
 * Padding (spec SS3.6): append 0x80, zero-pad to block_size - 8,
 * then a 64-bit big-endian count of total padded-message blocks.
 * When the 0x80 byte plus length field does not fit in the current
 * partial block, padding spans two blocks.
 * ================================================================ */

void
ichor_grostl_finalize(ichor_grostl_ctx_t *ctx, uint8_t *out)
{
    size_t block_size = ctx->state_bytes;
    uint64_t total_blocks;

    ctx->buf[ctx->buf_len++] = 0x80;

    if (ctx->buf_len > block_size - 8) {
        while (ctx->buf_len < block_size)
            ctx->buf[ctx->buf_len++] = 0x00;
        compress_block(ctx, ctx->buf);
        ctx->block_count++;
        ctx->buf_len = 0;
    }

    while (ctx->buf_len < block_size - 8)
        ctx->buf[ctx->buf_len++] = 0x00;

    total_blocks = ctx->block_count + 1;

    for (int i = 0; i < 8; i++)
        ctx->buf[block_size - 1 - i] = (uint8_t)(total_blocks >> (8 * i));

    compress_block(ctx, ctx->buf);
    ctx->block_count++;

    if (ctx->state_bytes == GROSTL_STATE_BYTES_256)
        output_transform_256(ctx->state);
    else
        output_transform_512(ctx->state);

    memcpy(out, ctx->state + (ctx->state_bytes - ctx->output_bytes),
           ctx->output_bytes);
}

/* ================================================================
 * Public API: finalize with zero padding only (no 0x80, no length).
 *
 * The final partial block is zero-filled and compressed; an exact-block-
 * multiple message adds no extra block.  Then the output transformation.
 * Sound only for a single fixed input length per IV / domain (see
 * grostl.h).  An all-empty message compresses a single zero block so the
 * result is still defined, though the intended use never passes one.
 * ================================================================ */

void
ichor_grostl_finalize_fixed(ichor_grostl_ctx_t *ctx, uint8_t *out)
{
    size_t block_size = ctx->state_bytes;

    if (ctx->buf_len > 0 || ctx->block_count == 0) {
        while (ctx->buf_len < block_size)
            ctx->buf[ctx->buf_len++] = 0x00;
        compress_block(ctx, ctx->buf);
        ctx->block_count++;
        ctx->buf_len = 0;
    }

    if (ctx->state_bytes == GROSTL_STATE_BYTES_256)
        output_transform_256(ctx->state);
    else
        output_transform_512(ctx->state);

    memcpy(out, ctx->state + (ctx->state_bytes - ctx->output_bytes),
           ctx->output_bytes);
}

/* ================================================================
 * Public API: secure cleanup and one-shot wrappers.
 * ================================================================ */

void
ichor_grostl_clear(ichor_grostl_ctx_t *ctx)
{
    ichor_secure_zero(ctx, sizeof(*ctx));
}

void
ichor_grostl256(uint8_t out[32], const uint8_t *msg, size_t msg_len)
{
    ichor_grostl_ctx_t ctx;

    ichor_grostl256_init(&ctx);
    if (msg_len > 0)
        ichor_grostl_absorb(&ctx, msg, msg_len);
    ichor_grostl_finalize(&ctx, out);
    ichor_grostl_clear(&ctx);
}

void
ichor_grostl512(uint8_t out[64], const uint8_t *msg, size_t msg_len)
{
    ichor_grostl_ctx_t ctx;

    ichor_grostl512_init(&ctx);
    if (msg_len > 0)
        ichor_grostl_absorb(&ctx, msg, msg_len);
    ichor_grostl_finalize(&ctx, out);
    ichor_grostl_clear(&ctx);
}

/* ================================================================
 * Public API: fixed-input single-compression node hashes.
 *
 * H = Omega(f(iv, block)): one compression under the caller-supplied
 * chaining value iv, then the output transformation, truncated to the
 * node width (the low n bytes, matching ichor_grostl_finalize).  No
 * padding: the input is exactly one fixed-width block.  Dispatch is
 * initialized here because compress_512 / output_transform_256
 * dereference ichor_grostl_ops directly (compress_block, which
 * normally performs the CAS init, is bypassed).
 * ================================================================ */

int
ichor_grostl256_compress_node(const uint8_t iv[64], const uint8_t block[64],
                              uint8_t out[32])
{
    uint8_t state[GROSTL_STATE_BYTES_256];

    if (iv == NULL || block == NULL || out == NULL)
        return -1;

    if (atomic_load_explicit(&ichor_grostl_ops, memory_order_acquire) == NULL)
        ichor_grostl_dispatch_init();

    memcpy(state, iv, GROSTL_STATE_BYTES_256);
    compress_512(state, block);
    output_transform_256(state);
    memcpy(out, state + (GROSTL_STATE_BYTES_256 - 32), 32);

    ichor_secure_zero(state, sizeof(state));
    return 0;
}

int
ichor_grostl512_compress_node(const uint8_t iv[128], const uint8_t block[128],
                              uint8_t out[64])
{
    uint8_t state[GROSTL_STATE_BYTES_512];

    if (iv == NULL || block == NULL || out == NULL)
        return -1;

    if (atomic_load_explicit(&ichor_grostl_ops, memory_order_acquire) == NULL)
        ichor_grostl_dispatch_init();

    memcpy(state, iv, GROSTL_STATE_BYTES_512);
    compress_1024(state, block);
    output_transform_512(state);
    memcpy(out, state + (GROSTL_STATE_BYTES_512 - 64), 64);

    ichor_secure_zero(state, sizeof(state));
    return 0;
}
