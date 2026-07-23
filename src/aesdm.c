/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aesdm.c - Davies-Meyer single-block-length compression over AES-128.
 *
 * Davies-Meyer feed-forward: the message block keys the cipher and the
 * chaining value is the plaintext, so H_out = AES_M(H_in) XOR H_in.
 * Delegates the block cipher to ichor_aes_*.  See aesdm.h for design
 * notes, including why the related-key structure is inert in the
 * opener-KDF role this serves.
 */

#include "aesdm.h"

#include "aes.h"
#include "util.h"

#include <string.h>

void
ichor_aesdm_iteration(const uint8_t H_in[16], const uint8_t M[16],
                      uint8_t H_out[16])
{
    ichor_aes_ctx_t ctx;
    uint8_t key[16];
    uint8_t H_buf[16];
    uint8_t ct[16];
    int i;

    /* Snapshot H_in so the in-place case (H_out == H_in) is safe. */
    memcpy(H_buf, H_in, 16);

    /* K = M. */
    memcpy(key, M, 16);

    ichor_aes_key_expand(&ctx, key, 128);

    /* H_out = AES_K(H_in) XOR H_in. */
    ichor_aes_encrypt(&ctx, ct, H_buf);
    for (i = 0; i < 16; i++)
        H_out[i] = ct[i] ^ H_buf[i];

    /*
     * Clear the AES context and all locals that contain message-derived
     * key material or intermediate AES output.
     */
    ichor_aes_ctx_clear(&ctx);
    ichor_secure_zero(key, sizeof(key));
    ichor_secure_zero(H_buf, sizeof(H_buf));
    ichor_secure_zero(ct, sizeof(ct));
}

/* ================================================================
 * Incremental multi-block AES-DM hash.
 *
 * Each full 16-byte message block keys one Davies-Meyer iteration under
 * the running chaining value.  The output is the chaining value itself;
 * there is no output transformation.  See aesdm.h for the framing notes.
 * ================================================================ */

void
ichor_aesdm_init_iv(ichor_aesdm_ctx_t *ctx, const uint8_t iv[16])
{
    memcpy(ctx->h, iv, 16);
    memset(ctx->buf, 0, sizeof(ctx->buf));
    ctx->buf_len = 0;
}

void
ichor_aesdm_absorb(ichor_aesdm_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t offset = 0;

    if (ctx->buf_len > 0) {
        size_t space = 16 - ctx->buf_len;
        size_t take = (len < space) ? len : space;
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        offset += take;
        if (ctx->buf_len == 16) {
            ichor_aesdm_iteration(ctx->h, ctx->buf, ctx->h);
            ctx->buf_len = 0;
        }
    }

    while (len - offset >= 16) {
        ichor_aesdm_iteration(ctx->h, data + offset, ctx->h);
        offset += 16;
    }

    if (offset < len) {
        size_t rem = len - offset;
        memcpy(ctx->buf, data + offset, rem);
        ctx->buf_len = rem;
    }
}

void
ichor_aesdm_finalize_fixed(ichor_aesdm_ctx_t *ctx, uint8_t out[16])
{
    if (ctx->buf_len > 0) {
        while (ctx->buf_len < 16)
            ctx->buf[ctx->buf_len++] = 0x00;
        ichor_aesdm_iteration(ctx->h, ctx->buf, ctx->h);
        ctx->buf_len = 0;
    }
    memcpy(out, ctx->h, 16);
}

void
ichor_aesdm_clear(ichor_aesdm_ctx_t *ctx)
{
    ichor_secure_zero(ctx, sizeof(*ctx));
}
