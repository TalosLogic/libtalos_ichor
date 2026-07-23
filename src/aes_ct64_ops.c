/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_ct64_ops.c - Bitsliced AES ops table for runtime dispatch.
 *
 * Wraps the aes_ct64_* functions (which take aes_ct64_ctx_t *) for
 * the ichor_aes_ctx_t * interface used by the dispatch table.
 *
 * The cast from ichor_aes_ctx_t * to aes_ct64_ctx_t * is valid:
 * both types place their round-key data at offset 0 (960 bytes) and
 * int nr at offset 960.  The _Alignas(16) on ichor_aes_ctx_t.storage
 * satisfies the uint64_t alignment requirement of the bitsliced engine.
 */

#include "aes_dispatch.h"
#include "aes_ct64.h"

#include <stddef.h>

/*
 * The casts below reinterpret an
 * ichor_aes_ctx_t as an aes_ct64_ctx_t.  That is sound only while the two
 * layouts agree on the round-key block (offset 0) and the round count nr,
 * and while the ct64 context fits inside ichor's storage.  Pin the
 * invariant here so any future field reorder, added padding, or resized
 * storage is a compile error rather than a silently misaligned nr and
 * corrupted key schedule.
 */
_Static_assert(offsetof(aes_ct64_ctx_t, rk) == 0,
               "aes_ct64_ctx_t.rk must be at offset 0");
_Static_assert(offsetof(ichor_aes_ctx_t, storage) == 0,
               "ichor_aes_ctx_t.storage must be at offset 0");
_Static_assert(offsetof(ichor_aes_ctx_t, nr) == offsetof(aes_ct64_ctx_t, nr),
               "ichor_aes_ctx_t.nr and aes_ct64_ctx_t.nr must share an offset");
_Static_assert(sizeof(((aes_ct64_ctx_t *)0)->rk) == ICHOR_AES_CTX_STORAGE_BYTES,
               "aes_ct64_ctx_t.rk must fit exactly in ichor_aes_ctx_t.storage");
_Static_assert(sizeof(aes_ct64_ctx_t) <= sizeof(ichor_aes_ctx_t),
               "aes_ct64_ctx_t must not exceed ichor_aes_ctx_t");

static int
ct64_key_expand(ichor_aes_ctx_t *ctx, const uint8_t *key, int bits)
{
    int rc = aes_ct64_key_expand((aes_ct64_ctx_t *)ctx, key, bits);
    if (rc == 0)
        ctx->backend_tag = ICHOR_AES_BACKEND_BITSLICED;
    return rc;
}

static void
ct64_encrypt(const ichor_aes_ctx_t *ctx, uint8_t out[16], const uint8_t in[16])
{
    aes_ct64_encrypt((const aes_ct64_ctx_t *)ctx, out, in);
}

static void
ct64_encrypt_x4(const ichor_aes_ctx_t *ctx, uint8_t out[64],
                const uint8_t in[64])
{
    aes_ct64_encrypt_x4((const aes_ct64_ctx_t *)ctx, out, in);
}

const ichor_aes_ops_t ichor_aes_ops_bitsliced = {
    .key_expand = ct64_key_expand,
    .encrypt = ct64_encrypt,
    .encrypt_x4 = ct64_encrypt_x4,
    .backend_tag = ICHOR_AES_BACKEND_BITSLICED,
    .name = "bitsliced",
};
