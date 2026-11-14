/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_vaes.c - Batched AES-128/192/256 encrypt using Intel VAES (256-bit
 * vector AES) with AVX2 round-key broadcasts.
 *
 * Compiled only when ICHOR_HAVE_AES_VAES is defined, which the build system
 * sets only where ICHOR_HAVE_AES_NI is also set: VAES is a strict superset of
 * AES-NI on every CPU that advertises it, so this backend reuses the AES-NI
 * key schedule and single-block encrypt unchanged and adds only a wide
 * batch kernel.  The whole TU is guarded so it compiles to an empty object
 * when VAES is absent.
 *
 * Why this backend exists: a single vaesenc on YMM encrypts two blocks, and
 * the unit needs roughly four independent dependency chains in flight to hide
 * its latency across the 10-14 rounds.  ichor_aes_encrypt_wide hands the
 * whole block run here so up to four YMM lanes (eight blocks) advance through
 * the rounds together, which the per-call encrypt_x4 (two lanes) could not
 * reach.
 *
 * Constant-time: vaesenc / vaesenclast are data-independent in latency, there
 * are no secret-dependent branches, and the only control flow keys on the
 * public block count n.
 */

#if defined(ICHOR_HAVE_AES_VAES) && defined(ICHOR_HAVE_AES_NI)

#include "aes_aesni.h"
#include "aes_dispatch.h"
#include "util.h"

#include <immintrin.h>

/* Blocks per YMM lane (two 128-bit AES blocks per 256-bit register). */
#define VAES_BLOCKS_PER_LANE 2
/* Lanes advanced together per wave: four chains saturate the AES unit. */
#define VAES_MAX_LANES 4
#define VAES_MAX_BLOCKS (VAES_BLOCKS_PER_LANE * VAES_MAX_LANES)

/*
 * Key expansion and single-block encrypt are identical to the AES-NI backend;
 * reuse them so the schedule layout (flat round keys in ctx->storage) and the
 * single-block path stay in one place.  Only the batch width differs.
 */
static int
vaes_key_expand(ichor_aes_ctx_t *ctx, const uint8_t *key, int key_bits)
{
    int rc = aes_aesni_key_expand(ctx, key, key_bits);
    if (rc == 0)
        ctx->backend_tag = ICHOR_AES_BACKEND_VAES;
    return rc;
}

static void
vaes_encrypt(const ichor_aes_ctx_t *ctx, uint8_t out[16], const uint8_t in[16])
{
    aes_aesni_encrypt(ctx, out, in);
}

/*
 * Encrypt n blocks in waves of up to VAES_MAX_BLOCKS.  Each wave loads
 * lanes = ceil(blocks / 2) YMM registers, runs them through the rounds
 * interleaved (the inner loop over lanes gives the unit its parallel chains),
 * and stores back only the real blocks.  A trailing odd block occupies the
 * low half of its lane and is loaded / stored 128 bits at a time so the kernel
 * never reads or writes past the caller's n-block buffer.
 */
static void
vaes_encrypt_wide(const ichor_aes_ctx_t *ctx, uint8_t *out, const uint8_t *in,
                  unsigned n)
{
    const __m128i *rk = (const __m128i *)ctx->storage;
    int nr = ctx->nr;
    __m256i rky[15];
    unsigned i;

    /* Splat each 128-bit round key across both lanes of a YMM once. */
    for (int r = 0; r <= nr; r++)
        rky[r] = _mm256_broadcastsi128_si256(_mm_loadu_si128(&rk[r]));

    for (i = 0; i < n;) {
        unsigned blocks = n - i;
        unsigned lanes, l;
        __m256i s[VAES_MAX_LANES];

        if (blocks > VAES_MAX_BLOCKS)
            blocks = VAES_MAX_BLOCKS;
        lanes = (blocks + 1) / VAES_BLOCKS_PER_LANE;

        for (l = 0; l < lanes; l++) {
            const uint8_t *src = in + 16 * (i + VAES_BLOCKS_PER_LANE * l);
            if (VAES_BLOCKS_PER_LANE * l + 1 < blocks)
                s[l] = _mm256_loadu_si256((const __m256i *)src);
            else
                s[l] = _mm256_castsi128_si256(
                    _mm_loadu_si128((const __m128i *)src));
        }

        for (l = 0; l < lanes; l++)
            s[l] = _mm256_xor_si256(s[l], rky[0]);
        for (int r = 1; r < nr; r++)
            for (l = 0; l < lanes; l++)
                s[l] = _mm256_aesenc_epi128(s[l], rky[r]);
        for (l = 0; l < lanes; l++)
            s[l] = _mm256_aesenclast_epi128(s[l], rky[nr]);

        for (l = 0; l < lanes; l++) {
            uint8_t *dst = out + 16 * (i + VAES_BLOCKS_PER_LANE * l);
            if (VAES_BLOCKS_PER_LANE * l + 1 < blocks)
                _mm256_storeu_si256((__m256i *)dst, s[l]);
            else
                _mm_storeu_si128((__m128i *)dst, _mm256_castsi256_si128(s[l]));
        }

        i += blocks;
    }

    ichor_secure_zero(rky, sizeof(rky));
}

/*
 * Multi-key batch (ichor_aes_encrypt_multikey) is intentionally NOT serviced
 * by a VAES kernel.  A lane-parallel version was written and benchmarked, but
 * it loses to the generic serial fallback on every tested core (i9 Raptor
 * included): unlike single-key encrypt_wide, which broadcasts the round keys
 * once, multikey must assemble per-lane round keys every call, and that gather
 * costs more than it saves, while N independent single-block AES-NI encrypts
 * already pipeline to near the single-block rate.  Leaving encrypt_multikey
 * NULL here routes multikey through the serial composition in aes.c, whose
 * per-block op on this backend is the AES-NI single-block encrypt, i.e. the
 * faster path.  A future multikey kernel that amortized the round-key gather
 * (caller-supplied pre-interleaved round keys reused across many calls) could
 * revisit this.
 */

const ichor_aes_ops_t ichor_aes_ops_vaes = {
    .key_expand = vaes_key_expand,
    .encrypt = vaes_encrypt,
    /* encrypt_x4 intentionally left NULL: the public encrypt_x4 calls
     * encrypt_wide with n == 4 when the table provides it, as this one does,
     * so the generic composition is never reached for VAES. */
    .encrypt_wide = vaes_encrypt_wide,
    /* encrypt_multikey left NULL on purpose; see the note above. */
    .backend_tag = ICHOR_AES_BACKEND_VAES,
    .name = "vaes",
};

#else /* !(ICHOR_HAVE_AES_VAES && ICHOR_HAVE_AES_NI) */

/* ISO C forbids an empty translation unit, and -Wpedantic / -Werror reject
 * one; give the guarded-out build a single harmless declaration. */
typedef int ichor_aes_vaes_translation_unit_not_empty;

#endif /* ICHOR_HAVE_AES_VAES && ICHOR_HAVE_AES_NI */
