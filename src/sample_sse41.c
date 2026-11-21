/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * sample_sse41.c - SSE4.1 (x86_64) overlay-resolve kernel for the constant-time
 * fixed-weight sampler (sample_dispatch.h).  The resolve is a last-wins priority
 * reduction (not an OR); its natural primitive is the 32-bit max introduced in
 * SSE4.1 (_mm_max_epu32), so SSE2-only hosts keep the scalar resolve.  This tier
 * reuses the SSE2 reduce kernel (it runs on the superset CPU).
 *
 * Compiled with -msse4.1 per-TU.  Gated by ICHOR_HAVE_SAMPLE_SSE41 and selected
 * at runtime only when ichor_cpu_features() reports ICHOR_CPU_SSE41 (SSE4.1 is
 * NOT baseline on x86_64).  Bit-identical to ichor_sample_overlay_resolve_scalar.
 */

#ifdef ICHOR_HAVE_SAMPLE_SSE41

#include "sample_dispatch.h"

#include <smmintrin.h>
#include <stdint.h>

/*
 * One Fisher-Yates overlay step, both targets resolved in a SINGLE pass over the
 * entries [0, i).  Each entry k is packed into the key ((k + 1) << SHIFT) |
 * ov_val[k]; _mm_max_epu32 keeps the matching entry with the greatest k (k is
 * distinct, so the high-bit index makes the max unique and selects last-wins),
 * and that entry's value is the key's low bits.  A non-match packs to 0, below
 * any real key (k + 1 >= 1), so a zero max means "no match" -> the default (the
 * slot index itself).  The scan rounds up to a multiple of four lanes; the
 * caller pads ov_slot with UINT32_MAX (never a valid target) and ov_val with 0,
 * so over-scanned lanes never match.  i is public, j secret, but both are only
 * compared, never used as an address, and the final select is branch-free.
 * Bit-identical to ichor_sample_overlay_resolve_scalar.
 */
static void
overlay_resolve_sse41(uint32_t i, uint32_t j, const uint32_t *ov_slot,
                      const uint32_t *ov_val, uint32_t *cur_i, uint32_t *cur_j)
{
    const __m128i tiv = _mm_set1_epi32((int)i);
    const __m128i tjv = _mm_set1_epi32((int)j);
    const __m128i four = _mm_set1_epi32(4);
    __m128i kv = _mm_setr_epi32(1, 2, 3, 4); /* (k + 1) for the first group */
    __m128i keyi = _mm_setzero_si128();
    __m128i keyj = _mm_setzero_si128();
    uint32_t ki, kj, hi, hj;
    uint32_t k;

    for (k = 0; k < i; k += 4u) {
        __m128i slot = _mm_loadu_si128((const __m128i *)(ov_slot + k));
        __m128i val = _mm_loadu_si128((const __m128i *)(ov_val + k));
        __m128i key =
            _mm_or_si128(_mm_slli_epi32(kv, (int)ICHOR_SAMPLE_KEY_SHIFT), val);
        __m128i mi = _mm_cmpeq_epi32(slot, tiv);
        __m128i mj = _mm_cmpeq_epi32(slot, tjv);

        keyi = _mm_max_epu32(keyi, _mm_and_si128(mi, key));
        keyj = _mm_max_epu32(keyj, _mm_and_si128(mj, key));
        kv = _mm_add_epi32(kv, four);
    }

    keyi =
        _mm_max_epu32(keyi, _mm_shuffle_epi32(keyi, _MM_SHUFFLE(2, 3, 0, 1)));
    keyi =
        _mm_max_epu32(keyi, _mm_shuffle_epi32(keyi, _MM_SHUFFLE(1, 0, 3, 2)));
    keyj =
        _mm_max_epu32(keyj, _mm_shuffle_epi32(keyj, _MM_SHUFFLE(2, 3, 0, 1)));
    keyj =
        _mm_max_epu32(keyj, _mm_shuffle_epi32(keyj, _MM_SHUFFLE(1, 0, 3, 2)));
    ki = (uint32_t)_mm_cvtsi128_si32(keyi);
    kj = (uint32_t)_mm_cvtsi128_si32(keyj);

    /* Branch-free: a zero key means no match -> default (the slot index). */
    hi = 0u - ((ki | (0u - ki)) >> 31); /* all-ones iff a match for i */
    hj = 0u - ((kj | (0u - kj)) >> 31); /* all-ones iff a match for j */
    *cur_i = ((ki & ICHOR_SAMPLE_VAL_MASK) & hi) | (i & ~hi);
    *cur_j = ((kj & ICHOR_SAMPLE_VAL_MASK) & hj) | (j & ~hj);
}

const ichor_sample_ops_t ichor_sample_ops_sse41 = {
    .reduce_batch = ichor_sample_reduce_batch_sse2,
    .overlay_resolve = overlay_resolve_sse41,
    .backend_tag = ICHOR_SAMPLE_BACKEND_SSE41,
    .name = "sse41",
};

#else /* !ICHOR_HAVE_SAMPLE_SSE41 */

typedef int ichor_sample_sse41_translation_unit_not_empty;

#endif /* ICHOR_HAVE_SAMPLE_SSE41 */
