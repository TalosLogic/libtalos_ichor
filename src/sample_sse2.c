/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * sample_sse2.c - SSE2 (x86_64) batched Lemire reduction for the constant-time
 * fixed-weight sampler (sample_dispatch.h).
 *
 * Compiled with -msse2 per-TU; the rest of the library does not require that
 * flag.  Gated by ICHOR_HAVE_SAMPLE_SSE2 (the same SSE2 probe as the gf2x
 * backend), so this file compiles to an empty object elsewhere.  The kernel is
 * bit-identical to ichor_sample_reduce_batch_scalar, so the KATs hold.
 */

#ifdef ICHOR_HAVE_SAMPLE_SSE2

#include "sample_dispatch.h"
#include "util.h"

#include <emmintrin.h>
#include <string.h>

static uint32_t
load32_le(const uint8_t b[4])
{
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}

/*
 * Two draws per step across the two 64-bit lanes.  Per draw and per 32-bit limb
 * the product limb * range is formed by the same 32-step shift-and-add as the
 * scalar ct_mul32_pub (the secret limb never reaches a hardware multiply): bit t
 * of the PUBLIC per-lane range gates whether (limb << t) is added.  range and
 * limb are consumed incrementally (range >>= 1 exposes the next bit as the LSB,
 * the shifted limb <<= 1), so only immediate 1-bit shifts are used and no shift
 * count is secret.  The limbs are folded low-to-high with the scalar carry
 * recurrence carry = prod + (carry >> 32); the result is carry >> 32.  Every
 * loop bound is public (w, limbs, 32), so control flow is data-independent.
 */
void
ichor_sample_reduce_batch_sse2(uint32_t *red, const uint8_t *tape, uint32_t w,
                               uint32_t n, unsigned limbs, size_t db)
{
    const __m128i one = _mm_set1_epi64x(1);
    const __m128i zero = _mm_setzero_si128();
    uint32_t i;

    for (i = 0; i < w; i += 2u) {
        uint32_t d0 = i;
        uint32_t d1 = (i + 1u < w) ? i + 1u : i;
        __m128i rangev = _mm_set_epi64x((int64_t)(uint64_t)(n - d1),
                                        (int64_t)(uint64_t)(n - d0));
        __m128i carryv = zero;
        unsigned l;

        for (l = 0; l < limbs; l++) {
            uint32_t a0 = load32_le(tape + (size_t)d0 * db + 4u * l);
            uint32_t a1 = load32_le(tape + (size_t)d1 * db + 4u * l);
            __m128i shifted =
                _mm_set_epi64x((int64_t)(uint64_t)a1, (int64_t)(uint64_t)a0);
            __m128i r = rangev;
            __m128i prodv = zero;
            unsigned t;

            for (t = 0; t < 32u; t++) {
                __m128i bit = _mm_and_si128(r, one);
                __m128i mask = _mm_sub_epi64(zero, bit);

                prodv = _mm_add_epi64(prodv, _mm_and_si128(shifted, mask));
                r = _mm_srli_epi64(r, 1);
                shifted = _mm_slli_epi64(shifted, 1);
            }
            carryv = _mm_add_epi64(prodv, _mm_srli_epi64(carryv, 32));
        }
        carryv = _mm_srli_epi64(carryv, 32);

        {
            uint64_t lanes[2];

            _mm_storeu_si128((__m128i *)lanes, carryv);
            red[d0] = (uint32_t)lanes[0];
            if (d1 != d0)
                red[d1] = (uint32_t)lanes[1];
            ichor_secure_zero(lanes, sizeof lanes);
        }
    }
}

const ichor_sample_ops_t ichor_sample_ops_sse2 = {
    .reduce_batch = ichor_sample_reduce_batch_sse2,
    .overlay_resolve = ichor_sample_overlay_resolve_scalar,
    .backend_tag = ICHOR_SAMPLE_BACKEND_SSE2,
    .name = "sse2",
};

#else /* !ICHOR_HAVE_SAMPLE_SSE2 */

/* ISO C forbids an empty translation unit; give the guarded-out build a single
 * harmless declaration. */
typedef int ichor_sample_sse2_translation_unit_not_empty;

#endif /* ICHOR_HAVE_SAMPLE_SSE2 */
