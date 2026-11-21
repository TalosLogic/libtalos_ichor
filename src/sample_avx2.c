/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * sample_avx2.c - AVX2 (x86_64) batched Lemire reduction for the constant-time
 * fixed-weight sampler (sample_dispatch.h); the 4-draw-wide analog of
 * sample_sse2.
 *
 * Compiled with -mavx2 per-TU.  Gated by ICHOR_HAVE_SAMPLE_AVX2 and selected at
 * runtime only when ichor_cpu_features() reports ICHOR_CPU_AVX2 (see
 * src/sample.c).  Bit-identical to ichor_sample_reduce_batch_scalar.
 */

#ifdef ICHOR_HAVE_SAMPLE_AVX2

#include "sample_dispatch.h"
#include "util.h"

#include <immintrin.h>
#include <string.h>

static uint32_t
load32_le(const uint8_t b[4])
{
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}

/*
 * Four draws per step across the four 64-bit lanes; otherwise identical in
 * structure and output to reduce_batch_sse2 (see that file for the per-draw
 * shift-and-add and the carry recurrence).  A draw index past w clamps to the
 * group's first draw (its lane is recomputed, never stored twice).
 */
static void
reduce_batch_avx2(uint32_t *red, const uint8_t *tape, uint32_t w, uint32_t n,
                  unsigned limbs, size_t db)
{
    const __m256i one = _mm256_set1_epi64x(1);
    const __m256i zero = _mm256_setzero_si256();
    uint32_t i;

    for (i = 0; i < w; i += 4u) {
        uint32_t d0 = i;
        uint32_t d1 = (i + 1u < w) ? i + 1u : i;
        uint32_t d2 = (i + 2u < w) ? i + 2u : i;
        uint32_t d3 = (i + 3u < w) ? i + 3u : i;
        __m256i rangev = _mm256_set_epi64x(
            (int64_t)(uint64_t)(n - d3), (int64_t)(uint64_t)(n - d2),
            (int64_t)(uint64_t)(n - d1), (int64_t)(uint64_t)(n - d0));
        __m256i carryv = zero;
        unsigned l;

        for (l = 0; l < limbs; l++) {
            uint32_t a0 = load32_le(tape + (size_t)d0 * db + 4u * l);
            uint32_t a1 = load32_le(tape + (size_t)d1 * db + 4u * l);
            uint32_t a2 = load32_le(tape + (size_t)d2 * db + 4u * l);
            uint32_t a3 = load32_le(tape + (size_t)d3 * db + 4u * l);
            __m256i shifted =
                _mm256_set_epi64x((int64_t)(uint64_t)a3, (int64_t)(uint64_t)a2,
                                  (int64_t)(uint64_t)a1, (int64_t)(uint64_t)a0);
            __m256i r = rangev;
            __m256i prodv = zero;
            unsigned t;

            for (t = 0; t < 32u; t++) {
                __m256i bit = _mm256_and_si256(r, one);
                __m256i mask = _mm256_sub_epi64(zero, bit);

                prodv =
                    _mm256_add_epi64(prodv, _mm256_and_si256(shifted, mask));
                r = _mm256_srli_epi64(r, 1);
                shifted = _mm256_slli_epi64(shifted, 1);
            }
            carryv = _mm256_add_epi64(prodv, _mm256_srli_epi64(carryv, 32));
        }
        carryv = _mm256_srli_epi64(carryv, 32);

        {
            uint64_t lanes[4];

            _mm256_storeu_si256((__m256i *)lanes, carryv);
            red[d0] = (uint32_t)lanes[0];
            if (d1 != d0)
                red[d1] = (uint32_t)lanes[1];
            if (d2 != d0)
                red[d2] = (uint32_t)lanes[2];
            if (d3 != d0)
                red[d3] = (uint32_t)lanes[3];
            ichor_secure_zero(lanes, sizeof lanes);
        }
    }
}

/* Horizontal unsigned-max of the eight u32 lanes. */
static uint32_t
hmax_u32_avx2(__m256i v)
{
    __m128i m = _mm_max_epu32(_mm256_castsi256_si128(v),
                              _mm256_extracti128_si256(v, 1));

    m = _mm_max_epu32(m, _mm_shuffle_epi32(m, _MM_SHUFFLE(2, 3, 0, 1)));
    m = _mm_max_epu32(m, _mm_shuffle_epi32(m, _MM_SHUFFLE(1, 0, 3, 2)));
    return (uint32_t)_mm_cvtsi128_si32(m);
}

/*
 * The 8-wide analog of overlay_resolve_sse41 (see sample_sse41.c for the packed-
 * key single-pass scheme and the padding contract); bit-identical to the scalar
 * resolve.
 */
static void
overlay_resolve_avx2(uint32_t i, uint32_t j, const uint32_t *ov_slot,
                     const uint32_t *ov_val, uint32_t *cur_i, uint32_t *cur_j)
{
    const __m256i tiv = _mm256_set1_epi32((int)i);
    const __m256i tjv = _mm256_set1_epi32((int)j);
    const __m256i eight = _mm256_set1_epi32(8);
    __m256i kv = _mm256_setr_epi32(1, 2, 3, 4, 5, 6, 7, 8);
    __m256i keyi = _mm256_setzero_si256();
    __m256i keyj = _mm256_setzero_si256();
    uint32_t ki, kj, hi, hj;
    uint32_t k;

    for (k = 0; k < i; k += 8u) {
        __m256i slot = _mm256_loadu_si256((const __m256i *)(ov_slot + k));
        __m256i val = _mm256_loadu_si256((const __m256i *)(ov_val + k));
        __m256i key = _mm256_or_si256(
            _mm256_slli_epi32(kv, (int)ICHOR_SAMPLE_KEY_SHIFT), val);
        __m256i mi = _mm256_cmpeq_epi32(slot, tiv);
        __m256i mj = _mm256_cmpeq_epi32(slot, tjv);

        keyi = _mm256_max_epu32(keyi, _mm256_and_si256(mi, key));
        keyj = _mm256_max_epu32(keyj, _mm256_and_si256(mj, key));
        kv = _mm256_add_epi32(kv, eight);
    }
    ki = hmax_u32_avx2(keyi);
    kj = hmax_u32_avx2(keyj);

    /* Branch-free: a zero key means no match -> default (the slot index). */
    hi = 0u - ((ki | (0u - ki)) >> 31);
    hj = 0u - ((kj | (0u - kj)) >> 31);
    *cur_i = ((ki & ICHOR_SAMPLE_VAL_MASK) & hi) | (i & ~hi);
    *cur_j = ((kj & ICHOR_SAMPLE_VAL_MASK) & hj) | (j & ~hj);
}

const ichor_sample_ops_t ichor_sample_ops_avx2 = {
    .reduce_batch = reduce_batch_avx2,
    .overlay_resolve = overlay_resolve_avx2,
    .backend_tag = ICHOR_SAMPLE_BACKEND_AVX2,
    .name = "avx2",
};

#else /* !ICHOR_HAVE_SAMPLE_AVX2 */

typedef int ichor_sample_avx2_translation_unit_not_empty;

#endif /* ICHOR_HAVE_SAMPLE_AVX2 */
