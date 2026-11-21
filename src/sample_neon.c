/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * sample_neon.c - NEON (aarch64) batched Lemire reduction for the constant-time
 * fixed-weight sampler (sample_dispatch.h); the NEON analog of sample_sse2 (two
 * 64-bit lanes).
 *
 * Advanced SIMD is baseline on aarch64, so no per-TU arch flag.  Gated by
 * ICHOR_HAVE_SAMPLE_NEON (set only on aarch64) and runtime-gated on
 * ICHOR_CPU_NEON.  Bit-identical to ichor_sample_reduce_batch_scalar.
 */

#ifdef ICHOR_HAVE_SAMPLE_NEON

#include "sample_dispatch.h"
#include "util.h"

#include <arm_neon.h>
#include <string.h>

static uint32_t
load32_le(const uint8_t b[4])
{
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}

/*
 * Two draws per step across the two 64-bit lanes; same per-draw shift-and-add
 * and carry recurrence as reduce_batch_sse2 (see that file).  Only immediate
 * shifts are used (no secret shift count).
 */
static void
reduce_batch_neon(uint32_t *red, const uint8_t *tape, uint32_t w, uint32_t n,
                  unsigned limbs, size_t db)
{
    const uint64x2_t one = vdupq_n_u64(1);
    const uint64x2_t zero = vdupq_n_u64(0);
    uint32_t i;

    for (i = 0; i < w; i += 2u) {
        uint32_t d0 = i;
        uint32_t d1 = (i + 1u < w) ? i + 1u : i;
        uint64x2_t rangev = vsetq_lane_u64(
            (uint64_t)(n - d1), vsetq_lane_u64((uint64_t)(n - d0), zero, 0), 1);
        uint64x2_t carryv = zero;
        unsigned l;

        for (l = 0; l < limbs; l++) {
            uint32_t a0 = load32_le(tape + (size_t)d0 * db + 4u * l);
            uint32_t a1 = load32_le(tape + (size_t)d1 * db + 4u * l);
            uint64x2_t shifted = vsetq_lane_u64(
                (uint64_t)a1, vsetq_lane_u64((uint64_t)a0, zero, 0), 1);
            uint64x2_t r = rangev;
            uint64x2_t prodv = zero;
            unsigned t;

            for (t = 0; t < 32u; t++) {
                uint64x2_t bit = vandq_u64(r, one);
                uint64x2_t mask = vsubq_u64(zero, bit);

                prodv = vaddq_u64(prodv, vandq_u64(shifted, mask));
                r = vshrq_n_u64(r, 1);
                shifted = vshlq_n_u64(shifted, 1);
            }
            carryv = vaddq_u64(prodv, vshrq_n_u64(carryv, 32));
        }
        carryv = vshrq_n_u64(carryv, 32);

        red[d0] = (uint32_t)vgetq_lane_u64(carryv, 0);
        if (d1 != d0)
            red[d1] = (uint32_t)vgetq_lane_u64(carryv, 1);
    }
}

/*
 * The NEON analog of overlay_resolve_sse41 (see sample_sse41.c for the packed-
 * key single-pass scheme and the padding contract); bit-identical to the scalar
 * resolve.  vmaxvq_u32 is the AArch64 across-lane max reduction.
 */
static void
overlay_resolve_neon(uint32_t i, uint32_t j, const uint32_t *ov_slot,
                     const uint32_t *ov_val, uint32_t *cur_i, uint32_t *cur_j)
{
    static const uint32_t kinit[4] = {1u, 2u, 3u, 4u};
    const uint32x4_t tiv = vdupq_n_u32(i);
    const uint32x4_t tjv = vdupq_n_u32(j);
    const uint32x4_t four = vdupq_n_u32(4u);
    uint32x4_t kv = vld1q_u32(kinit);
    uint32x4_t keyi = vdupq_n_u32(0u);
    uint32x4_t keyj = vdupq_n_u32(0u);
    uint32_t ki, kj, hi, hj;
    uint32_t k;

    for (k = 0; k < i; k += 4u) {
        uint32x4_t slot = vld1q_u32(ov_slot + k);
        uint32x4_t val = vld1q_u32(ov_val + k);
        uint32x4_t key =
            vorrq_u32(vshlq_n_u32(kv, ICHOR_SAMPLE_KEY_SHIFT), val);
        uint32x4_t mi = vceqq_u32(slot, tiv);
        uint32x4_t mj = vceqq_u32(slot, tjv);

        keyi = vmaxq_u32(keyi, vandq_u32(mi, key));
        keyj = vmaxq_u32(keyj, vandq_u32(mj, key));
        kv = vaddq_u32(kv, four);
    }
    ki = vmaxvq_u32(keyi);
    kj = vmaxvq_u32(keyj);

    /* Branch-free: a zero key means no match -> default (the slot index). */
    hi = 0u - ((ki | (0u - ki)) >> 31);
    hj = 0u - ((kj | (0u - kj)) >> 31);
    *cur_i = ((ki & ICHOR_SAMPLE_VAL_MASK) & hi) | (i & ~hi);
    *cur_j = ((kj & ICHOR_SAMPLE_VAL_MASK) & hj) | (j & ~hj);
}

const ichor_sample_ops_t ichor_sample_ops_neon = {
    .reduce_batch = reduce_batch_neon,
    .overlay_resolve = overlay_resolve_neon,
    .backend_tag = ICHOR_SAMPLE_BACKEND_NEON,
    .name = "neon",
};

#else /* !ICHOR_HAVE_SAMPLE_NEON */

typedef int ichor_sample_neon_translation_unit_not_empty;

#endif /* ICHOR_HAVE_SAMPLE_NEON */
