/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf2x_neon.c - NEON (aarch64) 128-bit kernels for the gf2x circulant barrel
 * rotation, the rotl_var per-step constant-time select, the mod-(x^p - 1)
 * reduction fold, and the opener-side oblivious support compaction.
 *
 * Advanced SIMD is mandatory on ARMv8-A, so no per-TU arch flag is needed and
 * the probe (CMakeLists.txt) restricts HAVE_GF2X_NEON to aarch64.  The backend
 * is still runtime-gated on ICHOR_CPU_NEON (set only on aarch64) in the
 * dispatch, so a 32-bit ARM / other build yields to scalar.  This file compiles
 * to an empty object when ICHOR_HAVE_GF2X_NEON is not defined.
 *
 * The rotate and reduce kernels are the 2-limb-wide analog of the SSE2 backend:
 * a 128-bit lane
 * holds two independent 64-bit limbs, the cross-limb carry comes from an
 * unaligned load offset by one limb, and the runtime shift distances go through
 * vshlq_u64 with a signed count (positive = left, negative = logical right).
 * Output is bit-identical to the scalar kernels, so the KATs hold.
 */

#ifdef ICHOR_HAVE_GF2X_NEON

#include "gf2x_dispatch.h"
#include "util.h"

#include <arm_neon.h>
#include <string.h>

/*
 * out = in * x^t mod (x^p - 1) for a PUBLIC fixed t in [1, p).  Bit-identical
 * to ichor_gf2x_rotl_fixed_scalar: out[i] = lo_i ^ hi_i, lo from (in << t), hi
 * from (in >> (p - t)).  Zero out, then XOR-accumulate the LO and HI funnels
 * over their valid ranges.  Output limbs whose 2-wide load would touch a source
 * limb outside [0, limbs) are peeled to the scalar expression.  Every loop
 * bound is a public function of t and p, so control flow is data-independent.
 * out must not alias in.
 */
static void
rotl_fixed_neon(const ichor_gf2x_ring *ring, uint64_t *out, const uint64_t *in,
                unsigned t)
{
    const size_t limbs = ring->limbs;
    const unsigned lq = t >> 6;                    /* left shift: whole-limb */
    const unsigned lr = t & 63u;                   /* left shift: intra-limb */
    const unsigned r = (unsigned)ring->p_bits - t; /* wrap shift distance    */
    const unsigned rq = r >> 6;                    /* wrap shift: whole-limb */
    const unsigned rs = r & 63u;                   /* wrap shift: intra-limb */
    size_t si, di;

    memset(out, 0, limbs * sizeof(uint64_t));

    /* LO part: out[si + lq] ^= limb si of (in << lr), si in [0, limbs - lq). */
    if (lr == 0u) {
        for (si = 0; si + lq < limbs; si++)
            out[si + lq] ^= in[si];
    } else {
        const int64x2_t sl = vdupq_n_s64((int64_t)lr);
        const int64x2_t sr = vdupq_n_s64(-(int64_t)(64u - lr));
        const size_t n = limbs - lq; /* LO output-limb count */

        /* si == 0 has no in[si - 1] neighbour. */
        out[lq] ^= in[0] << lr;

        /* Pairs (si, si + 1), si >= 1.  si + 1 < n implies si + 1 <= limbs - 1,
         * so cur's high read in[si + 1] is in range; prev's low read
         * in[si - 1] is in range since si >= 1. */
        for (si = 1; si + 1u < n; si += 2) {
            uint64x2_t cur = vld1q_u64(in + si);
            uint64x2_t prev = vld1q_u64(in + si - 1);
            uint64x2_t val = vorrq_u64(vshlq_u64(cur, sl), vshlq_u64(prev, sr));
            uint64x2_t d = vld1q_u64(out + lq + si);

            vst1q_u64(out + lq + si, veorq_u64(d, val));
        }
        for (; si < n; si++)
            out[lq + si] ^= (in[si] << lr) | (in[si - 1u] >> (64u - lr));
    }

    /* HI part: out[di] ^= limb (di + rq) of (in >> rs), di in [0, limbs - rq). */
    if (rs == 0u) {
        for (di = 0; di + rq < limbs; di++)
            out[di] ^= in[di + rq];
    } else {
        const int64x2_t sr = vdupq_n_s64(-(int64_t)rs);
        const int64x2_t sl = vdupq_n_s64((int64_t)(64u - rs));
        const size_t n = limbs - rq; /* HI output-limb count */

        /* Pairs (di, di + 1).  The high lane reads its neighbour
         * in[di + rq + 2], so require di + rq + 2 <= limbs - 1. */
        di = 0;
        for (; di + 1u < n && di + rq + 2u <= limbs - 1u; di += 2) {
            const uint64_t *k = in + di + rq;
            uint64x2_t cur = vld1q_u64(k);
            uint64x2_t nxt = vld1q_u64(k + 1);
            uint64x2_t val = vorrq_u64(vshlq_u64(cur, sr), vshlq_u64(nxt, sl));
            uint64x2_t d = vld1q_u64(out + di);

            vst1q_u64(out + di, veorq_u64(d, val));
        }
        for (; di < n; di++) {
            const size_t k = di + rq;
            uint64_t v = in[k] >> rs;

            if (k + 1u < limbs)
                v |= in[k + 1u] << (64u - rs);
            out[di] ^= v;
        }
    }

    out[limbs - 1] &= ring->top_mask;
}

/*
 * Reduce the 2*limbs-limb product modulo x^p - 1: r = prod_low ^ (prod >> p),
 * top limb masked.  Bit-identical to ichor_gf2x_reduce_scalar: r[i] = prod[i] ^
 * (prod[q + i] >> s | prod[q + i + 1] << (64 - s)), high term dropped past the
 * product.  q = p / 64 = limbs - 1 and s = p % 64 is in [1, 63], so there is no
 * whole-limb-only case.  Pairs whose load would reach past prod[2*limbs - 1]
 * are peeled to the scalar expression.  r and prod do not alias.
 */
static void
reduce_neon(const ichor_gf2x_ring *ring, uint64_t *r, const uint64_t *prod)
{
    const size_t limbs = ring->limbs;
    const unsigned q = ring->red_q; /* whole-limb shift (= limbs - 1) */
    const unsigned s = ring->red_s; /* intra-limb shift, 1..63        */
    const int64x2_t sr = vdupq_n_s64(-(int64_t)s);
    const int64x2_t sl = vdupq_n_s64((int64_t)(64u - s));
    size_t i;

    /* Pairs (i, i + 1).  The high lane reads prod[q + i + 2], so require
     * q + i + 2 < 2*limbs; i + 1 < limbs keeps the outputs in range. */
    for (i = 0; i + 1u < limbs && q + i + 2u < 2u * limbs; i += 2) {
        uint64x2_t lo = vld1q_u64(prod + i);
        uint64x2_t cur = vld1q_u64(prod + q + i);
        uint64x2_t nxt = vld1q_u64(prod + q + i + 1u);
        uint64x2_t hi = vorrq_u64(vshlq_u64(cur, sr), vshlq_u64(nxt, sl));

        vst1q_u64(r + i, veorq_u64(lo, hi));
    }
    for (; i < limbs; i++) {
        uint64_t hi = prod[q + i] >> s;

        if (q + i + 1u < 2u * limbs)
            hi |= prod[q + i + 1u] << (64u - s);
        r[i] = prod[i] ^ hi;
    }

    r[limbs - 1] &= ring->top_mask;
}

/*
 * acc[j] = (rot[j] & mask) | (acc[j] & ~mask), the constant-time per-step
 * select ichor_gf2x_rotl_var runs once per barrel iteration.  Bit-identical to
 * ichor_gf2x_rotl_blend_scalar: mask (0 or ~0) is broadcast to both lanes and
 * (acc & ~mask) is vbicq_u64(acc, m) (bit clear: acc AND NOT m).  Pairs
 * (j, j + 1) with j + 1 < limbs; the final odd limb is peeled to the scalar
 * expression.  The only loop bound is limbs (public), so control flow is
 * data-independent.
 */
static void
rotl_blend_neon(uint64_t *acc, const uint64_t *rot, uint64_t mask, size_t limbs)
{
    const uint64x2_t m = vdupq_n_u64(mask);
    size_t j;

    for (j = 0; j + 1u < limbs; j += 2) {
        uint64x2_t a = vld1q_u64(acc + j);
        uint64x2_t b = vld1q_u64(rot + j);
        uint64x2_t v = vorrq_u64(vandq_u64(b, m), vbicq_u64(a, m));

        vst1q_u64(acc + j, v);
    }
    for (; j < limbs; j++)
        acc[j] = (rot[j] & mask) | (acc[j] & ~mask);
}

/*
 * Per-limb fused barrel step: the scalar reference (identical to
 * ichor_gf2x_rotl_fixed_blend_scalar) for the seam and boundary limbs the NEON
 * body peels.  The C shift by (64 - lr/rs) is undefined for lr/rs == 0, so
 * those cases branch here; the vector body instead relies on a NEON shift by
 * +/- 64 yielding 0.
 */
static inline uint64_t
rotl_blend_limb_neon(const uint64_t *src, size_t limbs, uint64_t top_mask,
                     unsigned lq, unsigned lr, unsigned rq, unsigned rs,
                     uint64_t mask, size_t i)
{
    uint64_t lo = 0;
    uint64_t hi = 0;
    uint64_t rotv;

    if (i >= lq) {
        const size_t si = i - lq;
        if (lr == 0u) {
            lo = src[si];
        } else {
            lo = src[si] << lr;
            if (si >= 1u)
                lo |= src[si - 1u] >> (64u - lr);
        }
    }
    if (i + rq < limbs) {
        if (rs == 0u) {
            hi = src[i + rq];
        } else {
            hi = src[i + rq] >> rs;
            if (i + rq + 1u < limbs)
                hi |= src[i + rq + 1u] << (64u - rs);
        }
    }
    rotv = lo ^ hi;
    if (i == limbs - 1u)
        rotv &= top_mask;
    return (rotv & mask) | (src[i] & ~mask);
}

/*
 * Fused barrel step: dst = (src * x^t & mask) | (src & ~mask) in one pass, so
 * the rotated vector never round-trips through memory.  Bit-identical to
 * ichor_gf2x_rotl_fixed_blend_scalar; the 2-limb-wide analog of
 * rotl_fixed_blend_sse2 (see that TU for the three-region derivation).  With
 * t = 1 << i and r = p - t, lq + rq is limbs - 1 or limbs - 2, so output limbs
 * split into
 *   A = [0, lq)             rotv = hi only
 *   B = [lq, limbs - rq)    rotv = lo ^ hi   (seam; 1 or 2 limbs, scalar)
 *   C = [limbs - rq, limbs) rotv = lo only
 * A and C are vectorized in pairs with no internal peel, the top limb and seam
 * fall to scalar.  The signed-count vshlq_u64 shift by +/- (64 - lr/rs) yields
 * 0 when lr/rs == 0, so one vector expression serves the shifted and whole-limb
 * cases.  Every loop bound is a public function of t and p, so control flow is
 * data-independent.  dst must not alias src.
 */
static void
rotl_fixed_blend_neon(const ichor_gf2x_ring *ring, uint64_t *dst,
                      const uint64_t *src, uint64_t mask, unsigned t)
{
    const size_t limbs = ring->limbs;
    const uint64_t top = ring->top_mask;
    const unsigned lq = t >> 6;                    /* left shift: whole-limb */
    const unsigned lr = t & 63u;                   /* left shift: intra-limb */
    const unsigned r = (unsigned)ring->p_bits - t; /* wrap shift distance    */
    const unsigned rq = r >> 6;                    /* wrap shift: whole-limb */
    const unsigned rs = r & 63u;                   /* wrap shift: intra-limb */
    const size_t cbeg = limbs - rq;                /* start of LO-only region */
    const uint64x2_t m = vdupq_n_u64(mask);
    size_t i;

    /* Region A: [0, lq), HI funnel only. */
    {
        const int64x2_t sr = vdupq_n_s64(-(int64_t)rs);
        const int64x2_t sl = vdupq_n_s64((int64_t)(64u - rs));

        for (i = 0; i + 1u < lq; i += 2) {
            const uint64_t *k = src + i + rq;
            uint64x2_t cur = vld1q_u64(k);
            uint64x2_t nxt = vld1q_u64(k + 1);
            uint64x2_t hi = vorrq_u64(vshlq_u64(cur, sr), vshlq_u64(nxt, sl));
            uint64x2_t s = vld1q_u64(src + i);
            uint64x2_t d = vorrq_u64(vandq_u64(hi, m), vbicq_u64(s, m));

            vst1q_u64(dst + i, d);
        }
        for (; i < lq; i++)
            dst[i] =
                rotl_blend_limb_neon(src, limbs, top, lq, lr, rq, rs, mask, i);
    }

    /* Region B: [lq, cbeg), the 1-2 limb seam (both funnels). */
    for (i = lq; i < cbeg; i++)
        dst[i] = rotl_blend_limb_neon(src, limbs, top, lq, lr, rq, rs, mask, i);

    /* Region C: [cbeg, limbs), LO funnel only; top limb and odd tail scalar. */
    {
        const int64x2_t sl = vdupq_n_s64((int64_t)lr);
        const int64x2_t sr = vdupq_n_s64(-(int64_t)(64u - lr));

        for (i = cbeg; i + 2u < limbs; i += 2) {
            const uint64_t *k = src + i - lq;
            uint64x2_t cur = vld1q_u64(k);
            uint64x2_t prev = vld1q_u64(k - 1);
            uint64x2_t lo = vorrq_u64(vshlq_u64(cur, sl), vshlq_u64(prev, sr));
            uint64x2_t s = vld1q_u64(src + i);
            uint64x2_t d = vorrq_u64(vandq_u64(lo, m), vbicq_u64(s, m));

            vst1q_u64(dst + i, d);
        }
        for (; i < limbs; i++)
            dst[i] =
                rotl_blend_limb_neon(src, limbs, top, lq, lr, rq, rs, mask, i);
    }
}

/*
 * Oblivious dense->sparse compaction, bit-identical to
 * ichor_gf2x_compact_scalar; the NEON analog of compact_sse2.  A 128-bit lane
 * holds four u32, so (unlike the rotate/reduce kernels, which pack two 64-bit
 * limbs) the inner t-slot sweep runs 4 slots at a time.  Per position the
 * per-bit gate (ichor_ct_mask64, out-of-line so clang >= 17 cannot hoist a
 * secret branch) and the target global position are scalars; lane j is selected
 * iff the running count equals j, so idx[j] receives `global` under
 * (bitmask & (count == j)), via vceqq_u32 against the slot-index vector
 * jv = {0,1,2,3} + 4*step.  count is secret but only ever compared, never used
 * as an address, so control flow is data-independent; a tail of t mod 4 slots is
 * finished scalar with the same masks.  No output slot is skipped, matching the
 * scalar CT shape.
 */
static uint32_t
compact_neon(uint32_t *idx, uint32_t t, const uint8_t *block,
             size_t block_bytes, uint32_t base, uint32_t span, uint32_t count)
{
    static const uint32_t jinit[4] = {0u, 1u, 2u, 3u};
    const uint32x4_t four = vdupq_n_u32(4u);
    const uint32_t tv = t & ~3u;
    uint32_t pos;

    (void)block_bytes;
    for (pos = 0; pos < span; pos++) {
        uint32_t bit = (uint32_t)((block[pos >> 3] >> (pos & 7u)) & 1u);
        uint32_t bitmask = (uint32_t)ichor_ct_mask64(bit);
        uint32_t global = base + pos;
        uint32x4_t cv = vdupq_n_u32(count);
        uint32x4_t bm = vdupq_n_u32(bitmask);
        uint32x4_t gv = vdupq_n_u32(global);
        uint32x4_t jv = vld1q_u32(jinit);
        uint32_t j;

        for (j = 0; j < tv; j += 4u) {
            uint32x4_t cur = vld1q_u32(idx + j);
            uint32x4_t sel = vandq_u32(bm, vceqq_u32(jv, cv));
            uint32x4_t upd = vorrq_u32(vbicq_u32(cur, sel), vandq_u32(gv, sel));

            vst1q_u32(idx + j, upd);
            jv = vaddq_u32(jv, four);
        }
        for (; j < t; j++) {
            uint32_t x = count ^ j;
            uint32_t nz = (x | (0u - x)) >> 31;
            uint32_t sel = bitmask & (nz - 1u);

            idx[j] = (idx[j] & ~sel) | (global & sel);
        }
        count += bit;
    }
    return count;
}

/*
 * Oblivious sparse->dense scatter, byte-identical to ichor_gf2x_scatter_scalar;
 * the NEON analog of scatter_sse2.  A 128-bit lane holds four u32, so the dense
 * block is swept as 32-bit words four per step, ORing bmask[k] into the lane
 * whose word index equals the secret wpos[k] via vceqq_u32.  wpos is secret but
 * only compared, never used as an address.  The final partial 16-byte store is
 * bounded by block_bytes, preserving the memset-zeroed padding.
 */
static void
scatter_neon(uint8_t *block, size_t block_bytes, const uint32_t *idx,
             uint32_t w, uint32_t base, uint32_t span)
{
    static const uint32_t iinit[4] = {0u, 1u, 2u, 3u};
    uint32_t wpos[ICHOR_GF2X_MAX_WEIGHT];
    uint32_t bmask[ICHOR_GF2X_MAX_WEIGHT];
    uint32_t words = (span + 31u) >> 5;
    uint32_t i, k;

    memset(block, 0, block_bytes);
    if (w > ICHOR_GF2X_MAX_WEIGHT)
        return;

    ichor_gf2x_scatter_prep32(wpos, bmask, idx, w, base, span);

    for (i = 0; i < words; i += 4u) {
        uint32x4_t iv = vaddq_u32(vld1q_u32(iinit), vdupq_n_u32(i));
        uint32x4_t accv = vdupq_n_u32(0u);
        size_t bpos = (size_t)i * 4u;

        for (k = 0; k < w; k++) {
            uint32x4_t wp = vdupq_n_u32(wpos[k]);
            uint32x4_t bm = vdupq_n_u32(bmask[k]);

            accv = vorrq_u32(accv, vandq_u32(bm, vceqq_u32(iv, wp)));
        }

        if (bpos + 16u <= block_bytes) {
            vst1q_u8(block + bpos, vreinterpretq_u8_u32(accv));
        } else {
            uint8_t tmp[16];
            size_t j;

            vst1q_u8(tmp, vreinterpretq_u8_u32(accv));
            for (j = 0; j < 16u && bpos + j < block_bytes; j++)
                block[bpos + j] = tmp[j];
            ichor_secure_zero(tmp, sizeof tmp);
        }
    }

    ichor_secure_zero(wpos, sizeof wpos);
    ichor_secure_zero(bmask, sizeof bmask);
}

const ichor_gf2x_ops_t ichor_gf2x_ops_neon = {
    .rotl_fixed = rotl_fixed_neon,
    .reduce = reduce_neon,
    .rotl_blend = rotl_blend_neon,
    .rotl_fixed_blend = rotl_fixed_blend_neon,
    .school = ichor_gf2x_school_scalar,
    .compact = compact_neon,
    .scatter = scatter_neon,
    .backend_tag = ICHOR_GF2X_BACKEND_NEON,
    .name = "neon",
};

#else /* !ICHOR_HAVE_GF2X_NEON */

/* ISO C forbids an empty translation unit, and -Wpedantic / -Werror reject
 * one; give the guarded-out build a single harmless declaration. */
typedef int ichor_gf2x_neon_translation_unit_not_empty;

#endif /* ICHOR_HAVE_GF2X_NEON */
