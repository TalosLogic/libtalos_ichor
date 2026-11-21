/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf2x_avx2.c - AVX2 (x86_64) 256-bit kernels for the gf2x circulant barrel
 * rotation, the rotl_var per-step constant-time select, the mod-(x^p - 1)
 * reduction fold, and the opener-side oblivious support compaction.
 *
 * Compiled with -mavx2 per-TU; the rest of the library does not require that
 * flag.  AVX2 is not baseline on x86_64, so this backend is selected at runtime
 * only when ichor_cpu_features() reports ICHOR_CPU_AVX2 (see the dispatch in
 * src/gf2x.c).  This file compiles to an empty object when ICHOR_HAVE_GF2X_AVX2
 * is not defined.
 *
 * The kernels are the 4-limb-wide analog of the SSE2 backend: a 256-bit lane
 * holds four independent 64-bit limbs, the cross-limb carry comes from an
 * unaligned load offset by one limb, and the runtime shift distances go through
 * _mm256_sll_epi64 / _mm256_srl_epi64 (variable count).  Output is bit-identical
 * to the scalar kernels, so the KATs hold.
 */

#ifdef ICHOR_HAVE_GF2X_AVX2

#include "gf2x_dispatch.h"
#include "util.h"

#include <immintrin.h>
#include <string.h>

/*
 * out = in * x^t mod (x^p - 1) for a PUBLIC fixed t in [1, p).  Bit-identical
 * to ichor_gf2x_rotl_fixed_scalar: out[i] = lo_i ^ hi_i, lo from (in << t), hi
 * from (in >> (p - t)).  Zero out, then XOR-accumulate the LO and HI funnels
 * over their valid ranges.  Output limbs whose 4-wide load would touch a source
 * limb outside [0, limbs) are peeled to the scalar expression.  Every loop
 * bound is a public function of t and p, so control flow is data-independent.
 * out must not alias in.
 */
static void
rotl_fixed_avx2(const ichor_gf2x_ring *ring, uint64_t *out, const uint64_t *in,
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
        const __m128i cl = _mm_cvtsi32_si128((int)lr);
        const __m128i cr = _mm_cvtsi32_si128((int)(64u - lr));
        const size_t n = limbs - lq; /* LO output-limb count */

        /* si == 0 has no in[si - 1] neighbour. */
        out[lq] ^= in[0] << lr;

        /* Quads (si .. si + 3), si >= 1.  si + 3 < n implies si + 3 <=
         * limbs - 1, so cur's high read in[si + 3] is in range; prev's low read
         * in[si - 1] is in range since si >= 1. */
        for (si = 1; si + 3u < n; si += 4) {
            __m256i cur = _mm256_loadu_si256((const __m256i *)(in + si));
            __m256i prev = _mm256_loadu_si256((const __m256i *)(in + si - 1));
            __m256i val = _mm256_or_si256(_mm256_sll_epi64(cur, cl),
                                          _mm256_srl_epi64(prev, cr));
            __m256i d = _mm256_loadu_si256((__m256i *)(out + lq + si));

            _mm256_storeu_si256((__m256i *)(out + lq + si),
                                _mm256_xor_si256(d, val));
        }
        for (; si < n; si++)
            out[lq + si] ^= (in[si] << lr) | (in[si - 1u] >> (64u - lr));
    }

    /* HI part: out[di] ^= limb (di + rq) of (in >> rs), di in [0, limbs - rq). */
    if (rs == 0u) {
        for (di = 0; di + rq < limbs; di++)
            out[di] ^= in[di + rq];
    } else {
        const __m128i cr = _mm_cvtsi32_si128((int)rs);
        const __m128i cl = _mm_cvtsi32_si128((int)(64u - rs));
        const size_t n = limbs - rq; /* HI output-limb count */

        /* Quads (di .. di + 3).  The high lane reads its neighbour
         * in[di + rq + 4], so require di + rq + 4 < limbs. */
        di = 0;
        for (; di + 3u < n && di + rq + 4u < limbs; di += 4) {
            const uint64_t *k = in + di + rq;
            __m256i cur = _mm256_loadu_si256((const __m256i *)k);
            __m256i nxt = _mm256_loadu_si256((const __m256i *)(k + 1));
            __m256i val = _mm256_or_si256(_mm256_srl_epi64(cur, cr),
                                          _mm256_sll_epi64(nxt, cl));
            __m256i d = _mm256_loadu_si256((__m256i *)(out + di));

            _mm256_storeu_si256((__m256i *)(out + di),
                                _mm256_xor_si256(d, val));
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
 * whole-limb-only case.  Quads whose load would reach past prod[2*limbs - 1]
 * are peeled to the scalar expression.  r and prod do not alias.
 */
static void
reduce_avx2(const ichor_gf2x_ring *ring, uint64_t *r, const uint64_t *prod)
{
    const size_t limbs = ring->limbs;
    const unsigned q = ring->red_q; /* whole-limb shift (= limbs - 1) */
    const unsigned s = ring->red_s; /* intra-limb shift, 1..63        */
    const __m128i cr = _mm_cvtsi32_si128((int)s);
    const __m128i cl = _mm_cvtsi32_si128((int)(64u - s));
    size_t i;

    /* Quads (i .. i + 3).  The high lane reads prod[q + i + 4], so require
     * q + i + 4 < 2*limbs; i + 3 < limbs keeps the outputs in range. */
    for (i = 0; i + 3u < limbs && q + i + 4u < 2u * limbs; i += 4) {
        __m256i lo = _mm256_loadu_si256((const __m256i *)(prod + i));
        __m256i cur = _mm256_loadu_si256((const __m256i *)(prod + q + i));
        __m256i nxt = _mm256_loadu_si256((const __m256i *)(prod + q + i + 1u));
        __m256i hi = _mm256_or_si256(_mm256_srl_epi64(cur, cr),
                                     _mm256_sll_epi64(nxt, cl));

        _mm256_storeu_si256((__m256i *)(r + i), _mm256_xor_si256(lo, hi));
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
 * ichor_gf2x_rotl_blend_scalar: mask (0 or ~0) is broadcast to all four lanes
 * and (acc & ~mask) is _mm256_andnot_si256(m, acc).  Quads (j .. j + 3) with
 * j + 3 < limbs; the final up-to-three limbs are peeled to the scalar
 * expression.  The only loop bound is limbs (public), so control flow is
 * data-independent.
 */
static void
rotl_blend_avx2(uint64_t *acc, const uint64_t *rot, uint64_t mask, size_t limbs)
{
    const __m256i m = _mm256_set1_epi64x((long long)mask);
    size_t j;

    for (j = 0; j + 3u < limbs; j += 4) {
        __m256i a = _mm256_loadu_si256((const __m256i *)(acc + j));
        __m256i b = _mm256_loadu_si256((const __m256i *)(rot + j));
        __m256i v =
            _mm256_or_si256(_mm256_and_si256(b, m), _mm256_andnot_si256(m, a));

        _mm256_storeu_si256((__m256i *)(acc + j), v);
    }
    for (; j < limbs; j++)
        acc[j] = (rot[j] & mask) | (acc[j] & ~mask);
}

/*
 * Per-limb fused barrel step: the scalar reference (identical to
 * ichor_gf2x_rotl_fixed_blend_scalar) for the seam and boundary limbs the AVX2
 * body peels.  The C shift by (64 - lr/rs) is undefined for lr/rs == 0, so
 * those cases branch here; the vector body instead relies on an AVX2 shift by
 * 64 yielding 0.
 */
static inline uint64_t
rotl_blend_limb_avx2(const uint64_t *src, size_t limbs, uint64_t top_mask,
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
 * ichor_gf2x_rotl_fixed_blend_scalar; the 4-wide analog of rotl_fixed_blend_sse2
 * (see that TU for the three-region derivation).  With t = 1 << i and
 * r = p - t, lq + rq is limbs - 1 or limbs - 2, so output limbs split into
 *   A = [0, lq)             rotv = hi only
 *   B = [lq, limbs - rq)    rotv = lo ^ hi   (seam; 1 or 2 limbs, scalar)
 *   C = [limbs - rq, limbs) rotv = lo only
 * A and C are vectorized in quads with no internal peel (A: i + 3 < lq keeps
 * src[i + rq + 4] <= src[lq + rq] in range; C: i + 4 < limbs excludes the top
 * limb and keeps the LO reads in range), the top limb and seam fall to scalar.
 * The per-lane shift by (64 - lr) or (64 - rs) yields 0 when lr/rs == 0, so one
 * vector expression serves the shifted and whole-limb cases.  Every loop bound
 * is a public function of t and p, so control flow is data-independent.  dst
 * must not alias src.
 */
static void
rotl_fixed_blend_avx2(const ichor_gf2x_ring *ring, uint64_t *dst,
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
    const __m256i m = _mm256_set1_epi64x((long long)mask);
    size_t i;

    /* Region A: [0, lq), HI funnel only. */
    {
        const __m128i crr = _mm_cvtsi32_si128((int)rs);
        const __m128i crl = _mm_cvtsi32_si128((int)(64u - rs));

        for (i = 0; i + 3u < lq; i += 4) {
            const uint64_t *k = src + i + rq;
            __m256i cur = _mm256_loadu_si256((const __m256i *)k);
            __m256i nxt = _mm256_loadu_si256((const __m256i *)(k + 1));
            __m256i hi = _mm256_or_si256(_mm256_srl_epi64(cur, crr),
                                         _mm256_sll_epi64(nxt, crl));
            __m256i s = _mm256_loadu_si256((const __m256i *)(src + i));
            __m256i d = _mm256_or_si256(_mm256_and_si256(hi, m),
                                        _mm256_andnot_si256(m, s));

            _mm256_storeu_si256((__m256i *)(dst + i), d);
        }
        for (; i < lq; i++)
            dst[i] =
                rotl_blend_limb_avx2(src, limbs, top, lq, lr, rq, rs, mask, i);
    }

    /* Region B: [lq, cbeg), the 1-2 limb seam (both funnels). */
    for (i = lq; i < cbeg; i++)
        dst[i] = rotl_blend_limb_avx2(src, limbs, top, lq, lr, rq, rs, mask, i);

    /* Region C: [cbeg, limbs), LO funnel only; top limb and odd tail scalar. */
    {
        const __m128i cll = _mm_cvtsi32_si128((int)lr);
        const __m128i clr = _mm_cvtsi32_si128((int)(64u - lr));

        for (i = cbeg; i + 4u < limbs; i += 4) {
            const uint64_t *k = src + i - lq;
            __m256i cur = _mm256_loadu_si256((const __m256i *)k);
            __m256i prev = _mm256_loadu_si256((const __m256i *)(k - 1));
            __m256i lo = _mm256_or_si256(_mm256_sll_epi64(cur, cll),
                                         _mm256_srl_epi64(prev, clr));
            __m256i s = _mm256_loadu_si256((const __m256i *)(src + i));
            __m256i d = _mm256_or_si256(_mm256_and_si256(lo, m),
                                        _mm256_andnot_si256(m, s));

            _mm256_storeu_si256((__m256i *)(dst + i), d);
        }
        for (; i < limbs; i++)
            dst[i] =
                rotl_blend_limb_avx2(src, limbs, top, lq, lr, rq, rs, mask, i);
    }
}

/*
 * Oblivious dense->sparse compaction, bit-identical to
 * ichor_gf2x_compact_scalar; the 8-u32-wide analog of compact_sse2.  Per
 * position the per-bit gate (ichor_ct_mask64, out-of-line so clang >= 17 cannot
 * hoist a secret branch) and the target global position are scalars; the inner
 * sweep over the t output slots (the hotspot) runs 8 u32 at a time.  Lane j is
 * selected iff the running count equals j, so idx[j] receives `global` under
 * (bitmask & (count == j)), via _mm256_cmpeq_epi32 against the slot-index vector
 * jv = {0..7} + 8*step.  count is secret but only ever compared, never used as
 * an address, so control flow is data-independent; a tail of t mod 8 slots is
 * finished scalar with the same masks.  No output slot is skipped, matching the
 * scalar CT shape.  idx is accessed with unaligned loads/stores (the opener's
 * buffer is uint32_t, not 32-byte aligned).
 */
static uint32_t
compact_avx2(uint32_t *idx, uint32_t t, const uint8_t *block,
             size_t block_bytes, uint32_t base, uint32_t span, uint32_t count)
{
    const __m256i eight = _mm256_set1_epi32(8);
    const uint32_t tv = t & ~7u;
    uint32_t pos;

    (void)block_bytes;
    for (pos = 0; pos < span; pos++) {
        uint32_t bit = (uint32_t)((block[pos >> 3] >> (pos & 7u)) & 1u);
        uint32_t bitmask = (uint32_t)ichor_ct_mask64(bit);
        uint32_t global = base + pos;
        __m256i cv = _mm256_set1_epi32((int)count);
        __m256i bm = _mm256_set1_epi32((int)bitmask);
        __m256i gv = _mm256_set1_epi32((int)global);
        __m256i jv = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7);
        uint32_t j;

        for (j = 0; j < tv; j += 8u) {
            __m256i cur = _mm256_loadu_si256((const __m256i *)(idx + j));
            __m256i sel = _mm256_and_si256(bm, _mm256_cmpeq_epi32(jv, cv));
            __m256i upd = _mm256_or_si256(_mm256_andnot_si256(sel, cur),
                                          _mm256_and_si256(sel, gv));

            _mm256_storeu_si256((__m256i *)(idx + j), upd);
            jv = _mm256_add_epi32(jv, eight);
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
 * the 8-u32-wide analog of scatter_sse2.  Sweeps the dense block as 32-bit
 * words, eight per step, ORing bmask[k] into the lane whose word index equals
 * the secret wpos[k] via _mm256_cmpeq_epi32.  wpos is secret but only compared,
 * never used as an address, so control flow depends only on public (w, span).
 * The final partial 32-byte store is bounded by block_bytes, preserving the
 * memset-zeroed padding.
 */
static void
scatter_avx2(uint8_t *block, size_t block_bytes, const uint32_t *idx,
             uint32_t w, uint32_t base, uint32_t span)
{
    uint32_t wpos[ICHOR_GF2X_MAX_WEIGHT];
    uint32_t bmask[ICHOR_GF2X_MAX_WEIGHT];
    uint32_t words = (span + 31u) >> 5;
    uint32_t i, k;

    memset(block, 0, block_bytes);
    if (w > ICHOR_GF2X_MAX_WEIGHT)
        return;

    ichor_gf2x_scatter_prep32(wpos, bmask, idx, w, base, span);

    for (i = 0; i < words; i += 8u) {
        __m256i iv = _mm256_setr_epi32(
            (int)i, (int)(i + 1u), (int)(i + 2u), (int)(i + 3u), (int)(i + 4u),
            (int)(i + 5u), (int)(i + 6u), (int)(i + 7u));
        __m256i accv = _mm256_setzero_si256();
        size_t bpos = (size_t)i * 4u;

        for (k = 0; k < w; k++) {
            __m256i wp = _mm256_set1_epi32((int)wpos[k]);
            __m256i bm = _mm256_set1_epi32((int)bmask[k]);

            accv = _mm256_or_si256(
                accv, _mm256_and_si256(bm, _mm256_cmpeq_epi32(iv, wp)));
        }

        if (bpos + 32u <= block_bytes) {
            _mm256_storeu_si256((__m256i *)(block + bpos), accv);
        } else {
            uint8_t tmp[32];
            size_t j;

            _mm256_storeu_si256((__m256i *)tmp, accv);
            for (j = 0; j < 32u && bpos + j < block_bytes; j++)
                block[bpos + j] = tmp[j];
            ichor_secure_zero(tmp, sizeof tmp);
        }
    }

    ichor_secure_zero(wpos, sizeof wpos);
    ichor_secure_zero(bmask, sizeof bmask);
}

const ichor_gf2x_ops_t ichor_gf2x_ops_avx2 = {
    .rotl_fixed = rotl_fixed_avx2,
    .reduce = reduce_avx2,
    .rotl_blend = rotl_blend_avx2,
    .rotl_fixed_blend = rotl_fixed_blend_avx2,
    .school = ichor_gf2x_school_scalar,
    .compact = compact_avx2,
    .scatter = scatter_avx2,
    .backend_tag = ICHOR_GF2X_BACKEND_AVX2,
    .name = "avx2",
};

#ifdef ICHOR_HAVE_GF2X_VPCLMUL
/*
 * Same AVX2 rotation/reduction/blend kernels, but with the VPCLMULQDQ wide
 * schoolbook (gf2x_school_vpclmul, built in its own -mvpclmulqdq TU) in place
 * of the scalar base case.  Defined here because the rotation kernels have
 * internal linkage in this TU; this object only takes the schoolbook's address,
 * so it needs no VPCLMULQDQ flag of its own.
 */
const ichor_gf2x_ops_t ichor_gf2x_ops_avx2_vpclmul = {
    .rotl_fixed = rotl_fixed_avx2,
    .reduce = reduce_avx2,
    .rotl_blend = rotl_blend_avx2,
    .rotl_fixed_blend = rotl_fixed_blend_avx2,
    .school = gf2x_school_vpclmul,
    .compact = compact_avx2,
    .scatter = scatter_avx2,
    .backend_tag = ICHOR_GF2X_BACKEND_AVX2_VPCLMUL,
    .name = "avx2+vpclmul",
};
#endif /* ICHOR_HAVE_GF2X_VPCLMUL */

#else /* !ICHOR_HAVE_GF2X_AVX2 */

/* ISO C forbids an empty translation unit, and -Wpedantic / -Werror reject
 * one; give the guarded-out build a single harmless declaration. */
typedef int ichor_gf2x_avx2_translation_unit_not_empty;

#endif /* ICHOR_HAVE_GF2X_AVX2 */
