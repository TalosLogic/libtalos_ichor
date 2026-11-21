/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf2x_sse2.c - SSE2 (x86_64) 128-bit kernels for the gf2x circulant barrel
 * rotation, the rotl_var per-step constant-time select, the mod-(x^p - 1)
 * reduction fold, and the opener-side oblivious support compaction.
 *
 * Compiled with -msse2 per-TU; the rest of the library does not require that
 * flag.  SSE2 is baseline on x86_64, so this backend is selected by compile
 * presence (no runtime feature bit) whenever no wider backend applies.  This
 * file compiles to an empty object when ICHOR_HAVE_GF2X_SSE2 is not defined.
 *
 * Each kernel is bit-identical to its scalar counterpart, so the KATs hold.
 */

#ifdef ICHOR_HAVE_GF2X_SSE2

#include "gf2x_dispatch.h"
#include "util.h"

#include <emmintrin.h>
#include <string.h>

/*
 * out = in * x^t mod (x^p - 1) for a PUBLIC fixed t in [1, p).  Bit-identical
 * to ichor_gf2x_rotl_fixed_scalar: out[i] = lo_i ^ hi_i, where lo is limb i of
 * (in << t) and hi is limb i of (in >> (p - t)).  We zero out and then
 * XOR-accumulate the two funnels over their valid output ranges; a limb
 * outside a funnel's range contributes zero, so the XOR reproduces the scalar
 * per-limb lo ^ hi exactly (the seam limb, in both ranges, receives both).
 *
 * Each funnel is a whole-array bit-shift: the cross-limb carry comes from an
 * unaligned load offset by one limb (the neighbour), combined with the current
 * limbs via a per-lane 64-bit shift, so no lane-crossing is needed.  The
 * runtime shift distances enter through _mm_sll_epi64 / _mm_srl_epi64 (variable
 * count).  Output limbs whose 2-wide load would touch a source limb outside
 * [0, limbs) are peeled to the scalar funnel expression, so no out-of-range
 * limb is ever read.  Every loop bound is a public function of t and p (lq, lr,
 * rq, rs, limbs), so control flow is data-independent.  out must not alias in.
 */
static void
rotl_fixed_sse2(const ichor_gf2x_ring *ring, uint64_t *out, const uint64_t *in,
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

    /*
     * LO part: out[si + lq] ^= limb si of (in << lr), for si in [0, limbs - lq).
     * lq < limbs always (t < p), so the range is non-empty.
     */
    if (lr == 0u) {
        /* Whole-limb left shift: a straight limb copy into the offset range. */
        for (si = 0; si + lq < limbs; si++)
            out[si + lq] ^= in[si];
    } else {
        const __m128i cl = _mm_cvtsi32_si128((int)lr);
        const __m128i cr = _mm_cvtsi32_si128((int)(64u - lr));
        const size_t n = limbs - lq; /* LO output-limb count */

        /* si == 0 has no in[si - 1] neighbour. */
        out[lq] ^= in[0] << lr;

        /*
         * Vector body over pairs (si, si + 1), si >= 1.  si + 1 < n implies
         * si + 1 <= limbs - 1, so cur's high read in[si + 1] is in range;
         * prev's low read in[si - 1] is in range since si >= 1.
         */
        for (si = 1; si + 1u < n; si += 2) {
            __m128i cur = _mm_loadu_si128((const __m128i *)(in + si));
            __m128i prev = _mm_loadu_si128((const __m128i *)(in + si - 1));
            __m128i val =
                _mm_or_si128(_mm_sll_epi64(cur, cl), _mm_srl_epi64(prev, cr));
            __m128i d = _mm_loadu_si128((__m128i *)(out + lq + si));

            _mm_storeu_si128((__m128i *)(out + lq + si), _mm_xor_si128(d, val));
        }
        /* Scalar remainder (odd tail limb). */
        for (; si < n; si++)
            out[lq + si] ^= (in[si] << lr) | (in[si - 1u] >> (64u - lr));
    }

    /*
     * HI part: out[di] ^= limb (di + rq) of (in >> rs), for di in [0, limbs -
     * rq).  rq < limbs always (r < p), so the range is non-empty.
     */
    if (rs == 0u) {
        for (di = 0; di + rq < limbs; di++)
            out[di] ^= in[di + rq];
    } else {
        const __m128i cr = _mm_cvtsi32_si128((int)rs);
        const __m128i cl = _mm_cvtsi32_si128((int)(64u - rs));
        const size_t n = limbs - rq; /* HI output-limb count */

        /*
         * Vector body over pairs (di, di + 1).  The high lane (di + 1) reads
         * its neighbour in[di + rq + 2], so require di + rq + 2 <= limbs - 1.
         */
        di = 0;
        for (; di + 1u < n && di + rq + 2u <= limbs - 1u; di += 2) {
            const uint64_t *k = in + di + rq;
            __m128i cur = _mm_loadu_si128((const __m128i *)k);
            __m128i nxt = _mm_loadu_si128((const __m128i *)(k + 1));
            __m128i val =
                _mm_or_si128(_mm_srl_epi64(cur, cr), _mm_sll_epi64(nxt, cl));
            __m128i d = _mm_loadu_si128((__m128i *)(out + di));

            _mm_storeu_si128((__m128i *)(out + di), _mm_xor_si128(d, val));
        }
        /* Scalar remainder, including the top limb whose neighbour is out of
         * range (matches the scalar i + rq + 1 < limbs guard). */
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
 * Reduce the 2*limbs-limb carry-less product modulo x^p - 1: a coefficient at
 * position k >= p folds onto k - p (x^p == 1), i.e. r = prod_low ^ (prod >> p),
 * then the top limb is masked to p bits.  Bit-identical to
 * ichor_gf2x_reduce_scalar: for limb i, r[i] = prod[i] ^ (prod[q + i] >> s |
 * prod[q + i + 1] << (64 - s)), with the high term dropped when prod[q + i + 1]
 * is past the 2*limbs product.
 *
 * (prod >> p) is a right funnel by s with a whole-limb offset q; it vectorizes
 * exactly like the rotation's HI part (neighbour from an unaligned load offset
 * by one limb, runtime count via _mm_srl_epi64 / _mm_sll_epi64).  Here q =
 * p / 64 = limbs - 1 and s = p % 64 is always in [1, 63] (ring_init rejects p a
 * multiple of 64), so there is no whole-limb-only case.  Pairs whose loads
 * would reach past prod[2*limbs - 1] are peeled to the scalar expression.  All
 * bounds are public functions of p, so control flow is data-independent.  r and
 * prod do not alias (prod is mul scratch, r the caller element).
 */
static void
reduce_sse2(const ichor_gf2x_ring *ring, uint64_t *r, const uint64_t *prod)
{
    const size_t limbs = ring->limbs;
    const unsigned q = ring->red_q; /* whole-limb shift (= limbs - 1) */
    const unsigned s = ring->red_s; /* intra-limb shift, 1..63        */
    const __m128i cr = _mm_cvtsi32_si128((int)s);
    const __m128i cl = _mm_cvtsi32_si128((int)(64u - s));
    size_t i;

    /*
     * Vector body over pairs (i, i + 1).  The high lane reads its neighbour
     * prod[q + i + 2], so require q + i + 2 < 2*limbs; i + 1 < limbs keeps both
     * output limbs in range.
     */
    for (i = 0; i + 1u < limbs && q + i + 2u < 2u * limbs; i += 2) {
        __m128i lo = _mm_loadu_si128((const __m128i *)(prod + i));
        __m128i cur = _mm_loadu_si128((const __m128i *)(prod + q + i));
        __m128i nxt = _mm_loadu_si128((const __m128i *)(prod + q + i + 1u));
        __m128i hi =
            _mm_or_si128(_mm_srl_epi64(cur, cr), _mm_sll_epi64(nxt, cl));

        _mm_storeu_si128((__m128i *)(r + i), _mm_xor_si128(lo, hi));
    }
    /* Scalar remainder, including the top limb whose neighbour is past prod. */
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
 * (acc & ~mask) is _mm_andnot_si128(m, acc).  Pairs (j, j + 1) with j + 1 <
 * limbs; the final odd limb is peeled to the scalar expression.  The only loop
 * bound is limbs (public), so control flow is data-independent.
 */
static void
rotl_blend_sse2(uint64_t *acc, const uint64_t *rot, uint64_t mask, size_t limbs)
{
    const __m128i m = _mm_set1_epi64x((long long)mask);
    size_t j;

    for (j = 0; j + 1u < limbs; j += 2) {
        __m128i a = _mm_loadu_si128((const __m128i *)(acc + j));
        __m128i b = _mm_loadu_si128((const __m128i *)(rot + j));
        __m128i v = _mm_or_si128(_mm_and_si128(b, m), _mm_andnot_si128(m, a));

        _mm_storeu_si128((__m128i *)(acc + j), v);
    }
    for (; j < limbs; j++)
        acc[j] = (rot[j] & mask) | (acc[j] & ~mask);
}

/*
 * Per-limb fused barrel step: dst[i] = (rotv_i & mask) | (src[i] & ~mask),
 * rotv_i the rotated limb exactly as ichor_gf2x_rotl_fixed_blend_scalar forms
 * it (top limb masked to top_mask).  The scalar reference for the seam and
 * boundary limbs the SSE2 body peels; shift-by-(64 - lr/rs) is undefined in C
 * for lr/rs == 0, so those cases branch here (the vector body instead relies on
 * SSE2 shift-by-64 yielding 0).
 */
static inline uint64_t
rotl_blend_limb_sse2(const uint64_t *src, size_t limbs, uint64_t top_mask,
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
 * the rotated vector never round-trips through memory the way separate
 * rotl_fixed + rotl_blend calls do.  Bit-identical to
 * ichor_gf2x_rotl_fixed_blend_scalar.
 *
 * With t = 1 << i (so t a single set bit) and r = p - t, lq + rq is limbs - 1
 * or limbs - 2, so the output splits into three write-once regions:
 *   A = [0, lq)          rotv = hi only  (lo is zero: i < lq)
 *   B = [lq, limbs - rq) rotv = lo ^ hi  (the seam; 1 or 2 limbs)
 *   C = [limbs - rq, limbs) rotv = lo only (hi is zero: i + rq >= limbs)
 * A and C are vectorized in pairs with no internal peel (every source read is
 * in range), the top limb and the tiny seam fall to the scalar per-limb form.
 * The SSE2 per-lane shift by (64 - lr) or (64 - rs) yields 0 when lr/rs == 0,
 * so one vector expression serves both the shifted and whole-limb cases.  Every
 * loop bound is a public function of t and p, so control flow is
 * data-independent.  dst must not alias src.
 */
static void
rotl_fixed_blend_sse2(const ichor_gf2x_ring *ring, uint64_t *dst,
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
    const __m128i m = _mm_set1_epi64x((long long)mask);
    size_t i;

    /* Region A: [0, lq), HI funnel only; src[i + rq (+1)] stays in range for
     * i < lq since i + rq + 1 <= lq + rq <= limbs - 1. */
    {
        const __m128i crr = _mm_cvtsi32_si128((int)rs);
        const __m128i crl = _mm_cvtsi32_si128((int)(64u - rs));

        for (i = 0; i + 1u < lq; i += 2) {
            const uint64_t *k = src + i + rq;
            __m128i cur = _mm_loadu_si128((const __m128i *)k);
            __m128i nxt = _mm_loadu_si128((const __m128i *)(k + 1));
            __m128i hi =
                _mm_or_si128(_mm_srl_epi64(cur, crr), _mm_sll_epi64(nxt, crl));
            __m128i s = _mm_loadu_si128((const __m128i *)(src + i));
            __m128i d =
                _mm_or_si128(_mm_and_si128(hi, m), _mm_andnot_si128(m, s));

            _mm_storeu_si128((__m128i *)(dst + i), d);
        }
        for (; i < lq; i++)
            dst[i] =
                rotl_blend_limb_sse2(src, limbs, top, lq, lr, rq, rs, mask, i);
    }

    /* Region B: [lq, cbeg), the 1-2 limb seam where both funnels contribute. */
    for (i = lq; i < cbeg; i++)
        dst[i] = rotl_blend_limb_sse2(src, limbs, top, lq, lr, rq, rs, mask, i);

    /* Region C: [cbeg, limbs), LO funnel only; si = i - lq >= 1 here, so the
     * low neighbour src[si - 1] is in range.  The top limb (mask) and any odd
     * tail are peeled to scalar. */
    {
        const __m128i cll = _mm_cvtsi32_si128((int)lr);
        const __m128i clr = _mm_cvtsi32_si128((int)(64u - lr));

        for (i = cbeg; i + 2u < limbs; i += 2) {
            const uint64_t *k = src + i - lq;
            __m128i cur = _mm_loadu_si128((const __m128i *)k);
            __m128i prev = _mm_loadu_si128((const __m128i *)(k - 1));
            __m128i lo =
                _mm_or_si128(_mm_sll_epi64(cur, cll), _mm_srl_epi64(prev, clr));
            __m128i s = _mm_loadu_si128((const __m128i *)(src + i));
            __m128i d =
                _mm_or_si128(_mm_and_si128(lo, m), _mm_andnot_si128(m, s));

            _mm_storeu_si128((__m128i *)(dst + i), d);
        }
        for (; i < limbs; i++)
            dst[i] =
                rotl_blend_limb_sse2(src, limbs, top, lq, lr, rq, rs, mask, i);
    }
}

/*
 * Oblivious dense->sparse compaction, bit-identical to
 * ichor_gf2x_compact_scalar.  Per position the per-bit gate (ichor_ct_mask64,
 * kept out-of-line so clang >= 17 cannot hoist a secret branch) and the target
 * global position are scalars; the inner sweep over the t output slots (the
 * hotspot) runs 4 u32 at a time.  Lane j is selected iff the running count
 * equals j, so idx[j] receives `global` under (bitmask & (count == j)), via
 * _mm_cmpeq_epi32 against the slot-index vector jv = {0,1,2,3} + 4*step.  count
 * is secret but only ever compared, never used as an address, so control flow is
 * data-independent; a tail of t mod 4 slots is finished scalar with the same
 * masks.  No output slot is skipped, matching the scalar CT shape.  idx is
 * accessed with unaligned loads/stores (the opener's buffer is uint32_t, not
 * 16-byte aligned).
 */
static uint32_t
compact_sse2(uint32_t *idx, uint32_t t, const uint8_t *block,
             size_t block_bytes, uint32_t base, uint32_t span, uint32_t count)
{
    const __m128i four = _mm_set1_epi32(4);
    const uint32_t tv = t & ~3u;
    uint32_t pos;

    (void)block_bytes;
    for (pos = 0; pos < span; pos++) {
        uint32_t bit = (uint32_t)((block[pos >> 3] >> (pos & 7u)) & 1u);
        uint32_t bitmask = (uint32_t)ichor_ct_mask64(bit);
        uint32_t global = base + pos;
        __m128i cv = _mm_set1_epi32((int)count);
        __m128i bm = _mm_set1_epi32((int)bitmask);
        __m128i gv = _mm_set1_epi32((int)global);
        __m128i jv = _mm_setr_epi32(0, 1, 2, 3);
        uint32_t j;

        for (j = 0; j < tv; j += 4u) {
            __m128i cur = _mm_loadu_si128((const __m128i *)(idx + j));
            __m128i sel = _mm_and_si128(bm, _mm_cmpeq_epi32(jv, cv));
            __m128i upd = _mm_or_si128(_mm_andnot_si128(sel, cur),
                                       _mm_and_si128(sel, gv));

            _mm_storeu_si128((__m128i *)(idx + j), upd);
            jv = _mm_add_epi32(jv, four);
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
 * Oblivious sparse->dense scatter, byte-identical to ichor_gf2x_scatter_scalar.
 * The scalar reference sweeps 64-bit output words; this backend sweeps the dense
 * block as 32-bit words so the per-word compare is _mm_cmpeq_epi32 (SSE2
 * baseline), four words per step.  Per step the accumulator ORs bmask[k] into
 * the lane whose 32-bit word index equals the secret wpos[k]; wpos is secret but
 * only compared, never used as an address, so control flow is a function of the
 * public (w, span) alone.  The barriered single-bit masks come from
 * ichor_gf2x_scatter_prep32.  The final partial 16-byte store is bounded by
 * block_bytes, matching the scalar kernel's byte-wise tail, so no byte past the
 * covered span is written and the memset-zeroed padding is preserved.
 */
static void
scatter_sse2(uint8_t *block, size_t block_bytes, const uint32_t *idx,
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

    for (i = 0; i < words; i += 4u) {
        __m128i iv =
            _mm_setr_epi32((int)i, (int)(i + 1u), (int)(i + 2u), (int)(i + 3u));
        __m128i accv = _mm_setzero_si128();
        size_t bpos = (size_t)i * 4u;

        for (k = 0; k < w; k++) {
            __m128i wp = _mm_set1_epi32((int)wpos[k]);
            __m128i bm = _mm_set1_epi32((int)bmask[k]);

            accv =
                _mm_or_si128(accv, _mm_and_si128(bm, _mm_cmpeq_epi32(iv, wp)));
        }

        if (bpos + 16u <= block_bytes) {
            _mm_storeu_si128((__m128i *)(block + bpos), accv);
        } else {
            uint8_t tmp[16];
            size_t j;

            _mm_storeu_si128((__m128i *)tmp, accv);
            for (j = 0; j < 16u && bpos + j < block_bytes; j++)
                block[bpos + j] = tmp[j];
            ichor_secure_zero(tmp, sizeof tmp);
        }
    }

    ichor_secure_zero(wpos, sizeof wpos);
    ichor_secure_zero(bmask, sizeof bmask);
}

const ichor_gf2x_ops_t ichor_gf2x_ops_sse2 = {
    .rotl_fixed = rotl_fixed_sse2,
    .reduce = reduce_sse2,
    .rotl_blend = rotl_blend_sse2,
    .rotl_fixed_blend = rotl_fixed_blend_sse2,
    .school = ichor_gf2x_school_scalar,
    .compact = compact_sse2,
    .scatter = scatter_sse2,
    .backend_tag = ICHOR_GF2X_BACKEND_SSE2,
    .name = "sse2",
};

#else /* !ICHOR_HAVE_GF2X_SSE2 */

/* ISO C forbids an empty translation unit, and -Wpedantic / -Werror reject
 * one; give the guarded-out build a single harmless declaration. */
typedef int ichor_gf2x_sse2_translation_unit_not_empty;

#endif /* ICHOR_HAVE_GF2X_SSE2 */
