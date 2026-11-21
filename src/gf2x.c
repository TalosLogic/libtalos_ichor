/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf2x.c - constant-time circulant arithmetic over F_2[x]/(x^p - 1).
 *
 * Runtime-parameterized port of the QC-MDPC ring arithmetic: the modulus p
 * lives in an ichor_gf2x_ring descriptor (ichor_gf2x_ring_init) instead of a
 * compile-time constant, so one build serves every parameter set.  The
 * carry-less multiply is Karatsuba over ichor's dispatched 64x64 clmul
 * primitive; the schedule, reduction, and rotation barrel depend only on the
 * public p, so every routine is constant-time over the secret coefficients.
 * See include/ichor/gf2x.h for the contract.
 */

#include "gf2x.h"

#include "clmul.h"
#include "cpu.h"
#include "gf2x_dispatch.h"
#include "util.h"

#include <stdatomic.h>
#include <string.h>

/* Resolved kernel table (scalar or a SIMD backend); see the Dispatch section
 * at the end of this file.  The hot paths bind it once and call through it. */
static const ichor_gf2x_ops_t *gf2x_ops(void);

/*
 * Schoolbook crossover: gf2x_kara stops splitting and calls schoolbook once a
 * sub-product is <= this many limbs.  Machine-dependent; tune in ~16..40 by
 * benchmark.  The product is bit-identical regardless of the cutoff, so the
 * KATs stay valid across changes.
 */
#define GF2X_KARA_LEAF 32u

int
ichor_gf2x_ring_init(ichor_gf2x_ring *ring, size_t p_bits)
{
    size_t limbs, top_bits;

    memset(ring, 0, sizeof(*ring));

    /* The reduction assumes p is not a multiple of 64 (nonzero intra-limb
     * shift); every QC-MDPC prime is odd, so this always holds. */
    if (p_bits < 2u || (p_bits % 64u) == 0u)
        return -1;

    limbs = (p_bits + 63u) / 64u;
    top_bits = p_bits - 64u * (limbs - 1u);

    ring->p_bits = p_bits;
    ring->limbs = limbs;
    ring->block_bytes = (p_bits + 7u) / 8u;
    ring->top_mask =
        (top_bits >= 64u) ? ~UINT64_C(0) : ((UINT64_C(1) << top_bits) - 1u);
    ring->red_q = (unsigned)(p_bits / 64u);
    ring->red_s = (unsigned)(p_bits % 64u);
    ring->mul_scratch_limbs = 6u * limbs + 128u;
    ring->rotl_scratch_limbs = 2u * limbs;
    /* inv arena: b, tmp, chk, one (limbs each) + one mul scratch. */
    ring->inv_scratch_limbs = 4u * limbs + ring->mul_scratch_limbs;
    return 0;
}

void
ichor_gf2x_load(const ichor_gf2x_ring *ring, uint64_t *r, const uint8_t *in)
{
    size_t i;

    memset(r, 0, ring->limbs * sizeof(uint64_t));
    for (i = 0; i < ring->block_bytes; i++)
        r[i >> 3] |= (uint64_t)in[i] << (8u * (i & 7u));
    r[ring->limbs - 1] &= ring->top_mask;
}

void
ichor_gf2x_store(const ichor_gf2x_ring *ring, uint8_t *out, const uint64_t *a)
{
    size_t i;

    for (i = 0; i < ring->block_bytes; i++)
        out[i] = (uint8_t)(a[i >> 3] >> (8u * (i & 7u)));
}

void
ichor_gf2x_add(const ichor_gf2x_ring *ring, uint64_t *r, const uint64_t *a,
               const uint64_t *b)
{
    size_t i;

    for (i = 0; i < ring->limbs; i++)
        r[i] = a[i] ^ b[i];
}

/*
 * Reduce the 2*limbs-limb carry-less product modulo x^p - 1: each high
 * coefficient k >= p folds back onto k - p (shift the product right by p bits
 * and XOR), then mask the top limb to p bits.
 */
void
ichor_gf2x_reduce_scalar(const ichor_gf2x_ring *ring, uint64_t *r,
                         const uint64_t *prod)
{
    const size_t limbs = ring->limbs;
    const unsigned q = ring->red_q; /* whole-limb shift */
    const unsigned s = ring->red_s; /* intra-limb shift, 1..63 */
    size_t i;

    for (i = 0; i < limbs; i++) {
        uint64_t hi = prod[q + i] >> s;
        if (q + i + 1u < 2u * limbs)
            hi |= prod[q + i + 1u] << (64u - s);
        r[i] = prod[i] ^ hi;
    }
    r[limbs - 1] &= ring->top_mask;
}

/*
 * Schoolbook carry-less product: out[0, na+nb) = a * b (zeroed first).
 * na*nb clmul calls; the Karatsuba base case.  The 64x64 clmul backend is
 * bound once here (ichor_clmul64_resolve caches it), so per-column cost is one
 * indirect call.  na and nb are public, so control flow is data-independent.
 */
void
ichor_gf2x_school_scalar(uint64_t *out, const uint64_t *a, size_t na,
                         const uint64_t *b, size_t nb)
{
    ichor_clmul64_fn cl = ichor_clmul64_resolve();
    size_t i, j;

    memset(out, 0, (na + nb) * sizeof(uint64_t));
    for (i = 0; i < na; i++) {
        for (j = 0; j < nb; j++) {
            uint64_t lo, hi;
            cl(a[i], b[j], &lo, &hi);
            out[i + j] ^= lo;
            out[i + j + 1] ^= hi;
        }
    }
}

/*
 * Karatsuba carry-less product: out[0, 2n) = a * b, a and b each n limbs.
 * Split a = a_lo + a_hi*x^(64*lo), lo = n/2, hi = n - lo.  With P0 = a_lo*b_lo,
 * P2 = a_hi*b_hi, P1 = (a_lo+a_hi)(b_lo+b_hi), the cross term is
 * mid = P1 ^ P0 ^ P2 (subtraction is XOR over F_2).  `sc` is scratch: this
 * frame takes the leading 4*hi limbs and hands the rest to its (sequential)
 * child calls.  Every bound is a public function of n, so control flow is
 * data-independent.
 */
static void
gf2x_kara(uint64_t *out, const uint64_t *a, const uint64_t *b, size_t n,
          uint64_t *sc, ichor_gf2x_school_fn school)
{
    size_t lo, hi, i;
    uint64_t *sa, *sb, *p1, *child;

    if (n <= GF2X_KARA_LEAF) {
        school(out, a, n, b, n);
        return;
    }

    lo = n / 2u; /* low-half limbs          */
    hi = n - lo; /* high-half limbs (>= lo) */

    sa = sc;      /* hi limbs   */
    sb = sa + hi; /* hi limbs   */
    p1 = sb + hi; /* 2*hi limbs */
    child = p1 + 2u * hi;

    /* P0 -> out[0, 2*lo); P2 -> out[2*lo, 2*n): together these define all of
     * out, so no separate zeroing of out is needed. */
    gf2x_kara(out, a, b, lo, child, school);
    gf2x_kara(out + 2u * lo, a + lo, b + lo, hi, child, school);

    /* sum_a = a_lo + a_hi, sum_b = b_lo + b_hi (low halves zero-extended). */
    for (i = 0; i < lo; i++) {
        sa[i] = a[i] ^ a[lo + i];
        sb[i] = b[i] ^ b[lo + i];
    }
    for (i = lo; i < hi; i++) { /* trailing high limb(s) when n is odd */
        sa[i] = a[lo + i];
        sb[i] = b[lo + i];
    }

    gf2x_kara(p1, sa, sb, hi, child, school); /* P1 -> p1[0, 2*hi) */

    /* mid = P1 ^ P0 ^ P2 in place (p1), then out += mid << (lo limbs).  P0/P2
     * are read out of `out` before mid is folded back, so the overlap is
     * safe. */
    for (i = 0; i < 2u * lo; i++)
        p1[i] ^= out[i];
    for (i = 0; i < 2u * hi; i++)
        p1[i] ^= out[2u * lo + i];
    for (i = 0; i < 2u * hi; i++)
        out[lo + i] ^= p1[i];
}

void
ichor_gf2x_mul(const ichor_gf2x_ring *ring, uint64_t *r, const uint64_t *a,
               const uint64_t *b, uint64_t *scratch)
{
    const size_t limbs = ring->limbs;
    const ichor_gf2x_ops_t *ops = gf2x_ops();
    uint64_t *prod = scratch;              /* 2*limbs                 */
    uint64_t *kara = scratch + 2u * limbs; /* 4*limbs + 128           */

    gf2x_kara(prod, a, b, limbs, kara, ops->school);
    ops->reduce(ring, r, prod);

    /* scratch holds the secret double-width product and its Karatsuba
     * intermediates (a, b may be private key or error material). */
    ichor_secure_zero(scratch, ring->mul_scratch_limbs * sizeof(uint64_t));
}

/*
 * out = in * x^t mod (x^p - 1) for a PUBLIC fixed t in [1, p): a cyclic left
 * rotation of the p-bit element by t, computed in a single pass with no
 * double-width product buffer.  The coefficients split into two disjoint
 * output regions:
 *   - the low part is (in << t) truncated to [0, p): bits of in at positions
 *     [0, p - t) that stay in range;
 *   - the wrap part is the top t bits of in (positions [p - t, p)), which
 *     would overflow past x^(p-1) and fold back to the bottom via x^p == 1;
 *     that is exactly (in >> (p - t)), landing in positions [0, t).
 * The two regions never overlap, so XOR combines them.  This is bit-identical
 * to the former "shift into a 2*limbs buffer, then gf2x_reduce" (reduce's
 * right-shift by p of (in << t) is precisely (in >> (p - t))).
 *
 * t enters only as the two public shift distances t and p - t (each split into
 * a whole-limb and an intra-limb part), both derived from the public barrel
 * loop counter, so there is no secret-dependent control flow.  out must not
 * alias in.
 */
void
ichor_gf2x_rotl_fixed_scalar(const ichor_gf2x_ring *ring, uint64_t *out,
                             const uint64_t *in, unsigned t)
{
    const size_t limbs = ring->limbs;
    const unsigned lq = t >> 6;                    /* left shift: whole-limb */
    const unsigned lr = t & 63u;                   /* left shift: intra-limb */
    const unsigned r = (unsigned)ring->p_bits - t; /* wrap shift distance    */
    const unsigned rq = r >> 6;                    /* wrap shift: whole-limb */
    const unsigned rs = r & 63u;                   /* wrap shift: intra-limb */
    size_t i;

    for (i = 0; i < limbs; i++) {
        uint64_t lo = 0; /* limb i of (in << t)        */
        uint64_t hi = 0; /* limb i of (in >> (p - t))  */

        if (i >= lq) {
            const size_t si = i - lq;
            if (lr == 0u) {
                lo = in[si];
            } else {
                lo = in[si] << lr;
                if (si >= 1u)
                    lo |= in[si - 1u] >> (64u - lr);
            }
        }

        if (i + rq < limbs) {
            if (rs == 0u) {
                hi = in[i + rq];
            } else {
                hi = in[i + rq] >> rs;
                if (i + rq + 1u < limbs)
                    hi |= in[i + rq + 1u] << (64u - rs);
            }
        }

        out[i] = lo ^ hi;
    }
    out[limbs - 1] &= ring->top_mask;
}

/*
 * acc = (rot & mask) | (acc & ~mask), limb by limb: the constant-time select
 * ichor_gf2x_rotl_var runs once per barrel step, mask being 0 or ~0 from bit i
 * of the secret amount.  mask is applied uniformly to every limb and the only
 * loop bound is limbs (public), so the select is data-independent.  The SIMD
 * backends widen this exact per-limb expression.
 */
void
ichor_gf2x_rotl_blend_scalar(uint64_t *acc, const uint64_t *rot, uint64_t mask,
                             size_t limbs)
{
    size_t j;

    for (j = 0; j < limbs; j++)
        acc[j] = (rot[j] & mask) | (acc[j] & ~mask);
}

/*
 * Fused barrel step: dst = (src * x^t & mask) | (src & ~mask), the rotl_fixed
 * rotation and the rotl_var per-step select folded into a single pass so the
 * rotated vector is never written to memory.  Bit-identical to running
 * ichor_gf2x_rotl_fixed_scalar (into a temporary rot) followed by
 * ichor_gf2x_rotl_blend_scalar (rot -> dst with src as the pass-through): each
 * output limb's rotated value rotv is formed exactly as rotl_fixed forms it
 * (top limb masked to top_mask), then selected against src[i] by the opaque
 * 0/~0 mask.  dst must not alias src: the rotation reads src at both lower
 * (i - lq) and higher (i + rq) indices, so blending into src in place would
 * corrupt later reads; rotl_var ping-pongs its two scratch halves to satisfy
 * this.  t enters only as the public shift distances t and p - t, and mask is
 * applied uniformly, so control flow is data-independent.
 */
void
ichor_gf2x_rotl_fixed_blend_scalar(const ichor_gf2x_ring *ring, uint64_t *dst,
                                   const uint64_t *src, uint64_t mask,
                                   unsigned t)
{
    const size_t limbs = ring->limbs;
    const unsigned lq = t >> 6;                    /* left shift: whole-limb */
    const unsigned lr = t & 63u;                   /* left shift: intra-limb */
    const unsigned r = (unsigned)ring->p_bits - t; /* wrap shift distance    */
    const unsigned rq = r >> 6;                    /* wrap shift: whole-limb */
    const unsigned rs = r & 63u;                   /* wrap shift: intra-limb */
    size_t i;

    for (i = 0; i < limbs; i++) {
        uint64_t lo = 0; /* limb i of (src << t)       */
        uint64_t hi = 0; /* limb i of (src >> (p - t)) */
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
            rotv &= ring->top_mask;

        dst[i] = (rotv & mask) | (src[i] & ~mask);
    }
}

void
ichor_gf2x_rotl_var(const ichor_gf2x_ring *ring, uint64_t *out,
                    const uint64_t *in, uint32_t k, uint64_t *scratch)
{
    const size_t limbs = ring->limbs;
    const ichor_gf2x_ops_t *ops;
    uint64_t *src = scratch;         /* limbs */
    uint64_t *dst = scratch + limbs; /* limbs */
    unsigned i;

    ops = gf2x_ops();
    memcpy(src, in, limbs * sizeof(uint64_t));
    for (i = 0; (UINT32_C(1) << i) < (uint32_t)ring->p_bits; i++) {
        /*
         * Opaque mask: 0 or ~0 selected by bit i of the secret amount k.
         * ichor_ct_mask64 routes it through a volatile so the compiler
         * cannot lower the fused select below into a branch on the secret bit
         * (clang -O3 was observed doing exactly that).  Formed once per
         * iteration; the fused step stays branchless and vectorizable.
         */
        const uint64_t mask = ichor_ct_mask64((uint64_t)((k >> i) & 1u));
        uint64_t *tmp;

        /* dst = select(src * x^(1<<i), src) by secret bit i, fused so the
         * rotated vector never round-trips through memory; then ping-pong the
         * two scratch halves so this step's output feeds the next. */
        ops->rotl_fixed_blend(ring, dst, src, mask, 1u << i);

        tmp = src;
        src = dst;
        dst = tmp;
    }
    memcpy(out, src, limbs * sizeof(uint64_t));

    /* Both scratch halves held rotations of the secret input. */
    ichor_secure_zero(scratch, ring->rotl_scratch_limbs * sizeof(uint64_t));
}

/* ========================================================================
 * Inversion (Itoh-Tsujii).  Keygen-only; allocates internally.
 * ======================================================================== */

static int
gf2x_equal(const ichor_gf2x_ring *ring, const uint64_t *a, const uint64_t *b)
{
    size_t i;

    for (i = 0; i < ring->limbs; i++)
        if (a[i] != b[i])
            return 0;
    return 1;
}

/*
 * out = in^{2^k}: squaring maps the coefficient at position i to 2i mod p, so k
 * applications are the permutation i -> (i * 2^k) mod p.  Every index is a
 * public function of i, k, p, so the permutation is constant-time over the
 * secret coefficients (2^k is a unit mod the prime p, so each destination is
 * written exactly once).
 */
static void
gf2x_frob(const ichor_gf2x_ring *ring, uint64_t *out, const uint64_t *in,
          unsigned k)
{
    const size_t p = ring->p_bits;
    uint64_t e = 1;   /* 2^k mod p             */
    uint64_t dst = 0; /* running (i * e) mod p */
    unsigned step;
    size_t i;

    for (step = 0; step < k; step++) {
        e <<= 1;
        if (e >= p)
            e -= p;
    }

    memset(out, 0, ring->limbs * sizeof(uint64_t));
    for (i = 0; i < p; i++) {
        uint64_t bit = (in[i >> 6] >> (i & 63u)) & 1u;
        out[dst >> 6] |= bit << (dst & 63u);
        dst += e;
        if (dst >= p)
            dst -= p;
    }
}

/* Index of the most-significant set bit of n (n >= 1). */
static unsigned
gf2x_hibit(unsigned n)
{
    unsigned h = 0;

    while (n > 1u) {
        n >>= 1;
        h++;
    }
    return h;
}

int
ichor_gf2x_inv(const ichor_gf2x_ring *ring, uint64_t *r, const uint64_t *a,
               uint64_t *scratch)
{
    const size_t limbs = ring->limbs;
    const unsigned n = (unsigned)(ring->p_bits - 2u);
    uint64_t *b, *tmp, *chk, *one, *mulsc;
    unsigned m;
    int bit, ret;

    /* Caller scratch (>= inv_scratch_limbs): b, tmp, chk, one (limbs each) +
     * one mul scratch. */
    b = scratch;
    tmp = b + limbs;
    chk = tmp + limbs;
    one = chk + limbs;
    mulsc = one + limbs;

    /*
     * With ord_p(2) = p - 1 the unit group has order 2^{p-1} - 1, so
     * a^{-1} = a^{2^{p-1} - 2} = (a^{2^{p-2} - 1})^2.  Build b = a^{2^n - 1}
     * for n = p - 2 by the Itoh-Tsujii addition chain on n: m tracks the run
     * length of ones, doubling on each squaring and incrementing on each set
     * bit of n, ending at m == n.  The chain shape depends only on the public
     * p, so this is constant-time in a.
     */
    memcpy(b, a, limbs * sizeof(uint64_t)); /* a^{2^1 - 1}; m = 1 */
    m = 1;
    for (bit = (int)gf2x_hibit(n) - 1; bit >= 0; bit--) {
        gf2x_frob(ring, tmp, b, m); /* -> a^{2^{2m} - 1} */
        ichor_gf2x_mul(ring, b, tmp, b, mulsc);
        m <<= 1;
        if ((n >> bit) & 1u) {
            gf2x_frob(ring, tmp, b, 1); /* -> a^{2^{m+1} - 1} */
            ichor_gf2x_mul(ring, b, tmp, a, mulsc);
            m += 1;
        }
    }

    gf2x_frob(ring, r, b, 1); /* r = b^2 = a^{-1} */

    /* Confirm invertibility: a * r == 1.  An odd-weight block is a unit except
     * for a negligible-probability bad sample (keygen resamples). */
    memset(one, 0, limbs * sizeof(uint64_t));
    one[0] = 1;
    ichor_gf2x_mul(ring, chk, a, r, mulsc);
    ret = gf2x_equal(ring, chk, one) ? 0 : -1;

    /* scratch holds powers of the secret input a and its check product. */
    ichor_secure_zero(scratch, ring->inv_scratch_limbs * sizeof(uint64_t));
    return ret;
}

/*
 * 1ULL << pos, constant-time in pos: a chain of fixed-distance masked shifts, so
 * the (secret) bit position never becomes a variable shift distance (some
 * targets lack a barrel shifter, making a data-dependent shift variable-time).
 * Each step blends v and v << 2^i under the i-th bit of the secret pos through
 * ichor_ct_mask64 / ichor_ct_select64, NOT an inline (0 - bit) mask: the opaque
 * volatile stops the optimizer proving the blend is a select and lowering it to
 * a branch on the secret bit (a leak dudect observed with the inline form).
 */
static uint64_t
scatter_bit_at(uint32_t pos)
{
    uint64_t v = 1;

    v = ichor_ct_select64(ichor_ct_mask64((pos >> 0) & 1u), v << 1, v);
    v = ichor_ct_select64(ichor_ct_mask64((pos >> 1) & 1u), v << 2, v);
    v = ichor_ct_select64(ichor_ct_mask64((pos >> 2) & 1u), v << 4, v);
    v = ichor_ct_select64(ichor_ct_mask64((pos >> 3) & 1u), v << 8, v);
    v = ichor_ct_select64(ichor_ct_mask64((pos >> 4) & 1u), v << 16, v);
    v = ichor_ct_select64(ichor_ct_mask64((pos >> 5) & 1u), v << 32, v);
    return v;
}

/*
 * All-ones 64-bit mask if a == b, else 0.  The equal bit is barriered through
 * ichor_ct_mask64 so the caller's hot `acc |= bmask & scatter_word_eq(...)`
 * cannot be lowered to a branch on the secret word index (the asm-level leak
 * dudect flagged for the plain-arithmetic mask).
 */
static uint64_t
scatter_word_eq(uint32_t a, uint32_t b)
{
    uint32_t x = a ^ b;
    uint32_t ne = (x | (0u - x)) >> 31; /* 1 if a != b, else 0 */

    return ichor_ct_mask64((uint64_t)(ne ^ 1u));
}

/*
 * All-ones 64-bit mask if loc < span, else 0 (unsigned compare): the 64-bit
 * difference loc - span borrows into bit 63 exactly when loc < span.  Used to
 * drop out-of-span indices, including ones that localized into the padding bits
 * of the final partial word (which share that word's index).  The borrow bit is
 * barriered through ichor_ct_mask64 so the gate cannot become a branch on the
 * secret index.
 */
static uint64_t
scatter_in_span(uint32_t loc, uint32_t span)
{
    uint64_t lt = ((uint64_t)loc - (uint64_t)span) >> 63; /* 1 iff loc < span */

    return ichor_ct_mask64(lt);
}

/*
 * Scalar floor for ichor_gf2x_scatter (sparse support -> one dense ring
 * element) and the byte-identical reference the SIMD scatter backends are
 * validated against.  Sweeps 64-bit output words; see gf2x_dispatch.h.
 */
void
ichor_gf2x_scatter_scalar(uint8_t *block, size_t block_bytes,
                          const uint32_t *idx, uint32_t w, uint32_t base,
                          uint32_t span)
{
    uint32_t wpos[ICHOR_GF2X_MAX_WEIGHT];
    uint64_t bmask[ICHOR_GF2X_MAX_WEIGHT];
    uint32_t words = (span + 63u) >> 6;
    uint32_t i, k;

    /* Pre-zero so any buffer tail past the covered words stays defined. */
    memset(block, 0, block_bytes);
    if (w > ICHOR_GF2X_MAX_WEIGHT)
        return; /* precondition violated: leave the block zeroed */

    /* Per index: localize by base, then which 64-bit word it lands in and its
     * single-bit mask, gated by loc < span so an out-of-span index contributes
     * nothing.  The gate is load-bearing because the final word is partial: an
     * index localizing into its padding bits [span, words*64) shares the last
     * word's index and, without the gate, would be written into that padding. */
    for (k = 0; k < w; k++) {
        uint32_t loc = idx[k] - base;

        wpos[k] = loc >> 6;
        bmask[k] = scatter_bit_at(loc & 63u) & scatter_in_span(loc, span);
    }

    for (i = 0; i < words; i++) {
        uint64_t acc = 0;
        size_t bpos = (size_t)i << 3;
        size_t j;

        for (k = 0; k < w; k++)
            acc |= bmask[k] & scatter_word_eq(wpos[k], i);
        for (j = 0; j < 8u && bpos + j < block_bytes; j++)
            block[bpos + j] = (uint8_t)(acc >> (8u * j));
    }

    /* wpos/bmask encode the secret support; wipe them. */
    ichor_secure_zero(wpos, sizeof wpos);
    ichor_secure_zero(bmask, sizeof bmask);
}

/*
 * Shared constant-time precompute for the SIMD scatter backends: for each
 * support index, the 32-bit output word it localizes into (wpos) and its
 * single-bit mask gated by loc < span (bmask, zero for an out-of-span index).
 * The 32-bit granularity lets a backend's per-word compare be a single SSE2 /
 * NEON 32-bit equality while staying byte-identical to the 64-bit scalar sweep
 * (the set bit lands in global byte loc >> 3 either way).  The barriered
 * bit-building (scatter_bit_at, scatter_in_span) lives here so every backend
 * reuses one copy.  The caller has already enforced w <= ICHOR_GF2X_MAX_WEIGHT.
 */
void
ichor_gf2x_scatter_prep32(uint32_t *wpos, uint32_t *bmask, const uint32_t *idx,
                          uint32_t w, uint32_t base, uint32_t span)
{
    uint32_t k;

    for (k = 0; k < w; k++) {
        uint32_t loc = idx[k] - base;

        wpos[k] = loc >> 5;
        bmask[k] =
            (uint32_t)(scatter_bit_at(loc & 31u) & scatter_in_span(loc, span));
    }
}

/* All-ones 32-bit mask if a == b, else 0 (branch-free). */
static uint32_t
compact_eq32(uint32_t a, uint32_t b)
{
    uint32_t x = a ^ b;
    uint32_t nz = (x | (0u - x)) >> 31; /* 1 if a != b else 0 */

    return nz - 1u; /* 0 if a != b, all-ones if a == b */
}

/*
 * Scalar floor for ichor_gf2x_compact.  Mirrors the opener's oblivious
 * compaction exactly, so it is the bit-identical reference the SIMD backends are
 * validated against.  The per-bit gate routes through ichor_ct_mask64 (not a
 * plain 0u - bit) so clang >= 17 cannot prove the inner masked write is dead
 * when the bit is clear and hoist a secret-dependent branch around it; this
 * relies on ichor_ct_mask64 staying out-of-line (no LTO on the release build).
 * block_bytes is the buffer bound; only positions [0, span) are read, and
 * pos >> 3 < block_bytes holds by construction (block_bytes == ceil(span / 8)).
 */
uint32_t
ichor_gf2x_compact_scalar(uint32_t *idx, uint32_t t, const uint8_t *block,
                          size_t block_bytes, uint32_t base, uint32_t span,
                          uint32_t count)
{
    uint32_t pos;

    (void)block_bytes;
    for (pos = 0; pos < span; pos++) {
        uint32_t bit = (uint32_t)((block[pos >> 3] >> (pos & 7u)) & 1u);
        uint32_t bitmask = (uint32_t)ichor_ct_mask64(bit);
        uint32_t global = base + pos;
        uint32_t j;

        for (j = 0; j < t; j++) {
            uint32_t sel = bitmask & compact_eq32(count, j);

            idx[j] = (idx[j] & ~sel) | (global & sel);
        }
        count += bit;
    }
    return count;
}

/* ========================================================================
 * Kernel dispatch
 *
 * On first use, ichor_gf2x_dispatch_init() reads ichor_cpu_features() and
 * selects the highest-priority compiled-in backend whose feature bit is
 * present:
 *   1. AVX2+VPCLMUL (x86_64; ICHOR_HAVE_GF2X_AVX2 and ICHOR_HAVE_GF2X_VPCLMUL
 *              compiled in, ICHOR_CPU_AVX2 and ICHOR_CPU_VPCLMULQDQ present.
 *              Same AVX2 rotation/reduction/blend plus the VPCLMULQDQ wide
 *              schoolbook; a VPCLMULQDQ host is always an AVX2 host)
 *   2. AVX2    (x86_64; ICHOR_HAVE_GF2X_AVX2 compiled in, ICHOR_CPU_AVX2)
 *   3. SSE2    (x86_64; ICHOR_HAVE_GF2X_SSE2 compiled in; SSE2 is baseline
 *              on x86_64, so no runtime bit is consulted)
 *   4. NEON    (aarch64; ICHOR_HAVE_GF2X_NEON compiled in, ICHOR_CPU_NEON.
 *              The bit is set only on aarch64, where Advanced SIMD is
 *              mandatory; a 32-bit ARM / other build never sets it, so this
 *              backend yields to scalar there even if the TU were compiled)
 *   5. Scalar  (portable constant-time; always compiled in, the floor on
 *              every architecture)
 *
 * The selected ops pointer is stored with a release-store; subsequent calls
 * pay one load-acquire and one indirect branch.  Every backend is
 * constant-time and bit-identical to the scalar table, so the dispatch
 * decision is data-independent and the KATs hold across backends.
 * ======================================================================== */

const ichor_gf2x_ops_t ichor_gf2x_ops_scalar = {
    .rotl_fixed = ichor_gf2x_rotl_fixed_scalar,
    .reduce = ichor_gf2x_reduce_scalar,
    .rotl_blend = ichor_gf2x_rotl_blend_scalar,
    .rotl_fixed_blend = ichor_gf2x_rotl_fixed_blend_scalar,
    .school = ichor_gf2x_school_scalar,
    .compact = ichor_gf2x_compact_scalar,
    .scatter = ichor_gf2x_scatter_scalar,
    .backend_tag = ICHOR_GF2X_BACKEND_SCALAR,
    .name = "scalar",
};

_Atomic(const ichor_gf2x_ops_t *) ichor_gf2x_ops = NULL;

void
ichor_gf2x_dispatch_init(void)
{
    if (atomic_load_explicit(&ichor_gf2x_ops, memory_order_acquire) != NULL)
        return;

    const ichor_gf2x_ops_t *pick = NULL;

    /* feat is consulted by the AVX2 and NEON backends; a build with only SSE2
     * (baseline on x86_64) or none compiled in never reads it. */
#if defined(ICHOR_HAVE_GF2X_AVX2) || defined(ICHOR_HAVE_GF2X_NEON)
    uint32_t feat = ichor_cpu_features();
#endif
#if defined(ICHOR_HAVE_GF2X_AVX2) && defined(ICHOR_HAVE_GF2X_VPCLMUL)
    if (pick == NULL && (feat & ICHOR_CPU_AVX2) &&
        (feat & ICHOR_CPU_VPCLMULQDQ))
        pick = &ichor_gf2x_ops_avx2_vpclmul;
#endif
#if defined(ICHOR_HAVE_GF2X_AVX2)
    if (pick == NULL && (feat & ICHOR_CPU_AVX2))
        pick = &ichor_gf2x_ops_avx2;
#endif
#if defined(ICHOR_HAVE_GF2X_SSE2)
    if (pick == NULL)
        pick = &ichor_gf2x_ops_sse2;
#endif
#if defined(ICHOR_HAVE_GF2X_NEON)
    if (pick == NULL && (feat & ICHOR_CPU_NEON))
        pick = &ichor_gf2x_ops_neon;
#endif

    if (pick == NULL)
        pick = &ichor_gf2x_ops_scalar;

    const ichor_gf2x_ops_t *expected = NULL;
    atomic_compare_exchange_strong_explicit(&ichor_gf2x_ops, &expected, pick,
                                            memory_order_release,
                                            memory_order_acquire);
}

static const ichor_gf2x_ops_t *
gf2x_ops(void)
{
    const ichor_gf2x_ops_t *ops =
        atomic_load_explicit(&ichor_gf2x_ops, memory_order_acquire);
    if (ops == NULL) {
        ichor_gf2x_dispatch_init();
        ops = atomic_load_explicit(&ichor_gf2x_ops, memory_order_acquire);
    }
    return ops;
}

#ifdef ICHOR_ENABLE_FORCE_BACKEND
/* Test-only hook: clears the cached ops pointer so the next call re-selects a
 * backend.  Compiled out of release / vendored builds (see
 * ICHOR_ENABLE_FORCE_BACKEND in CMakeLists.txt). */
void
ichor_gf2x_dispatch_reset(void)
{
    atomic_store_explicit(&ichor_gf2x_ops, NULL, memory_order_release);
}
#endif /* ICHOR_ENABLE_FORCE_BACKEND */

uint32_t
ichor_gf2x_compact(uint32_t *idx, uint32_t t, const uint8_t *block,
                   size_t block_bytes, uint32_t base, uint32_t span,
                   uint32_t count)
{
    return gf2x_ops()->compact(idx, t, block, block_bytes, base, span, count);
}

void
ichor_gf2x_scatter(uint8_t *block, size_t block_bytes, const uint32_t *idx,
                   uint32_t w, uint32_t base, uint32_t span)
{
    gf2x_ops()->scatter(block, block_bytes, idx, w, base, span);
}
