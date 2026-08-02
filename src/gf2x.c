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
#include "util.h"

#include <string.h>

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
    ring->rotl_scratch_limbs = 4u * limbs;
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
static void
gf2x_reduce(const ichor_gf2x_ring *ring, uint64_t *r, const uint64_t *prod)
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
 * na*nb clmul calls; the Karatsuba base case.
 */
static void
gf2x_school(uint64_t *out, const uint64_t *a, size_t na, const uint64_t *b,
            size_t nb, ichor_clmul64_fn cl)
{
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
          uint64_t *sc, ichor_clmul64_fn cl)
{
    size_t lo, hi, i;
    uint64_t *sa, *sb, *p1, *child;

    if (n <= GF2X_KARA_LEAF) {
        gf2x_school(out, a, n, b, n, cl);
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
    gf2x_kara(out, a, b, lo, child, cl);
    gf2x_kara(out + 2u * lo, a + lo, b + lo, hi, child, cl);

    /* sum_a = a_lo + a_hi, sum_b = b_lo + b_hi (low halves zero-extended). */
    for (i = 0; i < lo; i++) {
        sa[i] = a[i] ^ a[lo + i];
        sb[i] = b[i] ^ b[lo + i];
    }
    for (i = lo; i < hi; i++) { /* trailing high limb(s) when n is odd */
        sa[i] = a[lo + i];
        sb[i] = b[lo + i];
    }

    gf2x_kara(p1, sa, sb, hi, child, cl); /* P1 -> p1[0, 2*hi) */

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
    uint64_t *prod = scratch;              /* 2*limbs                 */
    uint64_t *kara = scratch + 2u * limbs; /* 4*limbs + 128           */
    ichor_clmul64_fn cl = ichor_clmul64_resolve();

    gf2x_kara(prod, a, b, limbs, kara, cl);
    gf2x_reduce(ring, r, prod);

    /* scratch holds the secret double-width product and its Karatsuba
     * intermediates (a, b may be private key or error material). */
    ichor_secure_zero(scratch, ring->mul_scratch_limbs * sizeof(uint64_t));
}

/*
 * out = in * x^t for a PUBLIC fixed t in [1, p): shift in left by t bits into a
 * double-width buffer, then fold coefficients >= p back with the shared
 * reduction (x^p == 1).  t enters only as a shift distance and buffer offset,
 * both derived from the public barrel loop counter, so no secret-dependent
 * control flow.  `buf` is caller scratch of 2*limbs u64.
 */
static void
gf2x_rotl_fixed(const ichor_gf2x_ring *ring, uint64_t *out, const uint64_t *in,
                unsigned t, uint64_t *buf)
{
    const size_t limbs = ring->limbs;
    const unsigned wq = t >> 6;  /* whole-limb part of t (public) */
    const unsigned wr = t & 63u; /* intra-limb part of t (public) */
    size_t i;

    memset(buf, 0, 2u * limbs * sizeof(uint64_t));
    if (wr == 0u) {
        for (i = 0; i < limbs; i++)
            buf[i + wq] |= in[i];
    } else {
        for (i = 0; i < limbs; i++) {
            buf[i + wq] |= in[i] << wr;
            buf[i + wq + 1u] |= in[i] >> (64u - wr);
        }
    }
    gf2x_reduce(ring, out, buf);
}

void
ichor_gf2x_rotl_var(const ichor_gf2x_ring *ring, uint64_t *out,
                    const uint64_t *in, uint32_t k, uint64_t *scratch)
{
    const size_t limbs = ring->limbs;
    uint64_t *acc = scratch;              /* limbs   */
    uint64_t *rot = scratch + limbs;      /* limbs   */
    uint64_t *buf = scratch + 2u * limbs; /* 2*limbs */
    unsigned i;
    size_t j;

    memcpy(acc, in, limbs * sizeof(uint64_t));
    for (i = 0; (UINT32_C(1) << i) < (uint32_t)ring->p_bits; i++) {
        /*
         * Opaque mask: 0 or ~0 selected by bit i of the secret amount k.
         * ichor_ct_mask64 routes it through a volatile so the compiler
         * cannot lower the blend below into a branch on the secret bit
         * (clang -O3 was observed doing exactly that).  Formed once per
         * iteration; the inner blend stays branchless and vectorizable.
         */
        const uint64_t mask = ichor_ct_mask64((uint64_t)((k >> i) & 1u));

        gf2x_rotl_fixed(ring, rot, acc, 1u << i, buf);
        for (j = 0; j < limbs; j++)
            acc[j] = (rot[j] & mask) | (acc[j] & ~mask);
    }
    memcpy(out, acc, limbs * sizeof(uint64_t));

    /* acc/rot/buf are rotations of the secret input. */
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
 */
static uint64_t
scatter_bit_at(uint32_t pos)
{
    uint64_t v = 1, m;

    m = (uint64_t)0 - (uint64_t)((pos >> 0) & 1u);
    v = ((v << 1) & m) | (v & ~m);
    m = (uint64_t)0 - (uint64_t)((pos >> 1) & 1u);
    v = ((v << 2) & m) | (v & ~m);
    m = (uint64_t)0 - (uint64_t)((pos >> 2) & 1u);
    v = ((v << 4) & m) | (v & ~m);
    m = (uint64_t)0 - (uint64_t)((pos >> 3) & 1u);
    v = ((v << 8) & m) | (v & ~m);
    m = (uint64_t)0 - (uint64_t)((pos >> 4) & 1u);
    v = ((v << 16) & m) | (v & ~m);
    m = (uint64_t)0 - (uint64_t)((pos >> 5) & 1u);
    v = ((v << 32) & m) | (v & ~m);
    return v;
}

/* All-ones 64-bit mask if a == b, else 0 (branch-free). */
static uint64_t
scatter_word_eq(uint32_t a, uint32_t b)
{
    uint32_t x = a ^ b;
    uint32_t nz = (x | (0u - x)) >> 31; /* 1 if a != b else 0 */

    return (uint64_t)nz - 1u; /* 0 if a != b, all-ones if a == b */
}

void
ichor_gf2x_scatter(uint8_t *block, size_t block_bytes, const uint32_t *idx,
                   uint32_t w, uint32_t base, uint32_t span)
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
     * single-bit mask.  An out-of-span index localizes to a word >= words (or
     * wraps large), matching no word below, so it is never written. */
    for (k = 0; k < w; k++) {
        uint32_t loc = idx[k] - base;

        wpos[k] = loc >> 6;
        bmask[k] = scatter_bit_at(loc & 63u);
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
