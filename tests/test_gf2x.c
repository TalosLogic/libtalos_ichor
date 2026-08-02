/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_gf2x.c - algebraic KAT / self-test for the runtime-parameterized
 * F_2[x]/(x^p - 1) ring (ichor/gf2x.h).
 *
 * Parameter-driven port of libtalos_syndrome's per-set gf2x self-test: the
 * same ring identities (add, load/store, multiply identity/commutativity/
 * distributivity/cyclic reduction, Itoh-Tsujii inverse, variable rotation)
 * run against several primes so a limb-count- or shift-dependent bug in the
 * generic port is caught.  Inverse is only checked on primes with
 * ord_p(2) = p - 1 (the QC-MDPC sets); the small prime exercises the mul /
 * reduction / rotation paths with a different limb count and top-limb shift.
 */

#include "gf2x.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int total = 0;
static int fails = 0;

#define CHECK(ring, cond, msg)                                                 \
    do {                                                                       \
        total++;                                                               \
        if (!(cond)) {                                                         \
            printf("  FAIL [p=%zu]: %s\n", (ring)->p_bits, (msg));             \
            fails++;                                                           \
        }                                                                      \
    } while (0)

static void
setbits(const ichor_gf2x_ring *ring, uint64_t *poly, const unsigned *exps,
        size_t n)
{
    size_t i;

    memset(poly, 0, ring->limbs * sizeof(uint64_t));
    for (i = 0; i < n; i++)
        poly[exps[i] >> 6] |= UINT64_C(1) << (exps[i] & 63u);
}

static int
eq(const ichor_gf2x_ring *ring, const uint64_t *a, const uint64_t *b)
{
    size_t i;

    for (i = 0; i < ring->limbs; i++)
        if (a[i] != b[i])
            return 0;
    return 1;
}

static void
run_suite(size_t p_bits, int do_inv)
{
    ichor_gf2x_ring rbuf;
    ichor_gf2x_ring *ring = &rbuf;
    size_t L, i;
    uint64_t *zero, *one, *x, *a, *b, *c, *r, *r2, *t, *sc;
    uint8_t *bytes;

    static const unsigned e_x[] = {1};
    static const unsigned e_1px[] = {0, 1};
    static const unsigned e_1px2[] = {0, 2};

    if (ichor_gf2x_ring_init(ring, p_bits) != 0) {
        printf("  FAIL: ring_init(%zu)\n", p_bits);
        total++;
        fails++;
        return;
    }
    L = ring->limbs;

    zero = calloc(L, sizeof(uint64_t));
    one = calloc(L, sizeof(uint64_t));
    x = calloc(L, sizeof(uint64_t));
    a = calloc(L, sizeof(uint64_t));
    b = calloc(L, sizeof(uint64_t));
    c = calloc(L, sizeof(uint64_t));
    r = calloc(L, sizeof(uint64_t));
    r2 = calloc(L, sizeof(uint64_t));
    t = calloc(L, sizeof(uint64_t));
    /* inv_scratch_limbs >= mul/rotl scratch, so one buffer serves all three. */
    sc = calloc(ring->inv_scratch_limbs, sizeof(uint64_t));
    bytes = calloc(ring->block_bytes, 1);

    /* e_mix must reference in-range exponents, so build it from p. */
    const unsigned e_mix[] = {0u, 3u, 64u, (unsigned)(p_bits - 2u)};
    const unsigned e_top[] = {(unsigned)(p_bits - 1u)};

    setbits(ring, zero, NULL, 0);
    setbits(ring, one, NULL, 0);
    one[0] = 1;
    setbits(ring, x, e_x, 1);

    /* add: self-inverse, and (a + b) + b == a. */
    setbits(ring, a, e_mix, 4);
    setbits(ring, b, e_1px, 2);
    ichor_gf2x_add(ring, c, a, a);
    CHECK(ring, eq(ring, c, zero), "a + a == 0");
    ichor_gf2x_add(ring, c, a, b);
    ichor_gf2x_add(ring, c, c, b);
    CHECK(ring, eq(ring, c, a), "(a + b) + b == a");

    /* load/store round-trip. */
    ichor_gf2x_store(ring, bytes, a);
    ichor_gf2x_load(ring, r, bytes);
    CHECK(ring, eq(ring, r, a), "load(store(a)) == a");

    /* Multiplicative identity, both orders. */
    ichor_gf2x_mul(ring, r, a, one, sc);
    CHECK(ring, eq(ring, r, a), "a * 1 == a");
    ichor_gf2x_mul(ring, r, one, a, sc);
    CHECK(ring, eq(ring, r, a), "1 * a == a");

    /* (1 + x)^2 == 1 + x^2 (cross term 2x vanishes over F_2). */
    setbits(ring, b, e_1px, 2);
    setbits(ring, c, e_1px2, 2);
    ichor_gf2x_mul(ring, r, b, b, sc);
    CHECK(ring, eq(ring, r, c), "(1+x)^2 == 1+x^2");

    /* Cyclic reduction: x^{p-1} * x == 1 (x^p folds to x^0). */
    setbits(ring, a, e_top, 1);
    ichor_gf2x_mul(ring, r, a, x, sc);
    CHECK(ring, eq(ring, r, one), "x^{p-1} * x == 1");

    /* Commutativity: a*b == b*a. */
    setbits(ring, a, e_mix, 4);
    setbits(ring, b, e_top, 1);
    ichor_gf2x_add(ring, b, b, x); /* b = x^{p-1} + x */
    ichor_gf2x_mul(ring, r, a, b, sc);
    ichor_gf2x_mul(ring, r2, b, a, sc);
    CHECK(ring, eq(ring, r, r2), "a*b == b*a");

    /* Distributivity: a*(b + c) == a*b + a*c. */
    setbits(ring, c, e_1px2, 2);
    ichor_gf2x_add(ring, t, b, c);
    ichor_gf2x_mul(ring, r, a, t, sc);
    ichor_gf2x_mul(ring, r2, a, b, sc);
    ichor_gf2x_mul(ring, t, a, c, sc);
    ichor_gf2x_add(ring, r2, r2, t);
    CHECK(ring, eq(ring, r, r2), "a*(b+c) == a*b + a*c");

    if (do_inv) {
        /* inv(1) == 1. */
        CHECK(ring, ichor_gf2x_inv(ring, r, one, sc) == 0 && eq(ring, r, one),
              "inv(1) == 1");
        /* inv(x) == x^{p-1}, since x * x^{p-1} == x^p == 1. */
        setbits(ring, a, e_top, 1);
        CHECK(ring, ichor_gf2x_inv(ring, r, x, sc) == 0 && eq(ring, r, a),
              "inv(x) == x^{p-1}");
        /* Round-trip on an odd-weight unit: a * inv(a) == 1. */
        {
            static const unsigned e_mix3[] = {0, 1, 2};
            setbits(ring, a, e_mix3, 3);
            CHECK(ring, ichor_gf2x_inv(ring, r, a, sc) == 0,
                  "inv(a) invertible");
            ichor_gf2x_mul(ring, c, a, r, sc);
            CHECK(ring, eq(ring, c, one), "a * inv(a) == 1");
        }
    }

    /* Variable-amount rotation vs the trusted multiply: rotl_var(a, k) == a*x^k
     * for public k < p, spanning sub-limb / limb-aligned / cross-limb / near-p
     * offsets so every internal fixed rotate-by-2^i pass is exercised. */
    {
        const unsigned rot_amts[] = {0u,
                                     1u,
                                     5u,
                                     63u,
                                     64u,
                                     65u,
                                     127u,
                                     (unsigned)(p_bits / 2u),
                                     (unsigned)(p_bits - 2u),
                                     (unsigned)(p_bits - 1u)};
        setbits(ring, a, e_mix, 4);
        for (i = 0; i < sizeof(rot_amts) / sizeof(rot_amts[0]); i++) {
            unsigned amt = rot_amts[i];
            setbits(ring, b, &amt, 1); /* b = x^amt */
            ichor_gf2x_mul(ring, r, a, b, sc);
            ichor_gf2x_rotl_var(ring, r2, a, (uint32_t)amt, sc);
            CHECK(ring, eq(ring, r, r2), "rotl_var(a,k) == a*x^k");
        }

        /* k == p is the identity (x^p == 1). */
        ichor_gf2x_rotl_var(ring, r2, a, (uint32_t)p_bits, sc);
        CHECK(ring, eq(ring, r2, a), "rotl_var(a,p) == a");

        /* Aliasing: out == in must be safe.  rotl_var(a,1) == a*x. */
        memcpy(r, a, L * sizeof(uint64_t));
        ichor_gf2x_rotl_var(ring, r, r, 1u, sc);
        setbits(ring, b, e_x, 1);
        ichor_gf2x_mul(ring, r2, a, b, sc);
        CHECK(ring, eq(ring, r, r2), "rotl_var alias out==in");
    }

    free(zero);
    free(one);
    free(x);
    free(a);
    free(b);
    free(c);
    free(r);
    free(r2);
    free(t);
    free(sc);
    free(bytes);
}

/* Naive per-position reference scatter (sets only positions in [0, span)). */
static void
scatter_ref(uint8_t *block, size_t block_bytes, const uint32_t *idx, uint32_t w,
            uint32_t base, uint32_t span)
{
    uint32_t k;

    memset(block, 0, block_bytes);
    for (k = 0; k < w; k++) {
        uint32_t loc = idx[k] - base;

        if (loc < span)
            block[loc >> 3] |= (uint8_t)(1u << (loc & 7u));
    }
}

/*
 * ichor_gf2x_scatter vs the naive reference over the meaningful [0, p) bits, for
 * every shipped prime, scattering each of the n0 circulant blocks of a random
 * global support.  This exercises the adjacent-block filtering (indices from
 * other blocks must not appear in [0, p)) and the base offset.  Comparison masks
 * the top-byte pad, since an adjacent index may set a pad bit there by design
 * (consumers canonicalize on load).
 */
static void
run_scatter_tests(void)
{
    static const struct {
        uint32_t p, n0, w;
    } cfg[] = {
        {7829u, 5u, 57u},
        {13613u, 2u, 130u},
        {24733u, 5u, 113u},
        {43451u, 2u, 261u},
    };
    uint32_t seed = 0x1234567u;
    size_t ci;

    for (ci = 0; ci < sizeof cfg / sizeof cfg[0]; ci++) {
        uint32_t p = cfg[ci].p, n0 = cfg[ci].n0, w = cfg[ci].w, n = n0 * p, b,
                 k;
        size_t bb = (p + 7u) / 8u;
        uint8_t topmask = (p & 7u) ? (uint8_t)((1u << (p & 7u)) - 1u) : 0xFFu;
        uint32_t *idx = malloc((size_t)w * sizeof *idx);
        uint8_t *got = malloc(bb), *ref = malloc(bb);
        int okall = 1;

        if (idx == NULL || got == NULL || ref == NULL) {
            printf("  FAIL scatter alloc\n");
            fails++;
            total++;
            free(idx);
            free(got);
            free(ref);
            return;
        }
        for (k = 0; k < w; k++) {
            seed = seed * 1103515245u + 12345u;
            idx[k] = seed % n;
        }
        for (b = 0; b < n0; b++) {
            ichor_gf2x_scatter(got, bb, idx, w, b * p, p);
            scatter_ref(ref, bb, idx, w, b * p, p);
            got[bb - 1] &= topmask; /* drop pad bits (canonicalize) */
            if (memcmp(got, ref, bb) != 0)
                okall = 0;
        }
        total++;
        if (!okall) {
            printf("  FAIL scatter p=%u\n", p);
            fails++;
        }
        free(idx);
        free(got);
        free(ref);
    }
}

int
main(void)
{
    printf("=== ichor gf2x ring self-test ===\n");

    /* Small prime: fast, exercises a different limb count and top-limb shift
     * (191 % 64 == 63).  do_inv=0 (2 is not primitive mod 191). */
    run_suite(191u, /*do_inv=*/0);

    /* QC-MDPC sets (ord_p(2) = p - 1, so Itoh-Tsujii inverse applies). */
    run_suite(13613u, /*do_inv=*/1); /* n0=2, lambda128 */
    run_suite(7829u, /*do_inv=*/1);  /* n0=5, lambda128 */
    run_suite(43451u, /*do_inv=*/1); /* n0=2, lambda256 */
    run_suite(24733u, /*do_inv=*/1); /* n0=5, lambda256 */

    /* Fixed-weight support scatter (shared with the syndrome sampler and the
     * voleith opener). */
    run_scatter_tests();

    printf("\n%d / %d checks passed\n", total - fails, total);
    return fails == 0 ? 0 : 1;
}
