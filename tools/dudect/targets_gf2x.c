/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Constant-time targets for the F_2[x]/(x^p - 1) ring (ichor/gf2x.h).
 * Validates that the two secret-consuming paths exhibit no
 * secret-dependent runtime variation on the scalar-clmul software build
 * (the dudect core is compiled without the ICHOR_HAVE_* hardware defines,
 * so ichor_clmul64 dispatches to the constant-time scalar backend):
 *
 *   _mul_operand  -- a varies (weight-1 vs dense), b fixed.  The multiply
 *                    schedule is a public function of p, so operand
 *                    content/weight must not move the timing.
 *   _rotl_amount  -- the SECRET rotation amount k varies (small vs near-p),
 *                    applied to a fixed representative weight-t sparse vector
 *                    (NOT the rotation-invariant all-ones element, so the
 *                    barrel actually moves bits and the target retains power
 *                    against future data-dependent regressions).  rotl_var is
 *                    a fixed barrel of public rotations selected by the bits
 *                    of k; only the select mask depends on k, so k must not
 *                    move the timing.
 *   _ct_select    -- the SECRET selector bit varies (0 vs 1).  Guards the
 *                    ichor_ct_mask64 / ichor_ct_select64 primitives: forming
 *                    the mask and blending must not compile to a branch on
 *                    the bit (the exact failure mode that was fixed in
 *                    gf2x_rotl_var).
 *   _scatter      -- the SECRET fixed-weight support varies (clustered vs
 *                    spread).  ichor_gf2x_scatter (shared by the syndrome
 *                    sampler and the voleith opener) visits every word and
 *                    index and never indexes memory by a support value, so the
 *                    support content must not move the timing.
 *
 * A representative prime (13613, the n0=2 / lambda128 set) is used; the
 * control flow is identical across sets, so one prime suffices.
 */
#include "dudect_target.h"

#include "gf2x.h"
#include "util.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define GF2X_DUDECT_P 13613u
#define GF2X_DUDECT_SPARSE_WT                                                  \
    130u /* error weight t of the n0=2 / lambda128 set */

static ichor_gf2x_ring g_ring;
static uint64_t *g_a0, *g_a1, *g_b, *g_r, *g_sc, *g_sparse;
static int g_ready;

static volatile uint64_t gf2x_target_sink;

static void
gf2x_init_once(void)
{
    size_t L, i;

    if (g_ready)
        return;

    (void)ichor_gf2x_ring_init(&g_ring, GF2X_DUDECT_P);
    L = g_ring.limbs;

    g_a0 = calloc(L, sizeof(uint64_t));
    g_a1 = calloc(L, sizeof(uint64_t));
    g_b = calloc(L, sizeof(uint64_t));
    g_r = calloc(L, sizeof(uint64_t));
    g_sc = calloc(g_ring.mul_scratch_limbs, sizeof(uint64_t));

    /* a0: weight-1.  a1: dense (every coefficient set), top limb masked. */
    g_a0[0] = 1;
    for (i = 0; i < L; i++)
        g_a1[i] = ~UINT64_C(0);
    g_a1[L - 1] &= g_ring.top_mask;

    /* b: a fixed mid-density pattern. */
    for (i = 0; i < L; i++)
        g_b[i] = UINT64_C(0xa5a5a5a5a5a5a5a5);
    g_b[L - 1] &= g_ring.top_mask;

    /*
     * sparse: a fixed weight-t vector with the set bits spread across the
     * ring (positions w * floor(p / t)).  Unlike the all-ones element this
     * is NOT rotation-invariant, so rotl_var actually moves bits under it.
     */
    g_sparse = calloc(L, sizeof(uint64_t));
    {
        size_t step = GF2X_DUDECT_P / GF2X_DUDECT_SPARSE_WT;
        unsigned w;

        for (w = 0; w < GF2X_DUDECT_SPARSE_WT; w++) {
            size_t pos = (size_t)w * step;
            g_sparse[pos >> 6] |= (uint64_t)1 << (pos & 63u);
        }
    }

    g_ready = 1;
}

typedef struct {
    int cls;
} gf2x_state_t;

/* ----- multiply: secret operand a (weight-1 vs dense) ---------------- */

static void
gf2x_mul_setup(int cls, void *state)
{
    gf2x_init_once();
    ((gf2x_state_t *)state)->cls = cls;
}

static void
gf2x_mul_run(const void *state)
{
    const gf2x_state_t *s = (const gf2x_state_t *)state;
    const uint64_t *a = s->cls ? g_a1 : g_a0;

    ichor_gf2x_mul(&g_ring, g_r, a, g_b, g_sc);
    gf2x_target_sink ^= g_r[0];
}

const dudect_target_t target_gf2x_mul_operand = {
    .name = "gf2x_mul_operand",
    .setup_class = gf2x_mul_setup,
    .run = gf2x_mul_run,
    .state_size = sizeof(gf2x_state_t),
    .reps_per_trial = 8,
};

/* ----- rotate: secret amount k (small vs near-p) --------------------- */

static void
gf2x_rotl_setup(int cls, void *state)
{
    gf2x_init_once();
    ((gf2x_state_t *)state)->cls = cls;
}

static void
gf2x_rotl_run(const void *state)
{
    const gf2x_state_t *s = (const gf2x_state_t *)state;
    uint32_t k = s->cls ? (uint32_t)(GF2X_DUDECT_P - 1u) : 1u;

    ichor_gf2x_rotl_var(&g_ring, g_r, g_sparse, k, g_sc);
    gf2x_target_sink ^= g_r[0];
}

const dudect_target_t target_gf2x_rotl_amount = {
    .name = "gf2x_rotl_amount",
    .setup_class = gf2x_rotl_setup,
    .run = gf2x_rotl_run,
    .state_size = sizeof(gf2x_state_t),
    .reps_per_trial = 8,
};

/* ----- ct-select: secret selector bit (0 vs 1) ---------------------- */
/*
 * Guards ichor_ct_mask64 / ichor_ct_select64.  The mask is formed once from
 * the secret bit, then a full ring's worth of selects blend g_sparse against
 * g_b.  Neither the mask formation nor the blend may depend on the bit; if a
 * compiler lowers the select to a branch on the bit (as clang -O3 once did to
 * gf2x_rotl_var), the two classes diverge in timing.
 */
static void
gf2x_ct_select_setup(int cls, void *state)
{
    gf2x_init_once();
    ((gf2x_state_t *)state)->cls = cls;
}

static void
gf2x_ct_select_run(const void *state)
{
    const gf2x_state_t *s = (const gf2x_state_t *)state;
    uint64_t mask = ichor_ct_mask64((uint64_t)s->cls);
    size_t j;

    for (j = 0; j < g_ring.limbs; j++)
        g_r[j] = ichor_ct_select64(mask, g_sparse[j], g_b[j]);
    gf2x_target_sink ^= g_r[0];
}

const dudect_target_t target_gf2x_ct_select = {
    .name = "gf2x_ct_select",
    .setup_class = gf2x_ct_select_setup,
    .run = gf2x_ct_select_run,
    .state_size = sizeof(gf2x_state_t),
    .reps_per_trial = 8,
};

/* ----- invert: secret operand a (weight-1 vs dense unit) ------------- */
/*
 * The Itoh-Tsujii addition chain is a fixed function of the public p (its shape
 * is the bit pattern of p - 2), so the secret unit a must not move the timing.
 * Both classes are units: class 0 is the weight-1 element a = 1 (g_a0), class 1
 * is the dense odd-weight element g_a_dense.  inv takes inv_scratch_limbs of
 * caller scratch and allocates nothing.
 */
static uint64_t *g_inv_sc, *g_a_dense;

static void
gf2x_inv_setup(int cls, void *state)
{
    gf2x_init_once();
    if (g_inv_sc == NULL) {
        size_t i;

        g_inv_sc = calloc(g_ring.inv_scratch_limbs, sizeof(uint64_t));
        g_a_dense = calloc(g_ring.limbs, sizeof(uint64_t));
        /* Every coefficient set -> weight p (odd), a unit. */
        for (i = 0; i < g_ring.limbs; i++)
            g_a_dense[i] = ~UINT64_C(0);
        g_a_dense[g_ring.limbs - 1] &= g_ring.top_mask;
    }
    ((gf2x_state_t *)state)->cls = cls;
}

static void
gf2x_inv_run(const void *state)
{
    const gf2x_state_t *s = (const gf2x_state_t *)state;
    const uint64_t *a = s->cls ? g_a_dense : g_a0;

    (void)ichor_gf2x_inv(&g_ring, g_r, a, g_inv_sc);
    gf2x_target_sink ^= g_r[0];
}

const dudect_target_t target_gf2x_inv = {
    .name = "gf2x_inv",
    .setup_class = gf2x_inv_setup,
    .run = gf2x_inv_run,
    .state_size = sizeof(gf2x_state_t),
    .reps_per_trial = 1,
};

/* ----- scatter: secret support (clustered vs spread) ---------------- */
/*
 * ichor_gf2x_scatter (shared by the syndrome sampler and the voleith opener)
 * visits every output word and every index regardless of the support values and
 * never uses an index as a memory address, so two supports of the same weight
 * (class 0 clustered at the low positions, class 1 spread across the ring) must
 * not diverge in timing.  Reduced params: one block of the n0=2/lambda128 prime
 * at the set's weight t; the control flow is size-independent, so this suffices.
 */
static uint32_t *g_idx0, *g_idx1;
static uint8_t *g_block;

static void
gf2x_scatter_setup(int cls, void *state)
{
    gf2x_init_once();
    if (g_block == NULL) {
        size_t bb = (GF2X_DUDECT_P + 7u) / 8u;
        uint32_t step = GF2X_DUDECT_P / GF2X_DUDECT_SPARSE_WT;
        unsigned k;

        g_idx0 = calloc(GF2X_DUDECT_SPARSE_WT, sizeof(uint32_t));
        g_idx1 = calloc(GF2X_DUDECT_SPARSE_WT, sizeof(uint32_t));
        g_block = calloc(bb, 1);
        for (k = 0; k < GF2X_DUDECT_SPARSE_WT; k++) {
            g_idx0[k] = k;                  /* clustered at the low positions */
            g_idx1[k] = (uint32_t)k * step; /* spread across [0, p)      */
        }
    }
    ((gf2x_state_t *)state)->cls = cls;
}

static void
gf2x_scatter_run(const void *state)
{
    const gf2x_state_t *s = (const gf2x_state_t *)state;
    const uint32_t *idx = s->cls ? g_idx1 : g_idx0;
    size_t bb = (GF2X_DUDECT_P + 7u) / 8u;

    ichor_gf2x_scatter(g_block, bb, idx, GF2X_DUDECT_SPARSE_WT, 0u,
                       GF2X_DUDECT_P);
    gf2x_target_sink ^= g_block[0];
}

const dudect_target_t target_gf2x_scatter = {
    .name = "gf2x_scatter",
    .setup_class = gf2x_scatter_setup,
    .run = gf2x_scatter_run,
    .state_size = sizeof(gf2x_state_t),
    .reps_per_trial = 8,
};
