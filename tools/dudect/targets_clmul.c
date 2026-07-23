/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Constant-time software carry-less-multiply targets.  Validates that
 * clmul64_scalar -- the portable fallback selected when no PCLMULQDQ /
 * PMULL hardware is available -- exhibits no secret-dependent runtime
 * variation.  (The dudect harness library is built without the
 * ICHOR_HAVE_* hardware defines, so ichor_clmul64 dispatches to the
 * scalar backend here.  The hardware paths are single carry-less-
 * multiply instructions, constant-time by ISA specification, and are
 * out of scope.)
 *
 * Two descriptors split the operands by role:
 *
 *   _b  -- b varies across classes (all-zero vs all-ones), a fixed.
 *          b drives the per-bit 0/all-ones mask that replaces the
 *          conditional XOR; this is where a leak would surface.
 *   _a  -- a varies across classes, b fixed all-ones so every bit
 *          step executes.  Exercises the shift/accumulate data path
 *          independently of the mask.
 */
#include "dudect_target.h"

#include "clmul.h"

#include <stdint.h>

static volatile uint64_t clmul_target_sink;

typedef struct {
    uint64_t a, b;
} clmul_state_t;

/* ----- multiplier-bit pair (b varies) -------------------------------- */

static void
clmul_b_setup(int cls, void *state)
{
    clmul_state_t *s = (clmul_state_t *)state;
    s->a = 0x0123456789abcdefULL;
    s->b = (cls == 0) ? 0x0000000000000000ULL : 0xffffffffffffffffULL;
}

static void
clmul_b_run(const void *state)
{
    const clmul_state_t *s = (const clmul_state_t *)state;
    uint64_t lo, hi;
    ichor_clmul64(s->a, s->b, &lo, &hi);
    clmul_target_sink ^= lo ^ hi;
}

const dudect_target_t target_clmul64_scalar_b = {
    .name = "clmul64_scalar_b",
    .setup_class = clmul_b_setup,
    .run = clmul_b_run,
    .state_size = sizeof(clmul_state_t),
    .reps_per_trial = 2000,
};

/* ----- multiplicand-bit pair (a varies) ------------------------------ */

static void
clmul_a_setup(int cls, void *state)
{
    clmul_state_t *s = (clmul_state_t *)state;
    s->a = (cls == 0) ? 0x0000000000000000ULL : 0xffffffffffffffffULL;
    s->b = 0xffffffffffffffffULL;
}

static void
clmul_a_run(const void *state)
{
    const clmul_state_t *s = (const clmul_state_t *)state;
    uint64_t lo, hi;
    ichor_clmul64(s->a, s->b, &lo, &hi);
    clmul_target_sink ^= lo ^ hi;
}

const dudect_target_t target_clmul64_scalar_a = {
    .name = "clmul64_scalar_a",
    .setup_class = clmul_a_setup,
    .run = clmul_a_run,
    .state_size = sizeof(clmul_state_t),
    .reps_per_trial = 2000,
};
