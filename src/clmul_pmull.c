/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * clmul_pmull.c - ARMv8 PMULL implementation of the 64x64 carry-less mul.
 *
 * Compiled with -march=armv8-a+crypto (if needed) per-TU; the rest of the
 * library does not require that flag.  This file compiles to an empty
 * object when ICHOR_HAVE_PMULL is not defined.
 */

#ifdef ICHOR_HAVE_PMULL

#include "clmul_dispatch.h"

#include <arm_neon.h>

static void
clmul64_pmull(uint64_t a, uint64_t b, uint64_t *lo, uint64_t *hi)
{
    poly128_t r = vmull_p64((poly64_t)a, (poly64_t)b);

    *lo = (uint64_t)vgetq_lane_u64(vreinterpretq_u64_p128(r), 0);
    *hi = (uint64_t)vgetq_lane_u64(vreinterpretq_u64_p128(r), 1);
}

/* PMULL has no 2-wide form in this primitive; run the single mul twice. */
static void
clmul64_x2_pmull(uint64_t a0, uint64_t b0, uint64_t a1, uint64_t b1,
                 uint64_t lo[2], uint64_t hi[2])
{
    clmul64_pmull(a0, b0, &lo[0], &hi[0]);
    clmul64_pmull(a1, b1, &lo[1], &hi[1]);
}

const ichor_clmul_ops_t ichor_clmul_ops_pmull = {
    .mul = clmul64_pmull,
    .mul_x2 = clmul64_x2_pmull,
    .backend_tag = ICHOR_CLMUL_BACKEND_PMULL,
    .name = "pmull",
};

#else /* !ICHOR_HAVE_PMULL */

/* ISO C forbids an empty translation unit, and -Wpedantic / -Werror reject
 * one; give the guarded-out build a single harmless declaration. */
typedef int ichor_clmul_pmull_translation_unit_not_empty;

#endif /* ICHOR_HAVE_PMULL */
