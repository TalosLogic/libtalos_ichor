/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * clmul_pclmul.c - PCLMULQDQ implementation of the 64x64 carry-less mul.
 *
 * Compiled with -mpclmul -msse2 -msse4.1 per-TU; the rest of the library
 * does not require those flags.  This file compiles to an empty object
 * when ICHOR_HAVE_CLMUL is not defined.
 */

#ifdef ICHOR_HAVE_CLMUL

#include "clmul_dispatch.h"

#include <emmintrin.h>
#include <smmintrin.h>
#include <wmmintrin.h>

static void
clmul64_pclmul(uint64_t a, uint64_t b, uint64_t *lo, uint64_t *hi)
{
    __m128i va = _mm_set_epi64x(0, (long long)a);
    __m128i vb = _mm_set_epi64x(0, (long long)b);
    __m128i p = _mm_clmulepi64_si128(va, vb, 0x00);

    *lo = (uint64_t)_mm_extract_epi64(p, 0);
    *hi = (uint64_t)_mm_extract_epi64(p, 1);
}

/* 128-bit PCLMULQDQ has no 2-wide form; run the single mul twice.  (A
 * 256-bit VPCLMULQDQ path was measured a wash with this pair on the clmul
 * units of current x86 clients, so it is not carried.) */
static void
clmul64_x2_pclmul(uint64_t a0, uint64_t b0, uint64_t a1, uint64_t b1,
                  uint64_t lo[2], uint64_t hi[2])
{
    clmul64_pclmul(a0, b0, &lo[0], &hi[0]);
    clmul64_pclmul(a1, b1, &lo[1], &hi[1]);
}

const ichor_clmul_ops_t ichor_clmul_ops_pclmul = {
    .mul = clmul64_pclmul,
    .mul_x2 = clmul64_x2_pclmul,
    .backend_tag = ICHOR_CLMUL_BACKEND_PCLMUL,
    .name = "pclmul",
};

#else /* !ICHOR_HAVE_CLMUL */

/* ISO C forbids an empty translation unit, and -Wpedantic / -Werror reject
 * one; give the guarded-out build a single harmless declaration. */
typedef int ichor_clmul_pclmul_translation_unit_not_empty;

#endif /* ICHOR_HAVE_CLMUL */
