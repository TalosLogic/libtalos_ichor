/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf2x_vpclmul.c - VPCLMULQDQ (x86_64) wide schoolbook carry-less product, the
 * Karatsuba base case (school op) for ichor_gf2x_mul.
 *
 * Compiled with -mvpclmulqdq -mavx2 per-TU; the rest of the library does not
 * require those flags.  On shipping parts VPCLMULQDQ (Ice Lake / Zen 3 and
 * later) is a strict superset of AVX2, so the dispatch (src/gf2x.c) selects
 * this backend only when ichor_cpu_features() reports both ICHOR_CPU_AVX2 and
 * ICHOR_CPU_VPCLMULQDQ.  This file compiles to an empty object when
 * ICHOR_HAVE_GF2X_VPCLMUL is not defined.
 *
 * _mm256_clmulepi64_epi128 computes an independent 64x64 -> 128 carry-less
 * product in each of the two 128-bit lanes, so one instruction yields two
 * output columns and keeps the halves in registers (no indirect call, no lo/hi
 * memory round-trip).  The products and the XOR accumulation into out are
 * exactly those of ichor_gf2x_school_scalar; XOR is associative and
 * commutative, so computing two columns per step changes nothing, and the
 * output is bit-identical.  na and nb are public, so control flow is
 * data-independent.
 */

#ifdef ICHOR_HAVE_GF2X_VPCLMUL

#include "gf2x_dispatch.h"

#include <immintrin.h>
#include <string.h>

void
gf2x_school_vpclmul(uint64_t *out, const uint64_t *a, size_t na,
                    const uint64_t *b, size_t nb)
{
    size_t i, j;

    memset(out, 0, (na + nb) * sizeof(uint64_t));
    for (i = 0; i < na; i++) {
        const __m256i av = _mm256_set1_epi64x((long long)a[i]);

        /*
         * Column pairs (j, j + 1): imm 0x00 multiplies the low 64 bits of each
         * lane, so lane 0 holds a[i] * b[j] and lane 1 holds a[i] * b[j + 1].
         * The 256-bit result is four 64-bit words: lane 0 {lo, hi} at indices
         * 0, 1 and lane 1 {lo, hi} at indices 2, 3.
         */
        for (j = 0; j + 1u < nb; j += 2) {
            const __m256i bv =
                _mm256_set_epi64x(0, (long long)b[j + 1u], 0, (long long)b[j]);
            const __m256i p = _mm256_clmulepi64_epi128(av, bv, 0x00);

            out[i + j] ^= (uint64_t)_mm256_extract_epi64(p, 0);
            out[i + j + 1u] ^= (uint64_t)_mm256_extract_epi64(p, 1);
            out[i + j + 1u] ^= (uint64_t)_mm256_extract_epi64(p, 2);
            out[i + j + 2u] ^= (uint64_t)_mm256_extract_epi64(p, 3);
        }
        /* Odd trailing column: a single 128-bit PCLMUL (implied by
         * VPCLMULQDQ). */
        for (; j < nb; j++) {
            const __m128i p =
                _mm_clmulepi64_si128(_mm_set1_epi64x((long long)a[i]),
                                     _mm_set1_epi64x((long long)b[j]), 0x00);

            out[i + j] ^= (uint64_t)_mm_extract_epi64(p, 0);
            out[i + j + 1u] ^= (uint64_t)_mm_extract_epi64(p, 1);
        }
    }
}

#else /* !ICHOR_HAVE_GF2X_VPCLMUL */

/* ISO C forbids an empty translation unit, and -Wpedantic / -Werror reject
 * one; give the guarded-out build a single harmless declaration. */
typedef int ichor_gf2x_vpclmul_translation_unit_not_empty;

#endif /* ICHOR_HAVE_GF2X_VPCLMUL */
