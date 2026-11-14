/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf16.h - GF(2^16) region-multiply primitive (polynomial 0x1100B).
 *
 * Multiplies a contiguous array of GF(2^16) elements by a single field scalar,
 * in F_2[x]/(x^16 + x^12 + x^3 + x + 1) (reduction constant 0x100B).  That is
 * the field voleith's RLNC / GF(2^16) erasure coding use, and the natural field
 * for GF(2^16) network coding generally.  Elements are host-order uint16_t;
 * callers that hold a wire byte order convert at the boundary, not per element.
 *
 * Two region operations, dispatched at runtime to the best backend:
 *   mul_region:    dst[i]  = a (x) src[i]
 *   muladd_region: dst[i] ^= a (x) src[i]   (the RLNC recode / decode axpy)
 *
 * Backends:
 *   1. SSSE3   (x86_64; split-nibble vpshufb over the four nibbles of a 16-bit
 *              element, deinterleaving the low/high byte planes, ICHOR_CPU_SSSE3)
 *   2. Scalar  (portable constant-time software; always compiled in)
 * GFNI-assisted and NEON TBL backends are reserved for later.
 *
 * All backends, including the scalar fallback, are constant-time in both the
 * scalar `a` and the region data (the vpshufb path indexes register tables by
 * data nibbles and builds its per-scalar tables with the constant-time scalar
 * multiply; no secret value indexes memory).  The dispatch decision is
 * data-independent.  The element count is public.
 */

#ifndef ICHOR_GF16_H
#define ICHOR_GF16_H

#include <stddef.h>
#include <stdint.h>

/* Backend actually selected at runtime; reported for tests/diagnostics. */
typedef enum {
    ICHOR_GF16_BACKEND_SSSE3 = 1, /* x86_64 split-nibble vpshufb      */
    ICHOR_GF16_BACKEND_NEON,      /* aarch64 NEON TBL      (reserved) */
    ICHOR_GF16_BACKEND_SCALAR,    /* portable constant-time software  */
    ICHOR_GF16_BACKEND_GFNI       /* x86_64 GFNI affine (fixed-scalar) */
} ichor_gf16_backend_t;

/* dst[i] = a (x) src[i] for i in [0, n) elements.  dst and src may alias only
 * if identical (dst == src); otherwise they must not overlap. */
void ichor_gf16_mul_region(uint16_t *dst, const uint16_t *src, uint16_t a,
                           size_t n);

/* dst[i] ^= a (x) src[i] for i in [0, n).  Same aliasing rule as mul_region. */
void ichor_gf16_muladd_region(uint16_t *dst, const uint16_t *src, uint16_t a,
                              size_t n);

/*
 * Resolved-backend function pointers, for hot loops that call a region op many
 * times (e.g. an RLNC decode's Gaussian elimination).  Binding the backend
 * once avoids the per-call load-acquire on the cached ops pointer.  The
 * returned pointers carry the same constant-time guarantee.
 */
typedef void (*ichor_gf16_region_fn)(uint16_t *, const uint16_t *, uint16_t,
                                     size_t);
ichor_gf16_region_fn ichor_gf16_mul_region_resolve(void);
ichor_gf16_region_fn ichor_gf16_muladd_region_resolve(void);

/* Backend selected for the running CPU (resolves on first use). */
ichor_gf16_backend_t ichor_gf16_backend(void);
const char *ichor_gf16_backend_name(void);

#endif /* ICHOR_GF16_H */
