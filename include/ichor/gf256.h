/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf256.h - GF(2^8) region-multiply primitive (polynomial 0x11B).
 *
 * Multiplies a contiguous byte region by a single GF(2^8) scalar, in the
 * field F_2[x]/(x^8 + x^4 + x^3 + x + 1) = 0x11B.  That is the AES / Rijndael
 * polynomial, so a future GFNI backend (GF2P8MULB, hardwired to 0x11B) is
 * directly compatible, and it matches the field FAEST and voleith's gf8 use.
 *
 * Two region operations, dispatched at runtime to the best backend:
 *   mul_region:    dst[i]  = a (x) src[i]
 *   muladd_region: dst[i] ^= a (x) src[i]   (the RLNC recode / RS encode axpy)
 *
 * Backends:
 *   1. SSSE3   (x86_64; split-nibble vpshufb, ICHOR_CPU_SSSE3)
 *   2. Scalar  (portable constant-time software; always compiled in)
 * GFNI (x86) and NEON TBL (aarch64) backends are reserved for later.
 *
 * All backends, including the scalar fallback, are constant-time in both the
 * scalar `a` and the region data (the vpshufb path indexes a register table by
 * data nibbles, a fixed-latency shuffle, and builds its per-scalar tables with
 * the constant-time scalar multiply; no secret value indexes memory).  The
 * dispatch decision is data-independent.  The region length is public.
 */

#ifndef ICHOR_GF256_H
#define ICHOR_GF256_H

#include <stddef.h>
#include <stdint.h>

/* Backend actually selected at runtime; reported for tests/diagnostics. */
typedef enum {
    ICHOR_GF256_BACKEND_GFNI = 1, /* x86_64 GFNI GF2P8MULB            */
    ICHOR_GF256_BACKEND_SSSE3,    /* x86_64 split-nibble vpshufb      */
    ICHOR_GF256_BACKEND_NEON,     /* aarch64 NEON TBL      (reserved) */
    ICHOR_GF256_BACKEND_SCALAR,   /* portable constant-time software  */
    ICHOR_GF256_BACKEND_AVX2      /* x86_64 split-nibble vpshufb, YMM */
} ichor_gf256_backend_t;

/* dst[i] = a (x) src[i] for i in [0, n).  dst and src may alias only if
 * identical (dst == src); otherwise they must not overlap. */
void ichor_gf256_mul_region(uint8_t *dst, const uint8_t *src, uint8_t a,
                            size_t n);

/* dst[i] ^= a (x) src[i] for i in [0, n).  Same aliasing rule as mul_region. */
void ichor_gf256_muladd_region(uint8_t *dst, const uint8_t *src, uint8_t a,
                               size_t n);

/*
 * Resolved-backend function pointers, for hot loops that call a region op
 * many times (e.g. an RLNC encode sweeping coefficients).  Binding the
 * backend once avoids the per-call load-acquire on the cached ops pointer:
 *
 *     ichor_gf256_muladd_region_fn mac = ichor_gf256_muladd_region_resolve();
 *     for (...) mac(dst, src[j], coeff[j], n);
 *
 * The returned pointers carry the same constant-time guarantee.
 */
typedef void (*ichor_gf256_region_fn)(uint8_t *, const uint8_t *, uint8_t,
                                      size_t);
ichor_gf256_region_fn ichor_gf256_mul_region_resolve(void);
ichor_gf256_region_fn ichor_gf256_muladd_region_resolve(void);

/* Backend selected for the running CPU (resolves on first use). */
ichor_gf256_backend_t ichor_gf256_backend(void);
const char *ichor_gf256_backend_name(void);

#endif /* ICHOR_GF256_H */
