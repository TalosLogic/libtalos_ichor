/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * clmul.h - Carry-less (polynomial) multiplication primitive.
 *
 * Provides a single 64x64 -> 128-bit carry-less multiply over F_2[x],
 * dispatched at runtime to the best available backend:
 *   1. PCLMULQDQ   (x86_64; ICHOR_CPU_CLMUL)
 *   2. PMULL       (aarch64; ICHOR_CPU_PMULL)
 *   3. Scalar      (portable constant-time software; always compiled in)
 *
 * This is the shared atom on which polynomial-ring multiplications are
 * built (binary-field mul, GHASH, QC-MDPC circulant mul, ...).  Callers
 * own their own schedule (schoolbook / Karatsuba) and reduction; this
 * layer only multiplies two 64-bit operands as polynomials.
 *
 * All backends -- including the scalar fallback -- are constant-time in
 * their operands, so the primitive is safe on secret inputs.  The
 * dispatch decision is data-independent.
 */

#ifndef ICHOR_CLMUL_H
#define ICHOR_CLMUL_H

#include <stdint.h>

/* Backend actually selected at runtime; reported for tests/diagnostics. */
typedef enum {
    ICHOR_CLMUL_BACKEND_PCLMUL = 1, /* x86_64 PCLMULQDQ           */
    ICHOR_CLMUL_BACKEND_PMULL,      /* aarch64 PMULL              */
    ICHOR_CLMUL_BACKEND_SCALAR      /* portable constant-time SW  */
} ichor_clmul_backend_t;

/*
 * Carry-less product of a and b as polynomials over F_2: the 128-bit
 * result lands in *lo (bits 0..63) and *hi (bits 64..126; bit 127 is
 * always zero for a 64x64 product).  Resolves the backend on first use.
 */
void ichor_clmul64(uint64_t a, uint64_t b, uint64_t *lo, uint64_t *hi);

/*
 * Resolved-backend function pointer, for hot loops.
 *
 * ichor_clmul64() pays a load-acquire on the cached ops pointer per
 * call.  A multi-limb multiply that calls the primitive thousands of
 * times should bind the backend once via ichor_clmul64_resolve() and
 * call the returned pointer directly inside the loop, e.g.
 *
 *     ichor_clmul64_fn cl = ichor_clmul64_resolve();
 *     for (...) cl(a[i], b[j], &lo, &hi);
 *
 * The returned pointer has the same constant-time guarantee.
 */
typedef void (*ichor_clmul64_fn)(uint64_t, uint64_t, uint64_t *, uint64_t *);
ichor_clmul64_fn ichor_clmul64_resolve(void);

/* Backend selected for the running CPU (resolves on first use). */
ichor_clmul_backend_t ichor_clmul_backend(void);

/* Human-readable name of the active backend. */
const char *ichor_clmul_backend_name(void);

/*
 * Whether the active backend is optimal for this CPU or a software fallback
 * (host has hardware carry-less multiply but the accelerated backend was not
 * compiled in) is reported by ichor_clmul_backend_health() in
 * <ichor/backend.h>.
 */

#endif /* ICHOR_CLMUL_H */
