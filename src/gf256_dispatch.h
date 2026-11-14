/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf256_dispatch.h - Internal GF(2^8) region-multiply ops-table and dispatch.
 *
 * Not in include/; not part of the public API.  Consumed by:
 *   src/gf256.c        (publishes ichor_gf256_ops, runs init, scalar table)
 *   src/gf256_ssse3.c  (defines ichor_gf256_ops_ssse3)
 *
 * The SSSE3 ops table is guarded by ICHOR_HAVE_GF256_SSSE3, the same macro
 * that gates its TU.  ichor_gf256_ops points to whichever table
 * ichor_gf256_dispatch_init() selects.
 */

#ifndef ICHOR_GF256_DISPATCH_H
#define ICHOR_GF256_DISPATCH_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "gf256.h"

typedef struct {
    void (*mul_region)(uint8_t *, const uint8_t *, uint8_t, size_t);
    void (*muladd_region)(uint8_t *, const uint8_t *, uint8_t, size_t);
    ichor_gf256_backend_t backend_tag;
    const char *name;
} ichor_gf256_ops_t;

#ifdef ICHOR_HAVE_GF256_GFNI
extern const ichor_gf256_ops_t ichor_gf256_ops_gfni;
#endif
#ifdef ICHOR_HAVE_GF256_AVX2
extern const ichor_gf256_ops_t ichor_gf256_ops_avx2;
#endif
#ifdef ICHOR_HAVE_GF256_SSSE3
extern const ichor_gf256_ops_t ichor_gf256_ops_ssse3;
#endif
#ifdef ICHOR_HAVE_GF256_NEON
extern const ichor_gf256_ops_t ichor_gf256_ops_neon;
#endif
extern const ichor_gf256_ops_t ichor_gf256_ops_scalar;

/* Constant-time scalar GF(2^8) multiply (poly 0x11B), shared by the scalar
 * backend and the SSSE3 backend's per-scalar table build. */
uint8_t ichor_gf256_mul_scalar(uint8_t a, uint8_t b);

/* Selected at init; read by the public forwarders in src/gf256.c. */
extern _Atomic(const ichor_gf256_ops_t *) ichor_gf256_ops;

/* Called by public forwarders on first use. */
void ichor_gf256_dispatch_init(void);

#ifdef ICHOR_ENABLE_FORCE_BACKEND
void ichor_gf256_dispatch_reset(void);
#endif

#endif /* ICHOR_GF256_DISPATCH_H */
