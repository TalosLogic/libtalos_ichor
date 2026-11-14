/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf16_dispatch.h - Internal GF(2^16) region-multiply ops-table and dispatch.
 *
 * Not in include/; not part of the public API.  Consumed by:
 *   src/gf16.c        (publishes ichor_gf16_ops, runs init, scalar table)
 *   src/gf16_ssse3.c  (defines ichor_gf16_ops_ssse3)
 *
 * The SSSE3 ops table is guarded by ICHOR_HAVE_GF16_SSSE3, the same macro that
 * gates its TU.  ichor_gf16_ops points to whichever table
 * ichor_gf16_dispatch_init() selects.
 */

#ifndef ICHOR_GF16_DISPATCH_H
#define ICHOR_GF16_DISPATCH_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "gf16.h"

typedef struct {
    void (*mul_region)(uint16_t *, const uint16_t *, uint16_t, size_t);
    void (*muladd_region)(uint16_t *, const uint16_t *, uint16_t, size_t);
    ichor_gf16_backend_t backend_tag;
    const char *name;
} ichor_gf16_ops_t;

#ifdef ICHOR_HAVE_GF16_GFNI
extern const ichor_gf16_ops_t ichor_gf16_ops_gfni;
#endif
#ifdef ICHOR_HAVE_GF16_SSSE3
extern const ichor_gf16_ops_t ichor_gf16_ops_ssse3;
#endif
#ifdef ICHOR_HAVE_GF16_NEON
extern const ichor_gf16_ops_t ichor_gf16_ops_neon;
#endif
extern const ichor_gf16_ops_t ichor_gf16_ops_scalar;

/* Constant-time scalar GF(2^16) multiply (poly 0x1100B, reduce 0x100B), shared
 * by the scalar backend and the SSSE3 backend's per-scalar table build. */
uint16_t ichor_gf16_mul_scalar(uint16_t a, uint16_t b);

/* Selected at init; read by the public forwarders in src/gf16.c. */
extern _Atomic(const ichor_gf16_ops_t *) ichor_gf16_ops;

/* Called by public forwarders on first use. */
void ichor_gf16_dispatch_init(void);

#ifdef ICHOR_ENABLE_FORCE_BACKEND
void ichor_gf16_dispatch_reset(void);
#endif

#endif /* ICHOR_GF16_DISPATCH_H */
