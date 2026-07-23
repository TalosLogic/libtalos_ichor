/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * clmul_dispatch.h - Internal clmul ops-table and dispatch declarations.
 *
 * Not in include/; not part of the public API.  Consumed by:
 *   src/clmul.c          (publishes ichor_clmul_ops, runs init, scalar table)
 *   src/clmul_pclmul.c   (defines ichor_clmul_ops_pclmul)
 *   src/clmul_pmull.c    (defines ichor_clmul_ops_pmull)
 *
 * The two hardware ops tables are guarded by the same ICHOR_HAVE_*
 * macros that gate their TUs.  ichor_clmul_ops points to whichever
 * table ichor_clmul_dispatch_init() selects.
 */

#ifndef ICHOR_CLMUL_DISPATCH_H
#define ICHOR_CLMUL_DISPATCH_H

#include <stdatomic.h>

#include "clmul.h"

typedef struct {
    void (*mul)(uint64_t, uint64_t, uint64_t *, uint64_t *);
    ichor_clmul_backend_t backend_tag;
    const char *name;
} ichor_clmul_ops_t;

#ifdef ICHOR_HAVE_CLMUL
extern const ichor_clmul_ops_t ichor_clmul_ops_pclmul;
#endif
#ifdef ICHOR_HAVE_PMULL
extern const ichor_clmul_ops_t ichor_clmul_ops_pmull;
#endif
extern const ichor_clmul_ops_t ichor_clmul_ops_scalar;

/* Selected at init; read by the public forwarders in src/clmul.c. */
extern _Atomic(const ichor_clmul_ops_t *) ichor_clmul_ops;

/* Called by public forwarders on first use. */
void ichor_clmul_dispatch_init(void);

/* Resets the dispatch table pointer to NULL (test-only; compiled in only
 * under ICHOR_ENABLE_FORCE_BACKEND). */
#ifdef ICHOR_ENABLE_FORCE_BACKEND
void ichor_clmul_dispatch_reset(void);
#endif

#endif /* ICHOR_CLMUL_DISPATCH_H */
