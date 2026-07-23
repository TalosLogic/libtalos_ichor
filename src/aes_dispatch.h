/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_dispatch.h - Internal AES ops-table and dispatch declarations.
 *
 * Not in include/; not part of the public API.  Consumed by:
 *   core/aes.c          (publishes ichor_aes_ops, runs init)
 *   core/aes_aesni.c    (defines ichor_aes_ops_aesni)
 *   core/aes_armv8.c    (defines ichor_aes_ops_armv8)
 *   core/aes_ct64_ops.c (defines ichor_aes_ops_bitsliced)
 *
 * The three statically-defined ops tables are guarded by the same
 * ICHOR_HAVE_* macros that gate their TUs.  ichor_aes_ops points
 * to whichever table ichor_aes_dispatch_init() selects.
 */

#ifndef ICHOR_AES_DISPATCH_H
#define ICHOR_AES_DISPATCH_H

#include <stdatomic.h>
#include "aes.h"

typedef struct {
    int (*key_expand)(ichor_aes_ctx_t *, const uint8_t *, int);
    void (*encrypt)(const ichor_aes_ctx_t *, uint8_t[16], const uint8_t[16]);
    void (*encrypt_x4)(const ichor_aes_ctx_t *, uint8_t[64], const uint8_t[64]);
    ichor_aes_backend_t backend_tag;
    const char *name;
} ichor_aes_ops_t;

#ifdef ICHOR_HAVE_AES_NI
extern const ichor_aes_ops_t ichor_aes_ops_aesni;
#endif
#ifdef ICHOR_HAVE_ARMV8_AES
extern const ichor_aes_ops_t ichor_aes_ops_armv8;
#endif
extern const ichor_aes_ops_t ichor_aes_ops_bitsliced;

/* Selected at init; read by the public forwarders in core/aes.c. */
extern _Atomic(const ichor_aes_ops_t *) ichor_aes_ops;

/* Called by public forwarders on first use. */
void ichor_aes_dispatch_init(void);

#endif /* ICHOR_AES_DISPATCH_H */
