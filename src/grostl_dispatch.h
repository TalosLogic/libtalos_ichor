/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl_dispatch.h - Internal dispatch table for Groestl permutation backends.
 *
 * The four permutation functions (P512, Q512, P1024, Q1024) differ only in
 * their SubBytes implementation (AES-NI, ARMv8, or bitsliced software).
 * Each backend TU defines an ichor_grostl_ops_t and the public forwarders
 * in grostl.c route through ichor_grostl_ops, which is initialized once
 * via a CAS guard on the first compress call.
 *
 * Not in include/; not part of the public API.
 */

#ifndef ICHOR_GROSTL_DISPATCH_H
#define ICHOR_GROSTL_DISPATCH_H

#include <stdatomic.h>
#include "grostl_core.h"

typedef struct {
    void (*p512)(uint8_t state[GROSTL_STATE_BYTES_256]);
    void (*q512)(uint8_t state[GROSTL_STATE_BYTES_256]);
    void (*p1024)(uint8_t state[GROSTL_STATE_BYTES_512]);
    void (*q1024)(uint8_t state[GROSTL_STATE_BYTES_512]);
    const char *name;
} ichor_grostl_ops_t;

#ifdef ICHOR_HAVE_AES_NI
extern const ichor_grostl_ops_t ichor_grostl_ops_aesni;
#endif
#ifdef ICHOR_HAVE_ARMV8_AES
extern const ichor_grostl_ops_t ichor_grostl_ops_armv8;
#endif
extern const ichor_grostl_ops_t ichor_grostl_ops_soft;

extern _Atomic(const ichor_grostl_ops_t *) ichor_grostl_ops;

void ichor_grostl_dispatch_init(void);
/* test-only; compiled in only under ICHOR_ENABLE_FORCE_BACKEND (L4). */
#ifdef ICHOR_ENABLE_FORCE_BACKEND
void ichor_grostl_dispatch_reset(void);
#endif

#endif /* ICHOR_GROSTL_DISPATCH_H */
