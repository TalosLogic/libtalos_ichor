/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_armv8.h - Internal declarations for the ARMv8 Crypto Extension backend.
 *
 * Not for inclusion in public headers.  Included by core/aes.c to wire
 * the per-backend entry points into the compile-time dispatch ladder.
 * Functions are defined in core/aes_armv8.c.
 */

#ifndef ICHOR_AES_ARMV8_H
#define ICHOR_AES_ARMV8_H

#ifdef ICHOR_HAVE_ARMV8_AES

#include "aes.h"

int aes_armv8_key_expand(ichor_aes_ctx_t *, const uint8_t *, int);
void aes_armv8_encrypt(const ichor_aes_ctx_t *, uint8_t[16], const uint8_t[16]);
void aes_armv8_encrypt_x4(const ichor_aes_ctx_t *, uint8_t[64],
                          const uint8_t[64]);

#endif /* ICHOR_HAVE_ARMV8_AES */

#endif /* ICHOR_AES_ARMV8_H */
