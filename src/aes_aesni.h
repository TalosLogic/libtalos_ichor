/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_aesni.h - Internal declarations for the AES-NI backend.
 *
 * Not for inclusion in public headers.  Included by core/aes.c to wire
 * the per-backend entry points into the compile-time dispatch ladder.
 * Functions are defined in core/aes_aesni.c.
 */

#ifndef ICHOR_AES_AESNI_H
#define ICHOR_AES_AESNI_H

#ifdef ICHOR_HAVE_AES_NI

#include "aes.h"

int aes_aesni_key_expand(ichor_aes_ctx_t *, const uint8_t *, int);
void aes_aesni_encrypt(const ichor_aes_ctx_t *, uint8_t[16], const uint8_t[16]);
void aes_aesni_encrypt_x4(const ichor_aes_ctx_t *, uint8_t[64],
                          const uint8_t[64]);

#endif /* ICHOR_HAVE_AES_NI */

#endif /* ICHOR_AES_AESNI_H */
