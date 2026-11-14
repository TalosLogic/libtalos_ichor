/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * keccak_dispatch.h - internal declarations for the single-sponge Keccak-f
 * backend (the SHA-3-extension aarch64 kernel and the dispatch reset hook).
 *
 * Not part of the public API; the public entry points are the SHA-3 / SHAKE
 * functions in <ichor/hash.h>, which route their permutation through the
 * backend selected in hash.c.  The scalar permutation is always compiled in;
 * this header declares only the optional hardware kernel.
 */

#ifndef ICHOR_KECCAK_DISPATCH_H
#define ICHOR_KECCAK_DISPATCH_H

#include <stdint.h>

#ifdef ICHOR_HAVE_KECCAK_SHA3
/* Single-sponge Keccak-f[1600] via the ARMv8.2 SHA-3 extension; byte-identical
 * to the scalar permutation.  Defined in keccak_sha3_neon.c. */
void ichor_keccak_f1600_sha3(uint64_t state[25]);
#endif

#ifdef ICHOR_ENABLE_FORCE_BACKEND
/* Clear the cached single-sponge Keccak backend so the next permutation
 * re-selects.  Compiled out of release / vendored builds. */
void ichor_keccak_f1600_dispatch_reset(void);
#endif

#endif /* ICHOR_KECCAK_DISPATCH_H */
