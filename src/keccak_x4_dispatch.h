/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * keccak_x4_dispatch.h - internal declarations for the 4-way Keccak backend.
 *
 * The AVX2 permutation kernel (keccak_x4_avx2.c) and the test-only dispatch
 * reset hook.  Not part of the public API; the public entry points are
 * ichor_shake128_x4 / ichor_shake256_x4 in <ichor/hash.h>.
 */

#ifndef ICHOR_KECCAK_X4_DISPATCH_H
#define ICHOR_KECCAK_X4_DISPATCH_H

#include <stdint.h>

#ifdef ICHOR_HAVE_KECCAK_X4_AVX2
/* 4-lane Keccak-f[1600]: permute four sponges in place (st[lane][sponge]). */
void ichor_keccak_f1600_x4_avx2(uint64_t st[25][4]);
#endif

#ifdef ICHOR_HAVE_KECCAK_X4_SHA3
/* Same contract, ARMv8.2 SHA-3 (two 2-lane-packed passes); see
 * keccak_x4_sha3_neon.c. */
void ichor_keccak_f1600_x4_sha3(uint64_t st[25][4]);
#endif

#ifdef ICHOR_ENABLE_FORCE_BACKEND
/* Clear the cached backend so the next ichor_shake*_x4 re-selects.  Compiled
 * out of release / vendored builds (see ICHOR_ENABLE_FORCE_BACKEND). */
void ichor_keccak_x4_dispatch_reset(void);
#endif

#endif /* ICHOR_KECCAK_X4_DISPATCH_H */
