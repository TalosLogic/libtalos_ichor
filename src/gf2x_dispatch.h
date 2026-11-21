/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf2x_dispatch.h - Internal gf2x kernel ops-table and dispatch declarations.
 *
 * Not in include/; not part of the public API.  Consumed by:
 *   src/gf2x.c       (publishes ichor_gf2x_ops, runs init, scalar table)
 *   src/gf2x_sse2.c  (defines ichor_gf2x_ops_sse2)
 *   src/gf2x_avx2.c  (defines ichor_gf2x_ops_avx2)
 *   src/gf2x_neon.c  (defines ichor_gf2x_ops_neon)
 *
 * The dispatched kernels are: the circulant barrel rotation (gf2x_rotl_fixed)
 * and the constant-time per-step select (gf2x_rotl_blend), each the component
 * form of the fused barrel step (gf2x_rotl_fixed_blend) that ichor_gf2x_rotl_var
 * actually runs ~log2(p) times; the mod-(x^p - 1) fold (gf2x_reduce, once per
 * ichor_gf2x_mul); and the Karatsuba base-case schoolbook product (school,
 * threaded through gf2x_kara from ichor_gf2x_mul).  All depend only on public
 * sizes (the rotation on p; the blend on limbs and an opaque 0/~0 mask applied
 * uniformly; the school on na, nb), so every backend is constant-time and the
 * dispatch decision is data-independent; each produces bit-identical output to
 * the scalar table, so the KATs hold across backends.
 *
 * The hardware ops tables are guarded by the same ICHOR_HAVE_GF2X_* macros
 * that gate their TUs.  ichor_gf2x_ops points to whichever table
 * ichor_gf2x_dispatch_init() selects.  The scalar table is always compiled in
 * and is the portable floor on every architecture.
 */

#ifndef ICHOR_GF2X_DISPATCH_H
#define ICHOR_GF2X_DISPATCH_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "gf2x.h"

typedef enum {
    ICHOR_GF2X_BACKEND_SCALAR = 0,
    ICHOR_GF2X_BACKEND_SSE2,
    ICHOR_GF2X_BACKEND_AVX2,
    ICHOR_GF2X_BACKEND_AVX2_VPCLMUL,
    ICHOR_GF2X_BACKEND_NEON
} ichor_gf2x_backend_t;

/*
 * Karatsuba base-case schoolbook carry-less product:
 * out[0, na + nb) = a * b, zeroed first.  na and nb are public.
 */
typedef void (*ichor_gf2x_school_fn)(uint64_t *, const uint64_t *, size_t,
                                     const uint64_t *, size_t);

typedef struct {
    void (*rotl_fixed)(const ichor_gf2x_ring *, uint64_t *, const uint64_t *,
                       unsigned);
    void (*reduce)(const ichor_gf2x_ring *, uint64_t *, const uint64_t *);
    void (*rotl_blend)(uint64_t *, const uint64_t *, uint64_t, size_t);
    /*
     * Fused barrel step for ichor_gf2x_rotl_var: dst = select(src * x^t, src)
     * by an opaque 0/~0 mask, in a single pass so the rotated vector never
     * round-trips through memory the way separate rotl_fixed + rotl_blend
     * calls do.  dst must not alias src (rotl_var ping-pongs its two scratch
     * halves); t and the mask are public, so control flow is data-independent.
     */
    void (*rotl_fixed_blend)(const ichor_gf2x_ring *, uint64_t *,
                             const uint64_t *, uint64_t, unsigned);
    ichor_gf2x_school_fn school;
    /*
     * Oblivious dense->sparse compaction of one circulant block into the running
     * support list (the inverse of ichor_gf2x_scatter): scan span bits, place
     * each set bit's global position into output slot `count` by sweeping all t
     * slots under a constant-time equality mask, return the updated count.  The
     * t-slot inner sweep is the vectorized hotspot; the bounds (span, t) and the
     * opaque per-bit mask are public, so every backend is constant-time and
     * bit-identical to the scalar table.
     */
    uint32_t (*compact)(uint32_t *, uint32_t, const uint8_t *, size_t, uint32_t,
                        uint32_t, uint32_t);
    /*
     * Oblivious sparse->dense scatter, the inverse of compact: write a
     * fixed-weight support list into one dense ring element by sweeping every
     * output word and ORing each index's single-bit mask into the word whose
     * index matches under a constant-time equality.  The support is secret but
     * only compared, never used as an address, so every backend is
     * constant-time and byte-identical to the scalar table.
     */
    void (*scatter)(uint8_t *, size_t, const uint32_t *, uint32_t, uint32_t,
                    uint32_t);
    ichor_gf2x_backend_t backend_tag;
    const char *name;
} ichor_gf2x_ops_t;

#ifdef ICHOR_HAVE_GF2X_SSE2
extern const ichor_gf2x_ops_t ichor_gf2x_ops_sse2;
#endif
#ifdef ICHOR_HAVE_GF2X_AVX2
extern const ichor_gf2x_ops_t ichor_gf2x_ops_avx2;
#endif
/*
 * AVX2 rotation/reduction/blend plus the VPCLMULQDQ wide schoolbook.  Selected
 * only when the host reports both ICHOR_CPU_AVX2 and ICHOR_CPU_VPCLMULQDQ; a
 * VPCLMULQDQ host is always an AVX2 host, so this needs no table of its own for
 * the rotation ops.  Defined in gf2x_avx2.c (it needs the static AVX2 kernels);
 * the schoolbook lives in its own TU, built with -mvpclmulqdq.
 */
#if defined(ICHOR_HAVE_GF2X_AVX2) && defined(ICHOR_HAVE_GF2X_VPCLMUL)
extern const ichor_gf2x_ops_t ichor_gf2x_ops_avx2_vpclmul;
#endif
#ifdef ICHOR_HAVE_GF2X_VPCLMUL
void gf2x_school_vpclmul(uint64_t *, const uint64_t *, size_t, const uint64_t *,
                         size_t);
#endif
#ifdef ICHOR_HAVE_GF2X_NEON
extern const ichor_gf2x_ops_t ichor_gf2x_ops_neon;
#endif
extern const ichor_gf2x_ops_t ichor_gf2x_ops_scalar;

/*
 * The scalar kernels, exported (internal linkage header, not public API) so a
 * SIMD backend can reuse the scalar implementation for any op it does not yet
 * specialize.  Both are constant-time and are the bit-identical reference the
 * SIMD kernels are validated against.
 */
void ichor_gf2x_rotl_fixed_scalar(const ichor_gf2x_ring *, uint64_t *,
                                  const uint64_t *, unsigned);
void ichor_gf2x_reduce_scalar(const ichor_gf2x_ring *, uint64_t *,
                              const uint64_t *);
void ichor_gf2x_rotl_blend_scalar(uint64_t *, const uint64_t *, uint64_t,
                                  size_t);
void ichor_gf2x_rotl_fixed_blend_scalar(const ichor_gf2x_ring *, uint64_t *,
                                        const uint64_t *, uint64_t, unsigned);
void ichor_gf2x_school_scalar(uint64_t *, const uint64_t *, size_t,
                              const uint64_t *, size_t);
uint32_t ichor_gf2x_compact_scalar(uint32_t *, uint32_t, const uint8_t *,
                                   size_t, uint32_t, uint32_t, uint32_t);
void ichor_gf2x_scatter_scalar(uint8_t *, size_t, const uint32_t *, uint32_t,
                               uint32_t, uint32_t);

/*
 * Shared constant-time precompute for the SIMD scatter backends: per support
 * index, the 32-bit output word it localizes into (wpos) and its single-bit
 * mask gated by loc < span (bmask).  The barriered bit-building lives in one
 * place; wpos/bmask hold secret support and are the caller's to wipe.
 */
void ichor_gf2x_scatter_prep32(uint32_t *wpos, uint32_t *bmask,
                               const uint32_t *idx, uint32_t w, uint32_t base,
                               uint32_t span);

/* Selected at init; read by the internal forwarders in src/gf2x.c. */
extern _Atomic(const ichor_gf2x_ops_t *) ichor_gf2x_ops;

/* Called by the forwarders on first use. */
void ichor_gf2x_dispatch_init(void);

/* Resets the dispatch table pointer to NULL (test-only; compiled in only
 * under ICHOR_ENABLE_FORCE_BACKEND). */
#ifdef ICHOR_ENABLE_FORCE_BACKEND
void ichor_gf2x_dispatch_reset(void);
#endif

#endif /* ICHOR_GF2X_DISPATCH_H */
