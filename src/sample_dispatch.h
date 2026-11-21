/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * sample_dispatch.h - Internal dispatch for the constant-time sampler's one
 * vectorizable kernel.  Not in include/; not part of the public API.  Consumed
 * by:
 *   src/sample.c       (publishes ichor_sample_ops, runs init, scalar table)
 *   src/sample_sse2.c  (defines ichor_sample_ops_sse2)
 *   src/sample_avx2.c  (defines ichor_sample_ops_avx2)
 *   src/sample_neon.c  (defines ichor_sample_ops_neon)
 *
 * The dispatched kernel is the batched Lemire reduction (reduce_batch): the w
 * per-draw range reductions in ichor_sample_fixed_weight are mutually
 * independent (each a function only of its own public range n - i and its own
 * tape slice), so they are computed together, lane-parallel across draws, using
 * only public-count shifts and bitwise/add/sub ops.  No kernel issues a
 * data-operand-dependent integer multiply (the secret draw never reaches a
 * variable-latency unit) and none uses a gather, so every backend is
 * constant-time and bit-identical to the scalar table, and the sampler KATs
 * hold across backends.
 *
 * The SSE2/AVX2/NEON TUs are gated by the same ICHOR_HAVE_SAMPLE_* macros the
 * build sets alongside the gf2x probes (the kernels need only the identical
 * 64-bit shift / bitwise / add intrinsics those probes already validated).  The
 * scalar table is always compiled in and is the portable floor.
 */

#ifndef ICHOR_SAMPLE_DISPATCH_H
#define ICHOR_SAMPLE_DISPATCH_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    ICHOR_SAMPLE_BACKEND_SCALAR = 0,
    ICHOR_SAMPLE_BACKEND_SSE2,
    ICHOR_SAMPLE_BACKEND_SSE41,
    ICHOR_SAMPLE_BACKEND_AVX2,
    ICHOR_SAMPLE_BACKEND_NEON
} ichor_sample_backend_t;

/*
 * red[i] <- floor(draw_i * (n - i) / 2^(32*limbs)) for i in [0, w): the Lemire
 * high word of draw i, whose tape slice is tape + i*db (limbs 32-bit limbs, db
 * == limbs * 4 the per-draw width in bytes).  j = i + red[i] in the caller.
 * red/tape are the caller's; red holds the secret draws and is the caller's to
 * wipe.
 */
typedef void (*ichor_sample_reduce_batch_fn)(uint32_t *red, const uint8_t *tape,
                                             uint32_t w, uint32_t n,
                                             unsigned limbs, size_t db);

/*
 * Resolve one Fisher-Yates overlay step: cur_i <- the value currently in slot i,
 * cur_j <- the value in slot j, from overlay entries [0, i) under a constant-
 * time equality.  A slot may be recorded more than once; the LAST (highest-k)
 * entry wins, so this is a priority reduction, not an OR.  i is public, j is
 * secret.  ov_slot/ov_val are padded past i with a non-matching sentinel (the
 * caller sets unused slots to UINT32_MAX), so a backend may over-scan to its
 * vector-width boundary without a secret-dependent tail.
 */
typedef void (*ichor_sample_overlay_resolve_fn)(uint32_t i, uint32_t j,
                                                const uint32_t *ov_slot,
                                                const uint32_t *ov_val,
                                                uint32_t *cur_i,
                                                uint32_t *cur_j);

/*
 * Packed-key layout shared by the SIMD overlay-resolve kernels: the step index
 * k + 1 in the high bits, the overlay value in the low ICHOR_SAMPLE_KEY_SHIFT
 * bits.  Valid because k + 1 <= ICHOR_SAMPLE_MAXW (512) < 2^10 and a value is an
 * index < n, with n <= n0_max * p_max = 5 * 43451 < 2^18 for every shipped set,
 * so the value never reaches the index bits (over 4x headroom even there; the
 * real maximum n is ~123665 < 2^17).
 */
#define ICHOR_SAMPLE_KEY_SHIFT 22u
#define ICHOR_SAMPLE_VAL_MASK ((1u << ICHOR_SAMPLE_KEY_SHIFT) - 1u)

typedef struct {
    ichor_sample_reduce_batch_fn reduce_batch;
    ichor_sample_overlay_resolve_fn overlay_resolve;
    ichor_sample_backend_t backend_tag;
    const char *name;
} ichor_sample_ops_t;

#ifdef ICHOR_HAVE_SAMPLE_SSE2
extern const ichor_sample_ops_t ichor_sample_ops_sse2;
#endif
#ifdef ICHOR_HAVE_SAMPLE_SSE41
extern const ichor_sample_ops_t ichor_sample_ops_sse41;
#endif
#ifdef ICHOR_HAVE_SAMPLE_AVX2
extern const ichor_sample_ops_t ichor_sample_ops_avx2;
#endif
#ifdef ICHOR_HAVE_SAMPLE_NEON
extern const ichor_sample_ops_t ichor_sample_ops_neon;
#endif
extern const ichor_sample_ops_t ichor_sample_ops_scalar;

/*
 * The scalar kernel, exported (internal header, not public API) so a SIMD
 * backend can reuse it and the tests can validate against it.  It is the
 * bit-identical reference.
 */
void ichor_sample_reduce_batch_scalar(uint32_t *red, const uint8_t *tape,
                                      uint32_t w, uint32_t n, unsigned limbs,
                                      size_t db);
void ichor_sample_overlay_resolve_scalar(uint32_t i, uint32_t j,
                                         const uint32_t *ov_slot,
                                         const uint32_t *ov_val,
                                         uint32_t *cur_i, uint32_t *cur_j);

/* The SSE2 reduce kernel, exported so the SSE4.1 ops table (which runs on a
 * superset CPU) reuses it rather than duplicating the kernel. */
#ifdef ICHOR_HAVE_SAMPLE_SSE2
void ichor_sample_reduce_batch_sse2(uint32_t *red, const uint8_t *tape,
                                    uint32_t w, uint32_t n, unsigned limbs,
                                    size_t db);
#endif

/* Selected at init; read by the forwarder in src/sample.c. */
extern _Atomic(const ichor_sample_ops_t *) ichor_sample_ops;

/* Called by the forwarder on first use. */
void ichor_sample_dispatch_init(void);

/* Resets the dispatch pointer to NULL (test-only; compiled in only under
 * ICHOR_ENABLE_FORCE_BACKEND). */
#ifdef ICHOR_ENABLE_FORCE_BACKEND
void ichor_sample_dispatch_reset(void);
#endif

/* Internal forwarders used by ichor_sample_fixed_weight. */
void ichor_sample_reduce_batch(uint32_t *red, const uint8_t *tape, uint32_t w,
                               uint32_t n, unsigned limbs, size_t db);
void ichor_sample_overlay_resolve(uint32_t i, uint32_t j,
                                  const uint32_t *ov_slot,
                                  const uint32_t *ov_val, uint32_t *cur_i,
                                  uint32_t *cur_j);

#endif /* ICHOR_SAMPLE_DISPATCH_H */
