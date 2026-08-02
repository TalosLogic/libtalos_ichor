/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * sample.h - constant-time fixed-weight index sampling.
 *
 * Draws w DISTINCT indices in [0, n) from a caller-supplied random tape,
 * returned in DRAW ORDER.  This is the shared support sampler beneath
 * libtalos_syndrome's QC-MDPC KEM (weight-t error, weight-v private blocks) and
 * libtalos_voleith's designated-opener seal (weight-t error e); neither library
 * depends on the other, only on this.
 *
 * Order note: the drawn set is what carries the security (weight-t uniformity);
 * list order is a representation detail.  Consumers that scatter the set into a
 * dense vector (the syndrome multiply, and syndrome's own KEM which re-derives
 * an ascending list from the dense error) are order-independent.  A consumer
 * that hashes the sparse list AS AN ORDERED LIST (the Argus opener KDF, which
 * bit-packs the indices) needs a canonical order and must call
 * ichor_sample_sort_ascending first; syndrome's decap pins that canonical form
 * to ascending, so the seal producer conforms.
 *
 * The routine is a PURE FUNCTION of the tape: it performs no I/O, no DRBG
 * call, and no dynamic allocation.  The caller draws the tape from its own
 * PRG/DRBG and passes it in.  This keeps the constant-time property trivially
 * validatable (fixed tape -> fixed output; a dudect target feeds fixed-vs-
 * random tapes) and pins the mapping under a KAT independent of any PRG.
 *
 * Algorithm.  An O(w)-overlay partial Fisher-Yates shuffle selects w distinct
 * slots without materializing the length-n identity array: at public step i a
 * bias-controlled draw picks a tail slot j in [i, n), and pos[i], pos[j] are
 * resolved from the <= i recorded overlay entries under a branch-free equality
 * mask.  Each draw reduces a (lambda + 64)-bit tape word into the public range
 * by Lemire multiply-shift (division-free), so the residual bias sits far below
 * 2^-lambda with FIXED tape consumption and no rejection loop (a rejection loop
 * would make consumption, hence timing, depend on the secret draw).  The w
 * results are returned in draw order; ichor_sample_sort_ascending canonicalizes
 * them with a constant-time bitonic sorting network when a caller needs it.
 * Every loop bound is a public quantity (w, n, the network stage indices); no
 * secret is ever used as a branch condition or a memory address.
 */

#ifndef ICHOR_SAMPLE_H
#define ICHOR_SAMPLE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Largest weight w a single call accepts.  Bounds the fixed on-stack overlay
 * scratch; a larger w is rejected (return -1) rather than overrun it.  Covers
 * every shipped QC-MDPC set (max weight 261 at lambda-256 n0=2) with margin.
 */
#define ICHOR_SAMPLE_MAXW 512u

/*
 * Per-index tape draw width in bytes for a given lambda: (lambda + 64) / 8.
 * The 64-bit widening over the bare range word drives the Lemire bias below
 * 2^-lambda for every set (24 B at lambda 128, 32 B at 192, 40 B at 256).
 * Returns 0 for an unsupported lambda (must be 128, 192, or 256).
 */
size_t ichor_sample_draw_bytes(int lambda);

/*
 * Exact tape length required by ichor_sample_fixed_weight for (lambda, w):
 * w * ichor_sample_draw_bytes(lambda).  Returns 0 on an unsupported lambda or
 * w == 0 or w > ICHOR_SAMPLE_MAXW.
 */
size_t ichor_sample_fixed_weight_tape_bytes(int lambda, uint32_t w);

/*
 * idx[0..w) <- w distinct indices in [0, n), in DRAW ORDER, drawn from `tape`.
 *
 * lambda    128, 192, or 256 (selects the per-draw tape width).
 * tape      random bytes; tape_len MUST equal
 *           ichor_sample_fixed_weight_tape_bytes(lambda, w).
 *
 * The output is the drawn SET; its list order is the Fisher-Yates draw order,
 * not sorted.  Callers that need a canonical order (a support hashed as an
 * ordered list) apply ichor_sample_sort_ascending; scatter consumers do not.
 *
 * Constant-time and fixed-consumption over the tape contents.  Returns 0 on
 * success; -1 on a NULL argument, unsupported lambda, w == 0, w > n,
 * w > ICHOR_SAMPLE_MAXW, or a tape_len that does not match the required length.
 * On failure idx is left unspecified and any scratch is zeroed.
 */
int ichor_sample_fixed_weight(uint32_t *idx, uint32_t w, uint32_t n, int lambda,
                              const uint8_t *tape, size_t tape_len);

/*
 * Sort idx[0..w) into ascending order in place, constant-time over the values
 * (a bitonic network whose shape depends only on the public w).  Use to put a
 * drawn support into the canonical form hashed by an order-sensitive consumer
 * (the Argus opener KDF).  Returns 0 on success; -1 on NULL idx, w == 0, or
 * w > ICHOR_SAMPLE_MAXW.
 */
int ichor_sample_sort_ascending(uint32_t *idx, uint32_t w);

#endif /* ICHOR_SAMPLE_H */
