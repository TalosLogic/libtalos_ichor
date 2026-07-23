/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * backend.h - Runtime backend-health query.
 *
 * Each primitive (AES, carry-less multiply, Grøstl) selects a backend once,
 * on first use, from the compiled-in set and the running CPU's features.
 * When the host has a hardware-acceleration feature but the matching backend
 * was not compiled into this build, the primitive silently runs on its
 * constant-time software fallback instead: correct, but much slower.
 *
 * The library does no I/O of its own to report this (it may be running with
 * no terminal, or with stdout/stderr carrying protocol data).  Instead it
 * exposes the fact here so the application can decide whether and how to
 * surface it: log it through its own facility, record a metric, or ignore it.
 *
 * Backend selection is one-shot and cached, so the result of every query in
 * this header is stable for the lifetime of the process.  Call once at
 * start-up.  Each query triggers dispatch initialization if it has not run.
 */

#ifndef ICHOR_BACKEND_H
#define ICHOR_BACKEND_H

/*
 * Health of a single primitive's active backend.
 */
typedef enum {
    ICHOR_BACKEND_OPTIMAL = 0,  /* best backend this CPU can run is active */
    ICHOR_BACKEND_FALLBACK = 1, /* CPU has accel, but it was not compiled in */
} ichor_backend_health_t;

/*
 * Per-primitive health queries.
 *
 * Return ICHOR_BACKEND_FALLBACK when the running CPU advertises a hardware
 * feature that would accelerate this primitive but the corresponding backend
 * is absent from the build (so the software path was selected); otherwise
 * ICHOR_BACKEND_OPTIMAL.  A CPU with no relevant hardware feature is always
 * OPTIMAL: the software backend is the best available.
 */
ichor_backend_health_t ichor_aes_backend_health(void);
ichor_backend_health_t ichor_clmul_backend_health(void);
ichor_backend_health_t ichor_grostl_backend_health(void);

/*
 * Aggregate report for all three primitives, for a single start-up call.
 */
typedef struct {
    ichor_backend_health_t aes;    /* AES block cipher */
    ichor_backend_health_t clmul;  /* carry-less multiply (GF(2^k)) */
    ichor_backend_health_t grostl; /* Grøstl permutation */
} ichor_backend_report_t;

/*
 * Populate *out with the health of every primitive's backend.  Equivalent to
 * calling the three per-primitive queries above.
 */
void ichor_backend_report(ichor_backend_report_t *out);

#endif /* ICHOR_BACKEND_H */
