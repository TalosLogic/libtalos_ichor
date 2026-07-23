/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * clmul.c - Carry-less multiply public forwarders, runtime dispatch, and
 * the portable constant-time scalar backend.
 *
 * On first call, ichor_clmul_dispatch_init() reads ichor_cpu_features()
 * and selects the highest-priority compiled-in backend whose required
 * feature bit is present:
 *   1. PCLMULQDQ   (x86_64; ICHOR_HAVE_CLMUL compiled in)
 *   2. PMULL       (aarch64; ICHOR_HAVE_PMULL compiled in)
 *   3. Scalar      (portable constant-time; always compiled in)
 *
 * The selected ops pointer is stored with a release-store; subsequent
 * calls pay one load-acquire and one indirect branch.  All three
 * backends are constant-time; the dispatch decision is data-independent.
 */

#include "clmul.h"
#include "clmul_dispatch.h"
#include "backend.h"
#include "cpu.h"

#include <stdatomic.h>
#include <stdlib.h>

/* ========================================================================
 * Scalar backend (always compiled in)
 * ======================================================================== */

/*
 * Constant-time 64x64 -> 128-bit carry-less multiply.
 *
 * Bit-serial over the 64 bits of b: for each set bit i, the shifted
 * multiplicand (a << i) is XORed into the 128-bit accumulator.  The set
 * test is folded into a 0/all-ones mask so no control flow depends on
 * the operands -- the only branch keys on the loop counter i, which is
 * public, and exists solely to avoid the undefined (a >> 64) shift at
 * i == 0.
 */
static void
clmul64_scalar(uint64_t a, uint64_t b, uint64_t *lo, uint64_t *hi)
{
    uint64_t l = 0, h = 0;
    int i;

    for (i = 0; i < 64; i++) {
        uint64_t mask = (uint64_t)0 - ((b >> i) & 1u);
        l ^= (a << i) & mask;
        if (i != 0)
            h ^= (a >> (64 - i)) & mask;
    }
    *lo = l;
    *hi = h;
}

const ichor_clmul_ops_t ichor_clmul_ops_scalar = {
    .mul = clmul64_scalar,
    .backend_tag = ICHOR_CLMUL_BACKEND_SCALAR,
    .name = "scalar",
};

/* ========================================================================
 * Dispatch
 * ======================================================================== */

_Atomic(const ichor_clmul_ops_t *) ichor_clmul_ops = NULL;

void
ichor_clmul_dispatch_init(void)
{
    if (atomic_load_explicit(&ichor_clmul_ops, memory_order_acquire) != NULL)
        return;

    const ichor_clmul_ops_t *pick = NULL;

    /* feat is consulted only by the hardware backends; a lean build with none
     * compiled in selects the scalar path unconditionally and never reads it. */
#if defined(ICHOR_HAVE_CLMUL) || defined(ICHOR_HAVE_PMULL)
    uint32_t feat = ichor_cpu_features();
#ifdef ICHOR_HAVE_CLMUL
    if (pick == NULL && (feat & ICHOR_CPU_CLMUL))
        pick = &ichor_clmul_ops_pclmul;
#endif
#ifdef ICHOR_HAVE_PMULL
    if (pick == NULL && (feat & ICHOR_CPU_PMULL))
        pick = &ichor_clmul_ops_pmull;
#endif
#endif /* any hardware clmul backend */

    if (pick == NULL)
        pick = &ichor_clmul_ops_scalar;

    const ichor_clmul_ops_t *expected = NULL;
    atomic_compare_exchange_strong_explicit(&ichor_clmul_ops, &expected, pick,
                                            memory_order_release,
                                            memory_order_acquire);
}

static const ichor_clmul_ops_t *
clmul_ops(void)
{
    const ichor_clmul_ops_t *ops =
        atomic_load_explicit(&ichor_clmul_ops, memory_order_acquire);
    if (ops == NULL) {
        ichor_clmul_dispatch_init();
        ops = atomic_load_explicit(&ichor_clmul_ops, memory_order_acquire);
    }
    return ops;
}

/* ========================================================================
 * Public forwarders
 * ======================================================================== */

void
ichor_clmul64(uint64_t a, uint64_t b, uint64_t *lo, uint64_t *hi)
{
    clmul_ops()->mul(a, b, lo, hi);
}

ichor_clmul64_fn
ichor_clmul64_resolve(void)
{
    return clmul_ops()->mul;
}

ichor_clmul_backend_t
ichor_clmul_backend(void)
{
    return clmul_ops()->backend_tag;
}

const char *
ichor_clmul_backend_name(void)
{
    switch (ichor_clmul_backend()) {
    case ICHOR_CLMUL_BACKEND_PCLMUL:
        return "PCLMULQDQ (x86_64 hardware)";
    case ICHOR_CLMUL_BACKEND_PMULL:
        return "PMULL (aarch64 hardware)";
    case ICHOR_CLMUL_BACKEND_SCALAR:
        return "scalar (portable constant-time software)";
    }
    return "unknown";
}

/*
 * Backend health (backend.h): FALLBACK iff the host advertises a hardware
 * carry-less-multiply feature but the active backend is the scalar software
 * path, i.e. the accelerated backend was not compiled into this build.
 */
ichor_backend_health_t
ichor_clmul_backend_health(void)
{
    uint32_t feat = ichor_cpu_features();
    if (ichor_clmul_backend() == ICHOR_CLMUL_BACKEND_SCALAR &&
        (feat & (ICHOR_CPU_CLMUL | ICHOR_CPU_PMULL)))
        return ICHOR_BACKEND_FALLBACK;
    return ICHOR_BACKEND_OPTIMAL;
}

#ifdef ICHOR_ENABLE_FORCE_BACKEND
/* Test-only hook: clears the cached ops pointer
 * so the next call re-selects a backend.  Compiled out of release /
 * vendored builds (see ICHOR_ENABLE_FORCE_BACKEND in CMakeLists.txt). */
void
ichor_clmul_dispatch_reset(void)
{
    atomic_store_explicit(&ichor_clmul_ops, NULL, memory_order_release);
}
#endif /* ICHOR_ENABLE_FORCE_BACKEND */
