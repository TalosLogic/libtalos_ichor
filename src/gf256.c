/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf256.c - GF(2^8) region-multiply public forwarders, runtime dispatch, and
 * the portable constant-time scalar backend.
 *
 * On first call, ichor_gf256_dispatch_init() reads ichor_cpu_features() and
 * selects the highest-priority compiled-in backend whose feature bit is
 * present:
 *   1. SSSE3   (x86_64; ICHOR_HAVE_GF256_SSSE3 compiled in, ICHOR_CPU_SSSE3)
 *   2. Scalar  (portable constant-time; always compiled in)
 *
 * The selected ops pointer is stored with a release-store; subsequent calls
 * pay one load-acquire and one indirect branch.  Both backends are
 * constant-time; the dispatch decision is data-independent.
 */

#include "gf256.h"
#include "gf256_dispatch.h"
#include "backend.h"
#include "cpu.h"

#include <stdatomic.h>

/* ========================================================================
 * Shared scalar GF(2^8) multiply (poly 0x11B)
 * ======================================================================== */

/*
 * Constant-time product of a and b in GF(2^8) = F_2[x]/(x^8+x^4+x^3+x+1).
 *
 * Russian-peasant over the 8 bits of b: for each set bit the current a is
 * XORed into the accumulator, then a is doubled and reduced by 0x11B (low
 * byte 0x1B) whenever its top bit was set.  Both the set-bit test and the
 * reduction are folded into 0/all-ones masks, so no control flow depends on
 * a or b; the only branch keys on the public loop counter.
 */
uint8_t
ichor_gf256_mul_scalar(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    int i;

    for (i = 0; i < 8; i++) {
        uint8_t bmask = (uint8_t)0 - (uint8_t)(b & 1u);
        p ^= a & bmask;
        uint8_t hi = (uint8_t)0 - (uint8_t)(a >> 7);
        a = (uint8_t)((uint8_t)(a << 1) ^ (uint8_t)(0x1Bu & hi));
        b = (uint8_t)(b >> 1);
    }
    return p;
}

/* ========================================================================
 * Scalar backend (always compiled in)
 * ======================================================================== */

static void
gf256_mul_region_scalar(uint8_t *dst, const uint8_t *src, uint8_t a, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        dst[i] = ichor_gf256_mul_scalar(a, src[i]);
}

static void
gf256_muladd_region_scalar(uint8_t *dst, const uint8_t *src, uint8_t a,
                           size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        dst[i] ^= ichor_gf256_mul_scalar(a, src[i]);
}

const ichor_gf256_ops_t ichor_gf256_ops_scalar = {
    .mul_region = gf256_mul_region_scalar,
    .muladd_region = gf256_muladd_region_scalar,
    .backend_tag = ICHOR_GF256_BACKEND_SCALAR,
    .name = "scalar",
};

/* ========================================================================
 * Dispatch
 * ======================================================================== */

_Atomic(const ichor_gf256_ops_t *) ichor_gf256_ops = NULL;

void
ichor_gf256_dispatch_init(void)
{
    if (atomic_load_explicit(&ichor_gf256_ops, memory_order_acquire) != NULL)
        return;

    const ichor_gf256_ops_t *pick = NULL;

    /* feat is consulted only by the hardware backends; a build with none
     * compiled in selects the scalar path unconditionally and never reads it.
     * Priority: GFNI > AVX2 > SSSE3 > scalar. */
#if defined(ICHOR_HAVE_GF256_GFNI) || defined(ICHOR_HAVE_GF256_AVX2) ||        \
    defined(ICHOR_HAVE_GF256_SSSE3) || defined(ICHOR_HAVE_GF256_NEON)
    uint32_t feat = ichor_cpu_features();
#endif
#ifdef ICHOR_HAVE_GF256_GFNI
    if (pick == NULL && (feat & ICHOR_CPU_GFNI) && (feat & ICHOR_CPU_AVX2))
        pick = &ichor_gf256_ops_gfni;
#endif
#ifdef ICHOR_HAVE_GF256_AVX2
    if (pick == NULL && (feat & ICHOR_CPU_AVX2))
        pick = &ichor_gf256_ops_avx2;
#endif
#ifdef ICHOR_HAVE_GF256_SSSE3
    if (pick == NULL && (feat & ICHOR_CPU_SSSE3))
        pick = &ichor_gf256_ops_ssse3;
#endif
#ifdef ICHOR_HAVE_GF256_NEON
    if (pick == NULL && (feat & ICHOR_CPU_NEON))
        pick = &ichor_gf256_ops_neon;
#endif

    if (pick == NULL)
        pick = &ichor_gf256_ops_scalar;

    const ichor_gf256_ops_t *expected = NULL;
    atomic_compare_exchange_strong_explicit(&ichor_gf256_ops, &expected, pick,
                                            memory_order_release,
                                            memory_order_acquire);
}

static const ichor_gf256_ops_t *
gf256_ops(void)
{
    const ichor_gf256_ops_t *ops =
        atomic_load_explicit(&ichor_gf256_ops, memory_order_acquire);
    if (ops == NULL) {
        ichor_gf256_dispatch_init();
        ops = atomic_load_explicit(&ichor_gf256_ops, memory_order_acquire);
    }
    return ops;
}

/* ========================================================================
 * Public forwarders
 * ======================================================================== */

void
ichor_gf256_mul_region(uint8_t *dst, const uint8_t *src, uint8_t a, size_t n)
{
    gf256_ops()->mul_region(dst, src, a, n);
}

void
ichor_gf256_muladd_region(uint8_t *dst, const uint8_t *src, uint8_t a, size_t n)
{
    gf256_ops()->muladd_region(dst, src, a, n);
}

ichor_gf256_region_fn
ichor_gf256_mul_region_resolve(void)
{
    return gf256_ops()->mul_region;
}

ichor_gf256_region_fn
ichor_gf256_muladd_region_resolve(void)
{
    return gf256_ops()->muladd_region;
}

ichor_gf256_backend_t
ichor_gf256_backend(void)
{
    return gf256_ops()->backend_tag;
}

const char *
ichor_gf256_backend_name(void)
{
    switch (ichor_gf256_backend()) {
    case ICHOR_GF256_BACKEND_GFNI:
        return "GFNI GF2P8MULB (x86_64 hardware)";
    case ICHOR_GF256_BACKEND_AVX2:
        return "AVX2 split-nibble vpshufb (x86_64 hardware)";
    case ICHOR_GF256_BACKEND_SSSE3:
        return "SSSE3 split-nibble vpshufb (x86_64 hardware)";
    case ICHOR_GF256_BACKEND_NEON:
        return "NEON TBL (aarch64 hardware)";
    case ICHOR_GF256_BACKEND_SCALAR:
        return "scalar (portable constant-time software)";
    }
    return "unknown";
}

/*
 * Backend health (backend.h): FALLBACK iff the host advertises a hardware
 * GF(2^8) acceleration feature but the active backend is the scalar software
 * path, i.e. the accelerated backend was not compiled into this build.
 */
ichor_backend_health_t
ichor_gf256_backend_health(void)
{
    uint32_t feat = ichor_cpu_features();
    if (ichor_gf256_backend() == ICHOR_GF256_BACKEND_SCALAR &&
        (feat & (ICHOR_CPU_SSSE3 | ICHOR_CPU_NEON)))
        return ICHOR_BACKEND_FALLBACK;
    return ICHOR_BACKEND_OPTIMAL;
}

#ifdef ICHOR_ENABLE_FORCE_BACKEND
/* Test-only hook: clears the cached ops pointer so the next call re-selects a
 * backend.  Compiled out of release / vendored builds. */
void
ichor_gf256_dispatch_reset(void)
{
    atomic_store_explicit(&ichor_gf256_ops, NULL, memory_order_release);
}
#endif /* ICHOR_ENABLE_FORCE_BACKEND */
