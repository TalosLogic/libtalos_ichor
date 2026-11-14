/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf16.c - GF(2^16) region-multiply public forwarders, runtime dispatch, and
 * the portable constant-time scalar backend.
 *
 * On first call, ichor_gf16_dispatch_init() reads ichor_cpu_features() and
 * selects the highest-priority compiled-in backend whose feature bit is
 * present:
 *   1. SSSE3   (x86_64; ICHOR_HAVE_GF16_SSSE3 compiled in, ICHOR_CPU_SSSE3)
 *   2. Scalar  (portable constant-time; always compiled in)
 *
 * Both backends are constant-time; the dispatch decision is data-independent.
 */

#include "gf16.h"
#include "gf16_dispatch.h"
#include "backend.h"
#include "cpu.h"

#include <stdatomic.h>

/* ========================================================================
 * Shared scalar GF(2^16) multiply (poly 0x1100B, reduction constant 0x100B)
 * ======================================================================== */

/*
 * Constant-time product of a and b in GF(2^16) = F_2[x]/(x^16+x^12+x^3+x+1).
 *
 * Russian-peasant over the 16 bits of b: for each set bit the current a is
 * XORed into the accumulator, then a is doubled and reduced by 0x100B
 * whenever its top bit was set.  The set-bit test and the reduction are both
 * folded into 0/all-ones masks, so no control flow depends on a or b.
 */
uint16_t
ichor_gf16_mul_scalar(uint16_t a, uint16_t b)
{
    uint16_t p = 0;
    int i;

    for (i = 0; i < 16; i++) {
        uint16_t bmask = (uint16_t)0 - (uint16_t)(b & 1u);
        p ^= a & bmask;
        uint16_t hi = (uint16_t)0 - (uint16_t)(a >> 15);
        a = (uint16_t)((uint16_t)(a << 1) ^ (uint16_t)(0x100Bu & hi));
        b = (uint16_t)(b >> 1);
    }
    return p;
}

/* ========================================================================
 * Scalar backend (always compiled in)
 * ======================================================================== */

static void
gf16_mul_region_scalar(uint16_t *dst, const uint16_t *src, uint16_t a, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        dst[i] = ichor_gf16_mul_scalar(a, src[i]);
}

static void
gf16_muladd_region_scalar(uint16_t *dst, const uint16_t *src, uint16_t a,
                          size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        dst[i] ^= ichor_gf16_mul_scalar(a, src[i]);
}

const ichor_gf16_ops_t ichor_gf16_ops_scalar = {
    .mul_region = gf16_mul_region_scalar,
    .muladd_region = gf16_muladd_region_scalar,
    .backend_tag = ICHOR_GF16_BACKEND_SCALAR,
    .name = "scalar",
};

/* ========================================================================
 * Dispatch
 * ======================================================================== */

_Atomic(const ichor_gf16_ops_t *) ichor_gf16_ops = NULL;

void
ichor_gf16_dispatch_init(void)
{
    if (atomic_load_explicit(&ichor_gf16_ops, memory_order_acquire) != NULL)
        return;

    const ichor_gf16_ops_t *pick = NULL;

    /* Priority: GFNI > SSSE3 > scalar.  feat is read only when a hardware
     * backend is compiled in.  There is no gf16 AVX2 vpshufb backend: the
     * 16-bit interleaved layout forces lane-crossing permutes whose cost
     * cancels the widening (a wash-to-regression vs SSSE3 on every test host),
     * while GFNI covers the premium path. */
#if defined(ICHOR_HAVE_GF16_GFNI) || defined(ICHOR_HAVE_GF16_SSSE3) ||         \
    defined(ICHOR_HAVE_GF16_NEON)
    uint32_t feat = ichor_cpu_features();
#endif
#ifdef ICHOR_HAVE_GF16_GFNI
    if (pick == NULL && (feat & ICHOR_CPU_GFNI) && (feat & ICHOR_CPU_AVX2))
        pick = &ichor_gf16_ops_gfni;
#endif
#ifdef ICHOR_HAVE_GF16_SSSE3
    if (pick == NULL && (feat & ICHOR_CPU_SSSE3))
        pick = &ichor_gf16_ops_ssse3;
#endif
#ifdef ICHOR_HAVE_GF16_NEON
    if (pick == NULL && (feat & ICHOR_CPU_NEON))
        pick = &ichor_gf16_ops_neon;
#endif

    if (pick == NULL)
        pick = &ichor_gf16_ops_scalar;

    const ichor_gf16_ops_t *expected = NULL;
    atomic_compare_exchange_strong_explicit(&ichor_gf16_ops, &expected, pick,
                                            memory_order_release,
                                            memory_order_acquire);
}

static const ichor_gf16_ops_t *
gf16_ops(void)
{
    const ichor_gf16_ops_t *ops =
        atomic_load_explicit(&ichor_gf16_ops, memory_order_acquire);
    if (ops == NULL) {
        ichor_gf16_dispatch_init();
        ops = atomic_load_explicit(&ichor_gf16_ops, memory_order_acquire);
    }
    return ops;
}

/* ========================================================================
 * Public forwarders
 * ======================================================================== */

void
ichor_gf16_mul_region(uint16_t *dst, const uint16_t *src, uint16_t a, size_t n)
{
    gf16_ops()->mul_region(dst, src, a, n);
}

void
ichor_gf16_muladd_region(uint16_t *dst, const uint16_t *src, uint16_t a,
                         size_t n)
{
    gf16_ops()->muladd_region(dst, src, a, n);
}

ichor_gf16_region_fn
ichor_gf16_mul_region_resolve(void)
{
    return gf16_ops()->mul_region;
}

ichor_gf16_region_fn
ichor_gf16_muladd_region_resolve(void)
{
    return gf16_ops()->muladd_region;
}

ichor_gf16_backend_t
ichor_gf16_backend(void)
{
    return gf16_ops()->backend_tag;
}

const char *
ichor_gf16_backend_name(void)
{
    switch (ichor_gf16_backend()) {
    case ICHOR_GF16_BACKEND_GFNI:
        return "GFNI affine (fixed-scalar, x86_64 hardware)";
    case ICHOR_GF16_BACKEND_SSSE3:
        return "SSSE3 split-nibble vpshufb (x86_64 hardware)";
    case ICHOR_GF16_BACKEND_NEON:
        return "NEON TBL (aarch64 hardware)";
    case ICHOR_GF16_BACKEND_SCALAR:
        return "scalar (portable constant-time software)";
    }
    return "unknown";
}

/*
 * Backend health (backend.h): FALLBACK iff the host advertises a hardware
 * acceleration feature but the active backend is the scalar software path.
 */
ichor_backend_health_t
ichor_gf16_backend_health(void)
{
    uint32_t feat = ichor_cpu_features();
    if (ichor_gf16_backend() == ICHOR_GF16_BACKEND_SCALAR &&
        (feat & (ICHOR_CPU_SSSE3 | ICHOR_CPU_NEON)))
        return ICHOR_BACKEND_FALLBACK;
    return ICHOR_BACKEND_OPTIMAL;
}

#ifdef ICHOR_ENABLE_FORCE_BACKEND
void
ichor_gf16_dispatch_reset(void)
{
    atomic_store_explicit(&ichor_gf16_ops, NULL, memory_order_release);
}
#endif /* ICHOR_ENABLE_FORCE_BACKEND */
