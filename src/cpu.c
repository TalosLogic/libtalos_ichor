/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * cpu.c - Cached CPU feature query and override hook.
 *
 * The bitmask is computed once on first use via a hand-rolled
 * compare-and-swap guard on a static atomic uint32_t.  Sentinel value
 * 0x80000000u means "not yet initialized"; the high bit lies outside
 * the defined feature bits (all in bits 0-17), so post-init values
 * never collide with the sentinel.
 *
 * Per-architecture probing lives in cpu_x86.c, cpu_aarch64.c, and
 * cpu_generic.c; exactly one of those files defines ichor_cpu_probe()
 * for any given build target.
 *
 * ICHOR_FORCE_BACKEND: comma-separated list of domain:value pairs
 * read once during the first call to ichor_cpu_features().  Used to
 * strip feature bits so the dispatch table routes to a specific backend
 * -- chiefly to exercise the constant-time software path on hardware
 * that has AES acceleration.  Format example: "aes:bitsliced" or
 * "clmul:scalar"; multiple pairs are comma-separated.
 *
 * This is a test-only facility.  The parser (and its getenv) is compiled
 * in only when ICHOR_ENABLE_FORCE_BACKEND is defined, which the build
 * system sets for first-party / test / dudect builds and leaves unset in
 * a release/vendored build.  A malformed pair,
 * an unknown domain/value, or a backend the CPU lacks is silently ignored
 * (the mask is left as probed for that token); library code never writes to
 * stderr and never calls abort().  Tests confirm the requested backend by
 * inspecting the resulting selection (ichor_aes_backend() etc.), so the
 * parser needs no diagnostics of its own.
 */

#include "cpu.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define CPU_FEATURES_UNINIT 0x80000000u

static _Atomic(uint32_t) g_features = CPU_FEATURES_UNINIT;

/* Provided by the per-arch TU compiled for this target. */
uint32_t ichor_cpu_probe(void);

/* ========================================================================
 * ICHOR_FORCE_BACKEND parser
 * ======================================================================== */

#ifdef ICHOR_ENABLE_FORCE_BACKEND

/*
 * Parse the ICHOR_FORCE_BACKEND environment variable and return a modified
 * feature mask.  A malformed pair, an unknown domain/value, or a requested
 * backend the CPU lacks is silently ignored (the mask is left as probed for
 * that token); this function does no I/O and never aborts.  Tests verify the
 * effect by inspecting the resulting backend selection.
 */
static uint32_t
apply_force_backend(uint32_t mask)
{
    const char *env = getenv("ICHOR_FORCE_BACKEND");
    if (env == NULL)
        return mask;

    /* Copy into a local buffer.  A value over 255 chars is malformed. */
    char buf[256];
    size_t len = strlen(env);
    if (len >= sizeof(buf))
        return mask;
    memcpy(buf, env, len + 1);

    const char *p = buf;
    while (*p != '\0') {
        /* Token runs up to the next comma or NUL. */
        const char *tend = p;
        while (*tend != ',' && *tend != '\0')
            tend++;

        /* Split the token on the ':' separating domain from value.  A token
         * with no ':' is malformed and left to fall through unchanged. */
        const char *colon = p;
        while (colon < tend && *colon != ':')
            colon++;

        if (colon != tend) {
            const char *vstart = colon + 1;
            size_t dlen = (size_t)(colon - p);
            size_t vlen = (size_t)(tend - vstart);

#define DMATCH(s) (dlen == sizeof(s) - 1 && memcmp(p, (s), dlen) == 0)
#define VMATCH(s) (vlen == sizeof(s) - 1 && memcmp(vstart, (s), vlen) == 0)

            if (DMATCH("aes")) {
                if (VMATCH("bitsliced"))
                    mask &= ~(ICHOR_CPU_AES_NI | ICHOR_CPU_ARMV8_AES);
                else if (VMATCH("aesni") && (mask & ICHOR_CPU_AES_NI))
                    mask &= ~ICHOR_CPU_ARMV8_AES;
                else if (VMATCH("armv8") && (mask & ICHOR_CPU_ARMV8_AES))
                    mask &= ~ICHOR_CPU_AES_NI;
                /* unknown value, or a backend the CPU lacks: leave as probed */
            } else if (DMATCH("clmul")) {
                if (VMATCH("scalar"))
                    mask &= ~(ICHOR_CPU_CLMUL | ICHOR_CPU_PMULL);
                else if (VMATCH("pclmul") && (mask & ICHOR_CPU_CLMUL))
                    mask &= ~ICHOR_CPU_PMULL;
                else if (VMATCH("pmull") && (mask & ICHOR_CPU_PMULL))
                    mask &= ~ICHOR_CPU_CLMUL;
                /* unknown value, or a backend the CPU lacks: leave as probed */
            }
            /* unknown domain: leave as probed */

#undef DMATCH
#undef VMATCH
        }

        p = (*tend == ',') ? tend + 1 : tend;
    }
    return mask;
}

#else /* !ICHOR_ENABLE_FORCE_BACKEND */

/*
 * Release / vendored build: the environment override is not compiled in,
 * so neither the getenv nor any process-terminating path exists.  Feature
 * bits come straight from the hardware probe.
 */
static uint32_t
apply_force_backend(uint32_t mask)
{
    return mask;
}

#endif /* ICHOR_ENABLE_FORCE_BACKEND */

/* ========================================================================
 * Public API
 * ======================================================================== */

uint32_t
ichor_cpu_features(void)
{
    uint32_t cur;
    uint32_t probed;
    uint32_t expected;

    cur = atomic_load_explicit(&g_features, memory_order_acquire);
    if (cur != CPU_FEATURES_UNINIT)
        return cur;

    probed = apply_force_backend(ichor_cpu_probe());
    expected = CPU_FEATURES_UNINIT;

    /*
     * CAS: winner stores probed; loser's value is dropped.  Both
     * paths then re-read, returning the winner's value.  The probe
     * is deterministic so either result is identical.
     */
    atomic_compare_exchange_strong_explicit(&g_features, &expected, probed,
                                            memory_order_release,
                                            memory_order_acquire);
    return atomic_load_explicit(&g_features, memory_order_acquire);
}

#ifdef ICHOR_ENABLE_FORCE_BACKEND
/*
 * Test-only hook: stores an arbitrary feature
 * mask into the cached word so tests can cycle backends.  A mask claiming a
 * feature the CPU lacks would route dispatch to an unrunnable backend, so it
 * is compiled out of release / vendored builds along with the other test
 * hooks (see ICHOR_ENABLE_FORCE_BACKEND in CMakeLists.txt).
 */
void
ichor_cpu_features_override(uint32_t mask)
{
    atomic_store_explicit(&g_features, mask, memory_order_release);
}
#endif /* ICHOR_ENABLE_FORCE_BACKEND */
