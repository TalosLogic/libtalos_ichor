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

/* sysconf(_SC_NPROCESSORS_*) is exposed by glibc under _POSIX_C_SOURCE; macOS
 * hides sysctlbyname under a strict _POSIX_C_SOURCE / -std=c17, so on Apple we
 * also request _DARWIN_C_SOURCE.  Mirrors the feature-macro setup in pool.c. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif

#include "cpu.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

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
                    mask &= ~(ICHOR_CPU_AES_NI | ICHOR_CPU_ARMV8_AES |
                              ICHOR_CPU_VAES);
                else if (VMATCH("aesni") && (mask & ICHOR_CPU_AES_NI))
                    mask &= ~(ICHOR_CPU_ARMV8_AES | ICHOR_CPU_VAES);
                else if (VMATCH("armv8") && (mask & ICHOR_CPU_ARMV8_AES))
                    mask &= ~(ICHOR_CPU_AES_NI | ICHOR_CPU_VAES);
                else if (VMATCH("vaes") && (mask & ICHOR_CPU_VAES))
                    mask &= ~(ICHOR_CPU_AES_NI | ICHOR_CPU_ARMV8_AES);
                /* unknown value, or a backend the CPU lacks: leave as probed */
            } else if (DMATCH("clmul")) {
                if (VMATCH("scalar"))
                    mask &= ~(ICHOR_CPU_CLMUL | ICHOR_CPU_PMULL);
                else if (VMATCH("pclmul") && (mask & ICHOR_CPU_CLMUL))
                    mask &= ~ICHOR_CPU_PMULL;
                else if (VMATCH("pmull") && (mask & ICHOR_CPU_PMULL))
                    mask &= ~ICHOR_CPU_CLMUL;
                /* unknown value, or a backend the CPU lacks: leave as probed */
            } else if (DMATCH("gf256") || DMATCH("gf16")) {
                /*
                 * gf256 / gf16 region-multiply dispatch keys on GFNI, AVX2 and
                 * SSSE3 (x86) or NEON (aarch64); priority is gfni (GFNI+AVX2) >
                 * avx2 (AVX2) > ssse3 (SSSE3) > neon (aarch64) > scalar.
                 * Forcing a backend clears the bits that would select a
                 * higher-priority one.  "gfni" (x86) / "neon" (aarch64) is the
                 * default top pick, so no token forces it up.  Clearing these
                 * bits affects only this dispatch here; AES / Grostl key on the
                 * same bits but are selected by their own tokens.  Test-only.
                 */
                if (VMATCH("scalar"))
                    mask &= ~(ICHOR_CPU_SSSE3 | ICHOR_CPU_AVX2 |
                              ICHOR_CPU_GFNI | ICHOR_CPU_NEON);
                else if (VMATCH("ssse3"))
                    mask &= ~(ICHOR_CPU_AVX2 | ICHOR_CPU_GFNI);
                else if (VMATCH("avx2") && (mask & ICHOR_CPU_AVX2))
                    mask &= ~ICHOR_CPU_GFNI;
                /* unknown value, or a backend the CPU lacks: leave as probed */
            } else if (DMATCH("grostl")) {
                /*
                 * Grostl dispatch keys on the same AES-NI / GFNI / AVX2 bits as
                 * the AES backends, so forcing a Grostl backend clears the bits
                 * that would select a higher-priority one.  Priority is
                 * avx2gfni (GFNI+AVX2) > avx2 (AVX2+AES-NI) > aesni (AES-NI) >
                 * soft.  "avx2gfni" is the default top pick, so no token forces
                 * it up.  These are test-only knobs; the collateral effect on
                 * AES dispatch in the same process does not matter to the
                 * Grostl tests that use them.
                 */
                if (VMATCH("soft"))
                    mask &= ~(ICHOR_CPU_AES_NI | ICHOR_CPU_ARMV8_AES |
                              ICHOR_CPU_GFNI);
                else if (VMATCH("aesni") && (mask & ICHOR_CPU_AES_NI))
                    mask &= ~(ICHOR_CPU_GFNI | ICHOR_CPU_AVX2);
                else if (VMATCH("avx2") && (mask & ICHOR_CPU_AVX2) &&
                         (mask & ICHOR_CPU_AES_NI))
                    mask &= ~ICHOR_CPU_GFNI;
                /* unknown value, or a backend the CPU lacks: leave as probed */
            } else if (DMATCH("keccak")) {
                /*
                 * Keccak dispatch keys on AVX2 (the x86 4-way batch) and on
                 * SHA3 (the aarch64 single-sponge kernel), each "feature >
                 * scalar".  "scalar" clears both to force the portable paths
                 * (the 4x serial batch and the scalar single-sponge
                 * permutation).  The hardware tokens are the default top picks,
                 * so none forces up.  As with the gf256 / grostl knobs,
                 * clearing these collaterally affects any other dispatch on the
                 * same bits in this process; that does not matter to the Keccak
                 * tests that use this. Test-only.
                 */
                if (VMATCH("scalar"))
                    mask &= ~(ICHOR_CPU_AVX2 | ICHOR_CPU_SHA3);
                /* unknown value: leave as probed */
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

/* ========================================================================
 * Core-count detection (docs/THREAD_POOL.md Section 11)
 *
 * The physical-core count is derived from OS topology, never from CPUID: the
 * CPUID SMT-shift shortcut divides the logical count by threads-per-core, which
 * is wrong on hybrid parts (an Intel P/E CPU has SMT=2 P-cores and SMT=1
 * E-cores, so a single ratio does not hold).  The OS topology views below are
 * correct on hybrid parts for free.
 * ======================================================================== */

unsigned
ichor_cpu_logical_cpus(void)
{
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1) {
        return 1u;
    }
    return (unsigned)n;
}

#if defined(__APPLE__)

static unsigned
apple_physical_cores(void)
{
    int n = 0;
    size_t len = sizeof(n);
    if (sysctlbyname("hw.physicalcpu", &n, &len, NULL, 0) == 0 && n >= 1) {
        return (unsigned)n;
    }
    return 0u;
}

#elif defined(__linux__)

/*
 * Count distinct physical cores from sysfs.  Each online CPU's
 * thread_siblings_list names its sibling group, and the smallest id in the list
 * (always listed first) is the group's representative; counting distinct
 * representatives counts physical cores and is correct on hybrid parts.  Returns
 * 0 if sysfs topology is unavailable.
 */
static unsigned
linux_sysfs_physical_cores(void)
{
    long conf = sysconf(_SC_NPROCESSORS_CONF);
    if (conf < 1) {
        conf = sysconf(_SC_NPROCESSORS_ONLN);
    }
    if (conf < 1) {
        return 0u;
    }

    unsigned char *seen = calloc((size_t)conf, 1);
    if (seen == NULL) {
        return 0u;
    }

    unsigned count = 0;
    int readable = 0;
    for (long i = 0; i < conf; i++) {
        char path[128];
        int k = snprintf(path, sizeof(path),
                         "/sys/devices/system/cpu/cpu%ld/topology/"
                         "thread_siblings_list",
                         i);
        if (k < 0 || (size_t)k >= sizeof(path)) {
            continue;
        }
        FILE *f = fopen(path, "r");
        if (f == NULL) {
            continue; /* offline CPU, or no sysfs topology */
        }
        long rep = -1;
        int got = fscanf(f, "%ld", &rep);
        fclose(f);
        if (got != 1 || rep < 0 || rep >= conf) {
            continue;
        }
        readable = 1;
        if (!seen[rep]) {
            seen[rep] = 1;
            count++;
        }
    }

    free(seen);
    return readable ? count : 0u;
}

#define CPUINFO_MAX_PAIRS 4096u

static void
cpuinfo_add_pair(uint64_t *pairs, unsigned *npairs, int *overflow, long phys,
                 long core)
{
    uint64_t key = ((uint64_t)(uint32_t)phys << 32) | (uint64_t)(uint32_t)core;
    for (unsigned k = 0; k < *npairs; k++) {
        if (pairs[k] == key) {
            return;
        }
    }
    if (*npairs >= CPUINFO_MAX_PAIRS) {
        *overflow = 1;
        return;
    }
    pairs[(*npairs)++] = key;
}

/*
 * Fallback for a system without sysfs topology: count distinct
 * (physical id, core id) pairs in /proc/cpuinfo.  Each processor block carries
 * one of each; a pair repeated across blocks is a hyperthread sibling.  Returns
 * 0 if /proc/cpuinfo is unavailable, unparseable, or has more pairs than the
 * bounded table holds.
 */
static unsigned
linux_cpuinfo_physical_cores(void)
{
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f == NULL) {
        return 0u;
    }

    uint64_t *pairs = calloc(CPUINFO_MAX_PAIRS, sizeof(*pairs));
    if (pairs == NULL) {
        fclose(f);
        return 0u;
    }

    unsigned npairs = 0;
    int overflow = 0;
    long phys = -1;
    long core = -1;
    int have_phys = 0;
    int have_core = 0;
    char line[256];

    while (fgets(line, sizeof(line), f) != NULL) {
        if (line[0] == '\n') {
            if (have_phys && have_core) {
                cpuinfo_add_pair(pairs, &npairs, &overflow, phys, core);
            }
            phys = core = -1;
            have_phys = have_core = 0;
            continue;
        }
        long v;
        if (sscanf(line, "physical id : %ld", &v) == 1) {
            phys = v;
            have_phys = 1;
        } else if (sscanf(line, "core id : %ld", &v) == 1) {
            core = v;
            have_core = 1;
        }
    }
    /* A final block need not be terminated by a blank line. */
    if (have_phys && have_core) {
        cpuinfo_add_pair(pairs, &npairs, &overflow, phys, core);
    }

    free(pairs);
    fclose(f);
    if (overflow || npairs == 0) {
        return 0u;
    }
    return npairs;
}

#endif /* platform */

unsigned
ichor_cpu_physical_cores(void)
{
#if defined(__APPLE__)
    unsigned n = apple_physical_cores();
    if (n >= 1u) {
        return n;
    }
#elif defined(__linux__)
    unsigned n = linux_sysfs_physical_cores();
    if (n >= 1u) {
        return n;
    }
    n = linux_cpuinfo_physical_cores();
    if (n >= 1u) {
        return n;
    }
#endif
    return ichor_cpu_logical_cpus();
}
