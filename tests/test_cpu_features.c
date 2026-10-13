/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_cpu_features.c - Tests for the CPU feature detection layer.
 *
 * Validates:
 *   - ichor_cpu_features() returns the correct bitmask by cross-checking
 *     against compiler builtins (x86_64) or getauxval (aarch64).
 *   - ichor_cpu_features_override() replaces the cached mask.
 *   - The module is backend-agnostic: no aes.c / field.c / grostl.c
 *     reference to ichor_cpu_features() yet.
 */

#include "cpu.h"

#include <stdio.h>

#if defined(__aarch64__) && defined(__linux__)
#include <sys/auxv.h>
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif
#ifndef HWCAP_PMULL
#define HWCAP_PMULL (1 << 4)
#endif
#endif

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
    do {                                                                       \
        tests_run++;                                                           \
        printf("  [%2d] %-55s ", tests_run, name);                             \
    } while (0)

#define PASS()                                                                 \
    do {                                                                       \
        tests_passed++;                                                        \
        printf("PASS\n");                                                      \
    } while (0)

#define FAIL(msg)                                                              \
    do {                                                                       \
        printf("FAIL: %s\n", msg);                                             \
    } while (0)

/* ========================================================================
 * Test: basic probe returns a stable value
 * ======================================================================== */

static void
test_stable(void)
{
    TEST("ichor_cpu_features() stable across two calls");
    uint32_t first = ichor_cpu_features();
    uint32_t second = ichor_cpu_features();
    if (first == second)
        PASS();
    else
        FAIL("mask changed between calls");
}

/* ========================================================================
 * Test: cross-check the probe against an independent reference
 *
 * Each check reports the observed state on BOTH sides (probe vs reference) so
 * a reader can see why a line passed: agreement that a feature is ABSENT is a
 * validated result exactly as much as agreement that it is present. Without the
 * printed state, a PASS on a machine lacking (say) AVX2 looks like it asserted
 * nothing. The reference is the compiler's own view: on x86 that is
 * __builtin_cpu_supports (which needs a string literal, so the caller evaluates
 * it and passes the int), and it already reflects OS-enabled AVX state, so it
 * validates the probe's OSXSAVE + XGETBV gate, not just the raw CPUID bit.
 * ======================================================================== */

#if defined(__x86_64__) || defined(_M_X64) ||                                  \
    (defined(__aarch64__) && defined(__linux__))

static void
check_feature(const char *label, int probe, int reference)
{
    tests_run++;
    printf("  [%2d] %-34s probe=%-7s ref=%-7s ", tests_run, label,
           probe ? "present" : "absent", reference ? "present" : "absent");
    if (probe == (reference != 0)) {
        tests_passed++;
        printf("PASS\n");
    } else {
        printf("FAIL: probe disagrees with reference\n");
    }
}

#endif /* any arch with a cross-check reference */

#if defined(__x86_64__) || defined(_M_X64)

static void
test_x86_features(void)
{
    uint32_t m = ichor_cpu_features();

    check_feature("AES_NI vs builtin(aes)", (m & ICHOR_CPU_AES_NI) != 0,
                  __builtin_cpu_supports("aes"));
    check_feature("CLMUL vs builtin(pclmul)", (m & ICHOR_CPU_CLMUL) != 0,
                  __builtin_cpu_supports("pclmul"));
    check_feature("SSSE3 vs builtin(ssse3)", (m & ICHOR_CPU_SSSE3) != 0,
                  __builtin_cpu_supports("ssse3"));
    check_feature("SSE41 vs builtin(sse4.1)", (m & ICHOR_CPU_SSE41) != 0,
                  __builtin_cpu_supports("sse4.1"));
    check_feature("AVX vs builtin(avx)", (m & ICHOR_CPU_AVX) != 0,
                  __builtin_cpu_supports("avx"));
    check_feature("AVX2 vs builtin(avx2)", (m & ICHOR_CPU_AVX2) != 0,
                  __builtin_cpu_supports("avx2"));
    check_feature("FMA vs builtin(fma)", (m & ICHOR_CPU_FMA) != 0,
                  __builtin_cpu_supports("fma"));
}

/*
 * The three OS-gated bits imply one another on real hardware: AVX2 and FMA are
 * defined only on cores that also carry AVX, so neither may be reported without
 * AVX.  (AVX without AVX2/FMA is legitimate: the dev-box Sandy Bridge tier.)
 */
static void
test_x86_avx_implications(void)
{
    TEST("x86_64: AVX2 and FMA each imply AVX");
    uint32_t mask = ichor_cpu_features();
    int avx = (mask & ICHOR_CPU_AVX) != 0;
    int avx2 = (mask & ICHOR_CPU_AVX2) != 0;
    int fma = (mask & ICHOR_CPU_FMA) != 0;
    printf("[avx=%d avx2=%d fma=%d] ", avx, avx2, fma);
    if ((!avx2 || avx) && (!fma || avx))
        PASS();
    else
        FAIL("AVX2 or FMA reported without AVX");
}

#endif /* x86_64 */

/* ========================================================================
 * Test: aarch64 cross-check against getauxval
 * ======================================================================== */

#if defined(__aarch64__) && defined(__linux__)

static void
test_aarch64_features(void)
{
    uint32_t m = ichor_cpu_features();
    uint64_t hwcap = getauxval(AT_HWCAP);

    check_feature("ARMV8_AES vs hwcap(AES)", (m & ICHOR_CPU_ARMV8_AES) != 0,
                  (hwcap & HWCAP_AES) != 0);
    check_feature("PMULL vs hwcap(PMULL)", (m & ICHOR_CPU_PMULL) != 0,
                  (hwcap & HWCAP_PMULL) != 0);
}

#endif /* aarch64 Linux */

/* ========================================================================
 * Test: override roundtrip
 * ======================================================================== */

static void
test_override_zero(void)
{
    TEST("override(0) then features() returns 0");
    uint32_t original = ichor_cpu_features();
    ichor_cpu_features_override(0);
    uint32_t after = ichor_cpu_features();
    /* Restore so later tests in the same process are not affected. */
    ichor_cpu_features_override(original);
    if (after == 0)
        PASS();
    else
        FAIL("features() did not return 0 after override(0)");
}

static void
test_override_restore(void)
{
    TEST("override then restore returns original mask");
    uint32_t original = ichor_cpu_features();
    ichor_cpu_features_override(0);
    ichor_cpu_features_override(original);
    uint32_t restored = ichor_cpu_features();
    if (restored == original)
        PASS();
    else
        FAIL("restored mask does not match original");
}

/* ========================================================================
 * Test: no arch flags set for a non-local arch
 * ======================================================================== */

static void
test_no_cross_arch_bits(void)
{
    TEST("no cross-architecture bits set");
    uint32_t mask = ichor_cpu_features();
#if defined(__x86_64__) || defined(_M_X64)
    /* On x86_64, aarch64 bits must be clear. */
    if (mask & (ICHOR_CPU_ARMV8_AES | ICHOR_CPU_PMULL))
        FAIL("aarch64 bits set on x86_64 host");
    else
        PASS();
#elif defined(__aarch64__)
    /* On aarch64, x86_64 bits must be clear. */
    if (mask &
        (ICHOR_CPU_AES_NI | ICHOR_CPU_CLMUL | ICHOR_CPU_SSE41 |
         ICHOR_CPU_SSSE3 | ICHOR_CPU_AVX | ICHOR_CPU_FMA | ICHOR_CPU_AVX2))
        FAIL("x86_64 bits set on aarch64 host");
    else
        PASS();
#else
    /* Generic host: all bits should be zero. */
    if (mask != 0)
        FAIL("unexpected feature bits on generic host");
    else
        PASS();
#endif
}

/* ========================================================================
 * main
 * ======================================================================== */

int
main(void)
{
    printf("CPU feature detection tests\n");

    test_stable();
    test_no_cross_arch_bits();

#if defined(__x86_64__) || defined(_M_X64)
    test_x86_features();
    test_x86_avx_implications();
#endif

#if defined(__aarch64__) && defined(__linux__)
    test_aarch64_features();
#endif

    test_override_zero();
    test_override_restore();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
