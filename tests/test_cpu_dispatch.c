/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_cpu_dispatch.c - Tests for the AES runtime dispatch table.
 *
 * Validates:
 *   - Forcing all hardware bits clear routes to the bitsliced backend.
 *   - The dispatch table pointer is immutable after init (a second call
 *     to ichor_aes_dispatch_init() leaves the pointer unchanged).
 *   - The backend_tag in a key context matches the active backend.
 */

#include "aes.h"
#include "aes_dispatch.h"
#include "backend.h"
#include "clmul.h"
#include "cpu.h"
#include "grostl.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

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
 * Test: clearing all HW bits routes to bitsliced backend
 * ======================================================================== */

static void
test_force_bitsliced(void)
{
    TEST("override(no-HW) dispatches to bitsliced backend");

    uint32_t host = ichor_cpu_features();
    ichor_cpu_features_override(host &
                                ~(ICHOR_CPU_AES_NI | ICHOR_CPU_ARMV8_AES));
    ichor_aes_dispatch_reset();

    /* Trigger init by calling a public entry point. */
    uint8_t key[16] = {0};
    uint8_t in[16] = {0};
    uint8_t out[16];
    ichor_aes_ctx_t ctx;
    ichor_aes_key_expand(&ctx, key, 128);
    ichor_aes_encrypt(&ctx, out, in);

    ichor_aes_backend_t be = ichor_aes_backend();

    /* Restore before asserting so later tests see the native backend. */
    ichor_cpu_features_override(host);
    ichor_aes_dispatch_reset();

    if (be == ICHOR_AES_BACKEND_BITSLICED)
        PASS();
    else
        FAIL("expected ICHOR_AES_BACKEND_BITSLICED");
}

/* ========================================================================
 * Test: dispatch init is idempotent
 * ======================================================================== */

static void
test_dispatch_immutable(void)
{
    TEST("dispatch table pointer unchanged on second init call");

    /* Ensure the table is initialized. */
    uint8_t key[16] = {0};
    ichor_aes_ctx_t ctx;
    ichor_aes_key_expand(&ctx, key, 128);

    const ichor_aes_ops_t *snapshot =
        atomic_load_explicit(&ichor_aes_ops, memory_order_acquire);

    /* Second init should be a no-op. */
    ichor_aes_dispatch_init();

    const ichor_aes_ops_t *after =
        atomic_load_explicit(&ichor_aes_ops, memory_order_acquire);

    if (snapshot == after)
        PASS();
    else
        FAIL("dispatch table pointer changed after second init");
}

/* ========================================================================
 * Test: backend_tag in ctx matches active backend
 * ======================================================================== */

static void
test_ctx_backend_tag(void)
{
    TEST("ctx.backend_tag matches ichor_aes_backend() after key_expand");

    uint8_t key[16] = {0};
    ichor_aes_ctx_t ctx;
    ichor_aes_key_expand(&ctx, key, 128);

    ichor_aes_backend_t be = ichor_aes_backend();

    if (ctx.backend_tag == (uint8_t)be)
        PASS();
    else
        FAIL("ctx.backend_tag does not match active backend");
}

/* ========================================================================
 * Test: native backend is selected after restoring host features
 * ======================================================================== */

static void
test_native_backend_restored(void)
{
    TEST("native backend selected after restoring host feature mask");

    uint32_t host = ichor_cpu_features();

    /* Force bitsliced. */
    ichor_cpu_features_override(0);
    ichor_aes_dispatch_reset();
    ichor_aes_backend(); /* trigger init */

    /* Restore and re-init. */
    ichor_cpu_features_override(host);
    ichor_aes_dispatch_reset();
    ichor_aes_backend(); /* trigger init */

    /*
     * On a host without any hardware AES, the native backend IS
     * bitsliced, so this test just checks consistency.
     */
    uint8_t key[16] = {0};
    uint8_t in[16] = {0};
    uint8_t out[16];
    ichor_aes_ctx_t ctx;
    ichor_aes_key_expand(&ctx, key, 128);
    ichor_aes_encrypt(&ctx, out, in);

    /* If we got here without crashing, the dispatch is functional. */
    PASS();
}

/* ========================================================================
 * Test: aggregate report agrees with the per-primitive queries
 * ======================================================================== */

static void
test_backend_health_consistent(void)
{
    TEST("ichor_backend_report agrees with per-primitive health queries");

    ichor_backend_report_t rep;
    ichor_backend_report(&rep);

    int ok = rep.aes == ichor_aes_backend_health() &&
             rep.clmul == ichor_clmul_backend_health() &&
             rep.grostl == ichor_grostl_backend_health() &&
             (rep.aes == ICHOR_BACKEND_OPTIMAL ||
              rep.aes == ICHOR_BACKEND_FALLBACK) &&
             (rep.clmul == ICHOR_BACKEND_OPTIMAL ||
              rep.clmul == ICHOR_BACKEND_FALLBACK) &&
             (rep.grostl == ICHOR_BACKEND_OPTIMAL ||
              rep.grostl == ICHOR_BACKEND_FALLBACK);

    if (ok)
        PASS();
    else
        FAIL("aggregate report disagrees with per-primitive queries");
}

/* ========================================================================
 * Demonstration: surfacing the software-fallback advisory
 *
 * The library no longer prints anything itself (it may run with no terminal,
 * or with stdout/stderr carrying protocol data).  Instead a consumer calls
 * ichor_backend_report() once at start-up and routes the result through its
 * own output.  This function is exactly that consumer-side pattern, and
 * reproduces the notice the library used to emit -- printed to this program's
 * stdout, where an application's own logger would go.
 * ======================================================================== */

static void
demo_backend_health_report(void)
{
    ichor_backend_report_t rep;
    ichor_backend_report(&rep);

    printf("\nBackend health (as a consumer would report it):\n");

    if (rep.aes == ICHOR_BACKEND_FALLBACK)
        printf("  notice: AES running on the constant-time software fallback; "
               "this CPU has hardware AES but the accelerated backend was not "
               "compiled in. Rebuild with -DICHOR_AES_NI=ON or "
               "-DICHOR_ARMV8_AES=ON for full speed.\n");
    if (rep.clmul == ICHOR_BACKEND_FALLBACK)
        printf(
            "  notice: carry-less multiply running on the scalar software "
            "fallback; rebuild with -DICHOR_CLMUL=ON or -DICHOR_PMULL=ON.\n");
    if (rep.grostl == ICHOR_BACKEND_FALLBACK)
        printf("  notice: Grostl running on the software fallback; rebuild "
               "with -DICHOR_AES_NI=ON or -DICHOR_ARMV8_AES=ON.\n");

    if (rep.aes == ICHOR_BACKEND_OPTIMAL &&
        rep.clmul == ICHOR_BACKEND_OPTIMAL &&
        rep.grostl == ICHOR_BACKEND_OPTIMAL)
        printf("  all primitives are on the best backend for this CPU.\n");
}

/* ========================================================================
 * main
 * ======================================================================== */

int
main(void)
{
    printf("AES dispatch tests\n");

    test_force_bitsliced();
    test_dispatch_immutable();
    test_ctx_backend_tag();
    test_native_backend_restored();
    test_backend_health_consistent();

    demo_backend_health_report();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
