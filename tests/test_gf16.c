/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_gf16.c - Correctness tests for the GF(2^16) region-multiply primitive.
 *
 * Two CTest profiles: the default (SSSE3 split-nibble vpshufb where present)
 * and a _sw profile forcing ICHOR_FORCE_BACKEND=gf16:scalar.  Each profile
 * checks the active backend against an INDEPENDENT reference multiply (full
 * carry-less product then reduce mod 0x1100B, a different formulation from the
 * library's Russian-peasant backend), EXHAUSTIVELY over all 65536 scalars at a
 * size that spans the 16-element SIMD body and the scalar tail, plus a size
 * sweep, in-place, and resolve-pointer checks.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "gf16.h"

static int failures;

static void
report(const char *name, int ok)
{
    printf("  %-48s %s\n", name, ok ? "ok" : "FAIL");
    if (!ok)
        failures++;
}

/* Independent reference: a (x) b in GF(2^16), poly 0x1100B. */
static uint16_t
ref_mul16(uint16_t a, uint16_t b)
{
    uint32_t prod = 0;
    int i;

    for (i = 0; i < 16; i++)
        if ((b >> i) & 1u)
            prod ^= (uint32_t)a << i;
    for (i = 30; i >= 16; i--)
        if ((prod >> i) & 1u)
            prod ^= (uint32_t)0x1100Bu << (i - 16);
    return (uint16_t)prod;
}

static uint32_t
xs32(uint32_t *s)
{
    uint32_t x = *s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *s = x;
    return x;
}

#define MAXN 128

int
main(void)
{
    uint16_t src[MAXN], dst0[MAXN], got[MAXN], exp[MAXN];
    uint32_t rng = 0x12345678u;
    int exh_mul_ok = 1, exh_mac_ok = 1, sweep_ok = 1, resolve_ok = 1;
    unsigned a;
    size_t i;

    printf("gf16 tests (backend: %s):\n", ichor_gf16_backend_name());

    /* Exhaustive over all 65536 scalars at n = 33 (two SIMD blocks + a tail). */
    {
        const size_t n = 33;
        for (i = 0; i < n; i++) {
            src[i] = (uint16_t)xs32(&rng);
            dst0[i] = (uint16_t)xs32(&rng);
        }
        for (a = 0; a < 65536u; a++) {
            for (i = 0; i < n; i++)
                exp[i] = ref_mul16((uint16_t)a, src[i]);
            memset(got, 0xCC, n * sizeof got[0]);
            ichor_gf16_mul_region(got, src, (uint16_t)a, n);
            if (memcmp(got, exp, n * sizeof got[0]) != 0)
                exh_mul_ok = 0;

            for (i = 0; i < n; i++)
                exp[i] = (uint16_t)(dst0[i] ^ ref_mul16((uint16_t)a, src[i]));
            memcpy(got, dst0, n * sizeof got[0]);
            ichor_gf16_muladd_region(got, src, (uint16_t)a, n);
            if (memcmp(got, exp, n * sizeof got[0]) != 0)
                exh_mac_ok = 0;
        }
    }
    report("mul_region matches reference (all 65536 a, n=33)", exh_mul_ok);
    report("muladd_region matches reference (all 65536 a, n=33)", exh_mac_ok);

    /* Size sweep hitting the SIMD body and every tail length, over a spread of
     * scalars including the field edge cases. */
    {
        static const size_t sizes[] = {0,  1,  2,  7,  8,  15, 16,
                                       17, 31, 32, 33, 48, 64, 100};
        static const uint16_t avals[] = {0x0000, 0x0001, 0x0002, 0x0003,
                                         0x100B, 0x8000, 0xABCD, 0xFFFF};
        size_t k, ai;
        for (k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
            size_t n = sizes[k];
            for (i = 0; i < n; i++) {
                src[i] = (uint16_t)xs32(&rng);
                dst0[i] = (uint16_t)xs32(&rng);
            }
            for (ai = 0; ai < sizeof avals / sizeof avals[0]; ai++) {
                uint16_t av = avals[ai];
                for (i = 0; i < n; i++)
                    exp[i] = ref_mul16(av, src[i]);
                ichor_gf16_mul_region(got, src, av, n);
                if (memcmp(got, exp, n * sizeof got[0]) != 0)
                    sweep_ok = 0;

                for (i = 0; i < n; i++)
                    exp[i] = (uint16_t)(dst0[i] ^ ref_mul16(av, src[i]));
                memcpy(got, dst0, n * sizeof got[0]);
                ichor_gf16_muladd_region(got, src, av, n);
                if (memcmp(got, exp, n * sizeof got[0]) != 0)
                    sweep_ok = 0;
            }
        }
    }
    report("size sweep matches reference", sweep_ok);

    /* Resolved pointers agree with the forwarders. */
    {
        ichor_gf16_region_fn mul = ichor_gf16_mul_region_resolve();
        ichor_gf16_region_fn mac = ichor_gf16_muladd_region_resolve();
        uint16_t s[40], g1[40], g2[40];
        for (i = 0; i < 40; i++)
            s[i] = (uint16_t)xs32(&rng);

        memset(g1, 0, sizeof g1);
        memset(g2, 0, sizeof g2);
        ichor_gf16_mul_region(g1, s, 0x53A7, 40);
        mul(g2, s, 0x53A7, 40);
        if (memcmp(g1, g2, sizeof g1) != 0)
            resolve_ok = 0;

        for (i = 0; i < 40; i++)
            g1[i] = g2[i] = (uint16_t)xs32(&rng);
        ichor_gf16_muladd_region(g1, s, 0x53A7, 40);
        mac(g2, s, 0x53A7, 40);
        if (memcmp(g1, g2, sizeof g1) != 0)
            resolve_ok = 0;
    }
    report("resolve() pointers match forwarders", resolve_ok);

    /* In-place (dst == src). */
    {
        uint16_t buf[40], ref[40];
        int inplace_ok = 1;
        for (i = 0; i < 40; i++)
            buf[i] = ref[i] = (uint16_t)xs32(&rng);
        for (i = 0; i < 40; i++)
            ref[i] = ref_mul16(0x1D2C, ref[i]);
        ichor_gf16_mul_region(buf, buf, 0x1D2C, 40);
        if (memcmp(buf, ref, sizeof buf) != 0)
            inplace_ok = 0;
        report("mul_region in place (dst == src)", inplace_ok);
    }

    if (failures == 0)
        printf("gf16: all tests passed\n");
    else
        printf("gf16: %d FAILED\n", failures);
    return failures == 0 ? 0 : 1;
}
