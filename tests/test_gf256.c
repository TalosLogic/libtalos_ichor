/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_gf256.c - Correctness tests for the GF(2^8) region-multiply primitive.
 *
 * The same assertions run under two CTest profiles: the default hardware
 * profile (SSSE3 split-nibble vpshufb where present) and a _sw profile that
 * forces ICHOR_FORCE_BACKEND=gf256:scalar, so the constant-time scalar
 * fallback is validated on every host.  Each profile checks the active
 * backend against an INDEPENDENT reference multiply (full carry-less product
 * then reduce mod 0x11B, a different formulation from the library's
 * Russian-peasant backend), exhaustively over all 256 scalars and across
 * region lengths that exercise the 16-byte SIMD body and the scalar tail.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "gf256.h"

static int failures;

static void
report(const char *name, int ok)
{
    printf("  %-44s %s\n", name, ok ? "ok" : "FAIL");
    if (!ok)
        failures++;
}

/* Independent reference: a (x) b in GF(2^8), poly 0x11B.  Full 15-bit
 * carry-less product, then polynomial reduction from the top bit down. */
static uint8_t
ref_mul(uint8_t a, uint8_t b)
{
    uint16_t prod = 0;
    int i;

    for (i = 0; i < 8; i++)
        if ((b >> i) & 1u)
            prod ^= (uint16_t)((uint16_t)a << i);
    for (i = 15; i >= 8; i--)
        if ((prod >> i) & 1u)
            prod ^= (uint16_t)(0x11Bu << (i - 8));
    return (uint8_t)prod;
}

/* Deterministic xorshift32 so the pseudo-random regions are reproducible. */
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

#define MAXN 257

int
main(void)
{
    static const size_t sizes[] = {0,  1,  2,  15,  16,  17,  31,  32,  33,
                                   48, 63, 64, 127, 128, 129, 200, 255, 256};
    uint8_t src[MAXN], dst0[MAXN], got[MAXN], exp[MAXN];
    uint32_t rng = 0x9e3779b9u;
    int mul_ok = 1, mac_ok = 1, resolve_ok = 1;
    unsigned a;
    size_t k, i;

    printf("gf256 tests (backend: %s):\n", ichor_gf256_backend_name());

    for (k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        size_t n = sizes[k];
        for (i = 0; i < n; i++) {
            src[i] = (uint8_t)xs32(&rng);
            dst0[i] = (uint8_t)xs32(&rng);
        }
        for (a = 0; a < 256; a++) {
            /* mul_region: dst = a (x) src */
            for (i = 0; i < n; i++)
                exp[i] = ref_mul((uint8_t)a, src[i]);
            memset(got, 0xCC, n);
            ichor_gf256_mul_region(got, src, (uint8_t)a, n);
            if (memcmp(got, exp, n) != 0)
                mul_ok = 0;

            /* muladd_region: dst ^= a (x) src, over a nonzero initial dst */
            for (i = 0; i < n; i++)
                exp[i] = (uint8_t)(dst0[i] ^ ref_mul((uint8_t)a, src[i]));
            memcpy(got, dst0, n);
            ichor_gf256_muladd_region(got, src, (uint8_t)a, n);
            if (memcmp(got, exp, n) != 0)
                mac_ok = 0;
        }
    }
    report("mul_region matches reference (all a, all sizes)", mul_ok);
    report("muladd_region matches reference (all a, all sizes)", mac_ok);

    /* Resolved function pointers must agree with the forwarders. */
    {
        ichor_gf256_region_fn mul = ichor_gf256_mul_region_resolve();
        ichor_gf256_region_fn mac = ichor_gf256_muladd_region_resolve();
        uint8_t s[40], g1[40], g2[40];
        for (i = 0; i < sizeof s; i++)
            s[i] = (uint8_t)xs32(&rng);

        memset(g1, 0, sizeof g1);
        memset(g2, 0, sizeof g2);
        ichor_gf256_mul_region(g1, s, 0x53, sizeof s);
        mul(g2, s, 0x53, sizeof s);
        if (memcmp(g1, g2, sizeof s) != 0)
            resolve_ok = 0;

        for (i = 0; i < sizeof s; i++)
            g1[i] = g2[i] = (uint8_t)xs32(&rng);
        ichor_gf256_muladd_region(g1, s, 0x53, sizeof s);
        mac(g2, s, 0x53, sizeof s);
        if (memcmp(g1, g2, sizeof s) != 0)
            resolve_ok = 0;
    }
    report("resolve() pointers match forwarders", resolve_ok);

    /* In-place (dst == src) must behave as specified. */
    {
        uint8_t buf[40], ref[40];
        int inplace_ok = 1;
        for (i = 0; i < sizeof buf; i++)
            buf[i] = ref[i] = (uint8_t)xs32(&rng);
        for (i = 0; i < sizeof buf; i++)
            ref[i] = ref_mul(0x1D, ref[i]);
        ichor_gf256_mul_region(buf, buf, 0x1D, sizeof buf);
        if (memcmp(buf, ref, sizeof buf) != 0)
            inplace_ok = 0;
        report("mul_region in place (dst == src)", inplace_ok);
    }

    if (failures == 0)
        printf("gf256: all tests passed\n");
    else
        printf("gf256: %d FAILED\n", failures);
    return failures == 0 ? 0 : 1;
}
