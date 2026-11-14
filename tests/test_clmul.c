/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_clmul.c - Known-answer and algebraic tests for the carry-less
 * multiply primitive.
 *
 * The same assertions run under two CTest profiles: the default hardware
 * profile (PCLMULQDQ/PMULL where present) and a _sw profile that forces
 * ICHOR_FORCE_BACKEND=clmul:scalar, so the constant-time scalar fallback
 * is validated on every host.
 */
#include <stdint.h>
#include <stdio.h>

#include "clmul.h"

static int failures;

static void
report(const char *name, int ok)
{
    printf("  %-40s %s\n", name, ok ? "ok" : "FAIL");
    if (!ok)
        failures++;
}

/*
 * Carry-less products computed by hand.  In F_2[x], multiplying by 1 is
 * identity, squaring spreads each set bit to twice its index (cross terms
 * cancel in pairs), and shifts above bit 63 land in the high word.
 */
static const struct {
    uint64_t a, b, lo, hi;
} kat[] = {
    {0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull,
     0x0000000000000000ull},
    {0x0000000000000001ull, 0xdeadbeef12345678ull, 0xdeadbeef12345678ull,
     0x0000000000000000ull},
    {0x0000000000000002ull, 0x0000000000000002ull, 0x0000000000000004ull,
     0x0000000000000000ull},
    {0x0000000000000003ull, 0x0000000000000003ull, 0x0000000000000005ull,
     0x0000000000000000ull},
    {0x8000000000000000ull, 0x0000000000000002ull, 0x0000000000000000ull,
     0x0000000000000001ull},
    {0x8000000000000000ull, 0x8000000000000000ull, 0x0000000000000000ull,
     0x4000000000000000ull},
    {0xffffffffffffffffull, 0x0000000000000001ull, 0xffffffffffffffffull,
     0x0000000000000000ull},
    {0x0000000100000001ull, 0x0000000100000001ull, 0x0000000000000001ull,
     0x0000000000000001ull},
    /* (sum of all 64 bits)^2 -> every even-indexed bit set across 127. */
    {0xffffffffffffffffull, 0xffffffffffffffffull, 0x5555555555555555ull,
     0x5555555555555555ull},
};

int
main(void)
{
    size_t i;
    int kat_ok = 1, comm_ok = 1, resolve_ok = 1;
    int x2_ok = 1, x2_resolve_ok = 1;
    ichor_clmul64_fn fn;
    ichor_clmul64_x2_fn fn_x2;
    uint64_t rng = 0x123456789abcdef0ull;

    printf("clmul tests (backend: %s):\n", ichor_clmul_backend_name());

    /* Known-answer vectors. */
    for (i = 0; i < sizeof kat / sizeof kat[0]; i++) {
        uint64_t lo, hi;
        ichor_clmul64(kat[i].a, kat[i].b, &lo, &hi);
        if (lo != kat[i].lo || hi != kat[i].hi)
            kat_ok = 0;
    }
    report("known-answer vectors", kat_ok);

    /* Carry-less multiply is commutative. */
    for (i = 0; i < sizeof kat / sizeof kat[0]; i++) {
        uint64_t lo1, hi1, lo2, hi2;
        ichor_clmul64(kat[i].a, kat[i].b, &lo1, &hi1);
        ichor_clmul64(kat[i].b, kat[i].a, &lo2, &hi2);
        if (lo1 != lo2 || hi1 != hi2)
            comm_ok = 0;
    }
    report("commutativity a*b == b*a", comm_ok);

    /* The resolved function pointer agrees with the forwarder. */
    fn = ichor_clmul64_resolve();
    for (i = 0; i < sizeof kat / sizeof kat[0]; i++) {
        uint64_t lo1, hi1, lo2, hi2;
        ichor_clmul64(kat[i].a, kat[i].b, &lo1, &hi1);
        fn(kat[i].a, kat[i].b, &lo2, &hi2);
        if (lo1 != lo2 || hi1 != hi2)
            resolve_ok = 0;
    }
    report("resolve() matches forwarder", resolve_ok);

    /*
     * The 2-wide multiply computes two independent products that must each
     * equal the single mul, on every backend.  Check the KAT vectors paired
     * up, then a sweep of pseudo-random operand pairs.
     */
    for (i = 0; i + 1 < sizeof kat / sizeof kat[0]; i += 2) {
        uint64_t lo2[2], hi2[2], l0, h0, l1, h1;
        ichor_clmul64_x2(kat[i].a, kat[i].b, kat[i + 1].a, kat[i + 1].b, lo2,
                         hi2);
        ichor_clmul64(kat[i].a, kat[i].b, &l0, &h0);
        ichor_clmul64(kat[i + 1].a, kat[i + 1].b, &l1, &h1);
        if (lo2[0] != l0 || hi2[0] != h0 || lo2[1] != l1 || hi2[1] != h1)
            x2_ok = 0;
    }
    for (i = 0; i < 4096; i++) {
        uint64_t a0, b0, a1, b1, lo2[2], hi2[2], l0, h0, l1, h1;
        rng = rng * 6364136223846793005ull + 1442695040888963407ull;
        a0 = rng;
        rng = rng * 6364136223846793005ull + 1442695040888963407ull;
        b0 = rng;
        rng = rng * 6364136223846793005ull + 1442695040888963407ull;
        a1 = rng;
        rng = rng * 6364136223846793005ull + 1442695040888963407ull;
        b1 = rng;
        ichor_clmul64_x2(a0, b0, a1, b1, lo2, hi2);
        ichor_clmul64(a0, b0, &l0, &h0);
        ichor_clmul64(a1, b1, &l1, &h1);
        if (lo2[0] != l0 || hi2[0] != h0 || lo2[1] != l1 || hi2[1] != h1)
            x2_ok = 0;
    }
    report("x2 matches two single muls", x2_ok);

    /* The resolved x2 pointer agrees with the forwarder. */
    fn_x2 = ichor_clmul64_x2_resolve();
    for (i = 0; i < sizeof kat / sizeof kat[0]; i++) {
        uint64_t lo1[2], hi1[2], lo2[2], hi2[2];
        ichor_clmul64_x2(kat[i].a, kat[i].b, kat[i].b, kat[i].a, lo1, hi1);
        fn_x2(kat[i].a, kat[i].b, kat[i].b, kat[i].a, lo2, hi2);
        if (lo1[0] != lo2[0] || hi1[0] != hi2[0] || lo1[1] != lo2[1] ||
            hi1[1] != hi2[1])
            x2_resolve_ok = 0;
    }
    report("x2_resolve() matches forwarder", x2_resolve_ok);

    if (failures != 0) {
        fprintf(stderr, "clmul: %d failure(s)\n", failures);
        return 1;
    }
    printf("clmul: OK\n");
    return 0;
}
