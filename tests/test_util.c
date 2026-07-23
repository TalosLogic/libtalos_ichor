/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_util.c - Tests for the security-critical utility primitives
 * ichor_const_memcmp and ichor_secure_zero.
 *
 * Neither consumer unit-tested these in isolation; they were only
 * exercised transitively.  These are direct correctness tests.  The
 * constant-time property itself is certified separately by the dudect
 * target; this file checks the functional contract.
 *
 * const_memcmp tests:
 *   1: equal buffers return 0 (empty, and several non-trivial lengths).
 *   2: length 0 returns 0 even when the pointers address differing bytes
 *      (no byte is read).
 *   3: a difference at the first, last, and a middle position each
 *      returns non-zero.
 *   4: the return value does not depend on WHERE the single differing
 *      byte sits: the same one-byte delta at the first, a middle, and the
 *      last position yields the same non-zero result.
 *   5: aliasing a buffer with itself returns 0.
 *
 * secure_zero tests:
 *   6: a filled buffer reads back all-zero afterward (the read goes
 *      through a volatile pointer so the store cannot be elided).
 *   7: len 0 and a NULL pointer are safe no-ops.
 *   8: zeroing a sub-range leaves the surrounding bytes untouched.
 */

#include "util.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int test_count = 0;
static int pass_count = 0;

static void
check(const char *name, int cond)
{
    test_count++;
    if (cond)
        pass_count++;
    else
        printf("  FAIL: %s\n", name);
}

/*
 * Sum a buffer through a volatile pointer so the compiler cannot prove
 * the bytes are zero and elide a preceding ichor_secure_zero.
 */
static uint32_t
volatile_sum(const uint8_t *buf, size_t len)
{
    const volatile uint8_t *vp = buf;
    uint32_t acc = 0;
    for (size_t i = 0; i < len; i++)
        acc |= vp[i];
    return acc;
}

static void
test_const_memcmp_equal(void)
{
    uint8_t a[64];
    uint8_t b[64];

    for (int i = 0; i < 64; i++)
        a[i] = b[i] = (uint8_t)(0x5a ^ (i * 7));

    check("const_memcmp: equal, len 0", ichor_const_memcmp(a, b, 0) == 0);
    check("const_memcmp: equal, len 1", ichor_const_memcmp(a, b, 1) == 0);
    check("const_memcmp: equal, len 16", ichor_const_memcmp(a, b, 16) == 0);
    check("const_memcmp: equal, len 64", ichor_const_memcmp(a, b, 64) == 0);
}

static void
test_const_memcmp_len_zero_ignores_bytes(void)
{
    static const uint8_t a[1] = {0x00};
    static const uint8_t b[1] = {0xff};

    /* len 0 reads no byte, so a difference in the buffers is invisible. */
    check("const_memcmp: len 0 returns 0 despite differing bytes",
          ichor_const_memcmp(a, b, 1 - 1) == 0);
}

static void
test_const_memcmp_positions_differ(void)
{
    uint8_t a[32];
    uint8_t b[32];

    memset(a, 0xa5, sizeof(a));

    memcpy(b, a, sizeof(a));
    b[0] ^= 0x01;
    check("const_memcmp: difference at first byte is non-zero",
          ichor_const_memcmp(a, b, sizeof(a)) != 0);

    memcpy(b, a, sizeof(a));
    b[sizeof(a) / 2] ^= 0x01;
    check("const_memcmp: difference at a middle byte is non-zero",
          ichor_const_memcmp(a, b, sizeof(a)) != 0);

    memcpy(b, a, sizeof(a));
    b[sizeof(a) - 1] ^= 0x01;
    check("const_memcmp: difference at last byte is non-zero",
          ichor_const_memcmp(a, b, sizeof(a)) != 0);
}

static void
test_const_memcmp_result_position_independent(void)
{
    uint8_t a[32];
    uint8_t b[32];
    const uint8_t delta = 0x6c;
    int r_first, r_mid, r_last;

    memset(a, 0x3c, sizeof(a));

    memcpy(b, a, sizeof(a));
    b[0] ^= delta;
    r_first = ichor_const_memcmp(a, b, sizeof(a));

    memcpy(b, a, sizeof(a));
    b[sizeof(a) / 2] ^= delta;
    r_mid = ichor_const_memcmp(a, b, sizeof(a));

    memcpy(b, a, sizeof(a));
    b[sizeof(a) - 1] ^= delta;
    r_last = ichor_const_memcmp(a, b, sizeof(a));

    check("const_memcmp: single-byte-delta result is non-zero", r_first != 0);
    check("const_memcmp: result independent of differing position",
          r_first == r_mid && r_mid == r_last);
}

static void
test_const_memcmp_self_alias(void)
{
    uint8_t a[48];

    for (int i = 0; i < 48; i++)
        a[i] = (uint8_t)(i * 3 + 1);

    check("const_memcmp: buffer compared with itself returns 0",
          ichor_const_memcmp(a, a, sizeof(a)) == 0);
}

static void
test_secure_zero_clears(void)
{
    uint8_t buf[128];

    memset(buf, 0xff, sizeof(buf));
    ichor_secure_zero(buf, sizeof(buf));

    check("secure_zero: buffer reads back all-zero",
          volatile_sum(buf, sizeof(buf)) == 0);
}

static void
test_secure_zero_noop_cases(void)
{
    uint8_t buf[16];

    memset(buf, 0xab, sizeof(buf));

    /* len 0: must not touch the buffer. */
    ichor_secure_zero(buf, 0);
    check("secure_zero: len 0 leaves the buffer unchanged",
          volatile_sum(buf, sizeof(buf)) == 0xab);

    /* NULL pointer: must not crash. */
    ichor_secure_zero(NULL, 0);
    ichor_secure_zero(NULL, 32);
    check("secure_zero: NULL pointer is a safe no-op", 1);
}

static void
test_secure_zero_subrange(void)
{
    uint8_t buf[16];

    memset(buf, 0x77, sizeof(buf));
    ichor_secure_zero(buf + 4, 8);

    check("secure_zero: leading bytes untouched", volatile_sum(buf, 4) == 0x77);
    check("secure_zero: middle range cleared", volatile_sum(buf + 4, 8) == 0);
    check("secure_zero: trailing bytes untouched",
          volatile_sum(buf + 12, 4) == 0x77);
}

int
main(void)
{
    printf("test_util: const_memcmp and secure_zero\n");

    test_const_memcmp_equal();
    test_const_memcmp_len_zero_ignores_bytes();
    test_const_memcmp_positions_differ();
    test_const_memcmp_result_position_independent();
    test_const_memcmp_self_alias();
    test_secure_zero_clears();
    test_secure_zero_noop_cases();
    test_secure_zero_subrange();

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
