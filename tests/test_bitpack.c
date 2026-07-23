/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_bitpack.c - Tests for the LSB-first bit packing (ichor_bitpack /
 * ichor_bitunpack, _le16 and _le32).
 *
 * These serialize secret data (e.g. the support of a fixed-weight error
 * vector), so a wrong-endianness, off-by-one, or padding bug would break
 * interop silently.  No canonical external vector exists, so the anchors
 * are a hand-computed fixed vector plus exhaustive round-trip and the
 * documented boundary behaviors.
 *
 * Tests:
 *   1: fixed known-answer at a non-byte-aligned width (three 3-bit values).
 *   2: round-trip across widths (including 3, 12, 17) and counts, both
 *      element types, with the values masked to width_bits on comparison.
 *   3: high bits beyond width_bits are ignored on pack (documented).
 *   4: tail past the packed bits is deterministic zero padding.
 *   5: argument validation (width 0 / over-wide / short buffer).
 *   6: L5 overflow guard: a count whose bit total would overflow size_t is
 *      rejected rather than wrapping into an out-of-bounds access.
 */

#include "util.h"

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
 * Test 1: three 3-bit values {5, 2, 7} pack LSB-first into 9 bits.
 *   v0=5 -> bits 0..2, v1=2 -> bits 3..5, v2=7 -> bits 6..8.
 * Byte 0 = 0b11010101 = 0xD5, byte 1 bit 0 = 1 -> 0x01.
 */
static void
test_fixed_vector(void)
{
    const uint16_t values[3] = {5, 2, 7};
    const uint8_t expect[2] = {0xD5, 0x01};
    uint8_t dst[2] = {0xFF, 0xFF};
    uint16_t back[3];
    int rc;

    rc = ichor_bitpack_le16(dst, sizeof(dst), values, 3, 3);
    check("fixed vector: pack rc", rc == 0);
    check("fixed vector: packed bytes match", memcmp(dst, expect, 2) == 0);

    rc = ichor_bitunpack_le16(back, 3, 3, dst, sizeof(dst));
    check("fixed vector: unpack rc", rc == 0);
    check("fixed vector: round-trip values",
          back[0] == 5 && back[1] == 2 && back[2] == 7);
}

/* A simple deterministic value generator seeded by index. */
static uint32_t
gen32(size_t i)
{
    return (uint32_t)(0x9E3779B9u * (uint32_t)(i + 1));
}

static void
test_roundtrip(void)
{
    static const uint32_t widths[] = {1, 2, 3, 7, 8, 12, 16, 17, 24, 31, 32};
    static const size_t counts[] = {1, 2, 7, 8, 9, 33, 64};
    size_t wi, ci;
    int all_ok = 1;

    for (wi = 0; wi < sizeof(widths) / sizeof(widths[0]); wi++) {
        uint32_t w = widths[wi];
        uint32_t mask = (w == 32) ? 0xFFFFFFFFu : ((1u << w) - 1u);

        for (ci = 0; ci < sizeof(counts) / sizeof(counts[0]); ci++) {
            size_t n = counts[ci];
            uint8_t buf[512];
            uint32_t in32[64], out32[64];
            size_t need = (n * w + 7) / 8;
            size_t i;

            for (i = 0; i < n; i++)
                in32[i] = gen32(i + w);

            /* _le32 path */
            if (ichor_bitpack_le32(buf, sizeof(buf), in32, n, w) != 0 ||
                ichor_bitunpack_le32(out32, n, w, buf, need) != 0)
                all_ok = 0;
            for (i = 0; i < n; i++)
                if (out32[i] != (in32[i] & mask))
                    all_ok = 0;

            /* _le16 path for the widths it supports */
            if (w <= 16) {
                uint16_t in16[64], out16[64];
                uint16_t m16 = (uint16_t)mask;
                for (i = 0; i < n; i++)
                    in16[i] = (uint16_t)gen32(i + w);
                if (ichor_bitpack_le16(buf, sizeof(buf), in16, n, w) != 0 ||
                    ichor_bitunpack_le16(out16, n, w, buf, need) != 0)
                    all_ok = 0;
                for (i = 0; i < n; i++)
                    if (out16[i] != (uint16_t)(in16[i] & m16))
                        all_ok = 0;
            }
        }
    }
    check("round-trip across widths/counts (both element types)", all_ok);
}

static void
test_high_bits_ignored(void)
{
    const uint32_t values[2] = {0xFFFFFFFFu, 0xFFFFFFFFu};
    uint8_t dst[2] = {0};
    uint32_t back[2];
    int rc;

    /* width 5: only low 5 bits (0x1F) of each should survive. */
    rc = ichor_bitpack_le32(dst, sizeof(dst), values, 2, 5);
    rc |= ichor_bitunpack_le32(back, 2, 5, dst, sizeof(dst));
    check("high bits beyond width are ignored",
          rc == 0 && back[0] == 0x1Fu && back[1] == 0x1Fu);
}

static void
test_tail_padding(void)
{
    const uint16_t values[3] = {5, 2, 7}; /* 9 bits -> need 2 bytes */
    uint8_t dst[8];
    int rc, tail_zero = 1, i;

    memset(dst, 0xAA, sizeof(dst));
    rc = ichor_bitpack_le16(dst, sizeof(dst), values, 3, 3);
    for (i = 2; i < 8; i++)
        if (dst[i] != 0x00)
            tail_zero = 0;
    check("tail past packed bits is zeroed", rc == 0 && tail_zero);
}

static void
test_validation(void)
{
    uint16_t v16[4] = {1, 2, 3, 4};
    uint32_t v32[4] = {1, 2, 3, 4};
    uint16_t o16[4];
    uint32_t o32[4];
    uint8_t buf[16];

    check("pack le16 rejects width 0",
          ichor_bitpack_le16(buf, sizeof(buf), v16, 4, 0) == -1);
    check("pack le16 rejects width > 16",
          ichor_bitpack_le16(buf, sizeof(buf), v16, 4, 17) == -1);
    check("pack le32 rejects width > 32",
          ichor_bitpack_le32(buf, sizeof(buf), v32, 4, 33) == -1);
    /* 4 values * 16 bits = 64 bits = 8 bytes; give 7. */
    check("pack le16 rejects short dst",
          ichor_bitpack_le16(buf, 7, v16, 4, 16) == -1);
    check("unpack le16 rejects short src",
          ichor_bitunpack_le16(o16, 4, 16, buf, 7) == -1);
    check("unpack le32 rejects width 0",
          ichor_bitunpack_le32(o32, 4, 0, buf, sizeof(buf)) == -1);
}

/*
 * Test 6: L5.  A count large enough that count * width_bits overflows
 * size_t must be rejected before the buffer is touched.  The guard runs
 * before values is dereferenced, so a tiny values buffer is safe here.
 */
static void
test_overflow_guard(void)
{
    uint8_t dst[8];
    uint32_t one = 1;
    uint16_t one16 = 1;
    uint32_t o32[1];
    uint16_t o16[1];

    memset(dst, 0x5A, sizeof(dst));
    check("pack le32 rejects size_t-overflowing count",
          ichor_bitpack_le32(dst, sizeof(dst), &one, SIZE_MAX, 32) == -1);
    check("pack le16 rejects size_t-overflowing count",
          ichor_bitpack_le16(dst, sizeof(dst), &one16, SIZE_MAX, 16) == -1);
    check("unpack le32 rejects size_t-overflowing count",
          ichor_bitunpack_le32(o32, SIZE_MAX, 32, dst, sizeof(dst)) == -1);
    check("unpack le16 rejects size_t-overflowing count",
          ichor_bitunpack_le16(o16, SIZE_MAX, 16, dst, sizeof(dst)) == -1);
    {
        int untouched = 1, i;
        for (i = 0; i < 8; i++)
            if (dst[i] != 0x5A)
                untouched = 0;
        check("overflow-rejected pack leaves dst unwritten", untouched);
    }
}

int
main(void)
{
    printf("test_bitpack: LSB-first bit packing (le16/le32)\n");

    test_fixed_vector();
    test_roundtrip();
    test_high_bits_ignored();
    test_tail_padding();
    test_validation();
    test_overflow_guard();

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
