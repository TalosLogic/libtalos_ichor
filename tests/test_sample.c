/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_sample.c - Tests for the constant-time fixed-weight index sampler
 * (ichor/sample.h).
 *
 * The sampler draws the secret support of a fixed-weight error, so a bias,
 * off-by-one, or ordering bug would silently weaken the KEM / opener it feeds.
 * No external vector exists, so the anchors are:
 *   1: draw-width / tape-length accounting (per lambda).
 *   2: all-zero tape KAT: every Lemire draw reduces to 0, so no slot moves and
 *      the draw-order output is the identity [0, 1, ..., w-1] (hand-verified).
 *   3: equivalence to a straightforward full-array Fisher-Yates over the same
 *      tape and reduction: byte-identical in DRAW ORDER (the overlay must select
 *      the identical set in the identical order); the output is then required
 *      distinct and in range.
 *   4: ichor_sample_sort_ascending yields a strictly ascending permutation of
 *      the drawn set.
 *   5: argument validation (NULL, w == 0, w > n, w > MAXW, bad tape_len/lambda).
 *
 * Test 3 is the load-bearing correctness pin, mirroring libtalos_syndrome's
 * shuffle-equivalence vectors (which also compare in draw order); the CT
 * property itself is validated separately by the dudect target
 * (tools/dudect/targets_sample.c).
 */
#include "sample.h"
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

/* Deterministic xorshift64 stream for synthetic tapes. */
static uint64_t
xs64(uint64_t *s)
{
    uint64_t x = *s;

    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    return x;
}

static void
fill_tape(uint8_t *tape, size_t len, uint64_t seed)
{
    uint64_t s = seed ? seed : 1;
    size_t i;

    for (i = 0; i < len; i++)
        tape[i] = (uint8_t)xs64(&s);
}

/* Same widened Lemire reduction the sampler uses, for the reference shuffle. */
static uint32_t
ref_reduce(const uint8_t *buf, unsigned limbs, uint32_t range)
{
    uint64_t carry = 0;
    unsigned i;

    for (i = 0; i < limbs; i++) {
        uint32_t limb = (uint32_t)buf[4 * i] | ((uint32_t)buf[4 * i + 1] << 8) |
                        ((uint32_t)buf[4 * i + 2] << 16) |
                        ((uint32_t)buf[4 * i + 3] << 24);
        carry = (uint64_t)limb * range + (carry >> 32);
    }
    return (uint32_t)(carry >> 32);
}

/*
 * Straightforward full-array partial Fisher-Yates over the same tape.  Produces
 * the drawn set in DRAW ORDER (out[i] is the value swapped into slot i), which
 * the sampler must reproduce byte-identically.  n bounded small so the O(n)
 * array is cheap.
 */
static void
ref_fisher_yates(uint32_t *out, uint32_t w, uint32_t n, int lambda,
                 const uint8_t *tape)
{
    uint32_t arr[4096];
    unsigned limbs = (unsigned)(ichor_sample_draw_bytes(lambda) / 4u);
    size_t db = ichor_sample_draw_bytes(lambda);
    uint32_t i;

    for (i = 0; i < n; i++)
        arr[i] = i;
    for (i = 0; i < w; i++) {
        uint32_t range = n - i;
        uint32_t j = i + ref_reduce(tape + (size_t)i * db, limbs, range);
        uint32_t tmp = arr[i];

        arr[i] = arr[j];
        arr[j] = tmp;
        out[i] = arr[i];
    }
}

static void
sort_u32(uint32_t *a, uint32_t n)
{
    uint32_t i, j;

    for (i = 1; i < n; i++) {
        uint32_t v = a[i];

        for (j = i; j > 0 && a[j - 1] > v; j--)
            a[j] = a[j - 1];
        a[j] = v;
    }
}

static void
test_tape_accounting(void)
{
    check("draw_bytes 128 == 24", ichor_sample_draw_bytes(128) == 24);
    check("draw_bytes 192 == 32", ichor_sample_draw_bytes(192) == 32);
    check("draw_bytes 256 == 40", ichor_sample_draw_bytes(256) == 40);
    check("draw_bytes bad lambda == 0", ichor_sample_draw_bytes(64) == 0);

    check("tape_bytes 128 w=130 == 3120",
          ichor_sample_fixed_weight_tape_bytes(128, 130) == 3120);
    check("tape_bytes 256 w=261 == 10440",
          ichor_sample_fixed_weight_tape_bytes(256, 261) == 10440);
    check("tape_bytes w=0 == 0",
          ichor_sample_fixed_weight_tape_bytes(128, 0) == 0);
    check("tape_bytes w>MAXW == 0", ichor_sample_fixed_weight_tape_bytes(
                                        128, ICHOR_SAMPLE_MAXW + 1) == 0);
}

static void
test_zero_tape_identity(void)
{
    uint8_t tape[64 * 40];
    uint32_t idx[64];
    int rc;
    uint32_t i;
    int ok = 1;

    /* All-zero tape: every reduce() == 0, so j == i at each step and no slot
     * moves; the drawn set is {0, ..., w-1}, ascending to the identity. */
    memset(tape, 0, sizeof(tape));
    rc = ichor_sample_fixed_weight(
        idx, 64, 200, 256, tape, ichor_sample_fixed_weight_tape_bytes(256, 64));
    check("zero-tape rc == 0", rc == 0);
    for (i = 0; i < 64; i++)
        if (idx[i] != i)
            ok = 0;
    check("zero-tape output is identity", ok);
}

static void
test_equiv_and_properties(void)
{
    static const struct {
        uint32_t w, n;
        int lambda;
    } cases[] = {
        {1, 2, 128},    {7, 64, 128},    {13, 100, 192},
        {50, 300, 256}, {130, 800, 128}, {261, 2000, 256},
    };
    size_t c;
    int all_equiv = 1, all_distinct = 1, all_range = 1, all_rc = 1;

    for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        uint32_t w = cases[c].w, n = cases[c].n;
        int lambda = cases[c].lambda;
        uint8_t tape[512 * 40];
        uint32_t got[ICHOR_SAMPLE_MAXW], ref[ICHOR_SAMPLE_MAXW];
        size_t tlen = ichor_sample_fixed_weight_tape_bytes(lambda, w);
        uint32_t i;
        uint64_t seed;

        for (seed = 1; seed <= 40; seed++) {
            uint32_t cpy[ICHOR_SAMPLE_MAXW];

            fill_tape(tape, tlen, seed * 0x9e3779b97f4a7c15ULL);
            if (ichor_sample_fixed_weight(got, w, n, lambda, tape, tlen) != 0) {
                all_rc = 0;
                continue;
            }
            /* Byte-identical to the reference in draw order (no sort). */
            ref_fisher_yates(ref, w, n, lambda, tape);
            for (i = 0; i < w; i++)
                if (got[i] != ref[i])
                    all_equiv = 0;
            for (i = 0; i < w; i++)
                if (got[i] >= n)
                    all_range = 0;
            /* Distinctness: sort a copy and require strictly ascending. */
            for (i = 0; i < w; i++)
                cpy[i] = got[i];
            sort_u32(cpy, w);
            for (i = 1; i < w; i++)
                if (cpy[i] <= cpy[i - 1])
                    all_distinct = 0;
        }
    }
    check("overlay matches reference Fisher-Yates (draw order)", all_equiv);
    check("all indices in range", all_range);
    check("drawn indices distinct", all_distinct);
    check("all sample calls returned 0", all_rc);
}

static void
test_sort_ascending(void)
{
    static const struct {
        uint32_t w, n;
        int lambda;
    } cases[] = {
        {7, 64, 128},
        {50, 300, 256},
        {261, 2000, 256},
    };
    uint32_t one[1] = {5};
    size_t c;
    int all_asc = 1, all_perm = 1, all_rc = 1;

    for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        uint32_t w = cases[c].w, n = cases[c].n;
        int lambda = cases[c].lambda;
        uint8_t tape[512 * 40];
        uint32_t got[ICHOR_SAMPLE_MAXW], exp[ICHOR_SAMPLE_MAXW];
        size_t tlen = ichor_sample_fixed_weight_tape_bytes(lambda, w);
        uint32_t i;
        uint64_t seed;

        for (seed = 1; seed <= 20; seed++) {
            fill_tape(tape, tlen, seed * 0x2545f4914f6cdd1dULL);
            if (ichor_sample_fixed_weight(got, w, n, lambda, tape, tlen) != 0) {
                all_rc = 0;
                continue;
            }
            /* Independent expected order: sort a copy of the draw. */
            for (i = 0; i < w; i++)
                exp[i] = got[i];
            sort_u32(exp, w);
            if (ichor_sample_sort_ascending(got, w) != 0) {
                all_rc = 0;
                continue;
            }
            for (i = 0; i < w; i++)
                if (got[i] != exp[i])
                    all_perm = 0; /* same set, now ascending */
            for (i = 1; i < w; i++)
                if (got[i] <= got[i - 1])
                    all_asc = 0;
        }
    }
    check("sort_ascending yields strictly ascending", all_asc);
    check("sort_ascending is a permutation (same set)", all_perm);
    check("sort_ascending returned 0", all_rc);

    check("sort_ascending NULL rejected",
          ichor_sample_sort_ascending(NULL, 1) == -1);
    check("sort_ascending w==0 rejected",
          ichor_sample_sort_ascending(one, 0) == -1);
    check("sort_ascending w>MAXW rejected",
          ichor_sample_sort_ascending(one, ICHOR_SAMPLE_MAXW + 1) == -1);
}

static void
test_validation(void)
{
    uint8_t tape[16 * 40];
    uint32_t idx[16];
    size_t good = ichor_sample_fixed_weight_tape_bytes(128, 16);

    fill_tape(tape, sizeof(tape), 123);

    check("NULL idx rejected",
          ichor_sample_fixed_weight(NULL, 16, 64, 128, tape, good) == -1);
    check("NULL tape rejected",
          ichor_sample_fixed_weight(idx, 16, 64, 128, NULL, good) == -1);
    check("w == 0 rejected",
          ichor_sample_fixed_weight(idx, 0, 64, 128, tape, 0) == -1);
    check("w > n rejected",
          ichor_sample_fixed_weight(idx, 16, 8, 128, tape, good) == -1);
    check("w > MAXW rejected",
          ichor_sample_fixed_weight(idx, ICHOR_SAMPLE_MAXW + 1, 100000, 128,
                                    tape, good) == -1);
    check("bad lambda rejected",
          ichor_sample_fixed_weight(idx, 16, 64, 64, tape, good) == -1);
    check("short tape_len rejected",
          ichor_sample_fixed_weight(idx, 16, 64, 128, tape, good - 1) == -1);
    check("long tape_len rejected",
          ichor_sample_fixed_weight(idx, 16, 64, 128, tape, good + 1) == -1);
}

int
main(void)
{
    printf("test_sample: constant-time fixed-weight index sampling\n");

    test_tape_accounting();
    test_zero_tape_identity();
    test_equiv_and_properties();
    test_sort_ascending();
    test_validation();

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
