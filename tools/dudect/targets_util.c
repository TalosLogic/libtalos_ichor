/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Constant-time validation of ichor_const_memcmp, the byte comparator
 * used wherever inputs may be secret (commitment hashes, challenges,
 * MACs).  Both consumers depend on it and neither previously dudected
 * it.
 *
 *   const_memcmp -- must produce a PASS verdict (|t| <= 4.5): the
 *                   running time must not depend on WHETHER the buffers
 *                   are equal, nor on WHERE they first differ.
 *
 * Class A: the two buffers are equal.
 * Class B: the two buffers differ in exactly one byte at a uniformly
 *          random position (nonzero delta).
 *
 * The comparison length is fixed across both classes, so the only thing
 * that varies is the presence and position of a difference.  A correct
 * constant-time comparator reads all bytes regardless and must not leak
 * either fact through timing.
 */
#include "dudect_target.h"

#include "util.h"

#include <stdint.h>
#include <string.h>

/* Fixed comparison length: 32 bytes covers the largest secret this
 * comparator guards (256-bit hashes / challenges) and is constant
 * across both classes so length is never the distinguishing variable.
 */
#define UTIL_CMP_BYTES 32

typedef struct {
    uint8_t a[UTIL_CMP_BYTES];
    uint8_t b[UTIL_CMP_BYTES];
} util_cmp_state_t;

/* Volatile sink so the compiler cannot eliminate the comparison. */
static volatile int util_cmp_sink;

/* Small self-contained PRNG so the target needs no external seed source
 * and stays reproducible within a run.  The harness is single-threaded.
 */
static uint64_t util_rng_state = 0x9e3779b97f4a7c15ULL;

static uint64_t
util_rng_next(void)
{
    uint64_t x = util_rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    util_rng_state = x;
    return x;
}

static void
const_memcmp_setup(int cls, void *state)
{
    util_cmp_state_t *s = (util_cmp_state_t *)state;

    for (int i = 0; i < UTIL_CMP_BYTES; i++)
        s->a[i] = (uint8_t)util_rng_next();
    memcpy(s->b, s->a, UTIL_CMP_BYTES);

    if (cls != 0) {
        /* Flip one byte at a uniformly random position with a nonzero
         * delta, so the buffers differ in exactly one place.
         */
        int pos = (int)(util_rng_next() % UTIL_CMP_BYTES);
        uint8_t delta = (uint8_t)(util_rng_next() | 1u);
        s->b[pos] = (uint8_t)(s->b[pos] ^ delta);
    }
}

static void
const_memcmp_run(const void *state)
{
    const util_cmp_state_t *s = (const util_cmp_state_t *)state;
    util_cmp_sink ^= ichor_const_memcmp(s->a, s->b, UTIL_CMP_BYTES);
}

const dudect_target_t target_const_memcmp = {
    .name = "const_memcmp",
    .setup_class = const_memcmp_setup,
    .run = const_memcmp_run,
    .state_size = sizeof(util_cmp_state_t),
    .reps_per_trial = 2000,
};
