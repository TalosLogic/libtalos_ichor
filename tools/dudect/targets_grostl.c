/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Constant-time validation of the ichor Grøstl primitive.  Grøstl is
 * constant-time by construction (bitsliced AES S-box for SubBytes, fixed
 * straight-line MixBytes, data-independent ShiftBytes / round constants /
 * padding), but it processes secret input in the designated-opener PKE (it
 * compresses the secret error vector `e` into the shared secret), so it
 * earns an empirical target rather than only the by-construction argument.
 *
 *   grostl256_input -- must PASS (|t| <= 4.5): running time must not depend
 *   grostl512_input    on the message bytes.
 *
 * Class A: a fixed all-zero message.
 * Class B: a uniformly random message of the same length.
 *
 * The message length is fixed across both classes, so the only thing that
 * varies is the message content.  The dudect core copy is built with the
 * hardware defines unset (see tools/dudect/CMakeLists.txt), so dispatch
 * selects the bitsliced software SubBytes path this target validates.
 */
#include "dudect_target.h"

#include "grostl.h"

#include <stdint.h>
#include <string.h>

/* Fixed message length across both classes.  256 bytes spans several full
 * blocks plus a partial tail for either variant, exercising the absorb
 * buffering and the final padded compression.
 */
#define GROSTL_MSG_BYTES 256

typedef struct {
    uint8_t msg[GROSTL_MSG_BYTES];
} grostl_state_t;

/* Digest scratch (outside the const input state) and a volatile sink so
 * the compiler cannot eliminate the hash. */
static uint8_t grostl_out[64];
static volatile uint8_t grostl_sink;

/* Small self-contained PRNG; the harness is single-threaded. */
static uint64_t grostl_rng_state = 0xd1b54a32d192ed03ULL;

static uint64_t
grostl_rng_next(void)
{
    uint64_t x = grostl_rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    grostl_rng_state = x;
    return x;
}

static void
grostl_setup(int cls, void *state)
{
    grostl_state_t *s = (grostl_state_t *)state;

    if (cls == 0) {
        memset(s->msg, 0, GROSTL_MSG_BYTES);
    } else {
        for (int i = 0; i < GROSTL_MSG_BYTES; i++)
            s->msg[i] = (uint8_t)grostl_rng_next();
    }
}

static void
grostl256_run(const void *state)
{
    const grostl_state_t *s = (const grostl_state_t *)state;
    ichor_grostl256(grostl_out, s->msg, GROSTL_MSG_BYTES);
    grostl_sink ^= grostl_out[0];
}

static void
grostl512_run(const void *state)
{
    const grostl_state_t *s = (const grostl_state_t *)state;
    ichor_grostl512(grostl_out, s->msg, GROSTL_MSG_BYTES);
    grostl_sink ^= grostl_out[0];
}

const dudect_target_t target_grostl256_input = {
    .name = "grostl256_input",
    .setup_class = grostl_setup,
    .run = grostl256_run,
    .state_size = sizeof(grostl_state_t),
    .reps_per_trial = 16,
};

const dudect_target_t target_grostl512_input = {
    .name = "grostl512_input",
    .setup_class = grostl_setup,
    .run = grostl512_run,
    .state_size = sizeof(grostl_state_t),
    .reps_per_trial = 16,
};
