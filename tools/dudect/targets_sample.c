/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Constant-time target for the fixed-weight index sampler (ichor/sample.h).
 *
 *   _tape  -- the random tape varies (a fixed constant tape in class 0, a fresh
 *             random tape in class 1).  The tape drives the secret support draw,
 *             so if any part of the overlay Fisher-Yates, the Lemire reduction,
 *             or the bitonic sort branched on a drawn value, the two classes
 *             would diverge in timing.  Consumption is fixed by construction
 *             (no rejection loop), so this target guards the value-dependent
 *             control flow specifically.
 *
 * A representative shape is used (lambda 256, w = 261, n = 86902: the
 * lambda-256 n0=2 weight-t error), the largest weight any set requests; the
 * control flow is identical across shapes, so one suffices.
 */
#include "dudect_target.h"

#include "sample.h"

#include <stdint.h>
#include <string.h>

#define SAMPLE_DUDECT_LAMBDA 256
#define SAMPLE_DUDECT_W 261u
#define SAMPLE_DUDECT_N 86902u
#define SAMPLE_DUDECT_TAPE (SAMPLE_DUDECT_W * 40u) /* w * draw_bytes(256) */

static volatile uint32_t sample_target_sink;

typedef struct {
    uint8_t tape[SAMPLE_DUDECT_TAPE];
} sample_state_t;

/* Local xorshift so class-1 tapes vary trial to trial without libc rand(). */
static uint64_t
sample_xs64(uint64_t *s)
{
    uint64_t x = *s;

    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    return x;
}

static void
sample_tape_setup(int cls, void *state)
{
    sample_state_t *st = (sample_state_t *)state;
    static uint64_t stream = 0x243f6a8885a308d3ULL;
    size_t i;

    if (cls == 0) {
        /* Fixed reference tape: a constant byte pattern. */
        memset(st->tape, 0x5a, sizeof st->tape);
    } else {
        /* Fresh random tape each trial. */
        for (i = 0; i < sizeof st->tape; i++)
            st->tape[i] = (uint8_t)sample_xs64(&stream);
    }
}

static void
sample_tape_run(const void *state)
{
    const sample_state_t *st = (const sample_state_t *)state;
    uint32_t out[SAMPLE_DUDECT_W];

    (void)ichor_sample_fixed_weight(out, SAMPLE_DUDECT_W, SAMPLE_DUDECT_N,
                                    SAMPLE_DUDECT_LAMBDA, st->tape,
                                    sizeof st->tape);
    sample_target_sink ^= out[0] ^ out[SAMPLE_DUDECT_W - 1];
}

const dudect_target_t target_sample_tape = {
    .name = "sample_tape",
    .setup_class = sample_tape_setup,
    .run = sample_tape_run,
    .state_size = sizeof(sample_state_t),
    .reps_per_trial = 1,
};
