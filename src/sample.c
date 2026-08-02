/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * sample.c - constant-time fixed-weight index sampling (ichor/sample.h).
 *
 * See the header for the contract.  ichor_sample_fixed_weight is the overlay
 * Fisher-Yates plus widened Lemire reduction: the constant-time, fixed-
 * consumption core, returning the drawn set in DRAW ORDER.  A caller that needs
 * a canonical ordering (e.g. a support hashed as an ordered list) applies
 * ichor_sample_sort_ascending, the constant-time bitonic network below;
 * consumers that only scatter the set into a dense vector need no ordering.
 * All control flow is a function of the public (lambda, w, n); the tape and the
 * values being sorted never steer a branch or an address.
 */
#include "sample.h"

#include <string.h>

#include "util.h"

size_t
ichor_sample_draw_bytes(int lambda)
{
    if (lambda != 128 && lambda != 192 && lambda != 256)
        return 0;
    return (size_t)((lambda + 64) / 8);
}

size_t
ichor_sample_fixed_weight_tape_bytes(int lambda, uint32_t w)
{
    size_t db = ichor_sample_draw_bytes(lambda);

    if (db == 0 || w == 0 || w > ICHOR_SAMPLE_MAXW)
        return 0;
    return db * (size_t)w;
}

/* 0xFFFFFFFF if a == b, 0 otherwise -- branch-free. */
static uint32_t
ct_eq32(uint32_t a, uint32_t b)
{
    uint32_t x = a ^ b;
    uint32_t nz = (x | (0u - x)) >> 31; /* 1 if x != 0, else 0 */

    return nz - 1u;
}

/* 0xFFFFFFFF if a < b, 0 otherwise -- branch-free (64-bit borrow probe). */
static uint32_t
ct_lt32(uint32_t a, uint32_t b)
{
    uint64_t d = (uint64_t)a - (uint64_t)b; /* bit 63 set iff a < b */

    return (uint32_t)0 - (uint32_t)(d >> 63);
}

static uint32_t
load32_le(const uint8_t b[4])
{
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}

/*
 * Uniform reduction of a (4*limbs)-byte little-endian value into [0, range)
 * without division: floor(draw * range / 2^(32*limbs)), the Lemire high word.
 * Accumulated across 32-bit limbs low-to-high, each multiplied by the public
 * range with the carry propagated upward, so no wide integer type is needed and
 * limb*range + carry never overflows 64 bits (range fits in 32 bits).
 * Constant-time: fixed limb count, no branch or secret-dependent index.
 */
static uint32_t
sample_reduce(const uint8_t *buf, unsigned limbs, uint32_t range)
{
    uint64_t carry = 0;
    unsigned i;

    for (i = 0; i < limbs; i++)
        carry = (uint64_t)load32_le(buf + 4u * i) * range + (carry >> 32);

    return (uint32_t)(carry >> 32);
}

/*
 * Constant-time bitonic sort of buf[0..len) into ascending order, len a power
 * of two.  Stage indices (k, j, i) are public; only the compared values are
 * secret, so the direction of each compare-exchange (public i & k) may branch,
 * while the exchange itself is a branch-free masked swap.
 */
static void
bitonic_sort_asc(uint32_t *buf, uint32_t len)
{
    uint32_t k, j, i;

    for (k = 2; k <= len; k <<= 1) {
        for (j = k >> 1; j > 0; j >>= 1) {
            for (i = 0; i < len; i++) {
                uint32_t l = i ^ j;

                if (l > i) {
                    uint32_t a = buf[i], b = buf[l];
                    /* ascending block wants a <= b (swap if a > b); descending
                     * block wants a >= b (swap if a < b).  Direction is public. */
                    uint32_t m = ((i & k) == 0) ? ct_lt32(b, a) : ct_lt32(a, b);

                    buf[i] = (a & ~m) | (b & m);
                    buf[l] = (b & ~m) | (a & m);
                }
            }
        }
    }
}

int
ichor_sample_fixed_weight(uint32_t *idx, uint32_t w, uint32_t n, int lambda,
                          const uint8_t *tape, size_t tape_len)
{
    /*
     * O(w) overlay of the Fisher-Yates permutation: entry k (written at the
     * PUBLIC step index k) records that tail slot ov_slot[k] now holds value
     * ov_val[k].  The length-n identity array is never materialized; a slot's
     * current value is resolved by scanning the overlay under a constant-time
     * equality mask, defaulting to the slot index itself.
     */
    uint32_t ov_slot[ICHOR_SAMPLE_MAXW];
    uint32_t ov_val[ICHOR_SAMPLE_MAXW];
    size_t db = ichor_sample_draw_bytes(lambda);
    unsigned limbs;
    uint32_t i, k;

    if (idx == NULL || tape == NULL || db == 0 || w == 0 ||
        w > ICHOR_SAMPLE_MAXW || w > n || tape_len != db * (size_t)w)
        return -1;

    limbs = (unsigned)(db / 4u);

    for (i = 0; i < w; i++) {
        const uint8_t *buf = tape + (size_t)i * db;
        uint32_t range = n - i;
        uint32_t j = i + sample_reduce(buf, limbs, range);
        uint32_t cur_i = i; /* pos[i], default identity */
        uint32_t cur_j = j; /* pos[j], default identity */

        /*
         * Resolve pos[i] and pos[j] from the overlay entries [0, i).  Forward
         * scan, so a later override of the same slot wins.  k is public; the
         * slot compares are branch-free, and neither value is used as an index.
         */
        for (k = 0; k < i; k++) {
            uint32_t mi = ct_eq32(ov_slot[k], i);
            uint32_t mj = ct_eq32(ov_slot[k], j);

            cur_i = (cur_i & ~mi) | (ov_val[k] & mi);
            cur_j = (cur_j & ~mj) | (ov_val[k] & mj);
        }

        /*
         * Swap pos[i] <-> pos[j].  Slot i is now frozen (its new value cur_j is
         * the output) and never read again, so only the displaced tail slot j
         * needs recording: it now holds cur_i.  j == i is a self-swap whose
         * override targets slot i itself and is harmless (never read again).
         */
        idx[i] = cur_j;
        ov_slot[i] = j;
        ov_val[i] = cur_i;
    }

    /*
     * idx now holds the drawn set in draw order (the Fisher-Yates output).  A
     * caller that needs a canonical order applies ichor_sample_sort_ascending;
     * consumers that only scatter the set into a dense vector need no ordering.
     */
    ichor_secure_zero(ov_slot, sizeof ov_slot);
    ichor_secure_zero(ov_val, sizeof ov_val);
    return 0;
}

int
ichor_sample_sort_ascending(uint32_t *idx, uint32_t w)
{
    uint32_t buf[ICHOR_SAMPLE_MAXW];
    uint32_t plen, i;

    if (idx == NULL || w == 0 || w > ICHOR_SAMPLE_MAXW)
        return -1;

    /*
     * Pad to the next power of two with the UINT32_MAX sentinel (> every valid
     * index, since n <= UINT32_MAX), sort, and keep the low w.  The sentinels
     * sort above the real indices, so the first w slots are the input set in
     * ascending order.  Constant-time over the values: the network shape is a
     * function of the public w alone.
     */
    plen = 1;
    while (plen < w)
        plen <<= 1;
    for (i = 0; i < w; i++)
        buf[i] = idx[i];
    for (i = w; i < plen; i++)
        buf[i] = UINT32_MAX;
    bitonic_sort_asc(buf, plen);
    for (i = 0; i < w; i++)
        idx[i] = buf[i];

    ichor_secure_zero(buf, sizeof buf);
    return 0;
}
