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

#include "cpu.h"
#include "sample_dispatch.h"
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

/*
 * 0xFFFFFFFF if a == b, else 0.  The equal bit is barriered through
 * ichor_ct_mask64 (an opaque volatile 0/~0), not an inline nz - 1, so the
 * masked selects this feeds (the overlay resolve and the bitonic swap below,
 * both over secret indices) cannot be lowered to a branch on the comparison.
 */
static uint32_t
ct_eq32(uint32_t a, uint32_t b)
{
    uint32_t x = a ^ b;
    uint32_t ne = (x | (0u - x)) >> 31; /* 1 if a != b, else 0 */

    return (uint32_t)ichor_ct_mask64((uint64_t)(ne ^ 1u));
}

/*
 * 0xFFFFFFFF if a < b, else 0 (64-bit borrow probe).  The less-than bit is
 * barriered through ichor_ct_mask64 for the same reason as ct_eq32: the
 * compare-exchange swap it drives must stay branch-free at the machine level.
 */
static uint32_t
ct_lt32(uint32_t a, uint32_t b)
{
    uint64_t d = (uint64_t)a - (uint64_t)b; /* bit 63 set iff a < b */
    uint32_t lt = (uint32_t)(d >> 63);      /* 1 iff a < b          */

    return (uint32_t)ichor_ct_mask64((uint64_t)lt);
}

static uint32_t
load32_le(const uint8_t b[4])
{
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}

/*
 * Constant-time 32x32 -> 64 multiply of a SECRET multiplicand `a` by a PUBLIC
 * multiplier `b`: the sum of (a << i) over the set bits i of b.  The secret `a`
 * reaches only fixed-latency shifts and adds, never a native integer multiply,
 * whose latency is data-operand-dependent on some Intel cores unless DOITM is
 * enabled (observed as a dudect leak in the fixed-weight sampler's Lemire
 * reduction).  `b` is PUBLIC here (the reduction passes range = n - i, a
 * function of public parameters only), so the per-bit mask is derived from
 * public data and needs no ichor_ct_mask64 barrier: the sole requirement is
 * independence from `a`, which holds because `a` never conditions control flow
 * or a variable-latency unit.  Bit-identical to a * b; the product fits in 64
 * bits since a, b < 2^32.
 */
static uint64_t
ct_mul32_pub(uint32_t a, uint32_t b)
{
    uint64_t acc = 0;
    uint64_t wide = (uint64_t)a;
    unsigned i;

    for (i = 0; i < 32u; i++) {
        uint64_t mask =
            (uint64_t)0 - (uint64_t)((b >> i) & 1u); /* public bit */

        acc += (wide << i) & mask;
    }
    return acc;
}

/*
 * Uniform reduction of a (4*limbs)-byte little-endian value into [0, range)
 * without division: floor(draw * range / 2^(32*limbs)), the Lemire high word.
 * Accumulated across 32-bit limbs low-to-high, each multiplied by the public
 * range with the carry propagated upward, so no wide integer type is needed and
 * limb*range + carry never overflows 64 bits (range fits in 32 bits).  The
 * per-limb product uses the constant-time ct_mul32_pub rather than a native
 * multiply, so the secret draw never flows through a data-operand-dependent
 * multiply (see ct_mul32_pub).  Constant-time: fixed limb count, no branch or
 * secret-dependent index.
 */
static uint32_t
sample_reduce(const uint8_t *buf, unsigned limbs, uint32_t range)
{
    uint64_t carry = 0;
    unsigned i;

    for (i = 0; i < limbs; i++)
        carry = ct_mul32_pub(load32_le(buf + 4u * i), range) + (carry >> 32);

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

void
ichor_sample_reduce_batch_scalar(uint32_t *red, const uint8_t *tape, uint32_t w,
                                 uint32_t n, unsigned limbs, size_t db)
{
    uint32_t i;

    for (i = 0; i < w; i++)
        red[i] = sample_reduce(tape + (size_t)i * db, limbs, n - i);
}

/*
 * Scalar reference for the overlay resolve (see sample_dispatch.h): forward scan
 * [0, i) with last-wins overwrite, so the sequential order is load-bearing.  k
 * is public; the slot compares are branch-free and neither value indexes memory.
 */
void
ichor_sample_overlay_resolve_scalar(uint32_t i, uint32_t j,
                                    const uint32_t *ov_slot,
                                    const uint32_t *ov_val, uint32_t *cur_i,
                                    uint32_t *cur_j)
{
    uint32_t ci = i;
    uint32_t cj = j;
    uint32_t k;

    for (k = 0; k < i; k++) {
        uint32_t mi = ct_eq32(ov_slot[k], i);
        uint32_t mj = ct_eq32(ov_slot[k], j);

        ci = (ci & ~mi) | (ov_val[k] & mi);
        cj = (cj & ~mj) | (ov_val[k] & mj);
    }

    *cur_i = ci;
    *cur_j = cj;
}

const ichor_sample_ops_t ichor_sample_ops_scalar = {
    .reduce_batch = ichor_sample_reduce_batch_scalar,
    .overlay_resolve = ichor_sample_overlay_resolve_scalar,
    .backend_tag = ICHOR_SAMPLE_BACKEND_SCALAR,
    .name = "scalar",
};

_Atomic(const ichor_sample_ops_t *) ichor_sample_ops = NULL;

/*
 * On first use, select the highest-priority compiled-in backend whose feature
 * bit is present: AVX2 (runtime ICHOR_CPU_AVX2), else SSE4.1 (runtime
 * ICHOR_CPU_SSE41; its overlay resolve needs the SSE4.1 32-bit max and it reuses
 * the SSE2 reduce kernel), else SSE2 (baseline on x86_64, no runtime bit), else
 * NEON (aarch64, runtime ICHOR_CPU_NEON), else scalar.  Mirrors the gf2x
 * dispatch; every backend is bit-identical, so the choice is data-independent
 * and the KATs hold.
 */
void
ichor_sample_dispatch_init(void)
{
    if (atomic_load_explicit(&ichor_sample_ops, memory_order_acquire) != NULL)
        return;

    const ichor_sample_ops_t *pick = NULL;

#if defined(ICHOR_HAVE_SAMPLE_AVX2) || defined(ICHOR_HAVE_SAMPLE_SSE41) ||     \
    defined(ICHOR_HAVE_SAMPLE_NEON)
    uint32_t feat = ichor_cpu_features();
#endif
#if defined(ICHOR_HAVE_SAMPLE_AVX2)
    if (pick == NULL && (feat & ICHOR_CPU_AVX2))
        pick = &ichor_sample_ops_avx2;
#endif
#if defined(ICHOR_HAVE_SAMPLE_SSE41)
    if (pick == NULL && (feat & ICHOR_CPU_SSE41))
        pick = &ichor_sample_ops_sse41;
#endif
#if defined(ICHOR_HAVE_SAMPLE_SSE2)
    if (pick == NULL)
        pick = &ichor_sample_ops_sse2;
#endif
#if defined(ICHOR_HAVE_SAMPLE_NEON)
    if (pick == NULL && (feat & ICHOR_CPU_NEON))
        pick = &ichor_sample_ops_neon;
#endif

    if (pick == NULL)
        pick = &ichor_sample_ops_scalar;

    const ichor_sample_ops_t *expected = NULL;
    atomic_compare_exchange_strong_explicit(&ichor_sample_ops, &expected, pick,
                                            memory_order_release,
                                            memory_order_acquire);
}

static const ichor_sample_ops_t *
sample_ops(void)
{
    const ichor_sample_ops_t *ops =
        atomic_load_explicit(&ichor_sample_ops, memory_order_acquire);
    if (ops == NULL) {
        ichor_sample_dispatch_init();
        ops = atomic_load_explicit(&ichor_sample_ops, memory_order_acquire);
    }
    return ops;
}

#ifdef ICHOR_ENABLE_FORCE_BACKEND
/* Test-only hook: clears the cached ops pointer so the next call re-selects. */
void
ichor_sample_dispatch_reset(void)
{
    atomic_store_explicit(&ichor_sample_ops, NULL, memory_order_release);
}
#endif /* ICHOR_ENABLE_FORCE_BACKEND */

void
ichor_sample_reduce_batch(uint32_t *red, const uint8_t *tape, uint32_t w,
                          uint32_t n, unsigned limbs, size_t db)
{
    sample_ops()->reduce_batch(red, tape, w, n, limbs, db);
}

void
ichor_sample_overlay_resolve(uint32_t i, uint32_t j, const uint32_t *ov_slot,
                             const uint32_t *ov_val, uint32_t *cur_i,
                             uint32_t *cur_j)
{
    sample_ops()->overlay_resolve(i, j, ov_slot, ov_val, cur_i, cur_j);
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
    uint32_t red[ICHOR_SAMPLE_MAXW];
    size_t db = ichor_sample_draw_bytes(lambda);
    unsigned limbs;
    uint32_t i;

    if (idx == NULL || tape == NULL || db == 0 || w == 0 ||
        w > ICHOR_SAMPLE_MAXW || w > n || tape_len != db * (size_t)w)
        return -1;

    limbs = (unsigned)(db / 4u);

    /*
     * The vector overlay backends over-scan ov_slot/ov_val past i to their
     * vector-width boundary, so initialize every slot to a non-matching
     * sentinel (UINT32_MAX, which no index in [0, n) equals) and ov_val to 0:
     * the padding contributes nothing and no uninitialized slot is read.  The
     * scalar backend reads only [0, i) and is unaffected.
     */
    memset(ov_slot, 0xff, sizeof ov_slot);
    memset(ov_val, 0, sizeof ov_val);

    /*
     * The w Lemire reductions are mutually independent (each a function only of
     * its own public range n - i and its own tape slice), so they are computed
     * up front in one batched, backend-dispatched pass; the overlay resolve
     * below stays strictly sequential.  red[i] is the in-range draw offset, so
     * j = i + red[i].
     */
    ichor_sample_reduce_batch(red, tape, w, n, limbs, db);

    for (i = 0; i < w; i++) {
        uint32_t j = i + red[i];
        uint32_t cur_i;
        uint32_t cur_j;

        /* Resolve pos[i] and pos[j] from the overlay entries [0, i) (last-wins
         * over duplicate slots); backend-dispatched. */
        ichor_sample_overlay_resolve(i, j, ov_slot, ov_val, &cur_i, &cur_j);

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
    ichor_secure_zero(red, sizeof red);
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
