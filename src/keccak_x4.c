/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * keccak_x4.c - 4-way batched SHAKE front-end and backend dispatch.
 *
 * Public entry points ichor_shake128_x4 / ichor_shake256_x4 run four
 * independent same-length SHAKE sponges at once (FIPS 202).  On an AVX2 host
 * the four sponges share one keccak_f1600_x4 permutation (keccak_x4_avx2.c);
 * otherwise a portable fallback computes the four hashes serially through the
 * single-sponge API, which is byte-identical by construction.  The backend is
 * selected once on first use and cached.
 *
 * The AVX2 sponge byte I/O (absorb / squeeze) is scalar here and deliberately
 * so: it is memory-bound plumbing, while the 24-round permutation is the
 * compute that the 4-lane kernel accelerates.  The state is held as
 * st[lane][sponge] (25 lanes x 4 sponges), the layout the kernel consumes.
 */

#include "hash.h"
#include "util.h"
#include "cpu.h"
#include "keccak_x4_dispatch.h"

#include <stdatomic.h>
#include <string.h>

/* Rates (bytes): SHAKE-128 = (1600 - 2*128)/8, SHAKE-256 = (1600 - 2*256)/8. */
#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHAKE_SUFFIX 0x1f

/* ---- Backend selection ---- */

static _Atomic int g_backend =
    0; /* 0 = uninit; else ichor_keccak_x4_backend_t */

static int
select_backend(void)
{
    int b = atomic_load_explicit(&g_backend, memory_order_acquire);
    if (b != 0)
        return b;

    b = ICHOR_KECCAK_X4_BACKEND_SCALAR;
#ifdef ICHOR_HAVE_KECCAK_X4_AVX2
    if (ichor_cpu_features() & ICHOR_CPU_AVX2)
        b = ICHOR_KECCAK_X4_BACKEND_AVX2;
#endif
#ifdef ICHOR_HAVE_KECCAK_X4_SHA3
    if (ichor_cpu_features() & ICHOR_CPU_SHA3)
        b = ICHOR_KECCAK_X4_BACKEND_NEON_SHA3;
#endif

    int expected = 0;
    atomic_compare_exchange_strong_explicit(
        &g_backend, &expected, b, memory_order_release, memory_order_acquire);
    return atomic_load_explicit(&g_backend, memory_order_acquire);
}

ichor_keccak_x4_backend_t
ichor_keccak_x4_backend(void)
{
    return (ichor_keccak_x4_backend_t)select_backend();
}

const char *
ichor_keccak_x4_backend_name(void)
{
    switch (select_backend()) {
    case ICHOR_KECCAK_X4_BACKEND_AVX2:
        return "AVX2 4-lane Keccak-f[1600] (x86_64 hardware)";
    case ICHOR_KECCAK_X4_BACKEND_NEON_SHA3:
        return "ARMv8.2 SHA-3 2x2-lane Keccak-f[1600] (aarch64 hardware)";
    case ICHOR_KECCAK_X4_BACKEND_SCALAR:
        return "scalar 4x serial Keccak-f[1600] (portable software)";
    }
    return "unknown";
}

/* ---- Scalar fallback: four serial single-sponge hashes ---- */

static void
shake128_x4_scalar(uint8_t *const out[4], size_t outlen,
                   const uint8_t *const in[4], size_t inlen)
{
    for (int l = 0; l < 4; l++) {
        ichor_hash_ctx_t ctx;
        ichor_shake128_init(&ctx);
        (void)ichor_shake128_absorb(&ctx, in[l], inlen);
        ichor_shake128_squeeze(&ctx, out[l], outlen);
        ichor_hash_ctx_clear(&ctx);
    }
}

static void
shake256_x4_scalar(uint8_t *const out[4], size_t outlen,
                   const uint8_t *const in[4], size_t inlen)
{
    for (int l = 0; l < 4; l++) {
        ichor_hash_ctx_t ctx;
        ichor_shake256_init(&ctx);
        (void)ichor_shake256_absorb(&ctx, in[l], inlen);
        ichor_shake256_squeeze(&ctx, out[l], outlen);
        ichor_hash_ctx_clear(&ctx);
    }
}

/* ---- Hardware path: 4-lane sponge over a batched permutation ---- */

#if defined(ICHOR_HAVE_KECCAK_X4_AVX2) || defined(ICHOR_HAVE_KECCAK_X4_SHA3)

/* Batched permutation kernel: permute four sponges in place (st[lane][sponge]).
 * AVX2 or ARMv8.2 SHA-3, chosen by the caller per select_backend(). */
typedef void (*keccak_f1600_x4_fn)(uint64_t[25][4]);

/*
 * XOR n bytes of each lane's input (starting at source offset off) into the
 * four sponges, at state byte positions 0..n-1.  Callers absorb a whole rate
 * block (n == rate) or the final partial block (n < rate).
 */
static void
absorb_x4(uint64_t st[25][4], const uint8_t *const in[4], size_t off, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        size_t w = i / 8;
        unsigned sh = 8u * (unsigned)(i % 8);
        for (int l = 0; l < 4; l++)
            st[w][l] ^= (uint64_t)in[l][off + i] << sh;
    }
}

/*
 * Extract n bytes from each sponge (state byte positions 0..n-1) into each
 * lane's output at offset out_off.
 */
static void
squeeze_x4(uint64_t st[25][4], uint8_t *const out[4], size_t out_off, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        size_t w = i / 8;
        unsigned sh = 8u * (unsigned)(i % 8);
        for (int l = 0; l < 4; l++)
            out[l][out_off + i] = (uint8_t)(st[w][l] >> sh);
    }
}

static void
shake_x4_hw(keccak_f1600_x4_fn perm, size_t rate, uint8_t *const out[4],
            size_t outlen, const uint8_t *const in[4], size_t inlen)
{
    uint64_t st[25][4];
    size_t off, rem, poff;

    memset(st, 0, sizeof(st));

    /* Absorb full rate blocks. */
    for (off = 0; inlen - off >= rate; off += rate) {
        absorb_x4(st, in, off, rate);
        perm(st);
    }

    /* Final partial block + pad10*1 with the SHAKE domain suffix. */
    rem = inlen - off;
    absorb_x4(st, in, off, rem);
    {
        size_t w = rem / 8;
        unsigned sh = 8u * (unsigned)(rem % 8);
        for (int l = 0; l < 4; l++)
            st[w][l] ^= (uint64_t)SHAKE_SUFFIX << sh;
    }
    {
        size_t last = rate - 1;
        size_t w = last / 8;
        unsigned sh = 8u * (unsigned)(last % 8);
        for (int l = 0; l < 4; l++)
            st[w][l] ^= (uint64_t)0x80 << sh;
    }
    perm(st);

    /* Squeeze. */
    for (poff = 0;;) {
        size_t avail = outlen - poff;
        size_t chunk = avail < rate ? avail : rate;

        squeeze_x4(st, out, poff, chunk);
        poff += chunk;
        if (poff >= outlen)
            break;
        perm(st);
    }

    /* State may hold secret input (commitment seeds); scrub it. */
    ichor_secure_zero(st, sizeof(st));
}

/* Resolve the selected batched permutation kernel, or NULL for scalar. */
static keccak_f1600_x4_fn
keccak_f1600_x4_hw(void)
{
    switch (select_backend()) {
#ifdef ICHOR_HAVE_KECCAK_X4_AVX2
    case ICHOR_KECCAK_X4_BACKEND_AVX2:
        return ichor_keccak_f1600_x4_avx2;
#endif
#ifdef ICHOR_HAVE_KECCAK_X4_SHA3
    case ICHOR_KECCAK_X4_BACKEND_NEON_SHA3:
        return ichor_keccak_f1600_x4_sha3;
#endif
    default:
        return NULL;
    }
}

#endif /* hardware x4 path */

/* ---- Public entry points ---- */

void
ichor_shake128_x4(uint8_t *const out[4], size_t outlen,
                  const uint8_t *const in[4], size_t inlen)
{
#if defined(ICHOR_HAVE_KECCAK_X4_AVX2) || defined(ICHOR_HAVE_KECCAK_X4_SHA3)
    keccak_f1600_x4_fn perm = keccak_f1600_x4_hw();
    if (perm != NULL) {
        shake_x4_hw(perm, SHAKE128_RATE, out, outlen, in, inlen);
        return;
    }
#endif
    shake128_x4_scalar(out, outlen, in, inlen);
}

void
ichor_shake256_x4(uint8_t *const out[4], size_t outlen,
                  const uint8_t *const in[4], size_t inlen)
{
#if defined(ICHOR_HAVE_KECCAK_X4_AVX2) || defined(ICHOR_HAVE_KECCAK_X4_SHA3)
    keccak_f1600_x4_fn perm = keccak_f1600_x4_hw();
    if (perm != NULL) {
        shake_x4_hw(perm, SHAKE256_RATE, out, outlen, in, inlen);
        return;
    }
#endif
    shake256_x4_scalar(out, outlen, in, inlen);
}

#ifdef ICHOR_ENABLE_FORCE_BACKEND
void
ichor_keccak_x4_dispatch_reset(void)
{
    atomic_store_explicit(&g_backend, 0, memory_order_release);
}
#endif /* ICHOR_ENABLE_FORCE_BACKEND */
