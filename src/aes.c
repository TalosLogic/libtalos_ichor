/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes.c - AES-128/192/256 public forwarders and runtime dispatch init.
 *
 * On first call, ichor_aes_dispatch_init() reads ichor_cpu_features()
 * and selects the highest-priority compiled-in backend whose required
 * feature bits are present:
 *   1. AES-NI         (x86_64; ICHOR_HAVE_AES_NI compiled in)
 *   2. ARMv8 Crypto   (aarch64; ICHOR_HAVE_ARMV8_AES compiled in)
 *   3. Bitsliced      (portable constant-time; always compiled in)
 *
 * The selected ops pointer is stored with a release-store; subsequent
 * calls pay one load-acquire and one indirect branch.  All three
 * backends are constant-time; the dispatch decision is data-independent.
 */

#include "aes.h"
#include "aes_dispatch.h"
#include "backend.h"
#include "cpu.h"
#include "util.h"

#include <stdatomic.h>
#include <string.h>

_Atomic(const ichor_aes_ops_t *) ichor_aes_ops = NULL;

void
ichor_aes_dispatch_init(void)
{
    if (atomic_load_explicit(&ichor_aes_ops, memory_order_acquire) != NULL)
        return;

    const ichor_aes_ops_t *pick = NULL;

    /* feat is consulted only by the hardware backends; a lean build with none
     * compiled in selects the bitsliced path unconditionally and never reads
     * it. */
#if defined(ICHOR_HAVE_AES_NI) || defined(ICHOR_HAVE_ARMV8_AES)
    uint32_t feat = ichor_cpu_features();
#ifdef ICHOR_HAVE_AES_NI
    if (pick == NULL && (feat & ICHOR_CPU_AES_NI))
        pick = &ichor_aes_ops_aesni;
#endif
#ifdef ICHOR_HAVE_ARMV8_AES
    if (pick == NULL && (feat & ICHOR_CPU_ARMV8_AES))
        pick = &ichor_aes_ops_armv8;
#endif
#endif /* any hardware AES backend */

    if (pick == NULL)
        pick = &ichor_aes_ops_bitsliced;

    const ichor_aes_ops_t *expected = NULL;
    atomic_compare_exchange_strong_explicit(&ichor_aes_ops, &expected, pick,
                                            memory_order_release,
                                            memory_order_acquire);
}

/*
 * Backend health (backend.h): FALLBACK iff the host advertises a hardware
 * AES feature but the active backend is the bitsliced software path, i.e.
 * the accelerated backend was not compiled into this build.
 */
ichor_backend_health_t
ichor_aes_backend_health(void)
{
    uint32_t feat = ichor_cpu_features();
    if (ichor_aes_backend() == ICHOR_AES_BACKEND_BITSLICED &&
        (feat & (ICHOR_CPU_AES_NI | ICHOR_CPU_ARMV8_AES)))
        return ICHOR_BACKEND_FALLBACK;
    return ICHOR_BACKEND_OPTIMAL;
}

/* ========================================================================
 * Public forwarders
 * ======================================================================== */

int
ichor_aes_key_expand(ichor_aes_ctx_t *ctx, const uint8_t *key, int key_bits)
{
    const ichor_aes_ops_t *ops =
        atomic_load_explicit(&ichor_aes_ops, memory_order_acquire);
    if (ops == NULL) {
        ichor_aes_dispatch_init();
        ops = atomic_load_explicit(&ichor_aes_ops, memory_order_acquire);
    }
    return ops->key_expand(ctx, key, key_bits);
}

void
ichor_aes_encrypt(const ichor_aes_ctx_t *ctx, uint8_t out[16],
                  const uint8_t in[16])
{
    const ichor_aes_ops_t *ops =
        atomic_load_explicit(&ichor_aes_ops, memory_order_acquire);
    if (ops == NULL) {
        ichor_aes_dispatch_init();
        ops = atomic_load_explicit(&ichor_aes_ops, memory_order_acquire);
    }
    ops->encrypt(ctx, out, in);
}

void
ichor_aes_encrypt_x4(const ichor_aes_ctx_t *ctx, uint8_t out[64],
                     const uint8_t in[64])
{
    const ichor_aes_ops_t *ops =
        atomic_load_explicit(&ichor_aes_ops, memory_order_acquire);
    if (ops == NULL) {
        ichor_aes_dispatch_init();
        ops = atomic_load_explicit(&ichor_aes_ops, memory_order_acquire);
    }
    ops->encrypt_x4(ctx, out, in);
}

int
ichor_aes_ctr(const ichor_aes_ctx_t *ctx, uint8_t *out, const uint8_t *in,
              size_t len, const uint8_t nonce[12], uint32_t ctr0)
{
    uint8_t counter[16];
    uint8_t ks[16];
    size_t off = 0;
    uint64_t nblocks;

    /*
     * Fail closed if the request would exhaust the 32-bit block counter and
     * carry past byte 12 into the nonce region: that would reuse keystream
     * under a different effective nonce.  ceil(len / 16) is computed without
     * overflowing size_t, and the bound is checked in 64-bit so ctr0 near the
     * top of its range cannot wrap.  The check reads only public len / ctr0.
     */
    nblocks = (uint64_t)(len / 16) + (((len % 16) != 0) ? 1u : 0u);
    if ((uint64_t)ctr0 + nblocks > (uint64_t)UINT32_MAX + 1u)
        return -1;

    /*
     * Counter block = nonce[0..11] || big-endian ctr0 in bytes 12..15.  Only
     * the low 4 bytes are ever incremented, so bytes 0..11 stay fixed for the
     * life of the call.
     */
    memcpy(counter, nonce, 12);
    counter[12] = (uint8_t)(ctr0 >> 24);
    counter[13] = (uint8_t)(ctr0 >> 16);
    counter[14] = (uint8_t)(ctr0 >> 8);
    counter[15] = (uint8_t)(ctr0);

    while (off < len) {
        size_t take = (len - off < 16) ? (len - off) : 16;
        uint32_t carry;
        int i;

        ichor_aes_encrypt(ctx, ks, counter);

        if (in != NULL) {
            for (size_t j = 0; j < take; j++)
                out[off + j] = (uint8_t)(in[off + j] ^ ks[j]);
        } else {
            for (size_t j = 0; j < take; j++)
                out[off + j] = ks[j];
        }
        off += take;

        /*
         * Branchless big-endian increment of the low 4 counter bytes only
         * (indices 15..12); the nonce bytes 0..11 are never touched, and the
         * cap check above guarantees no carry needs to escape byte 12.
         */
        carry = 1;
        for (i = 15; i >= 12; i--) {
            carry += counter[i];
            counter[i] = (uint8_t)carry;
            carry >>= 8;
        }
    }

    ichor_secure_zero(counter, sizeof(counter));
    ichor_secure_zero(ks, sizeof(ks));
    return 0;
}

void
ichor_aes_ctx_clear(ichor_aes_ctx_t *ctx)
{
    ichor_secure_zero(ctx, sizeof(*ctx));
}

ichor_aes_backend_t
ichor_aes_backend(void)
{
    const ichor_aes_ops_t *ops =
        atomic_load_explicit(&ichor_aes_ops, memory_order_acquire);
    if (ops == NULL) {
        ichor_aes_dispatch_init();
        ops = atomic_load_explicit(&ichor_aes_ops, memory_order_acquire);
    }
    return ops->backend_tag;
}

const char *
ichor_aes_backend_name(void)
{
    switch (ichor_aes_backend()) {
    case ICHOR_AES_BACKEND_AESNI:
        return "AES-NI (x86_64 hardware)";
    case ICHOR_AES_BACKEND_ARMV8:
        return "ARMv8 Cryptography Extension (aarch64 hardware)";
    case ICHOR_AES_BACKEND_BITSLICED:
        return "bitsliced (portable constant-time software)";
    }
    return "unknown";
}

#ifdef ICHOR_ENABLE_FORCE_BACKEND
/* Test-only hook: clears the cached ops pointer
 * so the next call re-selects a backend, letting tests cycle backends
 * alongside ichor_cpu_features_override().  Compiled out of release /
 * vendored builds (see ICHOR_ENABLE_FORCE_BACKEND in CMakeLists.txt). */
void
ichor_aes_dispatch_reset(void)
{
    atomic_store_explicit(&ichor_aes_ops, NULL, memory_order_release);
}
#endif /* ICHOR_ENABLE_FORCE_BACKEND */
