/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * util.c - Security-critical utility functions
 */

/* Request glibc POSIX.1-2008 + BSD extensions for explicit_bzero(3) */
#define _DEFAULT_SOURCE

#include "util.h"
#include <stdint.h>
#include <string.h>

/* ================================================================
 * Secure memory zeroing
 * ================================================================ */

/*
 * explicit_bzero(3) is available on:
 *   - Linux with glibc >= 2.25  (since Ubuntu 18.04)
 *   - macOS >= 10.12
 *   - OpenBSD, FreeBSD, NetBSD
 *
 * It is specifically designed to not be optimized away, unlike memset().
 * Fall back to a volatile-pointer loop on platforms that lack it.
 */
#if defined(__linux__) || defined(__OpenBSD__) || defined(__FreeBSD__) ||      \
    defined(__NetBSD__)
#define ICHOR_HAVE_EXPLICIT_BZERO 1
#endif

void
ichor_secure_zero(void *ptr, size_t len)
{
    if (!ptr || len == 0)
        return;
#ifdef ICHOR_HAVE_EXPLICIT_BZERO
    explicit_bzero(ptr, len);
#else
    volatile uint8_t *vp = (volatile uint8_t *)ptr;
    while (len--)
        *vp++ = 0;
#endif
}

/* ================================================================
 * Constant-time comparison
 * ================================================================ */

int
ichor_const_memcmp(const void *a, const void *b, size_t len)
{
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    /*
     * volatile prevents the compiler from short-circuiting the loop or
     * hoisting the early-exit optimization that a plain uint8_t would allow.
     */
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff = (uint8_t)(diff | (pa[i] ^ pb[i]));
    return (int)diff;
}

/* ================================================================
 * LSB-first bit packing
 *
 * The _le16 and _le32 variants differ only in the source/destination
 * element type and its maximum field width; the bit addressing lives once
 * in pack_bits / unpack_bits.  Value i occupies bits [i*width, i*width +
 * width) of the buffer.  The access pattern depends only on the bit offset
 * and width (public), so packing secret values leaks nothing through
 * timing or memory-access order.
 * ================================================================ */

static void
pack_bits(uint8_t *dst, size_t bit_off, uint32_t v, uint32_t width_bits)
{
    for (uint32_t b = 0; b < width_bits; b++) {
        uint8_t bitval = (uint8_t)((v >> b) & 1u);
        size_t bit = bit_off + b;
        dst[bit >> 3] |= (uint8_t)(bitval << (bit & 7));
    }
}

static uint32_t
unpack_bits(const uint8_t *src, size_t bit_off, uint32_t width_bits)
{
    uint32_t v = 0;

    for (uint32_t b = 0; b < width_bits; b++) {
        size_t bit = bit_off + b;
        uint8_t bitval = (uint8_t)((src[bit >> 3] >> (bit & 7)) & 1u);
        v |= (uint32_t)bitval << b;
    }
    return v;
}

int
ichor_bitpack_le16(uint8_t *dst, size_t dst_len, const uint16_t *values,
                   size_t count, uint32_t width_bits)
{
    size_t need;
    size_t i;

    if (width_bits == 0 || width_bits > 16)
        return -1;

    /*
     * Reject a count whose bit total would overflow size_t (L5): without
     * this, count * width_bits wraps, need shrinks, the length guard passes,
     * and pack_bits writes out of bounds.  width_bits is nonzero here, so the
     * division is well defined; the check reads only public count / width.
     */
    if (count > (SIZE_MAX - 7) / width_bits)
        return -1;

    need = (count * width_bits + 7) / 8;
    if (dst_len < need)
        return -1;

    memset(dst, 0, dst_len);
    for (i = 0; i < count; i++)
        pack_bits(dst, i * width_bits, values[i], width_bits);
    return 0;
}

int
ichor_bitpack_le32(uint8_t *dst, size_t dst_len, const uint32_t *values,
                   size_t count, uint32_t width_bits)
{
    size_t need;
    size_t i;

    if (width_bits == 0 || width_bits > 32)
        return -1;

    /*
     * Reject a count whose bit total would overflow size_t (L5): without
     * this, count * width_bits wraps, need shrinks, the length guard passes,
     * and pack_bits writes out of bounds.  width_bits is nonzero here, so the
     * division is well defined; the check reads only public count / width.
     */
    if (count > (SIZE_MAX - 7) / width_bits)
        return -1;

    need = (count * width_bits + 7) / 8;
    if (dst_len < need)
        return -1;

    memset(dst, 0, dst_len);
    for (i = 0; i < count; i++)
        pack_bits(dst, i * width_bits, values[i], width_bits);
    return 0;
}

int
ichor_bitunpack_le16(uint16_t *values, size_t count, uint32_t width_bits,
                     const uint8_t *src, size_t src_len)
{
    size_t need;
    size_t i;

    if (width_bits == 0 || width_bits > 16)
        return -1;

    /*
     * Reject a count whose bit total would overflow size_t (L5): without
     * this, count * width_bits wraps, need shrinks, the length guard passes,
     * and unpack_bits reads out of bounds.  width_bits is nonzero here, so the
     * division is well defined; the check reads only public count / width.
     */
    if (count > (SIZE_MAX - 7) / width_bits)
        return -1;

    need = (count * width_bits + 7) / 8;
    if (src_len < need)
        return -1;

    for (i = 0; i < count; i++)
        values[i] = (uint16_t)unpack_bits(src, i * width_bits, width_bits);
    return 0;
}

int
ichor_bitunpack_le32(uint32_t *values, size_t count, uint32_t width_bits,
                     const uint8_t *src, size_t src_len)
{
    size_t need;
    size_t i;

    if (width_bits == 0 || width_bits > 32)
        return -1;

    /*
     * Reject a count whose bit total would overflow size_t (L5): without
     * this, count * width_bits wraps, need shrinks, the length guard passes,
     * and unpack_bits reads out of bounds.  width_bits is nonzero here, so the
     * division is well defined; the check reads only public count / width.
     */
    if (count > (SIZE_MAX - 7) / width_bits)
        return -1;

    need = (count * width_bits + 7) / 8;
    if (src_len < need)
        return -1;

    for (i = 0; i < count; i++)
        values[i] = unpack_bits(src, i * width_bits, width_bits);
    return 0;
}
