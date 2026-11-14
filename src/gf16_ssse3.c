/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf16_ssse3.c - Split-nibble vpshufb GF(2^16) region multiply (poly 0x1100B).
 *
 * Compiled with -mssse3 -msse2 per-TU.  Empty object when
 * ICHOR_HAVE_GF16_SSSE3 is not defined.
 *
 * A 16-bit element v has four nibbles at bit positions 0, 4, 8, 12.  The field
 * multiply is GF(2)-linear in v, so
 *   a (x) v = XOR_{k=0..3} a (x) (nibble_k(v) << 4k).
 * For a fixed multiplier a, each a (x) (j << 4k) (j in 0..15) is a 16-bit value;
 * its low and high bytes form eight 16-entry pshufb tables (Tklo, Tkhi).
 *
 * vpshufb works per byte on 16 lanes, so each iteration handles 16 elements:
 * two 16-byte loads (elements 0..7 and 8..15, host-order == little-endian
 * interleaved low/high bytes) are DEINTERLEAVED into a low-byte plane and a
 * high-byte plane; the plane nibbles index the tables; the resulting product
 * low/high byte planes are RE-INTERLEAVED back to little-endian uint16 and
 * stored (or XORed in, for muladd).  Register-table shuffles indexed by data
 * nibbles are fixed-latency, and the tables are built with the constant-time
 * scalar multiply, so the pass is constant-time in a and the data.
 */

#ifdef ICHOR_HAVE_GF16_SSSE3

#include "gf16_dispatch.h"

#include <emmintrin.h> /* SSE2 */
#include <tmmintrin.h> /* SSSE3: _mm_shuffle_epi8 */

static void
gf16_build_tables(uint16_t a, uint8_t tlo[4][16], uint8_t thi[4][16])
{
    int k, j;

    for (k = 0; k < 4; k++) {
        for (j = 0; j < 16; j++) {
            uint16_t v =
                ichor_gf16_mul_scalar(a, (uint16_t)((unsigned)j << (4 * k)));
            tlo[k][j] = (uint8_t)(v & 0xffu);
            thi[k][j] = (uint8_t)(v >> 8);
        }
    }
}

/* accumulate == 0: dst = a (x) src.  accumulate != 0: dst ^= a (x) src.  The
 * flag is a call-constant, hoisted out of the loop by the compiler. */
static void
gf16_region_ssse3(uint16_t *dst, const uint16_t *src, uint16_t a, size_t n,
                  int accumulate)
{
    uint8_t tlo[4][16], thi[4][16];
    gf16_build_tables(a, tlo, thi);

    __m128i T0lo = _mm_loadu_si128((const __m128i *)tlo[0]);
    __m128i T1lo = _mm_loadu_si128((const __m128i *)tlo[1]);
    __m128i T2lo = _mm_loadu_si128((const __m128i *)tlo[2]);
    __m128i T3lo = _mm_loadu_si128((const __m128i *)tlo[3]);
    __m128i T0hi = _mm_loadu_si128((const __m128i *)thi[0]);
    __m128i T1hi = _mm_loadu_si128((const __m128i *)thi[1]);
    __m128i T2hi = _mm_loadu_si128((const __m128i *)thi[2]);
    __m128i T3hi = _mm_loadu_si128((const __m128i *)thi[3]);
    __m128i m0f = _mm_set1_epi8(0x0f);

    /* Deinterleave masks: gather even (low) / odd (high) bytes of each 8-element
     * half into contiguous lanes; -128 (high bit set) zeroes a pshufb lane. */
    const __m128i EV0 = _mm_setr_epi8(0, 2, 4, 6, 8, 10, 12, 14, -128, -128,
                                      -128, -128, -128, -128, -128, -128);
    const __m128i EV1 = _mm_setr_epi8(-128, -128, -128, -128, -128, -128, -128,
                                      -128, 0, 2, 4, 6, 8, 10, 12, 14);
    const __m128i OD0 = _mm_setr_epi8(1, 3, 5, 7, 9, 11, 13, 15, -128, -128,
                                      -128, -128, -128, -128, -128, -128);
    const __m128i OD1 = _mm_setr_epi8(-128, -128, -128, -128, -128, -128, -128,
                                      -128, 1, 3, 5, 7, 9, 11, 13, 15);

    const uint8_t *s = (const uint8_t *)src;
    uint8_t *d = (uint8_t *)dst;
    size_t i = 0; /* element index */

    for (; i + 16 <= n; i += 16) {
        __m128i v0 = _mm_loadu_si128((const __m128i *)(s + 2 * i));
        __m128i v1 = _mm_loadu_si128((const __m128i *)(s + 2 * i + 16));
        __m128i lo =
            _mm_or_si128(_mm_shuffle_epi8(v0, EV0), _mm_shuffle_epi8(v1, EV1));
        __m128i hi =
            _mm_or_si128(_mm_shuffle_epi8(v0, OD0), _mm_shuffle_epi8(v1, OD1));
        __m128i n0 = _mm_and_si128(lo, m0f);
        __m128i n1 = _mm_and_si128(_mm_srli_epi16(lo, 4), m0f);
        __m128i n2 = _mm_and_si128(hi, m0f);
        __m128i n3 = _mm_and_si128(_mm_srli_epi16(hi, 4), m0f);
        __m128i plo = _mm_xor_si128(_mm_xor_si128(_mm_shuffle_epi8(T0lo, n0),
                                                  _mm_shuffle_epi8(T1lo, n1)),
                                    _mm_xor_si128(_mm_shuffle_epi8(T2lo, n2),
                                                  _mm_shuffle_epi8(T3lo, n3)));
        __m128i phi = _mm_xor_si128(_mm_xor_si128(_mm_shuffle_epi8(T0hi, n0),
                                                  _mm_shuffle_epi8(T1hi, n1)),
                                    _mm_xor_si128(_mm_shuffle_epi8(T2hi, n2),
                                                  _mm_shuffle_epi8(T3hi, n3)));
        __m128i o0 = _mm_unpacklo_epi8(plo, phi); /* elements 0..7  */
        __m128i o1 = _mm_unpackhi_epi8(plo, phi); /* elements 8..15 */
        if (accumulate) {
            o0 = _mm_xor_si128(o0,
                               _mm_loadu_si128((const __m128i *)(d + 2 * i)));
            o1 = _mm_xor_si128(
                o1, _mm_loadu_si128((const __m128i *)(d + 2 * i + 16)));
        }
        _mm_storeu_si128((__m128i *)(d + 2 * i), o0);
        _mm_storeu_si128((__m128i *)(d + 2 * i + 16), o1);
    }
    for (; i < n; i++) {
        uint16_t p = ichor_gf16_mul_scalar(a, src[i]);
        if (accumulate)
            dst[i] ^= p;
        else
            dst[i] = p;
    }
}

static void
gf16_mul_region_ssse3(uint16_t *dst, const uint16_t *src, uint16_t a, size_t n)
{
    gf16_region_ssse3(dst, src, a, n, 0);
}

static void
gf16_muladd_region_ssse3(uint16_t *dst, const uint16_t *src, uint16_t a,
                         size_t n)
{
    gf16_region_ssse3(dst, src, a, n, 1);
}

const ichor_gf16_ops_t ichor_gf16_ops_ssse3 = {
    .mul_region = gf16_mul_region_ssse3,
    .muladd_region = gf16_muladd_region_ssse3,
    .backend_tag = ICHOR_GF16_BACKEND_SSSE3,
    .name = "ssse3",
};

#else /* !ICHOR_HAVE_GF16_SSSE3 */

typedef int ichor_gf16_ssse3_translation_unit_not_empty;

#endif /* ICHOR_HAVE_GF16_SSSE3 */
