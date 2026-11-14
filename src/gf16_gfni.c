/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf16_gfni.c - GFNI GF(2^16) region multiply (poly 0x1100B) via affine maps.
 *
 * GFNI has no 16-bit multiply, but multiply by a FIXED scalar a is a GF(2)-
 * linear map on the 16 bits of an element, and GF2P8AFFINEQB applies an
 * arbitrary 8x8 binary matrix to every byte.  Writing an element as low and
 * high bytes xlo, xhi, the product bytes are
 *   ylo = A00 . xlo  ^  A01 . xhi
 *   yhi = A10 . xlo  ^  A11 . xhi
 * where the four 8x8 blocks A** are the byte sub-blocks of the 16x16 multiply-
 * by-a matrix.  This stays in the native 0x1100B basis: no field isomorphism,
 * no Karatsuba.  Each block is built once per region from a, then applied with
 * one affine instruction per 32 bytes.  Compiled with -mgfni -mavx2 per-TU
 * (the 256-bit affine is a VEX AVX2 encoding); empty object when
 * ICHOR_HAVE_GF16_GFNI is not defined.  Needs GFNI + AVX2 (no AES-NI).
 *
 * The matrices are built with the constant-time scalar multiply and
 * GF2P8AFFINEQB is fixed-latency and data-independent, so the pass is
 * constant-time in both a and the data.
 */

#ifdef ICHOR_HAVE_GF16_GFNI

#include "gf16_dispatch.h"
#include "gf16_avx2_common.h"

/*
 * Build the GF2P8AFFINEQB matrix qword for the 8x8 block of the multiply-by-a
 * map that takes input byte plane in_hi (0 = low, 1 = high) to output byte
 * plane out_hi.  col[s] is the output byte produced by the single input bit
 * (1 << (8*in_hi + s)); its bit o says whether output bit o depends on input
 * bit s.  GF2P8AFFINEQB computes out.bit[i] = parity(src AND matrix.byte[7-i]),
 * so matrix.byte[7-i].bit[s] must equal (col[s] >> i) & 1.
 */
static uint64_t
gf16_affine_block(uint16_t a, int out_hi, int in_hi)
{
    uint8_t col[8];
    uint64_t m = 0;
    int i, s;

    for (s = 0; s < 8; s++) {
        uint16_t prod =
            ichor_gf16_mul_scalar(a, (uint16_t)(1u << (8 * in_hi + s)));
        col[s] = out_hi ? (uint8_t)(prod >> 8) : (uint8_t)(prod & 0xffu);
    }
    for (i = 0; i < 8; i++) {
        uint8_t row = 0;
        for (s = 0; s < 8; s++)
            row |= (uint8_t)(((col[s] >> i) & 1u) << s);
        m |= (uint64_t)row << (8 * (7 - i));
    }
    return m;
}

static void
gf16_region_gfni(uint16_t *dst, const uint16_t *src, uint16_t a, size_t n,
                 int accumulate)
{
    __m256i A00 = _mm256_set1_epi64x((long long)gf16_affine_block(a, 0, 0));
    __m256i A01 = _mm256_set1_epi64x((long long)gf16_affine_block(a, 0, 1));
    __m256i A10 = _mm256_set1_epi64x((long long)gf16_affine_block(a, 1, 0));
    __m256i A11 = _mm256_set1_epi64x((long long)gf16_affine_block(a, 1, 1));

    const uint8_t *s = (const uint8_t *)src;
    uint8_t *d = (uint8_t *)dst;
    size_t i = 0; /* element index */

    for (; i + 32 <= n; i += 32) {
        __m256i lo, hi;
        gf16_deint256(s + 2 * i, &lo, &hi);
        __m256i plo =
            _mm256_xor_si256(_mm256_gf2p8affine_epi64_epi8(lo, A00, 0),
                             _mm256_gf2p8affine_epi64_epi8(hi, A01, 0));
        __m256i phi =
            _mm256_xor_si256(_mm256_gf2p8affine_epi64_epi8(lo, A10, 0),
                             _mm256_gf2p8affine_epi64_epi8(hi, A11, 0));
        gf16_int256(d + 2 * i, plo, phi, accumulate);
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
gf16_mul_region_gfni(uint16_t *dst, const uint16_t *src, uint16_t a, size_t n)
{
    gf16_region_gfni(dst, src, a, n, 0);
}

static void
gf16_muladd_region_gfni(uint16_t *dst, const uint16_t *src, uint16_t a,
                        size_t n)
{
    gf16_region_gfni(dst, src, a, n, 1);
}

const ichor_gf16_ops_t ichor_gf16_ops_gfni = {
    .mul_region = gf16_mul_region_gfni,
    .muladd_region = gf16_muladd_region_gfni,
    .backend_tag = ICHOR_GF16_BACKEND_GFNI,
    .name = "gfni",
};

#else /* !ICHOR_HAVE_GF16_GFNI */

/* ISO C forbids an empty translation unit; give the guarded-out build a single
 * harmless declaration. */
typedef int ichor_gf16_gfni_translation_unit_not_empty;

#endif /* ICHOR_HAVE_GF16_GFNI */
