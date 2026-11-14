/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf256_neon.c - Split-nibble NEON TBL GF(2^8) region multiply (poly 0x11B).
 *
 * The aarch64 counterpart of gf256_ssse3.c.  Advanced SIMD is mandatory on
 * ARMv8-A, so no per-TU arch flag is needed and the backend is the default
 * aarch64 pick; this file compiles to an empty object when ICHOR_HAVE_GF256_NEON
 * is not defined.
 *
 * For a fixed multiplier a, the product a (x) v of a 16-byte vector v is two
 * 16-entry table lookups indexed by v's nibbles, because the field multiply is
 * GF(2)-linear in v:
 *   a (x) v = (a (x) v_lo) ^ (a (x) (v_hi << 4))
 * lo[j] = a (x) j and hi[j] = a (x) (j << 4), built once per region.  vqtbl1q_u8
 * is the TBL analog of vpshufb: a register-table shuffle indexed by data
 * nibbles (fixed latency, no memory index), so the pass is constant-time in
 * both a (the table build uses the constant-time scalar multiply) and the data.
 * Unlike SSE2, NEON has a per-byte shift (vshrq_n_u8), so the high nibble needs
 * no extra mask.
 */

#ifdef ICHOR_HAVE_GF256_NEON

#include "gf256_dispatch.h"

#include <arm_neon.h>

static void
gf256_build_tables(uint8_t a, uint8_t lo[16], uint8_t hi[16])
{
    int j;

    for (j = 0; j < 16; j++) {
        lo[j] = ichor_gf256_mul_scalar(a, (uint8_t)j);
        hi[j] = ichor_gf256_mul_scalar(a, (uint8_t)(j << 4));
    }
}

static void
gf256_mul_region_neon(uint8_t *dst, const uint8_t *src, uint8_t a, size_t n)
{
    uint8_t lo[16], hi[16];
    gf256_build_tables(a, lo, hi);

    uint8x16_t tlo = vld1q_u8(lo);
    uint8x16_t thi = vld1q_u8(hi);
    uint8x16_t m0f = vdupq_n_u8(0x0f);
    size_t i = 0;

    for (; i + 16 <= n; i += 16) {
        uint8x16_t v = vld1q_u8(src + i);
        uint8x16_t vl = vandq_u8(v, m0f);
        uint8x16_t vh = vshrq_n_u8(v, 4);
        uint8x16_t p = veorq_u8(vqtbl1q_u8(tlo, vl), vqtbl1q_u8(thi, vh));
        vst1q_u8(dst + i, p);
    }
    for (; i < n; i++)
        dst[i] = ichor_gf256_mul_scalar(a, src[i]);
}

static void
gf256_muladd_region_neon(uint8_t *dst, const uint8_t *src, uint8_t a, size_t n)
{
    uint8_t lo[16], hi[16];
    gf256_build_tables(a, lo, hi);

    uint8x16_t tlo = vld1q_u8(lo);
    uint8x16_t thi = vld1q_u8(hi);
    uint8x16_t m0f = vdupq_n_u8(0x0f);
    size_t i = 0;

    for (; i + 16 <= n; i += 16) {
        uint8x16_t v = vld1q_u8(src + i);
        uint8x16_t d = vld1q_u8(dst + i);
        uint8x16_t vl = vandq_u8(v, m0f);
        uint8x16_t vh = vshrq_n_u8(v, 4);
        uint8x16_t p = veorq_u8(vqtbl1q_u8(tlo, vl), vqtbl1q_u8(thi, vh));
        vst1q_u8(dst + i, veorq_u8(d, p));
    }
    for (; i < n; i++)
        dst[i] ^= ichor_gf256_mul_scalar(a, src[i]);
}

const ichor_gf256_ops_t ichor_gf256_ops_neon = {
    .mul_region = gf256_mul_region_neon,
    .muladd_region = gf256_muladd_region_neon,
    .backend_tag = ICHOR_GF256_BACKEND_NEON,
    .name = "neon",
};

#else /* !ICHOR_HAVE_GF256_NEON */

/* ISO C forbids an empty translation unit, and -Wpedantic / -Werror reject
 * one; give the guarded-out build a single harmless declaration. */
typedef int ichor_gf256_neon_translation_unit_not_empty;

#endif /* ICHOR_HAVE_GF256_NEON */
