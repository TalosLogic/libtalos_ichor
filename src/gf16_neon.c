/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf16_neon.c - Split-nibble NEON TBL GF(2^16) region multiply (poly 0x1100B).
 *
 * The aarch64 counterpart of gf16_ssse3.c.  Advanced SIMD is mandatory on
 * ARMv8-A, so no per-TU arch flag is needed; empty object when
 * ICHOR_HAVE_GF16_NEON is not defined.
 *
 * A 16-bit element v has four nibbles at bit positions 0, 4, 8, 12.  The field
 * multiply is GF(2)-linear in v, so
 *   a (x) v = XOR_{k=0..3} a (x) (nibble_k(v) << 4k).
 * For a fixed multiplier a, each a (x) (j << 4k) (j in 0..15) is a 16-bit value;
 * its low and high bytes form eight 16-entry TBL tables (Tklo, Tkhi).
 *
 * Where the SSSE3 kernel deinterleaves the low / high byte planes with masked
 * vpshufb, NEON does it natively: vld2q_u8 loads 32 bytes (16 host-order
 * uint16 elements) straight into {low-byte plane, high-byte plane}, and
 * vst2q_u8 re-interleaves on store.  vqtbl1q_u8 (the TBL analog of vpshufb) is
 * a fixed-latency register-table shuffle indexed by data nibbles, and the
 * tables are built with the constant-time scalar multiply, so the pass is
 * constant-time in both a and the data.
 */

#ifdef ICHOR_HAVE_GF16_NEON

#include "gf16_dispatch.h"

#include <arm_neon.h>

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
gf16_region_neon(uint16_t *dst, const uint16_t *src, uint16_t a, size_t n,
                 int accumulate)
{
    uint8_t tlo[4][16], thi[4][16];
    gf16_build_tables(a, tlo, thi);

    uint8x16_t T0lo = vld1q_u8(tlo[0]);
    uint8x16_t T1lo = vld1q_u8(tlo[1]);
    uint8x16_t T2lo = vld1q_u8(tlo[2]);
    uint8x16_t T3lo = vld1q_u8(tlo[3]);
    uint8x16_t T0hi = vld1q_u8(thi[0]);
    uint8x16_t T1hi = vld1q_u8(thi[1]);
    uint8x16_t T2hi = vld1q_u8(thi[2]);
    uint8x16_t T3hi = vld1q_u8(thi[3]);
    uint8x16_t m0f = vdupq_n_u8(0x0f);

    const uint8_t *s = (const uint8_t *)src;
    uint8_t *d = (uint8_t *)dst;
    size_t i = 0; /* element index */

    for (; i + 16 <= n; i += 16) {
        /* val[0] = low bytes, val[1] = high bytes of 16 host-order uint16. */
        uint8x16x2_t v = vld2q_u8(s + 2 * i);
        uint8x16_t lo = v.val[0];
        uint8x16_t hi = v.val[1];
        uint8x16_t n0 = vandq_u8(lo, m0f);
        uint8x16_t n1 = vshrq_n_u8(lo, 4);
        uint8x16_t n2 = vandq_u8(hi, m0f);
        uint8x16_t n3 = vshrq_n_u8(hi, 4);
        uint8x16_t plo =
            veorq_u8(veorq_u8(vqtbl1q_u8(T0lo, n0), vqtbl1q_u8(T1lo, n1)),
                     veorq_u8(vqtbl1q_u8(T2lo, n2), vqtbl1q_u8(T3lo, n3)));
        uint8x16_t phi =
            veorq_u8(veorq_u8(vqtbl1q_u8(T0hi, n0), vqtbl1q_u8(T1hi, n1)),
                     veorq_u8(vqtbl1q_u8(T2hi, n2), vqtbl1q_u8(T3hi, n3)));
        uint8x16x2_t o;
        o.val[0] = plo;
        o.val[1] = phi;
        if (accumulate) {
            uint8x16x2_t cur = vld2q_u8(d + 2 * i);
            o.val[0] = veorq_u8(o.val[0], cur.val[0]);
            o.val[1] = veorq_u8(o.val[1], cur.val[1]);
        }
        vst2q_u8(d + 2 * i, o);
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
gf16_mul_region_neon(uint16_t *dst, const uint16_t *src, uint16_t a, size_t n)
{
    gf16_region_neon(dst, src, a, n, 0);
}

static void
gf16_muladd_region_neon(uint16_t *dst, const uint16_t *src, uint16_t a,
                        size_t n)
{
    gf16_region_neon(dst, src, a, n, 1);
}

const ichor_gf16_ops_t ichor_gf16_ops_neon = {
    .mul_region = gf16_mul_region_neon,
    .muladd_region = gf16_muladd_region_neon,
    .backend_tag = ICHOR_GF16_BACKEND_NEON,
    .name = "neon",
};

#else /* !ICHOR_HAVE_GF16_NEON */

typedef int ichor_gf16_neon_translation_unit_not_empty;

#endif /* ICHOR_HAVE_GF16_NEON */
