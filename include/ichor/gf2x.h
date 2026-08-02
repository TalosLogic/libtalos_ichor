/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf2x.h - constant-time circulant arithmetic over F_2[x]/(x^p - 1).
 *
 * A ring element is a length-p bit vector packed little-endian into 64-bit
 * limbs: coefficient x^j lives in limb floor(j/64), bit (j mod 64).  The top
 * 64*limbs - p bits are padding and MUST be zero (canonical form); every
 * routine here re-establishes that after writing an element.
 *
 * Set-agnostic: the ring is fully determined by the prime p, which the caller
 * fixes once via ichor_gf2x_ring_init().  All buffers are caller-owned and
 * caller-sized (read the descriptor's limb counts to allocate); ichor performs
 * NO dynamic allocation anywhere -- the multiply, rotate, and invert paths all
 * take a caller scratch buffer.  This is the shared core beneath
 * libtalos_syndrome's QC-MDPC KEM and libtalos_voleith's designated-opener
 * syndrome recompute; neither library depends on the other, only on this.
 *
 * Multiplication is a carry-less polynomial product (Karatsuba over ichor's
 * dispatched 64x64 clmul primitive, ichor_clmul64_resolve) followed by
 * reduction modulo x^p - 1 (coefficient k >= p folds onto k - p, since
 * x^p == 1).  Constant-time: every routine has data-independent control flow
 * and no secret-indexed memory access; the multiply schedule, reduction, and
 * rotation barrel depend only on the public parameter p.
 *
 * Inversion is Itoh-Tsujii over the unit group and REQUIRES ord_p(2) = p - 1
 * (2 is a primitive root mod p), which the QC-MDPC parameter sets guarantee; it
 * is a keygen-only, non-hot-path routine that, like multiply and rotate, takes
 * a caller scratch buffer (it allocates nothing).
 */

#ifndef ICHOR_GF2X_H
#define ICHOR_GF2X_H

#include <stddef.h>
#include <stdint.h>

/*
 * Ring descriptor.  Filled once by ichor_gf2x_ring_init() from the prime p;
 * treat as opaque/read-only after init.  The limb-count fields tell the caller
 * how big to size its buffers:
 *   - a ring element is `limbs` uint64_t;
 *   - a byte-packed element is `block_bytes` bytes (load/store width);
 *   - the multiply / rotate scratch is `mul_scratch_limbs` / `rotl_scratch_limbs`
 *     uint64_t (a single buffer of max(the two) serves both).
 */
typedef struct ichor_gf2x_ring {
    size_t p_bits;             /* the prime p (ring is F_2[x]/(x^p - 1)) */
    size_t limbs;              /* ceil(p / 64): element buffer size in u64 */
    size_t block_bytes;        /* ceil(p / 8):  packed element width in bytes */
    uint64_t top_mask;         /* mask of the valid bits in the top limb */
    unsigned red_q;            /* p / 64: whole-limb reduction shift */
    unsigned red_s;            /* p % 64: intra-limb reduction shift (1..63) */
    size_t mul_scratch_limbs;  /* scratch for ichor_gf2x_mul, in u64 */
    size_t rotl_scratch_limbs; /* scratch for ichor_gf2x_rotl_var, in u64 */
    size_t inv_scratch_limbs;  /* scratch for ichor_gf2x_inv, in u64 */
} ichor_gf2x_ring;

/*
 * Initialize `ring` for the modulus x^p - 1.  Returns 0 on success, -1 if p is
 * unsupported: p must be >= 2 and NOT a multiple of 64 (the reduction assumes a
 * nonzero intra-limb shift; every QC-MDPC prime p is odd, so this always
 * holds).  On failure `ring` is left zeroed.
 */
int ichor_gf2x_ring_init(ichor_gf2x_ring *ring, size_t p_bits);

/*
 * Load a byte-packed element (`ring->block_bytes` bytes, little-endian
 * LSB-first) into `r` (`ring->limbs` u64), zero-extending and masking the top
 * limb to the canonical p-bit form.
 */
void ichor_gf2x_load(const ichor_gf2x_ring *ring, uint64_t *r,
                     const uint8_t *in);

/*
 * Store `a` (`ring->limbs` u64, assumed canonical) into `out`
 * (`ring->block_bytes` bytes, little-endian LSB-first).
 */
void ichor_gf2x_store(const ichor_gf2x_ring *ring, uint8_t *out,
                      const uint64_t *a);

/* r = a + b (coefficient-wise XOR).  r may alias a and/or b. */
void ichor_gf2x_add(const ichor_gf2x_ring *ring, uint64_t *r, const uint64_t *a,
                    const uint64_t *b);

/*
 * r = a * b mod (x^p - 1).  a, b, r are each `ring->limbs` u64; `scratch` is a
 * caller buffer of at least `ring->mul_scratch_limbs` u64.  r may alias a
 * and/or b.  scratch is wiped before return (it holds the secret double-width
 * product and Karatsuba intermediates).
 */
void ichor_gf2x_mul(const ichor_gf2x_ring *ring, uint64_t *r, const uint64_t *a,
                    const uint64_t *b, uint64_t *scratch);

/*
 * out = in * x^k mod (x^p - 1): cyclic left-rotation by the SECRET amount k
 * (k <= p), constant-time over k (a barrel of fixed public rotations selected
 * by the bits of k).  out and in are `ring->limbs` u64; `scratch` is at least
 * `ring->rotl_scratch_limbs` u64.  out may alias in.  scratch is wiped before
 * return.
 */
void ichor_gf2x_rotl_var(const ichor_gf2x_ring *ring, uint64_t *out,
                         const uint64_t *in, uint32_t k, uint64_t *scratch);

/*
 * r = a^{-1} in the unit group, via Itoh-Tsujii.  REQUIRES ord_p(2) = p - 1.
 * Keygen-only (not a hot path).  `scratch` is a caller buffer of at least
 * `ring->inv_scratch_limbs` u64; it is wiped before return (it holds powers of
 * the secret input).  Returns 0 on success, -1 if a is not a unit (a * r != 1;
 * the caller resamples).  r and a are `ring->limbs` u64 and must not alias.
 */
int ichor_gf2x_inv(const ichor_gf2x_ring *ring, uint64_t *r, const uint64_t *a,
                   uint64_t *scratch);

/*
 * Maximum support weight ichor_gf2x_scatter accepts.  It sizes the internal
 * per-index scratch; every shipped QC-MDPC set stays well under it (the largest
 * weight across syndrome's (t, v) and the opener's t is 261).  A caller passing
 * w greater than this gets a zeroed block (the fixed-weight samplers already
 * bound w below their own ceilings, so this is a defensive floor, not a path).
 */
#define ICHOR_GF2X_MAX_WEIGHT 512u

/*
 * Obliviously scatter a fixed-weight support into one dense ring element.
 * `block` (`block_bytes`, little-endian LSB-first) receives the `span`-bit
 * indicator of the `w` support positions in `idx`: for each k, the bit at
 * position `idx[k] - base` is set iff that difference lies in [0, span).  An
 * index outside [base, base + span) (a different circulant block) localizes to
 * a word index at or beyond the covered range and is never written, so the same
 * global support list can be scattered block-by-block by varying `base`.
 *
 * Constant-time over the secret support: the loop bounds and every write
 * address are public (functions of span / block_bytes only); only the written
 * bit VALUES depend on `idx`.  The per-index scratch is wiped before return.
 * Precondition: w <= ICHOR_GF2X_MAX_WEIGHT (else `block` is zeroed and no
 * scatter is performed).  span is typically the ring prime p and block_bytes
 * ceil(span / 8).
 *
 * Only positions [0, span) are meaningful.  When span is not a multiple of 8,
 * an index from an adjacent block (idx - base in [span, 8*block_bytes)) may set
 * a pad bit in the top byte; this is why callers scattering block-by-block feed
 * the result through ichor_gf2x_load, which masks to the canonical p-bit form.
 * Do not consume the raw bytes above position span without that canonicalization.
 */
void ichor_gf2x_scatter(uint8_t *block, size_t block_bytes, const uint32_t *idx,
                        uint32_t w, uint32_t base, uint32_t span);

#endif /* ICHOR_GF2X_H */
