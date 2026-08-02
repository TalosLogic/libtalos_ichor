/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * util.h - Security-critical utility functions
 *
 * Provides:
 *   ichor_secure_zero   - zero memory in a way the compiler cannot elide
 *   ichor_const_memcmp  - constant-time byte comparison (no data-dependent branches)
 *   ichor_ct_mask64     - opaque all-ones/all-zeros mask from a secret bit
 *   ichor_ct_select64   - constant-time select between two 64-bit words
 */

#ifndef ICHOR_UTIL_H
#define ICHOR_UTIL_H

#include <stddef.h>
#include <stdint.h>

/*
 * Zero len bytes at ptr.  The zeroing is guaranteed not to be optimized away
 * by the compiler, making it safe for erasing key material and witness data.
 *
 * Uses explicit_bzero(3) on POSIX platforms (Linux glibc ≥ 2.25, macOS,
 * BSDs) and a volatile-pointer loop elsewhere.
 */
void ichor_secure_zero(void *ptr, size_t len);

/*
 * Compare len bytes at a and b in constant time.
 *
 * Returns 0 if all bytes are equal, non-zero otherwise.
 * Always reads all len bytes regardless of content - no early exit.
 *
 * Use instead of memcmp() wherever the inputs may be secret (e.g. comparing
 * commitment hashes, challenge values, MACs).
 */
int ichor_const_memcmp(const void *a, const void *b, size_t len);

/*
 * Constant-time selection primitives.
 *
 * ichor_ct_mask64(bit) returns an all-ones mask (0xFFFFFFFFFFFFFFFF) when the
 * low bit of `bit` is 1, and all-zeros when it is 0.  The value is routed
 * through a volatile so the compiler cannot prove it is one of {0, ~0} and
 * lower a dependent select into a branch.  This is not hypothetical: at -O3,
 * clang was observed rewriting the open-coded idiom
 *
 *     x = (a & mask) | (b & ~mask);
 *
 * into a secret-dependent branch (skip the store when the bit is 0), which is
 * a timing side channel.  Form the mask once with this helper, then blend with
 * ichor_ct_select64 or the open-coded AND/OR; the blend stays branchless and
 * vectorizable because `mask` is opaque to the caller's optimizer.  In a hot
 * loop, call ichor_ct_mask64 once outside the loop and open-code the blend
 * inside, so there is no per-element call.
 *
 * ichor_ct_select64(mask, a, b) returns a if `mask` is all-ones and b if it is
 * all-zeros: (a & mask) | (b & ~mask).  Pass a mask produced by
 * ichor_ct_mask64; any other value gives a bitwise mix, not a select.
 *
 * The constant-time guarantee is a property of the emitted machine code, not
 * the C source, so it must be re-checked in the disassembly after any compiler
 * or flag change.  In particular, the opacity relies on this helper staying
 * out-of-line: link-time / whole-program optimization (`-flto`) can inline it
 * into the caller, expose the volatile's value to the optimizer, and
 * reintroduce the secret-dependent branch.  Do not enable LTO without
 * re-verifying in the disassembly and re-running the dudect suite.
 */
uint64_t ichor_ct_mask64(uint64_t bit);
uint64_t ichor_ct_select64(uint64_t mask, uint64_t a, uint64_t b);

/*
 * Pack `count` fixed-width integers into a byte buffer, LSB-first.
 *
 * Each value contributes exactly width_bits bits.  Bit 0 of values[0]
 * lands at bit 0 of dst[0] (the least significant bit of the first byte);
 * successive bits fill toward the most significant bit of each byte and
 * then into the next byte.  Only the low width_bits of each value are
 * used; any higher bits are ignored (no range check - a check would be
 * data-dependent).  The written region is ceil(count * width_bits / 8)
 * bytes; dst is first zeroed over dst_len, so the tail past the packed
 * bits is deterministic zero padding.
 *
 * The access pattern depends only on count and width_bits (public), never
 * on the value contents, so the routine is constant-time with respect to
 * the packed values - suitable for serializing secret data such as the
 * support of a fixed-weight error vector.
 *
 * Two element widths are provided; use the narrowest that holds your field
 * so the source array itself stays compact (no widening copy):
 *   _le16  values are uint16_t, width_bits 1..16
 *   _le32  values are uint32_t, width_bits 1..32
 * (No uint64_t variant: nothing in the talos software needs > 32-bit
 * fields yet; it is a mechanical addition if that changes.)
 *
 * Returns 0 on success, -1 if width_bits is out of range for the element
 * type or dst_len is smaller than ceil(count * width_bits / 8) bytes.
 */
int ichor_bitpack_le16(uint8_t *dst, size_t dst_len, const uint16_t *values,
                       size_t count, uint32_t width_bits);
int ichor_bitpack_le32(uint8_t *dst, size_t dst_len, const uint32_t *values,
                       size_t count, uint32_t width_bits);

/*
 * Inverse of ichor_bitpack_le{16,32}: recover `count` width_bits-wide
 * integers from the LSB-first packing in src, each zero-extended into the
 * element type.  Same constant-time property: the access pattern depends
 * only on count and width_bits.
 *
 * Returns 0 on success, -1 if width_bits is out of range for the element
 * type or src_len is smaller than ceil(count * width_bits / 8) bytes.
 */
int ichor_bitunpack_le16(uint16_t *values, size_t count, uint32_t width_bits,
                         const uint8_t *src, size_t src_len);
int ichor_bitunpack_le32(uint32_t *values, size_t count, uint32_t width_bits,
                         const uint8_t *src, size_t src_len);

#endif /* ICHOR_UTIL_H */
