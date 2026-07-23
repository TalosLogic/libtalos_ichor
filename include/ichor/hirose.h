/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * hirose.h - Hirose double-block-length compression function over
 * AES-256 (Hirose, FSE 2006).
 *
 * Implements one iteration of the compression `f` only.  The framing
 * built on top of `f` - fixed IV, the message-padding rule, the
 * multi-block absorb, and any domain-separation constants - is
 * deliberately left to the consumer.  Two consumers exist in the talos
 * family: the in-circuit Merkle / opener-KDF gadgets in libtalos_voleith,
 * and the software opener-KDF in libtalos_syndrome (Argus).  Keeping the
 * bare primitive here lets one byte-exact reference serve both sides of
 * the circuit/software boundary, and prevents accidental use as a
 * general-purpose hash.
 *
 * The primitive is intentionally the naive two-encrypt form (one key
 * schedule plus two AES-256 encrypts per iteration), with no
 * key-schedule sharing.  Sharing is a gate-count optimization in the
 * circuit version; in software it would only complicate the primitive
 * without changing the output.  Routing both encryptions through
 * ichor_aes_encrypt lets this function serve as an independent oracle
 * for the circuit's KS-shared form: any divergence in circuit output
 * points to a circuit bug, not a primitive bug.
 */

#ifndef ICHOR_HIROSE_H
#define ICHOR_HIROSE_H

#include <stdint.h>
#include <stddef.h>

/*
 * ichor_hirose_iteration - one Hirose compression iteration `f`.
 *
 * Given a 256-bit chaining value (G, H), a 128-bit message block M,
 * and a 128-bit nonzero tweak constant `c`, computes:
 *
 *     K       = H || M                    (256-bit AES-256 key)
 *     G_out   = AES_K(G)        XOR G
 *     H_out   = AES_K(G XOR c)  XOR G XOR c
 *
 * The same key K is used for both encryptions (Hirose's defining
 * property).  `c` MUST be nonzero - a zero `c` collapses the two
 * encryptions to the same call and breaks the construction's
 * collision-resistance bound.
 *
 * G, H, M, c_const: 16-byte input blocks.
 * G_out, H_out:     16-byte output blocks (may alias any input).
 *
 * Constant-time with respect to all four inputs (provided the AES
 * backend is constant-time: AES-NI, ARMv8 Crypto, or bitsliced).
 */
void ichor_hirose_iteration(const uint8_t G[16], const uint8_t H[16],
                            const uint8_t M[16], const uint8_t c_const[16],
                            uint8_t G_out[16], uint8_t H_out[16]);

#endif /* ICHOR_HIROSE_H */
