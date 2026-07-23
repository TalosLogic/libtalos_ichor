/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_aesdm.c - Tests for the Davies-Meyer (AES-128) compression
 * primitive.
 *
 * AES-DM existed in libtalos_voleith only as an in-circuit gadget plus
 * Merkle-framed software references (leaf_hash_dm_ref / inode); there
 * was no bare-primitive KAT to copy.  These tests mirror test_hirose.c:
 * an independent in-test reference, aliasing and avalanche checks, and a
 * FIPS-197 anchor for the output formula.
 *
 * Tests:
 *   1: Output matches the spec formula H_out = AES_M(H_in) XOR H_in,
 *      computed independently via ichor_aes_encrypt.
 *   2: In-place call (H_out == H_in) matches a non-aliasing call.
 *   3: Changing M (the cipher key) changes the output.
 *   4: Changing H_in (the plaintext/chaining value) changes the output.
 *   5: H_out matches a value derived by hand from FIPS 197 Appendix C.1
 *      (AES-128 KAT) - third-party anchor for the output formula.  No
 *      canonical AES-DM KAT exists in NIST/ISO/IETF publications, so
 *      this is the strongest external grounding available, exactly as
 *      for the Hirose primitive (test_hirose.c test 7).
 */

#include "aesdm.h"
#include "aes.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int test_count = 0;
static int pass_count = 0;

static void
check(const char *name, int cond)
{
    test_count++;
    if (cond)
        pass_count++;
    else
        printf("  FAIL: %s\n", name);
}

/*
 * In-test reference: H_out = AES_M(H_in) XOR H_in, computed via the
 * ichor AES API independently of ichor_aesdm_iteration.
 */
static void
aesdm_iteration_ref(const uint8_t H_in[16], const uint8_t M[16],
                    uint8_t H_out[16])
{
    ichor_aes_ctx_t ctx;
    uint8_t ct[16];
    int i;

    ichor_aes_key_expand(&ctx, M, 128);
    ichor_aes_encrypt(&ctx, ct, H_in);
    for (i = 0; i < 16; i++)
        H_out[i] = ct[i] ^ H_in[i];
    ichor_aes_ctx_clear(&ctx);
}

/* Standard test vectors used across cases. */
static const uint8_t H_IN[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                 0xcc, 0xdd, 0xee, 0xff};
static const uint8_t M_IN[16] = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
                                 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67,
                                 0x89, 0xab, 0xcd, 0xef};

static void
test_matches_reference(void)
{
    uint8_t out_ref[16];
    uint8_t out[16];

    aesdm_iteration_ref(H_IN, M_IN, out_ref);
    ichor_aesdm_iteration(H_IN, M_IN, out);

    check("AES-DM: output matches independent reference",
          memcmp(out, out_ref, 16) == 0);
}

static void
test_in_place_safe(void)
{
    uint8_t out_ref[16];
    uint8_t alias[16];

    ichor_aesdm_iteration(H_IN, M_IN, out_ref);

    /* H_out aliases H_in. */
    memcpy(alias, H_IN, 16);
    ichor_aesdm_iteration(alias, M_IN, alias);

    check("AES-DM: in-place H_out=H_in yields the same output",
          memcmp(alias, out_ref, 16) == 0);
}

static void
test_m_changes_output(void)
{
    uint8_t out_a[16];
    uint8_t out_b[16];
    uint8_t M_alt[16];

    ichor_aesdm_iteration(H_IN, M_IN, out_a);

    memcpy(M_alt, M_IN, 16);
    M_alt[7] ^= 0x80;
    ichor_aesdm_iteration(H_IN, M_alt, out_b);

    check("AES-DM: output changes when M (key) changes",
          memcmp(out_a, out_b, 16) != 0);
}

static void
test_h_changes_output(void)
{
    uint8_t out_a[16];
    uint8_t out_b[16];
    uint8_t H_alt[16];

    ichor_aesdm_iteration(H_IN, M_IN, out_a);

    memcpy(H_alt, H_IN, 16);
    H_alt[0] ^= 0x01;
    ichor_aesdm_iteration(H_alt, M_IN, out_b);

    check("AES-DM: output changes when H_in (plaintext) changes",
          memcmp(out_a, out_b, 16) != 0);
}

/*
 * Test 5: output anchored to FIPS 197 Appendix C.1 (AES-128 KAT).
 *
 * Construction:
 *   M_FIPS  = K_FIPS = 00 01 02 03 04 05 06 07
 *                      08 09 0a 0b 0c 0d 0e 0f
 *   H_FIPS  = P_FIPS = 00 11 22 33 44 55 66 77
 *                      88 99 aa bb cc dd ee ff
 *
 * By FIPS 197 Appendix C.1:
 *   AES_K(P_FIPS) = C_FIPS = 69 c4 e0 d8 6a 7b 04 30
 *                            d8 cd b7 80 70 b4 c5 5a
 *
 * Davies-Meyer gives H_out = AES_M(H_in) XOR H_in, so:
 *   OUT_EXPECTED = C_FIPS XOR P_FIPS
 *                = 69 d5 c2 eb 2e 2e 62 47
 *                  50 54 1d 3b bc 69 2b a5
 *
 * Any reader can verify OUT_EXPECTED independently from FIPS 197.
 * Matching it confirms both the "message block as cipher key"
 * assignment and the "AES_M(H_in) XOR H_in" output formula.
 */
static void
test_output_matches_fips197_c1(void)
{
    static const uint8_t K_FIPS[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                       0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                       0x0c, 0x0d, 0x0e, 0x0f};
    static const uint8_t P_FIPS[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                       0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                       0xcc, 0xdd, 0xee, 0xff};
    static const uint8_t OUT_EXPECTED[16] = {0x69, 0xd5, 0xc2, 0xeb, 0x2e, 0x2e,
                                             0x62, 0x47, 0x50, 0x54, 0x1d, 0x3b,
                                             0xbc, 0x69, 0x2b, 0xa5};
    uint8_t out[16];

    ichor_aesdm_iteration(P_FIPS, K_FIPS, out);
    check("AES-DM: output matches FIPS 197 C.1 (C_FIPS XOR P_FIPS)",
          memcmp(out, OUT_EXPECTED, 16) == 0);
}

/*
 * Independent reference for the incremental fixed-input hash: seed the
 * chaining value with the IV, run each full 16-byte block through the bare
 * Davies-Meyer iteration, and, only if a partial block remains, zero-fill it
 * and run one more iteration.  An exact-block-multiple message (including the
 * empty message) adds no padding block, matching ichor_aesdm_finalize_fixed.
 */
static void
aesdm_hash_ref(const uint8_t iv[16], const uint8_t *data, size_t len,
               uint8_t out[16])
{
    uint8_t h[16];
    size_t off = 0;

    memcpy(h, iv, 16);
    while (len - off >= 16) {
        ichor_aesdm_iteration(h, data + off, h);
        off += 16;
    }
    if (off < len) {
        uint8_t last[16];
        memset(last, 0, sizeof(last));
        memcpy(last, data + off, len - off);
        ichor_aesdm_iteration(h, last, h);
    }
    memcpy(out, h, 16);
}

static const uint8_t IV_DS[16] = {0xa5, 0x5a, 0x00, 0xff, 0x11, 0x22,
                                  0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                  0x99, 0xaa, 0xbb, 0xcc};

static void
test_incremental_matches_reference(void)
{
    static const size_t lens[] = {0, 1, 15, 16, 17, 31, 32, 33, 48, 70};
    uint8_t msg[70];
    size_t li;
    int all_ok = 1;

    for (li = 0; li < sizeof(msg); li++)
        msg[li] = (uint8_t)(0x13 * (li + 1));

    for (li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
        ichor_aesdm_ctx_t ctx;
        uint8_t got[16], ref[16];

        ichor_aesdm_init_iv(&ctx, IV_DS);
        ichor_aesdm_absorb(&ctx, msg, lens[li]);
        ichor_aesdm_finalize_fixed(&ctx, got);
        ichor_aesdm_clear(&ctx);

        aesdm_hash_ref(IV_DS, msg, lens[li], ref);
        if (memcmp(got, ref, 16) != 0)
            all_ok = 0;
    }
    check("AES-DM incremental: matches reference across lengths", all_ok);
}

static void
test_incremental_split_absorb(void)
{
    static const uint8_t msg[40] = {0};
    ichor_aesdm_ctx_t ctx;
    uint8_t whole[16], split[16];
    size_t cut;
    int all_ok = 1;

    ichor_aesdm_init_iv(&ctx, IV_DS);
    ichor_aesdm_absorb(&ctx, msg, sizeof(msg));
    ichor_aesdm_finalize_fixed(&ctx, whole);
    ichor_aesdm_clear(&ctx);

    /* Absorbing in two pieces at every cut point must match one absorb. */
    for (cut = 0; cut <= sizeof(msg); cut++) {
        ichor_aesdm_init_iv(&ctx, IV_DS);
        ichor_aesdm_absorb(&ctx, msg, cut);
        ichor_aesdm_absorb(&ctx, msg + cut, sizeof(msg) - cut);
        ichor_aesdm_finalize_fixed(&ctx, split);
        ichor_aesdm_clear(&ctx);
        if (memcmp(split, whole, 16) != 0)
            all_ok = 0;
    }
    check("AES-DM incremental: split absorb equals single absorb", all_ok);
}

static void
test_incremental_empty_is_iv(void)
{
    ichor_aesdm_ctx_t ctx;
    uint8_t out[16];

    ichor_aesdm_init_iv(&ctx, IV_DS);
    ichor_aesdm_finalize_fixed(&ctx, out);
    ichor_aesdm_clear(&ctx);
    check("AES-DM incremental: empty message returns the IV unchanged",
          memcmp(out, IV_DS, 16) == 0);
}

int
main(void)
{
    printf("test_aesdm: Davies-Meyer (AES-128) compression primitive\n");

    test_matches_reference();
    test_in_place_safe();
    test_m_changes_output();
    test_h_changes_output();
    test_output_matches_fips197_c1();
    test_incremental_matches_reference();
    test_incremental_split_absorb();
    test_incremental_empty_is_iv();

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
