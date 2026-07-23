/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_aes_ctr.c - Tests for ichor_aes_ctr, the nonce/counter-split CTR
 * keystream generator.
 *
 * The counter block is nonce[0..11] || be32(ctr0 + b); only the low 4
 * bytes increment, and the call fails closed (returns -1) when the block
 * count would carry past byte 12 into the nonce.
 *
 * External anchor: NIST SP 800-38A appendix F.5 CTR-AES vectors
 * (F.5.1/128, F.5.3/192, F.5.5/256).  Those vectors use a 128-bit counter
 * that starts at f0f1..feff and spans only four blocks, so the increment
 * never carries above the low 4 bytes; the split form reproduces them
 * exactly with nonce = f0f1f2f3f4f5f6f7f8f9fafb and ctr0 = 0xfcfdfeff.
 *
 * Tests:
 *   1-3: F.5.1/F.5.3/F.5.5 known-answer, both encrypt (in = plaintext ->
 *        ciphertext) and raw keystream (in = NULL, keystream XOR plaintext
 *        == ciphertext).
 *   4:   independent reference sweep across lengths (including a starting
 *        counter chosen so the low-4-byte increment carries across a byte
 *        boundary), validating the branchless big-endian increment.
 *   5:   partial final block truncation matches the head of a full-block run.
 *   6:   in-place (out == in) matches a non-aliasing call.
 *   7:   nonce is untouched: keystream depends on the nonce region and the
 *        counter never bleeds into it.
 *   8:   usage cap: reject exactly when ctr0 + ceil(len/16) > 2^32, accept
 *        at the boundary, and leave out unwritten on rejection.
 */

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

/* The NIST F.5 vectors all share this 128-bit initial counter block; the
 * split form uses its high 12 bytes as the nonce and low 4 as ctr0. */
static const uint8_t NIST_NONCE[12] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
                                       0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb};
static const uint32_t NIST_CTR0 = 0xfcfdfeffu;

/* Common 4-block plaintext (SP 800-38A F.5). */
static const uint8_t PT[64] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
    0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
    0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
    0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
    0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
    0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

/* F.5.1 CTR-AES128 */
static const uint8_t KEY128[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                   0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                   0x09, 0xcf, 0x4f, 0x3c};
static const uint8_t CT128[64] = {
    0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68,
    0x64, 0x99, 0x0d, 0xb6, 0xce, 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70,
    0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff, 0x5a,
    0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02,
    0x0d, 0xb0, 0x3e, 0xab, 0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03,
    0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee};

/* F.5.3 CTR-AES192 */
static const uint8_t KEY192[24] = {
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
    0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
static const uint8_t CT192[64] = {
    0x1a, 0xbc, 0x93, 0x24, 0x17, 0x52, 0x1c, 0xa2, 0x4f, 0x2b, 0x04,
    0x59, 0xfe, 0x7e, 0x6e, 0x0b, 0x09, 0x03, 0x39, 0xec, 0x0a, 0xa6,
    0xfa, 0xef, 0xd5, 0xcc, 0xc2, 0xc6, 0xf4, 0xce, 0x8e, 0x94, 0x1e,
    0x36, 0xb2, 0x6b, 0xd1, 0xeb, 0xc6, 0x70, 0xd1, 0xbd, 0x1d, 0x66,
    0x56, 0x20, 0xab, 0xf7, 0x4f, 0x78, 0xa7, 0xf6, 0xd2, 0x98, 0x09,
    0x58, 0x5a, 0x97, 0xda, 0xec, 0x58, 0xc6, 0xb0, 0x50};

/* F.5.5 CTR-AES256 */
static const uint8_t KEY256[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae,
    0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61,
    0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
static const uint8_t CT256[64] = {
    0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5,
    0x04, 0xbb, 0xf3, 0xd2, 0x28, 0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62,
    0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5, 0x2b,
    0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba,
    0x2d, 0x84, 0x98, 0x8d, 0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad,
    0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6};

static void
run_nist_case(const char *label, const uint8_t *key, int key_bits,
              const uint8_t ct[64])
{
    ichor_aes_ctx_t ctx;
    uint8_t buf[64];
    uint8_t ks[64];
    char name[64];
    int i, rc;

    ichor_aes_key_expand(&ctx, key, key_bits);

    /* Encrypt: in = plaintext -> ciphertext. */
    rc = ichor_aes_ctr(&ctx, buf, PT, 64, NIST_NONCE, NIST_CTR0);
    snprintf(name, sizeof(name), "%s encrypt rc", label);
    check(name, rc == 0);
    snprintf(name, sizeof(name), "%s encrypt == KAT ciphertext", label);
    check(name, memcmp(buf, ct, 64) == 0);

    /* Raw keystream: in = NULL, then keystream XOR plaintext == ciphertext. */
    rc = ichor_aes_ctr(&ctx, ks, NULL, 64, NIST_NONCE, NIST_CTR0);
    snprintf(name, sizeof(name), "%s keystream rc", label);
    check(name, rc == 0);
    for (i = 0; i < 64; i++)
        buf[i] = ks[i] ^ PT[i];
    snprintf(name, sizeof(name), "%s keystream XOR pt == KAT ciphertext",
             label);
    check(name, memcmp(buf, ct, 64) == 0);

    ichor_aes_ctx_clear(&ctx);
}

/*
 * Independent reference: build each counter block as nonce || be32(ctr0 + b)
 * with 64-bit arithmetic (so a byte-boundary carry in the low 4 bytes is
 * modelled directly) and encrypt it with the single-block API.
 */
static void
ctr_ref(const ichor_aes_ctx_t *ctx, uint8_t *out, size_t len,
        const uint8_t nonce[12], uint32_t ctr0)
{
    size_t off = 0;
    uint64_t b = 0;

    while (off < len) {
        uint8_t blk[16], ks[16];
        uint32_t c = (uint32_t)(ctr0 + b);
        size_t take = (len - off < 16) ? (len - off) : 16;
        size_t j;

        memcpy(blk, nonce, 12);
        blk[12] = (uint8_t)(c >> 24);
        blk[13] = (uint8_t)(c >> 16);
        blk[14] = (uint8_t)(c >> 8);
        blk[15] = (uint8_t)(c);
        ichor_aes_encrypt(ctx, ks, blk);
        for (j = 0; j < take; j++)
            out[off + j] = ks[j];
        off += take;
        b++;
    }
}

static void
test_reference_sweep(void)
{
    ichor_aes_ctx_t ctx;
    /* Start just below a byte boundary so the increment carries 0x..ff -> 0x..
     * across bytes 15->14 within the low 4 counter bytes. */
    const uint32_t ctr0 = 0x0000fffeu;
    static const size_t lens[] = {1, 15, 16, 17, 31, 32, 33, 48, 64, 80, 129};
    size_t li;

    ichor_aes_key_expand(&ctx, KEY128, 128);

    for (li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
        uint8_t got[160], ref[160];
        char name[48];
        int rc;

        rc = ichor_aes_ctr(&ctx, got, NULL, lens[li], NIST_NONCE, ctr0);
        ctr_ref(&ctx, ref, lens[li], NIST_NONCE, ctr0);
        snprintf(name, sizeof(name), "reference sweep len=%zu", lens[li]);
        check(name, rc == 0 && memcmp(got, ref, lens[li]) == 0);
    }

    ichor_aes_ctx_clear(&ctx);
}

static void
test_partial_truncation(void)
{
    ichor_aes_ctx_t ctx;
    uint8_t full[64], part[37];
    int rc1, rc2;

    ichor_aes_key_expand(&ctx, KEY128, 128);
    rc1 = ichor_aes_ctr(&ctx, full, NULL, 64, NIST_NONCE, NIST_CTR0);
    rc2 = ichor_aes_ctr(&ctx, part, NULL, 37, NIST_NONCE, NIST_CTR0);
    check("partial run truncates cleanly",
          rc1 == 0 && rc2 == 0 && memcmp(part, full, 37) == 0);
    ichor_aes_ctx_clear(&ctx);
}

static void
test_in_place(void)
{
    ichor_aes_ctx_t ctx;
    uint8_t sep[64], inplace[64];
    int rc1, rc2;

    ichor_aes_key_expand(&ctx, KEY128, 128);
    rc1 = ichor_aes_ctr(&ctx, sep, PT, 64, NIST_NONCE, NIST_CTR0);
    memcpy(inplace, PT, 64);
    rc2 = ichor_aes_ctr(&ctx, inplace, inplace, 64, NIST_NONCE, NIST_CTR0);
    check("in-place (out == in) matches non-aliasing",
          rc1 == 0 && rc2 == 0 && memcmp(sep, inplace, 64) == 0);
    ichor_aes_ctx_clear(&ctx);
}

static void
test_nonce_binding(void)
{
    ichor_aes_ctx_t ctx;
    uint8_t a[16], b[16];
    uint8_t nonce2[12];
    int rc1, rc2;

    ichor_aes_key_expand(&ctx, KEY128, 128);
    rc1 = ichor_aes_ctr(&ctx, a, NULL, 16, NIST_NONCE, NIST_CTR0);
    memcpy(nonce2, NIST_NONCE, 12);
    nonce2[0] ^= 0x01; /* flip a nonce bit the counter can never reach */
    rc2 = ichor_aes_ctr(&ctx, b, NULL, 16, nonce2, NIST_CTR0);
    check("distinct nonce yields distinct keystream",
          rc1 == 0 && rc2 == 0 && memcmp(a, b, 16) != 0);
    ichor_aes_ctx_clear(&ctx);
}

static void
test_usage_cap(void)
{
    ichor_aes_ctx_t ctx;
    uint8_t out[32];
    int rc;

    ichor_aes_key_expand(&ctx, KEY128, 128);

    /* ctr0 = 2^32 - 1: one block fits exactly (sum == 2^32), two overflow. */
    rc = ichor_aes_ctr(&ctx, out, NULL, 16, NIST_NONCE, 0xffffffffu);
    check("cap: last counter value accepted (1 block, sum == 2^32)", rc == 0);

    /* Sentinel the buffer so a rejected call is observably non-writing. */
    memset(out, 0xa5, sizeof(out));
    rc = ichor_aes_ctr(&ctx, out, NULL, 32, NIST_NONCE, 0xffffffffu);
    check("cap: overflow rejected (2 blocks, sum == 2^32 + 1)", rc == -1);
    {
        int untouched = 1, i;
        for (i = 0; i < 32; i++)
            if (out[i] != 0xa5)
                untouched = 0;
        check("cap: rejected call leaves out unwritten", untouched);
    }

    /* ctr0 = 0: the full 2^32-block budget is accepted at the boundary; one
     * block past it (len forcing 2^32 + 1 blocks) would need ~64 GiB, which is
     * not allocatable here, so the boundary is covered by the ctr0-high case. */
    rc = ichor_aes_ctr(&ctx, out, NULL, 16, NIST_NONCE, 0u);
    check("cap: ctr0 = 0 single block accepted", rc == 0);

    /*
     * Boundary correctness: the last accepted counter value must be the real
     * 0xffffffff, not a prematurely wrapped 0.  The single boundary block must
     * equal a direct AES(nonce || be32(0xffffffff)) and differ from the
     * nonce||0 block.
     */
    {
        uint8_t blk[16], ks_direct[16], ks_ctr[16], ks_zero[16];
        int rc_b;

        memcpy(blk, NIST_NONCE, 12);
        blk[12] = 0xff;
        blk[13] = 0xff;
        blk[14] = 0xff;
        blk[15] = 0xff;
        ichor_aes_encrypt(&ctx, ks_direct, blk);
        memcpy(blk + 12, "\0\0\0\0", 4);
        ichor_aes_encrypt(&ctx, ks_zero, blk);

        rc_b = ichor_aes_ctr(&ctx, ks_ctr, NULL, 16, NIST_NONCE, 0xffffffffu);
        check("cap: boundary block uses counter 0xffffffff (no premature wrap)",
              rc_b == 0 && memcmp(ks_ctr, ks_direct, 16) == 0 &&
                  memcmp(ks_ctr, ks_zero, 16) != 0);
    }

    /*
     * The reuse the cap prevents: the rejected 2-block call at ctr0 =
     * 0xffffffff would have emitted a second block under the wrapped counter 0,
     * i.e. AES(nonce || be32(0)) -- identical to the ctr0 = 0 block-0
     * keystream.  Show that collision explicitly so the rejection's purpose is
     * anchored.
     */
    {
        uint8_t blk0[16], ks_wrap[16], ks_ctr0[16];
        int rc_z;

        memcpy(blk0, NIST_NONCE, 12);
        blk0[12] = 0;
        blk0[13] = 0;
        blk0[14] = 0;
        blk0[15] = 0;
        ichor_aes_encrypt(&ctx, ks_wrap, blk0);

        rc_z = ichor_aes_ctr(&ctx, ks_ctr0, NULL, 16, NIST_NONCE, 0u);
        check("cap: wrapped 2nd block would collide with ctr0=0 keystream",
              rc_z == 0 && memcmp(ks_ctr0, ks_wrap, 16) == 0);
    }

    ichor_aes_ctx_clear(&ctx);
}

int
main(void)
{
    printf("test_aes_ctr: nonce/counter-split AES-CTR keystream\n");

    run_nist_case("F.5.1/128", KEY128, 128, CT128);
    run_nist_case("F.5.3/192", KEY192, 192, CT192);
    run_nist_case("F.5.5/256", KEY256, 256, CT256);
    test_reference_sweep();
    test_partial_truncation();
    test_in_place();
    test_nonce_binding();
    test_usage_cap();

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
