/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * bench_grostl.c - throughput of the Groestl permutation, as a full hash and
 * as the fixed-input single-compression node hash.
 *
 * The AES-NI backend was reworked in place from SubBytes-only SIMD to a full
 * SIMD round; both revisions report backend "aesni", so the only way to see
 * that speedup is to run this program against the two git revisions (see
 * run_ab.sh).  ICHOR_FORCE_BACKEND=grostl:soft pins the pure-C reference on
 * either revision for a scalar baseline.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ichor/grostl.h>

#include "bench_util.h"

#define GROSTL_MSG_BYTES 4096
#define GROSTL_HASH_ITERS (1u << 11)
#define GROSTL_NODE_ITERS (1u << 14)

int
main(void)
{
    uint8_t msg[GROSTL_MSG_BYTES];
    uint8_t iv256[64], blk256[64], out256[32];
    uint8_t iv512[128], blk512[128], out512[64];
    uint8_t digest256[32], digest512[64];
    bench_stats_t s;
    volatile uint8_t sink = 0;

    for (size_t i = 0; i < sizeof(msg); i++)
        msg[i] = (uint8_t)i;
    for (int i = 0; i < 64; i++) {
        iv256[i] = (uint8_t)(0x10 + i);
        blk256[i] = (uint8_t)(0x80 + i);
    }
    for (int i = 0; i < 128; i++) {
        iv512[i] = (uint8_t)(0x20 + i);
        blk512[i] = (uint8_t)(0x90 + i);
    }

    printf("Groestl  backend=%s\n", ichor_grostl_backend_name());

    BENCH_MEASURE(s, BENCH_SAMPLES, BENCH_WARMUP, GROSTL_HASH_ITERS, {
        ichor_grostl256(digest256, msg, sizeof(msg));
        sink ^= digest256[0];
    });
    bench_print_mbps("grostl256 hash", s, (double)GROSTL_MSG_BYTES);

    BENCH_MEASURE(s, BENCH_SAMPLES, BENCH_WARMUP, GROSTL_HASH_ITERS, {
        ichor_grostl512(digest512, msg, sizeof(msg));
        sink ^= digest512[0];
    });
    bench_print_mbps("grostl512 hash", s, (double)GROSTL_MSG_BYTES);

    BENCH_MEASURE(s, BENCH_SAMPLES, BENCH_WARMUP, GROSTL_NODE_ITERS, {
        ichor_grostl256_compress_node(iv256, blk256, out256);
        sink ^= out256[0];
    });
    bench_print_opns("compress_node256", s, 1.0);

    BENCH_MEASURE(s, BENCH_SAMPLES, BENCH_WARMUP, GROSTL_NODE_ITERS, {
        ichor_grostl512_compress_node(iv512, blk512, out512);
        sink ^= out512[0];
    });
    bench_print_opns("compress_node512", s, 1.0);

    (void)sink;
    return 0;
}
