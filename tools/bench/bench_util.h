/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * bench_util.h - tiny standalone wall-clock benchmarking helpers for the
 * ichor micro-benchmark harness.
 *
 * This header has no ichor dependency: it only measures and reports, so the
 * same bench programs compile against any revision of ichor whose public API
 * they touch.  That is what lets run_ab.sh drop this suite onto an older
 * checkout and produce a true before/after number.
 *
 * Methodology note: timing noise on a loaded OS is one-sided slow
 * (preemption, cache misses, page faults, and frequency dips only ever make
 * a sample slower).  So the minimum is the cleanest estimate of intrinsic
 * cost and the median is the typical run; we never trim the fast tail.  Each
 * program runs a few warmup samples first and discards them.
 *
 * Requires _POSIX_C_SOURCE >= 200809L defined before any include: for
 * clock_gettime / CLOCK_MONOTONIC (POSIX.1b), and so that strict libc
 * implementations (Apple) still expose the C99 snprintf some bench programs
 * use (glibc leaks it in at the older level, Apple libc does not).
 */

#ifndef ICHOR_BENCH_UTIL_H
#define ICHOR_BENCH_UTIL_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define BENCH_SAMPLES 50
#define BENCH_WARMUP 5

static inline uint64_t
bench_now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
}

typedef struct {
    double min;
    double median;
    double mean;
    double max;
    size_t n;
} bench_stats_t;

static int
bench_cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* Computes stats over `n` per-iteration millisecond samples.  Sorts in place. */
static inline bench_stats_t
bench_compute(double *samples, size_t n)
{
    bench_stats_t s = {0, 0, 0, 0, n};
    double sum = 0;

    if (n == 0)
        return s;

    qsort(samples, n, sizeof(double), bench_cmp_double);

    for (size_t i = 0; i < n; i++)
        sum += samples[i];

    s.min = samples[0];
    s.max = samples[n - 1];
    s.mean = sum / (double)n;
    s.median =
        (n & 1u) ? samples[n / 2] : 0.5 * (samples[n / 2 - 1] + samples[n / 2]);
    return s;
}

/*
 * Time `stmt` run `iters` times per sample, collecting `nsamp` samples after
 * `warmup` discarded ones, and write the per-iteration millisecond stats into
 * `out`.  `stmt` must touch a volatile sink so the compiler cannot elide it.
 */
#define BENCH_MEASURE(out, nsamp, warmup, iters, stmt)                         \
    do {                                                                       \
        size_t __ns = (size_t)(nsamp);                                         \
        size_t __it = (size_t)(iters);                                         \
        double *__samp = malloc(__ns * sizeof(double));                        \
        if (__samp == NULL) {                                                  \
            perror("malloc");                                                  \
            exit(1);                                                           \
        }                                                                      \
        for (size_t __w = 0; __w < (size_t)(warmup); __w++)                    \
            for (size_t __i = 0; __i < __it; __i++) {                          \
                stmt;                                                          \
            }                                                                  \
        for (size_t __k = 0; __k < __ns; __k++) {                              \
            uint64_t __t0 = bench_now_ns();                                    \
            for (size_t __i = 0; __i < __it; __i++) {                          \
                stmt;                                                          \
            }                                                                  \
            uint64_t __t1 = bench_now_ns();                                    \
            __samp[__k] = (double)(__t1 - __t0) / 1e6 / (double)__it;          \
        }                                                                      \
        (out) = bench_compute(__samp, __ns);                                   \
        free(__samp);                                                          \
    } while (0)

/* Reports one case as a throughput: bytes processed per single `stmt`. */
static inline void
bench_print_mbps(const char *label, bench_stats_t s, double bytes_per_iter)
{
    double mbps = bytes_per_iter / (s.median / 1000.0) / 1e6;
    printf("  %-18s min %9.5f  median %9.5f ms  %9.1f MB/s\n", label, s.min,
           s.median, mbps);
}

/* Reports one case as latency: field operations per single `stmt`. */
static inline void
bench_print_opns(const char *label, bench_stats_t s, double ops_per_iter)
{
    double ns = s.median * 1e6 / ops_per_iter;
    printf("  %-18s min %9.5f  median %9.5f ms  %9.2f ns/op\n", label, s.min,
           s.median, ns);
}

#endif /* ICHOR_BENCH_UTIL_H */
