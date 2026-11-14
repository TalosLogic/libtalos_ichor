/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/*
 * ichor_pool (ichor/pool.h) functional tests.  Exercises the data-parallel
 * dispatch contract without any crypto:
 *
 *   - parallel_for runs fn once per index and joins (sum/flag coverage);
 *   - no index is lost or run twice (per-index flag set exactly once);
 *   - the result is independent of worker count and matches a serial
 *     recomputation (determinism / order independence);
 *   - a failing batch returns the code of the LOWEST failing index, and every
 *     index still runs (the pool does not cancel);
 *   - a pool is reusable across many dispatches, and create/destroy handle
 *     nthreads 0 (default), 1, and a large value, including a pool that never
 *     dispatched;
 *   - real concurrency: a rendezvous where a task cannot return until a peer is
 *     provably running at the same instant, so a pool that secretly ran serially
 *     would fail (a correct-results suite alone cannot tell the two apart).
 *
 * The same source builds and passes with ICHOR_THREADS=ON and =OFF; the serial
 * fallback is the reference semantics, so the determinism test compares pooled
 * output to a plain in-process loop.  CI runs this binary under AddressSanitizer
 * and ThreadSanitizer; the high-n and rendezvous cases are the lock-discipline
 * race gate.
 */

/* sched_yield() is POSIX; declare it under strict -std=c17. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include "ichor/pool.h"

#include "ichor/cpu.h"

#include <sched.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* Deterministic per-index value: a pure function of i, order-independent. */
static uint64_t
f_of(size_t i)
{
    uint64_t x = (uint64_t)i + 0x9e3779b97f4a7c15ull;
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ull;
    x ^= x >> 27;
    return x;
}

struct fill_ctx {
    uint64_t *out; /* per-index output slot */
    uint8_t *flag; /* per-index "ran" flag */
};

static int
fill_task(size_t i, void *ud)
{
    struct fill_ctx *c = (struct fill_ctx *)ud;
    c->out[i] = f_of(i);
    c->flag[i]++; /* its own byte; set exactly once if no index is duplicated */
    return 0;
}

struct err_ctx {
    uint8_t *flag;
};

/* Indices 2, 5 and 8 fail with distinct codes; index 2 is the lowest. */
static int
err_task(size_t i, void *ud)
{
    struct err_ctx *c = (struct err_ctx *)ud;
    c->flag[i]++;
    if (i == 2 || i == 5 || i == 8) {
        return -(int)(1000 + i);
    }
    return 0;
}

/*
 * Rendezvous task: proves real concurrency.  Each invocation announces its
 * arrival, then blocks until `expected` tasks are simultaneously in flight.  A
 * task cannot return until `arrived >= expected`, so if `expected >= 2` and the
 * loop exits, at least two tasks were provably running at the same instant.
 * The spin is bounded: if the required overlap never materializes (e.g. the
 * calling thread did not participate, or no worker ran), the cap trips `stuck`
 * and the test fails rather than hanging.  On a serial build `expected` is 1,
 * so the loop never spins.
 */
struct rendezvous_ctx {
    atomic_uint arrived;
    unsigned expected;
    atomic_int stuck;
    uint8_t *flag;
};

static int
rendezvous_task(size_t i, void *ud)
{
    struct rendezvous_ctx *c = (struct rendezvous_ctx *)ud;
    atomic_fetch_add_explicit(&c->arrived, 1u, memory_order_seq_cst);
    /* ~10^8 iterations is sub-second yet far longer than a scheduler timeslice,
     * so a runnable peer is always scheduled in before the cap on a working
     * pool; the cap only trips if concurrency genuinely fails to appear. */
    unsigned long spins = 0;
    const unsigned long cap = 100000000ul;
    while (atomic_load_explicit(&c->arrived, memory_order_seq_cst) <
           c->expected) {
        if (++spins >= cap) {
            atomic_store_explicit(&c->stuck, 1, memory_order_seq_cst);
            break;
        }
        sched_yield(); /* let a not-yet-arrived peer run (no-op cost if ready) */
    }
    c->flag[i]++;
    return 0;
}

/* ----- labelled submit/wait API helpers ------------------------------------ */

/* A single (non-indexed) job that writes a fixed value into a caller slot. */
struct one_ctx {
    uint64_t *slot;
    int rc;
};

static int
one_task(void *ud)
{
    struct one_ctx *c = (struct one_ctx *)ud;
    *c->slot = 0xABCDEF01ull;
    return c->rc;
}

static int
noop_one(void *ud)
{
    (void)ud;
    return 0;
}

static int
noop_idx(size_t i, void *ud)
{
    (void)i;
    (void)ud;
    return 0;
}

/* A job that submits back into its OWN pool, to exercise the self-submit guard;
 * records the rejected calls' return codes. */
struct reentrant_ctx {
    ichor_pool_t *pool;
    atomic_int submit_rc;
    atomic_int pfor_rc;
};

static int
reentrant_task(size_t i, void *ud)
{
    (void)i;
    struct reentrant_ctx *c = (struct reentrant_ctx *)ud;
    atomic_store(&c->submit_rc, ichor_pool_submit(c->pool, noop_one, NULL, 0u));
    atomic_store(&c->pfor_rc,
                 ichor_pool_parallel_for(c->pool, 2, noop_idx, NULL));
    return 0;
}

/* An outer job that drives an INNER pool, for nested parallelism across two
 * independent pools (the bootstrap pattern). */
struct nested_ctx {
    ichor_pool_t *inner;
    uint64_t *out;
    uint8_t *flag;
    size_t n;
    atomic_int rc;
};

static int
nested_outer(size_t i, void *ud)
{
    (void)i;
    struct nested_ctx *c = (struct nested_ctx *)ud;
    struct fill_ctx fc = {.out = c->out, .flag = c->flag};
    int rc = ichor_pool_parallel_for(c->inner, c->n, fill_task, &fc);
    atomic_store(&c->rc, rc);
    return rc;
}

/* A job that blocks until released, so a peer can be observed waiting on its
 * label (the EBUSY guard). Bounded, so it never truly hangs. */
struct block_ctx {
    atomic_int running;
    atomic_int release;
    int rc;
};

static int
block_task(size_t i, void *ud)
{
    (void)i;
    struct block_ctx *c = (struct block_ctx *)ud;
    atomic_store(&c->running, 1);
    unsigned long spins = 0;
    const unsigned long cap = 2000000000ul;
    while (!atomic_load(&c->release)) {
        if (++spins >= cap) {
            break;
        }
        sched_yield();
    }
    return c->rc;
}

/* A job (run on a helper pool) that blocks in a wait on a DIFFERENT pool's
 * label, so a second waiter can be driven without raw pthreads. */
struct waiter_ctx {
    ichor_pool_t *target;
    uint64_t label;
    atomic_int entered;
    int done;
    int err;
    int rc;
};

static int
waiter_task(void *ud)
{
    struct waiter_ctx *c = (struct waiter_ctx *)ud;
    atomic_store(&c->entered, 1);
    c->rc = ichor_pool_wait(c->target, c->label, -1, &c->done, &c->err);
    return 0;
}

/* Untracked-job counter, for drain. */
struct count_ctx {
    atomic_int *counter;
};

static int
count_task(void *ud)
{
    struct count_ctx *c = (struct count_ctx *)ud;
    atomic_fetch_add(c->counter, 1);
    return 0;
}

/* on_label_done sink. */
struct cb_ctx {
    atomic_int fired;
    int err;
    uint64_t label;
};

static void
label_done_cb(uint64_t label, int err, void *cb_ud)
{
    struct cb_ctx *c = (struct cb_ctx *)cb_ud;
    c->label = label;
    c->err = err;
    atomic_store(&c->fired, 1);
}

/* Run fill over n indices with a freshly created nthreads-worker pool; verify
 * every slot is f_of(i) and every flag is exactly 1. */
static void
run_fill(unsigned nthreads, size_t n)
{
    ichor_pool_t *p = NULL;
    CHECK(ichor_pool_create(&p, nthreads) == 0);
    CHECK(p != NULL);
    if (p == NULL) {
        return;
    }

    uint64_t *out = calloc(n ? n : 1, sizeof(*out));
    uint8_t *flag = calloc(n ? n : 1, sizeof(*flag));
    CHECK(out != NULL && flag != NULL);

    struct fill_ctx c = {.out = out, .flag = flag};
    CHECK(ichor_pool_parallel_for(p, n, fill_task, &c) == 0);

    for (size_t i = 0; i < n; i++) {
        CHECK(out[i] == f_of(i));
        CHECK(flag[i] == 1u);
    }

    free(out);
    free(flag);
    ichor_pool_destroy(p);
}

/* ---- descriptor-job (ichor_pool_submit_jobs) helpers ----------------------- */

struct desc_ctx {
    atomic_int *gate;     /* job spins until *gate != 0 (NULL = never gate) */
    atomic_uint *entered; /* incremented when a job enters its function */
    atomic_int *bailed;   /* incremented when a cooperative job honors cancel */
    uint8_t *ran;         /* per-index: set to 1 when the function is entered */
    uint64_t *out;        /* per-index output slot, or NULL */
    int cooperative;      /* 1: poll cancel and exit early; 0: ignore it */
    int fail_index;       /* an index that returns an error, or -1 for none */
};

/*
 * Gated / cancel-aware descriptor job.  Announces entry, writes its output slot,
 * then (if gated) spins until released, optionally honoring cancellation.  The
 * spin is bounded so a mis-wired test fails instead of hanging.
 */
static int
desc_task(size_t i, void *ud, ichor_job_ctx_t *ctx)
{
    struct desc_ctx *c = (struct desc_ctx *)ud;
    if (c->ran != NULL) {
        c->ran[i] = 1u;
    }
    if (c->entered != NULL) {
        atomic_fetch_add_explicit(c->entered, 1u, memory_order_seq_cst);
    }
    if (c->out != NULL) {
        c->out[i] = f_of(i);
    }
    if (c->gate != NULL) {
        unsigned long spins = 0;
        while (atomic_load_explicit(c->gate, memory_order_seq_cst) == 0) {
            if (c->cooperative && ichor_job_cancelled(ctx)) {
                if (c->bailed != NULL) {
                    atomic_fetch_add_explicit(c->bailed, 1,
                                              memory_order_seq_cst);
                }
                return 0;
            }
            if (++spins > 500000000UL) {
                return -1; /* safety cap: never block the suite forever */
            }
            sched_yield();
        }
    }
    if (c->fail_index >= 0 && (size_t)c->fail_index == i) {
        return -(int)(1000 + i);
    }
    return 0;
}

/* Acquire-load a descriptor's observable status. */
static int
desc_state(const ichor_job_info_t *j)
{
    return atomic_load_explicit(&j->state, memory_order_acquire);
}

/* Worker-index job (ichor_job_worker_index): records the worker index it saw
 * into seen[i], announces entry, then (if gated) spins until released, so a set
 * of jobs can be held concurrently to inspect their worker indices at once. */
struct widx_ctx {
    atomic_uint *entered;
    atomic_int *gate; /* NULL = do not gate (serial build) */
    unsigned *seen;   /* per-index: observed worker index */
};

static int
widx_task(size_t i, void *ud, ichor_job_ctx_t *ctx)
{
    struct widx_ctx *c = (struct widx_ctx *)ud;
    c->seen[i] = ichor_job_worker_index(ctx);
    if (c->entered != NULL) {
        atomic_fetch_add_explicit(c->entered, 1u, memory_order_seq_cst);
    }
    if (c->gate != NULL) {
        unsigned long spins = 0;
        while (atomic_load_explicit(c->gate, memory_order_seq_cst) == 0) {
            if (++spins > 500000000UL) {
                return -1; /* safety cap: never block the suite forever */
            }
            sched_yield();
        }
    }
    return 0;
}

int
main(void)
{
    /* 1 + 2: correctness and no lost/duplicated index, across a range of n
     * (below, at, and well above the worker count) and several worker counts. */
    static const unsigned widths[] = {0u, 1u, 2u, 4u, 8u};
    static const size_t sizes[] = {0, 1, 3, 7, 16, 64, 1000};
    for (size_t w = 0; w < sizeof(widths) / sizeof(widths[0]); w++) {
        for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
            run_fill(widths[w], sizes[s]);
        }
    }

    /* 3: determinism / order independence.  The pooled output over many worker
     * counts must equal a plain serial recomputation. */
    {
        const size_t n = 500;
        uint64_t *ref = calloc(n, sizeof(*ref));
        CHECK(ref != NULL);
        for (size_t i = 0; i < n; i++) {
            ref[i] = f_of(i);
        }
        static const unsigned ncfg[] = {1u, 2u, 3u, 8u, 16u};
        for (size_t k = 0; k < sizeof(ncfg) / sizeof(ncfg[0]); k++) {
            ichor_pool_t *p = NULL;
            CHECK(ichor_pool_create(&p, ncfg[k]) == 0);
            uint64_t *out = calloc(n, sizeof(*out));
            uint8_t *flag = calloc(n, sizeof(*flag));
            CHECK(out != NULL && flag != NULL);
            struct fill_ctx c = {.out = out, .flag = flag};
            /* Repeat on the same pool to exercise reuse (test 5). */
            for (int rep = 0; rep < 3; rep++) {
                memset(out, 0, n * sizeof(*out));
                memset(flag, 0, n * sizeof(*flag));
                CHECK(ichor_pool_parallel_for(p, n, fill_task, &c) == 0);
                CHECK(memcmp(out, ref, n * sizeof(*out)) == 0);
            }
            free(out);
            free(flag);
            ichor_pool_destroy(p);
        }
        free(ref);
    }

    /* 4: error propagation - lowest failing index wins, all indices still run. */
    {
        const size_t n = 12;
        ichor_pool_t *p = NULL;
        CHECK(ichor_pool_create(&p, 4u) == 0);
        uint8_t *flag = calloc(n, sizeof(*flag));
        CHECK(flag != NULL);
        struct err_ctx c = {.flag = flag};
        int rc = ichor_pool_parallel_for(p, n, err_task, &c);
        CHECK(rc == -(int)(1000 + 2)); /* index 2 is the lowest failure */
        for (size_t i = 0; i < n; i++) {
            CHECK(flag[i] == 1u); /* no cancellation: every index ran */
        }
        free(flag);
        ichor_pool_destroy(p);
    }

    /* 5: lifecycle - default/1/large worker counts, and a pool never dispatched. */
    {
        ichor_pool_t *p = NULL;
        CHECK(ichor_pool_create(&p, 0u) == 0); /* default (online CPU count) */
        CHECK(p != NULL);
        CHECK(ichor_pool_size(p) >= 1u);
        ichor_pool_destroy(p);

        p = NULL;
        CHECK(ichor_pool_create(&p, 1u) == 0);
        CHECK(ichor_pool_size(p) == 1u);
        ichor_pool_destroy(p);

        p = NULL;
        CHECK(ichor_pool_create(&p, 64u) == 0);
        ichor_pool_destroy(p); /* never dispatched */

        ichor_pool_destroy(NULL); /* NULL is a no-op */
    }

    /* Argument validation. */
    {
        ichor_pool_t *p = NULL;
        CHECK(ichor_pool_create(&p, 2u) == 0);
        CHECK(ichor_pool_parallel_for(p, 4, NULL, NULL) == ICHOR_POOL_EINVAL);
        CHECK(ichor_pool_parallel_for(NULL, 4, fill_task, NULL) ==
              ICHOR_POOL_EINVAL);
        CHECK(ichor_pool_parallel_for(p, 0, fill_task, NULL) == 0); /* no-op */
        ichor_pool_destroy(p);
        CHECK(ichor_pool_create(NULL, 2u) == ICHOR_POOL_EINVAL);
    }

    /* 6: real concurrency.  On a threaded pool of >= 2 participants, prove that
     * at least two tasks run simultaneously (a correct-results suite alone
     * cannot distinguish a genuine pool from one that secretly ran serially on
     * the caller).  On a serial build this reduces to expected == 1 and simply
     * confirms the tasks all run. */
    {
        const size_t n = 8;
        ichor_pool_t *p = NULL;
        CHECK(ichor_pool_create(&p, 2u) == 0);
        CHECK(p != NULL);
        if (p != NULL) {
            unsigned sz = ichor_pool_size(p);
            unsigned expected = (sz < n) ? sz : (unsigned)n;
            uint8_t *flag = calloc(n, sizeof(*flag));
            CHECK(flag != NULL);
            struct rendezvous_ctx c = {.expected = expected, .flag = flag};
            atomic_init(&c.arrived, 0u);
            atomic_init(&c.stuck, 0);
            CHECK(ichor_pool_parallel_for(p, n, rendezvous_task, &c) == 0);
            /* No task overran its spin cap: the required overlap did occur. */
            CHECK(atomic_load(&c.stuck) == 0);
            for (size_t i = 0; i < n; i++) {
                CHECK(flag[i] == 1u);
            }
            if (ichor_pool_threaded() && sz >= 2u) {
                CHECK(expected >= 2u); /* this build actually tested overlap */
            }
            free(flag);
        }
        ichor_pool_destroy(p);
    }

    /* 7: single submit + wait by label; the result reaches the caller sink, and
     * the collecting wait clears the label (a second wait reports done, err 0). */
    {
        ichor_pool_t *p = NULL;
        CHECK(ichor_pool_create(&p, 4u) == 0);
        uint64_t slot = 0;
        struct one_ctx c = {.slot = &slot, .rc = 0};
        uint64_t L = ichor_pool_new_label(p);
        CHECK(L != 0u);
        CHECK(ichor_pool_submit(p, one_task, &c, L) == 0);
        int done = 0, err = -1;
        CHECK(ichor_pool_wait(p, L, -1, &done, &err) == 0);
        CHECK(done == 1);
        CHECK(err == 0);
        CHECK(slot == 0xABCDEF01ull);
        done = 0;
        err = -1;
        CHECK(ichor_pool_wait(p, L, -1, &done, &err) == 0);
        CHECK(done == 1 && err == 0);
        ichor_pool_destroy(p);
    }

    /* 8: submit_n aggregate error (lowest failing index wins); every index runs. */
    {
        const size_t n = 12;
        ichor_pool_t *p = NULL;
        CHECK(ichor_pool_create(&p, 4u) == 0);
        uint8_t *flag = calloc(n, sizeof(*flag));
        CHECK(flag != NULL);
        struct err_ctx c = {.flag = flag};
        uint64_t L = ichor_pool_new_label(p);
        CHECK(ichor_pool_submit_n(p, n, err_task, &c, L) == 0);
        int done = 0, err = 0;
        CHECK(ichor_pool_wait(p, L, -1, &done, &err) == 0);
        CHECK(done == 1);
        CHECK(err == -(int)(1000 + 2)); /* index 2 is the lowest failure */
        for (size_t i = 0; i < n; i++) {
            CHECK(flag[i] == 1u);
        }
        free(flag);
        ichor_pool_destroy(p);
    }

    /* 9: new_label values are distinct and nonzero. */
    {
        ichor_pool_t *p = NULL;
        CHECK(ichor_pool_create(&p, 2u) == 0);
        uint64_t a = ichor_pool_new_label(p);
        uint64_t b = ichor_pool_new_label(p);
        uint64_t cc = ichor_pool_new_label(p);
        CHECK(a != 0u && b != 0u && cc != 0u);
        CHECK(a != b && b != cc && a != cc);
        ichor_pool_destroy(p);
    }

    /* 10: EREENTRANT - a job may not submit to the pool it runs on. Only a
     * threaded build has workers to enforce it; serial submit runs inline. */
    {
        ichor_pool_t *p = NULL;
        CHECK(ichor_pool_create(&p, 2u) == 0);
        struct reentrant_ctx c = {.pool = p};
        atomic_init(&c.submit_rc, 0);
        atomic_init(&c.pfor_rc, 0);
        CHECK(ichor_pool_parallel_for(p, 1, reentrant_task, &c) == 0);
        if (ichor_pool_threaded()) {
            CHECK(atomic_load(&c.submit_rc) == ICHOR_POOL_EREENTRANT);
            CHECK(atomic_load(&c.pfor_rc) == ICHOR_POOL_EREENTRANT);
        }
        ichor_pool_destroy(p);
    }

    /* 11: nested parallelism across two independent pools (an outer job drives
     * the inner pool). Deadlock-free because the pools' workers are disjoint. */
    {
        ichor_pool_t *a = NULL, *b = NULL;
        CHECK(ichor_pool_create(&a, 2u) == 0);
        CHECK(ichor_pool_create(&b, 4u) == 0);
        const size_t n = 200;
        uint64_t *out = calloc(n, sizeof(*out));
        uint8_t *flag = calloc(n, sizeof(*flag));
        CHECK(out != NULL && flag != NULL);
        struct nested_ctx c = {.inner = b, .out = out, .flag = flag, .n = n};
        atomic_init(&c.rc, 0);
        CHECK(ichor_pool_parallel_for(a, 1, nested_outer, &c) == 0);
        CHECK(atomic_load(&c.rc) == 0);
        for (size_t i = 0; i < n; i++) {
            CHECK(out[i] == f_of(i));
            CHECK(flag[i] == 1u);
        }
        free(out);
        free(flag);
        ichor_pool_destroy(a);
        ichor_pool_destroy(b);
    }

    /* 12: EBUSY - a second concurrent waiter on one label is rejected. A job on
     * a helper pool blocks in the wait; main then polls and must see EBUSY while
     * that waiter holds the label. Threaded only (serial has no concurrency). */
    if (ichor_pool_threaded()) {
        ichor_pool_t *a = NULL, *b = NULL;
        CHECK(ichor_pool_create(&a, 2u) == 0); /* holds the blocking job */
        CHECK(ichor_pool_create(&b, 1u) == 0); /* runs the first waiter */
        struct block_ctx bc = {.rc = 0};
        atomic_init(&bc.running, 0);
        atomic_init(&bc.release, 0);
        uint64_t L = ichor_pool_new_label(a);
        CHECK(ichor_pool_submit_n(a, 1, block_task, &bc, L) == 0);
        while (!atomic_load(&bc.running)) {
            sched_yield();
        }
        struct waiter_ctx wc = {.target = a, .label = L};
        atomic_init(&wc.entered, 0);
        uint64_t WB = ichor_pool_new_label(b);
        CHECK(ichor_pool_submit(b, waiter_task, &wc, WB) == 0);
        while (!atomic_load(&wc.entered)) {
            sched_yield();
        }
        /* The helper holds the waiter flag until we release the job, so a poll is
         * guaranteed to observe EBUSY once the helper is actually blocked. */
        int got_ebusy = 0;
        for (int t = 0; t < 1000000 && !got_ebusy; t++) {
            int d = 0, e = 0;
            if (ichor_pool_wait(a, L, 0, &d, &e) == ICHOR_POOL_EBUSY) {
                got_ebusy = 1;
            } else {
                sched_yield();
            }
        }
        CHECK(got_ebusy);
        atomic_store(&bc.release,
                     1); /* let the job (and the helper's wait) finish */
        int bd = 0, be = 0;
        CHECK(ichor_pool_wait(b, WB, -1, &bd, &be) == 0);
        CHECK(bd == 1);
        CHECK(wc.rc == 0);
        CHECK(wc.done == 1);
        ichor_pool_destroy(a);
        ichor_pool_destroy(b);
    }

    /* 13: drain waits for every in-flight (untracked) job to finish. */
    {
        ichor_pool_t *p = NULL;
        CHECK(ichor_pool_create(&p, 4u) == 0);
        const size_t n = 300;
        atomic_int counter;
        atomic_init(&counter, 0);
        struct count_ctx c = {.counter = &counter};
        for (size_t i = 0; i < n; i++) {
            CHECK(ichor_pool_submit(p, count_task, &c, 0u) ==
                  0); /* untracked */
        }
        CHECK(ichor_pool_drain(p, -1) == 0);
        CHECK((size_t)atomic_load(&counter) == n);
        ichor_pool_destroy(p);
    }

    /* 14: on_label_done fires once with the label's aggregate error. */
    {
        ichor_pool_t *p = NULL;
        CHECK(ichor_pool_create(&p, 4u) == 0);
        const size_t n = 12;
        uint8_t *flag = calloc(n, sizeof(*flag));
        CHECK(flag != NULL);
        struct err_ctx c = {.flag = flag};
        uint64_t L = ichor_pool_new_label(p);
        struct cb_ctx cb;
        atomic_init(&cb.fired, 0);
        cb.err = 0;
        cb.label = 0;
        CHECK(ichor_pool_submit_n(p, n, err_task, &c, L) == 0);
        CHECK(ichor_pool_on_label_done(p, L, label_done_cb, &cb) == 0);
        int d = 0, e = 0;
        CHECK(ichor_pool_wait(p, L, -1, &d, &e) == 0);
        /* The callback runs on the finishing worker, which may land just after
         * the wait wakes; spin briefly to avoid a benign ordering race. */
        for (int t = 0; t < 1000000 && !atomic_load(&cb.fired); t++) {
            sched_yield();
        }
        CHECK(atomic_load(&cb.fired) == 1);
        CHECK(cb.err == -(int)(1000 + 2));
        CHECK(cb.label == L);
        free(flag);
        ichor_pool_destroy(p);
    }

    /* 15: descriptor status is observable mid-flight (RUNNING/PENDING), and
     * every descriptor ends DONE after the batch.  On a serial build the gate
     * is pre-opened and jobs are DONE as soon as submit returns. */
    {
        ichor_pool_t *p = NULL;
        CHECK(ichor_pool_create(&p, 4u) == 0);
        unsigned w = ichor_pool_size(p);
        size_t n = (size_t)w * 4u + 4u;
        ichor_job_info_t *jobs = calloc(n, sizeof(*jobs));
        uint8_t *ran = calloc(n, 1);
        CHECK(jobs != NULL && ran != NULL);
        atomic_int gate;
        atomic_init(&gate, ichor_pool_threaded() ? 0 : 1);
        atomic_uint entered;
        atomic_init(&entered, 0u);
        struct desc_ctx c = {.gate = &gate,
                             .entered = &entered,
                             .ran = ran,
                             .cooperative = 0,
                             .fail_index = -1};
        for (size_t i = 0; i < n; i++) {
            jobs[i].fn = desc_task;
            jobs[i].ud = &c;
        }
        uint64_t L = ichor_pool_new_label(p);
        CHECK(ichor_pool_submit_jobs(p, jobs, n, L) == 0);
        if (ichor_pool_threaded()) {
            /* Wait until every worker is busy on a gated job. */
            unsigned long t = 0;
            while (atomic_load(&entered) < (unsigned)w && t < 100000000UL) {
                sched_yield();
                t++;
            }
            int running = 0, pending = 0, done = 0;
            for (size_t i = 0; i < n; i++) {
                int s = desc_state(&jobs[i]);
                if (s == ICHOR_JOB_RUNNING) {
                    running++;
                } else if (s == ICHOR_JOB_PENDING) {
                    pending++;
                } else if (s == ICHOR_JOB_DONE) {
                    done++;
                }
            }
            CHECK(done == 0); /* gate closed: nothing has finished */
            CHECK(running >= 1);
            CHECK(pending >= 1); /* n > workers, so some remain queued */
            atomic_store(&gate, 1);
        }
        int d = 0, e = 0;
        CHECK(ichor_pool_wait(p, L, -1, &d, &e) == 0);
        CHECK(d == 1);
        for (size_t i = 0; i < n; i++) {
            CHECK(desc_state(&jobs[i]) == ICHOR_JOB_DONE);
        }
        free(jobs);
        free(ran);
        ichor_pool_destroy(p);
    }

    /* 16: ichor_pool_cancel skips still-queued jobs (CANCELLED, never ran) while
     * the batch still completes.  Threaded only: a serial batch runs fully at
     * submit, so there is nothing queued to skip. */
    if (ichor_pool_threaded()) {
        ichor_pool_t *p = NULL;
        CHECK(ichor_pool_create(&p, 4u) == 0);
        size_t n = 256;
        ichor_job_info_t *jobs = calloc(n, sizeof(*jobs));
        uint8_t *ran = calloc(n, 1);
        CHECK(jobs != NULL && ran != NULL);
        atomic_int gate;
        atomic_init(&gate, 0);
        struct desc_ctx c = {
            .gate = &gate, .ran = ran, .cooperative = 0, .fail_index = -1};
        for (size_t i = 0; i < n; i++) {
            jobs[i].fn = desc_task;
            jobs[i].ud = &c;
        }
        uint64_t L = ichor_pool_new_label(p);
        CHECK(ichor_pool_submit_jobs(p, jobs, n, L) == 0);
        CHECK(ichor_pool_cancel(p, L) == 0);
        atomic_store(&gate, 1); /* let the few running jobs finish */
        int d = 0, e = 0;
        CHECK(ichor_pool_wait(p, L, -1, &d, &e) == 0);
        CHECK(d == 1);
        CHECK(e == 0); /* cancellation is not an error */
        int cancelled = 0, done = 0;
        for (size_t i = 0; i < n; i++) {
            int s = desc_state(&jobs[i]);
            CHECK(s == ICHOR_JOB_DONE || s == ICHOR_JOB_CANCELLED);
            if (s == ICHOR_JOB_CANCELLED) {
                cancelled++;
                CHECK(ran[i] == 0u);
            } else {
                done++;
            }
        }
        CHECK(cancelled >= 1);
        CHECK((size_t)(cancelled + done) == n);
        free(jobs);
        free(ran);
        ichor_pool_destroy(p);
    }

    /* 17: a running job that polls ichor_job_cancelled exits early and ends DONE
     * (not CANCELLED).  Threaded; n == workers, so none are left queued. */
    if (ichor_pool_threaded()) {
        ichor_pool_t *p = NULL;
        CHECK(ichor_pool_create(&p, 4u) == 0);
        size_t n = ichor_pool_size(p);
        ichor_job_info_t *jobs = calloc(n, sizeof(*jobs));
        CHECK(jobs != NULL);
        atomic_int gate;
        atomic_init(&gate, 0); /* never released: only cancel frees the jobs */
        atomic_uint entered;
        atomic_init(&entered, 0u);
        atomic_int bailed;
        atomic_init(&bailed, 0);
        struct desc_ctx c = {.gate = &gate,
                             .entered = &entered,
                             .bailed = &bailed,
                             .cooperative = 1,
                             .fail_index = -1};
        for (size_t i = 0; i < n; i++) {
            jobs[i].fn = desc_task;
            jobs[i].ud = &c;
        }
        uint64_t L = ichor_pool_new_label(p);
        CHECK(ichor_pool_submit_jobs(p, jobs, n, L) == 0);
        unsigned long t = 0;
        while (atomic_load(&entered) < (unsigned)n && t < 100000000UL) {
            sched_yield();
            t++;
        }
        CHECK(ichor_pool_cancel(p, L) == 0);
        int d = 0, e = 0;
        CHECK(ichor_pool_wait(p, L, -1, &d, &e) == 0);
        CHECK(d == 1);
        CHECK(atomic_load(&bailed) >= 1);
        for (size_t i = 0; i < n; i++) {
            CHECK(desc_state(&jobs[i]) == ICHOR_JOB_DONE);
        }
        free(jobs);
        ichor_pool_destroy(p);
    }

    /* 18: a running job that ignores the cancel flag runs to completion (DONE
     * with its normal result); the pool forces nothing. */
    if (ichor_pool_threaded()) {
        ichor_pool_t *p = NULL;
        CHECK(ichor_pool_create(&p, 4u) == 0);
        size_t n = 64;
        ichor_job_info_t *jobs = calloc(n, sizeof(*jobs));
        uint64_t *out = calloc(n, sizeof(*out));
        CHECK(jobs != NULL && out != NULL);
        struct desc_ctx c = {.out = out, .cooperative = 0, .fail_index = -1};
        for (size_t i = 0; i < n; i++) {
            jobs[i].fn = desc_task;
            jobs[i].ud = &c;
        }
        uint64_t L = ichor_pool_new_label(p);
        CHECK(ichor_pool_submit_jobs(p, jobs, n, L) == 0);
        CHECK(ichor_pool_cancel(p, L) == 0);
        int d = 0, e = 0;
        CHECK(ichor_pool_wait(p, L, -1, &d, &e) == 0);
        CHECK(d == 1);
        for (size_t i = 0; i < n; i++) {
            int s = desc_state(&jobs[i]);
            CHECK(s == ICHOR_JOB_DONE || s == ICHOR_JOB_CANCELLED);
            if (s == ICHOR_JOB_DONE) {
                CHECK(out[i] == f_of(i));
            }
        }
        free(jobs);
        free(out);
        ichor_pool_destroy(p);
    }

    /* 19: cancellation is not folded into the aggregate error, but a genuine
     * failing index still is. */
    {
        /* A: a cancelled batch with no failing job returns err 0 (threaded). */
        if (ichor_pool_threaded()) {
            ichor_pool_t *p = NULL;
            CHECK(ichor_pool_create(&p, 4u) == 0);
            size_t n = 128;
            ichor_job_info_t *jobs = calloc(n, sizeof(*jobs));
            CHECK(jobs != NULL);
            atomic_int gate;
            atomic_init(&gate, 0);
            struct desc_ctx c = {
                .gate = &gate, .cooperative = 0, .fail_index = -1};
            for (size_t i = 0; i < n; i++) {
                jobs[i].fn = desc_task;
                jobs[i].ud = &c;
            }
            uint64_t L = ichor_pool_new_label(p);
            CHECK(ichor_pool_submit_jobs(p, jobs, n, L) == 0);
            CHECK(ichor_pool_cancel(p, L) == 0);
            atomic_store(&gate, 1);
            int d = 0, e = 0;
            CHECK(ichor_pool_wait(p, L, -1, &d, &e) == 0);
            CHECK(d == 1);
            CHECK(e == 0);
            free(jobs);
            ichor_pool_destroy(p);
        }
        /* B: one failing index, no cancel, returns that index's error. */
        {
            ichor_pool_t *p = NULL;
            CHECK(ichor_pool_create(&p, 4u) == 0);
            size_t n = 16;
            ichor_job_info_t *jobs = calloc(n, sizeof(*jobs));
            CHECK(jobs != NULL);
            struct desc_ctx c = {.cooperative = 0, .fail_index = 5};
            for (size_t i = 0; i < n; i++) {
                jobs[i].fn = desc_task;
                jobs[i].ud = &c;
            }
            uint64_t L = ichor_pool_new_label(p);
            CHECK(ichor_pool_submit_jobs(p, jobs, n, L) == 0);
            int d = 0, e = 0;
            CHECK(ichor_pool_wait(p, L, -1, &d, &e) == 0);
            CHECK(d == 1);
            CHECK(e == -(int)(1000 + 5));
            free(jobs);
            ichor_pool_destroy(p);
        }
    }

    /* 20: one caller-owned descriptor array, reused across many batches with a
     * fresh label and reset state each time; results correct, never realloc'd. */
    {
        ichor_pool_t *p = NULL;
        CHECK(ichor_pool_create(&p, 4u) == 0);
        size_t n = 50;
        ichor_job_info_t *jobs = calloc(n, sizeof(*jobs));
        uint64_t *out = calloc(n, sizeof(*out));
        CHECK(jobs != NULL && out != NULL);
        struct desc_ctx c = {.out = out, .cooperative = 0, .fail_index = -1};
        for (int b = 0; b < 8; b++) {
            memset(out, 0, n * sizeof(*out));
            for (size_t i = 0; i < n; i++) {
                jobs[i].fn = desc_task;
                jobs[i].ud = &c;
                atomic_store_explicit(&jobs[i].state, ICHOR_JOB_PENDING,
                                      memory_order_relaxed);
            }
            uint64_t L = ichor_pool_new_label(p);
            CHECK(ichor_pool_submit_jobs(p, jobs, n, L) == 0);
            int d = 0, e = 0;
            CHECK(ichor_pool_wait(p, L, -1, &d, &e) == 0);
            CHECK(d == 1);
            CHECK(e == 0);
            for (size_t i = 0; i < n; i++) {
                CHECK(out[i] == f_of(i));
                CHECK(desc_state(&jobs[i]) == ICHOR_JOB_DONE);
            }
        }
        free(jobs);
        free(out);
        ichor_pool_destroy(p);
    }

    /* 21: cancel racing dequeue (ThreadSanitizer gate).  Each descriptor ends
     * DONE or CANCELLED exactly once, and a CANCELLED job never ran. */
    if (ichor_pool_threaded()) {
        for (int iter = 0; iter < 8; iter++) {
            ichor_pool_t *p = NULL;
            CHECK(ichor_pool_create(&p, 4u) == 0);
            size_t n = 1000;
            ichor_job_info_t *jobs = calloc(n, sizeof(*jobs));
            uint8_t *ran = calloc(n, 1);
            CHECK(jobs != NULL && ran != NULL);
            struct desc_ctx c = {
                .ran = ran, .cooperative = 0, .fail_index = -1};
            for (size_t i = 0; i < n; i++) {
                jobs[i].fn = desc_task;
                jobs[i].ud = &c;
            }
            uint64_t L = ichor_pool_new_label(p);
            CHECK(ichor_pool_submit_jobs(p, jobs, n, L) == 0);
            CHECK(ichor_pool_cancel(p, L) ==
                  0); /* races workers claiming jobs */
            int d = 0, e = 0;
            CHECK(ichor_pool_wait(p, L, -1, &d, &e) == 0);
            CHECK(d == 1);
            for (size_t i = 0; i < n; i++) {
                int s = desc_state(&jobs[i]);
                CHECK(s == ICHOR_JOB_DONE || s == ICHOR_JOB_CANCELLED);
                if (s == ICHOR_JOB_CANCELLED) {
                    CHECK(ran[i] == 0u);
                }
            }
            free(jobs);
            free(ran);
            ichor_pool_destroy(p);
        }
    }

    /* 22: core-count detection (docs/THREAD_POOL.md Section 11). */
    {
        unsigned phys = ichor_cpu_physical_cores();
        unsigned logi = ichor_cpu_logical_cpus();
        CHECK(phys >= 1u);
        CHECK(logi >= 1u);
        CHECK(phys <= logi);

        /* Default (nthreads == 0): physical cores threaded, 1 serial. */
        ichor_pool_t *p = NULL;
        CHECK(ichor_pool_create(&p, 0u) == 0);
        if (ichor_pool_threaded()) {
            CHECK(ichor_pool_size(p) == phys);
        } else {
            CHECK(ichor_pool_size(p) == 1u);
        }
        ichor_pool_destroy(p);

        /* Explicit nthreads is honored verbatim, bypassing detection. */
        ichor_pool_t *q = NULL;
        CHECK(ichor_pool_create(&q, 3u) == 0);
        if (ichor_pool_threaded()) {
            CHECK(ichor_pool_size(q) == 3u);
        } else {
            CHECK(ichor_pool_size(q) == 1u);
        }
        ichor_pool_destroy(q);
    }

    /* 23: ichor_job_worker_index (T2.1).  Hold exactly W jobs on a W-worker
     * pool concurrently (gated rendezvous); with W jobs and W workers each
     * worker runs exactly one, so the observed indices must be a permutation of
     * 0..W-1 (in range + distinct across concurrent jobs).  On the serial build
     * every job runs inline as worker 0. */
    {
        ichor_pool_t *p = NULL;
        CHECK(ichor_pool_create(&p, 4u) == 0);
        unsigned W = ichor_pool_size(p);
        size_t n = W;
        ichor_job_info_t *jobs = calloc(n, sizeof(*jobs));
        unsigned *seen = calloc(n, sizeof(*seen));
        CHECK(jobs != NULL && seen != NULL);
        atomic_uint entered = 0;
        atomic_int gate = 0;
        struct widx_ctx c = {.entered = &entered,
                             .gate = ichor_pool_threaded() ? &gate : NULL,
                             .seen = seen};
        for (size_t i = 0; i < n; i++) {
            jobs[i].fn = widx_task;
            jobs[i].ud = &c;
        }
        uint64_t L = ichor_pool_new_label(p);
        CHECK(ichor_pool_submit_jobs(p, jobs, n, L) == 0);
        if (ichor_pool_threaded()) {
            /* Wait until all W jobs are concurrently running, then release. */
            unsigned long spins = 0;
            while (atomic_load_explicit(&entered, memory_order_seq_cst) < W) {
                if (++spins > 500000000UL) {
                    CHECK(0);
                    break;
                }
                sched_yield();
            }
            atomic_store_explicit(&gate, 1, memory_order_seq_cst);
        }
        int d = 0, e = 0;
        CHECK(ichor_pool_wait(p, L, -1, &d, &e) == 0);
        CHECK(d == 1 && e == 0);
        for (size_t i = 0; i < n; i++) {
            CHECK(seen[i] < W);
        }
        if (ichor_pool_threaded()) {
            unsigned *count = calloc(W, sizeof(*count));
            CHECK(count != NULL);
            for (size_t i = 0; i < n; i++) {
                count[seen[i]]++;
            }
            for (unsigned w = 0; w < W; w++) {
                CHECK(count[w] == 1u);
            }
            free(count);
        } else {
            for (size_t i = 0; i < n; i++) {
                CHECK(seen[i] == 0u);
            }
        }
        free(jobs);
        free(seen);
        ichor_pool_destroy(p);
    }

    if (failures != 0) {
        fprintf(stderr, "test_pool: %d failure(s)\n", failures);
        return 1;
    }
    printf("test_pool: OK (threaded=%d)\n", ichor_pool_threaded());
    return 0;
}
