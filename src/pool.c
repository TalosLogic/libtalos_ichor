/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/*
 * pool.c - ichor_pool, a labelled fire-and-forget worker pool.
 *
 * Two implementations live in this one translation unit, selected by the build
 * define ICHOR_WITH_THREADS (wired in CMakeLists.txt):
 *
 *   - ICHOR_WITH_THREADS == 0: a serial fallback that runs every job inline on
 *     the submitting thread, keeping the same label bookkeeping so waits and
 *     aggregate errors behave identically.  No threading library is linked.
 *   - ICHOR_WITH_THREADS == 1: a POSIX pthreads pool.  Submission enqueues a job
 *     and returns; worker threads run the queue.  The submitting thread does not
 *     participate.
 *
 * Queue node.  The FIFO node is ichor_job_info_t (ichor/pool.h), the same type
 * the caller owns for ichor_pool_submit_jobs.  The legacy entry points
 * (ichor_pool_submit / ichor_pool_submit_n) allocate a node per job and set its
 * _owns flag so the worker frees it; ichor_pool_submit_jobs links the caller's
 * descriptors directly and frees nothing.  A node carries whichever function
 * form applies: _jfn for a single legacy job, _ifn for an indexed legacy job, or
 * the public ctx-bearing fn for a descriptor job (run_job picks).
 *
 * State.  The pool owns a FIFO queue of jobs and a list of active LABEL records.
 * A label record counts the jobs still in flight under that label and holds the
 * aggregate error (the lowest failing index wins) plus a cancel flag; it is
 * created on first submit under the label and freed when a wait COLLECTS it
 * (observes it idle).  That is why a label's error survives until someone waits
 * for it, even if the jobs finished first.  `inflight` counts jobs of every
 * label for ichor_pool_drain.
 *
 * Locking.  One mutex guards the queue and all label records.  cv_work wakes
 * workers when a job is posted (or on shutdown); cv_done wakes waiters when a
 * label reaches zero or the pool goes idle.  Jobs and completion callbacks run
 * with the mutex released, so they take no pool locks (the concurrency contract
 * in ichor/pool.h).  A worker tags itself in a thread-specific key so a submit
 * from inside the pool it runs on is rejected with ICHOR_POOL_EREENTRANT.
 *
 * Cancellation.  A worker decides a dequeued job's fate (run or skip) while
 * holding the mutex, and ichor_pool_cancel sets the group's cancel flag under
 * the same mutex, so each job is either run or skipped exactly once no matter
 * how a cancel races a worker (docs/THREAD_POOL.md Section 10.4, invariant 1).
 * The per-job status word is an atomic the worker release-stores and the caller
 * acquire-loads, so a caller that observes DONE sees the job's err and outputs.
 *
 * See docs/THREAD_POOL.md.
 */

/* pthreads needs a POSIX.1-2001 environment. sysconf(_SC_NPROCESSORS_ONLN) is a
 * widely supported extension, not base POSIX: glibc exposes it under
 * _POSIX_C_SOURCE, but macOS hides it (and other non-standard names) when a
 * strict _POSIX_C_SOURCE / -std=c17 (__STRICT_ANSI__) is in effect, so on Apple
 * we also request _DARWIN_C_SOURCE to re-expose it. */
#if defined(ICHOR_WITH_THREADS) && ICHOR_WITH_THREADS
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#endif

#include "ichor/pool.h"

#include "ichor/cpu.h"

#include <stdatomic.h>
#include <stdlib.h>

/*
 * Per-invocation handle passed to a descriptor job.  It holds a pointer to the
 * job's group cancel flag (NULL for untracked work), which ichor_job_cancelled
 * acquire-loads.  Defined for both builds; ichor_job_cancelled is shared.
 */
struct ichor_job_ctx {
    _Atomic int *cancel;
    unsigned worker; /* 0..nworkers-1, stable for the job's duration */
};

/* The new-label sequence starts well above the range a caller is likely to type
 * by hand, so ichor_pool_new_label values never collide with small literals. */
#define ICHOR_POOL_LABEL_BASE 0x100000000ULL

#if defined(ICHOR_WITH_THREADS) && ICHOR_WITH_THREADS

#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

/* Run a job through whichever function form the node carries. */
static int
run_job(ichor_job_info_t *j, ichor_job_ctx_t *ctx)
{
    if (j->_jfn != NULL) {
        return j->_jfn(j->ud);
    }
    if (j->_ifn != NULL) {
        return j->_ifn(j->_index, j->ud);
    }
    return j->fn(j->_index, j->ud, ctx);
}

/* A group of related jobs: how many are still in flight, the aggregate error
 * (lowest failing index wins), and the group cancel flag. Created on first
 * submit under the label, freed when a wait collects it. `waiter` is the
 * best-effort single-waiter guard. */
struct label_rec {
    struct label_rec *next;
    uint64_t label;
    size_t remaining;
    int err;
    size_t err_index;
    int has_err;
    int waiter;
    _Atomic int cancel; /* set by ichor_pool_cancel; read by workers and jobs */
    ichor_label_cb cb;  /* one-shot completion callback, or NULL */
    void *cb_ud;
};

struct ichor_pool {
    pthread_t *workers;
    unsigned nworkers;
    pthread_mutex_t mtx;
    pthread_cond_t cv_work; /* a job was posted, or shutdown */
    pthread_cond_t cv_done; /* a label reached zero, or the pool went idle */
    int shutdown;

    ichor_job_info_t *qhead; /* FIFO job queue */
    ichor_job_info_t *qtail;
    size_t inflight; /* jobs of every label not yet completed (for drain) */

    struct label_rec *labels; /* active label records */
    uint64_t next_label;      /* monotonic source for new_label */

    struct worker_arg *worker_args; /* one {pool, idx} per worker thread */
};

/* Per-worker thread argument: the pool plus the worker's own index.  Allocated
 * as an array on the pool so it outlives thread startup and is freed once at
 * destroy; a worker reads its index from here and reports it to jobs through
 * ichor_job_ctx.worker. */
struct worker_arg {
    ichor_pool_t *pool;
    unsigned idx;
};

/* Thread-specific pointer to the pool a worker belongs to, for the self-submit
 * guard. One process-wide key serves every pool. If the key cannot be created
 * the guard is simply disabled (it is an assertion aid, not load-bearing). */
static pthread_key_t g_pool_key;
static pthread_once_t g_pool_key_once = PTHREAD_ONCE_INIT;
static int g_pool_key_ok = 0;

static void
make_pool_key(void)
{
    g_pool_key_ok = (pthread_key_create(&g_pool_key, NULL) == 0);
}

static void
ensure_pool_key(void)
{
    (void)pthread_once(&g_pool_key_once, make_pool_key);
}

static int
submit_from_own_worker(const ichor_pool_t *p)
{
    return g_pool_key_ok && pthread_getspecific(g_pool_key) == (const void *)p;
}

static unsigned
default_threads(void)
{
    /* The sensible default is the physical-core count, not the logical-CPU
     * count: for the compute-bound workloads ichor serves, hyperthread siblings
     * contend for the same execution ports. An explicit nthreads is honored
     * verbatim; this runs only for nthreads == 0. See docs/THREAD_POOL.md
     * Section 11. The helper never returns 0. */
    return ichor_cpu_physical_cores();
}

static void
deadline_from_ms(struct timespec *ts, int ms)
{
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_sec += ms / 1000;
    ts->tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts->tv_nsec >= 1000000000L) {
        ts->tv_sec += 1;
        ts->tv_nsec -= 1000000000L;
    }
}

/* ----- queue and label helpers (caller holds p->mtx) ------------------------ */

static void
enqueue(ichor_pool_t *p, ichor_job_info_t *j)
{
    j->_next = NULL;
    if (p->qtail != NULL) {
        p->qtail->_next = j;
    } else {
        p->qhead = j;
    }
    p->qtail = j;
}

static ichor_job_info_t *
dequeue(ichor_pool_t *p)
{
    ichor_job_info_t *j = p->qhead;
    if (j != NULL) {
        p->qhead = j->_next;
        if (p->qhead == NULL) {
            p->qtail = NULL;
        }
    }
    return j;
}

static struct label_rec *
find_label(ichor_pool_t *p, uint64_t label)
{
    for (struct label_rec *r = p->labels; r != NULL; r = r->next) {
        if (r->label == label) {
            return r;
        }
    }
    return NULL;
}

/* Find or create the record for `label`; returns NULL only on allocation
 * failure. Caller holds the lock. */
static struct label_rec *
intern_label(ichor_pool_t *p, uint64_t label)
{
    struct label_rec *r = find_label(p, label);
    if (r != NULL) {
        return r;
    }
    r = calloc(1, sizeof(*r));
    if (r == NULL) {
        return NULL;
    }
    r->label = label;
    r->next = p->labels;
    p->labels = r;
    return r;
}

static void
remove_label(ichor_pool_t *p, struct label_rec *rec)
{
    struct label_rec **pp = &p->labels;
    while (*pp != NULL && *pp != rec) {
        pp = &(*pp)->next;
    }
    if (*pp != NULL) {
        *pp = rec->next;
    }
    free(rec);
}

/*
 * Account for one finished (or skipped) job. Caller holds the lock. `rc` is the
 * job's return, or 0 for a skipped (cancelled) job that never ran. If the job's
 * label just reached zero and carries a completion callback, the callback and
 * its arguments are handed back through *fire_* so the worker can invoke it
 * after unlocking; the callback is one-shot (cleared here).
 */
static void
complete_job(ichor_pool_t *p, uint64_t label, size_t index, int rc,
             ichor_label_cb *fire_cb, void **fire_ud, uint64_t *fire_label,
             int *fire_err)
{
    p->inflight--;
    if (label != 0u) {
        struct label_rec *r = find_label(p, label);
        if (r != NULL) {
            if (rc != 0 && (!r->has_err || index < r->err_index)) {
                r->has_err = 1;
                r->err = rc;
                r->err_index = index;
            }
            r->remaining--;
            if (r->remaining == 0u) {
                if (r->cb != NULL) {
                    *fire_cb = r->cb;
                    *fire_ud = r->cb_ud;
                    *fire_label = label;
                    *fire_err = r->has_err ? r->err : 0;
                    r->cb = NULL;
                }
                pthread_cond_broadcast(&p->cv_done);
            }
        }
    }
    if (p->inflight == 0u) {
        pthread_cond_broadcast(&p->cv_done);
    }
}

static void *
worker_main(void *arg)
{
    struct worker_arg *wa = (struct worker_arg *)arg;
    ichor_pool_t *p = wa->pool;
    unsigned my_index = wa->idx;
    if (g_pool_key_ok) {
        (void)pthread_setspecific(g_pool_key, p);
    }

    pthread_mutex_lock(&p->mtx);
    for (;;) {
        while (!p->shutdown && p->qhead == NULL) {
            pthread_cond_wait(&p->cv_work, &p->mtx);
        }
        if (p->shutdown && p->qhead == NULL) {
            break; /* drains the queue first: only exits once it is empty */
        }
        ichor_job_info_t *j = dequeue(p);

        /*
         * Decide run-vs-skip under the lock, so a cancel (which sets the flag
         * under the same lock) either is seen here (skip) or arrives after this
         * job has committed to RUNNING: exactly one outcome per job.
         */
        _Atomic int *cancelflag = NULL;
        int cancelled = 0;
        if (j->_label != 0u) {
            struct label_rec *r = find_label(p, j->_label);
            if (r != NULL) {
                cancelflag = &r->cancel;
                if (atomic_load_explicit(&r->cancel, memory_order_relaxed)) {
                    cancelled = 1;
                }
            }
        }
        if (cancelled) {
            atomic_store_explicit(&j->state, ICHOR_JOB_CANCELLED,
                                  memory_order_release);
        } else {
            atomic_store_explicit(&j->state, ICHOR_JOB_RUNNING,
                                  memory_order_release);
        }

        /* Snapshot what completion needs before the node can be freed/reused. */
        uint64_t label = j->_label;
        size_t index = j->_index;
        unsigned owns = j->_owns;

        pthread_mutex_unlock(&p->mtx);

        int rc = 0;
        if (!cancelled) {
            struct ichor_job_ctx ctx;
            ctx.cancel = cancelflag;
            ctx.worker = my_index;
            rc = run_job(j, &ctx);
            j->err = rc;
            atomic_store_explicit(&j->state, ICHOR_JOB_DONE,
                                  memory_order_release);
        }

        ichor_label_cb fire_cb = NULL;
        void *fire_ud = NULL;
        uint64_t fire_label = 0u;
        int fire_err = 0;
        pthread_mutex_lock(&p->mtx);
        complete_job(p, label, index, cancelled ? 0 : rc, &fire_cb, &fire_ud,
                     &fire_label, &fire_err);
        if (fire_cb != NULL) {
            pthread_mutex_unlock(&p->mtx);
            fire_cb(fire_label, fire_err, fire_ud);
            pthread_mutex_lock(&p->mtx);
        }
        if (owns) {
            free(j); /* a legacy-path node the pool allocated */
        }
    }
    pthread_mutex_unlock(&p->mtx);
    return NULL;
}

int
ichor_pool_create(ichor_pool_t **out, unsigned nthreads)
{
    if (out == NULL) {
        return ICHOR_POOL_EINVAL;
    }
    *out = NULL;
    ensure_pool_key();

    if (nthreads == 0u) {
        nthreads = default_threads();
    }

    ichor_pool_t *p = calloc(1, sizeof(*p));
    if (p == NULL) {
        return ICHOR_POOL_ENOMEM;
    }
    p->nworkers = nthreads;
    p->next_label = ICHOR_POOL_LABEL_BASE;

    if (pthread_mutex_init(&p->mtx, NULL) != 0) {
        free(p);
        return ICHOR_POOL_EOS;
    }
    if (pthread_cond_init(&p->cv_work, NULL) != 0) {
        pthread_mutex_destroy(&p->mtx);
        free(p);
        return ICHOR_POOL_EOS;
    }
    if (pthread_cond_init(&p->cv_done, NULL) != 0) {
        pthread_cond_destroy(&p->cv_work);
        pthread_mutex_destroy(&p->mtx);
        free(p);
        return ICHOR_POOL_EOS;
    }

    p->workers = calloc((size_t)p->nworkers, sizeof(*p->workers));
    p->worker_args = calloc((size_t)p->nworkers, sizeof(*p->worker_args));
    if (p->workers == NULL || p->worker_args == NULL) {
        free(p->workers);
        free(p->worker_args);
        pthread_cond_destroy(&p->cv_done);
        pthread_cond_destroy(&p->cv_work);
        pthread_mutex_destroy(&p->mtx);
        free(p);
        return ICHOR_POOL_ENOMEM;
    }
    for (unsigned k = 0; k < p->nworkers; k++) {
        p->worker_args[k].pool = p;
        p->worker_args[k].idx = k;
        if (pthread_create(&p->workers[k], NULL, worker_main,
                           &p->worker_args[k]) != 0) {
            pthread_mutex_lock(&p->mtx);
            p->shutdown = 1;
            pthread_cond_broadcast(&p->cv_work);
            pthread_mutex_unlock(&p->mtx);
            for (unsigned j = 0; j < k; j++) {
                pthread_join(p->workers[j], NULL);
            }
            free(p->workers);
            free(p->worker_args);
            pthread_cond_destroy(&p->cv_done);
            pthread_cond_destroy(&p->cv_work);
            pthread_mutex_destroy(&p->mtx);
            free(p);
            return ICHOR_POOL_EOS;
        }
    }

    *out = p;
    return 0;
}

void
ichor_pool_destroy(ichor_pool_t *p)
{
    if (p == NULL) {
        return;
    }
    pthread_mutex_lock(&p->mtx);
    p->shutdown = 1;
    pthread_cond_broadcast(&p->cv_work);
    pthread_mutex_unlock(&p->mtx);

    for (unsigned k = 0; k < p->nworkers; k++) {
        pthread_join(p->workers[k], NULL);
    }
    free(p->workers);
    free(p->worker_args);

    /* The workers drain the queue before exiting, so these are normally empty;
     * free defensively in case of a partial create or an abandoned submission.
     * Only pool-allocated (legacy) nodes are freed; caller-owned descriptor
     * nodes are never freed by the pool. */
    ichor_job_info_t *j = p->qhead;
    while (j != NULL) {
        ichor_job_info_t *nx = j->_next;
        if (j->_owns) {
            free(j);
        }
        j = nx;
    }
    struct label_rec *r = p->labels;
    while (r != NULL) {
        struct label_rec *nx = r->next;
        free(r);
        r = nx;
    }

    pthread_cond_destroy(&p->cv_done);
    pthread_cond_destroy(&p->cv_work);
    pthread_mutex_destroy(&p->mtx);
    free(p);
}

unsigned
ichor_pool_size(const ichor_pool_t *p)
{
    if (p == NULL) {
        return 0u;
    }
    return p->nworkers;
}

int
ichor_pool_threaded(void)
{
    return 1;
}

uint64_t
ichor_pool_new_label(ichor_pool_t *p)
{
    if (p == NULL) {
        return 0u;
    }
    pthread_mutex_lock(&p->mtx);
    uint64_t v = p->next_label++;
    pthread_mutex_unlock(&p->mtx);
    return v;
}

int
ichor_pool_submit(ichor_pool_t *p, ichor_job_fn fn, void *ud, uint64_t label)
{
    if (p == NULL || fn == NULL) {
        return ICHOR_POOL_EINVAL;
    }
    if (submit_from_own_worker(p)) {
        return ICHOR_POOL_EREENTRANT;
    }
    ichor_job_info_t *j = calloc(1, sizeof(*j));
    if (j == NULL) {
        return ICHOR_POOL_ENOMEM;
    }
    j->_jfn = fn;
    j->ud = ud;
    j->_label = label;
    j->_owns = 1u;
    atomic_store_explicit(&j->state, ICHOR_JOB_PENDING, memory_order_relaxed);

    pthread_mutex_lock(&p->mtx);
    if (label != 0u) {
        struct label_rec *r = intern_label(p, label);
        if (r == NULL) {
            pthread_mutex_unlock(&p->mtx);
            free(j);
            return ICHOR_POOL_ENOMEM;
        }
        r->remaining++;
    }
    p->inflight++;
    enqueue(p, j);
    pthread_cond_signal(&p->cv_work);
    pthread_mutex_unlock(&p->mtx);
    return 0;
}

int
ichor_pool_submit_n(ichor_pool_t *p, size_t n, ichor_pool_fn fn, void *ud,
                    uint64_t label)
{
    if (p == NULL || fn == NULL) {
        return ICHOR_POOL_EINVAL;
    }
    if (n == 0) {
        return 0;
    }
    if (submit_from_own_worker(p)) {
        return ICHOR_POOL_EREENTRANT;
    }

    /* Allocate every node up front so a failure enqueues nothing. */
    ichor_job_info_t **jobs = calloc(n, sizeof(*jobs));
    if (jobs == NULL) {
        return ICHOR_POOL_ENOMEM;
    }
    for (size_t i = 0; i < n; i++) {
        jobs[i] = calloc(1, sizeof(ichor_job_info_t));
        if (jobs[i] == NULL) {
            for (size_t k = 0; k < i; k++) {
                free(jobs[k]);
            }
            free(jobs);
            return ICHOR_POOL_ENOMEM;
        }
        jobs[i]->_ifn = fn;
        jobs[i]->_index = i;
        jobs[i]->ud = ud;
        jobs[i]->_label = label;
        jobs[i]->_owns = 1u;
        atomic_store_explicit(&jobs[i]->state, ICHOR_JOB_PENDING,
                              memory_order_relaxed);
    }

    pthread_mutex_lock(&p->mtx);
    if (label != 0u) {
        struct label_rec *r = intern_label(p, label);
        if (r == NULL) {
            pthread_mutex_unlock(&p->mtx);
            for (size_t i = 0; i < n; i++) {
                free(jobs[i]);
            }
            free(jobs);
            return ICHOR_POOL_ENOMEM;
        }
        r->remaining += n;
    }
    p->inflight += n;
    for (size_t i = 0; i < n; i++) {
        enqueue(p, jobs[i]);
    }
    pthread_cond_broadcast(&p->cv_work);
    pthread_mutex_unlock(&p->mtx);
    free(jobs);
    return 0;
}

int
ichor_pool_submit_jobs(ichor_pool_t *p, ichor_job_info_t *jobs, size_t n,
                       uint64_t label)
{
    if (p == NULL || jobs == NULL) {
        return ICHOR_POOL_EINVAL;
    }
    if (n == 0) {
        return 0;
    }
    if (submit_from_own_worker(p)) {
        return ICHOR_POOL_EREENTRANT;
    }
    for (size_t i = 0; i < n; i++) {
        if (jobs[i].fn == NULL) {
            return ICHOR_POOL_EINVAL;
        }
    }

    pthread_mutex_lock(&p->mtx);
    if (label != 0u) {
        struct label_rec *r = intern_label(p, label);
        if (r == NULL) {
            pthread_mutex_unlock(&p->mtx);
            return ICHOR_POOL_ENOMEM;
        }
        r->remaining += n;
    }
    p->inflight += n;
    for (size_t i = 0; i < n; i++) {
        jobs[i]._index = i;
        jobs[i]._label = label;
        jobs[i]._jfn = NULL;
        jobs[i]._ifn = NULL;
        jobs[i]._owns = 0u;
        jobs[i].err = 0;
        atomic_store_explicit(&jobs[i].state, ICHOR_JOB_PENDING,
                              memory_order_relaxed);
        enqueue(p, &jobs[i]);
    }
    pthread_cond_broadcast(&p->cv_work);
    pthread_mutex_unlock(&p->mtx);
    return 0;
}

int
ichor_pool_cancel(ichor_pool_t *p, uint64_t label)
{
    if (p == NULL) {
        return ICHOR_POOL_EINVAL;
    }
    pthread_mutex_lock(&p->mtx);
    struct label_rec *r = find_label(p, label);
    if (r != NULL) {
        atomic_store_explicit(&r->cancel, 1, memory_order_release);
    }
    pthread_mutex_unlock(&p->mtx);
    return 0;
}

int
ichor_pool_wait(ichor_pool_t *p, uint64_t label, int timeout_ms, int *done,
                int *err)
{
    if (p == NULL) {
        return ICHOR_POOL_EINVAL;
    }
    struct timespec deadline;
    if (timeout_ms > 0) {
        deadline_from_ms(&deadline, timeout_ms);
    }

    pthread_mutex_lock(&p->mtx);
    struct label_rec *r = find_label(p, label);
    if (r == NULL) {
        pthread_mutex_unlock(&p->mtx);
        if (done != NULL) {
            *done = 1;
        }
        if (err != NULL) {
            *err = 0;
        }
        return 0;
    }
    if (r->waiter) {
        pthread_mutex_unlock(&p->mtx);
        return ICHOR_POOL_EBUSY;
    }
    r->waiter = 1;

    while (r->remaining > 0u) {
        if (timeout_ms == 0) {
            break;
        }
        if (timeout_ms < 0) {
            pthread_cond_wait(&p->cv_done, &p->mtx);
        } else {
            int rc = pthread_cond_timedwait(&p->cv_done, &p->mtx, &deadline);
            if (rc == ETIMEDOUT) {
                break;
            }
        }
    }

    if (r->remaining == 0u) {
        if (done != NULL) {
            *done = 1;
        }
        if (err != NULL) {
            *err = r->has_err ? r->err : 0;
        }
        remove_label(p, r); /* collect: the record and its error are consumed */
    } else {
        r->waiter = 0; /* timed out, nothing collected */
        if (done != NULL) {
            *done = 0;
        }
        if (err != NULL) {
            *err = 0;
        }
    }
    pthread_mutex_unlock(&p->mtx);
    return 0;
}

int
ichor_pool_on_label_done(ichor_pool_t *p, uint64_t label, ichor_label_cb cb,
                         void *cb_ud)
{
    if (p == NULL || cb == NULL) {
        return ICHOR_POOL_EINVAL;
    }
    pthread_mutex_lock(&p->mtx);
    struct label_rec *r = find_label(p, label);
    if (r != NULL && r->remaining > 0u) {
        r->cb = cb;
        r->cb_ud = cb_ud;
        pthread_mutex_unlock(&p->mtx);
        return 0;
    }
    /* Already idle (completed but uncollected) or unknown: fire now, unlocked. */
    int e = (r != NULL && r->has_err) ? r->err : 0;
    pthread_mutex_unlock(&p->mtx);
    cb(label, e, cb_ud);
    return 0;
}

int
ichor_pool_drain(ichor_pool_t *p, int timeout_ms)
{
    if (p == NULL) {
        return ICHOR_POOL_EINVAL;
    }
    struct timespec deadline;
    if (timeout_ms > 0) {
        deadline_from_ms(&deadline, timeout_ms);
    }

    pthread_mutex_lock(&p->mtx);
    while (p->inflight > 0u) {
        if (timeout_ms == 0) {
            pthread_mutex_unlock(&p->mtx);
            return 1;
        }
        if (timeout_ms < 0) {
            pthread_cond_wait(&p->cv_done, &p->mtx);
        } else {
            int rc = pthread_cond_timedwait(&p->cv_done, &p->mtx, &deadline);
            if (rc == ETIMEDOUT) {
                pthread_mutex_unlock(&p->mtx);
                return 1;
            }
        }
    }
    pthread_mutex_unlock(&p->mtx);
    return 0;
}

#else /* !ICHOR_WITH_THREADS: serial fallback */

/* Serial label record: no in-flight count is needed (every job finishes inline
 * at submit), only the aggregate error held until a wait collects it, plus the
 * cancel flag so a job may cancel its own group mid-batch. */
struct label_rec {
    struct label_rec *next;
    uint64_t label;
    int err;
    size_t err_index;
    int has_err;
    _Atomic int cancel;
};

struct ichor_pool {
    struct label_rec *labels;
    uint64_t next_label;
};

static struct label_rec *
find_label(ichor_pool_t *p, uint64_t label)
{
    for (struct label_rec *r = p->labels; r != NULL; r = r->next) {
        if (r->label == label) {
            return r;
        }
    }
    return NULL;
}

/* Find or create the record for `label` (never for label 0). Returns NULL on
 * allocation failure. */
static struct label_rec *
intern_serial(ichor_pool_t *p, uint64_t label)
{
    if (label == 0u) {
        return NULL;
    }
    struct label_rec *r = find_label(p, label);
    if (r != NULL) {
        return r;
    }
    r = calloc(1, sizeof(*r));
    if (r == NULL) {
        return NULL;
    }
    r->label = label;
    r->next = p->labels;
    p->labels = r;
    return r;
}

static void
record_serial(struct label_rec *r, size_t index, int rc)
{
    if (r == NULL) {
        return;
    }
    if (rc != 0 && (!r->has_err || index < r->err_index)) {
        r->has_err = 1;
        r->err = rc;
        r->err_index = index;
    }
}

int
ichor_pool_create(ichor_pool_t **out, unsigned nthreads)
{
    (void)nthreads;
    if (out == NULL) {
        return ICHOR_POOL_EINVAL;
    }
    *out = calloc(1, sizeof(**out));
    if (*out == NULL) {
        return ICHOR_POOL_ENOMEM;
    }
    (*out)->next_label = ICHOR_POOL_LABEL_BASE;
    return 0;
}

void
ichor_pool_destroy(ichor_pool_t *p)
{
    if (p == NULL) {
        return;
    }
    struct label_rec *r = p->labels;
    while (r != NULL) {
        struct label_rec *nx = r->next;
        free(r);
        r = nx;
    }
    free(p);
}

unsigned
ichor_pool_size(const ichor_pool_t *p)
{
    (void)p;
    return 1u;
}

int
ichor_pool_threaded(void)
{
    return 0;
}

uint64_t
ichor_pool_new_label(ichor_pool_t *p)
{
    if (p == NULL) {
        return 0u;
    }
    return p->next_label++;
}

int
ichor_pool_submit(ichor_pool_t *p, ichor_job_fn fn, void *ud, uint64_t label)
{
    if (p == NULL || fn == NULL) {
        return ICHOR_POOL_EINVAL;
    }
    int rc = fn(ud);
    record_serial(intern_serial(p, label), 0u, rc);
    return 0;
}

int
ichor_pool_submit_n(ichor_pool_t *p, size_t n, ichor_pool_fn fn, void *ud,
                    uint64_t label)
{
    if (p == NULL || fn == NULL) {
        return ICHOR_POOL_EINVAL;
    }
    struct label_rec *r = intern_serial(p, label);
    for (size_t i = 0; i < n; i++) {
        int rc = fn(i, ud);
        record_serial(r, i, rc);
    }
    return 0;
}

int
ichor_pool_submit_jobs(ichor_pool_t *p, ichor_job_info_t *jobs, size_t n,
                       uint64_t label)
{
    if (p == NULL || jobs == NULL) {
        return ICHOR_POOL_EINVAL;
    }
    if (n == 0) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        if (jobs[i].fn == NULL) {
            return ICHOR_POOL_EINVAL;
        }
    }

    struct label_rec *r = intern_serial(p, label);
    struct ichor_job_ctx ctx;
    ctx.cancel = (r != NULL) ? &r->cancel : NULL;
    ctx.worker = 0u; /* serial fallback: a single inline "worker" */

    for (size_t i = 0; i < n; i++) {
        jobs[i]._index = i;
        jobs[i]._label = label;
        jobs[i]._jfn = NULL;
        jobs[i]._ifn = NULL;
        jobs[i]._owns = 0u;
        jobs[i].err = 0;

        /* Honor a cancel requested by an earlier job in this same batch (the
         * only way a serial batch can be cancelled, since all jobs run inline
         * before submit returns). Skipped jobs are CANCELLED and do not run. */
        if (r != NULL &&
            atomic_load_explicit(&r->cancel, memory_order_relaxed)) {
            atomic_store_explicit(&jobs[i].state, ICHOR_JOB_CANCELLED,
                                  memory_order_relaxed);
            continue;
        }
        atomic_store_explicit(&jobs[i].state, ICHOR_JOB_RUNNING,
                              memory_order_relaxed);
        int rc = jobs[i].fn(i, jobs[i].ud, &ctx);
        jobs[i].err = rc;
        atomic_store_explicit(&jobs[i].state, ICHOR_JOB_DONE,
                              memory_order_relaxed);
        record_serial(r, i, rc);
    }
    return 0;
}

int
ichor_pool_cancel(ichor_pool_t *p, uint64_t label)
{
    if (p == NULL) {
        return ICHOR_POOL_EINVAL;
    }
    struct label_rec *r = find_label(p, label);
    if (r != NULL) {
        atomic_store_explicit(&r->cancel, 1, memory_order_relaxed);
    }
    return 0;
}

int
ichor_pool_wait(ichor_pool_t *p, uint64_t label, int timeout_ms, int *done,
                int *err)
{
    (void)timeout_ms;
    if (p == NULL) {
        return ICHOR_POOL_EINVAL;
    }
    struct label_rec *r = find_label(p, label);
    if (done != NULL) {
        *done = 1; /* serial work is always already finished */
    }
    if (err != NULL) {
        *err = (r != NULL && r->has_err) ? r->err : 0;
    }
    if (r != NULL) {
        /* collect */
        struct label_rec **pp = &p->labels;
        while (*pp != NULL && *pp != r) {
            pp = &(*pp)->next;
        }
        if (*pp != NULL) {
            *pp = r->next;
        }
        free(r);
    }
    return 0;
}

int
ichor_pool_on_label_done(ichor_pool_t *p, uint64_t label, ichor_label_cb cb,
                         void *cb_ud)
{
    if (p == NULL || cb == NULL) {
        return ICHOR_POOL_EINVAL;
    }
    struct label_rec *r = find_label(p, label);
    int e = (r != NULL && r->has_err) ? r->err : 0;
    cb(label, e, cb_ud); /* serial: the jobs already ran, so fire at once */
    return 0;
}

int
ichor_pool_drain(ichor_pool_t *p, int timeout_ms)
{
    (void)timeout_ms;
    if (p == NULL) {
        return ICHOR_POOL_EINVAL;
    }
    return 0; /* nothing is ever in flight on the serial path */
}

#endif /* ICHOR_WITH_THREADS */

/* ----- shared convenience (both builds) ------------------------------------- */

int
ichor_job_cancelled(const ichor_job_ctx_t *ctx)
{
    if (ctx == NULL || ctx->cancel == NULL) {
        return 0;
    }
    return atomic_load_explicit(ctx->cancel, memory_order_acquire) != 0;
}

unsigned
ichor_job_worker_index(const ichor_job_ctx_t *ctx)
{
    return (ctx != NULL) ? ctx->worker : 0u;
}

int
ichor_pool_parallel_for(ichor_pool_t *p, size_t n, ichor_pool_fn fn, void *ud)
{
    if (p == NULL || fn == NULL) {
        return ICHOR_POOL_EINVAL;
    }
    if (n == 0) {
        return 0;
    }
    uint64_t label = ichor_pool_new_label(p);
    int rc = ichor_pool_submit_n(p, n, fn, ud, label);
    if (rc != 0) {
        return rc;
    }
    int err = 0;
    int done = 0;
    rc = ichor_pool_wait(p, label, -1, &done, &err);
    if (rc != 0) {
        return rc;
    }
    return err;
}
