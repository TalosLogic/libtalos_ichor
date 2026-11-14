/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * pool.h - a worker pool with labelled, fire-and-forget job submission.
 *
 * A pool is created once with a fixed number of worker threads and reused for
 * many submissions.  Work is submitted as jobs that run on the workers; the
 * submitting thread does not block or participate.  Each job carries a caller
 * chosen uint64 LABEL, and the caller waits for (or polls, or is called back
 * on) the completion of every job sharing a label.  A label is nothing more
 * than a name for a group of related jobs: the pool tracks, per label, how many
 * of its jobs are still in flight and an aggregate error code.
 *
 * Results.  The pool stores no per-job result; a job writes whatever it
 * produces into caller-owned memory reached through its `ud` pointer (for an
 * indexed batch, keyed by the job index).  Because each job touches only memory
 * private to it (see the concurrency contract below), the caller may read every
 * slot once the label's wait reports done.  The only value the pool itself
 * keeps is the job's int return, folded into the label's aggregate error.
 *
 * Waiting.  ichor_pool_wait takes a timeout in the poll(2) convention: < 0
 * blocks until the label is idle, 0 returns immediately (a non-blocking poll),
 * > 0 blocks up to that many milliseconds.  It reports whether the label is
 * idle and the aggregate error, and the call that observes a label idle is the
 * one that COLLECTS it: the label's record is cleared then, so its error
 * survives until someone waits for it (even if the jobs finished first) and a
 * later submission under the same value starts a fresh group.  A single waiter
 * per label is expected; a second concurrent waiter is rejected with EBUSY (a
 * best-effort guard: it holds only for the duration of a blocking call, so two
 * timed-poll loops on one label can still interleave -- do not do that).
 *
 * Grouping.  To get well-defined group completion, submit a label's jobs as one
 * batch with ichor_pool_submit_n, or submit all of them before any can finish.
 * A label's count reaching zero is what unblocks a wait and fires a callback, so
 * building a group with separate ichor_pool_submit calls whose jobs may finish
 * between submissions leaves "done" ambiguous.  ichor_pool_new_label hands out
 * values distinct from one another (and from small hand-picked literals), so
 * independent subsystems sharing a pool need not coordinate label values.
 *
 * Concurrency contract.  The only synchronization inside the pool is its own
 * mutex/condvars; jobs take no pool locks.  A job must touch only memory private
 * to it (its own outputs and scratch) and read only state that stays immutable
 * while it runs.  Under that contract submission is race-free with no caller
 * locking.  The pool does not order jobs or bind them to particular workers, so
 * a correct job set is order-independent.  A worker may NOT submit to the pool
 * it runs on (that would be able to deadlock a fixed worker set): such a submit
 * returns ICHOR_POOL_EREENTRANT.  Submitting to a DIFFERENT pool from within a
 * job is fine, which is how nested parallelism is expressed (an outer pool's job
 * drives an inner pool).
 *
 * Build.  When ichor is built without threading (ICHOR_WITH_THREADS == 0) every
 * job runs inline on the submitting thread at submission time; the API and the
 * label bookkeeping are unchanged and results are identical, only serial.  See
 * docs/THREAD_POOL.md.
 */

#ifndef ICHOR_POOL_H
#define ICHOR_POOL_H

#include <stddef.h>
#include <stdint.h>

/*
 * The per-job status word (ichor_job_info_t.state) is written by a worker and
 * read by the caller concurrently, so it is a C11 atomic.  A C++ translation
 * unit that includes this header gets the layout-compatible std::atomic<int>.
 */
#ifdef __cplusplus
#include <atomic>
#else
#include <stdatomic.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Error codes.  0 on success, negative on failure, matching the library-wide
 * convention (see hash.h).
 */
#define ICHOR_POOL_EINVAL (-1)     /* bad argument (null out/pool/fn) */
#define ICHOR_POOL_ENOMEM (-2)     /* allocation failure */
#define ICHOR_POOL_EOS (-3)        /* OS thread-primitive failure */
#define ICHOR_POOL_EREENTRANT (-4) /* submit from a worker of this same pool */
#define ICHOR_POOL_EBUSY (-5)      /* a second concurrent waiter on one label */

typedef struct ichor_pool ichor_pool_t;

/*
 * A single job.  `ud` is the user pointer passed to submit.  Returns 0 on
 * success or a negative error code, folded into its label's aggregate error.
 * Must not submit to the pool it runs on (see the concurrency contract).
 */
typedef int (*ichor_job_fn)(void *ud);

/*
 * An indexed job, invoked once per index i in [0, n) by ichor_pool_submit_n /
 * ichor_pool_parallel_for.  `ud` is identical for every index; the index is the
 * key into the caller's per-job result memory.  Returns as ichor_job_fn does.
 */
typedef int (*ichor_pool_fn)(size_t i, void *ud);

/*
 * Label-completion callback (ichor_pool_on_label_done).  Invoked once, on the
 * worker that finishes the label's last job, with the aggregate error.  Runs
 * with no pool lock held; must not submit to the pool it is called from.
 */
typedef void (*ichor_label_cb)(uint64_t label, int err, void *cb_ud);

/*
 * Caller-owned job descriptors (see docs/THREAD_POOL.md Section 10).
 *
 * ichor_pool_submit_jobs takes an array of descriptors the CALLER owns and
 * reuses, so submission costs no per-job allocation, and the worker writes an
 * observable per-job status the caller may read while the batch is in flight.
 * ichor_pool_cancel requests cooperative, group-scoped cancellation.
 */

/*
 * Per-job state.  Written by the pool, read-only for the caller.  Monotonic:
 * PENDING -> RUNNING -> DONE, or PENDING -> CANCELLED; a terminal state never
 * changes.  CANCELLED means strictly that the job never entered its function
 * (it was skipped before starting); a job that ran, even one that honored the
 * cancel flag and returned early, ends DONE.
 */
typedef enum ichor_job_state {
    ICHOR_JOB_PENDING = 0, /* submitted, not yet picked up by a worker */
    ICHOR_JOB_RUNNING,     /* a worker is executing the job function   */
    ICHOR_JOB_DONE,        /* the function ran and returned; err valid */
    ICHOR_JOB_CANCELLED    /* skipped before the function ran          */
} ichor_job_state;

/*
 * Opaque per-invocation handle passed to a descriptor job.  It carries the
 * job's group cancel flag; it is valid only for the duration of the job call,
 * and using it after the call returns is undefined.
 */
typedef struct ichor_job_ctx ichor_job_ctx_t;

/*
 * A descriptor job.  `i` is the descriptor's position in the submitted array;
 * `ud` is the descriptor's own user pointer.  Returns 0 on success or a negative
 * error code, folded into the group's aggregate error (lowest index wins).  May
 * poll ichor_job_cancelled(ctx) in its own loop to exit early.  Must not submit
 * to the pool it runs on (see the concurrency contract).
 */
typedef int (*ichor_job_run_fn)(size_t i, void *ud, ichor_job_ctx_t *ctx);

/*
 * A caller-owned job descriptor.  The caller sets `fn` and `ud` before submit
 * and may READ `state` (and `err` once state == ICHOR_JOB_DONE) at any time
 * while the batch is in flight; it must not write any field, and must keep the
 * descriptor alive and untouched from submit until the batch's wait reports
 * done.  The underscore-prefixed fields are pool-owned: the pool sets them at
 * submit and the caller must not touch them while the job is in flight.
 */
typedef struct ichor_job_info {
    ichor_job_run_fn fn; /* caller-set: the job to run                  */
    void *ud;            /* caller-set: user pointer passed to fn       */
#ifdef __cplusplus
    std::atomic<int>
        state; /* pool-written, caller-read-only: ichor_job_state */
#else
    _Atomic int state; /* pool-written, caller-read-only: ichor_job_state */
#endif
    int err;            /* pool-written: fn return, valid at DONE   */
    size_t _index;      /* pool-owned: position in the array        */
    uint64_t _label;    /* pool-owned: the group label              */
    ichor_job_fn _jfn;  /* pool-owned: legacy single-job form, else NULL */
    ichor_pool_fn _ifn; /* pool-owned: legacy indexed form, else NULL    */
    unsigned _owns;     /* pool-owned: 1 if the pool allocated this node */
    struct ichor_job_info *_next; /* pool-owned: FIFO linkage                 */
} ichor_job_info_t;

/*
 * Create a pool with `nthreads` worker threads.  nthreads == 0 requests a
 * sensible default (the online CPU count, at least 1).  On a non-threaded build
 * no OS threads are created and work runs inline.  Writes the pool to *out.
 * Returns 0, or a negative code (ICHOR_POOL_*) on bad argument or resource
 * failure; on failure *out is set to NULL.
 */
int ichor_pool_create(ichor_pool_t **out, unsigned nthreads);

/*
 * Destroy a pool: signal the workers to exit, join them, and free all
 * resources, including any label records not yet collected.  NULL is a no-op.
 * Must not be called concurrently with any other use of the same pool, and no
 * job may still be in flight that the caller means to observe.
 */
void ichor_pool_destroy(ichor_pool_t *p);

/* Number of worker threads (1 on a non-threaded build). */
unsigned ichor_pool_size(const ichor_pool_t *p);

/*
 * 1 if this ichor was built with threading (ICHOR_WITH_THREADS), 0 otherwise.
 * A build-time property for reporting/logging.
 */
int ichor_pool_threaded(void);

/*
 * Return a label value distinct from every other value this function returns
 * for this pool, and from small hand-picked literals (the sequence starts well
 * above the range a caller is likely to type).  Never returns 0 (which means
 * "untracked": a job submitted under label 0 cannot be waited for).  Thread
 * safe.
 */
uint64_t ichor_pool_new_label(ichor_pool_t *p);

/*
 * Submit one job, tagged with `label`, and return immediately; the pool owns the
 * job and runs it on a worker.  label == 0 submits untracked work (no group to
 * wait on).  Returns 0, ICHOR_POOL_EINVAL (null pool/fn), ICHOR_POOL_ENOMEM, or
 * ICHOR_POOL_EREENTRANT (called from a worker of this pool).
 */
int ichor_pool_submit(ichor_pool_t *p, ichor_job_fn fn, void *ud,
                      uint64_t label);

/*
 * Submit `n` indexed jobs (fn(0,ud) .. fn(n-1,ud)) as ONE group under `label`,
 * and return immediately.  This is the way to get well-defined group completion
 * (the whole count is registered before any job runs).  n == 0 is a no-op
 * returning 0.  Returns as ichor_pool_submit does.
 */
int ichor_pool_submit_n(ichor_pool_t *p, size_t n, ichor_pool_fn fn, void *ud,
                        uint64_t label);

/*
 * Wait for `label` to go idle (every job sharing it finished).  timeout_ms < 0
 * blocks indefinitely, 0 returns at once (a non-blocking poll), > 0 blocks up to
 * that many milliseconds.  On return, *done (if non-NULL) is 1 iff the label is
 * idle, else 0 (timed out with work pending); *err (if non-NULL) is the label's
 * aggregate error, valid when *done is 1.  Observing the label idle COLLECTS and
 * clears its record, so call it once per group.  Returns 0, ICHOR_POOL_EINVAL,
 * or ICHOR_POOL_EBUSY if another thread is already waiting on this label.  An
 * unknown label (never submitted, or already collected) reports done with err 0.
 */
int ichor_pool_wait(ichor_pool_t *p, uint64_t label, int timeout_ms, int *done,
                    int *err);

/*
 * Register a one-shot completion callback for `label`, invoked when its last job
 * finishes (or immediately, on the calling thread, if the label is already
 * idle).  Replaces any previous callback for the label.  Firing the callback
 * does NOT collect the label: a wait is still what clears its record.  Returns 0
 * or ICHOR_POOL_EINVAL.
 */
int ichor_pool_on_label_done(ichor_pool_t *p, uint64_t label, ichor_label_cb cb,
                             void *cb_ud);

/*
 * Wait for the whole pool to go idle (no job of any label in flight).
 * timeout_ms as in ichor_pool_wait.  Does not collect any label.  Returns 0 if
 * the pool went idle, 1 if it timed out first, or ICHOR_POOL_EINVAL.
 */
int ichor_pool_drain(ichor_pool_t *p, int timeout_ms);

/*
 * Blocking indexed batch: submit n jobs under a fresh private label, wait for
 * them all, and return the aggregate error (the lowest-numbered failing index
 * wins, as before).  n == 0 returns 0.  A null fn or pool returns
 * ICHOR_POOL_EINVAL; a call from a worker of this pool returns
 * ICHOR_POOL_EREENTRANT.  Equivalent to submit_n + wait(-1), kept as the
 * convenience most call sites use.
 */
int ichor_pool_parallel_for(ichor_pool_t *p, size_t n, ichor_pool_fn fn,
                            void *ud);

/*
 * Submit a caller-owned array of `n` descriptors as ONE group under `label`,
 * fire-and-forget.  The pool sets each descriptor's state to PENDING, fills its
 * pool-owned fields, links it, and returns immediately; it allocates and frees
 * none of the descriptors (the caller owns them).  `label` follows the same
 * rules as ichor_pool_submit_n (0 is untracked; use ichor_pool_new_label per
 * batch to avoid merging counts across batches).  The array and every descriptor
 * must stay alive and untouched by the caller until this batch's wait reports
 * done.  n == 0 is a no-op returning 0.  Returns 0, ICHOR_POOL_EINVAL (null
 * pool/jobs, or any descriptor with a null fn), ICHOR_POOL_ENOMEM (the group
 * record), or ICHOR_POOL_EREENTRANT (called from a worker of this pool).
 */
int ichor_pool_submit_jobs(ichor_pool_t *p, ichor_job_info_t *jobs, size_t n,
                           uint64_t label);

/*
 * Request cancellation of the group `label`.  Idempotent; an unknown or
 * already-collected label is a no-op.  Two effects, by job state: a job still
 * queued (PENDING) is skipped by the pool and marked CANCELLED (and still runs
 * its completion accounting, so the group's wait completes); a job already
 * RUNNING is not forced, the pool only reports the request through
 * ichor_job_cancelled, and a running job that ignores it runs to DONE.  Returns
 * 0 or ICHOR_POOL_EINVAL.
 */
int ichor_pool_cancel(ichor_pool_t *p, uint64_t label);

/*
 * Return 1 if cancellation has been requested for this job's group, else 0.  A
 * descriptor job calls this in its own loop to exit early (cooperatively); the
 * pool does nothing to force a running job to stop.  A null ctx, or a job
 * submitted untracked (label 0), reports 0.
 */
int ichor_job_cancelled(const ichor_job_ctx_t *ctx);

/*
 * Index of the worker running this job, in [0, ichor_pool_size()).  Stable for
 * the duration of the call (a worker runs one job at a time), so it is the key
 * for per-worker scratch: a caller preallocates ichor_pool_size() slots and a
 * job uses slot[ichor_job_worker_index(ctx)].  On the non-threaded (serial)
 * build every job runs inline as worker 0.  A null ctx reports 0.
 */
unsigned ichor_job_worker_index(const ichor_job_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ICHOR_POOL_H */
