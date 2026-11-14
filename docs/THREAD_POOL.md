# ichor thread pool (`ichor/pool.h`)

Status: implemented in 1.3.0 (`include/ichor/pool.h`, `src/pool.c`, `tests/test_pool.c`). This
document is the self-contained specification it was built from; it remains the reference for the
contract and the rationale.

Note on scope drift: the shipped 1.3.0 public API is the labelled fire-and-forget pool in
`include/ichor/pool.h` (submit / submit_n / wait / on_label_done / drain, with persistent workers
that the submitting thread does not join). That supersedes the `parallel_for`-only, caller-
participates sketch in Sections 3 and 4 below, which are kept for the original rationale.
Section 10 specifies the caller-owned job descriptors with an observable per-job status and
per-group cancellation, and Section 11 the physical-core thread-count default. Both are now
implemented in 1.3.0 (same files as the base pool: `include/ichor/pool.h`, `include/ichor/cpu.h`,
`src/pool.c`, `src/cpu.c`, `tests/test_pool.c`), and Section 10 is the normative contract for that
surface; they update the non-goals in Section 9 accordingly. The subsections that read as build
guidance (10.7, 10.8, 11.1, 11.3) now record what was built and where its tests live.

## 1. Purpose

Add a small, general-purpose thread pool to ichor so that Talos libraries which depend on
ichor can parallelize independent work without each rolling its own threading. The first
consumer is libtalos_nephele (a post-quantum FHE library): its key generation and its CKKS
bootstrap have large batches of independent operations (per rotation-key generation, and the
per-diagonal rotations of the CoeffsToSlots / SlotsToCoeffs linear transforms). These are the
long poles: on an Apple M1, key generation is ~77 s and a single CoeffsToSlots stage is 400 s+.

The pool contains **no cryptography**. It is placed in ichor because ichor is already the Talos
low-level foundation layer that every library sits on: beyond its crypto primitives it already
carries non-crypto platform/runtime code (`cpu.h` + `cpu_*.c` for runtime CPU feature detection
and dispatch, `util.h` for secure-zero and constant-time helpers). A thread pool is the same
category of runtime/platform support, so it belongs beside those rather than being duplicated in
each consumer.

## 2. Design principles

1. **Lockless over the work; locks only in the pool's own dispatch machinery.** The pool holds
   exactly one mutex and condition variable (for its work queue and wake-ups) plus a join
   counter. The *tasks themselves* take no locks: each task writes only its own disjoint output
   and its own scratch, and reads only shared, immutable state. Callers are responsible for
   ensuring that partition (the API documents it; see Section 5).

2. **Order independence is the caller's contract.** The pool makes no guarantee about the order
   in which indices run or which worker runs which index. A correct caller must produce the same
   result regardless of order. nephele already satisfies this (its key derivation is a pure
   function of a per-key seed; its homomorphic reductions are exact integer modular adds, which
   are associative, so partial sums combine order-independently). This is what makes the serial
   fallback (Section 4) a pure performance toggle that never changes results.

3. **Serial fallback, never fail-to-build.** Threading is a compile-time option. When it is off,
   the same API compiles and runs, executing tasks inline on the calling thread. Because of
   principle 2, serial and threaded builds produce identical results, so a platform or build that
   cannot provide threads is never blocked; it is only slower. A disabled build links no threading
   library at all (see Section 6), which also makes it the natural "analysis build" for dudect /
   AddressSanitizer / disassembly, where deterministic single-threaded execution is wanted.

4. **One API, no `#ifdef` in consumers.** Consumers call the pool unconditionally. The threaded
   and serial behaviours differ only inside `pool.c`, selected by one compile define.

## 3. Public header: `include/ichor/pool.h`

```c
/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/*
 * ichor_pool - a small fixed-size worker pool for data-parallel work.
 *
 * The pool is created once with a fixed number of workers and reused for many
 * dispatches. ichor_pool_parallel_for runs an indexed task across the workers and
 * blocks until every index has completed: the canonical "fork a batch, join" step.
 *
 * Concurrency contract. The only synchronization inside the pool is its own queue
 * mutex/condvar and a join counter; tasks take no pool locks. A task invocation for
 * index i must touch only memory private to i (its own outputs and scratch) and read
 * only state that stays immutable for the whole dispatch. Under that contract the
 * dispatch is race-free with no caller locking. The pool does not guarantee the order
 * of indices or the worker assignment, so a correct task set is order-independent.
 *
 * Build. When ichor is built without threading (ICHOR_WITH_THREADS == 0) the pool runs
 * every task inline on the calling thread; the API is unchanged and results are
 * identical, only serial. See docs/THREAD_POOL.md.
 */

#ifndef ICHOR_POOL_H
#define ICHOR_POOL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ichor_pool ichor_pool_t;

/* A task over an index space. Invoked once per index i in [0, n). `ud` is the shared
 * user pointer passed to parallel_for, identical for every index. Returns 0 on success
 * or a negative error code; the first nonzero return from any index is surfaced by
 * parallel_for (see below). Must not call back into pool functions on the same pool. */
typedef int (*ichor_pool_fn)(size_t i, void *ud);

/* Create a pool with `nthreads` workers. nthreads == 0 requests a sensible default
 * (the online CPU count, at least 1). On a non-threaded build the count is clamped to
 * 1 and no OS threads are created. Writes the pool to *out. Returns 0, or a negative
 * error code (ICHOR_POOL_* ) on bad argument or resource failure; on failure *out is
 * set to NULL. */
int ichor_pool_create(ichor_pool_t **out, unsigned nthreads);

/* Destroy a pool: signal the workers to exit, join them, and free all resources. NULL
 * is a no-op. Must not be called concurrently with any other use of the same pool, and
 * no parallel_for on this pool may be in flight. */
void ichor_pool_destroy(ichor_pool_t *p);

/* Number of workers (1 on a non-threaded build, or when created with nthreads==1). */
unsigned ichor_pool_size(const ichor_pool_t *p);

/* 1 if this ichor was built with threading (ICHOR_WITH_THREADS), 0 otherwise. A pool
 * is not required to answer; this is a build-time property for reporting/logging. */
int ichor_pool_threaded(void);

/* Run fn(i, ud) for every i in [0, n) across the pool's workers and block until all
 * have returned. n == 0 is a no-op returning 0. If any invocation returns nonzero, the
 * remaining not-yet-started indices are still scheduled (the pool does not cancel), and
 * parallel_for returns the error code from the lowest-numbered failing index after the
 * whole batch has drained; if several fail, lower index wins. A null fn or pool returns
 * ICHOR_POOL_EINVAL. Re-entrant calls on the same pool from within a running task are
 * not supported. */
int ichor_pool_parallel_for(ichor_pool_t *p, size_t n, ichor_pool_fn fn, void *ud);

#ifdef __cplusplus
}
#endif

#endif /* ICHOR_POOL_H */
```

Error codes: follow ichor's existing return convention (0 success, negative on failure). Define
a small set in the header or reuse ichor's shared error enum if one exists; at minimum
`ICHOR_POOL_EINVAL` (bad argument) and `ICHOR_POOL_ENOMEM` / `ICHOR_POOL_EOS` (allocation or OS
thread-primitive failure). Match whatever `aes.h` / `hash.h` already do for consistency.

## 4. Implementation: `src/pool.c`

One translation unit with both implementations behind `#if ICHOR_WITH_THREADS` (Section 6 wires
the define). Keep the serial path first-class; it is tiny and is exercised in CI.

### 4.1 Serial build (`ICHOR_WITH_THREADS == 0`)

```c
struct ichor_pool { int dummy; };   /* opaque, no state needed */

int ichor_pool_create(ichor_pool_t **out, unsigned nthreads) {
    (void)nthreads;
    if (out == NULL) return ICHOR_POOL_EINVAL;
    *out = calloc(1, sizeof **out);
    return (*out != NULL) ? 0 : ICHOR_POOL_ENOMEM;
}
void ichor_pool_destroy(ichor_pool_t *p) { free(p); }
unsigned ichor_pool_size(const ichor_pool_t *p) { (void)p; return 1u; }
int ichor_pool_threaded(void) { return 0; }

int ichor_pool_parallel_for(ichor_pool_t *p, size_t n, ichor_pool_fn fn, void *ud) {
    if (p == NULL || fn == NULL) return ICHOR_POOL_EINVAL;
    int first_err = 0;
    for (size_t i = 0; i < n; i++) {
        int rc = fn(i, ud);
        if (rc != 0 && first_err == 0) first_err = rc;   /* lowest index wins */
    }
    return first_err;
}
```

This links no threading library and has no synchronization. It is the reference semantics the
threaded build must match exactly (same return value for the same task set).

### 4.2 Threaded build (`ICHOR_WITH_THREADS == 1`), POSIX pthreads

Structure:

- `struct ichor_pool` holds: the worker `pthread_t` array and count; a `pthread_mutex_t mtx`
  and `pthread_cond_t cv_work` (work available / shutdown) and `pthread_cond_t cv_done` (batch
  drained); the current batch descriptor; and a `shutdown` flag.
- A batch descriptor (one dispatch at a time; `parallel_for` is not re-entrant and is serialized
  by the caller using the pool from one thread): `{ ichor_pool_fn fn; void *ud; size_t n;
  size_t next; size_t remaining; int first_err; }`. `next` is the next index to claim; `remaining`
  counts indices not yet completed.
- Workers loop: lock `mtx`; wait on `cv_work` until there is an unclaimed index (`next < n`) or
  `shutdown`; if shutdown and no work, unlock and exit; otherwise claim `i = next++`, unlock, run
  `fn(i, ud)` **outside the lock**, relock, record the error if it is the new lowest
  (`if (rc && (first_err == 0 || i < err_index)) { first_err = rc; err_index = i; }`), decrement
  `remaining`, and if `remaining == 0` signal `cv_done`.
- `parallel_for`: fast-path `n == 0` returns 0; set up the batch under `mtx`, broadcast `cv_work`,
  then **also run as a worker on the calling thread** (claim-and-run the same loop) so the caller
  is not idle and small `n` needs no extra wake-ups; when `remaining` reaches 0, read `first_err`,
  clear the batch, unlock, return. The calling thread participating is what makes `nthreads == 1`
  behave like the serial path with no deadlock.
- `create`: resolve `nthreads` (0 -> `default_threads()`), allocate, init mutex/conds, spawn
  `nthreads - 1` persistent workers (the caller is the Nth participant during a dispatch). Spawning
  `nthreads - 1` means a 1-thread pool spawns none and runs entirely on the caller.
- `destroy`: lock, set `shutdown`, broadcast `cv_work`, unlock, `pthread_join` every worker, then
  destroy the primitives and free.

`default_threads()`: `sysconf(_SC_NPROCESSORS_ONLN)`, clamped to `>= 1`; on error return 1. (ichor
`cpu.c` detects ISA features, not core count, so the pool does its own count here.)

Claim indices one at a time via `next++` under the lock (dynamic work-stealing-ish balancing).
Per-index locking overhead is negligible for nephele's tasks (each index is milliseconds to
seconds). If a future consumer has very fine-grained tasks, add an optional grain/chunk parameter
then; do not add it speculatively.

Keep the lock discipline strict: the only code under `mtx` is queue bookkeeping (claim index,
record error, decrement counter, signal). `fn` always runs with the lock released.

## 5. Threading contract for consumers

Document in the header and honour in consumers:

- **Shared, read-only for the whole dispatch**: anything the tasks only read (in nephele: the
  secret key, the gadget tables, NTT twiddles, parameters). Never mutated during `parallel_for`.
- **Per-index private**: each task's output slot (e.g. `keys[i]`) and any scratch it allocates
  itself inside the task. No two indices touch the same bytes.
- **The pool owns the only lock.** Tasks must not need a mutex. If a task would need to serialize
  on shared mutable state, the work was mis-partitioned; restructure so each index is independent
  and combine results after the join (and only if the combine is order-independent).

## 6. Build integration (`CMakeLists.txt`)

Follow the existing `ICHOR_*` option conventions.

1. Add the option near the other feature options:
   ```cmake
   option(ICHOR_THREADS "Build the ichor thread pool (POSIX threads); OFF compiles a serial fallback" ON)
   ```
2. Add `src/pool.c` to `ICHOR_SOURCES` (always compiled; the serial path is inside it).
3. After `add_library(ichor ...)`, wire the define and the link:
   ```cmake
   if(ICHOR_THREADS)
       find_package(Threads REQUIRED)
       target_link_libraries(ichor PUBLIC Threads::Threads)
       target_compile_definitions(ichor PUBLIC ICHOR_WITH_THREADS=1)
   else()
       target_compile_definitions(ichor PUBLIC ICHOR_WITH_THREADS=0)
   endif()
   ```
   `PUBLIC` on both so consumers that include `ichor/pool.h` see the correct `ICHOR_WITH_THREADS`
   value and inherit the pthreads link transitively. This is the one place ichor gains a
   dependency; with `ICHOR_THREADS=OFF` no threading library is linked anywhere.
4. Feature-test macro: `pool.c` needs `_POSIX_C_SOURCE >= 200112L` (or `_DEFAULT_SOURCE`) for
   `pthread_*` and `sysconf(_SC_NPROCESSORS_ONLN)`. Set it at the top of `pool.c` before any
   include, or via `target_compile_definitions`. Match how the rest of ichor handles POSIX feature
   macros if it does so centrally.
5. Hardening flags already apply to all of `ICHOR_SOURCES` via the existing
   `target_compile_options(ichor PRIVATE ${ICHOR_HARDENING_COMPILE_OPTIONS})`; `pool.c` inherits
   them.

### Version / changelog
Bump the minor version (`include/ichor/version.h` and `project(VERSION)` in `CMakeLists.txt`, kept
in sync by the existing check) since this is an additive public API. Add a `CHANGELOG.md` entry
describing the new `ichor/pool.h`, the `ICHOR_THREADS` option, and the new (optional) pthreads
dependency.

## 7. Tests (`tests/`, via `ichor_add_test`)

Add `tests/test_pool.c`, registered with `ichor_add_test(test_pool test_pool.c)` (the `_sw` variant
the macro also creates is harmless here; the pool does not use ISA dispatch). CI should build and
run the suite **both** with `-DICHOR_THREADS=ON` and `-DICHOR_THREADS=OFF` so the serial path stays
correct and the two agree.

Cases:

1. **Correctness / sum**: `parallel_for` over `n` indices where `fn(i)` writes `out[i] = f(i)` into
   a caller array; assert every slot is set exactly once and equals `f(i)`. Run with n from 0 up
   past the worker count, including n < nthreads and n >> nthreads.
2. **No lost/duplicated index**: `fn(i)` sets a per-index flag (its own byte); after the join every
   flag is set exactly once (detects a claim race or an off-by-one in `next`/`remaining`).
3. **Order independence / determinism**: a task set whose result must not depend on order (e.g.
   each writes its own slot); run many times and with different `nthreads` (1, 2, size, 2*size) and
   assert identical output every time, and identical to the serial build.
4. **Error propagation**: some indices return a negative code; assert `parallel_for` returns the
   code of the **lowest** failing index, and that all indices still ran (the pool does not cancel).
5. **Reuse / lifecycle**: one pool, many `parallel_for` calls back to back; create/destroy with
   nthreads 0 (default), 1, and a large value; destroy a pool that never dispatched.
6. **Stress (ThreadSanitizer)**: a high-n dispatch with each task doing a short bounded loop over
   its own memory, run under `-fsanitize=thread` in CI, to prove the lock discipline is race-free.
   This is the primary guard that tasks and the queue never collide.

Determinism note: because the serial build is the reference semantics, test 3 can assert the
threaded result equals a serial recomputation in-process.

## 8. First consumer: libtalos_nephele

Not part of this document to implement, but the motivating use, so the API is validated against it:

- `neph_lrlwe_gen_rotation_keys` (`src/leveled/rotkeys.c`) already generates each rotation key from
  its own seed-derived PRG substream (a pure function of the keygen seed and the key's Galois
  element), with each key written to its own `keys[i]` slot and the shared secret key read-only.
  That loop becomes a single `ichor_pool_parallel_for` over the distinct keys. Its order
  independence is already proven by a serial test (`test_order_independent` in
  `tests/test_leveled_rotkeys.c`), so the threaded result must match the serial result byte for
  byte.
- Later: the CoeffsToSlots / SlotsToCoeffs baby-step/giant-step diagonal loops in
  `src/ckks/lintrans.c`.

nephele holds the pool on its context or keyset (created once), passes `&ks->sk`, the gadget, and
the output array through the `void *ud`, and indexes the distinct steps. nephele's own
`NEPH_*`/profile machinery is unaffected; it links ichor as it already does.

## 9. Non-goals (for now)

- ~~A heterogeneous "submit N different task closures" queue.~~ Provided in 1.3.0: see Section 10
  (`ichor_pool_submit_jobs` over a caller-owned descriptor array, each descriptor carrying its own
  `fn`/`ud`). The index-space `parallel_for` and the labelled `submit`/`submit_n` remain for the
  simple, no-status case.
- ~~Task cancellation~~ is provided in 1.3.0 as cooperative, group-scoped cancellation: see
  Section 10 (`ichor_pool_cancel`). Priorities, futures, nested/recursive dispatch, and work on the
  pool from inside a task remain unsupported; add only if a real need arises.
- A per-dispatch grain/chunk size. Add only if a consumer's tasks are too fine-grained for
  one-index-at-a-time claiming to amortize the queue lock.
- Any use of the pool inside ichor's own crypto primitives. The pool is provided *for consumers*;
  ichor's primitives stay single-threaded unless a separate, deliberate decision changes that.

## 10. Caller-owned job descriptors: observable status and cancellation (1.3.0)

Implemented in 1.3.0: `ichor_job_info_t`, `ichor_job_state`, `ichor_job_ctx_t`,
`ichor_pool_submit_jobs`, `ichor_pool_cancel`, and `ichor_job_cancelled` in
`include/ichor/pool.h` / `src/pool.c`, with tests in `tests/test_pool.c` (Section 10.8). The
contract below is the reference it was built to.

This section specifies an additive submission surface layered on the same label machinery as
`submit`/`submit_n`/`wait`. It gives a consumer three things the index-space API does not:
submission with no per-job allocation (the caller owns the job storage), a per-job status it can
read while the batch is in flight, and cooperative, group-scoped cancellation. Nothing here
changes `wait`, `on_label_done`, or `drain`; a batch submitted this way is waited on and collected
exactly like any other label.

### 10.1 Types and functions

```c
#include <stdatomic.h>
#include <stdint.h>

/* Per-job state, written by the pool, read-only for the caller. Monotonic:
 * PENDING -> RUNNING -> DONE, or PENDING -> CANCELLED. A terminal state never changes. */
typedef enum ichor_job_state {
    ICHOR_JOB_PENDING = 0, /* submitted, not yet picked up by a worker          */
    ICHOR_JOB_RUNNING,     /* a worker is executing fn                          */
    ICHOR_JOB_DONE,        /* fn ran and returned; .err is valid                */
    ICHOR_JOB_CANCELLED,   /* skipped before fn ran (never entered fn)          */
} ichor_job_state;

/* Opaque per-invocation handle passed to the job, carrying the group's cancel flag
 * and the running worker's index. */
typedef struct ichor_job_ctx ichor_job_ctx_t;

/* A caller-owned job. `i` is the descriptor's position in the submitted array. Returns
 * 0 or a negative error code, folded into the group's aggregate error (lowest index wins).
 * Must not submit to the pool it runs on (see the concurrency contract). */
typedef int (*ichor_job_run_fn)(size_t i, void *ud, ichor_job_ctx_t *ctx);

typedef struct ichor_job_info {
    /* ---- caller sets before submit (input); the pool only reads these ---- */
    ichor_job_run_fn fn;
    void            *ud;
    /* ---- pool writes (output); caller reads only, never writes while in flight ---- */
    _Atomic int      state; /* an ichor_job_state value */
    int              err;   /* fn's return, valid once state == DONE */
    /* ---- pool-owned internals; caller must not touch while in flight ---- */
    size_t           _index;
    uint64_t         _label;
    struct ichor_job_info *_next;
} ichor_job_info_t;

/* 1 if cancellation has been requested for this job's group, else 0. A cheap
 * acquire-load. The job calls this in its own loop to exit early (cooperatively). */
int ichor_job_cancelled(const ichor_job_ctx_t *ctx);

/* Index of the worker running this job, in [0, ichor_pool_size()). Stable for the
 * job's duration (a worker runs one job at a time), so it is the key for per-worker
 * scratch: a caller preallocates ichor_pool_size() slots and the job uses
 * slot[ichor_job_worker_index(ctx)]. On the serial build every job runs inline as
 * worker 0. A null ctx reports 0. */
unsigned ichor_job_worker_index(const ichor_job_ctx_t *ctx);

/* Submit a caller-owned array of n jobs as ONE group under `label`, fire-and-forget.
 * The pool sets each job's state to PENDING, links it, and returns immediately. label
 * follows the same rules as submit_n (0 is untracked; use ichor_pool_new_label per batch
 * to avoid merging counts across batches). Returns 0, ICHOR_POOL_EINVAL (null pool/jobs/
 * any fn), ICHOR_POOL_ENOMEM (group record), or ICHOR_POOL_EREENTRANT. */
int ichor_pool_submit_jobs(ichor_pool_t *p, ichor_job_info_t *jobs, size_t n,
                           uint64_t label);

/* Request cancellation of the group `label`. Idempotent; an unknown or already-collected
 * label is a no-op. Returns 0 or ICHOR_POOL_EINVAL. See 10.3 for the two effects. */
int ichor_pool_cancel(ichor_pool_t *p, uint64_t label);
```

### 10.2 Lifetime and the no-allocation property

The descriptor array, and every descriptor in it, must stay alive and untouched by the caller
from `ichor_pool_submit_jobs` until that batch's `wait` reports the label done. This is stricter
than the internal-node path (whose node lived only enqueue to dequeue): the pool reads a
descriptor's immutable input fields while the job runs and writes its `state`/`err`, so the
descriptor must outlive job completion, not just submission. For the normal blocking pattern
(submit then wait on the same thread) this is automatic; the one thing it forbids is a descriptor
array that is a stack local of a frame that returns before the `wait`.

Because the caller owns the storage, it allocates the array ONCE, outside any hot path, and reuses
it:

```c
ichor_job_info_t *jobs = calloc(max_batch, sizeof *jobs);   /* once, at setup */
/* per batch: */
for (size_t i = 0; i < n; i++) {
    jobs[i].fn = ...; jobs[i].ud = ...;
    atomic_store_explicit(&jobs[i].state, ICHOR_JOB_PENDING, memory_order_relaxed);
}
uint64_t label = ichor_pool_new_label(p);
ichor_pool_submit_jobs(p, jobs, n, label);
...
ichor_pool_wait(p, label, -1, &done, &err);   /* collects; array is now reusable */
```

The caller resets each descriptor's input fields and `state` to PENDING before each resubmit, and
only after the prior batch is collected. There is no per-job allocation on this path. The pool
still allocates one small group record per batch internally (the label record carrying the
remaining count, cancel flag, and aggregate error); that is one allocation per batch, not per job.
If a consumer needs literally zero steady-state allocation, that group record can be promoted to a
caller-owned struct passed alongside the array; it is not provided now, because one-per-batch is
negligible beside the work in a batch.

### 10.3 Cancellation semantics

`ichor_pool_cancel(p, label)` sets the group's cancel flag (a single release store). It has two
distinct effects, by job state:

1. **Queued, not yet started (PENDING).** The pool owns these completely. At the moment a worker
   would dequeue and start such a job, it instead sets `state = CANCELLED`, does not call `fn`, and
   runs the normal completion accounting (so the group count still reaches zero and `wait`
   completes). This is automatic and needs no cooperation from the job.
2. **Already started (RUNNING).** The pool does nothing to force these. The only thing it offers is
   `ichor_job_cancelled(ctx)`, which the job may poll in its own loop and return early from if it
   can do so cleanly. A job that ignores the flag runs to completion and ends DONE. A job that
   honors it still ends DONE (it entered `fn`); the pool cannot tell "ran fully" from "ran and
   bailed", so the caller encodes that distinction in its own return value or result slot if it
   needs it. CANCELLED is reserved strictly for jobs that never entered `fn`.

A cancelled batch therefore legitimately ends as a mix of CANCELLED (jobs that had not started) and
DONE (jobs already running, whether they bailed or finished). The caller's status scan must accept
that mix; it is not an error.

### 10.4 Soundness invariants (normative)

An implementation MUST preserve these; they are what make the status field and the two cancel
modes race-free.

1. **The run-vs-skip decision and the cancel-flag set are serialized by the pool mutex.** A worker
   decides a dequeued job's fate (set RUNNING and run, or set CANCELLED and skip) while holding the
   mutex, and `ichor_pool_cancel` sets the flag under the same mutex. This gives a total order:
   each job is either skipped or run, exactly once, never both and never lost, no matter how a
   cancel races a worker picking the job up.
2. **`state` is an atomic, written only by the pool, read-only for the caller, with
   release/acquire ordering.** The worker writes `err` (plain) and then release-stores
   `state = DONE`; a caller that acquire-loads DONE is guaranteed to see `err` and whatever the job
   wrote through `ud`. A plain `int` here would be a data race (undefined behavior). The caller
   never writes `state`, which removes any write-write hazard.
3. **A skipped (CANCELLED) job runs the same completion accounting as a completed one** (decrement
   the group's remaining count and the pool inflight count), minus calling `fn` and minus folding
   an error. Otherwise `wait` on a cancelled batch would never complete. Skip means "complete
   without running", not "disappear".
4. **CANCELLED means strictly never-entered-`fn`.** Anything that entered `fn` ends DONE, including
   a job that honored the cancel flag and returned early. This keeps the invariant
   `CANCELLED <=> fn never ran`, so the status is unambiguous. Cancellation is never folded into the
   aggregate error (it is not a failure).

State transitions are monotonic and terminal: PENDING to (RUNNING to DONE) or PENDING to CANCELLED,
never backward, and a cancel after a job reaches a terminal state is a no-op on that job.

### 10.5 Serial build (`ICHOR_WITH_THREADS == 0`)

`ichor_pool_submit_jobs` runs each job inline at submit, in index order, setting
PENDING -> RUNNING -> DONE on each descriptor synchronously (the atomics are uncontended but behave
identically). Because the whole batch runs before submit returns, a cancel issued afterward is a
no-op, and `ichor_job_cancelled(ctx)` reports 0 throughout unless a job cancels its own group from
inside `fn`. Results and aggregate error are identical to the threaded build, matching principle 3.

### 10.6 Notes

- **False sharing.** Adjacent descriptors' `state` words share cache lines, so several workers
  storing status plus a caller polling will bounce lines. The cost is bounded (at most two status
  stores per job lifetime) and the descriptors are not padded by default; padding a large array
  costs more than it saves. Note it only for very large `n`.
- **Relationship to the other APIs.** `submit_jobs` reuses the label record, so `wait`,
  `on_label_done`, and `drain` apply unchanged. `submit`/`submit_n`/`parallel_for` keep their
  allocating, status-less behavior for the simple case; they are not removed.
- **Reentrancy.** As with the rest of the pool, a job must not submit to the pool it runs on
  (ICHOR_POOL_EREENTRANT); driving a different pool from inside a job is the supported way to nest.

### 10.7 Implementation approach

This subsection records the structural decisions the contract above does not pin down, as built in
`src/pool.c` (1.3.0). It is not part of the consumer contract; it may be trimmed at release if it
turns out not to be publicly useful. The implementation follows every decision below.

**Queue node unification.** The shipped pool links an internally `calloc`'d `struct job` in its
FIFO and frees it after dequeue. For `submit_jobs` to be allocation-free, the caller's
`ichor_job_info_t` must itself be the queue node: the pool links it through the descriptor's own
`_next` and never allocates or frees it. Do not wrap each descriptor in an allocated node, which
would silently reintroduce the per-job allocation this whole surface exists to remove. The intended
structure is to make `ichor_job_info_t` the single FIFO node type for the threaded path and
re-express the legacy entry points on top of it:

- `submit` and `submit_n` allocate a small `ichor_job_info_t` (or an array of them) internally,
  fill `fn`/`ud`/`_index`, submit through the same enqueue path, and free them after dequeue
  (their allocating behavior is unchanged from the caller's point of view).
- `submit_jobs` enqueues the caller's descriptors directly and frees nothing.

A worker therefore always dequeues an `ichor_job_info_t *`; a per-node "pool owns this, free after
run" bit (or a separate internal free-list) distinguishes the legacy allocated nodes from
caller-owned ones so the worker frees only the former. The legacy `ichor_pool_fn` (`(size_t,
void *)`, no ctx) and the new `ichor_job_run_fn` (`(size_t, void *, ichor_job_ctx_t *)`) are
distinct function-pointer types; the node carries whichever one applies, and the worker passes a
ctx only to the ctx-bearing form. (If, during development, keeping two function-pointer types is
more friction than it is worth, the alternative is to give every path the ctx-bearing signature and
drop the old one, which is allowed since nothing public depends on the threading API yet.)

As built (1.3.0): the two-function-pointer approach was taken, so the legacy signatures are
unchanged and the change is purely additive. `ichor_job_info_t` is the single FIFO node; it carries
the public ctx-bearing `fn` plus pool-owned `_jfn` (legacy single-job), `_ifn` (legacy indexed),
and `_owns` (1 for pool-allocated legacy nodes, which the worker frees; 0 for caller descriptors).
`run_job` dispatches on whichever is set. The cancel flag is `_Atomic int cancel` on
`struct label_rec`, set under the mutex by `ichor_pool_cancel`; `ichor_job_ctx` is a worker-stack
object holding a pointer to it plus the worker's own index (passed to each worker at thread create
via a per-worker `{pool, idx}` arg on the pool, and surfaced to jobs by `ichor_job_worker_index`;
the serial build reports worker 0). The worker snapshots `label` / `index` / `owns` before unlocking, so
a caller that reclaims its descriptor array once the batch's wait returns never races the worker.

**Where the cancel flag lives, and the ctx.** The group's cancel flag is a new `_Atomic int cancel`
on the label record (`struct label_rec`), set by `ichor_pool_cancel` under the pool mutex (invariant
1) and never cleared for the life of that record (a collected-and-reinterned label starts a fresh
record with `cancel == 0`). `ichor_job_ctx_t` is a tiny worker-stack object the worker constructs
per job, holding a pointer to that `cancel` field (and, if convenient, the job's index); it is valid
only for the duration of the `fn` call, and passing it outside `fn` is undefined. `ichor_job_cancelled`
is an acquire-load of `*ctx->cancel`. The worker's dequeue step, under the mutex, reads the same
`cancel` field to decide skip-vs-run (invariant 1), sets `state` to CANCELLED or RUNNING
accordingly, and on the skip path runs the normal completion accounting (invariant 3) without
calling `fn`.

**Descriptor internal fields.** The pool overwrites `_index`, `_label`, and `_next` at submit, so
the caller need not clear them between batches; the caller resets only the input fields (`fn`,
`ud`) and `state` (to PENDING). `submit_jobs` sets `_index = i` (the array position) and
`_label = label` on each descriptor as it links it.

**Error paths.** `submit_jobs` allocates nothing of the caller's, so a mid-submit failure (for
example a label-record `calloc` failure) has nothing to unwind: set no state, enqueue nothing,
return `ICHOR_POOL_ENOMEM`. Model the enqueue/intern/broadcast sequence on `submit_n` in
`src/pool.c`; the only differences are the caller-owned nodes and setting `state = PENDING` under
the lock before the job can be dequeued.

### 10.8 Tests

Implemented in `tests/test_pool.c` as blocks 15-21 (run under both `-DICHOR_THREADS=ON` and
`-DICHOR_THREADS=OFF`, as the existing suite is). These cover the descriptor/status/cancel surface
specifically; the Section 7 cases still cover the index-space path. The cases below map to those
blocks (threaded-only cases are guarded by `ichor_pool_threaded()`, since a serial batch runs fully
at submit); block 21 is the cancel-races-dequeue case run under ThreadSanitizer.

1. **Status observability.** Submit a batch whose jobs block on a caller-controlled gate; before
   releasing the gate, assert some descriptors read RUNNING and the rest PENDING; after the gate and
   the `wait`, assert every descriptor reads DONE and `err` matches the job's return. On the serial
   build, each descriptor is DONE immediately after submit.
2. **Pending-skip cancel.** Submit `n` jobs with `n` well above the worker count, cancel the group
   almost immediately, and after `wait` assert: every descriptor is either DONE or CANCELLED, at
   least some are CANCELLED, CANCELLED descriptors never ran (a per-job "fn entered" byte they would
   have set is clear), and the batch still completed (the group count reached zero).
3. **Cooperative cancel, honored.** Jobs run a bounded loop that polls `ichor_job_cancelled` and
   returns early when set. Cancel mid-run; assert the honoring jobs end DONE (not CANCELLED, per
   invariant 4) and returned promptly (for example a side counter shows they stopped before their
   full iteration count).
4. **Cooperative cancel, ignored.** Jobs that never poll the flag run to completion after a cancel;
   assert they end DONE with their normal result, proving the pool forces nothing.
5. **CANCELLED/DONE mix and aggregate error.** In a cancelled batch, assert the status mix is
   accepted and that cancellation is not folded into the group's aggregate error (a batch cancelled
   with no failing job returns err 0; a batch with one genuinely failing index still returns that
   index's error).
6. **Array reuse.** One `calloc`'d descriptor array, many back-to-back batches (reset input fields +
   state to PENDING, fresh `ichor_pool_new_label` each batch); assert results are correct every
   batch and no per-batch leak (the array is never reallocated).
7. **Cancel races dequeue (ThreadSanitizer).** High-`n` batches cancelled from another thread at the
   same moment workers are claiming jobs, run under `-fsanitize=thread`; assert no job both ran and
   was marked CANCELLED, none was lost (every descriptor ends DONE or CANCELLED exactly once), and
   TSan is clean. This is the primary guard for invariant 1.
8. **Serial equivalence.** The same descriptor batches run on the `-DICHOR_THREADS=OFF` build
   produce identical results and aggregate errors to a serial recomputation, matching the existing
   determinism test for the index-space path.

## 11. Worker-count default: physical-core detection (1.3.0)

`ichor_pool_create(out, nthreads)` with `nthreads == 0` requests a sensible default. As of 1.3.0
that default is the number of **physical cores**, not the logical-CPU count. An explicit nonzero
`nthreads` is always honored verbatim; detection runs only for the `nthreads == 0` case, and the
caller can always override it. The count is a scheduling hint, not a correctness input: because the
task set is order-independent (Section 2), the result is identical for any worker count, so this
only affects speed.

Rationale: for the compute-bound GF(2) / AES-NI / vector work ichor's consumers run, hyperthread
siblings contend for the same execution ports, so a physical-core count usually beats the logical
count. It is only a default, though. A memory-stall-bound workload can benefit from HT filling idle
slots, which is exactly why detection is confined to `nthreads == 0` and the caller's explicit
value wins.

### 11.1 Detection ladder

Detection asks the OS for topology. It does **not** use CPUID: the tempting CPUID shortcut (read
the SMT-level shift from leaf 0x1F/0x0B and divide the logical count) is wrong on hybrid parts. On
an Intel P/E CPU such as the i9-13950HX (8 P-cores with SMT=2 plus 16 E-cores with SMT=1: 24
physical cores, 32 logical threads) `logical / 2` yields 16, not 24. Correct CPUID topology on a
hybrid machine would require pinning a thread to every logical CPU and reading each APIC ID, far
more code and fragile across offline CPUs. The OS topology views below are correct on hybrid parts
for free, which is the same choice zstd's `UTIL_countPhysicalCores` makes.

Implemented as non-crypto helpers in `cpu.c` (platform/runtime detection, the same category as the
existing ISA detection), declared in `include/ichor/cpu.h`; `default_threads()` in `pool.c` calls
`ichor_cpu_physical_cores()` for the `nthreads == 0` default:

```c
unsigned ichor_cpu_physical_cores(void);  /* physical cores, >= 1; best effort */
unsigned ichor_cpu_logical_cpus(void);    /* logical CPUs (SMT siblings counted), >= 1 */
```

`ichor_cpu_physical_cores` tries, in order, and returns the first that succeeds:

1. **Linux**: enumerate `/sys/devices/system/cpu/cpu*/topology/thread_siblings_list` and count the
   distinct sibling groups (each group is one physical core; HT siblings share a group). This is
   correct on hybrid CPUs. If sysfs is unavailable, parse distinct `(physical id, core id)` pairs
   from `/proc/cpuinfo`.
2. **macOS**: `sysctlbyname("hw.physicalcpu", ...)` (as opposed to `hw.logicalcpu`).
3. **Fallback**: the logical count from `sysconf(_SC_NPROCESSORS_ONLN)`, clamped to `>= 1`. This is
   also the whole implementation of `ichor_cpu_logical_cpus`. Falling back to logical is safe: it
   just means no physical/logical distinction was available, so the old behavior is preserved.

Windows is out of scope while the pool is pthreads-only; if a Windows path is added later, the
physical-core query there is `GetLogicalProcessorInformationEx` counting `RelationProcessorCore`
records.

Reads happen once, at pool creation, so cost is irrelevant and there is no constant-time concern
(nothing here is secret-dependent). Detection never reports 0: every path clamps to at least 1, so
`default_threads()` always yields a usable count.

### 11.2 What detection deliberately does not do

It does not distinguish core types or place work on them. On a hybrid CPU the physical-core count
lumps P-cores and E-cores together; preferring P-cores for crypto would need affinity pinning and
is out of scope for a portable default. Detect the physical count and stop there.

Behavior-change note for the 1.3.0 bump: the `nthreads == 0` default changes from the logical count
to the physical count. A consumer that was relying on the logical count as the default should pass
an explicit `nthreads` (for example `ichor_cpu_logical_cpus()`), which is honored unchanged.

### 11.3 Tests

Implemented in `tests/test_pool.c` as block 22:

1. **Sane counts**: `ichor_cpu_physical_cores()` and `ichor_cpu_logical_cpus()` both return `>= 1`,
   and physical `<=` logical. (Exact values are machine-dependent and not asserted.)
2. **Default wiring**: a pool created with `nthreads == 0` reports `ichor_pool_size()` equal to
   `ichor_cpu_physical_cores()` on the threaded build, and 1 on the serial build.
3. **Explicit override honored**: a pool created with an explicit `nthreads` (including a value
   larger than the physical-core count) reports exactly that size, confirming detection is bypassed
   when `nthreads != 0`.
