# libtalos_ichor

Shared, constant-time symmetric primitives for the **talos** family of
cryptographic libraries (`libtalos_voleith`, `libtalos_syndrome`, …).

Named for the ichor, the single vein of divine fluid that ran through the
bronze automaton **Talos**, because this is the common substance that flows
through every talos library: the low-level primitives they all depend on, in
one clean-room, constant-time place instead of duplicated per repo.

## What's inside

| Header | Provides |
|--------|----------|
| `<ichor/aes.h>`     | AES-128/192/256 forward cipher + key expansion (FIPS 197) and a constant-time CTR-mode keystream / PRG (`ichor_aes_ctr`: 96-bit nonce + 32-bit big-endian counter, fails closed at 2^32 blocks), runtime-dispatched: AES-NI (x86_64), VAES batched (x86_64), ARMv8 Crypto (aarch64), and a bitsliced constant-time software fallback. Batch entry points `ichor_aes_encrypt_wide` (many blocks, one key, up to 8) and `ichor_aes_encrypt_multikey` (one block per key). Forward direction only (no inverse cipher; CTR and the KDF need no decrypt). |
| `<ichor/hash.h>`    | SHA3-256, SHAKE-128, SHAKE-256 (FIPS 202), Keccak-f[1600] sponge, one-shot and incremental, plus 4-way batched SHAKE (`ichor_shake128_x4` / `ichor_shake256_x4`). Keccak backends: scalar, AVX2 4-way (x86_64), ARMv8.2 SHA-3 (aarch64). |
| `<ichor/grostl.h>`  | Grøstl-256 / Grøstl-512 (one-shot, incremental, and fixed-input single-compression node hashes), runtime-dispatched: AVX2+GFNI / AVX2 / AES-NI (x86_64), NEON (aarch64), and a bitsliced software fallback. |
| `<ichor/clmul.h>`   | 64×64→128-bit carry-less (polynomial) multiply: PCLMULQDQ (x86_64), PMULL (aarch64), and a constant-time scalar fallback. `ichor_clmul64_x2` computes two independent products per call. The shared atom for binary-field arithmetic. |
| `<ichor/aesdm.h>`   | AES-128 Davies-Meyer single-block compression. |
| `<ichor/hirose.h>`  | Hirose double-block-length compression over AES-256 (256-bit output). |
| `<ichor/gf2x.h>`    | Constant-time circulant arithmetic over F_2[x]/(x^p - 1) (multiply, rotate, invert) for QC-MDPC codes; the shared ring beneath libtalos_syndrome and libtalos_voleith. |
| `<ichor/gf256.h>`   | Constant-time GF(2^8) region multiply over the AES polynomial 0x11B (`ichor_gf256_mul_region` / `_muladd_region`): the Reed-Solomon / RLNC axpy. Runtime-dispatched: GFNI `GF2P8MULB`, AVX2 / SSSE3 split-nibble vpshufb (x86_64), NEON TBL (aarch64), and a constant-time scalar fallback. |
| `<ichor/gf16.h>`    | Constant-time GF(2^16) region multiply over 0x1100B (the network-coding / RLNC field), same API. Runtime-dispatched: GFNI affine, SSSE3 vpshufb (x86_64), NEON TBL (aarch64), and a constant-time scalar fallback. |
| `<ichor/sample.h>`  | Constant-time fixed-weight index sampling from a caller-supplied random tape: `ichor_sample_fixed_weight` draws `w` distinct indices in `[0, n)` in draw order (a pure function of the tape, fixed consumption) via overlay Fisher-Yates + widened Lemire reduction; `ichor_sample_sort_ascending` canonicalizes a drawn support to ascending order with a constant-time bitonic network. The shared support sampler for fixed-weight errors. |
| `<ichor/pool.h>`    | A worker pool for data-parallel work: submit fire-and-forget jobs tagged with a `uint64` label, then wait on (or poll, or get a callback for) the label; `ichor_pool_parallel_for` is kept as a blocking indexed-batch convenience. Non-crypto runtime support for consumers that fan independent work across cores; built on POSIX threads, with a serial fallback (`ICHOR_THREADS=OFF`) that keeps the same API. See [Thread pool](#thread-pool). |
| `<ichor/cpu.h>`     | Runtime CPU feature detection (cached bitmask) feeding the dispatch tables: AES-NI, VAES, CLMUL / VPCLMULQDQ, SSSE3 / SSE4.1, AVX2, GFNI (x86_64), ARMv8 AES / PMULL, NEON, ARMv8.2 SHA-3 (aarch64), plus detection-only AVX / FMA for consumers running their own kernels. Topology queries `ichor_cpu_physical_cores` / `ichor_cpu_logical_cpus` (hybrid-aware). |
| `<ichor/backend.h>` | Query which backend each primitive selected, and whether it is optimal for this CPU or a software fallback (see [CPU dispatch](#cpu-dispatch)). |
| `<ichor/util.h>`    | `ichor_secure_zero` (non-elidable wipe), `ichor_const_memcmp` (constant-time compare), and `ichor_ct_mask64` / `ichor_ct_select64` (opaque constant-time select). |

Every backend, including each software fallback, is constant-time in its
secret inputs; the dispatch decision is on public CPU-feature bits only.

## CPU dispatch

Each primitive selects its backend **once**, on first use, from the set
compiled into the build and the running CPU's features (`<ichor/cpu.h>`). The
choice is cached behind an atomic guard, so later calls pay one load and an
indirect branch, and the selection never changes for the life of the process.
Priority is hardware-accelerated backend first, constant-time software
fallback last. `ichor_aes_backend_name()` and friends report the active choice.

If a build omits a hardware backend but runs on a CPU that has the feature, the
library silently uses the (correct, slower) software path. **ichor never writes
to `stderr` or reads the environment to report this**, because a library may be
running with no terminal, or with its streams carrying protocol data. Instead the
condition is a query the application makes once at start-up and routes through
its own logging:

```c
#include <ichor/backend.h>

ichor_backend_report_t rep;
ichor_backend_report(&rep);
if (rep.aes == ICHOR_BACKEND_FALLBACK)
    app_log("ichor: AES on software fallback; rebuild with -DICHOR_AES_NI=ON");
```

`ichor_aes_backend_health()` / `ichor_clmul_backend_health()` /
`ichor_grostl_backend_health()` answer the same question per primitive. See
`tests/test_cpu_dispatch.c` for a worked consumer example.

The `ICHOR_FORCE_BACKEND` environment override (e.g. `aes:bitsliced` to pin the
software AES path) exists only to exercise the fallbacks on accelerated
hardware. It is a **test-only** facility, compiled in only for first-party /
test / dudect builds and absent from a release or vendored build.

### AVX-family features (AVX2 consumed; AVX / FMA detection-only)

`ichor_cpu_features()` reports `ICHOR_CPU_AVX`, `ICHOR_CPU_AVX2`, and
`ICHOR_CPU_FMA`. As of 1.3.0 `ICHOR_CPU_AVX2` steers ichor's own dispatch (the
AVX2 gf256 / Grøstl backends, 4-way Keccak, and the VAES AES path). `ICHOR_CPU_AVX`
and `ICHOR_CPU_FMA` steer no ichor dispatch (ichor uses no 128-bit-VEX AVX or FMA);
they are exposed so a consumer that runs its own kernels can drive tier selection
from the same cached feature word rather than duplicating CPUID logic. Each is
**OS-gated**: the bit is set only when the CPU advertises the feature *and* the OS
has enabled AVX state (OSXSAVE with `XCR0[2:1] == 0b11`), so seeing the bit means
the instruction is safe to issue without a first-use fault. FMA shares the AVX
YMM-state requirement.

## Thread safety

The library is safe to call from many threads with no locking and no required
init step. The only shared mutable state is the lazily-initialized dispatch
data (the cached CPU-feature word and each primitive's backend pointer), all
guarded by C11 atomics with acquire/release ordering. A first-use race is safe
by construction: the backend choice is deterministic, a compare-and-swap lets
exactly one publish win, and the selected ops tables are read-only thereafter.
So concurrent calls to `ichor_aes_encrypt`, `ichor_sha3_256`, `ichor_grostl256`,
`ichor_clmul64`, `ichor_backend_report`, and the rest are race-free, as are
`ichor_secure_zero` and `ichor_const_memcmp`.

Two caveats, both standard:

1. **A context object is not internally synchronized.** `ichor_aes_ctx_t`,
   `ichor_hash_ctx_t`, and `ichor_grostl_ctx_t` are caller-owned plain structs;
   using one context from multiple threads concurrently is a data race. Give
   each thread its own context (distinct contexts are fully independent).
2. **The test-only backend hooks are not thread-safe** and are not meant to be:
   `ichor_cpu_features_override()` and `ichor_*_dispatch_reset()` mutate the
   dispatch globals out from under concurrent users. They are single-threaded
   test scaffolding, compiled out of release / vendored builds entirely
   (`ICHOR_ENABLE_FORCE_BACKEND`), so a shipped consumer cannot reach them.

## Thread pool

`<ichor/pool.h>` is a general-purpose worker pool for data-parallel work, so
talos libraries that have batches of independent operations can spread them
across cores without each rolling its own threading. It contains **no
cryptography**; it is runtime/platform support that sits beside the CPU-dispatch
layer. The pool is created once and reused for many submissions. Work is
submitted as fire-and-forget jobs, each tagged with a caller-chosen `uint64`
**label**; the submitting thread does not block, and the caller later waits on
(or polls, or is called back on) the label:

```c
#include <ichor/pool.h>

static int work(size_t i, void *ud)
{
    struct job *jobs = ud;
    jobs[i].result = compute(&jobs[i]);  /* writes only its own slot */
    return 0;                            /* 0 ok, negative on error */
}

ichor_pool_t *pool = NULL;
if (ichor_pool_create(&pool, 0) != 0)    /* 0 => one worker per online CPU */
    return -1;

uint64_t label = ichor_pool_new_label(pool);        /* collision-free group id */
ichor_pool_submit_n(pool, njobs, work, jobs, label); /* enqueue, return at once */
/* ... do other work, or submit another group ... */

int done = 0, err = 0;
ichor_pool_wait(pool, label, -1, &done, &err);  /* -1: block until the group is done */

ichor_pool_destroy(pool);
```

A job writes whatever it produces into caller-owned memory reached through `ud`
(for an indexed batch, keyed by the job index); the pool itself stores no
per-job result, only, per label, a count of jobs still in flight and an
**aggregate error** (the lowest-numbered failing index wins). The call that
observes a label idle **collects** it, clearing the record, so a label's error
survives until someone waits for it even if the jobs finished first.

The surface:

- `ichor_pool_submit(p, fn, ud, label)` / `ichor_pool_submit_n(p, n, fn, ud, label)`
  enqueue one job, or `n` indexed jobs as one group, and return immediately.
  `submit_n` is the way to get well-defined group completion (the whole count is
  registered before any job runs).
- `ichor_pool_new_label(p)` returns a label value distinct from every other it
  returns and from small hand-picked literals, so independent subsystems sharing
  a pool need not coordinate.
- `ichor_pool_wait(p, label, timeout_ms, &done, &err)` follows the `poll(2)`
  timeout convention: `< 0` blocks, `0` returns at once (a non-blocking poll),
  `> 0` blocks up to that many milliseconds. `*done` says whether the label is
  idle; `*err` is its aggregate error.
- `ichor_pool_on_label_done(p, label, cb, cb_ud)` registers a one-shot
  completion callback (the event-style alternative to polling).
- `ichor_pool_drain(p, timeout_ms)` waits for the whole pool to go idle.
- `ichor_pool_parallel_for(p, n, fn, ud)` is retained as a blocking
  indexed-batch convenience (a fresh label, `submit_n`, then `wait(-1)`),
  returning the aggregate error.

**Concurrency contract.** The pool holds the only lock (its own queue and label
records); jobs take none. A job must touch only memory private to it (its own
output slot and any scratch it allocates) and read only state that stays
immutable while it runs. Job order, and which worker runs which job, are
unspecified, so **a correct job set must be order-independent**. Under that
contract submission is race-free with no caller locking. A worker may **not**
submit to the pool it runs on (that could deadlock a fixed worker set): such a
submit returns `ICHOR_POOL_EREENTRANT`. Submitting to a *different* pool from
within a job **is** supported, which is how nested parallelism is expressed (an
outer pool's job drives an inner pool; the pools' disjoint workers cannot
deadlock). A single waiter per label is expected; a second concurrent waiter is
rejected with `ICHOR_POOL_EBUSY` (a best-effort guard). Cancellation and
priorities are out of scope.

**Serial fallback.** Threading is a compile-time option, `ICHOR_THREADS`
(default `ON`). With it `OFF`, the same API compiles so that each job runs
inline on the submitting thread at submission time, links no threading library,
and (because a correct job set is order-independent) produces identical results,
only serial. So a platform or build without threads is never blocked, and the
serial build doubles as a deterministic single-threaded build for analysis
(AddressSanitizer / dudect). `ichor_pool_threaded()` reports which build this
is; consumers never need an `#ifdef`. `ichor_pool_create(&p, 0)` requests one
worker per online CPU; a non-zero count fixes the worker total.

## Testing

`ctest --test-dir build` runs the full suite. Correctness is anchored to
published vectors, not just round-trips:

- **AES** against FIPS 197 / NIST known-answer vectors (single block and
  Monte-Carlo chains), plus the bitsliced path checked against the same vectors.
- **SHA3-256 / SHAKE-128 / SHAKE-256** against the FIPS 202 / NIST example
  vectors, one-shot and incremental, including block-boundary and multi-block
  cases.
- **Grøstl-256 / Grøstl-512** against known-answer and Monte-Carlo test
  vectors.
- **GF(2^8) / GF(2^16) region multiply** and **4-way SHAKE** against the scalar /
  single-sponge oracle, with per-backend force profiles (`gf256:`, `gf16:`,
  `keccak:`) that exercise every compiled backend on one host.
- **Carry-less multiply, AES-DM, and Hirose** unit and consistency tests, plus
  dispatch tests that force each backend and confirm the software and hardware
  paths agree bit-for-bit.

### Timing-leakage validation (dudect)

Beyond source-level constant-time discipline (no secret branches, no
secret-indexed loads), the software paths carry an empirical backstop: a
[dudect](https://github.com/oreparaz/dudect)-style harness under `tools/dudect`
that times each primitive under two input classes and applies Welch's *t*-test
to the cycle samples. A small `|t|` over many samples is evidence of no
secret-dependent timing.

It validates the **software** backends (bitsliced AES, scalar carry-less
multiply, Grøstl); the hardware backends are single constant-time ISA
instructions and out of scope. It is off by default and is not a CTest (runs
are slow and host-noise-sensitive):

```sh
cmake -B build -DICHOR_BUILD_DUDECT=ON
cmake --build build --target dudect
```

Recorded results across x86_64 (Sandy Bridge, Gracemont) and aarch64 (Apple M1)
hosts live in [`docs/dudect-runs/`](docs/dudect-runs/) as the constant-time
evidence trail.

These results are specific to the compiler and flags they were produced under
(the default release configuration). Changing the toolchain version or build
flags can alter the emitted code and invalidate them; in particular, do not add
`-flto`, which can inline the out-of-line constant-time barriers
(`ichor_ct_mask64` / `ichor_ct_select64` / `ichor_const_memcmp`) and reintroduce
a secret-dependent branch. If you change either, re-running the harness and
re-checking the disassembly is the builder's responsibility.

## Provenance

Clean-room, no third-party code. Every primitive here (AES and CPU dispatch,
the FIPS 202 Keccak/SHAKE code, Grøstl, carry-less multiply, AES-DM, Hirose) is
first-party talos code, extracted from `libtalos_voleith`'s own clean-room
implementations and re-homed here under the neutral `ichor_` / `ICHOR_` prefix
so the talos libraries share one copy instead of duplicating it per repo.

## Consuming it

ichor is vendored (git submodule) into each talos library to preserve their
no-external-dependency invariant; it is not a system package. A consumer adds
the `include/` directory to its include path and links the `ichor` static
library (`libtalos_ichor.a`):

```c
#include <ichor/aes.h>
#include <ichor/hash.h>
#include <ichor/backend.h>   /* optional: report backend health at start-up */
```

Backend selection is lazy (on first use) and thread-safe, so there is no
required init call. If you want to log the fallback condition, call
`ichor_backend_report()` once at start-up as shown under
[CPU dispatch](#cpu-dispatch).

## Building

No external dependencies beyond a C17 toolchain and CMake ≥ 3.16. The one
system dependency is POSIX threads, pulled in only when the thread pool is
enabled (`ICHOR_THREADS=ON`, the default) and linked transitively to consumers;
`ICHOR_THREADS=OFF` links no threading library at all.

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

| Option | Default | Meaning |
|--------|---------|---------|
| `ICHOR_AES_NI`      | `ON`  | Compile the AES-NI backend (x86_64) |
| `ICHOR_AES_VAES`    | `ON`  | Compile the VAES batched AES backend (x86_64; needs AES-NI) |
| `ICHOR_AES_PREFER_VAES` | `ON` | Prefer VAES over AES-NI when both are present; `OFF` for split-256 cores (e.g. Gracemont) where AES-NI is faster |
| `ICHOR_ARMV8_AES`   | `ON`  | Compile the ARMv8 AES backend (aarch64) |
| `ICHOR_CLMUL`       | `ON`  | Compile the PCLMULQDQ carry-less-multiply backend (x86_64) |
| `ICHOR_PMULL`       | `ON`  | Compile the PMULL carry-less-multiply backend (aarch64) |
| `ICHOR_GROSTL_AVX2` / `_AVX2_GFNI` | `ON` | AVX2 and AVX2+GFNI Grøstl backends (x86_64) |
| `ICHOR_GF256_SSSE3` / `_AVX2` / `_GFNI` | `ON` | GF(2^8) region-multiply backends (x86_64) |
| `ICHOR_GF16_SSSE3` / `_GFNI` | `ON` | GF(2^16) region-multiply backends (x86_64) |
| `ICHOR_GF256_NEON` / `ICHOR_GF16_NEON` | `ON` | NEON TBL region-multiply backends (aarch64) |
| `ICHOR_KECCAK_X4_AVX2` | `ON` | AVX2 4-way Keccak-f[1600] backend (x86_64) |
| `ICHOR_KECCAK_SHA3` | `ON`  | ARMv8.2 SHA-3 Keccak-f[1600] backend (aarch64) |
| `ICHOR_THREADS`     | `ON`  | Build the thread pool (`<ichor/pool.h>`) on POSIX threads; `OFF` compiles the serial fallback and links no threading library |
| `ICHOR_BUILD_TESTS` | `ON`  | Build the known-answer test suite |
| `ICHOR_BUILD_DUDECT`| `OFF` | Build the dudect timing-validation harness (`tools/dudect`) |
| `ICHOR_BUILD_BENCH` | `OFF` | Build the micro-benchmark harness (`tools/bench`); run manually |
| `ICHOR_WERROR`      | on if top-level | Treat compiler warnings as errors |

The constant-time software fallbacks (bitsliced AES, scalar carry-less
multiply, software Grøstl) are always compiled; omitting a hardware backend
just yields a lean / portable build that runs correctly on the software path.
A probe that does not compile (wrong architecture or toolchain) disables the
corresponding backend automatically.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
