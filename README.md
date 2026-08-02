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
| `<ichor/aes.h>`     | AES-128/192/256 forward cipher + key expansion (FIPS 197) and a constant-time CTR-mode keystream / PRG (`ichor_aes_ctr`: 96-bit nonce + 32-bit big-endian counter, fails closed at 2^32 blocks), runtime-dispatched: AES-NI (x86_64), ARMv8 Crypto (aarch64), and a bitsliced constant-time software fallback. Forward direction only (no inverse cipher; CTR and the KDF need no decrypt). |
| `<ichor/hash.h>`    | SHA3-256, SHAKE-128, SHAKE-256 (FIPS 202), Keccak-f[1600] sponge, one-shot and incremental. |
| `<ichor/grostl.h>`  | Grøstl-256 / Grøstl-512 (one-shot, incremental, and fixed-input single-compression node hashes), runtime-dispatched over the same AES S-box backends. |
| `<ichor/clmul.h>`   | 64×64→128-bit carry-less (polynomial) multiply: PCLMULQDQ (x86_64), PMULL (aarch64), and a constant-time scalar fallback. The shared atom for binary-field arithmetic. |
| `<ichor/aesdm.h>`   | AES-128 Davies-Meyer single-block compression. |
| `<ichor/hirose.h>`  | Hirose double-block-length compression over AES-256 (256-bit output). |
| `<ichor/gf2x.h>`    | Constant-time circulant arithmetic over F_2[x]/(x^p - 1) (multiply, rotate, invert) for QC-MDPC codes; the shared ring beneath libtalos_syndrome and libtalos_voleith. |
| `<ichor/sample.h>`  | Constant-time fixed-weight index sampling from a caller-supplied random tape: `ichor_sample_fixed_weight` draws `w` distinct indices in `[0, n)` in draw order (a pure function of the tape, fixed consumption) via overlay Fisher-Yates + widened Lemire reduction; `ichor_sample_sort_ascending` canonicalizes a drawn support to ascending order with a constant-time bitonic network. The shared support sampler for fixed-weight errors. |
| `<ichor/cpu.h>`     | Runtime CPU feature detection (cached bitmask) feeding the dispatch tables. |
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

No external dependencies (C17 toolchain + CMake ≥ 3.16).

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

| Option | Default | Meaning |
|--------|---------|---------|
| `ICHOR_AES_NI`      | `ON`  | Compile the AES-NI backend (x86_64) |
| `ICHOR_ARMV8_AES`   | `ON`  | Compile the ARMv8 AES backend (aarch64) |
| `ICHOR_CLMUL`       | `ON`  | Compile the PCLMULQDQ carry-less-multiply backend (x86_64) |
| `ICHOR_PMULL`       | `ON`  | Compile the PMULL carry-less-multiply backend (aarch64) |
| `ICHOR_BUILD_TESTS` | `ON`  | Build the known-answer test suite |
| `ICHOR_BUILD_DUDECT`| `OFF` | Build the dudect timing-validation harness (`tools/dudect`) |
| `ICHOR_WERROR`      | on if top-level | Treat compiler warnings as errors |

The constant-time software fallbacks (bitsliced AES, scalar carry-less
multiply, software Grøstl) are always compiled; omitting a hardware backend
just yields a lean / portable build that runs correctly on the software path.
A probe that does not compile (wrong architecture or toolchain) disables the
corresponding backend automatically.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
