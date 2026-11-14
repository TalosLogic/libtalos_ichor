# ichor micro-benchmarks

Wall-clock throughput for ichor's primitives. These are measurement tools for
developers, not part of the test pipeline, and they serve every ichor consumer
(libtalos_voleith, libtalos_syndrome's Argo opener, libtalos_nephele), not just
one.

Each program links the real `ichor` library with all compiled-in hardware
backends active, prints the backend it actually selected, and reports per-case
`min` / `median` timing with a throughput (MB/s) or latency (ns/op) column.
Minimum is the cleanest estimate of intrinsic cost; median is the typical run.

## Programs

- `bench_aes` : single `encrypt`, `encrypt_x4`, and `encrypt_wide` at n=1..8.
- `bench_grostl` : `grostl256` / `grostl512` hashing and the fixed-input
  `compress_node` node hashes (the Argo-opener and Merkle-node primitive).
- `bench_hash` : SHA3-256 and SHAKE-128/256 (scalar Keccak-f[1600] baseline).
- `bench_gf256` / `bench_gf16` : region multiply and muladd (RS / RLNC axpy).

## Building

```
cmake -S . -B build -DICHOR_BUILD_BENCH=ON -DICHOR_ENABLE_FORCE_BACKEND=ON \
      -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/tools/bench/bench_grostl
```

`ICHOR_ENABLE_FORCE_BACKEND=ON` is optional but lets one binary compare
backends without a rebuild:

```
ICHOR_FORCE_BACKEND=aes:aesni  ./build/tools/bench/bench_aes
ICHOR_FORCE_BACKEND=aes:vaes   ./build/tools/bench/bench_aes
ICHOR_FORCE_BACKEND=gf256:scalar ./build/tools/bench/bench_gf256
ICHOR_FORCE_BACKEND=gf256:avx2   ./build/tools/bench/bench_gf256
ICHOR_FORCE_BACKEND=gf256:gfni   ./build/tools/bench/bench_gf256
```

Backend values: `aes:` aesni/vaes/bitsliced; `grostl:` soft/aesni/avx2;
`gf256:` and `gf16:` scalar/ssse3/avx2/gfni; `clmul:` scalar/pclmul/pmull.
A force can only step dispatch DOWN (clear higher features), never up, so
`gf256:gfni` on a non-GFNI host just runs that host's natural pick.

## Before / after across git revisions

A backend reworked in place (the Groestl AES-NI path went from SubBytes-only
SIMD to a full SIMD round, keeping the tag `"aesni"`) cannot be measured with a
runtime toggle: both revisions report the same backend. `run_ab.sh` builds the
suite against two revisions in throwaway worktrees and runs both, so that kind
of change shows its real speedup:

```
tools/bench/run_ab.sh                 # before = 2da76e0, after = HEAD
tools/bench/run_ab.sh <before> <after>
tools/bench/run_ab.sh 2da76e0 dirty   # after = current working tree
```

It writes `before.txt`, `after.txt`, and `forced.txt` (the backend toggles on
the target) under `bench-results/<timestamp>/`. The current checkout is never
modified.

**Dirty mode** (`after` = `dirty`) builds the current working tree as-is,
including uncommitted changes, instead of a committed revision. This is how you
measure a change before committing it, so a regression the bench reveals never
has to be committed first. The baseline is still a committed revision in a
throwaway worktree; only the `after` side is the live tree, built out-of-source
(it never modifies the working tree). It requires the bench harness already
wired into the working tree's `CMakeLists.txt`. The suite uses only ichor's public API, so it drops cleanly
onto older revisions; `bench_aes` guards its `encrypt_wide` section on
`ICHOR_AES_WIDE_MAX` and so reports `encrypt_x4` only on revisions that predate
the wide API.
