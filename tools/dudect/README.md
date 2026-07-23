# dudect: empirical constant-time validation

A [dudect](https://github.com/oreparaz/dudect)-style timing-leakage harness
for ichor's **software** primitives. It times a function under two input
classes (A and B), then applies Welch's two-sample *t*-test to the cropped
cycle samples. A small `|t|` over many samples is evidence of no
secret-dependent timing; a large `|t|` is evidence of a leak.

This complements, and does not replace, the source-level constant-time
discipline (no secret branches, no secret-indexed memory). It is an
empirical backstop that catches leaks a compiler may have re-introduced.

## What it validates

Only the constant-time **software** paths. The harness library is built with
**no** `ICHOR_HAVE_*` hardware defines, so runtime dispatch can only select:

- **bitsliced AES** (`aes_ct64`): key-schedule and data-path, key-varying
  and plaintext-varying classes;
- **scalar carry-less multiply** (`clmul64_scalar`): multiplier-varying
  (`_b`) and multiplicand-varying (`_a`) classes.

Hardware backends (AES-NI, ARMv8 Crypto, PCLMULQDQ, PMULL) are single
constant-time instructions by ISA specification and are out of scope.

The two `sentinel_*` targets validate the *harness itself*: `sentinel_leak`
(a deliberately variable-time function) must FAIL, and `sentinel_clean` must
PASS. If a sentinel reports the wrong verdict, the host is too noisy to
trust the real results.

## Building and running

It is **off by default** and is a standalone executable, not a CTest; runs
are slow and host-noise-sensitive and must not gate CI.

```sh
cmake -B build -DICHOR_BUILD_DUDECT=ON
cmake --build build --target dudect
# disable frequency scaling first for stable numbers:
sudo cpupower frequency-set -g performance
./build/tools/dudect/dudect --all
./build/tools/dudect/dudect --target clmul64_scalar_b --verbose
./build/tools/dudect/dudect --list
```

Verdict per target: `|t| > 4.5` → **FAIL**; `|t| <= 4.5` with at least
100 000 samples/class → **PASS**; otherwise **INCONCLUSIVE** (collect more
samples with `--samples`). Process exit code is non-zero if any target
failed or was inconclusive.
