# Changelog

All notable changes to libtalos_ichor are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.3.0

### Added

- `<ichor/pool.h>`: a non-crypto worker pool for data-parallel work. Fire-and-forget
  jobs tagged with a `uint64` label; wait, poll, or get a callback on a label.
  `ichor_pool_submit` / `_submit_n` / `_submit_jobs` (the last over a caller-owned
  `ichor_job_info_t` array with observable per-job state and group cancellation),
  `ichor_pool_wait` (`poll(2)` timeout convention), `ichor_pool_on_label_done`,
  `ichor_pool_drain`, and the blocking `ichor_pool_parallel_for`. `ICHOR_THREADS`
  (default ON) selects the pthreads implementation; OFF compiles an identical-result
  serial fallback that links no threading library. First consumer: libtalos_nephele.
- `<ichor/gf256.h>`: constant-time GF(2^8) region multiply over poly 0x11B
  (`ichor_gf256_mul_region`, `ichor_gf256_muladd_region`): the Reed-Solomon / RLNC
  axpy. Dispatch GFNI (`GF2P8MULB`) > AVX2 > SSSE3 (split-nibble vpshufb) > NEON TBL
  > scalar.
- `<ichor/gf16.h>`: constant-time GF(2^16) region multiply over poly 0x1100B (the
  network-coding / RLNC field), same API. Dispatch GFNI affine (`GF2P8AFFINEQB`) >
  SSSE3 > NEON TBL > scalar.
- `<ichor/hash.h>`: 4-way batched SHAKE `ichor_shake128_x4` / `ichor_shake256_x4`
  (shared `inlen` / `outlen`), over one AVX2 Keccak-f[1600]x4, ARMv8.2 SHA-3, or a
  4x-serial fallback; each lane byte-identical to `ichor_shakeN`.
- ARMv8.2 SHA-3 (FEAT_SHA3) Keccak-f[1600] backend accelerating single-sponge
  SHA3/SHAKE and the 4-way batch on aarch64; byte-identical to the scalar path.
- `<ichor/aes.h>`: `ichor_aes_encrypt_wide` (up to `ICHOR_AES_WIDE_MAX` = 8 blocks,
  with a VAES backend on VAES+AVX2 hosts) and `ichor_aes_encrypt_multikey` (one block
  per key). `encrypt_x4` now forwards to `encrypt_wide(..., 4)`.
- `<ichor/clmul.h>`: `ichor_clmul64_x2`, two independent 64x64->128 products per call
  (output identical to two `ichor_clmul64`; halves per-call dispatch overhead).
- `<ichor/cpu.h>`: feature bits `ICHOR_CPU_GFNI`, `ICHOR_CPU_VPCLMULQDQ`,
  `ICHOR_CPU_VAES`, `ICHOR_CPU_SHA3`, `ICHOR_CPU_NEON`; topology queries
  `ichor_cpu_physical_cores` / `ichor_cpu_logical_cpus` (correct on hybrid P/E CPUs).
  `ichor_pool_create(_, 0)` now defaults to the physical-core count.
- `tools/bench`: a micro-benchmark harness (`ICHOR_BUILD_BENCH`, default OFF, run
  manually), with `run_ab.sh` for a before/after run across two git revisions.

### Changed

- Grøstl x86: P and Q now run the full round in SIMD, with AVX2-widened backends that
  lockstep P and Q in YMM lanes (one with a GFNI `GF2P8AFFINEINVQB` S-box, one with
  the AES-NI split-lane S-box for AVX2 hosts without GFNI). Dispatch GFNI+AVX2 > AVX2
  > AES-NI > ARMv8 > soft. Byte-identical (KAT/MCT).
- Grøstl ARMv8: full round in NEON (ShiftBytes via `vqtbl1q_u8`, branchless-xtime
  MixBytes) instead of SubBytes-only plus scalar helpers. Byte-identical.
- AES: VAES-vs-AES-NI preference is now the `ICHOR_AES_PREFER_VAES` build option
  (default ON; turn OFF for split-256 cores such as Gracemont). `encrypt_x4` calls the
  backend wide op directly instead of routing through `encrypt_wide`.
- `ICHOR_FORCE_BACKEND` (test-only) gains `gf256` (ssse3/avx2/gfni), `gf16`
  (ssse3/gfni), `grostl` (soft/aesni/avx2), and `keccak` (scalar) domains, so one host
  can exercise every backend.

## 1.2.0

### Added

- `<ichor/cpu.h>`: OS-gated AVX / AVX2 / FMA detection (`ICHOR_CPU_AVX`,
  `ICHOR_CPU_AVX2`, `ICHOR_CPU_FMA`) in the `ichor_cpu_features()` bitmask. These
  256-bit-vector features steer no ichor dispatch (ichor's own primitives do not
  use them); they are reported so a consumer running its own 256-bit kernels can
  drive tier selection from the same cached feature word. Each bit is set only
  when the CPU advertises the feature and the OS has enabled AVX state (OSXSAVE,
  `XCR0[2:1] == 0b11`), so seeing the bit means the instruction is safe to issue
  (#24).

## 1.1.0

### Added

- `<ichor/gf2x.h>`: constant-time binary-polynomial arithmetic over the circulant
  ring `F_2[x]/(x^p - 1)`, shared with libtalos_syndrome's QC-MDPC KEM: multiply,
  add, load/store, secret-amount cyclic rotation, and Itoh-Tsujii inversion.
  Ships with `ichor_ct_mask64` /
  `ichor_ct_select64` in `<ichor/util.h>`, which keep the variable-rotation
  branchless select constant-time under -O3 (a clang miscompile otherwise
  reintroduced a secret-dependent branch); verified at the asm level and via
  dudect (#21).
- `<ichor/sample.h>`: constant-time fixed-weight index sampler shared by
  libtalos_syndrome and libtalos_voleith. `ichor_sample_fixed_weight` draws w
  distinct indices in `[0, n)` from a caller-supplied tape in draw order (a pure
  function of the tape, fixed consumption); `ichor_sample_sort_ascending`
  canonicalizes a drawn support to ascending order with a constant-time bitonic
  network, for consumers that hash the sparse list as an ordered list. Own test
  suite and dudect target (#22).
- `<ichor/gf2x.h>`: `ichor_gf2x_scatter`, the constant-time word-parallel
  fixed-weight-support to dense-ring-element scatter, generalized with a
  `base`/`span` offset so it serves both syndrome's per-block error assembly and
  the voleith opener's `M*e^T`. De-duplicates the copy that lived in both
  consumers. Test + dudect target (`gf2x_scatter`).

## 1.0.0

Initial release: the layer-0 shared symmetric-primitive core extracted from
libtalos_voleith `core/`, consumed by libtalos_voleith and libtalos_syndrome.

- AES, AES-DM, Grøstl, and SHAKE, with runtime CLMUL / AES-NI backend dispatch
  and a portable software fallback.
- `ichor_secure_zero` and `ichor_const_memcmp` utilities.
- Per-primitive dudect timing harnesses and known-answer vectors.
