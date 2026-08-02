# Changelog

All notable changes to libtalos_ichor are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
