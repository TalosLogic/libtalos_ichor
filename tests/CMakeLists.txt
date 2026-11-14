# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

# Test sources include the public headers and the internal headers
# (aes_ct64.h, aes_dispatch.h) by bare name, matching how they are written.
set(ICHOR_TEST_INCLUDES
    ${PROJECT_SOURCE_DIR}/include/ichor
    ${PROJECT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR})

# Register a test under two CTest names:
#   <NAME>     hardware profile -- runtime dispatch picks the best backend.
#   <NAME>_sw  software profile -- ICHOR_FORCE_BACKEND=aes:bitsliced forces the
#              constant-time bitsliced AES path even on AES-capable hardware, so
#              the software backend is validated on every host.
#
# Extra source files (e.g. the shared aes_kat_runner.c) follow TEST_SOURCE.
function(ichor_add_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE} ${ARGN})
    target_link_libraries(${TEST_NAME} PRIVATE ichor)
    target_include_directories(${TEST_NAME} PRIVATE ${ICHOR_TEST_INCLUDES})

    add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)

    add_test(NAME ${TEST_NAME}_sw COMMAND $<TARGET_FILE:${TEST_NAME}>)
    set_tests_properties(${TEST_NAME}_sw PROPERTIES
        ENVIRONMENT "ICHOR_FORCE_BACKEND=aes:bitsliced")
endfunction()

# Register a test that only runs in the hardware profile (no _sw variant).
# Use for detection-layer tests whose assertions cross-check the real CPU and
# would be made trivially wrong by the ICHOR_FORCE_BACKEND override.
function(ichor_add_hw_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE} ${ARGN})
    target_link_libraries(${TEST_NAME} PRIVATE ichor)
    target_include_directories(${TEST_NAME} PRIVATE ${ICHOR_TEST_INCLUDES})

    add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)
endfunction()

# AES: dispatch (public API) and bitsliced backend, against the shared NIST KAT
# runner.  Both get an _sw profile so the bitsliced path runs on hardware hosts.
ichor_add_test(test_aes      test_aes.c      aes_kat_runner.c)
ichor_add_test(test_aes_ct64 test_aes_ct64.c aes_kat_runner.c)

# CTR keystream (nonce/counter split): NIST SP 800-38A F.5 known-answer plus
# an independent-reference sweep, truncation, aliasing, and usage-cap checks.
ichor_add_test(test_aes_ctr test_aes_ctr.c)

# SHA-3 / SHAKE (FIPS 202).  The default profile runs the host's top Keccak-f
# backend (the ARMv8.2 SHA-3 single-sponge kernel on an aarch64 host that has
# it); the forced profile steps dispatch down to the scalar permutation
# (keccak:scalar clears SHA3), so one host validates both against the NIST
# vectors.  On a host without the SHA-3 extension the force is a no-op and the
# natural scalar run still validates the KAT.
ichor_add_test(test_hash test_hash.c)
add_test(NAME test_hash_scalar COMMAND $<TARGET_FILE:test_hash>)
set_tests_properties(test_hash_scalar PROPERTIES
    ENVIRONMENT "ICHOR_FORCE_BACKEND=keccak:scalar")

# 4-way batched SHAKE (ichor_shake128_x4 / _x4): validated lane-for-lane against
# the single-sponge oracle.  The default profile runs the host's top backend
# (AVX2 if present); the forced profile steps dispatch down to the portable 4x
# serial path (keccak:scalar clears AVX2), so one host validates both backends.
# On a host lacking AVX2 the force is a no-op and the natural scalar run still
# validates the KAT.
add_executable(test_keccak_x4 test_keccak_x4.c)
target_link_libraries(test_keccak_x4 PRIVATE ichor)
target_include_directories(test_keccak_x4 PRIVATE ${ICHOR_TEST_INCLUDES})
add_test(NAME test_keccak_x4 COMMAND $<TARGET_FILE:test_keccak_x4>)
add_test(NAME test_keccak_x4_scalar COMMAND $<TARGET_FILE:test_keccak_x4>)
set_tests_properties(test_keccak_x4_scalar PROPERTIES
    ENVIRONMENT "ICHOR_FORCE_BACKEND=keccak:scalar")

# Grøstl-256 / Grøstl-512.  test_grostl embeds a hand-picked NIST KAT subset
# and the node-hash contract (no file I/O).  test_grostl_kat and
# test_grostl_mct sweep the full official round-3 corpus from tests/KAT_MCT/;
# they read vector files, so they get ICHOR_TEST_SOURCE_DIR.  ichor now carries
# the whole core-primitive Grøstl suite; the consumer keeps only the
# circuit-level Grøstl tests.
ichor_add_test(test_grostl     test_grostl.c)
ichor_add_test(test_grostl_kat test_grostl_kat.c)
ichor_add_test(test_grostl_mct test_grostl_mct.c)

# The file-based sweeps locate tests/KAT_MCT/ relative to the ichor source root.
target_compile_definitions(test_grostl_kat PRIVATE
    ICHOR_TEST_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
target_compile_definitions(test_grostl_mct PRIVATE
    ICHOR_TEST_SOURCE_DIR="${PROJECT_SOURCE_DIR}")

# Grøstl dispatches on GFNI / AVX2 as well as AES-NI, so the generic
# aes:bitsliced _sw override no longer reaches the software path; point the
# three _sw profiles at the dedicated grostl:soft override instead.
set_tests_properties(test_grostl_sw test_grostl_kat_sw test_grostl_mct_sw
    PROPERTIES ENVIRONMENT "ICHOR_FORCE_BACKEND=grostl:soft")

# Extra KAT profiles so a single capable host validates every Grøstl backend:
# the 128-bit AES-NI round and the AVX2-widened round (the default picks
# avx2gfni on a GFNI host, so the plain run already covers it).  On a host
# lacking the forced backend the override is a no-op and the KAT still passes.
add_test(NAME test_grostl_kat_avx2 COMMAND $<TARGET_FILE:test_grostl_kat>)
set_tests_properties(test_grostl_kat_avx2 PROPERTIES
    ENVIRONMENT "ICHOR_FORCE_BACKEND=grostl:avx2")
add_test(NAME test_grostl_kat_aesni COMMAND $<TARGET_FILE:test_grostl_kat>)
set_tests_properties(test_grostl_kat_aesni PROPERTIES
    ENVIRONMENT "ICHOR_FORCE_BACKEND=grostl:aesni")

# The Monte Carlo chain is 100000 hashes per digest size; label it so CTest can
# exclude it from quick runs (ctest -LE slow).
set_tests_properties(test_grostl_mct test_grostl_mct_sw PROPERTIES LABELS slow)

# Security-critical utilities: constant-time compare and secure zeroing.
# No backend dispatch of its own; the _sw variant just matches the siblings.
ichor_add_test(test_util test_util.c)

# LSB-first bit packing (also in util.c): fixed vector, round-trip across
# non-byte-aligned widths, tail padding, argument validation, and the L5
# size_t-overflow guard.  Pure C, no backend dispatch.
ichor_add_test(test_bitpack test_bitpack.c)

# Fixed-weight index sampler (ichor/sample.h): tape accounting, all-zero KAT,
# equivalence to a reference full-array Fisher-Yates over the same tape, and
# argument validation.  The CT property is validated by the dudect target.
ichor_add_test(test_sample test_sample.c)

# Thread pool (ichor/pool.h): parallel_for correctness, no lost/duplicated
# index, determinism across worker counts and against a serial recomputation,
# lowest-index error propagation, and pool lifecycle/reuse.  The _sw variant is
# harmless (the pool does no ISA dispatch).  Builds and passes under both
# -DICHOR_THREADS=ON and -DICHOR_THREADS=OFF; CI should exercise both.
ichor_add_test(test_pool test_pool.c)

# Block-cipher compression primitives over AES (Hirose DBL, Davies-Meyer).
# Both get an _sw profile so the bitsliced AES path is exercised too.
ichor_add_test(test_hirose test_hirose.c)
ichor_add_test(test_aesdm  test_aesdm.c)

# CPU dispatch table; and feature detection (hardware-only: it cross-checks the
# real CPU, which the _sw override would contradict).
ichor_add_test(test_cpu_dispatch test_cpu_dispatch.c)
ichor_add_hw_test(test_cpu_features test_cpu_features.c)

# Carry-less multiply: hardware profile plus a _sw profile that forces the
# scalar fallback (clmul:scalar) rather than the aes:bitsliced override the
# generic helper applies, so the constant-time scalar path runs on every host.
add_executable(test_clmul test_clmul.c)
target_link_libraries(test_clmul PRIVATE ichor)
target_include_directories(test_clmul PRIVATE ${ICHOR_TEST_INCLUDES})
add_test(NAME test_clmul COMMAND $<TARGET_FILE:test_clmul>)
add_test(NAME test_clmul_sw COMMAND $<TARGET_FILE:test_clmul>)
set_tests_properties(test_clmul_sw PROPERTIES
    ENVIRONMENT "ICHOR_FORCE_BACKEND=clmul:scalar")
# Force clmul:pclmul so the 2-wide x2 path is validated against the hardware
# single mul (not just the scalar fallback covered by test_clmul_sw).  A
# no-op equivalent where pclmul is unavailable.
add_test(NAME test_clmul_pclmul COMMAND $<TARGET_FILE:test_clmul>)
set_tests_properties(test_clmul_pclmul PROPERTIES
    ENVIRONMENT "ICHOR_FORCE_BACKEND=clmul:pclmul")

# F_2[x]/(x^p - 1) ring: parameter-driven algebraic KAT.  Dispatches through
# clmul, so the _sw profile forces the scalar clmul fallback (matching
# test_clmul) rather than the aes:bitsliced override.
add_executable(test_gf2x test_gf2x.c)
target_link_libraries(test_gf2x PRIVATE ichor)
target_include_directories(test_gf2x PRIVATE ${ICHOR_TEST_INCLUDES})
add_test(NAME test_gf2x COMMAND $<TARGET_FILE:test_gf2x>)
add_test(NAME test_gf2x_sw COMMAND $<TARGET_FILE:test_gf2x>)

# GF(2^8) region multiply.  The default profile exercises the top backend the
# host offers (gfni > avx2 > ssse3); the forced profiles step the dispatch down
# one rung at a time so each compiled-in backend is validated against the same
# KAT.  A force that names a backend the host lacks cannot force dispatch UP, so
# it simply runs the natural pick (still a valid KAT run).
add_executable(test_gf256 test_gf256.c)
target_link_libraries(test_gf256 PRIVATE ichor)
target_include_directories(test_gf256 PRIVATE ${ICHOR_TEST_INCLUDES})
add_test(NAME test_gf256 COMMAND $<TARGET_FILE:test_gf256>)
add_test(NAME test_gf256_sw COMMAND $<TARGET_FILE:test_gf256>)
set_tests_properties(test_gf256_sw PROPERTIES
    ENVIRONMENT "ICHOR_FORCE_BACKEND=gf256:scalar")
add_test(NAME test_gf256_ssse3 COMMAND $<TARGET_FILE:test_gf256>)
set_tests_properties(test_gf256_ssse3 PROPERTIES
    ENVIRONMENT "ICHOR_FORCE_BACKEND=gf256:ssse3")
add_test(NAME test_gf256_avx2 COMMAND $<TARGET_FILE:test_gf256>)
set_tests_properties(test_gf256_avx2 PROPERTIES
    ENVIRONMENT "ICHOR_FORCE_BACKEND=gf256:avx2")
add_test(NAME test_gf256_gfni COMMAND $<TARGET_FILE:test_gf256>)
set_tests_properties(test_gf256_gfni PROPERTIES
    ENVIRONMENT "ICHOR_FORCE_BACKEND=gf256:gfni")

# GF(2^16) region multiply: per-backend KAT profiles (gfni > ssse3 > scalar).
# gf16 has no AVX2 vpshufb backend (dropped: a wash-to-regression vs SSSE3).
add_executable(test_gf16 test_gf16.c)
target_link_libraries(test_gf16 PRIVATE ichor)
target_include_directories(test_gf16 PRIVATE ${ICHOR_TEST_INCLUDES})
add_test(NAME test_gf16 COMMAND $<TARGET_FILE:test_gf16>)
add_test(NAME test_gf16_sw COMMAND $<TARGET_FILE:test_gf16>)
set_tests_properties(test_gf16_sw PROPERTIES
    ENVIRONMENT "ICHOR_FORCE_BACKEND=gf16:scalar")
add_test(NAME test_gf16_ssse3 COMMAND $<TARGET_FILE:test_gf16>)
set_tests_properties(test_gf16_ssse3 PROPERTIES
    ENVIRONMENT "ICHOR_FORCE_BACKEND=gf16:ssse3")
add_test(NAME test_gf16_gfni COMMAND $<TARGET_FILE:test_gf16>)
set_tests_properties(test_gf16_gfni PROPERTIES
    ENVIRONMENT "ICHOR_FORCE_BACKEND=gf16:gfni")
set_tests_properties(test_gf2x_sw PROPERTIES
    ENVIRONMENT "ICHOR_FORCE_BACKEND=clmul:scalar")
