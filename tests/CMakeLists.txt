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

# SHA-3 / SHAKE (FIPS 202).
ichor_add_test(test_hash test_hash.c)

# Grøstl-256 / Grøstl-512.  test_grostl embeds a hand-picked NIST KAT subset
# and the node-hash contract (no file I/O).  test_grostl_kat and
# test_grostl_mct sweep the full official round-3 corpus from tests/KAT_MCT/;
# they read vector files, so they get ICHOR_TEST_SOURCE_DIR.  All three get the
# _sw variant, which forces the bitsliced SubBytes path (Grøstl dispatches on
# the same AES feature bits).  ichor now carries the whole core-primitive
# Grøstl suite; the consumer keeps only the circuit-level Grøstl tests.
ichor_add_test(test_grostl     test_grostl.c)
ichor_add_test(test_grostl_kat test_grostl_kat.c)
ichor_add_test(test_grostl_mct test_grostl_mct.c)

# The file-based sweeps locate tests/KAT_MCT/ relative to the ichor source root.
target_compile_definitions(test_grostl_kat PRIVATE
    ICHOR_TEST_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
target_compile_definitions(test_grostl_mct PRIVATE
    ICHOR_TEST_SOURCE_DIR="${PROJECT_SOURCE_DIR}")

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
