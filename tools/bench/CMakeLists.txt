# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# ichor micro-benchmark harness.  Each program links the real ichor library
# (all compiled-in hardware backends active) and measures one primitive
# family, printing the active backend name and per-case min / median timing
# with a throughput or ns/op column.
#
# Run manually; these are not part of the test pipeline.  See README.md and
# run_ab.sh for the before/after (two git revision) procedure.
#
# The programs touch only ichor's public API, so this directory also builds
# against older revisions of ichor: bench_aes.c guards its encrypt_wide
# section on ICHOR_AES_WIDE_MAX, and the gf256 / gf16 programs are added only
# when their headers are present (they are newer primitives).

set(_bench_progs bench_aes bench_grostl bench_hash)

if(EXISTS ${PROJECT_SOURCE_DIR}/include/ichor/gf256.h)
    list(APPEND _bench_progs bench_gf256)
endif()
if(EXISTS ${PROJECT_SOURCE_DIR}/include/ichor/gf16.h)
    list(APPEND _bench_progs bench_gf16)
endif()
# bench_keccak_x4 uses the 4-way SHAKE API (ichor_shake128_x4), a newer symbol;
# add it only where the header actually declares it so the suite still builds
# against an older ichor checkout in run_ab.sh.
file(READ ${PROJECT_SOURCE_DIR}/include/ichor/hash.h _ichor_hash_hdr)
string(FIND "${_ichor_hash_hdr}" "ichor_shake128_x4" _have_shake_x4)
if(NOT _have_shake_x4 EQUAL -1)
    list(APPEND _bench_progs bench_keccak_x4)
endif()
# bench_hash self-reports the single-sponge Keccak backend via
# ichor_keccak_f1600_backend_name(), a newer symbol; flag it only where hash.h
# declares it so bench_hash still builds (and links) against an older ichor
# checkout in run_ab.sh's baseline worktree.
string(FIND "${_ichor_hash_hdr}" "ichor_keccak_f1600_backend_name"
    _have_keccak_name)
unset(_ichor_hash_hdr)
# bench_clmul uses the 2-wide ichor_clmul64_x2 API, a newer symbol; add it only
# where clmul.h declares it so the suite still builds against an older checkout.
file(READ ${PROJECT_SOURCE_DIR}/include/ichor/clmul.h _ichor_clmul_hdr)
string(FIND "${_ichor_clmul_hdr}" "ichor_clmul64_x2" _have_clmul_x2)
if(NOT _have_clmul_x2 EQUAL -1)
    list(APPEND _bench_progs bench_clmul)
endif()
unset(_ichor_clmul_hdr)

foreach(_prog ${_bench_progs})
    add_executable(${_prog} ${_prog}.c)
    target_include_directories(${_prog} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/include)
    target_link_libraries(${_prog} ichor)
    set_target_properties(${_prog} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tools/bench)
endforeach()

if(TARGET bench_hash AND NOT _have_keccak_name EQUAL -1)
    target_compile_definitions(bench_hash PRIVATE ICHOR_BENCH_HAVE_KECCAK_NAME)
endif()
unset(_have_keccak_name)

unset(_bench_progs)
