# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only

cmake_minimum_required(VERSION 3.16)
project(libtalos_ichor VERSION 1.1.0 LANGUAGES C
    DESCRIPTION "Shared constant-time symmetric primitives for the talos libraries")

# include/ichor/version.h is the consumer-facing statement of the same
# version; refuse to configure if the two drift.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/include/ichor/version.h" _ichor_ver_lines
    REGEX "#define ICHOR_VERSION_(MAJOR|MINOR|PATCH)")
string(REGEX MATCH "ICHOR_VERSION_MAJOR ([0-9]+)" _ "${_ichor_ver_lines}")
set(_ichor_hdr_major "${CMAKE_MATCH_1}")
string(REGEX MATCH "ICHOR_VERSION_MINOR ([0-9]+)" _ "${_ichor_ver_lines}")
set(_ichor_hdr_minor "${CMAKE_MATCH_1}")
string(REGEX MATCH "ICHOR_VERSION_PATCH ([0-9]+)" _ "${_ichor_ver_lines}")
set(_ichor_hdr_patch "${CMAKE_MATCH_1}")
set(_ichor_hdr_version "${_ichor_hdr_major}.${_ichor_hdr_minor}.${_ichor_hdr_patch}")
if(NOT _ichor_hdr_version VERSION_EQUAL PROJECT_VERSION)
    message(FATAL_ERROR "include/ichor/version.h says ${_ichor_hdr_version} but project(VERSION) says ${PROJECT_VERSION}; keep them in sync")
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Build options.  Omit a hardware backend for a lean / portable-only build;
# the constant-time bitsliced AES fallback is always compiled in.
option(ICHOR_AES_NI    "Compile the AES-NI backend (x86_64)"  ON)
option(ICHOR_ARMV8_AES "Compile the ARMv8 AES backend (aarch64)" ON)
option(ICHOR_CLMUL     "Compile the PCLMULQDQ carry-less mul backend (x86_64)" ON)
option(ICHOR_PMULL     "Compile the PMULL carry-less mul backend (aarch64)" ON)
option(ICHOR_BUILD_TESTS "Build the test suite" ON)
option(ICHOR_BUILD_DUDECT "Build the dudect timing-validation harness (tools/dudect)" OFF)

add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)

# Is ichor the top-level project, or vendored into a consumer (voleith,
# syndrome) via add_subdirectory?  The link-time and -Werror hardening below
# is scoped to first-party (top-level) builds so a vendored consumer's build
# is never wedged by a flag its toolchain rejects or a stricter warning gate.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(ICHOR_IS_TOP_LEVEL TRUE)
else()
    set(ICHOR_IS_TOP_LEVEL FALSE)
endif()

# Treat warnings as errors on first-party builds.
# Default ON only when top-level so consumer builds on a differently-warning
# toolchain are not broken; consumers can still opt in.
option(ICHOR_WERROR "Treat compiler warnings as errors" ${ICHOR_IS_TOP_LEVEL})
if(ICHOR_WERROR)
    add_compile_options(-Werror)
endif()

#
# Exploit-mitigation hardening.  ichor holds and
# processes key material, so its objects are compiled with stack canaries,
# fortified libc calls, and position-independent code; first-party
# executables (tests, dudect) additionally link with full RELRO and
# immediate binding.  Every flag is probed for support so a non-GCC/Clang or
# non-glibc toolchain silently skips the ones it lacks.  RELRO/now and PIE
# are properties of a linked binary, not of this static archive, so a
# vendored consumer still owns its own link-line hardening.
#
include(CheckCCompilerFlag)

set(ICHOR_HARDENING_COMPILE_OPTIONS "")

check_c_compiler_flag("-fstack-protector-strong" ICHOR_HAS_STACK_PROTECTOR)
if(ICHOR_HAS_STACK_PROTECTOR)
    list(APPEND ICHOR_HARDENING_COMPILE_OPTIONS -fstack-protector-strong)
endif()

# _FORTIFY_SOURCE requires an optimizing build (it is a no-op, with a
# warning, at -O0), so restrict it to non-Debug configs.  The -U guards
# against a redefinition warning on a toolchain that predefines it.  On a
# non-glibc libc the macro is simply inert.
list(APPEND ICHOR_HARDENING_COMPILE_OPTIONS
    "$<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE>"
    "$<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=2>")

# Emit position-independent code for the library so its objects link cleanly
# into a PIE executable or shared object on the consumer side.
include(CheckPIESupported)
check_pie_supported(LANGUAGES C)

if(ICHOR_IS_TOP_LEVEL)
    # First-party executables (tests, dudect) build as PIE, with RELRO and
    # immediate binding.  Scoped to top-level so a vendored build inherits
    # none of this.
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    # RELRO / immediate binding are GNU-ld (ELF) options.  Probe them as actual
    # link options, not with check_c_compiler_flag: the compiler-flag check only
    # compiles, so clang silently accepts -Wl,-z,... and the probe passes, but
    # Apple's ld64 rejects "-z" at link time ("ld: unknown options: -z -z").
    # Linking a trivial program with the flags makes the probe fail on macOS
    # (and any non-GNU linker), so the options are skipped there.
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_LINK_OPTIONS -Wl,-z,relro -Wl,-z,now)
    check_c_source_compiles("int main(void) { return 0; }" ICHOR_HAS_RELRO_NOW_LINK)
    unset(CMAKE_REQUIRED_LINK_OPTIONS)
    if(ICHOR_HAS_RELRO_NOW_LINK)
        add_link_options(-Wl,-z,relro -Wl,-z,now)
    endif()
endif()

#
# AES-NI probe (x86_64).  HAVE_AES_NI is only set where the SSE/AES
# intrinsics compile, so the -maes flags below are never emitted on a
# non-x86 toolchain.
#
if(ICHOR_AES_NI)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-maes -msse2 -mssse3")
    check_c_source_compiles("
        #include <wmmintrin.h>
        int main(void) {
            __m128i a = _mm_setzero_si128();
            __m128i b = _mm_aesenc_si128(a, a);
            (void)b;
            return 0;
        }
    " HAVE_AES_NI)
    unset(CMAKE_REQUIRED_FLAGS)
endif()

#
# ARMv8 Crypto Extension probe (aarch64).  Try without explicit flags
# first (Apple Silicon / compilers that enable crypto by default); fall
# back to -march=armv8-a+crypto (Linux GCC/Clang).
#
set(_ARMV8_AES_SRC "
    #include <arm_neon.h>
    int main(void) {
        uint8x16_t a = vdupq_n_u8(0);
        a = vaeseq_u8(a, a);
        a = vaesmcq_u8(a);
        (void)a;
        return 0;
    }
")
if(ICHOR_ARMV8_AES)
    include(CheckCSourceCompiles)
    check_c_source_compiles("${_ARMV8_AES_SRC}" HAVE_ARMV8_AES_NO_FLAG)
    if(HAVE_ARMV8_AES_NO_FLAG)
        set(HAVE_ARMV8_AES TRUE)
        set(ARMV8_CRYPTO_FLAGS "")
    else()
        set(CMAKE_REQUIRED_FLAGS "-march=armv8-a+crypto")
        check_c_source_compiles("${_ARMV8_AES_SRC}" HAVE_ARMV8_AES_WITH_FLAG)
        unset(CMAKE_REQUIRED_FLAGS)
        if(HAVE_ARMV8_AES_WITH_FLAG)
            set(HAVE_ARMV8_AES TRUE)
            set(ARMV8_CRYPTO_FLAGS "-march=armv8-a+crypto")
        endif()
    endif()
endif()
unset(_ARMV8_AES_SRC)

#
# PCLMULQDQ probe (x86_64).  HAVE_CLMUL is only set where the carry-less
# multiply and SSE4.1 extract intrinsics compile, so the flags below are
# never emitted on a non-x86 toolchain.
#
if(ICHOR_CLMUL)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-mpclmul -msse2 -msse4.1")
    check_c_source_compiles("
        #include <wmmintrin.h>
        #include <smmintrin.h>
        int main(void) {
            __m128i a = _mm_setzero_si128();
            __m128i p = _mm_clmulepi64_si128(a, a, 0x00);
            return (int)_mm_extract_epi64(p, 0);
        }
    " HAVE_CLMUL)
    unset(CMAKE_REQUIRED_FLAGS)
endif()

#
# ARMv8 PMULL probe (aarch64).  Try without explicit flags first (Apple
# Silicon / compilers that enable crypto by default); fall back to
# -march=armv8-a+crypto (Linux GCC/Clang).
#
set(_PMULL_SRC "
    #include <arm_neon.h>
    int main(void) {
        poly128_t r = vmull_p64((poly64_t)1, (poly64_t)1);
        return (int)vgetq_lane_u64(vreinterpretq_u64_p128(r), 0);
    }
")
if(ICHOR_PMULL)
    include(CheckCSourceCompiles)
    check_c_source_compiles("${_PMULL_SRC}" HAVE_PMULL_NO_FLAG)
    if(HAVE_PMULL_NO_FLAG)
        set(HAVE_PMULL TRUE)
        set(PMULL_CRYPTO_FLAGS "")
    else()
        set(CMAKE_REQUIRED_FLAGS "-march=armv8-a+crypto")
        check_c_source_compiles("${_PMULL_SRC}" HAVE_PMULL_WITH_FLAG)
        unset(CMAKE_REQUIRED_FLAGS)
        if(HAVE_PMULL_WITH_FLAG)
            set(HAVE_PMULL TRUE)
            set(PMULL_CRYPTO_FLAGS "-march=armv8-a+crypto")
        endif()
    endif()
endif()
unset(_PMULL_SRC)

if(HAVE_AES_NI)
    message(STATUS "ichor: AES backend = AES-NI (x86_64 hardware) + bitsliced fallback")
elseif(HAVE_ARMV8_AES)
    message(STATUS "ichor: AES backend = ARMv8 Crypto (aarch64 hardware) + bitsliced fallback")
else()
    message(STATUS "ichor: AES backend = bitsliced software only (constant-time)")
endif()

if(HAVE_CLMUL)
    message(STATUS "ichor: clmul backend = PCLMULQDQ (x86_64 hardware) + scalar fallback")
elseif(HAVE_PMULL)
    message(STATUS "ichor: clmul backend = PMULL (aarch64 hardware) + scalar fallback")
else()
    message(STATUS "ichor: clmul backend = scalar software only (constant-time)")
endif()

set(ICHOR_SOURCES
    src/util.c
    src/cpu.c
    src/cpu_x86.c
    src/cpu_aarch64.c
    src/cpu_generic.c
    src/aes.c
    src/backend.c
    src/aes_aesni.c
    src/aes_armv8.c
    src/aes_ct64.c
    src/aes_ct64_ops.c
    src/clmul.c
    src/clmul_pclmul.c
    src/clmul_pmull.c
    src/hash.c
    src/hirose.c
    src/aesdm.c
    src/grostl.c
    src/grostl_soft.c
    src/grostl_aesni.c
    src/grostl_armv8.c
    src/gf2x.c
    src/sample.c)

add_library(ichor STATIC ${ICHOR_SOURCES})
set_target_properties(ichor PROPERTIES
    OUTPUT_NAME talos_ichor
    POSITION_INDEPENDENT_CODE ON)

# Compile-time memory hardening.  PRIVATE: these
# govern how ichor's own objects are built and do not leak to consumers.
target_compile_options(ichor PRIVATE ${ICHOR_HARDENING_COMPILE_OPTIONS})

# Test-only hooks.  Two classes of hook that
# exist purely to exercise the dispatch machinery from the test suite:
#   - the ICHOR_FORCE_BACKEND env override, which the _sw test variants and
#     the dudect harness set to force the software path on accelerated
#     hardware (M2);
#   - the feature-override and dispatch-reset entry points
#     (ichor_cpu_features_override, ichor_{aes,clmul,grostl}_dispatch_reset),
#     which cycle the cached backend selection between test cases (L4).
# Both are compiled in only for first-party / test / dudect builds; a release
# or vendored build leaves them out entirely, so the shipped library never
# reads the environment for dispatch, has no process-terminating path, and
# exposes no entry point that could route dispatch to a backend the CPU
# cannot run.  PUBLIC so test targets linking ichor also see the guarded
# declarations.
if(ICHOR_IS_TOP_LEVEL OR ICHOR_BUILD_TESTS OR ICHOR_BUILD_DUDECT)
    set(_ichor_force_default ON)
else()
    set(_ichor_force_default OFF)
endif()
option(ICHOR_ENABLE_FORCE_BACKEND
    "Compile the ICHOR_FORCE_BACKEND override and the dispatch-reset test hooks (test-only; leave OFF for release)"
    ${_ichor_force_default})
unset(_ichor_force_default)
if(ICHOR_ENABLE_FORCE_BACKEND)
    target_compile_definitions(ichor PUBLIC ICHOR_ENABLE_FORCE_BACKEND)
endif()

# Consumers include <ichor/aes.h>; the implementation finds its own
# public and internal headers by bare name.
target_include_directories(ichor
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/ichor
            ${CMAKE_CURRENT_SOURCE_DIR}/src)

#
# Hardware capability flags.  Defined per detected feature; the ISA
# instruction flags are additionally pinned on the one backend TU that
# needs them so the rest of the library never assumes those instructions.
#
if(HAVE_AES_NI)
    target_compile_definitions(ichor PUBLIC ICHOR_HAVE_AES_NI)
    set_source_files_properties(src/aes_aesni.c src/grostl_aesni.c PROPERTIES
        COMPILE_FLAGS "-maes -msse2 -mssse3")
endif()
if(HAVE_ARMV8_AES)
    target_compile_definitions(ichor PUBLIC ICHOR_HAVE_ARMV8_AES)
    if(ARMV8_CRYPTO_FLAGS)
        set_source_files_properties(src/aes_armv8.c src/grostl_armv8.c PROPERTIES
            COMPILE_FLAGS "${ARMV8_CRYPTO_FLAGS}")
    endif()
endif()
if(HAVE_CLMUL)
    target_compile_definitions(ichor PUBLIC ICHOR_HAVE_CLMUL)
    set_source_files_properties(src/clmul_pclmul.c PROPERTIES
        COMPILE_FLAGS "-mpclmul -msse2 -msse4.1")
endif()
if(HAVE_PMULL)
    target_compile_definitions(ichor PUBLIC ICHOR_HAVE_PMULL)
    if(PMULL_CRYPTO_FLAGS)
        set_source_files_properties(src/clmul_pmull.c PROPERTIES
            COMPILE_FLAGS "${PMULL_CRYPTO_FLAGS}")
    endif()
endif()

# Software-only companion library.  Same sources as `ichor` minus the
# hardware-backend TUs, built with none of the ICHOR_HAVE_* capability
# defines and no ISA flags, so the dispatch layer compiles down to the
# constant-time software backends only (bitsliced AES, scalar carry-less
# multiply, software Grostl).  A consumer's dudect timing harness links this
# instead of `ichor` so it measures the software path on any host, without
# forcing the main `ichor` build software (which would strip hardware from the
# consumer's shipping library / hardware test profile in the same configure).
# Not installed / exported: a build-tree validation aid only.
option(ICHOR_BUILD_SOFT_LIB
    "Also build ichor_soft, a software-only static lib for consumer dudect harnesses"
    OFF)
if(ICHOR_BUILD_SOFT_LIB)
    set(ICHOR_SOFT_SOURCES
        src/util.c
        src/cpu.c
        src/cpu_x86.c
        src/cpu_aarch64.c
        src/cpu_generic.c
        src/aes.c
        src/backend.c
        src/aes_ct64.c
        src/aes_ct64_ops.c
        src/clmul.c
        src/hash.c
        src/hirose.c
        src/aesdm.c
        src/grostl.c
        src/grostl_soft.c
        src/gf2x.c
        src/sample.c)
    add_library(ichor_soft STATIC ${ICHOR_SOFT_SOURCES})
    set_target_properties(ichor_soft PROPERTIES
        OUTPUT_NAME talos_ichor_soft
        POSITION_INDEPENDENT_CODE ON)
    target_compile_options(ichor_soft PRIVATE ${ICHOR_HARDENING_COMPILE_OPTIONS})
    # Deliberately no ICHOR_HAVE_* defines: the hardware backend TUs are absent
    # and the dispatch guards compile them out, leaving software-only.
    if(ICHOR_ENABLE_FORCE_BACKEND)
        target_compile_definitions(ichor_soft PUBLIC ICHOR_ENABLE_FORCE_BACKEND)
    endif()
    target_include_directories(ichor_soft
        PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/ichor
                ${CMAKE_CURRENT_SOURCE_DIR}/src)
endif()

if(ICHOR_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(ICHOR_BUILD_DUDECT)
    add_subdirectory(tools/dudect)
endif()
