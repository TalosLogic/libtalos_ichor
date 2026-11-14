# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only

cmake_minimum_required(VERSION 3.16)
project(libtalos_ichor VERSION 1.3.0 LANGUAGES C
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
option(ICHOR_AES_VAES  "Compile the VAES batched AES backend (x86_64; needs AES-NI)" ON)
option(ICHOR_AES_PREFER_VAES "Prefer VAES over AES-NI in auto-dispatch when both are present; turn OFF for split-256 (e.g. Gracemont) fleets where AES-NI is faster" ON)
option(ICHOR_GROSTL_AVX2 "Compile the AVX2 (P+Q widened) Groestl backend (x86_64; needs AES-NI)" ON)
option(ICHOR_GROSTL_AVX2_GFNI "Compile the AVX2+GFNI Groestl backend (x86_64)" ON)
option(ICHOR_ARMV8_AES "Compile the ARMv8 AES backend (aarch64)" ON)
option(ICHOR_CLMUL     "Compile the PCLMULQDQ carry-less mul backend (x86_64)" ON)
option(ICHOR_PMULL     "Compile the PMULL carry-less mul backend (aarch64)" ON)
option(ICHOR_GF256_SSSE3 "Compile the SSSE3 GF(2^8) region-multiply backend (x86_64)" ON)
option(ICHOR_GF256_AVX2 "Compile the AVX2 GF(2^8) region-multiply backend (x86_64)" ON)
option(ICHOR_GF256_GFNI "Compile the GFNI GF2P8MULB GF(2^8) region-multiply backend (x86_64; needs AVX2)" ON)
option(ICHOR_GF16_SSSE3 "Compile the SSSE3 GF(2^16) region-multiply backend (x86_64)" ON)
option(ICHOR_GF16_GFNI "Compile the GFNI affine GF(2^16) region-multiply backend (x86_64; needs AVX2)" ON)
option(ICHOR_GF256_NEON "Compile the NEON TBL GF(2^8) region-multiply backend (aarch64)" ON)
option(ICHOR_GF16_NEON "Compile the NEON TBL GF(2^16) region-multiply backend (aarch64)" ON)
option(ICHOR_KECCAK_X4_AVX2 "Compile the AVX2 4-way Keccak-f[1600] backend (x86_64)" ON)
option(ICHOR_KECCAK_SHA3 "Compile the ARMv8.2 SHA-3 single-sponge Keccak-f[1600] backend (aarch64)" ON)
option(ICHOR_THREADS "Build the ichor thread pool (POSIX threads); OFF compiles a serial fallback" ON)
option(ICHOR_BUILD_TESTS "Build the test suite" ON)
option(ICHOR_BUILD_DUDECT "Build the dudect timing-validation harness (tools/dudect)" OFF)
option(ICHOR_BUILD_BENCH "Build the micro-benchmark harness (tools/bench); run manually" OFF)

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
# VAES probe (x86_64).  The batched backend reuses the AES-NI key schedule and
# single-block path, so it is only probed when AES-NI compiled; HAVE_AES_VAES
# is set only where the 256-bit vaesenc intrinsic and the AVX2 round-key
# broadcast both compile, so the -mvaes -mavx2 flags below are never emitted on
# a toolchain that lacks them.
#
if(ICHOR_AES_VAES AND HAVE_AES_NI)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-mvaes -mavx2")
    check_c_source_compiles("
        #include <immintrin.h>
        int main(void) {
            __m256i a = _mm256_setzero_si256();
            __m128i k = _mm_setzero_si128();
            __m256i r = _mm256_broadcastsi128_si256(k);
            r = _mm256_aesenc_epi128(a, r);
            r = _mm256_aesenclast_epi128(r, r);
            return _mm_cvtsi128_si32(_mm256_castsi256_si128(r));
        }
    " HAVE_AES_VAES)
    unset(CMAKE_REQUIRED_FLAGS)
endif()

#
# AVX2 Groestl probe (x86_64).  Widens the P/Q permutations into YMM lanes; the
# S-box uses aesenclast (AES-NI, 128-bit) split across the two halves, so this
# backend needs AES-NI too.  HAVE_GROSTL_AVX2 is set only where the YMM integer
# ops and aesenclast both compile.
#
if(ICHOR_GROSTL_AVX2 AND HAVE_AES_NI)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-mavx2 -maes")
    check_c_source_compiles("
        #include <immintrin.h>
        int main(void) {
            __m256i a = _mm256_set1_epi8(1);
            __m128i s = _mm_aesenclast_si128(_mm256_castsi256_si128(a),
                                             _mm_setzero_si128());
            a = _mm256_shuffle_epi8(_mm256_set_m128i(s, s), a);
            a = _mm256_xor_si256(a, _mm256_add_epi8(a, a));
            return _mm_cvtsi128_si32(_mm256_castsi256_si128(a));
        }
    " HAVE_GROSTL_AVX2)
    unset(CMAKE_REQUIRED_FLAGS)
endif()

#
# AVX2+GFNI Groestl probe (x86_64).  The GFNI affine S-box needs no AES-NI.
# HAVE_GROSTL_AVX2_GFNI is set only where GF2P8AFFINEINVQB on a YMM compiles.
#
if(ICHOR_GROSTL_AVX2_GFNI)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-mavx2 -mgfni")
    check_c_source_compiles("
        #include <immintrin.h>
        int main(void) {
            __m256i a = _mm256_set1_epi8(1);
            __m256i m = _mm256_set1_epi64x((long long)0xF1E3C78F1F3E7CF8ULL);
            a = _mm256_gf2p8affineinv_epi64_epi8(a, m, 0x63);
            return _mm_cvtsi128_si32(_mm256_castsi256_si128(a));
        }
    " HAVE_GROSTL_AVX2_GFNI)
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

#
# ARMv8.2 SHA-3 extension probe (aarch64) for the single-sponge Keccak-f[1600]
# kernel (FEAT_SHA3: EOR3/RAX1/BCAX/XAR).  Try without explicit flags first
# (Apple Silicon enables it by default), then -march=armv8.2-a+sha3.
# HAVE_KECCAK_SHA3 is set only where the intrinsics compile, so the +sha3 flag
# is never emitted on a non-aarch64 toolchain.
#
set(_SHA3_SRC "
    #include <arm_neon.h>
    int main(void) {
        uint64x2_t a = vdupq_n_u64(1);
        uint64x2_t b = veor3q_u64(a, a, a);
        uint64x2_t c = vrax1q_u64(a, b);
        uint64x2_t d = vbcaxq_u64(a, b, c);
        uint64x2_t e = vxarq_u64(d, a, 1);
        return (int)vgetq_lane_u64(e, 0);
    }
")
if(ICHOR_KECCAK_SHA3)
    include(CheckCSourceCompiles)
    check_c_source_compiles("${_SHA3_SRC}" HAVE_SHA3_NO_FLAG)
    if(HAVE_SHA3_NO_FLAG)
        set(HAVE_KECCAK_SHA3 TRUE)
        set(SHA3_FLAGS "")
    else()
        set(CMAKE_REQUIRED_FLAGS "-march=armv8.2-a+sha3")
        check_c_source_compiles("${_SHA3_SRC}" HAVE_SHA3_WITH_FLAG)
        unset(CMAKE_REQUIRED_FLAGS)
        if(HAVE_SHA3_WITH_FLAG)
            set(HAVE_KECCAK_SHA3 TRUE)
            set(SHA3_FLAGS "-march=armv8.2-a+sha3")
        endif()
    endif()
endif()
unset(_SHA3_SRC)

#
# SSSE3 probe (x86_64) for the GF(2^8) split-nibble region multiply.
# HAVE_GF256_SSSE3 is only set where the pshufb intrinsic compiles, so the
# -mssse3 flag below is never emitted on a non-x86 toolchain.
#
if(ICHOR_GF256_SSSE3)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-mssse3 -msse2")
    check_c_source_compiles("
        #include <tmmintrin.h>
        int main(void) {
            __m128i t = _mm_setzero_si128();
            __m128i v = _mm_setzero_si128();
            __m128i r = _mm_shuffle_epi8(t, v);
            return _mm_cvtsi128_si32(r);
        }
    " HAVE_GF256_SSSE3)
    unset(CMAKE_REQUIRED_FLAGS)
endif()

#
# SSSE3 probe (x86_64) for the GF(2^16) split-nibble region multiply.  Same
# pshufb requirement as gf256, probed independently so either backend can be
# disabled on its own.
#
if(ICHOR_GF16_SSSE3)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-mssse3 -msse2")
    check_c_source_compiles("
        #include <tmmintrin.h>
        int main(void) {
            __m128i t = _mm_setzero_si128();
            __m128i v = _mm_setzero_si128();
            __m128i r = _mm_shuffle_epi8(t, v);
            return _mm_cvtsi128_si32(r);
        }
    " HAVE_GF16_SSSE3)
    unset(CMAKE_REQUIRED_FLAGS)
endif()

#
# AVX2 probe (x86_64) for the GF(2^8) split-nibble region multiply.
# HAVE_GF256_AVX2 is set only where the 256-bit vpshufb intrinsic compiles, so
# -mavx2 is never emitted on a non-x86 toolchain.  gf16 has no AVX2 vpshufb
# backend: the 16-bit interleaved layout forces lane-crossing permutes whose
# cost cancels the widening (measured a wash-to-regression vs SSSE3 on every
# test host), so gf16 ships SSSE3 + GFNI only.
#
if(ICHOR_GF256_AVX2)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-mavx2 -mssse3 -msse2")
    check_c_source_compiles("
        #include <immintrin.h>
        int main(void) {
            __m256i t = _mm256_setzero_si256();
            __m256i v = _mm256_setzero_si256();
            __m256i r = _mm256_shuffle_epi8(t, v);
            return _mm256_extract_epi32(r, 0);
        }
    " HAVE_GF256_AVX2)
    unset(CMAKE_REQUIRED_FLAGS)
endif()

#
# GFNI probe (x86_64) for the GF(2^8) GF2P8MULB and GF(2^16) affine region
# multiply.  Both 256-bit forms are VEX AVX2 encodings, so the probe requires
# -mgfni -mavx2 and both intrinsics compiling.  HAVE_GF256_GFNI needs
# GF2P8MULB; HAVE_GF16_GFNI needs GF2P8AFFINEQB.
#
if(ICHOR_GF256_GFNI)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-mgfni -mavx2")
    check_c_source_compiles("
        #include <immintrin.h>
        int main(void) {
            __m256i a = _mm256_set1_epi8(2);
            __m256i v = _mm256_setzero_si256();
            __m256i r = _mm256_gf2p8mul_epi8(a, v);
            return _mm256_extract_epi32(r, 0);
        }
    " HAVE_GF256_GFNI)
    unset(CMAKE_REQUIRED_FLAGS)
endif()
if(ICHOR_GF16_GFNI)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-mgfni -mavx2")
    check_c_source_compiles("
        #include <immintrin.h>
        int main(void) {
            __m256i a = _mm256_set1_epi64x(1);
            __m256i v = _mm256_setzero_si256();
            __m256i r = _mm256_gf2p8affine_epi64_epi8(v, a, 0);
            return _mm256_extract_epi32(r, 0);
        }
    " HAVE_GF16_GFNI)
    unset(CMAKE_REQUIRED_FLAGS)
endif()

#
# NEON TBL probe (aarch64) for the GF(2^8) / GF(2^16) split-nibble region
# multiply.  Advanced SIMD is mandatory on ARMv8-A, so no arch flag is needed;
# the probe only confirms the toolchain is aarch64 and the table-lookup +
# deinterleave intrinsics compile, so neither backend is emitted on a non-NEON
# toolchain.  One probe gates both HAVE_GF256_NEON and HAVE_GF16_NEON.
#
if(ICHOR_GF256_NEON OR ICHOR_GF16_NEON)
    include(CheckCSourceCompiles)
    check_c_source_compiles("
        #include <arm_neon.h>
        int main(void) {
            uint8x16_t t = vdupq_n_u8(0);
            uint8x16_t v = vqtbl1q_u8(t, t);
            uint8x16x2_t w = vld2q_u8((const unsigned char[32]){0});
            v = veorq_u8(v, w.val[0]);
            return (int)vgetq_lane_u8(v, 0);
        }
    " HAVE_GF_NEON)
endif()
if(ICHOR_GF256_NEON AND HAVE_GF_NEON)
    set(HAVE_GF256_NEON TRUE)
endif()
if(ICHOR_GF16_NEON AND HAVE_GF_NEON)
    set(HAVE_GF16_NEON TRUE)
endif()

#
# AVX2 probe (x86_64) for the 4-way Keccak-f[1600] permutation.  The kernel
# needs the AVX2 64-bit variable shifts and VPANDN; HAVE_KECCAK_X4_AVX2 is set
# only where they compile, so -mavx2 is never emitted on a non-x86 toolchain.
#
if(ICHOR_KECCAK_X4_AVX2)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-mavx2")
    check_c_source_compiles("
        #include <immintrin.h>
        int main(void) {
            __m256i a = _mm256_set1_epi64x(1);
            __m256i b = _mm256_sll_epi64(a, _mm_cvtsi32_si128(3));
            __m256i c = _mm256_andnot_si256(a, b);
            return _mm256_extract_epi32(c, 0);
        }
    " HAVE_KECCAK_X4_AVX2)
    unset(CMAKE_REQUIRED_FLAGS)
endif()

if(HAVE_AES_VAES)
    message(STATUS "ichor: AES backend = VAES batched + AES-NI (x86_64 hardware) + bitsliced fallback")
elseif(HAVE_AES_NI)
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

if(HAVE_GF256_GFNI)
    message(STATUS "ichor: gf256 backend = GFNI GF2P8MULB + AVX2/SSSE3 vpshufb (x86_64 hardware) + scalar fallback")
elseif(HAVE_GF256_AVX2)
    message(STATUS "ichor: gf256 backend = AVX2 + SSSE3 split-nibble vpshufb (x86_64 hardware) + scalar fallback")
elseif(HAVE_GF256_SSSE3)
    message(STATUS "ichor: gf256 backend = SSSE3 split-nibble vpshufb (x86_64 hardware) + scalar fallback")
elseif(HAVE_GF256_NEON)
    message(STATUS "ichor: gf256 backend = NEON TBL split-nibble (aarch64 hardware) + scalar fallback")
else()
    message(STATUS "ichor: gf256 backend = scalar software only (constant-time)")
endif()

if(HAVE_GF16_GFNI)
    message(STATUS "ichor: gf16 backend = GFNI affine + SSSE3 vpshufb (x86_64 hardware) + scalar fallback")
elseif(HAVE_GF16_SSSE3)
    message(STATUS "ichor: gf16 backend = SSSE3 split-nibble vpshufb (x86_64 hardware) + scalar fallback")
elseif(HAVE_GF16_NEON)
    message(STATUS "ichor: gf16 backend = NEON TBL split-nibble (aarch64 hardware) + scalar fallback")
else()
    message(STATUS "ichor: gf16 backend = scalar software only (constant-time)")
endif()

if(HAVE_GROSTL_AVX2_GFNI)
    message(STATUS "ichor: Groestl SIMD = AVX2+GFNI (P+Q widened) + AVX2 + AES-NI + bitsliced fallback")
elseif(HAVE_GROSTL_AVX2)
    message(STATUS "ichor: Groestl SIMD = AVX2 (P+Q widened) + AES-NI + bitsliced fallback")
endif()

if(HAVE_KECCAK_X4_AVX2)
    message(STATUS "ichor: Keccak x4 backend = AVX2 4-lane Keccak-f[1600] + scalar fallback")
elseif(HAVE_KECCAK_SHA3)
    message(STATUS "ichor: Keccak x4 backend = ARMv8.2 SHA-3 2x2-lane Keccak-f[1600] + scalar fallback")
else()
    message(STATUS "ichor: Keccak x4 backend = scalar 4x serial (portable software)")
endif()

if(HAVE_KECCAK_SHA3)
    message(STATUS "ichor: Keccak single-sponge backend = ARMv8.2 SHA-3 (aarch64 hardware) + scalar fallback")
else()
    message(STATUS "ichor: Keccak single-sponge backend = scalar (portable software)")
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
    src/aes_vaes.c
    src/aes_armv8.c
    src/aes_ct64.c
    src/aes_ct64_ops.c
    src/clmul.c
    src/clmul_pclmul.c
    src/clmul_pmull.c
    src/gf256.c
    src/gf256_ssse3.c
    src/gf256_avx2.c
    src/gf256_gfni.c
    src/gf256_neon.c
    src/gf16.c
    src/gf16_ssse3.c
    src/gf16_gfni.c
    src/gf16_neon.c
    src/hash.c
    src/keccak_x4.c
    src/keccak_x4_avx2.c
    src/keccak_sha3_neon.c
    src/keccak_x4_sha3_neon.c
    src/hirose.c
    src/aesdm.c
    src/grostl.c
    src/grostl_soft.c
    src/grostl_aesni.c
    src/grostl_avx2.c
    src/grostl_avx2_gfni.c
    src/grostl_armv8.c
    src/gf2x.c
    src/sample.c
    src/pool.c)

add_library(ichor STATIC ${ICHOR_SOURCES})
set_target_properties(ichor PROPERTIES
    OUTPUT_NAME talos_ichor
    POSITION_INDEPENDENT_CODE ON)

# Compile-time memory hardening.  PRIVATE: these
# govern how ichor's own objects are built and do not leak to consumers.
target_compile_options(ichor PRIVATE ${ICHOR_HARDENING_COMPILE_OPTIONS})

# Thread pool (src/pool.c).  ICHOR_WITH_THREADS is PUBLIC so consumers that
# include <ichor/pool.h> compile against the same build (threaded vs serial)
# and inherit the pthreads link transitively.  With ICHOR_THREADS=OFF no
# threading library is linked anywhere and pool.c compiles its serial
# fallback, which doubles as the deterministic analysis build (dudect/ASan).
if(ICHOR_THREADS)
    find_package(Threads REQUIRED)
    target_link_libraries(ichor PUBLIC Threads::Threads)
    target_compile_definitions(ichor PUBLIC ICHOR_WITH_THREADS=1)
else()
    target_compile_definitions(ichor PUBLIC ICHOR_WITH_THREADS=0)
endif()

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
if(HAVE_AES_VAES)
    target_compile_definitions(ichor PUBLIC ICHOR_HAVE_AES_VAES)
    set_source_files_properties(src/aes_vaes.c PROPERTIES
        COMPILE_FLAGS "-mvaes -mavx2 -maes -msse2")
    if(ICHOR_AES_PREFER_VAES)
        target_compile_definitions(ichor PUBLIC ICHOR_AES_PREFER_VAES)
    endif()
endif()
if(HAVE_GROSTL_AVX2)
    target_compile_definitions(ichor PUBLIC ICHOR_HAVE_GROSTL_AVX2)
    set_source_files_properties(src/grostl_avx2.c PROPERTIES
        COMPILE_FLAGS "-mavx2 -maes -mssse3 -msse2")
endif()
# The GFNI backend reuses the 128-bit AES-NI single-permutation entries for the
# lone Omega P, so it is enabled only when AES-NI is also compiled (every GFNI
# CPU has AES-NI).
if(HAVE_GROSTL_AVX2_GFNI AND HAVE_AES_NI)
    target_compile_definitions(ichor PUBLIC ICHOR_HAVE_GROSTL_AVX2_GFNI)
    set_source_files_properties(src/grostl_avx2_gfni.c PROPERTIES
        COMPILE_FLAGS "-mavx2 -mgfni -msse2")
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
if(HAVE_GF256_SSSE3)
    target_compile_definitions(ichor PUBLIC ICHOR_HAVE_GF256_SSSE3)
    set_source_files_properties(src/gf256_ssse3.c PROPERTIES
        COMPILE_FLAGS "-mssse3 -msse2")
endif()
if(HAVE_GF256_AVX2)
    target_compile_definitions(ichor PUBLIC ICHOR_HAVE_GF256_AVX2)
    set_source_files_properties(src/gf256_avx2.c PROPERTIES
        COMPILE_FLAGS "-mavx2 -mssse3 -msse2")
endif()
if(HAVE_GF256_GFNI)
    target_compile_definitions(ichor PUBLIC ICHOR_HAVE_GF256_GFNI)
    set_source_files_properties(src/gf256_gfni.c PROPERTIES
        COMPILE_FLAGS "-mgfni -mavx2 -msse2")
endif()
if(HAVE_GF16_SSSE3)
    target_compile_definitions(ichor PUBLIC ICHOR_HAVE_GF16_SSSE3)
    set_source_files_properties(src/gf16_ssse3.c PROPERTIES
        COMPILE_FLAGS "-mssse3 -msse2")
endif()
if(HAVE_GF256_NEON)
    # Advanced SIMD is baseline on aarch64, so no per-TU arch flag.
    target_compile_definitions(ichor PUBLIC ICHOR_HAVE_GF256_NEON)
endif()
if(HAVE_GF16_NEON)
    target_compile_definitions(ichor PUBLIC ICHOR_HAVE_GF16_NEON)
endif()
if(HAVE_GF16_GFNI)
    target_compile_definitions(ichor PUBLIC ICHOR_HAVE_GF16_GFNI)
    set_source_files_properties(src/gf16_gfni.c PROPERTIES
        COMPILE_FLAGS "-mgfni -mavx2 -msse2")
endif()
if(HAVE_KECCAK_X4_AVX2)
    target_compile_definitions(ichor PUBLIC ICHOR_HAVE_KECCAK_X4_AVX2)
    set_source_files_properties(src/keccak_x4_avx2.c PROPERTIES
        COMPILE_FLAGS "-mavx2")
endif()
if(HAVE_KECCAK_SHA3)
    target_compile_definitions(ichor PUBLIC ICHOR_HAVE_KECCAK_SHA3)
    set_source_files_properties(src/keccak_sha3_neon.c PROPERTIES
        COMPILE_FLAGS "${SHA3_FLAGS}")
    # The 4-way batched SHA-3 kernel rides the same FEAT_SHA3 probe / flag.
    target_compile_definitions(ichor PUBLIC ICHOR_HAVE_KECCAK_X4_SHA3)
    set_source_files_properties(src/keccak_x4_sha3_neon.c PROPERTIES
        COMPILE_FLAGS "${SHA3_FLAGS}")
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
        src/gf256.c
        src/gf16.c
        src/hash.c
        src/keccak_x4.c
        src/hirose.c
        src/aesdm.c
        src/grostl.c
        src/grostl_soft.c
        src/gf2x.c
        src/sample.c
        src/pool.c)
    add_library(ichor_soft STATIC ${ICHOR_SOFT_SOURCES})
    set_target_properties(ichor_soft PROPERTIES
        OUTPUT_NAME talos_ichor_soft
        POSITION_INDEPENDENT_CODE ON)
    target_compile_options(ichor_soft PRIVATE ${ICHOR_HARDENING_COMPILE_OPTIONS})
    # Mirror the thread-pool wiring so ichor_soft stays a drop-in replacement.
    if(ICHOR_THREADS)
        find_package(Threads REQUIRED)
        target_link_libraries(ichor_soft PUBLIC Threads::Threads)
        target_compile_definitions(ichor_soft PUBLIC ICHOR_WITH_THREADS=1)
    else()
        target_compile_definitions(ichor_soft PUBLIC ICHOR_WITH_THREADS=0)
    endif()
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

if(ICHOR_BUILD_BENCH)
    add_subdirectory(tools/bench)
endif()
