/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * cpu.h - Runtime CPU feature detection.
 *
 * Provides a one-shot bitmask describing the hardware acceleration
 * features available on the running CPU.  The mask is computed once
 * on first use and cached; subsequent calls pay a single atomic load.
 *
 * The detection layer is intentionally separate from the dispatch
 * tables in core/aes.c, core/field.c, and core/grostl.c.  Those
 * tables consume this mask; they are not referenced from here.
 */

#ifndef ICHOR_CPU_H
#define ICHOR_CPU_H

#include <stdint.h>

/* ========================================================================
 * Feature flags
 *
 * Bit assignments are stable across library versions.  Bits 0-15 are
 * reserved for x86_64 features; bits 16-31 for aarch64 features.
 * ======================================================================== */

#define ICHOR_CPU_AES_NI (1u << 0) /* x86_64: CPUID.01H:ECX[25]      */
#define ICHOR_CPU_CLMUL (1u << 1)  /* x86_64: CPUID.01H:ECX[1]       */
#define ICHOR_CPU_SSE41 (1u << 2)  /* x86_64: CPUID.01H:ECX[19]      */
#define ICHOR_CPU_SSSE3 (1u << 3)  /* x86_64: CPUID.01H:ECX[9]       */
/*
 * The 256-bit-vector features below are reported only when the OS has also
 * enabled AVX state (OSXSAVE plus XCR0[2:1] == 0b11); a CPU that supports AVX
 * under an OS that has not enabled YMM save/restore is reported as lacking it,
 * because the first AVX instruction would otherwise fault.  FMA operates on YMM
 * and carries the same OS-state requirement.
 */
#define ICHOR_CPU_AVX (1u << 4)        /* x86_64: CPUID.01H:ECX[28], OS-gated */
#define ICHOR_CPU_FMA (1u << 5)        /* x86_64: CPUID.01H:ECX[12], OS-gated */
#define ICHOR_CPU_AVX2 (1u << 6)       /* x86_64: CPUID.07H:EBX[5],  OS-gated */
#define ICHOR_CPU_ARMV8_AES (1u << 16) /* aarch64: HWCAP_AES             */
#define ICHOR_CPU_PMULL (1u << 17)     /* aarch64: HWCAP_PMULL           */

/* ========================================================================
 * API
 * ======================================================================== */

/*
 * Return a bitmask of ICHOR_CPU_* flags for the running CPU.
 *
 * Thread-safe.  The bitmask is computed on the first call via a
 * compare-and-swap guard; all subsequent calls return the cached value
 * with a single atomic load.
 */
uint32_t ichor_cpu_features(void);

/*
 * Override the cached feature bitmask.
 *
 * Intended for tests and debugging.  Replaces the cached mask with
 * the supplied value; the next call to ichor_cpu_features() returns
 * that value instead of the probed hardware mask.
 *
 * Setting bits the running CPU does not support would route dispatch to a
 * backend it cannot execute, so this entry point is compiled in only for
 * test builds (ICHOR_ENABLE_FORCE_BACKEND, see CMakeLists.txt) and is absent
 * from a release / vendored build.
 */
#ifdef ICHOR_ENABLE_FORCE_BACKEND
void ichor_cpu_features_override(uint32_t mask);
#endif

#endif /* ICHOR_CPU_H */
