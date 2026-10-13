/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * cpu_x86.c - CPU feature probing for x86_64.
 *
 * Uses <cpuid.h> (shipped by GCC and Clang) rather than inline
 * assembly so the probe compiles without requiring per-feature ISA
 * flags on this translation unit.
 *
 * Compiled on all targets but only produces non-empty code on x86_64.
 */

#if defined(__x86_64__) || defined(_M_X64)

#include "cpu.h"

#include <cpuid.h>

/*
 * Read an extended control register.  XGETBV is issued as a mnemonic (the
 * assembler encodes it; no per-feature ISA compile flag is needed on this TU,
 * matching the <cpuid.h> approach above) and is reached only after the OSXSAVE
 * bit confirms the instruction is enabled.
 */
static uint64_t
read_xcr(uint32_t xcr)
{
    uint32_t lo, hi;
    __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(xcr));
    return ((uint64_t)hi << 32) | lo;
}

uint32_t
ichor_cpu_probe(void)
{
    uint32_t eax, ebx, ecx, edx;
    uint32_t mask = 0;
    int os_avx = 0;

    if (__get_cpuid_count(1, 0, &eax, &ebx, &ecx, &edx)) {
        if (ecx & (1u << 25))
            mask |= ICHOR_CPU_AES_NI;
        if (ecx & (1u << 1))
            mask |= ICHOR_CPU_CLMUL;
        if (ecx & (1u << 19))
            mask |= ICHOR_CPU_SSE41;
        if (ecx & (1u << 9))
            mask |= ICHOR_CPU_SSSE3;

        /* AVX-class features are usable only when the OS has enabled YMM
         * save/restore: OSXSAVE (ECX[27]) must be set AND XCR0 must have both
         * the SSE (bit 1) and AVX (bit 2) state bits. */
        if (ecx & (1u << 27)) {
            uint64_t xcr0 = read_xcr(0);
            if ((xcr0 & 0x6u) == 0x6u)
                os_avx = 1;
        }

        if (os_avx) {
            if (ecx & (1u << 28))
                mask |= ICHOR_CPU_AVX;
            if (ecx & (1u << 12))
                mask |= ICHOR_CPU_FMA;
        }
    }

    /* AVX2 lives in the leaf-7 feature set and shares the AVX OS-state gate. */
    if (os_avx && __get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        if (ebx & (1u << 5))
            mask |= ICHOR_CPU_AVX2;
    }

    return mask;
}

#else /* !(__x86_64__ || _M_X64) */

/* ISO C forbids an empty translation unit, and -Wpedantic / -Werror reject
 * one; give the non-x86 build a single harmless declaration. */
typedef int ichor_cpu_x86_translation_unit_not_empty;

#endif /* __x86_64__ || _M_X64 */
