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

uint32_t
ichor_cpu_probe(void)
{
    uint32_t eax, ebx, ecx, edx;
    uint32_t mask = 0;

    if (__get_cpuid_count(1, 0, &eax, &ebx, &ecx, &edx)) {
        if (ecx & (1u << 25))
            mask |= ICHOR_CPU_AES_NI;
        if (ecx & (1u << 1))
            mask |= ICHOR_CPU_CLMUL;
        if (ecx & (1u << 19))
            mask |= ICHOR_CPU_SSE41;
        if (ecx & (1u << 9))
            mask |= ICHOR_CPU_SSSE3;
    }
    return mask;
}

#else /* !(__x86_64__ || _M_X64) */

/* ISO C forbids an empty translation unit, and -Wpedantic / -Werror reject
 * one; give the non-x86 build a single harmless declaration. */
typedef int ichor_cpu_x86_translation_unit_not_empty;

#endif /* __x86_64__ || _M_X64 */
