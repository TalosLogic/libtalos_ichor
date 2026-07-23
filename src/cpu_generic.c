/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * cpu_generic.c - CPU feature probing for architectures other than
 * x86_64 and aarch64.
 *
 * Returns 0: no hardware acceleration available; dispatch falls through
 * to the bitsliced/scalar software backends.
 *
 * Compiled on all targets but only produces non-empty code on hosts
 * that are neither x86_64 nor aarch64 (where cpu_x86.c and
 * cpu_aarch64.c both compile to empty objects).
 */

#if !defined(__x86_64__) && !defined(_M_X64) && !defined(__aarch64__)

#include "cpu.h"

uint32_t
ichor_cpu_probe(void)
{
    return 0;
}

#else /* x86_64 or aarch64: handled by cpu_x86.c / cpu_aarch64.c */

/* ISO C forbids an empty translation unit, and -Wpedantic / -Werror reject
 * one; give the non-generic build a single harmless declaration. */
typedef int ichor_cpu_generic_translation_unit_not_empty;

#endif
