/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef DUDECT_TIMER_H
#define DUDECT_TIMER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return the current high-resolution timer reading in implementation-
 * defined ticks.  Differences between consecutive readings are
 * meaningful; absolute values are not.  x86_64 uses RDTSCP, aarch64
 * uses CNTVCT_EL0, and other platforms fall back to clock_gettime.
 */
uint64_t ichor_dudect_now_ticks(void);

/* Human-readable name of the active timer source.  Printed in the
 * harness summary so a captured run report identifies which clock
 * produced the numbers.
 */
const char *ichor_dudect_timer_name(void);

#ifdef __cplusplus
}
#endif

#endif /* DUDECT_TIMER_H */
