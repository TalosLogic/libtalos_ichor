/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * backend.c - Aggregate backend-health report.
 *
 * The per-primitive health queries live in their respective dispatch TUs
 * (aes.c, clmul.c, grostl.c), where the compile-time backend guards and the
 * runtime pick are both in scope.  This file only bundles them into a single
 * start-up call.
 */

#include "backend.h"

void
ichor_backend_report(ichor_backend_report_t *out)
{
    out->aes = ichor_aes_backend_health();
    out->clmul = ichor_clmul_backend_health();
    out->grostl = ichor_grostl_backend_health();
}
