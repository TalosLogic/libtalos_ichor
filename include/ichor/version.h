/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * version.h - library version, as consumer-checkable macros
 *
 * The single authoritative statement of the ichor version, kept in sync with
 * project(VERSION) in CMakeLists.txt (the build fails to configure if they
 * drift).  Consumers pin their supported range against these macros, both at
 * configure time (parsing this header) and at compile time (#if guards), so
 * a version-skewed ichor is rejected before it can link.
 *
 * Versioning policy is semantic: a breaking API change bumps MAJOR, a
 * compatible addition bumps MINOR, a fix bumps PATCH.  Consumers should
 * accept a single major version (>= x.0.0, < x+1.0.0).
 */

#ifndef ICHOR_VERSION_H
#define ICHOR_VERSION_H

#define ICHOR_VERSION_MAJOR 1
#define ICHOR_VERSION_MINOR 0
#define ICHOR_VERSION_PATCH 0

#endif /* ICHOR_VERSION_H */
