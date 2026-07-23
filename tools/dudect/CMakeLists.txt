# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# dudect timing-validation harness.  Builds a dedicated static library
# copy of the ichor sources with NO hardware-acceleration defines
# (ICHOR_HAVE_AES_NI / ARMV8_AES / CLMUL / PMULL all unset), so runtime
# dispatch can only select the constant-time software paths we want to
# validate: bitsliced AES (aes_ct64) and scalar carry-less multiply.
# The hardware paths are constant-time by ISA specification and do not
# need empirical validation here.  The guarded hardware backend TUs
# compile to empty objects without their defines, so they are harmless
# to include and need no ISA flags.

# Re-anchor ICHOR_SOURCES (paths relative to the ichor project root) so
# this subdirectory finds them whether ichor is the top-level project or
# vendored as a submodule.
set(_DUDECT_CORE_SOURCES "")
foreach(_src ${ICHOR_SOURCES})
    list(APPEND _DUDECT_CORE_SOURCES "${PROJECT_SOURCE_DIR}/${_src}")
endforeach()

add_library(ichor_dudect_core STATIC ${_DUDECT_CORE_SOURCES})
target_include_directories(ichor_dudect_core PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/include/ichor
    ${PROJECT_SOURCE_DIR}/src)
unset(_DUDECT_CORE_SOURCES)

# Harness executable.
set(DUDECT_SOURCES
    dudect_runner.c
    dudect_timer.c
    dudect_platform.c
    dudect_main.c
    targets_sentinel.c
    targets_aes.c
    targets_clmul.c
    targets_util.c
    targets_grostl.c)

add_executable(dudect ${DUDECT_SOURCES})
target_include_directories(dudect PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/include/ichor
    ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(dudect ichor_dudect_core)

# libm for sqrt() in the t-statistic.  Linux requires -lm explicitly;
# macOS / BSD fold it into libc but tolerate the link line.
if(NOT APPLE)
    target_link_libraries(dudect m)
endif()

# Lives outside the test pipeline.  Run manually; see README.md.
set_target_properties(dudect PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tools/dudect)
