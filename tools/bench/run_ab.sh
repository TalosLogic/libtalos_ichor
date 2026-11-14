#!/bin/sh
# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# run_ab.sh - before/after micro-benchmark for ichor.
#
# Builds this bench suite against a baseline revision and against a target,
# then runs every program at each, so a reworked-in-place backend such as the
# Groestl AES-NI round (SubBytes-only -> full SIMD round, same backend tag
# "aesni") shows its true speedup, which no runtime backend toggle can surface.
# It then runs the force-backend toggles on the target for the primitives that
# ARE runtime-isolable (gf256/gf16 scalar vs SSSE3, AES aesni vs vaes).
#
# The baseline is always a committed revision, built in a throwaway git
# worktree so the current checkout is never touched (the suite is copied in,
# since the baseline predates it, and a guarded add_subdirectory is appended to
# that worktree's CMakeLists.txt if absent).
#
# The target is either a committed revision (same worktree treatment) OR, when
# given as "dirty", the current working tree as-is, INCLUDING uncommitted
# changes.  Dirty mode is the point: measure a change before committing it, so
# a regression the bench reveals never has to be committed first.  It builds
# out-of-source and never modifies the working tree.
#
# Usage:
#   tools/bench/run_ab.sh [before-ref] [after-ref|dirty]
#
# Examples:
#   tools/bench/run_ab.sh                 # before=2da76e0, after=HEAD
#   tools/bench/run_ab.sh 2da76e0 dirty   # before=2da76e0, after=working tree
#
# Run from the ichor repository root.  Requires cmake and a C compiler.

set -eu

BEFORE=${1:-2da76e0}
AFTER=${2:-HEAD}

# Locate the ichor repo root (this script lives in tools/bench).
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
cd "$REPO"

if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "run_ab.sh: not a git repository: $REPO" >&2
    exit 1
fi

# Recognize the dirty / in-place target spelling.
AFTER_DIRTY=0
case "$AFTER" in
dirty | DIRTY | --dirty | WORKTREE | .) AFTER_DIRTY=1 ;;
esac

STAMP=$(date +%Y%m%d-%H%M%S)
OUT="$REPO/bench-results/$STAMP"
WTROOT="$OUT/.worktrees"
mkdir -p "$OUT" "$WTROOT"

BENCH_FILES="bench_util.h bench_aes.c bench_grostl.c bench_hash.c \
bench_gf256.c bench_gf16.c bench_keccak_x4.c bench_clmul.c CMakeLists.txt \
README.md run_ab.sh"

# Configure, build, and run the suite from a source tree.
# $1 = label, $2 = source dir.  Build dir is $OUT/$label-build; binaries land
# in $OUT/$label-build/tools/bench.
configure_build_run() {
    _label=$1
    _src=$2
    _build="$OUT/$_label-build"

    cmake -S "$_src" -B "$_build" \
        -DCMAKE_BUILD_TYPE=Release \
        -DICHOR_BUILD_BENCH=ON \
        -DICHOR_ENABLE_FORCE_BACKEND=ON \
        -DICHOR_BUILD_TESTS=OFF \
        -DICHOR_BUILD_DUDECT=OFF >"$OUT/$_label.cmake.log" 2>&1
    cmake --build "$_build" -j >"$OUT/$_label.build.log" 2>&1

    _bin="$_build/tools/bench"
    for _prog in bench_aes bench_grostl bench_hash bench_gf256 bench_gf16 bench_keccak_x4 bench_clmul; do
        [ -x "$_bin/$_prog" ] || continue
        echo "--- $_label: $_prog (default backend) ---" | tee -a "$OUT/$_label.txt"
        "$_bin/$_prog" | tee -a "$OUT/$_label.txt"
        echo "" | tee -a "$OUT/$_label.txt"
    done
}

# Committed revision via a throwaway worktree.  $1 = ref, $2 = label.
build_and_run_ref() {
    _ref=$1
    _label=$2
    _sha=$(git rev-parse --short "$_ref")
    _wt="$WTROOT/$_label"

    echo "=== $_label ($_ref -> $_sha) ==="
    git worktree add --detach "$_wt" "$_ref" >/dev/null

    mkdir -p "$_wt/tools/bench"
    for _f in $BENCH_FILES; do
        cp "$SCRIPT_DIR/$_f" "$_wt/tools/bench/$_f"
    done

    if ! grep -q "add_subdirectory(tools/bench)" "$_wt/CMakeLists.txt"; then
        {
            echo ""
            echo "if(ICHOR_BUILD_BENCH)"
            echo "    add_subdirectory(tools/bench)"
            echo "endif()"
        } >>"$_wt/CMakeLists.txt"
    fi

    configure_build_run "$_label" "$_wt"
}

# Current working tree as-is, uncommitted changes included.  $1 = label.
build_and_run_dirty() {
    _label=$1

    echo "=== $_label (working tree, uncommitted changes included) ==="
    if ! grep -q "add_subdirectory(tools/bench)" "$REPO/CMakeLists.txt"; then
        echo "run_ab.sh: $REPO/CMakeLists.txt has no 'add_subdirectory(tools/bench)';" >&2
        echo "  the bench harness is not wired into the working tree, so dirty mode" >&2
        echo "  cannot build it.  Add the wiring (see tools/bench/README.md) first." >&2
        exit 1
    fi
    configure_build_run "$_label" "$REPO"
}

# Force-backend toggles, target only.  $1 = bin dir.
run_forced() {
    _bin=$1
    echo "=== forced-backend toggles (after target) ===" | tee -a "$OUT/forced.txt"
    for _spec in \
        "bench_aes aes:aesni" \
        "bench_aes aes:vaes" \
        "bench_aes aes:bitsliced" \
        "bench_grostl grostl:soft" \
        "bench_grostl grostl:aesni" \
        "bench_grostl grostl:avx2" \
        "bench_gf256 gf256:scalar" \
        "bench_gf256 gf256:ssse3" \
        "bench_gf256 gf256:avx2" \
        "bench_gf256 gf256:gfni" \
        "bench_gf16 gf16:scalar" \
        "bench_gf16 gf16:ssse3" \
        "bench_gf16 gf16:gfni" \
        "bench_hash keccak:scalar" \
        "bench_keccak_x4 keccak:scalar" \
        "bench_keccak_x4 aes:aesni" \
        "bench_keccak_x4 aes:vaes" \
        "bench_clmul clmul:scalar" \
        "bench_clmul clmul:pclmul"; do
        _prog=${_spec%% *}
        _force=${_spec#* }
        [ -x "$_bin/$_prog" ] || continue
        echo "--- ICHOR_FORCE_BACKEND=$_force $_prog ---" | tee -a "$OUT/forced.txt"
        ICHOR_FORCE_BACKEND="$_force" "$_bin/$_prog" | tee -a "$OUT/forced.txt"
        echo "" | tee -a "$OUT/forced.txt"
    done
}

build_and_run_ref "$BEFORE" before
if [ "$AFTER_DIRTY" -eq 1 ]; then
    build_and_run_dirty after
else
    build_and_run_ref "$AFTER" after
fi
run_forced "$OUT/after-build/tools/bench"

# Tear down the worktree(s) we created; keep the result text.
git worktree remove --force "$WTROOT/before" >/dev/null 2>&1 || true
[ "$AFTER_DIRTY" -eq 1 ] || git worktree remove --force "$WTROOT/after" >/dev/null 2>&1 || true
rmdir "$WTROOT" 2>/dev/null || true

echo ""
echo "Results in: $OUT"
echo "  before.txt  after.txt  forced.txt  (+ *.cmake.log / *.build.log)"
