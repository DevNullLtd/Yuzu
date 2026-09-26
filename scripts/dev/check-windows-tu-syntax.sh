#!/usr/bin/env bash
# check-windows-tu-syntax.sh — syntax-check the Windows-only plugin TUs on a
# non-Windows dev box, using the mingw-w64 cross compiler.
#
# WHY THIS EXISTS. A `#if defined(_WIN32)` translation unit compiles to NOTHING
# on macOS and Linux, so a full local `meson test` can be 100% green while the
# Windows leg does not compile at all. That is not hypothetical: PR #3967 passed
# 40/40 local targets and every review gate, then failed Windows MSVC CI on a
# deleted-copy-constructor error in a function no local build had ever seen.
#
# This is a SYNTAX check, not a build. It cannot validate MSVC-specific
# behaviour, link correctness, or device IOCTL semantics — CI remains the
# enforcement point. What it does catch is the large class of ordinary C++
# errors in code the local toolchain never reads.
#
# -fno-elide-constructors is deliberate: it forces the compiler to require a
# viable move/copy constructor for a by-value return of a named local, which is
# what MSVC debug does and what release-mode NRVO would otherwise hide.
#
# Usage:  bash scripts/dev/check-windows-tu-syntax.sh [extra TU paths...]
# Install: brew install mingw-w64   (or apt-get install g++-mingw-w64-x86-64)

set -uo pipefail

CXX=${MINGW_CXX:-x86_64-w64-mingw32-g++}
if ! command -v "$CXX" >/dev/null 2>&1; then
    echo "check-windows-tu-syntax: $CXX not found — install mingw-w64 to use this check." >&2
    echo "  macOS: brew install mingw-w64" >&2
    exit 127
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root" || exit 1

# Minimal stubs for third-party headers the plugin TUs include. We are checking
# OUR code, not vendored headers, and vcpkg's x64-windows tree is not present on
# a non-Windows box.
shim=$(mktemp -d)
trap 'rm -rf "$shim"' EXIT
mkdir -p "$shim/spdlog"
cat > "$shim/spdlog/spdlog.h" <<'SHIM'
#pragma once
#include <string_view>
namespace spdlog {
template <class... A> void warn(std::string_view, A&&...) {}
template <class... A> void info(std::string_view, A&&...) {}
template <class... A> void error(std::string_view, A&&...) {}
template <class... A> void debug(std::string_view, A&&...) {}
template <class... A> void critical(std::string_view, A&&...) {}
}
SHIM

# Windows-only TUs worth checking. Extend as new ones land.
tus=(
    agents/plugins/disk_actions/src/disk_actions_win.cpp
    agents/plugins/power_health/src/power_health_plugin.cpp
    agents/plugins/autoruns/src/autoruns_win.cpp
    agents/plugins/peripherals/src/peripherals_win.cpp
    agents/plugins/pkg_inventory/src/pkg_inventory_win.cpp
    agents/plugins/tar/src/tar_removable_collector.cpp
    agents/plugins/execution_artifacts/src/execution_artifacts_win.cpp
    agents/plugins/runtimes/src/runtimes_win.cpp
    agents/plugins/runtimes/src/runtimes_linux.cpp # empty on Windows: checks the portable half of the Linux walk header
    agents/core/src/dism_bounded_call.cpp
    agents/plugins/windows_optional_features/src/windows_optional_features_plugin.cpp
    agents/plugins/firmware_posture/src/firmware_posture_win.cpp
    agents/plugins/app_control/src/app_control_plugin.cpp
    agents/plugins/app_control/src/app_control_win.cpp
    agents/plugins/platform_security/src/platform_security_win.cpp
    agents/plugins/system_hardening/src/system_hardening_plugin.cpp
    agents/plugins/system_hardening/src/system_hardening_win.cpp
)
[ "$#" -gt 0 ] && tus+=("$@")

# tar_removable_collector.cpp pulls in tar_removable_parsers.hpp, which uses
# nlohmann::json for real (encode/decode of the whole cursor structure, not a
# handful of calls a small stub could faithfully cover the way the spdlog
# stub above does) — so unlike every TU above, this one needs the real
# header. It is genuinely header-only and triplet-independent, so ANY
# populated vcpkg_installed tree's copy is a valid stand-in; this script
# still does not require one to exist (its own header comment's promise), it
# just skips that ONE TU gracefully when none is bootstrapped, rather than
# failing the whole check or attempting a hand-rolled JSON-library shim.
nlohmann_include=""
for candidate in vcpkg_installed/*/include; do
    if [ -d "$candidate/nlohmann" ]; then
        nlohmann_include="$candidate"
        break
    fi
done

# autoruns_win.cpp transitively includes autoruns_parsers.hpp, which parses
# Task Scheduler XML via real libxml2 (<libxml/parser.h>, <libxml/tree.h>) --
# same rationale as the nlohmann case just above: libxml2's real headers are
# triplet-independent and genuinely needed (not a handful of calls a shim
# could faithfully cover), so discover any populated vcpkg_installed copy
# and skip gracefully when none is bootstrapped, rather than failing the
# whole check or hand-rolling an XML-parser shim.
libxml2_include=""
for candidate in vcpkg_installed/*/include; do
    if [ -d "$candidate/libxml2/libxml" ]; then
        libxml2_include="$candidate/libxml2"
        break
    fi
done

rc=0
for tu in "${tus[@]}"; do
    [ -f "$tu" ] || { echo "  SKIP  $tu (not present)"; continue; }
    src_dir=$(dirname "$tu")
    extra_inc=()
    # Scoped to the TU's OWN directory (its sibling headers), not a repo-wide
    # glob — disk_actions_win.cpp must stay shim-only even though some
    # unrelated plugin elsewhere in the tree uses nlohmann.
    if grep -lq "nlohmann/json.hpp" "$src_dir"/*.hpp "$src_dir"/*.cpp 2>/dev/null; then
        if [ -z "$nlohmann_include" ]; then
            echo "  SKIP  $tu (needs nlohmann/json.hpp — bootstrap vcpkg_installed to check it)"
            continue
        fi
        extra_inc+=(-I "$nlohmann_include")
    fi
    if grep -lq "libxml/parser.h" "$src_dir"/*.hpp "$src_dir"/*.cpp 2>/dev/null; then
        if [ -z "$libxml2_include" ]; then
            echo "  SKIP  $tu (needs libxml/parser.h — bootstrap vcpkg_installed to check it)"
            continue
        fi
        extra_inc+=(-I "$libxml2_include")
    fi
    if "$CXX" -std=c++23 -fsyntax-only -fno-elide-constructors \
        -DWIN32_LEAN_AND_MEAN -DNOMINMAX \
        -I "$shim" -I "$src_dir" -I agents/shared -I agents/core/include -I sdk/include \
        "${extra_inc[@]}" "$tu" 2>"$shim/err.log"; then
        echo "  ok    $tu"
    else
        echo "  FAIL  $tu"
        sed 's/^/        /' "$shim/err.log"
        rc=1
    fi
done

if [ "$rc" -eq 0 ]; then
    echo "check-windows-tu-syntax: all Windows TUs syntax-check clean."
else
    echo "check-windows-tu-syntax: at least one Windows TU does not compile." >&2
fi
exit "$rc"
