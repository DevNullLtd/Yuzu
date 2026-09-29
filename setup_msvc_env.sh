#!/bin/bash
# setup_msvc_env.sh - Source this before running Claude Code or building Yuzu
# Usage: source ./setup_msvc_env.sh
#
# Sets up the full MSVC + vcpkg + protobuf/gRPC toolchain for MSYS2 bash.
# After sourcing, you can run cmake, meson, ninja, cl.exe etc. directly.
#
# All paths are globally accessible — no user-specific directories.

# ── Version pins (update when toolchain upgrades) ────────────────────────────
_MSVC_VER="14.44.35207"
_SDK_VER="10.0.26100.0"

# ── Base directories (Unix-style paths for MSYS2) ────────────────────────────
_VS_ROOT="/c/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools"
_VS_INSTALLER="/c/Program Files (x86)/Microsoft Visual Studio/Installer"
_VC_TOOLS="${_VS_ROOT}/VC/Tools/MSVC/${_MSVC_VER}"
_WIN_SDK="/c/Program Files (x86)/Windows Kits/10"
_VCPKG="/c/vcpkg"
_PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_CMAKE_DIR="/c/Program Files/CMake/bin"
_PYTHON_DIR="/c/Python314"
_MESON_DIR="/c/Python314/Scripts"

# ── Fail-closed SDK admission ────────────────────────────────────────────────
# A stale SDK earlier on PATH can make `which rc.exe` look healthy while the
# pinned INCLUDE/LIB directories do not exist.  Validate the three live
# artifacts that define the reviewed SDK target before exporting any build
# environment.  Keep this at the top of the sourced script so callers fail in
# seconds rather than at the first Windows.h include or kernel32 link.
_SDK_HEADER="${_WIN_SDK}/Include/${_SDK_VER}/um/Windows.h"
_SDK_LIB="${_WIN_SDK}/Lib/${_SDK_VER}/um/x64/kernel32.lib"
_SDK_RC="${_WIN_SDK}/bin/${_SDK_VER}/x64/rc.exe"
_SDK_MISSING=0
_require_sdk_artifact() {
    local name="$1"
    local path="$2"
    if [ ! -f "$path" ]; then
        printf "ERROR: Windows SDK %s missing required %s: %s\n" \
            "${_SDK_VER}" "$name" "$path" >&2
        _SDK_MISSING=1
    fi
}
_require_sdk_artifact Windows.h "${_SDK_HEADER}"
_require_sdk_artifact kernel32.lib "${_SDK_LIB}"
_require_sdk_artifact rc.exe "${_SDK_RC}"
unset -f _require_sdk_artifact
if [ "${_SDK_MISSING}" -ne 0 ]; then
    unset _MSVC_VER _SDK_VER _VS_ROOT _VS_INSTALLER _VC_TOOLS _WIN_SDK _VCPKG
    unset _PROJECT_ROOT _CMAKE_DIR _PYTHON_DIR _MESON_DIR
    unset _SDK_HEADER _SDK_LIB _SDK_RC _SDK_MISSING
    return 1 2>/dev/null || exit 1
fi
unset _SDK_HEADER _SDK_LIB _SDK_RC _SDK_MISSING

# ── Compiler selection (force MSVC, never Clang) ─────────────────────────────
export CC="cl.exe"
export CXX="cl.exe"

# ── VSCMD_VER — Meson checks this to decide C++20 modules support ────────────
# Without vcvars64.bat this is unset, causing Meson to crash parsing an empty
# string as a version number. Set it manually from the VS BuildTools version.
export VSCMD_VER="17.14.27"

# ── Temp directories (Windows-native paths for non-MSYS2 tools like rebar3) ──
# MSYS2 sets TMP=/tmp which native Windows programs interpret as \\tmp\\ (UNC),
# causing rebar3 fetches to fail when moving downloaded dependencies.
_WINUSER="${USER:-${USERNAME:-natha}}"
export TMP="C:\\Users\\${_WINUSER}\\AppData\\Local\\Temp"
unset _WINUSER
export TEMP="$TMP"

# ── CMake / build config ─────────────────────────────────────────────────────
export CMAKE_GENERATOR="Ninja"
export CMAKE_BUILD_TYPE="Debug"

# ── vcpkg ─────────────────────────────────────────────────────────────────────
export VCPKG_ROOT="C:\\vcpkg"
export CMAKE_TOOLCHAIN_FILE="C:\\vcpkg\\scripts\\buildsystems\\vcpkg.cmake"
export VCPKG_DEFAULT_TRIPLET="x64-windows"

# ── INCLUDE paths for cl.exe (Windows backslash format — cl.exe is native) ───
_VC_TOOLS_WIN="C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Tools\\MSVC\\${_MSVC_VER}"
_WIN_SDK_WIN="C:\\Program Files (x86)\\Windows Kits\\10"
export INCLUDE="${_VC_TOOLS_WIN}\\include;${_WIN_SDK_WIN}\\Include\\${_SDK_VER}\\ucrt;${_WIN_SDK_WIN}\\Include\\${_SDK_VER}\\um;${_WIN_SDK_WIN}\\Include\\${_SDK_VER}\\shared"

# ── LIB paths for link.exe (Windows backslash format) ────────────────────────
export LIB="${_VC_TOOLS_WIN}\\lib\\x64;${_WIN_SDK_WIN}\\Lib\\${_SDK_VER}\\ucrt\\x64;${_WIN_SDK_WIN}\\Lib\\${_SDK_VER}\\um\\x64"

# ── PATH (Unix forward-slash format for MSYS2) ──────────────────────────────
#
# Order matters — we prepend so our tools win over any MSYS2/mingw defaults.
# Specifically: cl.exe before gcc, CMake before MSYS cmake, etc.
#
# Components:
#   1. MSVC compiler + linker (cl.exe, link.exe, lib.exe)
#   2. vswhere.exe (needed if vcvars64.bat is ever called)
#   3. CMake (standalone install — more recent than VS bundled)
#   4. Ninja (VS bundled)
#   5. Python + Meson + pip-installed ninja (system-wide Python)
#   6. vcpkg root (vcpkg.exe)
#   7. protoc + grpc_cpp_plugin (vcpkg tools)
#   8. Windows SDK bin (rc.exe, mt.exe, midl.exe)
_NEW_PATH=""
_NEW_PATH+="${_VC_TOOLS}/bin/Hostx64/x64:"
_NEW_PATH+="${_VS_INSTALLER}:"
_NEW_PATH+="${_CMAKE_DIR}:"
_NEW_PATH+="${_VS_ROOT}/Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja:"
_NEW_PATH+="${_PYTHON_DIR}:"
_NEW_PATH+="${_MESON_DIR}:"
_NEW_PATH+="${_VCPKG}:"
_NEW_PATH+="${_PROJECT_ROOT}/vcpkg_installed/x64-windows/tools/protobuf:"
_NEW_PATH+="${_PROJECT_ROOT}/vcpkg_installed/x64-windows/tools/grpc:"
_NEW_PATH+="${_WIN_SDK}/bin/${_SDK_VER}/x64:"

export PATH="${_NEW_PATH}${PATH}"

# ── Verify ───────────────────────────────────────────────────────────────────
echo "MSVC environment loaded for MSYS2 bash."
echo ""
_check() {
    local name="$1"
    local path
    path=$(which "$name" 2>/dev/null)
    if [ -n "$path" ]; then
        printf "  %-20s %s\n" "$name" "$path"
    else
        printf "  %-20s \e[31mNOT FOUND\e[0m\n" "$name"
    fi
}
_check cl.exe
_check link.exe
_check cmake
_check ninja
_check meson
_check python
_check vcpkg
_check protoc
_check grpc_cpp_plugin
_check rc.exe
echo ""
echo "  VCPKG_ROOT=$VCPKG_ROOT"
echo "  CMAKE_GENERATOR=$CMAKE_GENERATOR"
echo "  CC=$CC  CXX=$CXX"

# Clean up temp vars
unset _MSVC_VER _SDK_VER _VS_ROOT _VS_INSTALLER _VC_TOOLS _WIN_SDK _VCPKG
unset _PROJECT_ROOT _CMAKE_DIR _PYTHON_DIR _MESON_DIR _VC_TOOLS_WIN _WIN_SDK_WIN _NEW_PATH
unset -f _check
