set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)

# ============================================================================
# Windows grpc/protobuf/abseil linkage — #375
# ============================================================================
#
# The static-linkage override below AND `meson.build`'s Windows-specific
# `cxx.find_library()` branch for protobuf_dep/grpcpp_dep are **both
# load-bearing**. You cannot simplify either half without the other — they
# together thread two mutually exclusive failure modes on Windows MSVC.
# Before modifying either file, read `.claude/agents/build-ci.md` section
# "Windows MSVC static-link history and #375" for the full timeline.
#
# ── DO NOT set(VCPKG_BUILD_TYPE release)
#
# Setting that flag tells vcpkg to skip building the debug variant of
# every package, leaving only release-CRT (`/MD`, `_ITERATOR_DEBUG_LEVEL=0`)
# binaries in `vcpkg_installed/x64-windows/`. Our debug build compiles
# user code with `/MDd` and `_ITERATOR_DEBUG_LEVEL=2`, and the linker
# refuses to mix the two — every Windows debug build fails with dozens
# of LNK2038 "RuntimeLibrary mismatch" / "_ITERATOR_DEBUG_LEVEL mismatch"
# errors against `libprotobuf.lib`, `absl_cord.lib`, `absl_strings.lib`.
#
# The Linux triplet keeps `VCPKG_BUILD_TYPE release` because gcc/clang
# don't have MSVC's runtime-library variant ABI — debug user code can
# safely link against release-built `.a` static libs.
#
# ── LNK2038 / LNK2005 history
#
# Every alternative to the current configuration has failed:
#
#   * f0bb58b (2026-04-10) added `VCPKG_BUILD_TYPE release` to halve
#     install time. Broke every Windows MSVC debug build for 4 days.
#   * 0fe5eac (2026-04-13) reverted that line but kept the static-linkage
#     override below. vcpkg then built both release and debug static
#     variants of each affected package, but meson's cmake dependency
#     probe only reads `IMPORTED_LOCATION_RELEASE` from vcpkg's imported
#     targets and ignores `IMPORTED_LOCATION_DEBUG` — so the debug build
#     still linked against release static libs and still failed with
#     LNK2038.
#   * #375 option A (per-build-type triplets `x64-windows-debug` +
#     `x64-windows-release`) failed on (1) the `catch2` port's portfile
#     calling `vcpkg_replace_string` on a release-side pkgconfig file
#     that doesn't exist in debug-only install trees, and (2) an
#     unexplained find_package(Protobuf) failure on the release-only tree.
#   * #375 option B (explicit `cmake_args: ['-DCMAKE_BUILD_TYPE=Debug']`
#     in meson `dependency()` calls) made find_package succeed but meson's
#     cmake dep translator still picked `IMPORTED_LOCATION_RELEASE`.
#     Same LNK2038.
#   * #375 option H (dropping this static-linkage override entirely and
#     letting abseil/protobuf/etc. build as DLLs) debug-passed but
#     release-failed with LNK2005 duplicate-symbol errors — vcpkg's grpc
#     port forces static regardless of `VCPKG_LIBRARY_LINKAGE`, grpc.lib's
#     object files contain inlined abseil template symbols embedded at
#     grpc's compile time, and those collide with abseil_dll.lib's
#     exports when the linker pulls both in. The historical "abseil DLL
#     symbol conflicts" warning was accurate and still current for
#     abseil `20260107.1`. Reverted.
#
# ── The fix that works: #375 option D
#
# Static linkage for the grpc stack (below) + a Windows-specific
# `cxx.find_library()` branch in `meson.build` that constructs
# `protobuf_dep` and `grpcpp_dep` manually with build-type-conditional
# library search directories. The static linkage avoids LNK2005 (no DLL
# → no duplicate symbol exports). The hand-rolled find_library avoids
# LNK2038 (meson is told exactly which .lib to link, so the cmake-dep
# translator's release-path bias doesn't get to choose). Linux/macOS
# are unaffected — they continue to use `dependency('protobuf', method:
# 'cmake', ...)` and gcc/clang's CRT-agnostic static linkage tolerates
# mixed build types.
#
# ── Permanent, not a stopgap
#
# The gRPC→QUIC "strategic escape" (#376) was withdrawn by ADR-0066:
# gRPC is the permanent transport, so this override stays load-bearing.
# ============================================================================

# Force static linkage for the grpc stack — option D of #375.
# Keep in sync with meson.build's Windows branch; both are load-bearing.
if(PORT MATCHES "^(abseil|grpc|protobuf|upb|re2|c-ares|utf8-range)$")
    set(VCPKG_LIBRARY_LINKAGE static)
endif()
