# x64-linux-asan triplet — vcpkg builds vendored deps (protobuf, abseil,
# grpc, etc.) with AddressSanitizer + UndefinedBehaviorSanitizer enabled.
# The Yuzu sanitize-asan CI job uses this triplet so the application's
# ASan instrumentation cooperates with abseil's container-poisoning
# logic (`ABSL_HAVE_ADDRESS_SANITIZER` is auto-detected by abseil's
# build when `-fsanitize=address` is in the compile flags).
#
# Without this, abseil's flat_hash_map poisons unused container slots
# at static-init time (during protobuf's DescriptorPool::Tables
# constructor), and gcc 13's libstdc++ basic_string SSO inline-buffer
# read on an adjacent slot trips a spurious `use-after-poison` ASan
# error before any Yuzu test runs. Issue around governance pipeline,
# v0.12.0-rc /test sweep.
#
# VCPKG_LIBRARY_LINKAGE is STATIC (#4019, matching the stock x64-linux
# triplet - see triplets/x64-linux.cmake in $VCPKG_ROOT). It was DYNAMIC
# from this triplet's introduction (afd390475) through #4019; that
# commit's rationale was entirely about the -fsanitize=... compile-flag
# propagation below making abseil auto-detect
# ABSL_HAVE_ADDRESS_SANITIZER, never about needing dynamic linkage
# specifically, and flag propagation is orthogonal to linkage mode - the
# flags below apply to a static archive exactly as they did to a .so
# (proven in this repo already: the libpq carve-out below, the only
# static exception this triplet had before #4019, forced static linkage
# for libpq alone and its sanitizer coverage was never in question).
#
# Root cause fixed by going static: under dynamic linkage, protobuf/
# grpc/re2/etc. each become separate .so images, and each independently
# embeds abseil's hash-mixing internals (abseil ships static-archive-only
# from vcpkg regardless of this triplet's linkage; grpc's own build also
# vendors a private copy of some abseil internals into libgpr.so - see
# nightly.yml's `ASAN_OPTIONS: detect_odr_violation=0`, already carrying
# the `libgpr.so embeds a static copy of abseil's kToUpper` comment for
# this exact class of split). `MixingHashState::kSeed` is self-referential
# (derived from its own storage address), so each image's copy legitimately
# differs - a protobuf::Map populated by one image's hash function and
# queried by another's silently misses ~50% of the time. This is the same
# shape as the pre-existing #501 cross-image hash-seed incident (see the
# `guardian_dispatch_push_bytes_for_test` serialize-then-dispatch workaround
# in tests/unit/test_guardian_engine.cpp, still load-bearing -- see below),
# spilling wider because the sanitizer triplets introduce MORE separate .so
# images than the stock static triplet has. Static linkage collapses the
# vcpkg dependency graph (grpc/protobuf/re2/abseil) into one archive per
# consuming binary, closing the grpc-stack-boundary split this triplet was
# hitting. It does NOT collapse everything Yuzu ships into one image: the
# plugin-ABI shared library (`libyuzu_agent_core.so`) is architecturally
# always a separate consumer, independent of this triplet's linkage, and
# still independently embeds its own abseil copy with its own `kSeed` --
# confirmed present post-fix via `nm -D`. That boundary is the reason the
# #501 workaround above stays load-bearing rather than becoming dead code;
# don't remove it on the assumption this fix eliminated every cross-image
# split.

set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)

# libpq (Postgres substrate, ADR-0006): now redundant with the base
# VCPKG_LIBRARY_LINKAGE above (both are `static`), kept only so libpq's
# own linkage can't silently drift if the base setting ever changes again.
# libpq specifically NEEDS static regardless of what the rest of the dep
# tree uses - two reasons, both surfaced by the Big Tam cold sanitizer
# build:
#   1. meson.build's unix libpq block hard-requires the static
#      libpgcommon.a/libpgport.a archives (scram/auth helpers) that ONLY the
#      static build emits; a dynamic libpq.so has no standalone pgcommon → meson
#      fails with "library 'pgcommon' not found".
#   2. PostgreSQL's shared-lib `libpq-refs-stamp` check rejects the ASan-injected
#      symbols as "calling exit". vcpkg's libpq Makefile builds the .so only on
#      the `all-shared-lib` path; the static path (`all-static-lib`) skips the .so
#      and that check entirely.
if(PORT STREQUAL "libpq")
    set(VCPKG_LIBRARY_LINKAGE static)
endif()

# Sanitiser flags propagate to every compiled C/C++ TU in vendored
# dependencies. `-fno-omit-frame-pointer` keeps backtraces accurate;
# `-g` keeps file:line debug info.
#
# UBSan is intentionally **not** built into the deps. Adding
# `-fsanitize=undefined` instruments function-pointer + vptr access
# in a way that prevents abseil 20260107.1's
# `TypeErasedApplyToSlotFn` constexpr address-comparison in
# `absl/container/internal/hash_policy_traits.h:158` from being
# constant-evaluated, breaking the abseil build before it can
# produce artefacts. The Yuzu application binary still compiles
# under both ASan + UBSan via meson `-Db_sanitize=address,undefined`,
# but the vendored libs only need to cooperate with ASan's
# container-poisoning logic to fix the protobuf-static-init
# use-after-poison; UBSan instrumentation in libs adds nothing.
set(VCPKG_C_FLAGS   "-fsanitize=address -fno-omit-frame-pointer -g")
set(VCPKG_CXX_FLAGS "-fsanitize=address -fno-omit-frame-pointer -g")
set(VCPKG_LINKER_FLAGS "-fsanitize=address")

# Skip dep debug variants — the sanitiser job builds protobuf/abseil/
# grpc (already large); a debug-side build would double the binary-
# cache footprint and the from-source first-run time.
set(VCPKG_BUILD_TYPE release)
