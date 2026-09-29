# x64-linux-tsan triplet — vcpkg builds vendored deps (protobuf, abseil,
# grpc, openssl, sqlite, etc.) with ThreadSanitizer enabled. The Yuzu
# sanitize-tsan CI job uses this triplet so the application's TSan
# instrumentation can observe synchronization primitives inside the
# dependency code, and abseil's TSan-aware container ops engage
# (`ABSL_HAVE_THREAD_SANITIZER` is auto-detected by abseil's build when
# `-fsanitize=thread` is in the compile flags).
#
# Without this, TSan-instrumented Yuzu code passes through non-TSan
# library code paths that hold real locks, and TSan can't observe
# the happens-before edges. Symptoms: false-positive races, missed
# real races, or hard SEGV-without-race-report when TSan's shadow
# memory model collides with a dep's atomic ops it didn't instrument.
# Issue #917.
#
# VCPKG_LIBRARY_LINKAGE is STATIC (#4019, matching the stock x64-linux
# triplet - see triplets/x64-linux.cmake in $VCPKG_ROOT). It was DYNAMIC
# from #917 through #4019; that commit mirrored the ASan triplet's
# layout for the TSan flag set, and (per the ASan triplet's own #4019
# comment) neither commit's rationale ever actually required dynamic
# linkage - only that the -fsanitize=... flags below reach every
# vendored dep's own build, which a static archive receives identically.
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
#   2. PostgreSQL's shared-lib `libpq-refs-stamp` check rejects TSan's injected
#      `__tsan_func_exit` symbol as "calling exit" ("libpq must not be calling any
#      function which invokes exit"). vcpkg's libpq Makefile builds the .so only on
#      the `all-shared-lib` path; the static path (`all-static-lib`) skips the .so
#      and that check entirely.
if(PORT STREQUAL "libpq")
    set(VCPKG_LIBRARY_LINKAGE static)
endif()

# Sanitiser flags propagate to every compiled C/C++ TU in vendored
# dependencies. `-fno-omit-frame-pointer` keeps backtraces accurate
# in race reports; `-g` keeps file:line debug info. Matches what
# meson `-Db_sanitize=thread` emits for the application binary so
# the dep tree and app tree are ABI-compatible.
#
# UBSan is intentionally **not** built into the deps for the same
# reason as x64-linux-asan: `-fsanitize=undefined` instruments
# function-pointer + vptr access in a way that prevents abseil's
# constexpr address-comparison from being constant-evaluated,
# breaking the abseil build. The Yuzu application binary still
# compiles under TSan via meson `-Db_sanitize=thread`; UBSan
# instrumentation in libs adds nothing here.
set(VCPKG_C_FLAGS   "-fsanitize=thread -fno-omit-frame-pointer -g")
set(VCPKG_CXX_FLAGS "-fsanitize=thread -fno-omit-frame-pointer -g")
set(VCPKG_LINKER_FLAGS "-fsanitize=thread")

# Skip dep debug variants — protobuf/abseil/grpc are already large;
# a debug-side build would double the binary-cache footprint and the
# from-source first-run time. Same reasoning as x64-linux-asan.
set(VCPKG_BUILD_TYPE release)
