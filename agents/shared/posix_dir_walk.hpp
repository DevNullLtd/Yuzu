// posix_dir_walk.hpp -- one correct, shared capped-directory-enumeration
// primitive for POSIX (opendir/readdir) callers.
//
// Before this header existed, autoruns hand-rolled the identical
// while(readdir()) loop shape five separate times across two files
// (autoruns_linux.cpp's list_dir/build_wants_listing, autoruns_macos.cpp's
// walk_plist_dir_handle/walk_dir_names/collect_user_launchagents), each a
// slightly different copy. Round 8 of PR #4154's review found the terminal-
// error-detection fix landed in round 7 had a gap of the SAME shape one
// level down (the cap-boundary lookahead call's own failure was silently
// discarded) independently reproduced in all three macOS copies -- exactly
// because the logic was triplicated instead of centralized, so fixing it in
// one place never propagated to its siblings. This header exists so there
// is exactly one implementation to get right, and every caller shares it.
//
// Deliberately narrow: takes an ALREADY-OPEN `DIR*` (opening/closing a
// directory stays with each caller's own platform-specific logic -- e.g.
// macOS's open_dir_no_follow_checked security hardening, or Linux's plain
// opendir() -- this header is only about correctly WALKING one once it's
// open) and a per-entry callback, matching the zero-dependency,
// core/plugin-edge-free "leaf helper" convention every other file in this
// directory (win_str.hpp, wmi_bounded.hpp, ...) follows per
// docs/cpp-conventions.md.
//
// Windows never reaches this header (FindFirstFileW/FindNextFileW is a
// different API entirely, handled locally in autoruns_win.cpp) -- guarded
// out by construction, matching win_str.hpp's own `#ifdef _WIN32` pattern
// in the opposite direction.
#pragma once

#if !defined(_WIN32)

#include <cerrno>
#include <cstddef>
#include <dirent.h>
#include <string_view>

namespace yuzu::shared {

struct DirWalkResult {
    bool truncated = false;         // cap reached AND a real entry remained unread
    bool enumeration_error = false; // a real readdir() I/O error stopped the scan
                                    // early -- at EITHER the main loop's own call
                                    // or the cap-boundary lookahead call itself
};

namespace detail {
/// Default readdir seam -- the real libc call. Tests pass their own
/// stateful callable (a lambda with capture, so it can't decay to this
/// function-pointer type) via the `ReadDirFn` template parameter to inject
/// a synthetic I/O error at an exact point in the scan -- issue #4183: a
/// genuine mid-scan readdir() failure isn't reliably reproducible against a
/// real filesystem (see test_posix_dir_walk.cpp's original banner), so the
/// seam is injected at the call boundary instead of relying on a real fault.
using DefaultReadDirFn = struct dirent* (*)(DIR*);
inline struct dirent* default_readdir(DIR* d) { return ::readdir(d); }
} // namespace detail

/// Walks an already-open POSIX directory stream, capped at `cap` real
/// entries (`.`/`..` never counted), invoking `on_entry(const dirent*)` for
/// each. Correctly distinguishes three outcomes a naive `while(readdir())`
/// loop conflates:
///   1. Clean end of directory (readdir() returns null, errno unchanged).
///   2. A real I/O error mid-scan (readdir() returns null, errno set) --
///      `errno` is reset immediately after every successful readdir() call
///      (an RAII guard covers every loop-body exit path, including
///      `on_entry`'s own syscalls potentially setting it) so only readdir()'s
///      OWN errno is ever attributed to it.
///   3. The cap boundary: once `cap` entries are collected, a lookahead scan
///      determines whether more REAL entries existed (`truncated`) -- dot
///      entries encountered during the lookahead are skipped (matching the
///      main loop's own `.`/`..` exclusion), so a directory whose only
///      remaining entries are `.`/`..` is correctly reported clean, not
///      truncated. That lookahead scan can ALSO fail, which must never be
///      silently read as "no more entries" (`enumeration_error`, matching
///      PR #4154 round 8's exact finding).
/// `on_entry` returning `false` stops the walk early without it counting as
/// truncation -- the caller decided it has enough, not that data was missed.
///
/// `readdir_fn` defaults to the real `::readdir` and is overridable only for
/// tests (production call sites never pass it).
template <typename OnEntry, typename ReadDirFn = detail::DefaultReadDirFn>
DirWalkResult walk_dir_capped(DIR* d, std::size_t cap, OnEntry&& on_entry,
                               ReadDirFn&& readdir_fn = &detail::default_readdir) {
    DirWalkResult result;
    std::size_t seen = 0;
    struct dirent* entry = nullptr;
    errno = 0;
    while (seen < cap && (entry = readdir_fn(d)) != nullptr) {
        struct ErrnoResetGuard {
            ~ErrnoResetGuard() { errno = 0; }
        } reset_errno_guard;
        const std::string_view name{entry->d_name};
        if (name == "." || name == "..") continue;
        ++seen;
        if (!on_entry(entry)) return result;
    }
    if (errno != 0) {
        result.enumeration_error = true;
        return result;
    }
    if (seen < cap) return result; // clean end of directory, cap never reached

    // Cap reached -- lookahead for a REAL entry, skipping any trailing `.`/
    // `..` (unspecified readdir() order means either can appear after the
    // cap boundary rather than only before it) so a directory whose only
    // remaining entries are dot entries reports clean, not truncated. The
    // lookahead's OWN errno must be checked independently of the main
    // loop's (already known clean, or we'd have returned above).
    for (;;) {
        errno = 0;
        struct dirent* lookahead = readdir_fn(d);
        if (lookahead == nullptr) {
            if (errno != 0) result.enumeration_error = true;
            return result;
        }
        const std::string_view name{lookahead->d_name};
        if (name == "." || name == "..") continue;
        result.truncated = true;
        return result;
    }
}

} // namespace yuzu::shared

#endif // !defined(_WIN32)
