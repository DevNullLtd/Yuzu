#pragma once

/**
 * local_security_policy_scratch_sweep.hpp -- the PURE decisions behind the
 * Windows leg's secedit export: which leftover directories under
 * agent.data_dir the pre-dispatch sweep may reclaim, how the secedit run and
 * the read of its output are classified. No OS calls -- only the standard
 * library -- so every decision compiles on every OS (the plugin has no dedicated
 * unit suite; the decisions were kept pure so one can be added). The shell in
 * local_security_policy_win.cpp only performs what these functions return. The
 * exported-INI -> rows mapping is NOT here: it is the parsers header's.
 *
 * Why a sweep: the CHILD (secedit) writes the export, so a crash or service
 * stop between export and the agent's RAII delete orphans a copy of the
 * machine's policy under agent.data_dir. Each Windows policy dispatch with
 * agent.data_dir set and the system directory resolved sweeps stale
 * `local_security_policy-<32 hex>` directories BEFORE spawning.
 *
 * The selection policy is shaped after execution_artifacts' (prefix + 32 hex +
 * strict age + unconditional caps). It is a plugin-local COPY, not a lift into
 * agents/shared: that root takes zero-dependency leaves only and this package
 * needs agents/core (confined_fs's WinHandle, via the identity header), so the
 * real destination is agents/core/include/yuzu/agent/ beside confined_fs.hpp.
 * Tracked for extraction as its own change; until then a fix to either copy
 * MUST be applied to both.
 *
 * ---- Clock-guarded-retention adoption (docs/clock-guarded-retention.md,
 *      parts 1-7) -- DELIBERATE, PARTIAL adoption, decided here -------------
 * This is a wall-clock-cutoff reclaim pass, so the routed concern applies, and
 * it is the RECORDED reasoning that satisfies it -- copying a guard without
 * deciding is itself the defect the concern names. The doc's shape exists to
 * stop a wrong wall clock destroying real operator data that cannot be
 * recreated. Nothing here is that: the only thing this sweep can touch is a
 * `secedit /export` output THIS PLUGIN staged into its own scratch directory,
 * a regenerable copy of the host's own policy that the next dispatch
 * reproduces exactly. A wrong clock can reclaim such a directory early or
 * late; it can destroy nothing.
 *   - Parts 1 (probe by OUTCOME) and 2 (compare against a PERSISTED reading):
 *     NOT adopted -- nothing to probe for, and no prior reading worth
 *     persisting when what ages out is disposable scratch space.
 *   - Parts 3 (SANITISE the reading) and 4 (SUPPRESS only a repeat of the SAME
 *     anomaly): NOT adopted -- they exist to stop a transient clock glitch
 *     mass-wiping records across passes, and the caps below leave no mass-wipe
 *     blast radius for that machinery to protect.
 *   - Part 5 (cap every accepted pass UNCONDITIONALLY): ADOPTED, via the five
 *     kScratchSweep* constants -- root entries enumerated, removals per pass,
 *     FAILURES per pass, one wall deadline computed once for the whole pass,
 *     and entries per candidate. A truncated enumeration or a spent budget is
 *     reported as `deferred`, never as done.
 *   - Part 6 (decide deliberately what a missing anchor means): NOT adopted --
 *     there is no persisted anchor here to be missing. Single-process by
 *     construction.
 *   - Part 7 (thresholds ABSOLUTE, never relative to a shrinking remainder):
 *     HOLDS -- is_stale compares now - mtime against one fixed threshold.
 * ON THE CONSTANTS. The concern forbids copying NUMBERS rather than shape, so
 * be exact about what happened here: all five caps and the one-hour floor are
 * the SAME VALUES as execution_artifacts' (4096 / 64 / 256 / 2000 / 64, 3600 s),
 * and that is deliberate, not inherited by default -- the substrate is identical
 * (Windows filesystem, agent process, the same confined_fs primitives, the same
 * create-to-open window), so the same numbers are the right answer and a
 * different one would need its own justification. Only one DERIVATION differs:
 * kScratchSweepMaxDirEntries is 64 here because a real export directory holds
 * exactly ONE file (policy.inf), where the sibling reaches the same 64 sizing
 * for a hive plus its .LOG1/.LOG2 sidecars. kScratchSweepMaxFailures is capped
 * separately from removals for the reason the sibling gives at its own
 * declaration -- a failure deletes nothing, so persistent failures early in
 * enumeration order must not exhaust the budget a later removable orphan needs.
 * This adoption is also recorded in docs/clock-guarded-retention.md's own
 * per-store adoption register.
 *
 * The one-hour floor is not a data-safety guard: a live directory is protected
 * by the dispatch holding it open without FILE_SHARE_DELETE; the floor only
 * covers the create-to-open window of a concurrent dispatch.
 */

#include "local_security_policy_parsers.hpp" // RunEnd

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::local_security_policy {

// -- Scratch directory naming -------------------------------------------------

/// MUST equal the literal prefix passed to yuzu_create_temp_dir() in
/// local_security_policy_win.cpp.
inline constexpr std::string_view kScratchDirPrefix = "local_security_policy-";

/// yuzu_create_temp_dir appends exactly this many hex characters (128 bits).
inline constexpr std::size_t kScratchDirRandomHexLen = 32;

/// One hour; strictly-greater comparison (see is_stale).
inline constexpr std::int64_t kScratchDirStaleAfterSecs = 3600;

// -- Unconditional per-pass caps ----------------------------------------------

inline constexpr std::size_t kScratchSweepMaxRootEntries = 4096;
inline constexpr std::size_t kScratchSweepMaxRemovals = 64;
/// Counted separately from removals: failures delete nothing, so a run of
/// persistent failures must not starve a later removable orphan.
inline constexpr std::size_t kScratchSweepMaxFailures = 256;
inline constexpr std::int64_t kScratchSweepMaxWallMs = 2000;
/// A real export directory holds one file (policy.inf).
inline constexpr std::size_t kScratchSweepMaxDirEntries = 64;

struct ScratchSweepResult {
    std::size_t removed{0};
    std::size_t failed{0};
    std::size_t skipped_fresh{0};
    std::size_t skipped_not_ours{0};
    std::size_t deferred{0};
    bool enumerate_error{false};
    int os_error{0};
};

/// True only for the exact prefix followed by exactly 32 hex digits (either
/// case) and nothing else.
[[nodiscard]] inline bool is_scratch_dir_name(std::string_view name) noexcept {
    if (!name.starts_with(kScratchDirPrefix))
        return false;
    const std::string_view rest = name.substr(kScratchDirPrefix.size());
    if (rest.size() != kScratchDirRandomHexLen)
        return false;
    for (const char c : rest) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                         (c >= 'A' && c <= 'F');
        if (!hex)
            return false;
    }
    return true;
}

/// True only when `now - mtime` is STRICTLY GREATER than `stale_after`: exact
/// equality and a future-dated mtime (clock skew) are both FRESH.
[[nodiscard]] inline bool is_stale(std::int64_t mtime_unix_s, std::int64_t now_unix_s,
                                   std::int64_t stale_after_s) noexcept {
    return (now_unix_s - mtime_unix_s) > stale_after_s;
}

enum class SweepCandidate {
    NotCandidate, // wrong name shape or not a directory -- never opened
    NoMtime,      // absence of an mtime is never treated as "old"
    Fresh,        // younger than the threshold -- left for a later pass
    Stale,        // eligible for the ownership check and removal
};

[[nodiscard]] inline SweepCandidate
classify_sweep_candidate(std::string_view name, bool is_directory,
                         std::optional<std::int64_t> mtime_unix_s, std::int64_t now_unix_s,
                         std::int64_t stale_after_s) noexcept {
    if (!is_scratch_dir_name(name) || !is_directory)
        return SweepCandidate::NotCandidate;
    if (!mtime_unix_s)
        return SweepCandidate::NoMtime;
    return is_stale(*mtime_unix_s, now_unix_s, stale_after_s) ? SweepCandidate::Stale
                                                              : SweepCandidate::Fresh;
}

/// A stale candidate is removed only when this process's token owner owns it;
/// a same-named directory owned by any other SID is skipped, never touched.
[[nodiscard]] inline bool sweep_may_remove(bool owned_by_current_token_owner) noexcept {
    return owned_by_current_token_owner;
}

/// Log-line only, never a row or a constraint token: the wire carries no
/// provenance for a sweep, so the agent log is the ONLY surface a sweep's
/// health has. Each outcome is therefore named rather than summed. An earlier
/// shape collapsed fresh + foreign-SID + failed + deferred into one `skipped`
/// number, which made "two concurrent dispatches" (healthy) and "two orphans
/// that could not be removed" (disk accumulating) the same string. `failed`
/// and `deferred` are the two that mean the sweep is not reclaiming; keep them
/// separately visible. Same counter set execution_artifacts' own sweep logs.
[[nodiscard]] inline std::string format_sweep_summary(const ScratchSweepResult& r) {
    return "scratch_sweep: removed " + std::to_string(r.removed) + " failed " +
           std::to_string(r.failed) + " fresh " + std::to_string(r.skipped_fresh) +
           " not_ours " + std::to_string(r.skipped_not_ours) + " deferred " +
           std::to_string(r.deferred);
}

/// True when a pass did anything worth a log line. A steady-state pass finds
/// nothing and says nothing: this runs before each Windows policy dispatch, and an
/// unconditional per-dispatch info line is noise at fleet scale (the agent core
/// already logs one line per command with rc, timing and provenance).
[[nodiscard]] inline bool sweep_worth_logging(const ScratchSweepResult& r) noexcept {
    return r.removed > 0 || r.failed > 0 || r.skipped_not_ours > 0 || r.deferred > 0 ||
           r.enumerate_error;
}

// -- secedit run / read classification ----------------------------------------

inline constexpr std::int64_t kExportDeadlineMs = 30'000;
inline constexpr std::size_t kExportMaxBytes = 1024 * 1024; // 1 MiB

/// Win32 error numbers, plain integers here and static_asserted against
/// winerror.h in the Windows TU.
inline constexpr unsigned long kWin32FileNotFound = 2;
inline constexpr unsigned long kWin32PathNotFound = 3;
inline constexpr unsigned long kWin32AccessDenied = 5;

/// Empty string = the run succeeded; otherwise the CONSTRAINED token.
[[nodiscard]] inline std::string classify_export_run(RunEnd end, int exit_code) {
    switch (end) {
    case RunEnd::SpawnError:
        return "secedit:spawn_error";
    case RunEnd::Deadline:
        return "secedit:deadline"; // the same word as pwpolicy:deadline, one fleet query
    case RunEnd::Cancelled:
        return "secedit:cancelled";
    case RunEnd::Signaled:
        return "secedit:signaled";
    case RunEnd::Other:
        return "secedit:unexpected_termination";
    case RunEnd::Exited:
        break;
    }
    return exit_code == 0 ? std::string{} : "secedit:exit_" + std::to_string(exit_code);
}

struct ExportReadFailure {
    bool permission_denied{false}; // -> PERMISSION_DENIED, else CONSTRAINED
    std::string token;
};

/// Classifies a failed open/read of the exported file. A refused read is
/// PERMISSION_DENIED; a file that is not there after a zero exit is its own
/// token; anything else keeps its Win32 number. Never reads as "absent".
[[nodiscard]] inline ExportReadFailure classify_export_read_error(unsigned long win32_error) {
    if (win32_error == kWin32AccessDenied)
        return {true, "secedit:access_denied"};
    if (win32_error == kWin32FileNotFound || win32_error == kWin32PathNotFound)
        return {false, "secedit:output_missing"};
    return {false, "secedit:read_" + std::to_string(win32_error)};
}

/// The exported object's shape, decided before any byte is read; nullopt = usable.
/// Lives here rather than in the leg TU so every `secedit:` read-side wire token
/// is decided by one pure layer.
[[nodiscard]] inline std::optional<ExportReadFailure>
classify_export_object(bool reparse_or_directory, std::uint64_t size_bytes) {
    if (reparse_or_directory)
        return ExportReadFailure{false, "secedit:output_not_regular"};
    if (size_bytes > kExportMaxBytes)
        return ExportReadFailure{false, "secedit:output_oversized"};
    return std::nullopt;
}

/// A short read is never a complete export: the file is smaller than the size
/// the handle just reported, so what decoded is a prefix. A truncated-but-
/// even-length UTF-16LE prefix still decodes and can still carry `[System
/// Access]`, which would report `absent` for keys the export really holds --
/// a wrong answer with status OK. Empty string = complete.
[[nodiscard]] inline std::string classify_export_read_length(std::uint64_t expected,
                                                             std::uint64_t got) {
    return got == expected ? std::string{} : "secedit:output_short_read";
}

/// A real export is never empty, so an empty decode is a failed decode, exactly
/// like a decode that did not happen. A U+0000 ANYWHERE is `secedit:embedded_nul`,
/// as checked_read does for files: a NUL in a key that is then never found would
/// otherwise report that key `absent` under OK. Empty string = usable.
[[nodiscard]] inline std::string
classify_decoded_export(const std::optional<std::string>& text) {
    if (!text || text->empty()) return "secedit:decode_failed";
    return text->find('\0') == std::string::npos ? std::string{} : "secedit:embedded_nul";
}

} // namespace yuzu::local_security_policy
