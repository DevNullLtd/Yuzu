#pragma once

/**
 * execution_artifacts_scratch_sweep.hpp — SELECTION POLICY for reclaiming
 * stale execution_artifacts scratch directories left under agent.data_dir
 * by a crashed or killed amcache dispatch (#4390). Portable: no OS calls,
 * no Windows/POSIX headers -- only the standard library. The Windows shell
 * that actually walks and deletes anything lives in the sibling TU
 * execution_artifacts_scratch_sweep_win.cpp; this header owns only the pure
 * "is this name a scratch dir, and is it old enough" decisions plus the
 * unconditional caps, so they can be reasoned about and unit-tested without
 * a filesystem.
 *
 * ── Name/prefix contract ─────────────────────────────────────────────────
 * `kScratchDirPrefix` MUST equal the literal prefix collect_amcache passes
 * to yuzu_create_temp_dir() (execution_artifacts_win.cpp's own
 * `yuzu_create_temp_dir("execution_artifacts-", ...)` call). temp_file.cpp's
 * build_temp_path_w appends exactly kScratchDirRandomHexLen (32) lowercase
 * hex characters after the prefix and nothing else -- no suffix, no
 * extension -- so `is_scratch_dir_name` below is the exact inverse of that
 * construction, not an approximation of it.
 *
 * ── Clock-guarded-retention adoption (docs/clock-guarded-retention.md,
 *    parts 1-7) — DELIBERATE, PARTIAL adoption ────────────────────────────
 * The doc's guarded shape exists to stop a WRONG WALL CLOCK from destroying
 * real operator data (sessions, routes, command-execution mappings) that
 * cannot be recreated. That threat model does not transfer here: everything
 * this sweep can ever touch is a REGENERABLE COPY this plugin itself made
 * of a system hive (amcache.hve + its .LOG1/.LOG2 sidecars) into its own
 * scratch directory -- never operator data, never the only copy of
 * anything, and trivially reproduced by the next dispatch. A wrong clock
 * reading here can make the sweep reclaim a scratch dir a little early or
 * late; it can never destroy something that cannot be regenerated. On that
 * basis:
 *   - Part 1 (probe by OUTCOME) and part 2 (compare against a PERSISTED
 *     clock reading) are NOT adopted: there is nothing to probe for and no
 *     prior reading worth persisting when the content being aged out is
 *     disposable scratch space, not a record whose true age matters.
 *   - Part 3 (SANITISE the reading) and part 4 (SUPPRESS only a repeat of
 *     the SAME anomaly) are NOT adopted for the same reason: they exist to
 *     stop a transient clock glitch from mass-wiping real records across
 *     passes; a scratch sweep has no "mass-wipe" blast radius to begin with
 *     (see the caps below), so the anomaly-suppression machinery has
 *     nothing to protect.
 *   - Part 5 (cap every accepted pass UNCONDITIONALLY) IS adopted, via the
 *     four `kScratchSweep*` constants below -- a pass never opens more than
 *     kScratchSweepMaxRootEntries root entries, never removes more than
 *     kScratchSweepMaxRemovals candidates, never starts a new candidate once
 *     kScratchSweepMaxWallMs has elapsed (checked before each root entry and
 *     before each candidate -- not preemptive mid-candidate, since one
 *     candidate's own bounded file-unlink loop is never interrupted once
 *     started), and never trusts more than kScratchSweepMaxDirEntries
 *     entries inside one candidate.
 *   - Part 6 (decide deliberately what a missing anchor means) is NOT
 *     adopted: there is no persisted anchor here to be missing.
 *   - Part 7 (elapsed-time thresholds are ABSOLUTE, never relative to a
 *     shrinking remainder) HOLDS: `is_stale` below compares `now - mtime`
 *     against one fixed threshold, exactly as part 7 requires.
 * This partial adoption -- and the reasoning above -- is also recorded in
 * docs/clock-guarded-retention.md's own per-store adoption register (a
 * separate integrator task; not this package).
 *
 * ── The one-hour floor is NOT a data-safety guard ────────────────────────
 * A live scratch directory's safety comes from the OS, not from age: while
 * collect_amcache's ScratchDirGuard-owned handle stays open (no
 * FILE_SHARE_DELETE -- see execution_artifacts_win.cpp's
 * open_scratch_dir_handle banner), Windows itself refuses to delete or
 * rename the directory object out from under it, regardless of how old
 * `is_stale` would judge it to be. `kScratchDirStaleAfterSecs` exists only
 * to cover the narrow window between yuzu_create_temp_dir() creating the
 * directory and open_scratch_dir_handle() opening it, during a CONCURRENT
 * dispatch (the same agent process on another thread, or a plugin-capture
 * process sharing the same data_dir) -- a fresh, still-empty directory has
 * no protecting handle yet for that brief span. One hour is generous
 * headroom over that window, not a claim about how long real content stays
 * meaningful.
 */

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace yuzu::execution_artifacts {

/// MUST equal the literal prefix passed to yuzu_create_temp_dir() at
/// execution_artifacts_win.cpp's collect_amcache call site.
inline constexpr std::string_view kScratchDirPrefix = "execution_artifacts-";

/// Exact number of lowercase-or-uppercase hex characters
/// temp_file.cpp's build_temp_path_w appends after the prefix -- no
/// separator, no suffix.
inline constexpr std::size_t kScratchDirRandomHexLen = 32;

/// One hour. See the file banner's "one-hour floor is NOT a data-safety
/// guard" section for what this threshold actually protects.
inline constexpr std::int64_t kScratchDirStaleAfterSecs = 3600;

// ── Unconditional per-pass caps (clock-guarded-retention part 5) ─────────

/// Maximum entries enumerated directly under agent.data_dir in one pass.
inline constexpr std::size_t kScratchSweepMaxRootEntries = 4096;

/// Maximum candidate scratch directories successfully REMOVED in one pass;
/// once reached, remaining stale candidates wait for the next pass and are
/// counted in ScratchSweepResult::deferred, never silently dropped.
inline constexpr std::size_t kScratchSweepMaxRemovals = 64;

/// Maximum candidates that may FAIL (any reason -- sharing violation,
/// ownership mismatch, non-flat contents, a transient OS error) in one
/// pass, tracked SEPARATELY from kScratchSweepMaxRemovals. Deliberately
/// distinct: a failure consumes none of the "blast radius" a removal does
/// (nothing was deleted), so a run of persistent failures earlier in
/// enumeration order must not be able to exhaust the SAME budget a later,
/// genuinely-removable orphan needs to be reached in the same pass -- the
/// two are counted and capped independently, and only a removal ever stops
/// the pass at kScratchSweepMaxRemovals.
inline constexpr std::size_t kScratchSweepMaxFailures = 256;

/// Maximum wall-clock time (milliseconds) one sweep pass may run.
inline constexpr std::int64_t kScratchSweepMaxWallMs = 2000;

/// Maximum entries enumerated inside one candidate scratch directory. A
/// real scratch dir holds amcache.hve plus its .LOG1/.LOG2 sidecars -- a
/// small, fixed set -- so this is a generous cap, not a working limit.
inline constexpr std::size_t kScratchSweepMaxDirEntries = 64;

/// Outcome of one sweep pass. Every count defaults to zero; `enumerate_error`
/// + `os_error` are set only when the root itself could not be opened/
/// enumerated at all (the pass then did nothing, rather than guessing).
struct ScratchSweepResult {
    std::size_t removed{0};
    std::size_t failed{0};
    std::size_t skipped_fresh{0};
    std::size_t skipped_not_ours{0};
    std::size_t deferred{0};
    bool enumerate_error{false};
    int os_error{0};
};

/// True only for the exact prefix followed by exactly
/// kScratchDirRandomHexLen hex digits (either case) and nothing else -- no
/// shorter/longer hex run, no different prefix, no trailing separator or
/// extra character. The exact inverse of yuzu_create_temp_dir's
/// prefix-then-32-hex construction (see the file banner).
[[nodiscard]] inline bool is_scratch_dir_name(std::string_view name) noexcept {
    if (!name.starts_with(kScratchDirPrefix))
        return false;
    const std::string_view rest = name.substr(kScratchDirPrefix.size());
    if (rest.size() != kScratchDirRandomHexLen)
        return false;
    for (const char c : rest) {
        const bool is_digit = c >= '0' && c <= '9';
        const bool is_lower_hex = c >= 'a' && c <= 'f';
        const bool is_upper_hex = c >= 'A' && c <= 'F';
        if (!is_digit && !is_lower_hex && !is_upper_hex)
            return false;
    }
    return true;
}

/// True only when `now - mtime` is STRICTLY GREATER than `stale_after` --
/// exact equality is FRESH, and a negative age (a future-dated mtime, e.g.
/// clock skew) is also FRESH, never treated as impossibly old. Part 7 of
/// clock-guarded-retention (elapsed-time thresholds are absolute): this
/// compares against one fixed threshold, never a shrinking remainder.
[[nodiscard]] inline bool is_stale(std::int64_t mtime_unix_s, std::int64_t now_unix_s,
                                   std::int64_t stale_after_s) noexcept {
    return (now_unix_s - mtime_unix_s) > stale_after_s;
}

#ifdef _WIN32
/// Sweep `data_dir` for stale execution_artifacts scratch directories and
/// remove them, using confined_fs's handle-relative, ownership-verified
/// primitives (execution_artifacts_scratch_sweep_win.cpp). Never throws;
/// never removes anything whose name fails is_scratch_dir_name, whose type
/// is not a directory, whose age (per is_stale) is not past `stale_after_s`,
/// or whose owner is not this process's own token owner.
[[nodiscard]] ScratchSweepResult
sweep_stale_scratch_dirs(const std::wstring& data_dir, std::int64_t now_unix_s,
                          std::int64_t stale_after_s = kScratchDirStaleAfterSecs) noexcept;
#endif

} // namespace yuzu::execution_artifacts
