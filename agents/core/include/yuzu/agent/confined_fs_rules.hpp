#pragma once

/**
 * confined_fs_rules.hpp -- PURE decision core for confined recursive delete
 * (blast-radius-capped deletion below a pinned root; PLAN-001/002/004/014/016).
 *
 * This header is deliberately OS-header-free and allocation-free in its hot
 * path: `decide_entry` is a single `constexpr noexcept` function so the two
 * platform shells (confined_fs.cpp, one per OS) and the pure walker template
 * (confined_fs_walk.hpp) can be reasoned about, fuzzed, and unit-tested
 * without ever touching disk or a syscall. Allowed includes only:
 * <cstdint>, <chrono>, <string>, <string_view>, <vector>, <functional>,
 * <optional> -- no POSIX headers, no Windows headers, no path-library headers.
 *
 * ── Fail-closed defaults (PLAN-*) ───────────────────────────────────────────
 * A default-constructed `DeleteLimits` (all fields zero-initialized)
 * authorizes NOTHING: `max_entries == 0` trips the entry-cap rule on the very
 * first entry, so `decide_entry` can never return `Unlink` against an
 * unconfigured limits object. A caller MUST explicitly opt into a bounded
 * blast radius; there is no "no cap" sentinel value.
 *
 * ── Byte-cap arithmetic is OVERFLOW-SAFE (PLAN-004, adopted) ────────────────
 * The naive check `bytes_deleted + size_bytes > max_bytes` is WRONG: on a
 * 64-bit unsigned tally, `bytes_deleted + size_bytes` can wrap past
 * UINT64_MAX and come back around to a SMALL value that compares as "under
 * the cap," which would authorize deleting past the configured blast-radius
 * limit -- exactly the failure this cap exists to prevent. The comparison
 * below is therefore written as
 *
 *     bytes_deleted > max_bytes || size_bytes > max_bytes - bytes_deleted
 *
 * which never computes a sum of two `uint64_t`s that could wrap. The
 * invariant this relies on is `bytes_deleted <= max_bytes` at every call
 * (true by construction: `bytes_deleted` only grows by a `size_bytes` that
 * itself passed this same check) -- the first clause is defense-in-depth
 * for a caller that violates that invariant, not the primary guard.
 *
 * A file that trips the byte cap is SKIPPED, not treated as a walk-stopping
 * condition: the walk CONTINUES to later, possibly-smaller entries, so one
 * oversized file cannot block deletion of everything smaller than it that
 * still fits under the remaining budget.
 *
 * ── decide_entry's rule order is BINDING (PLAN-001/002/014) ─────────────────
 * Two other engineers implement the platform shells and the walker against
 * this signature sight-unseen; the first-match order below is not
 * reorderable without a spec change. See the function's own doc comment.
 */

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::agent::confined_fs {

/// What kind of directory entry a directory enumeration produced.
enum class EntryType : std::uint8_t {
    RegularFile,
    Directory,
    Symlink,
    Reparse, // Windows junction/reparse point; POSIX never produces this.
    Other,   // socket, fifo, device node, etc.
};

/// Why an entry was skipped, failed, or the walk stopped. `MatchError` and
/// `Internal` both STOP the walk (PLAN-014): `MatchError` means the caller's
/// `MatchFn` threw, `Internal` means an unexpected exception escaped
/// somewhere else inside the walk body -- both are firewalled by
/// `walk_delete`'s outermost try/catch, never propagated to the caller.
enum class Reason : std::uint8_t {
    None,
    SymlinkRejected,
    ReparseRejected,
    DeviceBoundary,
    NotRegularFile,
    EntryCap,
    ByteCap,
    WallTimeCap,
    DepthCap,
    NameFilteredOut,
    InvalidName,
    OsError,
    RootInvalid,
    Unsupported,
    MatchError,
    Internal,
    /// The entry was captured (renamed aside) but could NOT be restored,
    /// because something now occupies its original name. It was NOT deleted;
    /// it remains under the capture name and the tree HAS been modified.
    CaptureOrphaned,
    /// The walk stopped because it would have had to hold more directory handles
    /// open at once than DeleteLimits::max_open_dirs permits. A cap stop, not a
    /// failure: the tree was NOT fully visited.
    OpenDirCap,
};

/// Terminal per-entry disposition recorded in a `DeleteResult`.
enum class EntryStatus : std::uint8_t {
    Deleted,
    Skipped,
    Failed,
};

/// What `decide_entry` says to do with one entry.
enum class Action : std::uint8_t {
    // Named Unlink (matches UnlinkKind/Ops::unlink); the obvious name collides
    // with an object-like file-deletion macro winbase.h defines even under
    // WIN32_LEAN_AND_MEAN (see confined_fs.hpp's Windows-branch banner).
    Unlink,
    RecurseIntoDir,
    SkipEntry,
    StopWalk,
};

/// Convert a Windows FILETIME (100-nanosecond ticks since 1601-01-01 UTC) to
/// seconds since the Unix epoch, or nullopt when the value is not a timestamp.
///
/// PURE and unit-tested on every platform, deliberately. This is the one piece
/// of arithmetic in the mtime change that can be silently WRONG rather than
/// obviously broken: an incorrect epoch offset or tick scale yields timestamps
/// that are plausible, correctly ORDERED, and off by decades -- so an age
/// filter built on it would still appear to work while selecting the wrong
/// files. Getting that wrong on a DELETION path is not cosmetic, which is why
/// it lives here in the pure layer with its own fixtures rather than inline in
/// the Windows TU where no test could reach it.
///
/// 11644473600 is the number of seconds between 1601-01-01 and 1970-01-01.
///
/// Truncation is toward zero, i.e. FLOOR for every value this guard admits, so a
/// Windows entry can read up to one second OLDER than reality while POSIX's
/// st_mtime is already whole seconds. Against the minute-or-hour thresholds an
/// age filter uses that is immaterial; it is recorded because it errs marginally
/// toward deletion rather than away from it.
///
/// A zero or negative tick count is Windows' "not set", NOT a timestamp of
/// 1601: returning the literal conversion would read to an age filter as
/// impossibly old and therefore safe to delete.
[[nodiscard]] inline constexpr std::optional<std::int64_t>
filetime_to_unix_seconds(std::int64_t ticks) noexcept {
    if (ticks <= 0) return std::nullopt;
    constexpr std::int64_t kTicksPerSecond = 10'000'000;        // 100ns units
    constexpr std::int64_t kEpochDeltaSeconds = 11'644'473'600; // 1601 -> 1970
    return (ticks / kTicksPerSecond) - kEpochDeltaSeconds;
}

/// Metadata `decide_entry` needs about one already-enumerated entry, and that
/// a caller's `MatchFn` may additionally use for its own selection policy.
///
/// `mtime` is here so a consumer can express a MINIMUM AGE without re-opening
/// the entry by path. That distinction is load-bearing rather than convenient:
/// the first consumer of this primitive (disk_actions' temp-file cleanup) is
/// required to refuse files younger than a threshold, and the only other way to
/// learn an entry's age from a `MatchFn` that receives just a path would be to
/// stat that path -- a path-resolving open BELOW THE ROOT, which is precisely
/// what this primitive's first catastrophic invariant forbids and what would
/// hand an attacker the swap target.
///
/// It costs nothing to supply: both platform enumerators already hold the
/// timestamp in the same structure they already read for `size_bytes`
/// (`fstatat`'s `struct stat` on POSIX, `FILE_FULL_DIR_INFO::LastWriteTime` on
/// Windows), both obtained parent-handle-relative. No extra syscall, no new
/// path resolution, and `decide_entry` is deliberately NOT changed -- age is
/// caller policy, not primitive policy, so the binding first-match order below
/// is untouched.
///
/// AGE IS A SAFETY HEURISTIC, NOT A SECURITY CONTROL. This is the same
/// best-effort class as `size_bytes`, and for the same reason: a writer who
/// controls the parent directory can backdate a file (`utimensat`, `SetFileTime`)
/// exactly as it can swap a large file over a measured name. Confinement holds
/// absolutely; SELECTION does not. A minimum-age rule stops this primitive
/// eating a file a legitimate process wrote moments ago -- it does NOT stop a
/// local attacker choosing what gets deleted, and no consumer may present it
/// as though it does.
struct EntryMeta {
    EntryType type;
    std::uint64_t size_bytes;
    bool same_device_as_root;

    /// Seconds since the Unix epoch, or `nullopt` when this platform could not
    /// supply one. SIGNED because pre-1970 timestamps exist on real
    /// filesystems (restored archives, deliberately backdated files) and a
    /// caller comparing ages must see them as old rather than as enormous
    /// positive values.
    ///
    /// OPTIONAL, NOT A SENTINEL, and that is a corrected defect rather than a
    /// style choice. An earlier revision used INT64_MIN for "unknown", reasoning
    /// that unknown should mean "do not act". It achieved the opposite: the
    /// natural predicate `now - mtime >= min_age` reads INT64_MIN as older than
    /// the epoch -- MAXIMALLY deletable, worse than the 0 the comment rejected --
    /// and the subtraction is signed-overflow UB that traps under UBSan. Any
    /// numeric sentinel has that shape. `optional` makes absence
    /// unrepresentable as a number, so no arithmetic can silently take the
    /// wrong branch; a caller must decide what absence means before it can
    /// compute anything.
    std::optional<std::int64_t> mtime;
};

/// Caller-supplied blast-radius caps. Zero-initialized fields are
/// deliberately the most restrictive possible value for that field (see the
/// header banner) -- there is no "unlimited" sentinel.
struct DeleteLimits {
    std::uint64_t max_entries{0};
    std::uint64_t max_bytes{0};
    std::chrono::milliseconds max_wall{0};
    std::uint32_t max_depth{0};
    /// Maximum directory handles the walk may hold OPEN AT ONCE. The other caps
    /// bound work; this one bounds the resource the walk actually consumes. The
    /// walker opens a handle per pending subdirectory, so a wide tree under a
    /// large max_entries could otherwise exhaust the PROCESS's descriptor
    /// budget -- degrading gRPC, SQLite and plugin loading in the same agent,
    /// not merely this walk. Zero permits nothing, like every other cap here.
    std::uint32_t max_open_dirs{0};
};

/// Running counters `decide_entry` is evaluated against; the walker owns the
/// single live instance and updates it after each acted-upon entry.
struct WalkTally {
    std::uint64_t entries_seen{0};
    std::uint64_t bytes_deleted{0};
};

/// One `decide_entry` verdict.
struct Decision {
    Action action;
    Reason reason;
};

/**
 * Decide what to do with one entry. First-match order, BINDING:
 *
 *   1. deadline_exceeded            -> StopWalk(WallTimeCap)
 *   2. entries_seen >= max_entries  -> StopWalk(EntryCap)
 *   3. type == Symlink              -> SkipEntry(SymlinkRejected)
 *   4. type == Reparse              -> SkipEntry(ReparseRejected)
 *   5. !same_device_as_root         -> SkipEntry(DeviceBoundary)
 *   6. type == Directory            -> depth_exceeded ? SkipEntry(DepthCap)
 *                                                      : RecurseIntoDir
 *   7. type == Other                -> SkipEntry(NotRegularFile)
 *   8. !name_matched                -> SkipEntry(NameFilteredOut)
 *   9. byte-cap overflow-safe check -> SkipEntry(ByteCap)
 *  10. else                         -> Unlink
 *
 * Rules 1-2 are walk-level stops and take priority over anything else about
 * the entry (a symlink discovered past the entry cap reports EntryCap, not
 * SymlinkRejected). Rules 3-7 are structural/policy rejections that never
 * need the entry's match state. Rule 8 is why `walk_delete` uses the LAZY
 * MATCH protocol (see confined_fs_walk.hpp): `name_matched` is only
 * meaningful, and only costs a `MatchFn` call, once every earlier rule has
 * already passed. Rule 9 is the overflow-safe byte-cap form documented in
 * the header banner. `name_matched=true` combined with a small enough
 * `size_bytes` falls through every rule to `Unlink`.
 */
[[nodiscard]] constexpr Decision decide_entry(const EntryMeta& meta, const DeleteLimits& limits,
                                               const WalkTally& tally, bool deadline_exceeded,
                                               bool depth_exceeded, bool name_matched) noexcept {
    if (deadline_exceeded)
        return Decision{Action::StopWalk, Reason::WallTimeCap};
    if (tally.entries_seen >= limits.max_entries)
        return Decision{Action::StopWalk, Reason::EntryCap};
    if (meta.type == EntryType::Symlink)
        return Decision{Action::SkipEntry, Reason::SymlinkRejected};
    if (meta.type == EntryType::Reparse)
        return Decision{Action::SkipEntry, Reason::ReparseRejected};
    if (!meta.same_device_as_root)
        return Decision{Action::SkipEntry, Reason::DeviceBoundary};
    if (meta.type == EntryType::Directory)
        return depth_exceeded ? Decision{Action::SkipEntry, Reason::DepthCap}
                               : Decision{Action::RecurseIntoDir, Reason::None};
    if (meta.type == EntryType::Other)
        return Decision{Action::SkipEntry, Reason::NotRegularFile};
    if (!name_matched)
        return Decision{Action::SkipEntry, Reason::NameFilteredOut};
    // Overflow-safe byte-cap check (PLAN-004): never compute
    // `tally.bytes_deleted + meta.size_bytes` -- see header banner.
    if (tally.bytes_deleted > limits.max_bytes ||
        meta.size_bytes > limits.max_bytes - tally.bytes_deleted)
        return Decision{Action::SkipEntry, Reason::ByteCap};
    return Decision{Action::Unlink, Reason::None};
}

/// Enumeration-level budget (PLAN-001): enumerating a directory is itself
/// bounded by the same entry cap and wall-time deadline as the walk, so a
/// directory with more entries than the remaining budget cannot be used to
/// evade the walk-level caps by enumerating unboundedly before any entry is
/// ever decided.
struct EnumBudget {
    std::uint64_t max_entries{0};
    std::chrono::steady_clock::time_point deadline;
};

/// One raw directory entry as returned by a platform `enumerate`.
/// `stat_error != 0` (PLAN-002) means metadata acquisition for this entry
/// failed -- the walker records `Failed(OsError, stat_error)` and NEVER
/// deletes it (never treats a stat failure as "safe to skip and move on"
/// silently; the failure is recorded). `name_invalid` (PLAN-016) means the
/// platform could not round-trip the native on-disk name into `name` --
/// the walker records `Skipped(InvalidName)` and never lets it reach
/// `decide_entry`'s name-match rule at all.
struct DirEntry {
    std::string name;
    EntryMeta meta;
    int stat_error{0};
    bool name_invalid{false};
};

/// Result of enumerating one directory under a budget.
/// `reason == None` means the directory was fully enumerated (not
/// truncated). `EntryCap`/`WallTimeCap` mean enumeration itself was
/// truncated by `EnumBudget` -- `entries` holds at most `budget.max_entries`
/// entries. `OsError` means the enumeration syscall itself failed (as
/// opposed to a per-entry `stat_error`).
struct EnumerateResult {
    std::vector<DirEntry> entries;
    Reason reason{Reason::None};
    int os_error{0};
};

/// What kind of on-disk object `unlink` is being asked to remove --
/// platform `unlink_at` uses this to pick the right syscall (unlink vs
/// rmdir/RemoveDirectory) rather than inferring it from a stat.
enum class UnlinkKind : std::uint8_t {
    File,
    EmptyDirectory,
};

/// Outcome of one unlink/rmdir attempt.
/// Structural component-name validation, shared by BOTH platform legs (PLAN-015).
/// A directory-entry name is refused BEFORE any syscall when it is empty, `.`,
/// `..`, carries a path separator, or contains an EMBEDDED NUL -- the last
/// checked against size(), never strlen, because `c_str()` would truncate there
/// and the syscall would then act on a different name than the one validated.
/// `windows_separators` additionally refuses a backslash. This lives here, in
/// the OS-free header, because it is pure decision logic: two hand-copies of one
/// binding rule is exactly the drift the shared walker was centralised to stop.
[[nodiscard]] constexpr bool is_invalid_component(std::string_view name,
                                                 bool windows_separators) noexcept {
    if (name.empty() || name == "." || name == "..")
        return true;
    if (name.find('/') != std::string_view::npos)
        return true;
    if (windows_separators && name.find('\\') != std::string_view::npos)
        return true;
    if (name.find('\0') != std::string_view::npos)
        return true;
    return false;
}

struct UnlinkOutcome {
    EntryStatus status;
    Reason reason;
    int os_error;
    /// Bytes actually removed, measured by the platform leg immediately before
    /// the delete -- NOT the size seen during enumeration. The walker adds THIS
    /// to the tally: an entry swapped between enumeration and delete would
    /// otherwise let a large file be removed while the cap was charged the small
    /// size seen earlier, defeating the byte cap it is meant to enforce.
    /// Zero on any non-Deleted outcome.
    std::uint64_t bytes{0};
};

/// One entry's terminal outcome as recorded into a `DeleteResult`.
struct EntryOutcome {
    std::string rel_path;
    EntryStatus status;
    Reason reason;
    int os_error;
};

/// Overall result of a `delete_matching` / `walk_delete` run.
/// `stop_reason == None` means the walk completed (visited everything
/// reachable under the caps); any other value names why it stopped early.
struct DeleteResult {
    std::vector<EntryOutcome> entries;
    Reason stop_reason;
    WalkTally tally;
};

/// Caller-supplied predicate deciding whether a given entry should be deleted
/// at all. Name, glob and AGE filtering all live entirely in the caller's
/// closure -- this header knows nothing about match syntax or policy.
///
/// The entry's metadata is passed alongside the path so an age or size policy
/// never has to re-open the entry by path to learn what it needs; see
/// `EntryMeta::mtime` for why that matters here specifically. `meta` is
/// the same value `decide_entry` was given, so a `MatchFn` and the primitive
/// always reason about identical facts.
///
/// BORROWED FOR THE CALL ONLY. `rel_path` views a string the walker owns and
/// `meta` references an entry in the enumeration buffer; both are valid for the
/// duration of the invocation and no longer. A predicate needing either beyond
/// that must copy it.
///
/// May throw; `walk_delete` firewalls that into `Reason::MatchError`.
using MatchFn = std::function<bool(std::string_view rel_path, const EntryMeta& meta)>;

} // namespace yuzu::agent::confined_fs
