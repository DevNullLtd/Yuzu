/**
 * execution_artifacts_scratch_sweep_win.cpp — Windows shell for A1's stale
 * scratch-directory sweep (#4390): implements
 * execution_artifacts_scratch_sweep.hpp's sweep_stale_scratch_dirs() on top
 * of agents/core's confined_fs primitives (open_root / enumerate_at /
 * unlink_at), so every open below agent.data_dir is handle-relative,
 * reparse-refusing and (for the candidate itself) ownership-verified via
 * the hoisted execution_artifacts_scratch_identity.hpp::scratch_dir_is_ours
 * -- the same bar this plugin's own scratch-directory verify-then-use
 * already sets (execution_artifacts_win.cpp's ScratchDirGuard/
 * scratch_dir_is_ours banners).
 *
 * Zero path-resolving opens below the root: open_root() is the ONE
 * CreateFileW-equivalent (inside confined_fs's own open_root); every
 * subsequent open in this file is either confined_fs::enumerate_at /
 * confined_fs::unlink_at, or this file's own open_candidate_relative()
 * helper, which is an NtOpenFile call carrying the pinned root HANDLE as
 * OBJECT_ATTRIBUTES.RootDirectory and a single relative path component
 * (never a joined path string) -- confined_fs::open_dir_at() is
 * deliberately NOT used for the candidate open, because it requests only
 * FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE
 * (confined_fs_win.cpp:360-363) and the ownership check below needs
 * READ_CONTROL too (GetSecurityInfo(OWNER_SECURITY_INFORMATION) requires
 * it) -- confined_fs.hpp is NOT touched to add a parameterised access mask
 * (this package's boundaries: "no confined_fs API change"), so this one
 * extra right is requested by a small, plugin-local NtOpenFile call
 * instead.
 *
 * This sweep NEVER recurses: a real scratch directory is FLAT by
 * construction (amcache.hve plus its .LOG1/.LOG2 sidecars), so a candidate
 * whose own enumeration turns up anything other than a plain regular file
 * is left entirely intact and counted failed, never partially cleaned up
 * and never descended into.
 *
 * kCaptureNamePrefix (confined_fs.hpp) orphans cannot exist under this
 * root: that name is only ever produced by confined_fs's POSIX rename-
 * then-measure delete path, which this Windows leg never uses (Windows
 * deletes by handle disposition, never by rename) -- so there is nothing
 * of that shape for this sweep to reason about here.
 */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h> // NTSTATUS, UNICODE_STRING, OBJECT_ATTRIBUTES, IO_STATUS_BLOCK

#include "execution_artifacts_scratch_identity.hpp" // detail::scratch_dir_is_ours
#include "execution_artifacts_scratch_sweep.hpp"

#include <yuzu/agent/confined_fs.hpp>
#include <yuzu/agent/confined_fs_rules.hpp>

#include <win_str.hpp> // yuzu::win::to_wide (agents/shared/win_str.hpp)

#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <string>

namespace yuzu::execution_artifacts {

namespace {

namespace cfs = yuzu::agent::confined_fs;

// Local NT OpenOptions values -- see confined_fs_win.cpp's identical
// comment on why these are defined locally rather than pulled from
// <ntstatus.h>/a WDK header: <winternl.h> does not reliably export them,
// and duplicating a handful of documented NT constants removes a
// first-real-MSVC-build risk cheaper than adding a WDK dependency for it.
constexpr ULONG kFileDirectoryFile = 0x00000001UL;         // FILE_DIRECTORY_FILE
constexpr ULONG kFileOpenReparsePoint = 0x00200000UL;      // FILE_OPEN_REPARSE_POINT
constexpr ULONG kFileSynchronousIoNonalert = 0x00000020UL; // FILE_SYNCHRONOUS_IO_NONALERT

constexpr bool nt_success(NTSTATUS status) noexcept {
    return status >= 0;
}

using NtOpenFileFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                       ULONG, ULONG);

// Resolved ONCE via GetProcAddress(GetModuleHandleW(L"ntdll.dll"), ...),
// behind a function-local static -- confined_fs_win.cpp's
// resolve_ntcreatefile precedent. A null result is a legitimate outcome:
// callers below never fall back to a path-based open, they just fail this
// one candidate.
NtOpenFileFn resolve_ntopenfile() {
    static const NtOpenFileFn resolved = []() -> NtOpenFileFn {
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
            return nullptr;
        return reinterpret_cast<NtOpenFileFn>(
            reinterpret_cast<void*>(GetProcAddress(ntdll, "NtOpenFile")));
    }();
    return resolved;
}

/// Opens `wide_name` (a single relative path component -- guaranteed
/// separator-free by is_scratch_dir_name having already accepted it)
/// handle-relative to `root`, requesting READ_CONTROL in addition to the
/// usual list/read-attributes rights that confined_fs::open_dir_at itself
/// requests, since the ownership check below needs it and open_dir_at does
/// not carry it (see the file banner). ALSO requests DELETE: collect_amcache's
/// own dest_dir_handle (execution_artifacts_win.cpp's open_scratch_dir_handle)
/// is held for the entire privilege-bearing span with share mode
/// FILE_SHARE_READ only -- no FILE_SHARE_DELETE -- specifically so a
/// concurrent DELETE-seeking open of that same directory is refused for as
/// long as the dispatch holds it. Without DELETE in OUR OWN desired access,
/// this sweep's candidate open would not need to negotiate against that
/// share restriction at all and could proceed to open the directory (for
/// list/read-attributes purposes) and then unlink its children out from
/// under a live dispatch. Requesting DELETE here is what makes this sweep
/// actually observe that protection via ERROR_SHARING_VIOLATION for the
/// dispatch's entire copy-through-RegLoadAppKeyW-through-enumeration span,
/// not just during the narrow window a handle-relative reopen would
/// otherwise miss. Shares for read, write AND delete on OUR OWN handle --
/// so a well-behaved LATER opener (another sweep pass, or the next
/// dispatch once this one completes) is never blocked BY us; only an
/// EXISTING share-restricted handle blocks THIS open, never the reverse.
/// Reparse points are opened raw (never followed); the check is then made
/// explicitly on the returned handle's attributes.
cfs::WinHandle open_candidate_relative(HANDLE root, const std::wstring& wide_name) {
    const NtOpenFileFn fn = resolve_ntopenfile();
    if (fn == nullptr)
        return {};

    if (wide_name.size() * sizeof(wchar_t) > (std::numeric_limits<USHORT>::max)())
        return {};

    UNICODE_STRING object_name{};
    object_name.Length = static_cast<USHORT>(wide_name.size() * sizeof(wchar_t));
    object_name.MaximumLength = object_name.Length;
    // const_cast proof: OBJECT_ATTRIBUTES::ObjectName is an INPUT-only field
    // to NtOpenFile (never written through); `wide_name` outlives this call
    // as a local in the caller. Same proof as confined_fs_win.cpp's
    // make_unicode_string.
    object_name.Buffer = const_cast<PWSTR>(wide_name.c_str());

    OBJECT_ATTRIBUTES attrs{};
    attrs.Length = sizeof(attrs);
    attrs.RootDirectory = root;
    attrs.ObjectName = &object_name;
    attrs.Attributes = 0;
    attrs.SecurityDescriptor = nullptr;
    attrs.SecurityQualityOfService = nullptr;

    HANDLE raw = INVALID_HANDLE_VALUE;
    IO_STATUS_BLOCK iosb{};
    const ACCESS_MASK desired_access =
        FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE | DELETE;
    const ULONG share_access = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    const ULONG open_options =
        kFileDirectoryFile | kFileOpenReparsePoint | kFileSynchronousIoNonalert;

    const NTSTATUS status =
        fn(&raw, desired_access, &attrs, &iosb, share_access, open_options);
    if (!nt_success(status))
        return {};
    return cfs::WinHandle(raw);
}

} // namespace

ScratchSweepResult sweep_stale_scratch_dirs(const std::wstring& data_dir,
                                             std::int64_t now_unix_s,
                                             std::int64_t stale_after_s) noexcept {
    ScratchSweepResult res{};
    try {
        cfs::OpenRootResult opened = cfs::open_root(std::filesystem::path{data_dir});
        if (!opened.root.has_value()) {
            res.enumerate_error = true;
            res.os_error = opened.os_error;
            return res;
        }
        const cfs::ConfinedRoot& root = *opened.root;

        // Computed ONCE, reused for every enumerate_at call this pass makes
        // (the root's and every candidate's) -- confined_fs_walk.hpp's own
        // binding rule for why a re-derived deadline would let the wall-time
        // cap creep forward indefinitely.
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds{kScratchSweepMaxWallMs};

        cfs::EnumerateResult root_entries = cfs::enumerate_at(
            root.h_.get(), root.identity(),
            cfs::EnumBudget{static_cast<std::uint64_t>(kScratchSweepMaxRootEntries), deadline});

        if (root_entries.reason == cfs::Reason::OsError) {
            res.enumerate_error = true;
            res.os_error = root_entries.os_error;
            return res;
        }
        if (root_entries.reason == cfs::Reason::EntryCap ||
            root_entries.reason == cfs::Reason::WallTimeCap) {
            // Truncated -- more entries may exist under data_dir than this
            // pass looked at. Never silently "nothing left" (this
            // package's spec).
            ++res.deferred;
        }

        for (const auto& entry : root_entries.entries) {
            if (!is_scratch_dir_name(entry.name))
                continue; // not ours to consider -- skip silently

            if (entry.meta.type != cfs::EntryType::Directory)
                continue; // never opened -- skip silently

            if (!entry.meta.mtime) {
                // Absence is never treated as "old".
                ++res.failed;
                continue;
            }
            if (!is_stale(*entry.meta.mtime, now_unix_s, stale_after_s)) {
                ++res.skipped_fresh;
                continue;
            }

            // The wall-time deadline is enforced by enumerate_at at entry
            // (root and per-candidate) but NOT by anything in between --
            // check it explicitly here too, before starting a new
            // candidate's open/query/delete sequence, so a long run of
            // slow-but-successful deletions can't carry the pass past its
            // advertised bound. A single already-in-flight file-delete loop
            // below is not itself interrupted mid-candidate (one candidate
            // is a bounded, small unit of work), but no NEW candidate
            // starts once the deadline has passed.
            if (std::chrono::steady_clock::now() >= deadline) {
                ++res.deferred;
                break;
            }

            // Removed and failed are capped SEPARATELY (see
            // kScratchSweepMaxFailures's doc comment): a run of persistent
            // failures earlier in enumeration order must not be able to
            // starve a later, genuinely-removable orphan out of this same
            // pass by exhausting a shared budget.
            if (res.removed >= kScratchSweepMaxRemovals ||
                res.failed >= kScratchSweepMaxFailures) {
                // Whichever cap was hit -- stop considering further entries
                // this pass rather than acting past the configured blast
                // radius.
                ++res.deferred;
                break;
            }

            const std::wstring wide_name = yuzu::win::to_wide(entry.name);
            cfs::WinHandle candidate = open_candidate_relative(root.h_.get(), wide_name);
            if (!candidate) {
                // Includes a sharing violation -- an in-flight dispatch's
                // own handle (no FILE_SHARE_DELETE) blocking this open is
                // exactly the concurrent-dispatch window
                // kScratchDirStaleAfterSecs exists to wait out; leave it
                // for the next pass.
                ++res.failed;
                continue;
            }

            BY_HANDLE_FILE_INFORMATION info{};
            if (!GetFileInformationByHandle(candidate.get(), &info)) {
                ++res.failed;
                continue;
            }
            // Defence in depth over the EntryType check above: reject a
            // reparse point discovered on the OPEN OBJECT itself (a
            // mid-walk swap), and reject a volume mismatch against the
            // pinned root -- both mirror confined_fs's own open_dir_at
            // checks.
            if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                ++res.failed;
                continue;
            }
            if (info.dwVolumeSerialNumber != root.identity().volume_serial) {
                ++res.failed;
                continue;
            }

            if (!detail::scratch_dir_is_ours(candidate.get())) {
                // A planted, foreign-owned directory named like a scratch
                // dir is left entirely alone -- never touched.
                ++res.skipped_not_ours;
                spdlog::debug(
                    "execution_artifacts: scratch sweep leaving foreign-owned candidate '{}' "
                    "under agent.data_dir alone",
                    entry.name);
                continue;
            }

            cfs::EnumerateResult inner = cfs::enumerate_at(
                candidate.get(), root.identity(),
                cfs::EnumBudget{static_cast<std::uint64_t>(kScratchSweepMaxDirEntries), deadline});

            bool candidate_flat_and_clean = inner.reason == cfs::Reason::None;
            if (candidate_flat_and_clean) {
                for (const auto& inner_entry : inner.entries) {
                    if (inner_entry.meta.type != cfs::EntryType::RegularFile) {
                        candidate_flat_and_clean = false;
                        break;
                    }
                }
            }
            if (!candidate_flat_and_clean) {
                // A subdirectory, reparse point, other entry type, a
                // truncated enumeration, or an OS error -- the whole
                // candidate is left intact; this sweep never recurses one
                // level deeper.
                ++res.failed;
                continue;
            }

            bool all_files_deleted = true;
            for (const auto& inner_entry : inner.entries) {
                const cfs::UnlinkOutcome file_outcome = cfs::unlink_at(
                    candidate.get(), inner_entry.name, cfs::UnlinkKind::File,
                    (std::numeric_limits<std::uint64_t>::max)(), root.identity());
                if (file_outcome.status != cfs::EntryStatus::Deleted) {
                    all_files_deleted = false;
                    break;
                }
            }
            if (!all_files_deleted) {
                ++res.failed;
                continue;
            }

            // Close the candidate's own handle BEFORE deleting the now-
            // empty directory itself -- RemoveDirectory-equivalent
            // (delete-by-disposition) semantics need no other open handle
            // on the object being removed, same requirement as
            // ScratchDirGuard's own banner in execution_artifacts_win.cpp.
            candidate.reset();

            const cfs::UnlinkOutcome dir_outcome = cfs::unlink_at(
                root.h_.get(), entry.name, cfs::UnlinkKind::EmptyDirectory, 0, root.identity());
            if (dir_outcome.status == cfs::EntryStatus::Deleted)
                ++res.removed;
            else
                ++res.failed;
        }

        return res;
    } catch (...) {
        ++res.failed;
        return res;
    }
}

} // namespace yuzu::execution_artifacts

#endif // defined(_WIN32)
