/**
 * local_security_policy_win.cpp -- Windows leg of local_security_policy:
 * password_policy / lockout_policy / audit_policy read from ONE
 * `secedit /export` of the SECURITYPOLICY area, parsed from its UTF-16LE INI.
 *
 * RUNG 2 (an honest argv leaf, not rung 1): no in-tree LSA policy-query
 * precedent, NetUserModalsGet passed over, and docs/agent-privilege-model.md "Audit and review"
 * names `secedit /export` the authoritative source on a running box. Spawned via
 * yuzu::agent::run_bounded_subprocess (Job-Object path unchanged), argv[0] the
 * absolute `<system directory>\secedit.exe` resolved through
 * yuzu::agent::windows_system_directory() (GetSystemDirectoryW, never a guessed
 * `C:\Windows\System32` literal; unresolved -> `secedit:system_directory_unresolved`),
 * no shell/PowerShell/.bat/.cmd. Sink-manifest site ID:
 * local_security_policy/do_export#1 (one spawn per dispatch, all three actions).
 * Read-only as far as host policy goes: no /configure, /import, other area or auditpol.
 *
 * ---- What this leg writes to disk --------------------------------------------
 * The CHILD writes the export: `<agent.data_dir>\local_security_policy-<32 hex>\policy.inf`,
 * the WHOLE SECURITYPOLICY area (privilege-right assignments with SIDs, registry
 * values, ...), not only the keys reported. The agent creates that directory per
 * dispatch with yuzu_create_temp_dir("local_security_policy-", data_dir) (128-bit
 * random name, CREATE_NEW, owner-only DACL; `constrained|data_dir_unset` when
 * data_dir is empty -- no fallback location), holds it open without
 * FILE_SHARE_DELETE, verifies with scratch_dir_is_ours, and removes it (RAII)
 * on every survivable path. A crash or service stop between export and delete
 * orphans that copy, so each Windows policy dispatch with agent.data_dir set and the
 * system directory resolved first sweeps stale `local_security_policy-<32hex>`
 * directories older than one hour under data_dir through agents/core confined_fs
 * (open_root / enumerate_at / unlink_at), ownership-verified: a same-named directory
 * owned by another SID is skipped, a non-flat one is left intact. RESIDUAL: an orphan
 * younger than one hour, or one left with no later Windows dispatch, stays on disk
 * until a sweep reaches it (an uninstall that keeps the data directory keeps it too).
 * NO STARTUP SWEEP (declined, unlike execution_artifacts' init-time pass): the sweep
 * already runs before every export, and an orphan's directory is owner-only, so a
 * restart-time pass would only shorten that window.
 * kCaptureNamePrefix (confined_fs.hpp) orphans cannot exist under this root: that
 * name is produced only by confined_fs's POSIX rename-then-measure delete path, and
 * this Windows sweep deletes by handle disposition and never renames -- so there is
 * nothing of that shape for it to reason about (execution_artifacts' decision too).
 * A non-default agent.data_dir (an SMB share whose owner reads as HOST$, a non-NTFS
 * volume, a path over MAX_PATH) is unmeasured and may fail the leg as `dest_dir_acl`
 * or `secedit:exit_<n>`. Per
 * Microsoft's secedit documentation, with no /log argument secedit appends to its default
 * log (%windir%\security\logs\scesrv.log); the rig wrote none with or without /log (2026-09-30),
 * and /log <scratch>\secedit.log is passed anyway so any output stays in the scratch dir. The
 * sweep outcome is logged at warn, only when the pass did something, as
 * `scratch_sweep: removed <n> failed <n> fresh <n> not_ours <n> deferred <n>`
 * (format_sweep_summary) -- never a row or a token.
 *
 * ---- Pure/thin split -------------------------------------------------------
 * Every decision (sweep selection, run/read classification) is a pure function
 * in local_security_policy_scratch_sweep.hpp, OS-free so it compiles everywhere.
 * The exported INI -> rows mapping is NOT in this TU: it is the parsers header's
 * (secedit_policy_rows), the one mapper. Both pure layers are unit-tested in
 * test_local_security_policy_parsers.cpp; this TU (the Win32 calls) is covered only by the
 * rig probe below -- the unit suite's dispatcher never sets agent.data_dir, so on Windows it
 * stops at the fail-closed `data_dir_unset` row. This TU performs the Win32 calls and writes
 * what those return. The exception
 * boundary is the shared execute(); it is not repeated here.
 *
 * ---- RIG PROBE (the-rig, 2026-09-21; sweep contract re-run 2026-09-29) -------------
 * The exact argv was run as LocalSystem (scheduled task, RunLevel Highest) on the-rig
 * (Windows 11 Pro 10.0.26200 x64, standalone, not domain-joined): exit 0, `[System Access]
 * [Event Audit] [Registry Values] [Version]` in that order, SeSecurityPrivilege present but
 * Disabled. It does not show which privilege is required, nor that NT SERVICE\YuzuAgent
 * (#1442) succeeds -- neither was measured; a refusal would surface as `secedit:exit_<n>`
 * (CONSTRAINED), also unmeasured. Sweep, with a SYSTEM-owned stale directory, a
 * BUILTIN\Administrators-owned one of the same shape and a fresh one under data_dir:
 * the stale one was removed, the foreign-owned and fresh ones were left alone.
 * No fixture of the export is committed.
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

#include "local_security_policy_legs.hpp"
#include "local_security_policy_parsers.hpp" // decode_utf16le_bom, parse_inf_sections,
                                              // secedit_export_complete, secedit_policy_rows
#include "local_security_policy_scratch_identity.hpp"
#include "local_security_policy_scratch_sweep.hpp"

#include <yuzu/agent/confined_fs.hpp>
#include <yuzu/agent/confined_fs_rules.hpp>
#include <yuzu/agent/subprocess_runner.hpp>
#include <yuzu/plugin.hpp> // yuzu_create_temp_dir

#include <win_str.hpp> // yuzu::win::to_wide

#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace yuzu::local_security_policy {

namespace {

namespace cfs = yuzu::agent::confined_fs;

static_assert(kWin32FileNotFound == ERROR_FILE_NOT_FOUND);
static_assert(kWin32PathNotFound == ERROR_PATH_NOT_FOUND);
static_assert(kWin32AccessDenied == ERROR_ACCESS_DENIED);

/// The leading `constrained` is this leg's GENERIC failure-row tag, not a mirror
/// of `status` -- a PERMISSION_DENIED result also writes `constrained|<token>`,
/// with the typed status and the token (`secedit:access_denied`) carrying the
/// distinction. That shape is the declared one (README "Outputs", and the
/// `row_kind` enum of the three policy definitions). Built through join_row so the token
/// passes the same escaper every other row in this plugin uses: today every token
/// is a literal or a `std::to_string`d integer, and this keeps that a property of
/// the code rather than of the current token list.
int emit_failure(yuzu::CommandContext& ctx, YuzuResultStatus status, const std::string& token) {
    ctx.set_result_status(status, YUZU_RESULT_COMPLETENESS_PARTIAL, token);
    ctx.write_output(join_row("constrained", {token}));
    // Unlike execution_artifacts' identically-named helper, this plugin's rc contract
    // (set by apply_collected in local_security_policy_legs.hpp, which the Linux/macOS
    // legs always route through) is "a read returns 0, degradation is the status" --
    // rc is not a proxy for OK-vs-degraded here. This Windows-only helper bypasses
    // apply_collected entirely, so it must return 0 itself or the three secedit-backed
    // actions silently diverge from the plugin's own documented, tested contract.
    return 0;
}

int emit_constrained(yuzu::CommandContext& ctx, const std::string& token) {
    return emit_failure(ctx, YUZU_RESULT_STATUS_CONSTRAINED, token);
}

// ---- Stale sweep (confined_fs shell over the pure policy) -------------------

// Local NT option values -- <winternl.h> does not reliably export them
// (confined_fs_win.cpp's identical rationale).
constexpr ULONG kFileDirectoryFile = 0x00000001UL;
constexpr ULONG kFileOpenReparsePoint = 0x00200000UL;
constexpr ULONG kFileSynchronousIoNonalert = 0x00000020UL;

using NtOpenFileFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                       ULONG, ULONG);

NtOpenFileFn resolve_ntopenfile() {
    static const NtOpenFileFn resolved = []() -> NtOpenFileFn {
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
            return nullptr;
        // The documented GetProcAddress pattern (confined_fs_win.cpp:18-20 does the same for
        // NtCreateFile): FARPROC -> void* -> the exact NtOpenFile signature declared above.
        // ntdll is mapped into every process for its whole lifetime, so the pointer never
        // dangles; it is only ever called through NtOpenFileFn, never as FARPROC.
        return reinterpret_cast<NtOpenFileFn>(
            reinterpret_cast<void*>(GetProcAddress(ntdll, "NtOpenFile")));
    }();
    return resolved;
}

/// Opens `wide_name` (one separator-free component) handle-relative to `root`
/// with READ_CONTROL (the owner check needs it) and DELETE (so it collides with
/// a live dispatch's no-FILE_SHARE_DELETE handle: a sharing violation, never a
/// delete under an in-flight export). Reparse points are opened raw.
cfs::WinHandle open_candidate_relative(HANDLE root, const std::wstring& wide_name) {
    const NtOpenFileFn fn = resolve_ntopenfile();
    if (fn == nullptr)
        return {};
    // An empty ObjectName with RootDirectory set is the NT "reopen the parent"
    // form, which would hand the sweep a handle to data_dir itself. Unreachable
    // (the name has already passed is_scratch_dir_name, so it is ASCII and
    // to_wide cannot empty it), but confined_fs_win.cpp's to_wide_checked refuses
    // it explicitly and this mirrors that primitive.
    if (wide_name.empty())
        return {};
    if (wide_name.size() * sizeof(wchar_t) > (std::numeric_limits<USHORT>::max)())
        return {};

    UNICODE_STRING object_name{};
    object_name.Length = static_cast<USHORT>(wide_name.size() * sizeof(wchar_t));
    object_name.MaximumLength = object_name.Length;
    // ObjectName is input-only to NtOpenFile; wide_name outlives the call.
    object_name.Buffer = const_cast<PWSTR>(wide_name.c_str());

    OBJECT_ATTRIBUTES attrs{};
    attrs.Length = sizeof(attrs);
    attrs.RootDirectory = root;
    attrs.ObjectName = &object_name;

    HANDLE raw = INVALID_HANDLE_VALUE;
    IO_STATUS_BLOCK iosb{};
    const ACCESS_MASK access =
        FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE | DELETE;
    const ULONG share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    const ULONG options = kFileDirectoryFile | kFileOpenReparsePoint | kFileSynchronousIoNonalert;
    if (fn(&raw, access, &attrs, &iosb, share, options) < 0)
        return {};
    return cfs::WinHandle(raw);
}

/// Sweeps stale scratch directories under `data_dir`. Never throws, never
/// recurses (a real export directory is flat), never removes anything the pure
/// policy or the ownership check refuses.
ScratchSweepResult sweep_stale_scratch_dirs(const std::wstring& data_dir,
                                            std::int64_t now_unix_s) noexcept {
    ScratchSweepResult res{};
    try {
        cfs::OpenRootResult opened = cfs::open_root(std::filesystem::path{data_dir});
        if (!opened.root.has_value()) {
            res.enumerate_error = true;
            res.os_error = opened.os_error;
            return res;
        }
        const cfs::ConfinedRoot& root = *opened.root;
        // One deadline for every enumerate_at of the pass (the wall cap must
        // not creep forward per call).
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
            root_entries.reason == cfs::Reason::WallTimeCap)
            ++res.deferred; // truncated: never silently "nothing left"

        for (const auto& entry : root_entries.entries) {
            switch (classify_sweep_candidate(entry.name,
                                             entry.meta.type == cfs::EntryType::Directory,
                                             entry.meta.mtime, now_unix_s,
                                             kScratchDirStaleAfterSecs)) {
            case SweepCandidate::NotCandidate:
                continue;
            case SweepCandidate::NoMtime:
                ++res.failed;
                continue;
            case SweepCandidate::Fresh:
                ++res.skipped_fresh;
                continue;
            case SweepCandidate::Stale:
                break;
            }

            // No NEW candidate once the wall budget or either cap is spent.
            if (std::chrono::steady_clock::now() >= deadline ||
                res.removed >= kScratchSweepMaxRemovals ||
                res.failed >= kScratchSweepMaxFailures) {
                ++res.deferred;
                break;
            }

            cfs::WinHandle candidate =
                open_candidate_relative(root.h_.get(), yuzu::win::to_wide(entry.name));
            if (!candidate) { // includes a live dispatch's sharing violation
                ++res.failed;
                continue;
            }
            BY_HANDLE_FILE_INFORMATION info{};
            if (!GetFileInformationByHandle(candidate.get(), &info) ||
                (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                info.dwVolumeSerialNumber != root.identity().volume_serial) {
                ++res.failed;
                continue;
            }
            if (!sweep_may_remove(detail::scratch_dir_is_ours(candidate.get()))) {
                ++res.skipped_not_ours;
                spdlog::debug("local_security_policy: sweep leaving foreign-owned '{}' alone",
                              entry.name);
                continue;
            }

            cfs::EnumerateResult inner = cfs::enumerate_at(
                candidate.get(), root.identity(),
                cfs::EnumBudget{static_cast<std::uint64_t>(kScratchSweepMaxDirEntries), deadline});
            bool flat_and_clean = inner.reason == cfs::Reason::None;
            for (const auto& e : inner.entries)
                flat_and_clean = flat_and_clean && e.meta.type == cfs::EntryType::RegularFile;
            if (!flat_and_clean) { // leave the whole candidate intact
                ++res.failed;
                continue;
            }
            bool all_deleted = true;
            for (const auto& e : inner.entries) {
                const cfs::UnlinkOutcome o = cfs::unlink_at(
                    candidate.get(), e.name, cfs::UnlinkKind::File,
                    (std::numeric_limits<std::uint64_t>::max)(), root.identity());
                if (o.status != cfs::EntryStatus::Deleted) {
                    all_deleted = false;
                    break;
                }
            }
            if (!all_deleted) {
                ++res.failed;
                continue;
            }
            candidate.reset(); // delete-by-disposition needs no other handle open
            const cfs::UnlinkOutcome d = cfs::unlink_at(
                root.h_.get(), entry.name, cfs::UnlinkKind::EmptyDirectory, 0, root.identity());
            if (d.status == cfs::EntryStatus::Deleted)
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

// ---- Per-dispatch scratch directory ---------------------------------------

/// RAII owner of the per-dispatch directory: removes it and its contents on
/// every exit path. Kept as a wstring (never a narrow std::filesystem decode,
/// which would mangle a non-ASCII data_dir). MUST be declared BEFORE the
/// directory handle: RemoveDirectory fails with a sharing violation while a
/// no-FILE_SHARE_DELETE handle is open, so that handle must destruct first.
/// A failed removal is logged (never thrown from a destructor) and left for
/// the next dispatch's sweep. Removal is by path, unlike the handle-relative
/// sweep: this directory was created by this dispatch with CREATE_NEW and an
/// owner-only DACL, so no other principal can have swapped the DIRECTORY (its entries: the
/// export the child writes carries the child's default DACL, not an owner-only one); the
/// sweep handles directories it did not create, which is why it is confined.
class ScratchDirGuard {
public:
    explicit ScratchDirGuard(std::wstring path) : path_(std::move(path)) {}
    ScratchDirGuard(const ScratchDirGuard&) = delete;
    ScratchDirGuard& operator=(const ScratchDirGuard&) = delete;
    const std::wstring& path() const { return path_; }
    ~ScratchDirGuard() {
        // Nothing may escape a destructor that can run during unwinding (a second bad_alloc
        // while another is in flight would terminate the agent), so the path construction is
        // inside the same try as the log call.
        try {
            std::error_code ec;
            std::filesystem::remove_all(std::filesystem::path{path_}, ec);
            if (ec) {
                // The error code matters: a sharing violation is transient, an
                // access denial is not, and the next sweep's outcome depends on it.
                spdlog::warn("local_security_policy: scratch directory cleanup failed ({}); the "
                             "next dispatch's sweep will retry",
                             ec.value());
            }
        } catch (...) {
        }
    }

private:
    std::wstring path_;
};

/// Opens the directory as a handle WITHOUT FILE_SHARE_DELETE but REQUESTING
/// DELETE, so Windows itself refuses a concurrent delete/rename (the sweep's
/// DELETE-requesting open) for as long as it is held. Reparse points are
/// opened raw so the ownership check sees the object actually opened.
detail::ScopedHandle open_scratch_dir_handle(const std::wstring& dir) {
    return detail::ScopedHandle(CreateFileW(
        dir.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
}

// ---- Export read ------------------------------------------------------------

struct ExportBytes {
    std::vector<std::uint8_t> bytes;
    std::optional<ExportReadFailure> failure;
};

/// Reads the exported file (cap kExportMaxBytes) from the verified scratch
/// directory. Reparse points and non-regular objects are refused.
ExportBytes read_export(const std::wstring& file) {
    ExportBytes out;
    detail::ScopedHandle h(CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                       OPEN_EXISTING,
                                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                                       nullptr));
    if (!h) {
        out.failure = classify_export_read_error(GetLastError());
        return out;
    }
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(h.get(), &info)) {
        out.failure = classify_export_read_error(GetLastError());
        return out;
    }
    const std::uint64_t size = (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) |
                               info.nFileSizeLow;
    if (auto bad = classify_export_object(
            (info.dwFileAttributes &
             (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0,
            size)) {
        out.failure = std::move(bad);
        return out;
    }
    out.bytes.resize(static_cast<std::size_t>(size));
    std::size_t got = 0;
    while (got < out.bytes.size()) {
        DWORD n = 0;
        if (!ReadFile(h.get(), out.bytes.data() + got, static_cast<DWORD>(out.bytes.size() - got),
                      &n, nullptr)) {
            const DWORD err = GetLastError(); // before anything else can touch it
            out.bytes.clear();
            out.failure = classify_export_read_error(err);
            return out;
        }
        if (n == 0)
            break;
        got += n;
    }
    out.bytes.resize(got);
    if (auto bad = classify_export_read_length(size, got); !bad.empty()) {
        out.bytes.clear();
        out.failure = ExportReadFailure{false, std::move(bad)};
    }
    return out;
}

} // namespace

int collect_windows_policy(yuzu::CommandContext& ctx, std::string_view action,
                           std::string_view data_dir) {
    // The shared dispatcher has already validated `action` before calling a leg.
    if (data_dir.empty())
        return emit_constrained(ctx, "data_dir_unset");
    // Fail closed on an unresolved system directory: never a guessed literal.
    const std::string& sys_dir = yuzu::agent::windows_system_directory();
    if (sys_dir.empty())
        return emit_constrained(ctx, "secedit:system_directory_unresolved");

    // Sweep BEFORE spawning: a prior crash may have orphaned an export.
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    const ScratchSweepResult swept = sweep_stale_scratch_dirs(
        yuzu::win::to_wide(std::string{data_dir}), static_cast<std::int64_t>(now));
    // warn, and only when the pass did something: a sweep that reclaimed nothing
    // and failed at nothing is the steady state and needs no line. Matches the
    // sibling's `if (total > 0) spdlog::warn(...)` shape.
    if (sweep_worth_logging(swept))
        spdlog::warn("local_security_policy: {}", format_sweep_summary(swept));
    if (swept.enumerate_error)
        spdlog::warn("local_security_policy: sweep could not enumerate data_dir (os error {})",
                     swept.os_error);

    // 128-bit random name, CREATE_NEW, owner-only DACL.
    char scratch_utf8[512]{};
    // Named locals, not temporaries in the condition: both would be destroyed at the
    // end of the full expression, and freeing a non-SSO std::string can itself clobber
    // GetLastError() before the token is built. temp_file.cpp takes the same precaution
    // internally and says why.
    const std::string prefix{kScratchDirPrefix};
    const std::string parent{data_dir};
    if (yuzu_create_temp_dir(prefix.c_str(), parent.c_str(), scratch_utf8,
                             sizeof(scratch_utf8)) != 0) {
        const DWORD err = GetLastError();
        return emit_constrained(ctx, "dest_dir_create_" + std::to_string(err));
    }

    ScratchDirGuard scratch(yuzu::win::to_wide(scratch_utf8)); // declared BEFORE the handle
    detail::ScopedHandle dir_handle = open_scratch_dir_handle(scratch.path());
    if (!dir_handle)
        return emit_constrained(ctx, "dest_dir_open_" + std::to_string(GetLastError()));
    if (!detail::scratch_dir_is_ours(dir_handle.get()))
        return emit_constrained(ctx, "dest_dir_acl");

    const std::string out_utf8 = std::string{scratch_utf8} + "\\policy.inf";
    // Per Microsoft's documentation, without /log secedit appends to
    // %windir%\security\logs\scesrv.log, a log the agent does not own; the rig wrote none either
    // way, so this is precautionary: any log output stays inside what the guard and the sweep remove.
    const std::string log_utf8 = std::string{scratch_utf8} + "\\secedit.log";

    // sink: local_security_policy/do_export#1
    const yuzu::agent::SubprocessResult run = yuzu::agent::run_bounded_subprocess(
        {sys_dir + "\\secedit.exe", "/export", "/cfg", out_utf8, "/areas", "SECURITYPOLICY", "/log",
         log_utf8, "/quiet"},
        yuzu::agent::SubprocessOptions{.deadline = std::chrono::milliseconds{kExportDeadlineMs}});
    const std::string run_token = classify_export_run(to_run_end(run.termination_reason),
                                                      run.exit_code);
    if (!run_token.empty())
        return emit_constrained(ctx, run_token);

    ExportBytes exported = read_export(scratch.path() + L"\\policy.inf");
    if (exported.failure) {
        return exported.failure->permission_denied
                   ? emit_failure(ctx, YUZU_RESULT_STATUS_PERMISSION_DENIED,
                                exported.failure->token)
                   : emit_constrained(ctx, exported.failure->token);
    }

    // decode -> completeness -> INI -> rows is one pure function (scratch_sweep.hpp, unit-tested
    // on every OS); never re-add a second mapper or reorder its checks in this TU.
    const SeceditRows built = secedit_export_to_rows(
        std::span<const std::uint8_t>{exported.bytes.data(), exported.bytes.size()}, action);
    if (!built.failure_token.empty())
        return emit_constrained(ctx, built.failure_token);

    for (const auto& row : built.rows)
        ctx.write_output(row);
    ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
    return 0;
}

} // namespace yuzu::local_security_policy

#endif // defined(_WIN32)
