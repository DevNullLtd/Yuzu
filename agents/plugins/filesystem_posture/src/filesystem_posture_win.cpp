/**
 * filesystem_posture_win.cpp — Windows leg entry points for the
 * filesystem_posture plugin (mounts/quotas/snapshots).
 *
 * HOST-VERIFIED on the-rig (DESKTOP-04DNSIG, Windows SDK 10.0.26100.0, MSVC
 * Build Tools 2022) on 2026-09-03: this TU compiles clean under real MSVC
 * (zero errors, zero warnings), the plugin's unit suite passes there
 * (145 assertions / 23 cases), and the snapshots leg was exercised against
 * three live VSS shadow copies (its VSS walk has since moved to agent-core,
 * which that run does not cover). The volume-enumeration walk and the
 * IDiskQuotaControl quota path are compiled and linked but have not been
 * asserted against a host with quotas configured, so their runtime
 * behaviour past "it runs" is still unproven.
 *
 * One SDK surface is soft-guarded via `__has_include` here, and the guard's
 * failure is not allowed to silently look like success:
 *   - `<dskquota.h>` (quota state); a build lacking it reports every volume
 *     `unavailable` and degrades the result. It needs no dedicated import
 *     library, so the fallback is genuinely REACHABLE -- but it is still not a
 *     SUPPORTED configuration: the dispatcher suite asserts that no leg ever
 *     reports its own guard excluded it, so such a build fails its tests by
 *     design (Gate 4, consistency-auditor CA-4).
 * The VSS shadow-copy walk, and its `<vsbackup.h>` guard, live in agent-core
 * (yuzu/agent/win_vss_snapshots.hpp).
 *
 * Snapshots do NOT use `FSCTL_SRV_ENUMERATE_SNAPSHOTS`, which an earlier
 * revision of this file did. That control is not declared by ANY header in
 * SDK 10.0.26100.0 -- verified twice on the-rig: a direct probe fails
 * `C2065: undeclared identifier`, and the shipped DLL contained the
 * "built without FSCTL_SRV_ENUMERATE_SNAPSHOTS" sentinel, proving the guard
 * had compiled the real path out and the leg was a permanent fallback row.
 * It is also the wrong question: it is an SMB *server*-side control listing
 * the previous versions a share exposes to clients, not the shadow copies a
 * volume holds. See the snapshots section below.
 *
 * Every OS call here is read-only: no write/format/delete right is ever
 * requested on a volume handle, quota control instance, or drive.
 */

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <win_com.hpp>
#include <win_str.hpp>

#include "filesystem_posture_legs.hpp"

// initguid.h must precede dskquota.h in exactly this TU: it makes dskquota.h
// DEFINE (not merely declare) CLSID_DiskQuotaControl / IID_IDiskQuotaControl
// as local storage, so this TU needs no uuid.lib dependency.
#if __has_include(<dskquota.h>)
#define YUZU_FSPOSTURE_HAVE_DSKQUOTA 1
#include <initguid.h>
#include <dskquota.h>
#endif

#include <format>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::filesystem_posture {

namespace {

// RAII guard: set the thread error mode on construction, restore on scope
// exit. Local copy of disk_space_plugin.cpp:61's ThreadErrorModeGuard --
// that class is private to disk_space_plugin.cpp, not a shared header (peer
// M12); promoting it to agents/shared/ is a follow-up outside this PR.
// Suppresses the session-0 hard-error dialog around a volume query against a
// not-ready removable / BitLocker-locked volume, which would otherwise block
// a dispatch-pool worker. Thread-scoped -- never the process-wide
// SetErrorMode, which would race other workers in the bounded pool.
class ThreadErrorModeGuard {
public:
    explicit ThreadErrorModeGuard(DWORD mode) noexcept { ::SetThreadErrorMode(mode, &prev_); }
    ~ThreadErrorModeGuard() { ::SetThreadErrorMode(prev_, nullptr); }
    ThreadErrorModeGuard(const ThreadErrorModeGuard&) = delete;
    ThreadErrorModeGuard& operator=(const ThreadErrorModeGuard&) = delete;

private:
    DWORD prev_ = 0;
};

// (ScopedFileHandle lived here and was removed with the FSCTL snapshots path
// that was its only consumer -- the VSS leg opens no volume handle at all. An
// unused class definition draws no compiler warning, so nothing but a
// deliberate sweep after the removal would have caught it.)

// RAII owner for a volume-search handle from FindFirstVolumeW (closes via
// FindVolumeClose, a different API from CloseHandle). Fix-round addition
// (peer review M-finding): a bare local HANDLE plus a FindVolumeClose() call
// reached only at normal loop exit leaks the search handle if anything in
// the loop body throws (std::format/allocation/ctx.write_output all can);
// tying the close to a destructor makes every exit path -- return, break,
// or an exception unwinding through this scope -- safe.
class ScopedVolumeFindHandle {
public:
    explicit ScopedVolumeFindHandle(HANDLE h) noexcept : h_(h) {}
    ~ScopedVolumeFindHandle() {
        if (valid())
            ::FindVolumeClose(h_);
    }
    ScopedVolumeFindHandle(const ScopedVolumeFindHandle&) = delete;
    ScopedVolumeFindHandle& operator=(const ScopedVolumeFindHandle&) = delete;

    [[nodiscard]] HANDLE get() const { return h_; }
    [[nodiscard]] bool valid() const { return h_ != nullptr && h_ != INVALID_HANDLE_VALUE; }

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
};

// Fixed vocabulary (peer M5): "ro" xor "rw", plus at most one of
// removable/remote/cdrom, derived only from enum/bitmask values -- never
// from parsed text.
std::string flags_for_volume(DWORD fs_flags, UINT drive_type) {
    std::string out = (fs_flags & FILE_READ_ONLY_VOLUME) ? "ro" : "rw";
    switch (drive_type) {
    case DRIVE_REMOVABLE:
        out += ",removable";
        break;
    case DRIVE_REMOTE:
        out += ",remote";
        break;
    case DRIVE_CDROM:
        out += ",cdrom";
        break;
    default:
        break;
    }
    return out;
}

// Enumerates local volume GUID paths (trailing-backslash form, e.g.
// "\\?\Volume{...}\\") via FindFirstVolumeW/FindNextVolumeW, always closing
// the find handle via FindVolumeClose before returning. `ok` is false only
// when the enumeration itself failed (FindFirstVolumeW, or FindNextVolumeW
// with an error other than the expected ERROR_NO_MORE_FILES end-of-list);
// `err` carries the Win32 error in that case.
std::vector<std::wstring> enumerate_volume_guid_paths(bool& ok, DWORD& err) {
    ThreadErrorModeGuard err_guard{SEM_FAILCRITICALERRORS};
    std::vector<std::wstring> out;
    wchar_t volume_name[MAX_PATH] = {};
    const ScopedVolumeFindHandle find(::FindFirstVolumeW(volume_name, MAX_PATH));
    if (!find.valid()) {
        ok = false;
        err = ::GetLastError();
        return out;
    }
    ok = true;
    for (;;) {
        out.emplace_back(volume_name);
        if (!::FindNextVolumeW(find.get(), volume_name, MAX_PATH)) {
            const DWORD last_err = ::GetLastError();
            if (last_err != ERROR_NO_MORE_FILES) {
                ok = false;
                err = last_err;
            }
            break;
        }
    }
    return out;
}

// The volume's first drive-letter-style mount path (e.g. "C:\\"), or the
// volume GUID path itself when GetVolumePathNamesForVolumeNameW reports no
// mount point -- the same "always something to key the row on" choice
// emit_mounts makes per path.
std::wstring primary_mount_point(const std::wstring& volume_guid) {
    DWORD needed = 0;
    ::GetVolumePathNamesForVolumeNameW(volume_guid.c_str(), nullptr, 0, &needed);
    if (needed > 0) {
        std::vector<wchar_t> buf(needed, L'\0');
        if (::GetVolumePathNamesForVolumeNameW(volume_guid.c_str(), buf.data(), needed, &needed) &&
            !buf.empty() && buf[0] != L'\0') {
            return std::wstring(buf.data());
        }
    }
    return volume_guid;
}

// ── mounts ───────────────────────────────────────────────────────────────

void emit_one_mount_row(yuzu::CommandContext& ctx, const wchar_t* mount_point_w,
                        const std::string& device, const std::string& fstype,
                        const std::string& flags) {
    const std::string mount_point = yuzu::win::from_wide(mount_point_w);

    std::optional<unsigned long long> total;
    std::optional<unsigned long long> free_bytes;
    std::optional<unsigned long long> available;

    ULARGE_INTEGER avail_to_caller{};
    ULARGE_INTEGER total_bytes{};
    ULARGE_INTEGER total_free{};
    if (::GetDiskFreeSpaceExW(mount_point_w, &avail_to_caller, &total_bytes, &total_free)) {
        total = total_bytes.QuadPart;
        free_bytes = total_free.QuadPart;
        available = avail_to_caller.QuadPart;
    } else {
        mark_result_partial(ctx, "windows:volume_enum",
                            std::format("{} GetDiskFreeSpaceExW failed: {}", mount_point,
                                        ::GetLastError()));
    }
    // No per-mount option string exists on this leg (peer H1 fallback
    // prose); the options column is always "-".
    write_mount_row(ctx, mount_point, device, fstype, "-", total, free_bytes, available, flags);
}

// One volume: resolve its filesystem name/flags once, then emit one row per
// GetVolumePathNamesForVolumeNameW path (or one row keyed by the volume GUID
// path itself when it has no mount point). Any single API failure for this
// volume degrades that row's columns to "-"/nullopt and reports via
// mark_result_partial rather than dropping the row or aborting the walk.
void emit_mount_rows_for_volume(yuzu::CommandContext& ctx, const wchar_t* volume_guid) {
    const std::string device = yuzu::win::from_wide(volume_guid);

    wchar_t vol_label[MAX_PATH + 1] = {};
    wchar_t fs_name[MAX_PATH + 1] = {};
    DWORD serial = 0;
    DWORD max_component = 0;
    DWORD fs_flags = 0;
    const BOOL info_ok = ::GetVolumeInformationW(volume_guid, vol_label, MAX_PATH, &serial,
                                                 &max_component, &fs_flags, fs_name, MAX_PATH);
    std::string fstype = "-";
    std::string flags = "-";
    if (info_ok) {
        fstype = yuzu::win::from_wide(fs_name);
        if (fstype.empty())
            fstype = "-";
        // DRIVE_UNKNOWN means GetDriveTypeW could not classify the volume
        // (e.g. a not-ready removable) -- that is itself a failure, not a
        // fifth drive-type category, so it must degrade the flags column
        // rather than silently pass through as an unqualified "ro"/"rw".
        const UINT drive_type = ::GetDriveTypeW(volume_guid);
        if (drive_type == DRIVE_UNKNOWN) {
            mark_result_partial(ctx, "windows:volume_enum",
                                std::format("{} GetDriveTypeW returned DRIVE_UNKNOWN", device));
        } else {
            flags = flags_for_volume(fs_flags, drive_type);
        }
    } else {
        mark_result_partial(ctx, "windows:volume_enum",
                            std::format("{} GetVolumeInformationW failed: {}", device,
                                        ::GetLastError()));
    }

    // The sizing call is expected to fail with ERROR_MORE_DATA when the
    // volume has mount points to report; needed==0 with any OTHER error is
    // a genuine enumeration failure that must not masquerade as the
    // legitimate "this volume has zero mount points" case (peer H6-style
    // failure/emptiness distinction, applied here too).
    DWORD path_chars = 0;
    const BOOL sized_ok = ::GetVolumePathNamesForVolumeNameW(volume_guid, nullptr, 0, &path_chars);
    const DWORD sizing_err = sized_ok ? ERROR_SUCCESS : ::GetLastError();
    std::vector<wchar_t> path_buf;
    bool have_paths = false;
    bool paths_query_failed = false;
    DWORD paths_query_err = sizing_err;
    if (path_chars > 0) {
        path_buf.assign(path_chars, L'\0');
        if (::GetVolumePathNamesForVolumeNameW(volume_guid, path_buf.data(), path_chars,
                                               &path_chars) &&
            !path_buf.empty() && path_buf[0] != L'\0') {
            have_paths = true;
        } else {
            paths_query_failed = true;
            paths_query_err = ::GetLastError();
        }
    } else if (!sized_ok && sizing_err != ERROR_MORE_DATA) {
        paths_query_failed = true;
    }
    if (paths_query_failed) {
        mark_result_partial(ctx, "windows:volume_enum",
                            std::format("{} GetVolumePathNamesForVolumeNameW failed: {}", device,
                                        paths_query_err));
    }

    if (have_paths) {
        const wchar_t* p = path_buf.data();
        while (*p) {
            const std::wstring mp_w(p);
            emit_one_mount_row(ctx, mp_w.c_str(), device, fstype, flags);
            p += mp_w.size() + 1;
        }
    } else {
        emit_one_mount_row(ctx, volume_guid, device, fstype, flags);
    }
}

// ── quotas ───────────────────────────────────────────────────────────────

#if defined(YUZU_FSPOSTURE_HAVE_DSKQUOTA)

void emit_quota_rows_dskquota(yuzu::CommandContext& ctx, const std::vector<std::wstring>& volumes) {
    yuzu::shared::win::ComInit com;
    const bool com_ok = com.ok();
    bool any_ntfs = false;
    bool any_success = false;
    bool any_quota_failure = false; // ANY degraded volume, not only an all-failed walk
    // CP-1 (Gate 3): the per-volume loop already distinguishes E_ACCESSDENIED,
    // but the summary below reported every cause as generic CONSTRAINED. Track
    // whether a denial was actually seen so the reported STATUS can say so.
    bool any_permission_denied = false;

    for (const auto& vol : volumes) {
        const std::wstring mount_w = primary_mount_point(vol);
        const std::string mp = yuzu::win::from_wide(mount_w.c_str());

        wchar_t fs_name[MAX_PATH + 1] = {};
        const BOOL info_ok = ::GetVolumeInformationW(vol.c_str(), nullptr, 0, nullptr, nullptr,
                                                     nullptr, fs_name, MAX_PATH);
        if (!info_ok) {
            any_quota_failure = true; // G4-01: a probe we could not complete
            write_quota_row(ctx, mp, QuotaState::Unavailable, std::nullopt, std::nullopt,
                            "volume filesystem type unavailable");
            continue;
        }
        if (yuzu::win::from_wide(fs_name) != "NTFS") {
            write_quota_row(ctx, mp, QuotaState::UnsupportedFs, std::nullopt, std::nullopt, "-");
            continue;
        }
        any_ntfs = true;

        // IDiskQuotaControl::Initialize is meant to be handed a drive-letter
        // root path ("per LETTERED NTFS volume" in the spec): a volume with
        // no drive letter (mounted only at a folder, or not mounted at all)
        // has no such root, and quietly substituting the raw volume GUID
        // path there would be an unrequested scope widening, not a graceful
        // fallback -- report it and move on instead.
        const bool lettered = mount_w.size() == 3 && mount_w[1] == L':' && mount_w[2] == L'\\' &&
                              ((mount_w[0] >= L'A' && mount_w[0] <= L'Z') ||
                               (mount_w[0] >= L'a' && mount_w[0] <= L'z'));
        if (!lettered) {
            any_quota_failure = true; // G4-01: a probe we could not complete
            write_quota_row(ctx, mp, QuotaState::Unavailable, std::nullopt, std::nullopt,
                            "volume has no drive letter");
            continue;
        }

        if (!com_ok) {
            any_quota_failure = true; // G4-01: a probe we could not complete
            write_quota_row(ctx, mp, QuotaState::Unavailable, std::nullopt, std::nullopt,
                            "COM apartment initialization failed");
            continue;
        }

        yuzu::shared::win::ComPtr<IDiskQuotaControl> quota_ctl;
        HRESULT hr = ::CoCreateInstance(CLSID_DiskQuotaControl, nullptr, CLSCTX_INPROC_SERVER,
                                        IID_IDiskQuotaControl,
                                        reinterpret_cast<void**>(quota_ctl.put()));
        if (SUCCEEDED(hr)) {
            // Read-only (peer H4): TRUE here requests read/write access to
            // the quota control and fails E_ACCESSDENIED for a
            // non-Administrator agent identity on every volume. FALSE is
            // sufficient for GetQuotaState/GetDefaultQuotaLimit/
            // GetDefaultQuotaThreshold, and matches this plugin's ReadOnly
            // capability classification.
            hr = quota_ctl->Initialize(mount_w.c_str(), FALSE);
        }

        const auto write_hresult_failure = [&](HRESULT failed_hr) {
            any_quota_failure = true; // G4-01: every HRESULT failure degrades the run
            if (failed_hr == E_ACCESSDENIED) {
                any_permission_denied = true;
                write_quota_row(ctx, mp, QuotaState::PermissionDenied, std::nullopt, std::nullopt,
                                "-");
            } else {
                write_quota_row(
                    ctx, mp, QuotaState::Unavailable, std::nullopt, std::nullopt,
                    std::format("hr=0x{:08X}", static_cast<unsigned long>(failed_hr)));
            }
        };

        if (FAILED(hr)) {
            write_hresult_failure(hr);
            continue;
        }

        DWORD state_flags = 0;
        const HRESULT state_hr = quota_ctl->GetQuotaState(&state_flags);
        if (FAILED(state_hr)) {
            write_hresult_failure(state_hr);
            continue;
        }

        // GetQuotaState's DWORD carries DISKQUOTA_FILESTATE_* bits alongside
        // the state -- mask with DISKQUOTA_STATE_MASK (0x3) before comparing
        // (a raw == would misclassify a rebuilding/incomplete volume).
        const DWORD state = state_flags & DISKQUOTA_STATE_MASK;
        if (state == DISKQUOTA_STATE_DISABLED) {
            write_quota_row(ctx, mp, QuotaState::NotEnabled, std::nullopt, std::nullopt, "-");
            any_success = true;
            continue;
        }
        if (state != DISKQUOTA_STATE_TRACK && state != DISKQUOTA_STATE_ENFORCE) {
            // The mask covers 2 bits (0-3); DISABLED/TRACK/ENFORCE are the
            // only documented values. The remaining (reserved) value is not
            // a healthy default to fold silently into "configured".
            any_quota_failure = true; // G4-01: reserved/unknown state is not a healthy answer
            write_quota_row(ctx, mp, QuotaState::Unavailable, std::nullopt, std::nullopt,
                            std::format("unrecognized quota state: {}", state));
            continue;
        }

        // TRACK or ENFORCE: read the default limit/threshold. There is no
        // NOQUOTA macro in dskquota.h -- the no-limit sentinel is -1
        // (0xFFFFFFFFFFFFFFFF as LONGLONG), which renders as nullopt/"-".
        // Both reads' HRESULTs are checked: a failure here (e.g.
        // E_ACCESSDENIED mid-session) must degrade this row rather than
        // fall through to an unqualified "configured" built on values that
        // were never actually written by a failed out-param call.
        LONGLONG limit = -1;
        const HRESULT limit_hr = quota_ctl->GetDefaultQuotaLimit(&limit);
        if (FAILED(limit_hr)) {
            write_hresult_failure(limit_hr);
            continue;
        }
        LONGLONG threshold = -1;
        const HRESULT threshold_hr = quota_ctl->GetDefaultQuotaThreshold(&threshold);
        if (FAILED(threshold_hr)) {
            write_hresult_failure(threshold_hr);
            continue;
        }
        const std::optional<unsigned long long> limit_opt =
            limit == -1 ? std::nullopt
                       : std::optional<unsigned long long>(static_cast<unsigned long long>(limit));
        const std::optional<unsigned long long> threshold_opt =
            threshold == -1
                ? std::nullopt
                : std::optional<unsigned long long>(static_cast<unsigned long long>(threshold));

        write_quota_row(ctx, mp, QuotaState::Configured, limit_opt, threshold_opt, "-");
        any_success = true;
    }

    // G4-01/SG-1: !any_success is an ALL-or-nothing test, so ONE quota-enabled
    // volume masked E_ACCESSDENIED on every peer -- the ordinary posture for a
    // non-Administrator agent identity. Report any failure, and keep the
    // all-failed message distinct because it is the more actionable one.
    //
    // CP-1: where a denial was actually observed, report PERMISSION_DENIED
    // rather than generic CONSTRAINED -- the all-failed case is the ordinary
    // posture for a non-Administrator agent identity, so collapsing it to
    // CONSTRAINED hid the single most actionable cause. A mixed walk with no
    // denial seen stays CONSTRAINED: claiming a denial there would be a guess.
    if (any_ntfs && !any_success) {
        const char* detail = "quota query failed on every NTFS volume";
        if (any_permission_denied)
            mark_result_denied(ctx, "windows:dskquota", detail);
        else
            mark_result_partial(ctx, "windows:dskquota", detail);
    } else if (any_quota_failure) {
        const char* detail = "quota query failed on at least one NTFS volume";
        if (any_permission_denied)
            mark_result_denied(ctx, "windows:dskquota", detail);
        else
            mark_result_partial(ctx, "windows:dskquota", detail);
    }
}

#endif // YUZU_FSPOSTURE_HAVE_DSKQUOTA

} // namespace

// ── entry points ─────────────────────────────────────────────────────────
//
// Each is a read; each returns 0 unconditionally (ADR-style: a read never
// fails the call, degradation is reported via mark_result_partial).

int emit_mounts(yuzu::CommandContext& ctx) {
    ThreadErrorModeGuard err_guard{SEM_FAILCRITICALERRORS};
    wchar_t volume_name[MAX_PATH] = {};
    const ScopedVolumeFindHandle find(::FindFirstVolumeW(volume_name, MAX_PATH));
    if (!find.valid()) {
        mark_result_partial(ctx, "windows:volume_enum",
                            std::format("FindFirstVolumeW failed: {}", ::GetLastError()));
    } else {
        for (;;) {
            emit_mount_rows_for_volume(ctx, volume_name);
            if (!::FindNextVolumeW(find.get(), volume_name, MAX_PATH)) {
                const DWORD err = ::GetLastError();
                if (err != ERROR_NO_MORE_FILES) {
                    mark_result_partial(ctx, "windows:volume_enum",
                                        std::format("FindNextVolumeW failed: {}", err));
                }
                break;
            }
        }
    }
    return 0;
}

int emit_quotas(yuzu::CommandContext& ctx) {
    // UP-4 (Gate 4): the per-volume quota work calls primary_mount_point and
    // GetVolumeInformationW, which is exactly what this guard exists to make
    // safe -- a not-ready removable or BitLocker-locked volume otherwise pops
    // the session-0 hard-error dialog and blocks a dispatch worker. It was
    // scoped to enumerate_volume_guid_paths and emit_mounts only.
    ThreadErrorModeGuard err_guard{SEM_FAILCRITICALERRORS};
    bool enum_ok = false;
    DWORD enum_err = 0;
    // A mid-walk FindNextVolumeW failure still leaves `volumes` holding
    // every entry collected before the failure -- those are real volumes
    // that were genuinely enumerated, so they are queried below rather than
    // discarded; the enumeration failure itself is reported separately via
    // mark_result_partial so it is never silently dropped either.
    const std::vector<std::wstring> volumes = enumerate_volume_guid_paths(enum_ok, enum_err);

    if (!enum_ok) {
        mark_result_partial(ctx, "windows:dskquota",
                            std::format("volume enumeration failed: {}", enum_err));
    }
    if (!volumes.empty()) {
#if defined(YUZU_FSPOSTURE_HAVE_DSKQUOTA)
        emit_quota_rows_dskquota(ctx, volumes);
#else
        for (const auto& vol : volumes) {
            const std::string mp = yuzu::win::from_wide(primary_mount_point(vol).c_str());
            write_quota_row(ctx, mp, QuotaState::Unavailable, std::nullopt, std::nullopt,
                            "built without dskquota.h");
        }
        mark_result_partial(ctx, "windows:dskquota", "SDK header dskquota.h not present at build time");
#endif
    }
    return 0;
}

// ── snapshots ────────────────────────────────────────────────────────────
//
// MECHANISM: VSS/COM (IVssBackupComponents::Query), replacing
// FSCTL_SRV_ENUMERATE_SNAPSHOTS. The file banner records why the FSCTL was
// both unavailable on the current SDK and the wrong question.
//
// VERIFIED on the-rig 2026-09-03 against three live shadow copies (Windows
// SDK 10.0.26100.0). Query returns every snapshot machine-wide in one call
// and each carries its own originating volume, so this leg -- unlike
// emit_mounts/emit_quotas -- does not enumerate volumes first.
//
// PRIVILEGE. Measured on that host, and ONLY these three were measured:
//   NT AUTHORITY\SYSTEM           CreateVssBackupComponents -> S_OK, 3 found
//   NT AUTHORITY\LOCAL SERVICE    -> E_ACCESSDENIED (0x80070005)
//   NT AUTHORITY\NETWORK SERVICE  -> E_ACCESSDENIED (0x80070005)
//
// The Windows agent service runs as LocalSystem today (#1442), so this leg
// works as shipped. Should #1442 move it to NT SERVICE\YuzuAgent, the call is
// EXPECTED to return E_ACCESSDENIED -- expected, not measured: that account
// was not among the three tested, and docs/agent-privilege-model.md shows it
// being granted Administrators out of band for other actions, which would
// change the answer. Either way a denial is reported as an explicit
// PERMISSION_DENIED degradation below and must never read as an empty,
// healthy snapshot set.
//
// BOUNDED READ. The COM walk runs in agent-core on its own worker thread,
// waited on for at most kVssDeadline: see yuzu/agent/win_vss_snapshots.hpp.
// This leg only resolves mount points and writes the rows and marks that
// plan_vss_rows decides.

int emit_snapshots(yuzu::CommandContext& ctx) {
    // UP-4: the VSS leg resolves each snapshot's originating volume through
    // primary_mount_point, so it needs the same hard-error suppression.
    ThreadErrorModeGuard err_guard{SEM_FAILCRITICALERRORS};
    // Deliberately does NOT enumerate volumes first, unlike emit_mounts and
    // emit_quotas. IVssBackupComponents::Query returns every shadow copy on
    // the machine in one call and each carries its own originating volume,
    // so a volume walk here would add a second failure mode without adding
    // any coverage -- a volume with no snapshots contributes nothing either
    // way, and a snapshot whose volume the walk missed would be dropped.
    const auto read = yuzu::agent::win::read_vss_snapshots(yuzu::agent::win::kVssDeadline);
    // The originating volume is a volume GUID path in exactly the form
    // primary_mount_point() expects, so a snapshot maps to the same
    // mount-point vocabulary the mounts action reports.
    const VssRowPlan plan = plan_vss_rows(read, [](const std::string& volume) {
        return yuzu::win::from_wide(primary_mount_point(yuzu::win::to_wide(volume)).c_str());
    });
    for (const auto& row : plan.rows)
        write_snapshot_row(ctx, row.mount_point, row.name, row.kind, row.detail);
    for (const auto& mark : plan.marks) {
        std::string provenance{"windows:vss"};
        if (!mark.cause.empty())
            provenance.append(":").append(mark.cause);
        if (mark.denied)
            mark_result_denied(ctx, provenance, mark.detail);
        else
            mark_result_partial(ctx, provenance, mark.detail);
    }
    return 0;
}

} // namespace yuzu::filesystem_posture

#endif // defined(_WIN32)
