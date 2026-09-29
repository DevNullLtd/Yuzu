/**
 * filesystem_posture_win.cpp — Windows leg entry points for the
 * filesystem_posture plugin (mounts/quotas/snapshots).
 *
 * HOST-VERIFIED on the-rig (DESKTOP-04DNSIG, Windows SDK 10.0.26100.0, MSVC
 * Build Tools 2022) on 2026-09-03: this TU compiles clean under real MSVC
 * (zero errors, zero warnings), the plugin's unit suite passes there
 * (145 assertions / 23 cases), and the snapshots leg was exercised against
 * three live VSS shadow copies. The volume-enumeration walk and the
 * IDiskQuotaControl quota path are compiled and linked but have not been
 * asserted against a host with quotas configured, so their runtime
 * behaviour past "it runs" is still unproven.
 *
 * Two SDK surfaces are soft-guarded via `__has_include`, and neither guard's
 * failure is allowed to silently look like success:
 *   - `<dskquota.h>` (quota state); a build lacking it reports every volume
 *     `unavailable` and degrades the result. Unlike VSS this needs no
 *     dedicated import library, so the fallback is genuinely REACHABLE -- but
 *     it is still not a SUPPORTED configuration: the dispatcher suite asserts
 *     that no leg ever reports its own guard excluded it, so such a build
 *     fails its tests by design (Gate 4, consistency-auditor CA-4).
 *   - `<vsbackup.h>` (VSS shadow-copy enumeration); the guarded fallback emits
 *     an honest `none` row. **In practice that fallback is unreachable**, and
 *     saying otherwise would overstate it (governance Gate 3,
 *     plugin-developer): meson requires `vssapi` unconditionally on Windows,
 *     and an SDK without `<vsbackup.h>` has no `vssapi.lib` either, so such a
 *     build fails at CONFIGURE time and never reaches this code. The guard is
 *     kept as defence in depth and to keep the TU self-describing, not because
 *     it is a supported configuration.
 *
 * Snapshots do NOT use `FSCTL_SRV_ENUMERATE_SNAPSHOTS`, which an earlier
 * revision of this file did. That control is not declared by ANY header in
 * SDK 10.0.26100.0 -- verified twice on the-rig: a direct probe fails
 * `C2065: undeclared identifier`, and the shipped DLL contained the
 * "built without FSCTL_SRV_ENUMERATE_SNAPSHOTS" sentinel, proving the guard
 * had compiled the real path out and the leg was a permanent fallback row.
 * It is also the wrong question: it is an SMB *server*-side control listing
 * the previous versions a share exposes to clients, not the shadow copies a
 * volume holds. See the mechanism banner above emit_snapshot_rows_vss.
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

// VSS must be included BEFORE the initguid.h block below. initguid.h switches
// DEFINE_GUID from "declare" to "allocate storage", and that switch applies to
// every header processed AFTER it -- letting it reach the VSS headers would
// define GUIDs that vssapi.lib already exports and risk LNK2005. Including VSS
// first keeps its GUIDs as plain declarations resolved from the import library.
#if __has_include(<vsbackup.h>)
#define YUZU_FSPOSTURE_HAVE_VSS 1
#include <vss.h>
#include <vswriter.h> // both are prerequisites of vsbackup.h, in this order
#include <vsbackup.h>
#endif

// initguid.h must precede dskquota.h in exactly this TU: it makes dskquota.h
// DEFINE (not merely declare) CLSID_DiskQuotaControl / IID_IDiskQuotaControl
// as local storage, so this TU needs no uuid.lib dependency.
#if __has_include(<dskquota.h>)
#define YUZU_FSPOSTURE_HAVE_DSKQUOTA 1
#include <initguid.h>
#include <dskquota.h>
#endif

#include <cstddef>
#include <format>
#include <optional>
#include <string>
#include <string_view>
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
// KNOWN OPERATIONAL HAZARD -- NO DEADLINE ON THESE CALLS.
// CreateVssBackupComponents/InitializeForBackup/SetContext/Query/Next are
// synchronous cross-process COM, executed on a bounded agent dispatch-pool
// worker, with no timeout. A wedged VSS service or a hung third-party writer
// parks that worker permanently; a repeating scheduled `snapshots` instruction
// parks one per fire, and once the pool and its queue are exhausted the agent
// REJECTs EVERY command, not just this one -- the pool is shared with
// quarantine/containment dispatch, so this is an availability coupling with a
// security operation, not merely a slow read.
//
// Raised independently at governance Gate 4 (unhappy-path UP-1) and Gate 6
// (sre S-3). Shipped deliberately, ALEX RULING: documented rather than bounded
// here, because (a) every other plugin's OS calls are equally unbounded --
// agents/plugins/ has no bounded_call site outside `discovery` -- so bounding
// this one leg would be an inconsistent point fix, and (b) the obvious
// mechanism is unsafe for COM: bounded_wait.hpp bounds the WAIT by abandoning
// a DETACHED thread, and this plugin can be dlclosed out from under it. A
// tree-wide bounding strategy is tracked as a follow-up issue; do not "fix"
// this locally without reading that issue first.
//
// NO CoInitializeSecurity call anywhere in this leg: it is a process-global,
// once-only setting and a plugin must never impose one on its host agent.
// Verified as SYSTEM that CreateVssBackupComponents/Query both succeed under
// a bare CoInitializeEx(MTA) -- exactly what yuzu::shared::win::ComInit does.
// Note ComInit also accepts RPC_E_CHANGED_MODE (another plugin already put
// this pool thread in an STA); MSDN directs VSS requesters to an MTA, so VSS
// would then run in an STA. No in-tree plugin initialises STA (grep:
// zero COINIT_APARTMENTTHREADED), so this is latent, and any resulting
// failure lands in the generic "failed: 0x…" branch rather than being
// misreported as a privilege problem.

#if defined(YUZU_FSPOSTURE_HAVE_VSS)

/// RAII owner for the heap strings VSS allocates into a VSS_SNAPSHOT_PROP.
/// Next() fills a fresh property block on every iteration, so this must free
/// on every exit from the turn on which it is CONSTRUCTED. It is constructed
/// immediately after a successful fetch and BEFORE every other decision, so
/// the failed-status `break`, the cap `break`, the normal end of the walk, and
/// any check added later are all covered by construction. The one `continue`
/// -- the non-snapshot skip -- runs on a turn where no owner was constructed
/// at all; see the trade-off note at that branch.
///
/// Two earlier revisions of this comment were wrong in opposite directions,
/// which is why the ordering is spelled out rather than asserted: one claimed
/// it freed on "every loop turn, including the early-continue paths" (the skip
/// path contradicts that -- Gate 2, docs-writer), and the code then briefly
/// checked the cap BEFORE constructing the owner, making the cap `break` leak
/// (Gate 3, cpp-safety and cpp-expert, independently).
/// Unwrapped manual cleanup in new C++ is a governance policy floor, not a
/// style preference.
class ScopedSnapshotProp {
public:
    explicit ScopedSnapshotProp(VSS_SNAPSHOT_PROP& p) : p_(&p) {}
    ~ScopedSnapshotProp() {
        if (p_) ::VssFreeSnapshotProperties(p_);
    }
    ScopedSnapshotProp(const ScopedSnapshotProp&) = delete;
    ScopedSnapshotProp& operator=(const ScopedSnapshotProp&) = delete;

private:
    VSS_SNAPSHOT_PROP* p_;
};

std::string guid_to_string(const GUID& g) {
    wchar_t buf[64] = {};
    if (::StringFromGUID2(g, buf, static_cast<int>(std::size(buf))) == 0) return "-";
    return yuzu::win::from_wide(buf);
}

/// Renders a VSS step failure for both the row `detail` and the
/// mark_result_partial provenance. E_ACCESSDENIED is named explicitly: it is
/// the one failure here an operator can actually act on, and it is what
/// #1442 will turn this leg into fleet-wide.
std::string vss_failure_detail(std::string_view step, HRESULT hr) {
    if (hr == E_ACCESSDENIED) {
        // "commonly indicates", not "lacks": E_ACCESSDENIED from a COM call
        // can also arise from COM security negotiation or the VSS service's
        // own ACL. Administrative rights are the overwhelmingly likely cause
        // and the one an operator can act on, but asserting a single cause
        // from a generic HRESULT would be stating more than the code knows.
        return std::format("{} denied (0x{:08X}): VSS snapshot enumeration requires "
                           "administrative rights; this commonly indicates the agent service "
                           "account lacks them",
                           step, static_cast<unsigned long>(hr));
    }
    return std::format("{} failed: 0x{:08X}", step, static_cast<unsigned long>(hr));
}

void emit_snapshot_rows_vss(yuzu::CommandContext& ctx) {
    // Every early return below writes BOTH a `none` row and a degraded mark:
    // a failure must stay distinguishable from a genuinely empty snapshot
    // set, which is the same peer-H6 rule the retired FSCTL path carried.
    //
    // A privilege denial gets PERMISSION_DENIED rather than CONSTRAINED, so a
    // status-keyed consumer can tell "not allowed to read this" from any other
    // degradation. The descriptor and four operator docs state that a denied
    // read reports permission_denied; routing it here is what makes that
    // sentence true rather than aspirational (governance Gate 2).
    const auto fail = [&ctx](std::string_view step, HRESULT hr) {
        const std::string detail = vss_failure_detail(step, hr);
        write_snapshot_row(ctx, "-", "-", "none", detail);
        if (hr == E_ACCESSDENIED)
            mark_result_denied(ctx, "windows:vss", detail);
        else
            mark_result_partial(ctx, "windows:vss", detail);
    };

    yuzu::shared::win::ComInit com;
    if (!com.ok()) {
        constexpr const char* kDetail = "COM initialisation failed";
        write_snapshot_row(ctx, "-", "-", "none", kDetail);
        mark_result_partial(ctx, "windows:vss", kDetail);
        return;
    }

    yuzu::shared::win::ComPtr<IVssBackupComponents> backup;
    HRESULT hr = ::CreateVssBackupComponents(backup.put());
    if (FAILED(hr) || !backup) {
        fail("CreateVssBackupComponents", hr);
        return;
    }

    hr = backup->InitializeForBackup();
    if (FAILED(hr)) {
        fail("InitializeForBackup", hr);
        return;
    }

    // VSS_CTX_ALL so both persistent backup snapshots and the
    // client-accessible ones behind "Previous Versions" / System Restore are
    // enumerated; the default context reports only a subset. A failure here
    // is NOT fatal -- the query still runs at the default context -- but it
    // narrows what can be seen, so it is recorded rather than swallowed.
    const bool context_narrowed = FAILED(backup->SetContext(VSS_CTX_ALL));

    yuzu::shared::win::ComPtr<IVssEnumObject> snapshots;
    hr = backup->Query(GUID_NULL, VSS_OBJECT_NONE, VSS_OBJECT_SNAPSHOT, snapshots.put());
    if (FAILED(hr) || !snapshots) {
        fail("Query", hr);
        return;
    }

    // Bound the walk. Next() is driven by a storage provider this process
    // does not control, so the loop carries its own ceiling for the same
    // reason the macOS leg caps fs_snapshot_list; the cap matches that leg's
    // so the two platforms' truncation semantics stay comparable.
    constexpr std::size_t kMaxSnapshots = 1024;

    std::size_t emitted = 0;
    // The cap is counted in LOOP TURNS, not emitted rows. Counting rows would
    // let the non-snapshot `continue` below bypass the counter entirely, so a
    // provider that yields non-snapshot objects indefinitely would spin
    // forever AND leak on every turn -- defeating the exact rationale the cap
    // is here for, since Next() is driven by code this process does not
    // control. Governance Gate 2 (security-guardian) caught this; the two
    // decisions were individually fine and wrong in combination.
    std::size_t iterations = 0;
    bool truncated = false;
    bool enum_failed = false;
    HRESULT enum_hr = S_OK;
    bool skipped_wrong_type = false;

    for (;;) {
        VSS_OBJECT_PROP prop{};
        ULONG fetched = 0;
        const HRESULT next_hr = snapshots->Next(1, &prop, &fetched);

        // `fetched`, NOT the HRESULT, decides whether the provider wrote
        // anything into `prop`. Three cases, and they are NOT interchangeable
        // (Gate 4, unhappy-path UP-2 -- an earlier revision collapsed the
        // second into the first, so an over-fetch reported a healthy EMPTY
        // host on a machine that had snapshots, and leaked the block):
        //
        //   fetched == 0  -> normal end of the walk (S_FALSE). Nothing owned.
        //   fetched  > 1  -> the enumerator ignored our celt of 1. We cannot
        //                    own or free what we cannot address, so this is an
        //                    enumeration FAILURE, never an end-of-walk.
        //   fetched == 1  -> the contract we asked for; fall through and own.
        if (fetched == 0) {
            if (FAILED(next_hr)) {
                enum_failed = true;
                enum_hr = next_hr;
            }
            break;
        }
        if (fetched != 1) {
            enum_failed = true;
            enum_hr = SUCCEEDED(next_hr) ? E_UNEXPECTED : next_hr;
            break;
        }

        // OWNERSHIP IS TAKEN HERE, before ANY other decision, and that
        // ordering is the whole point -- governance Gate 3 (cpp-safety and
        // cpp-expert, independently) found that an earlier revision checked
        // the walk ceiling BEFORE constructing the owner, so the truncation
        // `break` discarded a fully-populated property block that nothing ever
        // freed. Every check below is therefore safe to add: the owner is
        // already alive on every path out of this turn.
        //
        // std::optional is what makes the ownership CONDITIONAL without a
        // second owner type: ScopedSnapshotProp is non-copyable and
        // non-movable, and emplace() constructs it in place.
        const bool is_snapshot = (prop.Type == VSS_OBJECT_SNAPSHOT);
        std::optional<ScopedSnapshotProp> owner;
        if (is_snapshot)
            owner.emplace(prop.Obj.Snap);

        // A populated entry delivered alongside a failed status: own it (above)
        // and then stop.
        if (FAILED(next_hr)) {
            enum_failed = true;
            enum_hr = next_hr;
            break;
        }

        // Bound the WALK, counted in loop turns rather than emitted rows, so
        // the skip below cannot bypass the ceiling.
        if (++iterations > kMaxSnapshots) {
            truncated = true;
            break;
        }

        // Only a snapshot-typed property owns snapshot strings, so such an
        // entry is skipped and no owner was constructed for it above.
        //
        // DELIBERATE TRADE-OFF, adjudicated at governance Gate 2 by
        // security-guardian (NOT self-granted -- the policy floor on non-RAII
        // cleanup requires an adjudicator who is not the author):
        //
        // this path frees nothing, so a non-snapshot entry leaks whatever
        // strings its own union arm holds. Accepted because (a) the Query
        // above asks for VSS_OBJECT_SNAPSHOT only, so the branch is
        // unreachable in practice; (b) the alternative -- calling
        // VssFreeSnapshotProperties on a union arm that is not a
        // VSS_SNAPSHOT_PROP -- is undefined behaviour on data this process did
        // not shape; and (c) the leak is BOUNDED by the kMaxSnapshots walk
        // ceiling checked above, which is counted in loop turns precisely so
        // this branch cannot spin. The branch is not silent either: it
        // degrades the result below.
        //
        // A strictly better third option exists and is deferred, not rejected:
        // switch on prop.Type and release VSS_PROVIDER_PROP's own strings with
        // CoTaskMemFree (VSS publishes no VssFreeProviderProperties). Left out
        // of this change because it is ~6 lines of untestable code on a branch
        // no query can reach; filed as a follow-up.
        if (!is_snapshot) {
            skipped_wrong_type = true;
            continue;
        }

        const VSS_SNAPSHOT_PROP& snap = prop.Obj.Snap;

        // m_pwszOriginalVolumeName is a volume GUID path in exactly the form
        // primary_mount_point() expects, so a snapshot maps to the same
        // mount-point vocabulary the mounts action reports.
        const std::wstring original =
            snap.m_pwszOriginalVolumeName ? snap.m_pwszOriginalVolumeName : L"";
        const std::string mount_point =
            original.empty() ? std::string("-")
                             : yuzu::win::from_wide(primary_mount_point(original).c_str());
        const std::string name = guid_to_string(snap.m_SnapshotId);
        const std::string device = snap.m_pwszSnapshotDeviceObject
                                       ? yuzu::win::from_wide(snap.m_pwszSnapshotDeviceObject)
                                       : std::string("-");

        write_snapshot_row(ctx, mount_point, name, "vss", device);
        ++emitted; // rows only -- the walk ceiling is `iterations`, checked above
    }

    if (enum_failed) {
        const std::string detail = vss_failure_detail("IVssEnumObject::Next", enum_hr);
        // Rows already emitted are real; only a walk that produced nothing
        // needs the `none` sentinel to carry the failure.
        if (emitted == 0) write_snapshot_row(ctx, "-", "-", "none", detail);
        // Mirror the `fail` lambda's routing. Raised independently by
        // cpp-safety and plugin-developer at Gate 3: without this branch a
        // denial arriving MID-walk logged "requires administrative rights"
        // while the typed status said CONSTRAINED -- the exact prose/status
        // divergence the PERMISSION_DENIED work existed to close, surviving in
        // the one site the first fix did not reach.
        if (enum_hr == E_ACCESSDENIED)
            mark_result_denied(ctx, "windows:vss", detail);
        else
            mark_result_partial(ctx, "windows:vss", detail);
        return;
    }
    // Only claim an empty machine when the walk was COMPLETE AND UNNARROWED.
    // Gate 3 (cpp-safety F3) gated this on `truncated`; Gate 4
    // (consistency-auditor CA-3) found the other two narrowing paths reach
    // here too -- a failed SetContext enumerates a narrower context, and a
    // skipped non-snapshot object means the walk did not see everything. Any
    // of the three makes "no shadow copies present" a claim the code cannot
    // support, so each gets its own honest sentinel instead.
    if (emitted == 0) {
        if (!truncated && !context_narrowed && !skipped_wrong_type) {
            write_snapshot_row(ctx, "-", "-", "none", "no shadow copies present on any volume");
        } else {
            write_snapshot_row(ctx, "-", "-", "none",
                               "no shadow copies observed, but the enumeration was incomplete "
                               "-- see the degraded status for why");
        }
    }
    // mark_result_partial ASSIGNS -- last writer wins for the reported
    // provenance -- so these run least-material first, leaving the most
    // material cause (an incomplete list) as the one an operator sees.
    if (skipped_wrong_type) {
        mark_result_partial(ctx, "windows:vss",
                            "the provider returned a non-snapshot object; it was skipped");
    }
    if (context_narrowed) {
        mark_result_partial(
            ctx, "windows:vss",
            "SetContext(VSS_CTX_ALL) failed; only the default snapshot context was enumerated");
    }
    if (truncated) {
        mark_result_partial(
            ctx, "windows:vss",
            std::format("snapshot list truncated at the {}-entry cap", kMaxSnapshots));
    }
}

#endif // YUZU_FSPOSTURE_HAVE_VSS

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
#if defined(YUZU_FSPOSTURE_HAVE_VSS)
    emit_snapshot_rows_vss(ctx);
#else
    write_snapshot_row(ctx, "-", "-", "none", "built without the VSS SDK headers");
    mark_result_partial(ctx, "windows:vss", "SDK header vsbackup.h not present at build time");
#endif
    return 0;
}

} // namespace yuzu::filesystem_posture

#endif // defined(_WIN32)
