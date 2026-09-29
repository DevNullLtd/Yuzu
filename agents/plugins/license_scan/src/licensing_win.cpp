/**
 * licensing_win.cpp — Windows detection surfaces for the license_scan plugin
 * (SLE roadmap §5 PR1 detection-surface table; ADR-0024 Decisions 2/11).
 *
 * Surfaces (probe_status tokens):
 *   slp_wmi         — WMI SoftwareLicensingProduct via the bounded enumerator
 *                     (C-8; never WBEM_INFINITE). Authoritative: OS/Office/MS
 *                     server licence status, channel, grace, evaluation end,
 *                     partial key.
 *   office_c2r      — HKLM ...\ClickToRun\Configuration (probable: C2R SKU →
 *                     subscription/volume/retail type).
 *   <ProbeSpec>     — machine-scope ProbeSpec table rows (sql_server,
 *                     exchange, visual_studio, autodesk_adsklicensing, veeam,
 *                     acronis, av_suites, vmware_workstation, winrar,
 *                     open_source_classification).
 *   per_user_hives  — user-scope ProbeSpec rows probed in each profile's
 *                     registry hive: loaded HKU\<SID> hives FIRST, offline
 *                     NTUSER.DAT via RegLoadKeyW only as fallback (roadmap
 *                     C-1). Since #2771 the ladder itself lives in
 *                     agents/shared/win_profiles.hpp — this file was the
 *                     reference it was ported from and now consumes it, so
 *                     the close-every-hive-HKEY-before-unload rule and the
 *                     privilege handling are enforced in one place rather
 *                     than cloned. Reports `privilege_missing` when
 *                     SeBackup/SeRestore cannot be enabled for a profile
 *                     that actually needed the offline fallback (R15).
 *   per_user_files  — per-profile licence files (JetBrains
 *                     %APPDATA%-shaped .key paths, Adobe NGL sign-in
 *                     artefact), resolved via ProfileList — no hive needed.
 *
 * R17: every registry read goes through wide Reg*W APIs +
 * agents/shared/win_str.hpp (never the *A siblings).
 *
 * ADR-0024 D11 (binds the emission): per-user records carry
 * user_scope=user and user_ref=<local profile name>; when the profile name
 * cannot be resolved user_ref stays EMPTY — NEVER a SID. That invariant now
 * belongs to yuzu::profiles::build_profile_list, which every per-user
 * consumer shares; installed_apps' contradicting `username = sid` fallback
 * was removed in #2771 rather than worked around here.
 */

#ifdef _WIN32

#include "licensing_parsers.hpp"
#include "licensing_probes.hpp"
#include "licensing_record.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681, R17)

// Shared per-user profile/hive ladder (#2771). This file's own copy of the
// ProfileList walk, the privilege enable and the hive mount was the reference
// the shared version was ported FROM; it now consumes it instead, which also
// retires this file's process-wide privilege leak.
#include <user_profile_model.hpp>
#include <win_profiles.hpp>
#include <win_reg_handle.hpp>

// Bounded WMI enumerator (roadmap C-8), hoisted to agents/shared/ — this file
// was the reference wmi_bounded.{hpp,cpp} was extracted FROM (its own header
// comment anticipated the move), and now consumes it instead of a
// plugin-local copy.
#include <wmi_bounded.hpp>

#include <cstdlib>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::license_scan {

namespace {

using yuzu::win::from_wide;
using yuzu::win::reg_sz_to_utf8;
using yuzu::win::to_wide;

// ── RAII registry helpers ───────────────────────────────────────────────────

// Closing every handle into a RegLoadKeyW-mounted hive BEFORE the unload is
// load-bearing: RegUnLoadKeyW fails ERROR_ACCESS_DENIED while any subtree
// handle is open (installed_apps_plugin.cpp:165-166 rule). All ProbeHost
// registry operations below open and close their HKEY within the call, so
// nothing outlives the mount.
struct HKeyCloser {
    HKEY h;
    explicit HKeyCloser(HKEY k) : h(k) {}
    ~HKeyCloser() {
        if (h)
            RegCloseKey(h);
    }
    HKeyCloser(const HKeyCloser&) = delete;
    HKeyCloser& operator=(const HKeyCloser&) = delete;
};

// This file's HiveUnloadGuard and its local two-pass expand_env_strings are
// retired (#2771): agents/shared/win_reg_handle.hpp's ScopedUserHive and
// win_profiles.hpp's expand_env_strings are the canonical copies, and the
// shared ladder calls both on this plugin's behalf.

// ── ProbeHost with Reg*W registry access (R17) ─────────────────────────────

class WinRegProbeHost final : public ProbeHost {
public:
    /// Machine scope: HKLM, probing the 64-bit view first and falling back to
    /// the WoW6432Node view (32-bit-only installs like older vendor tools).
    WinRegProbeHost() : root_(HKEY_LOCAL_MACHINE), wow64_fallback_(true) {}

    /// User scope: a loaded HKU\<SID> hive or a RegLoadKeyW mount root. The
    /// caller owns `hive_root` and closes it before any unload.
    explicit WinRegProbeHost(HKEY hive_root) : root_(hive_root), wow64_fallback_(false) {}

    bool reg_key_exists(std::string_view key_path) override {
        HKEY h = open_key(key_path);
        if (!h)
            return false;
        RegCloseKey(h);
        return true;
    }

    std::optional<std::string> reg_read_str(std::string_view key_path,
                                            std::string_view value_name) override {
        HKEY h = open_key(key_path);
        if (!h)
            return std::nullopt;
        HKeyCloser guard{h};
        return read_str_value(h, value_name);
    }

    std::vector<std::string> reg_enum_subkeys(std::string_view key_path) override {
        std::vector<std::string> out;
        HKEY h = open_key(key_path);
        if (!h)
            return out;
        HKeyCloser guard{h};
        // RegEnumKeyExW's lpcchName is a WCHAR COUNT, not a byte size; bind
        // the buffer size and every reset to one constant (#1662 gotcha).
        constexpr DWORD kNameBufLen = 256;
        wchar_t name_buf[kNameBufLen]{};
        DWORD idx = 0;
        DWORD name_len = kNameBufLen;
        while (RegEnumKeyExW(h, idx++, name_buf, &name_len, nullptr, nullptr, nullptr, nullptr) ==
               ERROR_SUCCESS) {
            out.push_back(from_wide(name_buf, static_cast<int>(name_len)));
            name_len = kNameBufLen;
        }
        return out;
    }

    std::vector<std::pair<std::string, std::string>>
    reg_enum_str_values(std::string_view key_path) override {
        std::vector<std::pair<std::string, std::string>> out;
        HKEY h = open_key(key_path);
        if (!h)
            return out;
        HKeyCloser guard{h};
        constexpr DWORD kNameBufLen = 512; // registry value names cap at 16383 wchars
        wchar_t name_buf[kNameBufLen]{};
        DWORD idx = 0;
        DWORD name_len = kNameBufLen;
        DWORD type = 0;
        while (RegEnumValueW(h, idx++, name_buf, &name_len, nullptr, &type, nullptr, nullptr) ==
               ERROR_SUCCESS) {
            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                std::string name = from_wide(name_buf, static_cast<int>(name_len));
                std::wstring wname(name_buf, name_len);
                if (auto value = read_str_value(h, wname))
                    out.emplace_back(std::move(name), std::move(*value));
            }
            name_len = kNameBufLen;
            type = 0;
        }
        return out;
    }

private:
    [[nodiscard]] HKEY open_key(std::string_view key_path) const {
        const std::wstring wpath = to_wide(key_path);
        HKEY h{};
        if (wow64_fallback_) {
            if (RegOpenKeyExW(root_, wpath.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &h) ==
                ERROR_SUCCESS)
                return h;
            if (RegOpenKeyExW(root_, wpath.c_str(), 0, KEY_READ | KEY_WOW64_32KEY, &h) ==
                ERROR_SUCCESS)
                return h;
            return nullptr;
        }
        if (RegOpenKeyExW(root_, wpath.c_str(), 0, KEY_READ, &h) == ERROR_SUCCESS)
            return h;
        return nullptr;
    }

    static std::optional<std::string> read_str_value(HKEY h, std::string_view value_name) {
        return read_str_value(h, to_wide(value_name));
    }

    static std::optional<std::string> read_str_value(HKEY h, const std::wstring& wname) {
        DWORD type = 0;
        DWORD size = 0;
        if (RegQueryValueExW(h, wname.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS)
            return std::nullopt;
        if ((type != REG_SZ && type != REG_EXPAND_SZ) || size == 0)
            return std::nullopt;
        std::vector<wchar_t> buf(size / sizeof(wchar_t) + 2, L'\0');
        DWORD size2 = static_cast<DWORD>(buf.size() * sizeof(wchar_t));
        if (RegQueryValueExW(h, wname.c_str(), nullptr, &type,
                             reinterpret_cast<LPBYTE>(buf.data()), &size2) != ERROR_SUCCESS)
            return std::nullopt;
        return reg_sz_to_utf8(buf.data(), size2);
    }

    HKEY root_;
    bool wow64_fallback_;
};

// ── slp_wmi (authoritative; surface table Windows row 1) ───────────────────

namespace wmi = yuzu::shared::wmi;

// Thin caller of the shared bounded query — the license-specific SLP query
// (roadmap surface table Windows row 1): all SoftwareLicensingProduct
// instances from root\cimv2. SELECT * rather than a property list because the
// property set drifts across Windows versions (e.g. ProductKeyChannel is
// absent on older builds and a named-property query would fail outright);
// the caller reads Name, Description, LicenseStatus, GracePeriodRemaining,
// PartialProductKey, ProductKeyChannel and EvaluationEndDate from the row map
// and filters to rows with a PartialProductKey or a meaningful (non-zero)
// LicenseStatus.
wmi::BoundedQueryResult query_software_licensing_products(const wmi::BoundedQueryOptions& opts = {}) {
    return wmi::run_bounded_wmi_query(L"root\\cimv2", L"SELECT * FROM SoftwareLicensingProduct", opts);
}

std::string row_get(const wmi::WmiRow& row, const char* key) {
    const auto it = row.find(key);
    return it == row.end() ? std::string{} : it->second;
}

void run_slp_surface(long long now_epoch, std::vector<LicRecord>& records,
                     std::vector<ProbeOutcome>& outcomes) {
    const auto result = query_software_licensing_products();
    if (result.error) {
        outcomes.push_back({"slp_wmi", false, 0, *result.error});
        return;
    }

    std::size_t emitted = 0;
    for (const auto& row : result.rows) {
        const std::string partial_key = row_get(row, "PartialProductKey");
        const std::string status_raw = row_get(row, "LicenseStatus");
        const long status_code = status_raw.empty() ? -1 : std::strtol(status_raw.c_str(), nullptr, 10);
        // Only rows with a PartialProductKey or a meaningful (non-zero)
        // licence status — SLP carries ~100 keyless, never-activated SKU rows.
        if (partial_key.empty() && status_code <= 0)
            continue;

        LicRecord r;
        r.product = row_get(row, "Name");
        r.vendor = "Microsoft";
        r.status = status_raw.empty() ? "unknown" : slp_status_to_status(status_code);
        r.channel = classify_channel(row_get(row, "ProductKeyChannel"), row_get(row, "Description"));

        const std::string eval_end = parse_wmi_datetime_to_expiry(row_get(row, "EvaluationEndDate"));
        if (!eval_end.empty()) {
            r.license_type = "trial";
            r.expires_at = eval_end;
        } else if (r.channel == "kms" || r.channel == "mak") {
            r.license_type = "volume";
        } else if (r.channel == "oem") {
            r.license_type = "oem";
        } else if (r.channel == "retail") {
            r.license_type = "retail";
        } // else stays "unknown" — unknown-preserving, never guessed

        if (r.status == "grace") {
            // Countdown → ABSOLUTE midnight-epoch (D3 blob-stability): a
            // ticking minute counter must not change the record between syncs.
            const std::string grace_raw = row_get(row, "GracePeriodRemaining");
            const long long minutes = grace_raw.empty() ? 0 : std::strtoll(grace_raw.c_str(), nullptr, 10);
            const std::string until = grace_expiry_date(now_epoch, minutes);
            if (!until.empty())
                r.expires_at = until;
        }

        r.source = "os_licensing_api";
        r.confidence = "authoritative";
        r.key_hint = derive_key_hint(partial_key, ""); // OS partial key verbatim
        records.push_back(std::move(r));
        ++emitted;
    }

    if (result.truncated) {
        // The enumeration did not complete (C-8 row cap) — not a structural
        // success (ADR-0024 D3). Rows collected so far are still emitted for
        // diagnostics; the sync source decides skip semantics off this status.
        outcomes.push_back({"slp_wmi", false, emitted, "row_cap_exceeded"});
    } else {
        outcomes.push_back({"slp_wmi", true, emitted, {}});
    }
}

// ── office_c2r (probable; surface table Windows row 2) ─────────────────────

void run_office_c2r_surface(ProbeHost& host, std::vector<LicRecord>& records,
                            std::vector<ProbeOutcome>& outcomes) {
    static constexpr const char* kConfigKey =
        "SOFTWARE\\Microsoft\\Office\\ClickToRun\\Configuration";
    std::size_t emitted = 0;
    if (host.reg_key_exists(kConfigKey)) {
        const std::string release_ids = host.reg_read_str(kConfigKey, "ProductReleaseIds").value_or("");
        const std::string version = host.reg_read_str(kConfigKey, "VersionToReport").value_or("");
        std::size_t pos = 0;
        while (pos <= release_ids.size() && !release_ids.empty()) {
            std::size_t comma = release_ids.find(',', pos);
            if (comma == std::string::npos)
                comma = release_ids.size();
            std::string token = release_ids.substr(pos, comma - pos);
            pos = comma + 1;
            while (!token.empty() && token.front() == ' ')
                token.erase(token.begin());
            while (!token.empty() && token.back() == ' ')
                token.pop_back();
            if (token.empty())
                continue;
            LicRecord r;
            r.product = "Microsoft Office (" + token + ")";
            r.vendor = "Microsoft";
            r.version = version;
            r.license_type = classify_office_release_id(token);
            r.status = "unknown"; // the C2R SKU says type, not licence state —
                                  // slp_wmi is the authoritative state source
            r.source = "registry_probe";
            r.confidence = "probable";
            r.exe_hints = "winword.exe,excel.exe,outlook.exe,powerpnt.exe";
            records.push_back(std::move(r));
            ++emitted;
            if (comma == release_ids.size())
                break;
        }
    }
    outcomes.push_back({"office_c2r", true, emitted, {}});
}

// ── per-user surfaces (C-1 hive mounting; R15 privileges; D11 user_ref) ────

// ProfileEntry / enumerate_profiles / enable_privilege are retired (#2771).
// This file was the reference the shared ladder was ported FROM; it now
// consumes agents/shared/win_profiles.hpp instead of carrying the third copy
// of the ProfileList walk. enable_privilege in particular left
// SeBackupPrivilege/SeRestorePrivilege ENABLED for the remaining life of the
// agent process; PrivilegeScope restores the token's prior attributes on
// scope exit, which is the security fix this migration buys.

void stamp_user_records(std::vector<LicRecord>& records, std::size_t from,
                        const std::string& profile_name) {
    for (std::size_t i = from; i < records.size(); ++i) {
        records[i].user_scope = "user";
        // Stays EMPTY, never "-" -- deliberately DIFFERENT from
        // installed_apps' operator-facing row, which renders "-" for
        // display (code-review Standards question). user_ref feeds
        // sync_source_software_licensing.cpp's HMAC pseudonym; a cosmetic
        // "-" substituted here would change what gets hashed for every
        // profile with an unresolvable name, not just how it displays.
        // Never a SID either way (D11).
        records[i].user_ref = profile_name;
    }
}

void per_user_file_probes(ProbeHost& fs_host, const std::string& profile_path_utf8,
                          std::vector<LicRecord>& out) {
    if (profile_path_utf8.empty())
        return;
    // JetBrains licence keys (roadmap: "%LOCALAPPDATA%-shaped per-profile
    // paths" — the .key files live under the profile's Roaming tree;
    // <Product>/eval/ keys are evaluations).
    static const ProbeSpec kJetbrainsSpec{"per_user_files", Platform::windows_os, Scope::user,
                                          ProbeKind::file_glob, "", jetbrains_key_interpreter(),
                                          nullptr, nullptr, nullptr, nullptr, nullptr, nullptr};
    for (const char* suffix :
         {"/AppData/Roaming/JetBrains/*/*.key", "/AppData/Roaming/JetBrains/*/eval/*.key"}) {
        for (const auto& match : fs_host.glob(profile_path_utf8 + suffix))
            kJetbrainsSpec.interpret(fs_host, kJetbrainsSpec, match, out);
    }
    // Adobe NGL sign-in artefact (Creative Cloud licensing state cache).
    const std::string opm = profile_path_utf8 + "\\AppData\\Local\\Adobe\\OOBE\\opm.db";
    if (fs_host.file_exists(opm)) {
        LicRecord r;
        r.product = "Adobe Creative Cloud";
        r.vendor = "Adobe";
        r.license_type = "subscription";
        r.status = "unknown"; // presence of the NGL artefact, not licence state
        r.source = "heuristic";
        r.confidence = "heuristic";
        out.push_back(std::move(r));
    }
}

void run_per_user_surfaces(std::vector<LicRecord>& records, std::vector<ProbeOutcome>& outcomes) {
    bool profiles_ok = false;
    bool truncated = false;
    const auto raw_profiles = yuzu::win::enumerate_profile_records(profiles_ok, &truncated);
    if (!profiles_ok) {
        outcomes.push_back({"per_user_hives", false, 0, "profile_list_unreadable"});
        outcomes.push_back({"per_user_files", false, 0, "profile_list_unreadable"});
        return;
    }
    const auto hku_subkeys = yuzu::win::enumerate_hku_subkeys();
    // System SIDs are filtered inside build_profile_list, and the D11
    // never-the-SID rule for profile_name is an invariant of that header —
    // this file no longer restates either.
    const auto profiles = yuzu::profiles::build_profile_list(raw_profiles, hku_subkeys);

    WinRegProbeHost fs_host; // filesystem defaults only (per-user file probes)
    std::size_t hive_rows = 0;
    std::size_t file_rows = 0;
    bool hive_unload_failed = false; // any profile's RegUnLoadKeyW failed
    bool privilege_missing = false;  // some profile NEEDED an offline mount and could not

    for (const auto& profile : profiles) {
        // ── registry hive: loaded HKU\<SID> FIRST, offline NTUSER.DAT as the
        // fallback (C-1 probe order) — both now inside the shared ladder,
        // which also closes every HKEY into the mount before unloading and
        // restores the privilege token state on the way out.
        std::size_t before = records.size();
        std::vector<ProbeOutcome> scratch; // aggregated into one surface below
        yuzu::win::HiveAccessReport report;
        const auto status = yuzu::win::with_user_hive(
            profile.sid, profile.profile_path,
            [&](HKEY root) {
                WinRegProbeHost user_host{root};
                run_probe_specs(user_host, Platform::windows_os, Scope::user, records, scratch);
            },
            &report);
        if (report.unload_failed)
            hive_unload_failed = true;
        if (status == yuzu::win::HiveAccessStatus::privilege_missing)
            privilege_missing = true;
        // A per-profile load failure (hive corrupt/locked) is still not a
        // surface failure: per-user hives are never a primary surface
        // (ADR-0024 D3/R15) — the profile is skipped, the cycle proceeds.
        stamp_user_records(records, before, profile.profile_name);
        hive_rows += records.size() - before;

        // ── profile licence files (no hive required) ───────────────────────
        before = records.size();
        per_user_file_probes(fs_host, profile.profile_path, records);
        stamp_user_records(records, before, profile.profile_name);
        file_rows += records.size() - before;
    }

    // Precedence unchanged: privilege_missing outranks an unload failure.
    // What DID change is when it fires — previously a single process-wide
    // enable was attempted up front, so a hardened install reported
    // privilege_missing even when every profile was live-loaded and no
    // offline mount was ever needed. Now it reflects a profile that actually
    // required the fallback and could not get it.
    if (privilege_missing) {
        // R15: hardened installs that strip SeBackup/SeRestore surface here
        // through the live `surfaces` diagnostics. Loaded hives were still
        // probed (their records ride `list` regardless); offline NTUSER.DAT
        // hives were unreadable, so availability is honestly degraded.
        outcomes.push_back({"per_user_hives", false, hive_rows, "privilege_missing"});
    } else if (hive_unload_failed) {
        // A RegUnLoadKeyW failure (exotic — the ladder closes every HKEY into
        // the hive before unloading) leaves that profile's NTUSER.DAT mounted
        // and locked. The rows probed are still valid (they ride `list`
        // regardless), but the condition must be visible: ok=false + rows,
        // the privilege_missing precedent. Never a silent leak of a
        // system-wide mount. Non-cycle-blocking — per-user hives are never a
        // primary surface (sync source, ADR-0024 D3/R15).
        outcomes.push_back({"per_user_hives", false, hive_rows, "hive_unload_failed"});
    } else if (truncated) {
        // New with the shared ladder, which caps the walk at kMaxProfiles
        // where this file's own enumerate_profiles was unbounded. Reported
        // rather than silently returning a short list.
        outcomes.push_back({"per_user_hives", false, hive_rows, "profile_list_truncated"});
    } else {
        outcomes.push_back({"per_user_hives", true, hive_rows, {}});
    }
    outcomes.push_back({"per_user_files", true, file_rows, {}});
}

} // namespace

// ── the Windows run ─────────────────────────────────────────────────────────

SurfaceRun run_platform_surfaces() {
    SurfaceRun run;
    WinRegProbeHost machine_host;

    // Authoritative first: SLP via the bounded WMI enumerator (C-8).
    run_slp_surface(machine_host.now_epoch(), run.records, run.outcomes);

    // Office ClickToRun configuration (probable).
    run_office_c2r_surface(machine_host, run.records, run.outcomes);

    // Machine-scope ProbeSpec rows (probable/heuristic).
    run_probe_specs(machine_host, Platform::windows_os, Scope::machine, run.records,
                    run.outcomes);

    // Per-user surfaces (ADR-0016 deviation, Decision 11; never primary).
    run_per_user_surfaces(run.records, run.outcomes);

    return run;
}

} // namespace yuzu::license_scan

#endif // _WIN32
