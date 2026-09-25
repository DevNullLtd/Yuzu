/**
 * app_control_win.cpp -- Windows leg of the app_control plugin: configured WDAC
 * (Code Integrity) and AppLocker application-control posture, read-only.
 *
 *   wdac_policy      HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy (every 32-bit and
 *                    string value; VerifiedAndReputablePolicyState mapped) + presence of
 *                    %SystemRoot%\System32\CodeIntegrity\CiPolicies\Active\*.cip and of the
 *                    legacy single-format %SystemRoot%\System32\CodeIntegrity\SiPolicy.p7b
 *                    (a stat: presence only, never opened).
 *   applocker_policy wmi_bounded.hpp run_bounded_wmi_query against
 *                    root\StandardCimv2\Security\ApplicationControl / MSFT_ApplockerPolicy;
 *                    when the class is absent, empty or failing, a walk of
 *                    HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\<collection>
 *                    (EnforcementMode + rule-subkey count).
 *
 * This TU owns ONLY the Win32 I/O; every mapping, row format, namespace floor and error
 * classification is the pure app_control_parsers.hpp (registry types stop at RegValueView).
 *
 * RIG PROBE (rig session A, 2026-09-21, Windows 11 Pro 10.0.26200, x64; NT AUTHORITY\SYSTEM
 * scheduled task, RunLevel Highest) -- COMPLETE for what this host can show. Real captures:
 * tests/unit/fixtures/wave8/app_control/windows/ and docs/samples/windows.txt.
 *   AppLocker CIM: the namespace root\StandardCimv2\Security\ApplicationControl does NOT exist.
 *             A throwaway probe calling yuzu::shared::wmi::run_bounded_wmi_query (the same helper
 *             this TU uses) returned `error=wmi_connect_failed_0x8004100e rows=0`
 *             (WBEM_E_INVALID_NAMESPACE); PowerShell Get-CimClass says "Invalid namespace"
 *             (managed HRESULT 0x80131500); root\StandardCimv2 holds only MS_409, MS_809,
 *             embedded. So MSFT_ApplockerPolicy's property names (Collection / EnforcementMode /
 *             RuleCount, pinned by parse_cim_applocker_row) are STILL UNVERIFIED on hardware.
 *   SrpV2 walk: `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2 /s` -> "ERROR: The
 *             system was unable to find the specified registry key or value." (no AppLocker policy
 *             configured); the plugin reports `applocker|none|absent|0`, OK / FULL /
 *             registry_srpv2. The rule-collection layout was therefore never read on an
 *             AppLocker-configured host. CI\Policy values as SYSTEM: EmodePolicyRequired=0, SkuPolicyRequired=0,
 *             VerifiedAndReputablePolicyState=0 (maps `disabled`), SAC_PreviousState=0xffffffff
 *             (`unmodelled`); 8 default .cip policies in CodeIntegrity\CiPolicies\Active. Only
 *             VerifiedAndReputablePolicyState=0 has been observed; 1/2 are mapped per documentation
 *             and unverified on hardware.
 * The probe decided the branch on this host: CIM class absent -> SrpV2 registry walk. Both
 * branches are implemented and chosen at runtime; the CIM-present branch is untested on hardware.
 *
 * FAILURE SEMANTICS: every failed step records a token on ConstraintAccumulator and is
 * never rendered as absent. ERROR_ACCESS_DENIED -> PERMISSION_DENIED, anything else ->
 * CONSTRAINED/PARTIAL; exit code 0 only on OK. The only "absent" outputs are a genuine
 * ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND of a key, a value (EnforcementMode) or a directory,
 * a directory read cleanly that held no policy file, and a stat of SiPolicy.p7b (or a missing
 * parent) reporting not-found.
 */
#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <win_reg_handle.hpp> // yuzu::win::RegKey
#include <win_str.hpp>        // yuzu::win::to_wide / from_wide / reg_sz_to_utf8
#include <wmi_bounded.hpp>    // yuzu::shared::wmi::run_bounded_wmi_query

#include "app_control_parsers.hpp"

#include <yuzu/plugin.hpp>

#include <constraint_accumulator.hpp>

#include "app_control_legs.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <vector>

namespace yuzu::app_control {

namespace {

constexpr wchar_t kCiPolicyKey[] = L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy";
constexpr wchar_t kSrpV2Key[] = L"SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2";
constexpr wchar_t kCipActiveSubdir[] = L"\\System32\\CodeIntegrity\\CiPolicies\\Active";
constexpr wchar_t kSiPolicySubpath[] = L"\\System32\\CodeIntegrity\\SiPolicy.p7b";

constexpr DWORD kMaxValueBytes = 4096;      // per-value data cap (CI\Policy values are tiny)
constexpr DWORD kMaxValueNameChars = 16384; // registry's documented maximum value-name length
constexpr DWORD kMaxValues = 256;

// The pure classifier (app_control_parsers.hpp) carries these as plain integers.
static_assert(kErrorSuccess == static_cast<std::uint32_t>(ERROR_SUCCESS));
static_assert(kErrorFileNotFound == static_cast<std::uint32_t>(ERROR_FILE_NOT_FOUND));
static_assert(kErrorPathNotFound == static_cast<std::uint32_t>(ERROR_PATH_NOT_FOUND));
static_assert(kErrorAccessDenied == static_cast<std::uint32_t>(ERROR_ACCESS_DENIED));
static_assert(kErrorMoreData == static_cast<std::uint32_t>(ERROR_MORE_DATA));
static_assert(kErrorNoMoreItems == static_cast<std::uint32_t>(ERROR_NO_MORE_ITEMS));
static_assert(kMaxValueBytes % sizeof(wchar_t) == 0, "the value buffer is sized in wchar_t units");
// x64 only (the installer is x64compatible): a 32-bit build would be WOW64-redirected away from the
// real CodeIntegrity\CiPolicies\Active and misreport it as an absent directory.
static_assert(sizeof(void*) == 8);
// plan_cim consumes the bounded query's rows directly.
static_assert(std::is_same_v<yuzu::app_control::WmiRow, yuzu::shared::wmi::WmiRow>);

struct Outcome {
    yuzu::shared::ConstraintAccumulator acc;
    bool denied = false;

    /// Classifies one Win32 read result, records its failure token (an absence carries none) and
    /// returns the state; the decision is the pure classify_win32_read.
    RegRead note(std::string_view what, LONG rc, ReadKind kind) {
        const auto f = classify_win32_read(what, static_cast<std::uint32_t>(rc), kind);
        if (f.access_denied)
            denied = true;
        if (!f.token.empty())
            acc.add_failure(f.token);
        return f.state;
    }
};

/// Emits the constrained row on any failure, sets the typed status; exit 0 only when OK.
int apply_verdict(yuzu::CommandContext& ctx, const ActionVerdict& v, const Outcome& o) {
    if (v.constrained_row_due)
        ctx.write_output(format_constrained_row(o.acc.reason()));
    ctx.set_result_status(v.status, v.completeness, v.provenance);
    return v.rc;
}

int finish(yuzu::CommandContext& ctx, const Outcome& o, std::string_view source) {
    return apply_verdict(ctx, select_verdict(o.acc, o.denied, source), o);
}

/// One REG_DWORD: ERROR_SUCCESS, the query error, or ERROR_INVALID_DATA (wrong type/size).
struct U32Read {
    LONG rc;
    std::uint32_t value{}; // meaningful only when rc == ERROR_SUCCESS
};

U32Read read_u32(HKEY key, const wchar_t* name) {
    DWORD type = 0, size = sizeof(DWORD), value = 0;
    const LONG rc =
        RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE*>(&value), &size);
    if (rc == ERROR_SUCCESS && (type != REG_DWORD || size != sizeof(DWORD)))
        return {ERROR_INVALID_DATA, 0};
    return {rc, static_cast<std::uint32_t>(value)};
}

void read_ci_policy_values(yuzu::CommandContext& ctx, Outcome& o) {
    yuzu::win::RegKey key;
    const LONG open_rc =
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, kCiPolicyKey, 0, KEY_READ | KEY_WOW64_64KEY, key.put());
    const auto open = o.note("ci_policy_open", open_rc, ReadKind::open_or_query);
    if (open == RegRead::absent) {
        ctx.write_output(format_wdac_key_absent_row());
        return;
    }
    if (open != RegRead::ok)
        return;

    std::vector<wchar_t> name(kMaxValueNameChars);
    std::vector<wchar_t> data(kMaxValueBytes / sizeof(wchar_t)); // aligned for reg_sz_to_utf8
    for (DWORD index = 0;; ++index) {
        DWORD name_len = static_cast<DWORD>(name.size());
        DWORD data_len = kMaxValueBytes;
        DWORD type = 0;
        const LONG rc = RegEnumValueW(key.get(), index, name.data(), &name_len, nullptr, &type,
                                      reinterpret_cast<BYTE*>(data.data()), &data_len);
        const auto step = enum_step(index, kMaxValues, static_cast<std::uint32_t>(rc));
        if (step == EnumStep::stop_done)
            break;
        if (step == EnumStep::stop_row_cap) {
            o.acc.add_failure("row_cap"); // a value exists beyond the cap: truncated
            break;
        }
        if (step == EnumStep::skip_too_large) {
            o.acc.add_failure("value_too_large"); // skipped; enumeration continues
            continue;
        }
        if (step == EnumStep::stop_failed) {
            (void)o.note("ci_policy_enum", rc, ReadKind::enumerate); // token / denial, never absent
            break;
        }
        if (std::wstring_view{name.data(), name_len}.find(L'\0') != std::wstring_view::npos) {
            o.acc.add_failure("value_name_embedded_nul"); // its row would be cut at the NUL
            continue;
        }

        RegValueView v;
        v.name = yuzu::win::from_wide(name.data(), static_cast<int>(name_len));
        if (type == REG_DWORD && data_len == sizeof(DWORD)) {
            DWORD raw = 0;
            std::memcpy(&raw, data.data(), sizeof(raw));
            v.kind = RegValueKind::u32;
            v.u32 = static_cast<std::uint32_t>(raw);
        } else if (type == REG_SZ || type == REG_EXPAND_SZ) {
            v.kind = RegValueKind::text;
            v.text = yuzu::win::reg_sz_to_utf8(data.data(), data_len);
        } else {
            v.kind = RegValueKind::other;
            v.byte_len = data_len;
        }
        ctx.write_output(format_wdac_row(v));
    }
}

void list_active_cip_files(yuzu::CommandContext& ctx, Outcome& o) {
    wchar_t win_dir[MAX_PATH] = {};
    const UINT n = GetSystemWindowsDirectoryW(win_dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        o.acc.add_failure("system_directory_unresolved");
        return;
    }
    const std::filesystem::path dir = std::wstring{win_dir} + kCipActiveSubdir;

    // The shell owns only the filesystem calls; CipScan decides what each result means (and when
    // "no policy files" is a definitive absence rather than a failed read).
    std::error_code ec;
    CipScan scan{o.acc, o.denied};
    auto it = std::filesystem::directory_iterator(dir, ec);
    for (; !ec && it != std::filesystem::directory_iterator{}; it.increment(ec)) {
        std::error_code stat_ec;
        const bool regular = it->is_regular_file(stat_ec);
        // from_wide is total (a lone surrogate becomes U+FFFD); u8string() would throw on one.
        const std::string leaf = yuzu::win::from_wide(it->path().filename().c_str());
        if (!scan.observe(leaf, regular, stat_ec))
            break;
    }
    scan.finish(ec);
    // The legacy single-policy file is one more active policy (presence only).
    std::error_code single_ec;
    const bool single_regular =
        std::filesystem::is_regular_file(std::wstring{win_dir} + kSiPolicySubpath, single_ec);
    scan.observe_single(single_regular, single_ec);
    if (scan.none_row_due())
        ctx.write_output(format_cip_none_row());
    for (const auto& fname : scan.names())
        ctx.write_output(format_cip_row(fname));
    if (scan.single_present())
        ctx.write_output(format_cip_single_row());
}

/// Caller-side namespace floor (wmi_bounded.hpp does NO allowlisting).
yuzu::shared::wmi::BoundedQueryResult bounded_cim_query(std::string_view ns, std::string_view wql) {
    if (!is_allowed_cim_namespace(ns)) {
        yuzu::shared::wmi::BoundedQueryResult refused;
        refused.error = "namespace_not_allowed";
        return refused;
    }
    // sink: app_control/bounded_cim_query#1 -- rung 1, in-process CIM query (no PowerShell).
    yuzu::shared::wmi::BoundedQueryOptions opts;
    // A handful of rows is expected, so the enumeration stage is bounded at 15 s, not the helper's
    // 60 s. The connect stage keeps the helper's own max-wait bound (it has no millisecond knob).
    opts.enumeration_deadline_ms = 15000;
    return yuzu::shared::wmi::run_bounded_wmi_query(yuzu::win::to_wide(ns), yuzu::win::to_wide(wql),
                                                    opts);
}

/// SrpV2 registry walk. Returns the number of collection rows written.
std::size_t walk_srpv2(yuzu::CommandContext& ctx, Outcome& o) {
    yuzu::win::RegKey root;
    const LONG root_rc =
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, kSrpV2Key, 0, KEY_READ | KEY_WOW64_64KEY, root.put());
    if (o.note("srpv2_open", root_rc, ReadKind::open_or_query) != RegRead::ok)
        return 0;

    std::size_t written = 0;
    for (const auto collection : kApplockerCollections) {
        yuzu::win::RegKey sub;
        const LONG sub_rc = RegOpenKeyExW(root.get(), yuzu::win::to_wide(collection).c_str(), 0,
                                          KEY_READ | KEY_WOW64_64KEY, sub.put());
        const auto step =
            srpv2_collection_step(o.note("srpv2_collection_open", sub_rc, ReadKind::open_or_query));
        if (step == CollectionStep::absent_row) { // collection not configured: a definitive row
            ctx.write_output(format_applocker_row({std::string{collection}, std::nullopt, 0, true}));
            ++written;
            continue;
        }
        if (step == CollectionStep::skip)
            continue; // unreadable: recorded, never absent

        std::optional<std::uint32_t> mode;
        const auto mode_r = read_u32(sub.get(), L"EnforcementMode");
        const auto mode_read = o.note("enforcement_mode_read", mode_r.rc, ReadKind::open_or_query);
        if (mode_read == RegRead::unreadable)
            continue; // wrong type / denied: never rendered as absent
        if (mode_read == RegRead::ok)
            mode = mode_r.value; // absent leaves it nullopt

        DWORD rule_subkeys = 0;
        const LONG info_rc =
            RegQueryInfoKeyW(sub.get(), nullptr, nullptr, nullptr, &rule_subkeys, nullptr, nullptr,
                             nullptr, nullptr, nullptr, nullptr, nullptr);
        if (o.note("srpv2_rule_count", info_rc, ReadKind::enumerate) != RegRead::ok)
            continue;
        ctx.write_output(
            format_applocker_row({std::string{collection}, mode, rule_subkeys, true}));
        ++written;
    }
    return written;
}

} // namespace

int collect_wdac(yuzu::CommandContext& ctx) {
    Outcome o;
    read_ci_policy_values(ctx, o);
    list_active_cip_files(ctx, o);
    return finish(ctx, o, kProvenanceCiPolicy);
}

int collect_applocker(yuzu::CommandContext& ctx) {
    Outcome o;

    // The shell only performs the query; plan_cim decides what its result means.
    const auto q = bounded_cim_query(kCimNamespace, kCimApplockerWql);
    const auto plan = plan_cim(q.error, q.rows, q.truncated);
    for (const auto& r : plan.rows)
        ctx.write_output(format_applocker_row(r));

    // settle_applocker folds the CIM failures onto `o`, walks SrpV2 only when no CIM row mapped
    // (class absent / empty / failed), and decides the `none` row and the verdict.
    const auto fin =
        settle_applocker(plan, o.acc, o.denied, [&] { return walk_srpv2(ctx, o); });
    if (fin.none_row_due)
        ctx.write_output(format_applocker_none_row());
    return apply_verdict(ctx, fin.verdict, o);
}

} // namespace yuzu::app_control

#endif // _WIN32
