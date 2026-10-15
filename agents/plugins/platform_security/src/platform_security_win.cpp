/**
 * platform_security_win.cpp -- Windows leg of platform_security: defines collect_secure_boot_win()
 * and collect_code_integrity_win() from platform_security_legs.hpp. Rung 1, no spawn / WMI /
 * PowerShell / LSA: RegQueryValueExW on the HKLM keys named in platform_security_win_parsers.hpp
 * (kSecureBootKey, kCiPolicyKey, kDeviceGuardKey, kHvciScenarioKey, kLsaKey); CI\Policy value NAMES
 * come from the bounded win_profiles.hpp enumerate_value_names. Every decision (absent vs denied vs
 * failed, value -> state, the status) is a pure function in the parsers header; this TU only makes
 * the Win32 calls and writes the rows that layer returns. An escaped exception is contained by the
 * portable execute(); every data-level outcome returns 0.
 *
 * FAILURE SEMANTICS ("failure never reads as absent; absence is never a failure"): not-found ->
 * `absent`, no token; ERROR_ACCESS_DENIED -> `unreadable` + <name>:access_denied, PERMISSION_DENIED
 * (any refusal); other Win32 / wrong REG type / oversized / wrong size -> `unreadable`, one token.
 *
 * THE-RIG PROBE (rig session A, 2026-09-21T15:29:55+01:00, Windows 11 Pro 10.0.26200 x64, run as
 * NT AUTHORITY\SYSTEM via scheduled task, RunLevel Highest) -- PARTIAL, verbatim:
 *   HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy (present, 4 values, all REG_DWORD):
 *     EmodePolicyRequired 0x0 | SkuPolicyRequired 0x0 | VerifiedAndReputablePolicyState 0x0 |
 *     SAC_PreviousState 0xffffffff   (fixtures/wave8/platform_security/windows/ci_policy.reg)
 * RIG SESSION C (2026-09-21, the-rig, same identity; the transcript is in the PR body), verbatim:
 *   SecureBoot\State (Secure Boot ON; Confirm-SecureBootUEFI = True): UEFISecureBootEnabled REG_DWORD 0x1 |
 *     PolicyPublisher REG_SZ {77fa9abd-0359-4d32-bd60-28f4e78f784b} | PolicyVersion REG_DWORD 0x1
 *     (fixtures/wave8/platform_security/windows/secureboot_state.reg). The OFF state was NOT captured:
 *     the firmware toggle cannot be flipped remotely.
 *   Control\DeviceGuard (default host, VBS/HVCI not configured): CachedDrtmAuthIndex 0x0 |
 *     RequireMicrosoftSignedBootChain 0x1; EnableVirtualizationBasedSecurity,
 *     RequirePlatformSecurityFeatures and HypervisorEnforcedCodeIntegrity are ABSENT; Scenarios has
 *     CredentialGuard\Enabled 0x0 and KeyGuard\Status (deviceguard_real.reg).
 *   DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity: ABSENT (no such subkey).
 *   Control\Lsa: LsaCfgFlags ABSENT (only LsaCfgFlagsDefault 0x0 exists); the policy mirror
 *     HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard is ABSENT.
 *   WLDP: LoadLibraryExW(wldp.dll, LOAD_LIBRARY_SEARCH_SYSTEM32) succeeded and WldpGetLockdownPolicy
 *     resolves. Called with hostId GLOBAL it returns E_INVALIDARG (0x80070057); with hostId POWERSHELL
 *     and ALL it returns S_OK and lockdownState 0x80000000 (undefined), i.e. nothing the registry
 *     lacks, so no WLDP row is emitted.
 *   Never measured: any VBS/HVCI/Credential Guard ON state, a non-zero LsaCfgFlags, Secure Boot OFF.
 */

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <win_profiles.hpp>   // yuzu::win::enumerate_value_names
#include <win_reg_handle.hpp> // yuzu::win::RegKey
#include <win_str.hpp>        // yuzu::win::to_wide / reg_sz_to_utf8

#include "platform_security_legs.hpp"
#include "platform_security_win_parsers.hpp"

#include <yuzu/plugin.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::platform_security {

namespace {

namespace ps = yuzu::platform_security::win;

// The pure layer keeps the Win32 numbers as plain integers; pin them to the SDK's.
static_assert(ps::kErrorFileNotFound == static_cast<std::uint32_t>(ERROR_FILE_NOT_FOUND));
static_assert(ps::kErrorPathNotFound == static_cast<std::uint32_t>(ERROR_PATH_NOT_FOUND));
static_assert(ps::kErrorAccessDenied == static_cast<std::uint32_t>(ERROR_ACCESS_DENIED));
static_assert(ps::kErrorMoreData == static_cast<std::uint32_t>(ERROR_MORE_DATA));
static_assert(ps::kRegSz == static_cast<std::uint32_t>(REG_SZ));
static_assert(ps::kRegExpandSz == static_cast<std::uint32_t>(REG_EXPAND_SZ));
static_assert(ps::kRegDword == static_cast<std::uint32_t>(REG_DWORD));

ps::ValueOutcome failed(ps::ValueOutcome o, ps::Failure f) {
    o.ok = false;
    o.failure = std::move(f);
    return o;
}

/// One value: a size/type probe first (so an opaque REG_BINARY is never read), then the 4 bytes
/// or the string the pure plan_value_read asked for.
ps::ValueOutcome read_value(HKEY key, const ps::KeySpec& spec, const std::string& name) {
    ps::ValueOutcome o;
    o.name = name;
    const std::string rk = ps::row_key(spec, name);
    const std::wstring wname = yuzu::win::to_wide(name);
    DWORD type = 0;
    DWORD size = 0;
    LSTATUS rc = RegQueryValueExW(key, wname.c_str(), nullptr, &type, nullptr, &size);
    if (rc != ERROR_SUCCESS)
        return failed(o, ps::classify_win32_failure(rk, static_cast<std::uint32_t>(rc)));
    o.value.type = type;
    const DWORD probed_type = type; // the plan below is chosen from THIS type; the fill call's
                                     // own returned type is re-checked against it so a value
                                     // whose type changes between the probe and the fill (a
                                     // narrow TOCTOU window) is never silently misread as the
                                     // stale plan's kind.
    switch (ps::plan_value_read(type, size)) {
    case ps::ReadPlan::dword: {
        DWORD v = 0;
        DWORD sz = sizeof(v);
        rc = RegQueryValueExW(key, wname.c_str(), nullptr, &type, reinterpret_cast<BYTE*>(&v), &sz);
        if (rc != ERROR_SUCCESS)
            return failed(o, ps::classify_win32_failure(rk, static_cast<std::uint32_t>(rc)));
        if (type != probed_type)
            return failed(o, ps::unreadable_failure(rk, "type_changed"));
        // PR #4792 review (fjarvis, 5289352195): if the value shrinks below 4
        // bytes between the probe and this fill (a narrow TOCTOU on an
        // admin-writable key), RegQueryValueExW still returns ERROR_SUCCESS
        // with `sz` set to the actual (smaller) size and `v`'s un-written
        // trailing bytes left at their zero-init -- silently fabricating a
        // zero-extended dword instead of reporting the shrink.
        if (sz != sizeof(v))
            return failed(o, ps::unreadable_failure(rk, "size_" + std::to_string(sz)));
        o.value.kind = ps::ValueKind::dword;
        o.value.dword = static_cast<std::uint32_t>(v);
        return o;
    }
    case ps::ReadPlan::text: {
        std::vector<wchar_t> buf(size / sizeof(wchar_t) + 1, L'\0');
        DWORD sz = size;
        rc = RegQueryValueExW(key, wname.c_str(), nullptr, &type, reinterpret_cast<BYTE*>(buf.data()),
                              &sz);
        if (rc != ERROR_SUCCESS)
            return failed(o, ps::classify_win32_failure(rk, static_cast<std::uint32_t>(rc)));
        if (type != probed_type)
            return failed(o, ps::unreadable_failure(rk, "type_changed"));
        o.value.kind = ps::ValueKind::text;
        o.value.text = yuzu::win::reg_sz_to_utf8(buf.data(), sz);
        return o;
    }
    case ps::ReadPlan::opaque:
        o.value.kind = ps::ValueKind::other;
        o.value.byte_len = size;
        return o;
    case ps::ReadPlan::bad_size:
        return failed(o, ps::unreadable_failure(rk, "size_" + std::to_string(size)));
    case ps::ReadPlan::oversized:
        return failed(o, ps::unreadable_failure(rk, "oversized"));
    }
    return failed(o, ps::unreadable_failure(rk, "internal_error"));
}

/// One key: open it, then read every value the spec names (or, for CI\Policy, every value found).
ps::KeyRead read_key(const ps::KeySpec& spec) {
    ps::KeyRead kr;
    yuzu::win::RegKey key;
    const LSTATUS orc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, yuzu::win::to_wide(spec.path).c_str(), 0,
                                      KEY_READ | KEY_WOW64_64KEY, key.put());
    if (orc != ERROR_SUCCESS) {
        kr.opened = false;
        kr.failure = ps::classify_win32_failure(spec.label, static_cast<std::uint32_t>(orc));
        return kr;
    }
    std::vector<std::string> names;
    if (spec.enumerate) {
        auto en = yuzu::win::enumerate_value_names(key.get());
        names = std::move(en.names);
        kr.complete = en.complete;
    } else {
        for (const auto& e : spec.expected)
            names.emplace_back(e.name);
    }
    for (const auto& n : names)
        kr.values.push_back(read_value(key.get(), spec, n));
    return kr;
}

int emit(yuzu::CommandContext& ctx, const ps::Report& rep) {
    for (const auto& r : rep.rows)
        ctx.write_output(ps::format_row(r));
    const auto s = ps::select_status(rep);
    ctx.set_result_status(s.status, s.completeness, s.provenance);
    return 0;
}

} // namespace

int collect_secure_boot_win(yuzu::CommandContext& ctx) {
    return emit(ctx, ps::build_secure_boot_report(read_key(ps::kSecureBootKey)));
}

int collect_code_integrity_win(yuzu::CommandContext& ctx) {
    return emit(ctx, ps::build_code_integrity_report(read_key(ps::kCiPolicyKey),
                                                     read_key(ps::kDeviceGuardKey),
                                                     read_key(ps::kHvciScenarioKey),
                                                     read_key(ps::kLsaKey)));
}

} // namespace yuzu::platform_security

#endif // _WIN32
