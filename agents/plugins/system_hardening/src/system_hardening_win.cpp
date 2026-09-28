/**
 * system_hardening_win.cpp -- Windows leg of the system_hardening `posture`
 * action; defines collect_posture_win() from system_hardening_legs.hpp. All
 * decode and failure-classification logic is in the pure
 * system_hardening_win_parsers.hpp; this TU owns only the Win32 reads
 * (rung 1: no spawn, no WMI, no PowerShell):
 *   1. RegQueryValueExW on HKLM\SYSTEM\CurrentControlSet\Control\Session
 *      Manager\kernel : MitigationOptions, MitigationAuditOptions.
 *   2. GetProcessMitigationPolicy(GetCurrentProcess(), DEP/ASLR/CFG): the
 *      agent's OWN process only, as `self.*` rows.
 *
 * FAILURE SEMANTICS ("failure never reads as absent; absence is never a failure"):
 *   ABSENT -- the OS definitively reports the thing is not there. The row reads
 *   `absent`, adds NO token and does not lower the status:
 *   ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND on a registry VALUE
 *                        -> `absent` (a not-found on the Session Manager\kernel KEY
 *                           itself is NOT absence: that key exists on every install,
 *                           so it reads `unreadable`, <row>:key_missing)
 *   GetProcessMitigationPolicy ERROR_NOT_SUPPORTED
 *                        -> `absent`
 *   UNREADABLE -- the read failed; the row reads `unreadable` with one token per cause:
 *   ERROR_ACCESS_DENIED  -> `unreadable`, <name>:access_denied, status
 *                           PERMISSION_DENIED
 *   GetProcessMitigationPolicy ERROR_INVALID_PARAMETER
 *                        -> `unreadable`, <name>:win32_87 (every supported target implements
 *                           DEP/ASLR/CFG, so it is a malformed call, not an answer)
 *   other Win32 / a type other than REG_BINARY or an 8-byte REG_QWORD / oversized /
 *   undecodable blob     -> `unreadable`, <name>:win32_<n> | type_<n> |
 *                           oversized | <decoder token>
 * Only unreadable rows accumulate tokens (ConstraintAccumulator); the status is
 * select_status (system_hardening_parsers.hpp): PERMISSION_DENIED when any read
 * was refused, else CONSTRAINED/PARTIAL when any token exists, else OK/FULL.
 * MitigationOptions/MitigationAuditOptions do not exist on a default install
 * (the rig probe below), so that modal state reads two `absent` rows and
 * OK/FULL. A missing or unreadable key never yields a non-zero exit: return 0
 * for every data-level outcome; an internal exception is contained by the
 * portable execute() (rc 1, constrained|<os>|internal_error|-|unreadable).
 *
 * THE-RIG PROBE (rig session A, 2026-09-21, Windows 11 Pro 10.0.26200, x64, run as
 * NT AUTHORITY\SYSTEM). The full transcript is in the PR body; the fixture and its provenance are
 * tests/unit/fixtures/wave8/system_hardening/windows/mitigation_options.hex[.provenance.txt].
 *   - MitigationOptions and MitigationAuditOptions are ABSENT on a fresh install (`reg query`: the
 *     system was unable to find the specified registry key or value).
 *   - With DEP, SEHOP, BottomUp, HighEntropy and CFG enabled system-wide the value is a 24-byte
 *     REG_BINARY whose QWORD 0 has exactly the nibbles {0,1,4,5,10} set. This REFUTED the
 *     <winbase.h> flag layout the first decoder assumed (see system_hardening_win_parsers.hpp).
 *     UNVERIFIED on hardware: the other eleven nibble positions, nibble values other than 1, and
 *     any non-zero MitigationAuditOptions value.
 *   - GetProcessMitigationPolicy from a 64-bit SYSTEM process: DEP (Flags 0x3), ASLR (0x5) and
 *     CFG (0x0) all succeed, so `self.dep` is a real row on x64. The installer admits only
 *     Windows 10+ x64, where all three classes exist, so neither failure branch below was
 *     exercised on this rig: ERROR_NOT_SUPPORTED -> `absent` (no token) and
 *     ERROR_INVALID_PARAMETER -> `unreadable` (`win32_87`). Windows on ARM64 running the x64
 *     build under emulation is not verified.
 *   - UNVERIFIED on hardware: a REG_QWORD MitigationOptions (the documented font-blocking
 *     steps); it is decoded as the 8-byte QWORD it is (decode_registry_value).
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

#include "system_hardening_legs.hpp"
#include "system_hardening_win_parsers.hpp"

#include <constraint_accumulator.hpp>
#include <yuzu/plugin.hpp>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace yuzu::system_hardening {

namespace {

namespace mit = yuzu::system_hardening::mitigation;

constexpr wchar_t kKernelKey[] = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel";

/// One byte over the decoder's cap is enough to detect "oversized": a 257-byte value reaches the
/// decoder, which labels it so; anything larger fails the read itself (ERROR_MORE_DATA).
constexpr DWORD kReadCap = static_cast<DWORD>(mit::kMaxBlobBytes) + 1;

struct Probe {
    yuzu::shared::ConstraintAccumulator acc;
    bool denied{false};
};

// The pure classifier keeps the Win32 numbers as plain integers; pin them to the SDK's.
static_assert(mit::kErrorFileNotFound == static_cast<std::uint32_t>(ERROR_FILE_NOT_FOUND));
static_assert(mit::kErrorPathNotFound == static_cast<std::uint32_t>(ERROR_PATH_NOT_FOUND));
static_assert(mit::kErrorAccessDenied == static_cast<std::uint32_t>(ERROR_ACCESS_DENIED));
static_assert(mit::kErrorNotSupported == static_cast<std::uint32_t>(ERROR_NOT_SUPPORTED));
static_assert(mit::kErrorInvalidParameter == static_cast<std::uint32_t>(ERROR_INVALID_PARAMETER));
static_assert(mit::kRegBinary == static_cast<std::uint32_t>(REG_BINARY));
static_assert(mit::kRegQword == static_cast<std::uint32_t>(REG_QWORD));

/// Writes the row for one failed read, as the pure layer classified it. `absent` (the OS
/// definitively says it is not there) adds no token and leaves the status alone; `unreadable`
/// adds one token per cause, and ERROR_ACCESS_DENIED also marks the run PERMISSION_DENIED.
void report_failure(yuzu::CommandContext& ctx, Probe& p, std::string_view row_name,
                    const mit::ReadFailure& f) {
    if (f.access_denied)
        p.denied = true;
    if (!f.token.empty())
        p.acc.add_failure(f.token);
    ctx.write_output(mit::format_posture_row(row_name, "-", f.state));
}

/// Reads + decodes one mitigation value, emitting its rows or one absent/unreadable row.
void collect_blob(yuzu::CommandContext& ctx, Probe& p, HKEY kernel_key, const mit::RegistryRow& row) {
    const std::wstring value_w{row.value_name};
    const std::string_view row_name = row.row_name;
    DWORD type = 0;
    DWORD size = kReadCap;
    std::vector<BYTE> buf(kReadCap);
    const LSTATUS rc = RegQueryValueExW(kernel_key, value_w.c_str(), nullptr, &type, buf.data(), &size);
    if (rc == ERROR_MORE_DATA)
        return report_failure(ctx, p, row_name, mit::unreadable_failure(row_name, "oversized"));
    if (rc != ERROR_SUCCESS)
        return report_failure(ctx, p, row_name,
                              mit::classify_win32_failure(row_name, static_cast<std::uint32_t>(rc),
                                                          mit::ReadSource::registry));
    // The type decision (REG_BINARY, or an 8-byte REG_QWORD) is the pure decode_registry_value's.
    auto rows = mit::decode_registry_value(static_cast<std::uint32_t>(type),
                                           std::span<const std::uint8_t>{buf.data(), size},
                                           row.row_prefix);
    if (!rows)
        return report_failure(ctx, p, row_name,
                              mit::unreadable_failure(row_name, rows.error().token));
    for (const auto& r : *rows)
        ctx.write_output(mit::format_posture_row(r));
}

void collect_registry(yuzu::CommandContext& ctx, Probe& p) {
    yuzu::win::RegKey key;
    const LSTATUS orc =
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, kKernelKey, 0, KEY_READ | KEY_WOW64_64KEY, key.put());
    if (orc != ERROR_SUCCESS) {
        // The key itself, not a value inside it: never legitimate absence (the pure layer
        // classifies it ReadSource::structural_key), so every registry row reads unreadable.
        for (const auto& f : mit::kernel_key_open_failures(static_cast<std::uint32_t>(orc)))
            report_failure(ctx, p, f.row_name, f.failure);
        return;
    }
    for (const auto& row : mit::kRegistryRows)
        collect_blob(ctx, p, key.get(), row);
}

/// One GetProcessMitigationPolicy call; the pure decoder consumes `Flags`.
template <class Policy>
void collect_self(yuzu::CommandContext& ctx, Probe& p, PROCESS_MITIGATION_POLICY which,
                  mit::SelfPolicy kind, std::string_view row_name) {
    Policy policy{};
    if (!GetProcessMitigationPolicy(GetCurrentProcess(), which, &policy, sizeof(policy))) {
        const DWORD err = GetLastError();
        return report_failure(ctx, p, row_name,
                              mit::classify_win32_failure(row_name, static_cast<std::uint32_t>(err),
                                                          mit::ReadSource::process_policy));
    }
    for (const auto& r : mit::decode_self_policy(kind, static_cast<std::uint32_t>(policy.Flags)))
        ctx.write_output(mit::format_posture_row(r));
}

} // namespace

int collect_posture_win(yuzu::CommandContext& ctx) {
    Probe p;
    collect_registry(ctx, p);
    collect_self<PROCESS_MITIGATION_DEP_POLICY>(ctx, p, ProcessDEPPolicy, mit::SelfPolicy::dep,
                                                "self.dep");
    collect_self<PROCESS_MITIGATION_ASLR_POLICY>(ctx, p, ProcessASLRPolicy, mit::SelfPolicy::aslr,
                                                 "self.aslr");
    collect_self<PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY>(
        ctx, p, ProcessControlFlowGuardPolicy, mit::SelfPolicy::cfg, "self.cfg");

    const auto s = select_status(p.acc, p.denied);
    ctx.set_result_status(s.status, s.completeness, s.provenance);
    return 0;
}

} // namespace yuzu::system_hardening

#endif // _WIN32
