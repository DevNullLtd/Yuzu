/**
 * hardware_estate_win.cpp -- the Windows leg of chassis / baseboard / swap / machine_id.
 *
 * Thin I/O only: every decision (field hygiene, placeholder handling, the stable swap total, the
 * outcome mapping) is in hardware_estate_parsers.hpp and is unit-tested on every host. This file
 * reads and hands over.
 *
 *   chassis, baseboard  GetSystemFirmwareTable('RSMB') through the shared reader
 *                       (agents/shared/win_rsmb.hpp), decoded by the shared SMBIOS walker.
 *   machine_id          HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid (64-bit view), hashed
 *                       with the fixed-label HMAC (machine_id_hash.hpp); the raw id never leaves
 *                       this function's scope.
 *   swap                Win32_PageFileUsage (+ Win32_PageFileSetting for the stable maximum)
 *                       through the bounded WMI helper (wmi_bounded.hpp).
 *
 * BOUNDEDNESS (roadmap Principle 14: no unbounded OS call on the daily sync thread).
 *   - The WMI reads ride run_bounded_wmi_query: per-Next wait, whole-enumeration and row cap.
 *   - The registry read is one RegGetValueW against a local hive, size-capped.
 *   - GetSystemFirmwareTable('RSMB') copies a table the kernel already holds; the argument is in
 *     win_rsmb.hpp.
 * No DeviceIoControl is used anywhere here.
 *
 * PRIVILEGE. All four reads were measured readable by an unprivileged account in S-H1 (RSMB, the
 * MachineGuid value, and the Win32_PageFile* classes under a non-admin virtual service account).
 * A refusal on another host is reported `permission_denied`, never as an absent value.
 */
#ifdef _WIN32

#include "hardware_estate_win.hpp"

#include "hardware_estate_emit.hpp"
#include "hardware_estate_parsers.hpp"

#include "hardware_wmi_rows.hpp"

#include <win_reg_handle.hpp>
#include <win_rsmb.hpp>
#include <win_str.hpp>
#include <wmi_bounded.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>
#include <exception>
#include <string>
#include <vector>

// The pure layer carries these Win32 numbers as bare integers (it must stay OS-header-free);
// pin them so a wrong constant fails the Windows build instead of misclassifying a refusal.
static_assert(static_cast<std::uint32_t>(ERROR_FILE_NOT_FOUND) ==
                      yuzu::hardware::estate::kErrFileNotFound &&
                  static_cast<std::uint32_t>(ERROR_PATH_NOT_FOUND) ==
                      yuzu::hardware::estate::kErrPathNotFound &&
                  static_cast<std::uint32_t>(ERROR_ACCESS_DENIED) ==
                      yuzu::hardware::estate::kErrAccessDenied,
              "hardware_estate_parsers.hpp's Win32 error numbers must match winerror.h");

namespace yuzu::hardware::estate {

namespace {

namespace wmi = yuzu::shared::wmi;
using yuzu::hardware::wmi_rows::wmi_row_string;
using yuzu::hardware::wmi_rows::wmi_row_uint64;
namespace rsmb = yuzu::shared::rsmb;

constexpr wchar_t kCryptoKey[] = L"SOFTWARE\\Microsoft\\Cryptography";
constexpr wchar_t kMachineGuidValue[] = L"MachineGuid";
// MachineGuid is a 36-character GUID; anything past this is not one and is refused unread.
constexpr DWORD kMaxMachineGuidBytes = 256 * sizeof(wchar_t);

Report smbios_leg(Kind kind) {
    const rsmb::RsmbRead read = rsmb::read_rsmb_table();
    switch (read.error) {
    case rsmb::ReadError::none:
        break;
    case rsmb::ReadError::call_failed:
        return rsmb_failure_report(RsmbFailure::call_failed, read.win32_error);
    case rsmb::ReadError::oversized:
        return rsmb_failure_report(RsmbFailure::oversized, 0);
    case rsmb::ReadError::size_race:
        return rsmb_failure_report(RsmbFailure::size_race, 0);
    }
    const auto table = yuzu::shared::smbios::parse_rsmb(read.bytes);
    return kind == Kind::chassis ? chassis_report(table) : baseboard_report(table);
}

MachineIdRead read_machine_guid() {
    MachineIdRead out;
    // KEY_WOW64_64KEY: the value lives in the native 64-bit view, and a 32-bit host process would
    // otherwise be redirected away from it. Opened read-only; the handle is closed by RegKey.
    HKEY raw = nullptr;
    LONG rc = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, kCryptoKey, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                              &raw);
    if (rc != ERROR_SUCCESS) {
        out.win32_error = static_cast<std::uint32_t>(rc);
        return out;
    }
    yuzu::win::RegKey key{raw};

    DWORD type = 0;
    DWORD size = 0;
    rc = ::RegQueryValueExW(key.get(), kMachineGuidValue, nullptr, &type, nullptr, &size);
    if (rc != ERROR_SUCCESS) {
        out.win32_error = static_cast<std::uint32_t>(rc);
        return out;
    }
    if (type != REG_SZ || size == 0 || size > kMaxMachineGuidBytes) {
        out.win32_error = ERROR_INVALID_DATA; // not a string, empty, or not GUID-sized
        return out;
    }
    // +1 wchar so the buffer is NUL-terminated even if the stored value is not.
    std::wstring buf(size / sizeof(wchar_t) + 1, L'\0');
    DWORD got = size;
    rc = ::RegQueryValueExW(key.get(), kMachineGuidValue, nullptr, &type,
                            reinterpret_cast<LPBYTE>(buf.data()), &got);
    if (rc != ERROR_SUCCESS) {
        out.win32_error = static_cast<std::uint32_t>(rc);
        return out;
    }
    out.value = yuzu::win::reg_sz_to_utf8(buf.data(), got);
    return out;
}

Report swap_leg() {
    // The usage class IS the section: without it there is nothing to report. The setting class
    // only sharpens the total, so its failure constrains the section instead of failing it.
    auto usage = wmi::run_bounded_wmi_query(
        L"ROOT\\CIMV2", L"SELECT Name, AllocatedBaseSize, CurrentUsage FROM Win32_PageFileUsage");
    if (usage.error)
        return wmi_failure_report("pagefile_usage", *usage.error, usage.rows_before_error);

    std::vector<PageFile> files;
    files.reserve(usage.rows.size());
    for (const auto& row : usage.rows)
        files.push_back({wmi_row_string(row, "Name"), wmi_row_uint64(row, "AllocatedBaseSize"),
                         wmi_row_uint64(row, "CurrentUsage")});

    std::string constraint;
    if (usage.truncated)
        constraint = "wmi:pagefile_usage:row_cap";

    std::vector<PageFileSetting> settings;
    auto setting = wmi::run_bounded_wmi_query(
        L"ROOT\\CIMV2", L"SELECT Name, MaximumSize FROM Win32_PageFileSetting");
    if (setting.error) {
        // A missing class just means no configured maximum; any other fault is a degraded total.
        const Report bad =
            wmi_failure_report("pagefile_setting", *setting.error, setting.rows_before_error);
        if (bad.outcome != Outcome::unavailable && constraint.empty())
            constraint = bad.token;
    } else {
        for (const auto& row : setting.rows)
            settings.push_back({wmi_row_string(row, "Name"), wmi_row_uint64(row, "MaximumSize")});
        // A capped setting list can miss the configured maximum of a page file: the total then
        // falls back to the (drifting) allocation, which must be visible, not silent.
        if (setting.truncated && constraint.empty())
            constraint = "wmi:pagefile_setting:row_cap";
    }
    return swap_report(files, settings, constraint);
}

Report build(Kind kind) {
    switch (kind) {
    case Kind::chassis:
    case Kind::baseboard:
        return smbios_leg(kind);
    case Kind::machine_id:
        return machine_id_report(read_machine_guid());
    case Kind::swap:
        return swap_leg();
    }
    return Report::failure(Outcome::unavailable, "windows:unknown_kind");
}

} // namespace

int run_windows(yuzu::CommandContext& ctx, Kind kind) noexcept {
    try {
        return emit_report(ctx, kind_name(kind), build(kind));
    } catch (...) {
        // Frozen plugin ABI: nothing may propagate. Report it as a degraded read if we still can.
        // If even that cannot be written, rc 1 is the honest answer: it makes the device record
        // store the section as unavailable (`agent:rc=1`), whereas rc 0 with no rows would record a
        // false "ok" section for a read that never happened.
        try {
            return emit_report(ctx, kind_name(kind),
                               Report::failure(Outcome::constrained, "windows:internal_error"));
        } catch (...) {
            return 1;
        }
    }
}

} // namespace yuzu::hardware::estate

#endif // _WIN32
