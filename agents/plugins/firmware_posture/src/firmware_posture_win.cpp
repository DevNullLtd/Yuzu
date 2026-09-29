/**
 * firmware_posture_win.cpp -- Windows leg: Win32_BIOS via WMI + the raw
 * SMBIOS table via GetSystemFirmwareTable('RSMB').
 *
 * Two sources, both rung 1 (in-process, no spawn, no wmic/PowerShell):
 *
 *   wmi     run_bounded_wmi_query(L"root\\CIMV2", "SELECT Manufacturer,
 *           SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS") -- the same
 *           column names hardware_plugin.cpp:316 reads, through the same
 *           bounded helper bitlocker_plugin.cpp:107-109 uses. The first row
 *           goes to wmi_bios_rows (pure).
 *           NOT selected: the BIOSVersion column. It is a string ARRAY
 *           (VT_ARRAY|VT_BSTR) and agents/shared/wmi_bounded.hpp's
 *           variant_to_string returns empty for every non-scalar VARIANT, so
 *           extract_row drops it and it could never reach a row (changing that
 *           shared helper is its own PR). SMBIOSBIOSVersion carries the same
 *           version as a scalar. Consequence: 3 of the 4 columns a spec might
 *           name are reachable, and Windows never emits a `bios_version_list`
 *           row.
 *   smbios  GetSystemFirmwareTable('RSMB', 0, ...) with the documented
 *           two-call size probe (first call returns the required size, the
 *           second fills the buffer). The bytes -- including the 8-byte
 *           RawSMBIOSData header -- go to parse_smbios_type0 (pure,
 *           bounds-checked). This TU never interprets a byte.
 *
 * Failure vs absence: a definitive not-there (WMI class/namespace absent, no
 * RSMB provider) is its own row -- vendor/version/release_date `absent`, via
 * the same pure formatter (wmi_bios_rows / smbios_rows) an empty result maps
 * through -- with NO failure token; a refused call (ERROR_ACCESS_DENIED /
 * WBEM access denied) and any other failure go through FirmwareReport::fail
 * as an `unreadable` row plus a `<source>:<cause>` token (the refusal also
 * sets the denial flag).
 * Every classification (classify_win32_error / classify_hresult /
 * classify_wmi_error_token), the failed-call mappings (apply_wmi_error_token /
 * apply_smbios_call_failed) and row mapping (wmi_bios_rows /
 * parse_smbios_type0 / smbios_rows) is a pure function in the parsers header;
 * this TU performs the calls, records the truncation and size tokens
 * (wmi:row_cap, smbios:oversized, smbios:size_race) and the empty-rowset absent
 * row inline, builds a FirmwareReport and hands it to finish_report.
 *
 * ── Probe record (run-context: symbol + service-identity in the banner) ──
 * the-rig, Windows 11 Pro 10.0.26200 x64, 2026-09-21, run as NT AUTHORITY\SYSTEM (scheduled task,
 * RunLevel Highest; the transcript is in the PR body):
 *   GetSystemFirmwareTable('RSMB', 0, NULL, 0)  -> 3233 (the required size); the second call
 *     copied 3233 bytes, an 8-byte RawSMBIOSData header (SMBIOS 3.3) plus 83 structures.
 *   The plugin as SYSTEM returned OK / FULL with both sources agreeing: vendor "American Megatrends
 *     Inc.", version 3801, release_date 2021-07-30 (WMI and SMBIOS), rom_size_bytes 16777216,
 *     bios_release 5.17 (SMBIOS only).
 *   Not measured: an Administrator (non-SYSTEM) identity, a host with no RSMB provider, and a
 *     machine whose BIOS reports a non-standard release date.
 * The trimmed table is tests/unit/fixtures/wave8/firmware_posture/windows/rsmb.bin (see its
 * .provenance.txt: the other structures carry the system UUID and serials).
 */
#include "firmware_posture_legs.hpp"

#if defined(_WIN32)

#include <wmi_bounded.hpp> // yuzu::shared::wmi bounded WMI query (agents/shared)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wbemidl.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// The pure classifiers carry these numbers as bare integers (they must stay
// OS-header-free); pin every one against the SDK so a wrong constant fails
// the Windows build instead of silently misclassifying a refusal as absence.
static_assert(ERROR_FILE_NOT_FOUND == 2 && ERROR_PATH_NOT_FOUND == 3 && ERROR_ACCESS_DENIED == 5,
              "classify_win32_error's Win32 numbers must match winerror.h");
static_assert(static_cast<std::uint32_t>(WBEM_E_ACCESS_DENIED) == 0x80041003u,
              "classify_hresult: WBEM_E_ACCESS_DENIED");
static_assert(static_cast<std::uint32_t>(E_ACCESSDENIED) == 0x80070005u,
              "classify_hresult: E_ACCESSDENIED");
static_assert(static_cast<std::uint32_t>(WBEM_E_INVALID_NAMESPACE) == 0x8004100Eu,
              "classify_hresult: WBEM_E_INVALID_NAMESPACE");
static_assert(static_cast<std::uint32_t>(WBEM_E_INVALID_CLASS) == 0x80041010u,
              "classify_hresult: WBEM_E_INVALID_CLASS");
static_assert(static_cast<std::uint32_t>(WBEM_E_NOT_FOUND) == 0x80041002u,
              "classify_hresult: WBEM_E_NOT_FOUND");
// classify_wmi_error_token spells wmi_bounded's stage prefixes as literals (it must stay
// OS-header-free); pin them so a renamed prefix fails the Windows build instead of silently
// misclassifying a stage.
static_assert(std::string_view{yuzu::shared::wmi::error_tokens::kWmiConnectFailedPrefix} ==
                      "wmi_connect_failed_" &&
                  std::string_view{yuzu::shared::wmi::error_tokens::kWmiQueryFailedPrefix} ==
                      "wmi_query_failed_" &&
                  std::string_view{yuzu::shared::wmi::error_tokens::kWmiNextFailedPrefix} ==
                      "wmi_next_failed_",
              "classify_wmi_error_token's stage prefixes must match wmi_bounded.hpp's error_tokens");

namespace yuzu::firmware_posture {

namespace {

// 'RSMB' as the little-endian DWORD GetSystemFirmwareTable takes (a
// multi-character literal is implementation-defined, so spell the value).
constexpr DWORD kRsmbProvider = 0x52534D42;

// A real RawSMBIOSData table is tens of KiB; refuse anything an order of
// magnitude past that rather than allocate whatever a broken provider claims.
constexpr std::size_t kMaxSmbiosBytes = 1u << 20; // 1 MiB

// The table can change size between the probe and the fill (rare: a
// hot-plug SMBIOS update). Retry the pair a bounded number of times.
constexpr int kMaxSmbiosAttempts = 3;

// ── wmi ──────────────────────────────────────────────────────────────────

void collect_wmi(FirmwareReport& report) {
    // rung 1: in-process bounded WMI query (Win32_BIOS); no wmic/PowerShell
    // spawn (not a spawn sink).
    auto query = yuzu::shared::wmi::run_bounded_wmi_query(
        L"root\\CIMV2", L"SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS");

    if (query.error.has_value()) {
        // Stage-aware, in the pure layer (apply_wmi_error_token): a missing namespace or class
        // (connect/query stage, or INVALID_CLASS delivered at the first Next, i.e. with no row read
        // before it) is an explicit absent row; any other fault is an unreadable row plus a token;
        // a refusal is denied.
        apply_wmi_error_token(report, *query.error, query.rows_before_error);
        return;
    }
    if (query.truncated)
        report.note_failure("wmi:row_cap");
    // Win32_BIOS is a singleton on every host seen; if a host reports more
    // than one instance the first is authoritative and the rest ignored.
    if (query.rows.empty()) {
        report.add_all(wmi_bios_rows({})); // class present, no instance: a definitive absent row
        return;
    }
    report.add_all(wmi_bios_rows(query.rows.front()));
}

// ── smbios ───────────────────────────────────────────────────────────────

/// A GetSystemFirmwareTable call that returned 0: classify GetLastError().
void smbios_call_failed(FirmwareReport& report, DWORD err) {
    apply_smbios_call_failed(report, static_cast<std::uint32_t>(err)); // pure mapping
}

void collect_smbios(FirmwareReport& report) {
    std::vector<std::uint8_t> table;
    for (int attempt = 0; attempt < kMaxSmbiosAttempts; ++attempt) {
        // rung 1: in-process
        // GetSystemFirmwareTable size probe (buffer NULL, size 0 -> returns
        // the required byte count, or 0 with GetLastError set).
        const UINT need = ::GetSystemFirmwareTable(kRsmbProvider, 0, nullptr, 0);
        if (need == 0) {
            smbios_call_failed(report, ::GetLastError());
            return;
        }
        if (need > kMaxSmbiosBytes) {
            report.fail("vendor", kSrcSmbios, "smbios:oversized");
            return;
        }

        table.assign(need, 0);
        // The fill call returns the bytes written, or the (larger) required
        // size if the table grew since the probe, or 0 on failure.
        const UINT got = ::GetSystemFirmwareTable(kRsmbProvider, 0, table.data(), need);
        if (got == 0) {
            smbios_call_failed(report, ::GetLastError());
            return;
        }
        if (got > need)
            continue; // grew between the two calls: probe again
        table.resize(got);

        const Smbios0Result r = parse_smbios_type0(std::span<const std::uint8_t>{table});
        if (r.constrained)
            report.fail("vendor", kSrcSmbios, r.token); // smbios:truncated|malformed|no_type0
        else
            report.add_all(smbios_rows(r.data));
        return;
    }
    report.fail("vendor", kSrcSmbios, "smbios:size_race");
}

} // namespace

int collect_firmware_win(yuzu::CommandContext& ctx) {
    FirmwareReport report;
    collect_wmi(report);
    collect_smbios(report);
    return finish_report(ctx, report);
}

} // namespace yuzu::firmware_posture

#endif // _WIN32
