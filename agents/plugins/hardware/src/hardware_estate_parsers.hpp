/**
 * hardware_estate_parsers.hpp -- the pure half of the hardware-estate legs (chassis, baseboard,
 * swap, machine_id) and of the appended `processors` / `memory` columns.
 *
 * Everything here is data in, rows and a typed outcome out: no OS call, no I/O. The Windows TU
 * (hardware_estate_win.cpp) does the reads -- RSMB, the registry, bounded WMI -- and hands the
 * results to these functions; tests inject fixtures (tests/unit/test_hardware_estate_parsers.cpp).
 * H.11 (Linux) and H.13 (macOS) add their own readers and reuse the formatters.
 *
 * THE OUTCOME CONTRACT (one place, so every leg agrees):
 *
 *   ok           status|<a>|supported|-            result OK/FULL       data rows follow
 *   constrained  status|<a>|constrained|<token>    result CONSTRAINED   rows that WERE read, if any
 *                                                   (an SMBIOS structure decoded before a framing
 *                                                   fault; swap rows when only the optional setting
 *                                                   query failed). A WMI query that fails ends in no
 *                                                   rows at all: wmi_bounded.hpp clears the partial
 *                                                   rows on its error path.
 *   denied       status|<a>|constrained|<token>    result PERMISSION_DENIED   no rows
 *   unavailable  status|<a>|unsupported|<token>    result UNAVAILABLE   no rows
 *
 * `constrained` is reserved for a read that FAILED or came back partial. A value the firmware
 * reports as OEM filler ("To Be Filled By O.E.M.", an empty string) is not a failed read: the
 * field is written "-" and the section stays `ok`, because "no value was assigned" is a
 * definitive answer and most OEM machines give it for the asset tag. Marking those sections
 * constrained would present most of a fleet as incomplete (the server-side surfaces render a
 * constrained section as incomplete). `-` therefore means ABSENT; a field that could not be read
 * at all is never written as a value.
 *
 * The device-record writer (agents/core/src/sync_source_device_ci.cpp) takes the section level
 * from the typed result, projects rows only for `ok` and `constrained`, and copies the first
 * chassis / baseboard / machine_id row's columns into the record's scalars verbatim.
 */
#pragma once

#include <hmac_sha256.hpp>
#include <inventory_status_row.hpp>
#include <machine_id_hash.hpp>
#include <smbios_parsers.hpp>
#include <wire_utf8.hpp>
#include <wmi_error_token.hpp>

#include <yuzu/string_utils.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::hardware::estate {

// -- the outcome ----------------------------------------------------------------------------

enum class Outcome { ok, constrained, denied, unavailable };

struct Report {
    std::vector<std::string> rows; ///< data rows only; the status row is formatted separately
    Outcome outcome = Outcome::ok;
    std::string token; ///< failure / reason token; empty when outcome == ok

    [[nodiscard]] static Report failure(Outcome o, std::string t) {
        Report r;
        r.outcome = o;
        r.token = std::move(t);
        return r;
    }
};

[[nodiscard]] constexpr yuzu::shared::StatusLevel status_level_of(Outcome o) noexcept {
    switch (o) {
    case Outcome::ok:
        return yuzu::shared::StatusLevel::supported;
    case Outcome::constrained:
    case Outcome::denied:
        return yuzu::shared::StatusLevel::constrained;
    case Outcome::unavailable:
        return yuzu::shared::StatusLevel::unsupported;
    }
    return yuzu::shared::StatusLevel::constrained;
}

/// `status|<action>|<level>|<token or ->`.
[[nodiscard]] inline std::string status_row_for(std::string_view action, const Report& r) {
    return yuzu::shared::format_status_row(action, status_level_of(r.outcome), r.token);
}

// -- field hygiene -------------------------------------------------------------------------

/// Longest identity string a row carries, measured on the SOURCE string before escaping (escaping a
/// '|' or '\\' can roughly double the emitted field). SMBIOS strings are bounded only by the 1 MiB
/// table, and the on-demand response is not clamped the way the daily record is, so cap here. 256
/// bytes is several times any real serial, part number or vendor string.
inline constexpr std::size_t kMaxIdentityBytes = 256;

/// A free-text identity field read from firmware or WMI, ready for a row: right-trimmed, OEM
/// filler (or empty) -> "-", and escaped through safe_output_field. This is the single place a
/// leg turns "the firmware said nothing real" into the absent marker.
[[nodiscard]] inline std::string clean_identity(std::string_view raw_in) {
    // SMBIOS strings are raw firmware bytes, not text: a byte outside well-formed UTF-8 would make
    // the receiver reject the whole CommandResponse (wire_utf8.hpp), so offending bytes become '?'
    // BEFORE anything else looks at the string. (WMI strings are already UTF-8 from the wide
    // conversion; scrubbing them is a no-op.)
    std::string scrubbed{raw_in};
    yuzu::shared::scrub_wire_bytes(scrubbed);
    if (scrubbed.size() > kMaxIdentityBytes) {
        // Cut on a UTF-8 scalar boundary: the string is well-formed after the scrub, so back up over
        // continuation bytes (10xxxxxx) to the lead byte of the scalar the cut would split.
        std::size_t cut = kMaxIdentityBytes;
        while (cut > 0 && (static_cast<unsigned char>(scrubbed[cut]) & 0xC0u) == 0x80u)
            --cut;
        scrubbed.resize(cut);
    }
    std::string_view raw{scrubbed};
    // is_placeholder / rtrim are right-trim only (the walker's contract); a leg also drops leading
    // blanks so padded filler ("  Default string") is still filler and a real value never starts
    // with a space.
    while (!raw.empty() && (raw.front() == ' ' || raw.front() == '\t'))
        raw.remove_prefix(1);
    if (yuzu::shared::smbios::is_placeholder(raw))
        return "-";
    // A string that was ONLY bytes the scrub had to replace (a 0xFF-filled serial) is now "????": the
    // same pseudo-value on every such device. It is garbage, not data.
    if (!raw.empty() && std::ranges::all_of(raw, [](char c) { return c == '?'; }))
        return "-";
    return yuzu::util::safe_output_field(yuzu::shared::smbios::rtrim(raw));
}

/// As above for a string the SMBIOS walker may not have found at all (nullopt -> "-").
[[nodiscard]] inline std::string clean_identity_opt(const std::optional<std::string>& raw) {
    return raw ? clean_identity(std::string_view{*raw}) : std::string{"-"};
}

inline constexpr std::string_view kSourceSmbios = "smbios";
inline constexpr std::string_view kSourceRegistry = "registry";
inline constexpr std::string_view kSourceWmi = "wmi";

// -- SMBIOS-backed legs (chassis, baseboard) ------------------------------------------------

/// Why the RSMB read itself failed, independent of the Win32 header (so this stays portable).
enum class RsmbFailure { call_failed, oversized, size_race };

/// Win32 numbers the Windows TU static_asserts against winerror.h.
inline constexpr std::uint32_t kErrFileNotFound = 2;
inline constexpr std::uint32_t kErrPathNotFound = 3;
inline constexpr std::uint32_t kErrAccessDenied = 5;

/// A failed GetSystemFirmwareTable becomes a Report with NO rows. A missing provider (2/3) is
/// `unavailable` with no pretence of a value; a refusal (5) is `denied`; every other fault, an
/// oversized table and a size race are `constrained`.
[[nodiscard]] inline Report rsmb_failure_report(RsmbFailure f, std::uint32_t win32_error) {
    switch (f) {
    case RsmbFailure::oversized:
        return Report::failure(Outcome::constrained, "smbios:oversized");
    case RsmbFailure::size_race:
        return Report::failure(Outcome::constrained, "smbios:size_race");
    case RsmbFailure::call_failed:
        break;
    }
    if (win32_error == kErrFileNotFound || win32_error == kErrPathNotFound)
        return Report::failure(Outcome::unavailable, "smbios:absent");
    if (win32_error == kErrAccessDenied)
        return Report::failure(Outcome::denied, "smbios:win32_" + std::to_string(win32_error));
    return Report::failure(Outcome::constrained, "smbios:win32_" + std::to_string(win32_error));
}

namespace detail {

[[nodiscard]] inline std::string_view table_error_token(yuzu::shared::smbios::Error e) noexcept {
    return e == yuzu::shared::smbios::Error::truncated ? "smbios:truncated" : "smbios:malformed";
}

/// The shared "this structure type was not decoded" mapping. `malformed` names the structure;
/// `absent` after a walk that stopped on a framing fault is that fault; `absent` after a clean
/// walk is a table that simply has no such structure.
template <class T>
[[nodiscard]] std::optional<Report> undecoded(const yuzu::shared::smbios::SmbiosTable& table,
                                              const yuzu::shared::smbios::Entry<T>& e,
                                              std::string_view malformed_token) {
    using yuzu::shared::smbios::Status;
    if (e.status == Status::ok)
        return std::nullopt;
    if (e.status == Status::malformed)
        return Report::failure(Outcome::constrained, std::string{malformed_token});
    if (table.error)
        return Report::failure(Outcome::constrained, std::string{table_error_token(*table.error)});
    // A clean walk with no such structure: a definitive absence, reported as a state (one row of
    // absent markers), never as a failure.
    return Report{};
}

/// The walker's failure model (smbios_parsers.hpp): `error` set means the walk STOPPED -- every entry
/// decoded before the fault is valid, but the table was not fully read, and a consumer MUST surface
/// a constraint token and never present the result as complete. A structure that decoded before the
/// fault keeps its row; the section is constrained, not ok.
inline void note_walk_fault(const yuzu::shared::smbios::SmbiosTable& table, Report& r) {
    if (!table.error)
        return;
    r.outcome = Outcome::constrained;
    r.token = std::string{table_error_token(*table.error)};
}

} // namespace detail

/// chassis|<type>|<serial>|<asset_tag>|<source>
[[nodiscard]] inline Report chassis_report(const yuzu::shared::smbios::SmbiosTable& table) {
    using namespace yuzu::shared::smbios;
    if (auto bad = detail::undecoded(table, table.chassis, "smbios:chassis_malformed")) {
        if (bad->outcome == Outcome::ok)
            bad->rows.push_back("chassis|-|-|-|-"); // no type-3 structure: absent markers
        return *bad;
    }
    const Type3& c = table.chassis.data;
    const auto name = chassis_type_name(c.chassis_type);
    Report r;
    r.rows.push_back("chassis|" + (name ? yuzu::util::safe_output_field(*name) : std::string{"-"}) +
                     "|" + clean_identity_opt(c.serial) + "|" + clean_identity_opt(c.asset_tag) + "|" +
                     std::string{kSourceSmbios});
    detail::note_walk_fault(table, r);
    return r;
}

/// baseboard|<vendor>|<product>|<serial>|<source>
[[nodiscard]] inline Report baseboard_report(const yuzu::shared::smbios::SmbiosTable& table) {
    using namespace yuzu::shared::smbios;
    if (auto bad = detail::undecoded(table, table.baseboard, "smbios:baseboard_malformed")) {
        if (bad->outcome == Outcome::ok)
            bad->rows.push_back("baseboard|-|-|-|-");
        return *bad;
    }
    const Type2& b = table.baseboard.data;
    Report r;
    r.rows.push_back("baseboard|" + clean_identity_opt(b.manufacturer) + "|" +
                     clean_identity_opt(b.product) + "|" + clean_identity_opt(b.serial) + "|" +
                     std::string{kSourceSmbios});
    detail::note_walk_fault(table, r);
    return r;
}

// -- machine_id -----------------------------------------------------------------------------

/// What a registry read of the machine identifier gave: a value, or a Win32 error.
struct MachineIdRead {
    std::optional<std::string> value; ///< the raw id; set only when the read succeeded
    std::uint32_t win32_error = 0;    ///< meaningful when `value` is empty
};

/// machine_id|<hash_hex>|<algorithm>|<source>. The raw id is hashed here and goes no further.
[[nodiscard]] inline Report machine_id_report(const MachineIdRead& read) {
    if (!read.value) {
        const std::uint32_t e = read.win32_error;
        const std::string tok = "windows:machine_guid:";
        if (e == kErrFileNotFound || e == kErrPathNotFound)
            return Report::failure(Outcome::unavailable, tok + "absent");
        if (e == kErrAccessDenied)
            return Report::failure(Outcome::denied, tok + "win32_" + std::to_string(e));
        return Report::failure(Outcome::constrained, tok + "win32_" + std::to_string(e));
    }
    const std::string norm = yuzu::shared::normalise_machine_id(*read.value);
    // The nil GUID (WinPE, a broken sysprep) is the same string on every such device: hashing it would
    // give them all one "identity". It is not an identifier, so report it as such.
    if (!norm.empty() && std::ranges::all_of(norm, [](char c) { return c == '0' || c == '-'; }))
        return Report::failure(Outcome::unavailable, "windows:machine_guid:nil");
    const auto h = yuzu::shared::hash_machine_id(*read.value);
    if (!h)
        return Report::failure(Outcome::unavailable, "windows:machine_guid:empty");
    Report r;
    r.rows.push_back("machine_id|" + *h + "|" + std::string{yuzu::shared::kMachineIdHashAlgorithm} +
                     "|" + std::string{kSourceRegistry});
    return r;
}

// -- swap -----------------------------------------------------------------------------------

/// One page file as WMI reports it. Sizes are megabytes, as the classes report them.
struct PageFile {
    std::string name;                  ///< Win32_PageFileUsage.Name (e.g. C:\pagefile.sys)
    std::uint64_t allocated_mb = 0;    ///< AllocatedBaseSize: what is allocated NOW
    std::uint64_t current_usage_mb = 0; ///< CurrentUsage: live, on-demand only
};

/// A configured maximum from Win32_PageFileSetting, keyed by the same Name.
struct PageFileSetting {
    std::string name;
    std::uint64_t maximum_mb = 0; ///< 0 = system managed (no fixed maximum)
};

/// The size the daily record should carry. A system-managed page file GROWS under memory
/// pressure, so AllocatedBaseSize moves between cycles on an otherwise unchanged host and would
/// make every report a full upload (roadmap Principle 13). A configured MaximumSize is stable, so
/// it wins when it is set; otherwise the allocation is used and that residual drift is documented
/// in the plugin README (it cannot be removed without inventing a number).
[[nodiscard]] inline std::uint64_t stable_swap_total_mb(const PageFile& pf,
                                                         const std::vector<PageFileSetting>& settings) {
    auto lower = [](std::string s) {
        for (char& c : s)
            if (c >= 'A' && c <= 'Z')
                c = static_cast<char>(c - 'A' + 'a');
        return s;
    };
    const std::string key = lower(pf.name);
    for (const auto& s : settings)
        if (lower(s.name) == key && s.maximum_mb > 0)
            return s.maximum_mb;
    return pf.allocated_mb;
}

/// swap|<device>|<total_mb>|<used_mb>|<source>. `used_mb` is live telemetry: it is in this
/// on-demand row, and the device-record writer drops it from the daily record. No page file at
/// all is a definitive answer (ok, zero rows), not a failure. `setting_token` is a failure token
/// from the optional Win32_PageFileSetting query ("" when it was fine); it constrains the section
/// because the total may then be the allocation rather than the configured maximum.
[[nodiscard]] inline Report swap_report(const std::vector<PageFile>& files,
                                        const std::vector<PageFileSetting>& settings,
                                        std::string_view setting_token = {}) {
    Report r;
    for (const auto& pf : files) {
        r.rows.push_back("swap|" + yuzu::util::safe_output_field(pf.name) + "|" +
                         std::to_string(stable_swap_total_mb(pf, settings)) + "|" +
                         std::to_string(pf.current_usage_mb) + "|" + std::string{kSourceWmi});
    }
    if (!setting_token.empty()) {
        r.outcome = Outcome::constrained;
        r.token = std::string{setting_token};
    }
    return r;
}

/// A WMI query that produced no usable result set, mapped through the shared stage-aware
/// classifier. A class that does not exist is `unavailable`; a refusal is `denied`; any other
/// fault is `constrained`. The token is prefixed so the cause names the class.
[[nodiscard]] inline Report wmi_failure_report(std::string_view class_token, std::string_view error,
                                               std::size_t rows_before_error) {
    using yuzu::shared::wmi_token::WmiReadOutcome;
    const auto o = yuzu::shared::wmi_token::classify_wmi_error_token(error, rows_before_error);
    std::string tok = "wmi:" + std::string{class_token} + ":";
    switch (o) {
    case WmiReadOutcome::absent:
        return Report::failure(Outcome::unavailable, tok + "absent");
    case WmiReadOutcome::denied:
        return Report::failure(Outcome::denied, tok + std::string{error});
    case WmiReadOutcome::ok:
    case WmiReadOutcome::failed:
        break;
    }
    return Report::failure(Outcome::constrained, tok + std::string{error});
}

// -- appended processors / memory columns ----------------------------------------------------

/// Win32_Processor.Architecture values for the two x86 families whose ProcessorId is CPUID data.
inline constexpr std::uint32_t kArchX86 = 0;
inline constexpr std::uint32_t kArchX64 = 9;

/// `socket_designation` column: the firmware's label ("U3E1", "CPU 1"), or "-".
[[nodiscard]] inline std::string socket_designation_field(std::string_view raw) {
    return clean_identity(raw);
}

/// `stepping` column. On x86/x64 the stepping is the low nibble of CPUID leaf 1 EAX, which is the
/// last 8 hex digits of Win32_Processor.ProcessorId ("BFEBFBFF000906EA" -> EAX 0x000906EA ->
/// stepping 10). Anywhere else (arm64, an unknown architecture, an unparsable id) the class's own
/// Stepping string is used when it is a plain decimal number, else "-". Decimal, no padding.
[[nodiscard]] inline std::string stepping_field(std::string_view processor_id,
                                                std::optional<std::uint32_t> architecture,
                                                std::string_view stepping_property) {
    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    // An ABSENT architecture is not x86: it must not default to 0 (kArchX86) and read a CPUID nibble
    // out of an id that may belong to another instruction set.
    if (architecture && (*architecture == kArchX86 || *architecture == kArchX64) &&
        processor_id.size() == 16) {
        const int nib = hex_val(processor_id.back());
        const bool all_hex = std::ranges::all_of(processor_id, [&](char c) { return hex_val(c) >= 0; });
        if (all_hex && nib >= 0)
            return std::to_string(nib);
    }
    std::string_view s = stepping_property;
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    if (!s.empty() && s.size() <= 4 &&
        std::ranges::all_of(s, [](char c) { return c >= '0' && c <= '9'; }))
        return std::string{s};
    return "-";
}

/// `manufacturer` / `part_number` / `serial` DIMM columns: the module's own strings, OEM filler
/// and empty -> "-". Part numbers are padded with spaces on real modules; clean_identity trims.
[[nodiscard]] inline std::string dimm_identity_field(std::string_view raw) {
    return clean_identity(raw);
}

// -- swap: which constraint token the section carries -------------------------------------------

/// The one constraint token a swap section reports, by precedence: the usage query's row cap, then a
/// FAILED setting query (a missing setting class is no failure: it means no configured maximum),
/// then a capped setting list (reported only when the query itself did not fail). Empty = none.
/// Pure so the precedence is tested on every host; the Windows TU only gathers the three facts.
[[nodiscard]] inline std::string swap_constraint_token(bool usage_truncated,
                                                       const std::optional<Report>& setting_failure,
                                                       bool setting_truncated) {
    if (usage_truncated)
        return "wmi:pagefile_usage:row_cap";
    if (setting_failure)
        return setting_failure->outcome == Outcome::unavailable ? std::string{}
                                                                : setting_failure->token;
    if (setting_truncated)
        return "wmi:pagefile_setting:row_cap";
    return {};
}

// -- Windows cpu / dimm row formatters --------------------------------------------------------------

/// `cpu|idx|name|cores|threads|clock_mhz|socket_designation|stepping`. `name` is WMI text and is
/// escaped here (a '|' in it would shift every later column, a newline would forge a row);
/// `socket` and `stepping` arrive already cleaned by socket_designation_field / stepping_field.
[[nodiscard]] inline std::string format_cpu_row(int idx, std::string_view name, std::uint32_t cores,
                                                std::uint32_t threads, std::uint32_t clock_mhz,
                                                std::string_view socket, std::string_view stepping) {
    std::string r = "cpu|" + std::to_string(idx) + "|" + yuzu::util::safe_output_field(name) + "|" +
                    std::to_string(cores) + "|" + std::to_string(threads) + "|" +
                    std::to_string(clock_mhz) + "|";
    r += socket;
    r += '|';
    r += stepping;
    return r;
}

/// `dimm|slot|size_mb|type|speed_mhz|manufacturer|part_number|serial`. `slot` (DeviceLocator) is WMI
/// text and is escaped here; the three identity columns arrive already cleaned by
/// dimm_identity_field; `type` is a fixed enum string.
[[nodiscard]] inline std::string format_dimm_row(std::string_view slot, std::uint64_t size_mb,
                                                 std::string_view type, std::uint32_t speed_mhz,
                                                 std::string_view manufacturer,
                                                 std::string_view part_number, std::string_view serial) {
    std::string r = "dimm|" + yuzu::util::safe_output_field(slot) + "|" + std::to_string(size_mb) + "|";
    r += type;
    r += '|' + std::to_string(speed_mhz) + '|';
    r += manufacturer;
    r += '|';
    r += part_number;
    r += '|';
    r += serial;
    return r;
}

} // namespace yuzu::hardware::estate
