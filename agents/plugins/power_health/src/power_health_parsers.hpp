#pragma once

/**
 * power_health_parsers.hpp — pure parse/interpretation helpers for the
 * power_health plugin (battery, thermal, and power-plan legs across all
 * three OSes).
 *
 * Header-only and OS-free (firewall_parsers.hpp precedent) so every
 * classification decision is unit-tested on every host
 * (test_power_health_parsers.cpp); the real syscalls (GetSystemPowerStatus/
 * CallNtPowerInformation/PowrProf/Pdh on Windows, IOPSCopyPowerSourcesInfo/
 * NSProcessInfo/IOPMGetThermalWarningLevel on macOS via power_health_macos
 * .mm, /sys/class/power_supply and /sys/class/thermal on Linux) live in the
 * impure shell (power_health_plugin.cpp / power_health_macos.mm) and hand
 * their raw results to these functions through a plain-struct injected
 * boundary — never a live OS handle or CF/NS type crosses into this header.
 *
 * Honest-status invariant, same as firewall_parsers.hpp: an unreadable,
 * absent, or unrecognised reading parses to an explicit "unknown"/-1
 * sentinel — never a fabricated value and never a silently-empty result
 * mistaken for a healthy one. A genuinely absent capability (no battery, no
 * thermal zone instances) is reported as an EXPLICIT SUCCESS with a named
 * reason, not as an error.
 */

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field — zone names are firmware-supplied

namespace yuzu::power_health {

// ─────────────────────────────────────────────────────────── battery ──────

/// Schema per the spec: one line per source with present, state, percent
/// (-1 = unknown), time_to_empty_min (-1 = unknown), cycle_count
/// (-1 = unknown), health_percent (-1 = unknown). No mechanism this plugin
/// uses (GetSystemPowerStatus/CallNtPowerInformation SystemBatteryState,
/// IOPSCopyPowerSourcesInfo, or Linux sysfs) can honestly supply
/// cycle_count/health_percent on every OS, so those two fields are -1
/// wherever the underlying leg has no real source for them — never derived
/// from a proxy value.
/// `not_charging` is a REPORTED state, not a failure to read one.
///
/// A present battery sitting on AC, neither charging nor discharging and not at
/// 100%, is the ordinary state of a plugged-in laptop — Windows and macOS both
/// defer charging at a firmware stop threshold (commonly 80-95%) to preserve
/// cell life. Every one of those facts came from the OS. Reporting it as
/// `unknown`, the sentinel this enum reserves for "the OS told us nothing",
/// makes the modal state of a docked fleet indistinguishable from a broken
/// read — verified on real hardware (an HP ZBook Firefly reported
/// `battery|1|unknown|99|-1|-1|-1`, PR #4009 review).
///
/// So `unknown` must stay narrow: it means the read failed or the OS declined
/// to answer. Anything the OS did tell us gets a state of its own.
enum class BatteryState { charging, discharging, full, not_charging, ac_no_battery, unknown };

[[nodiscard]] constexpr std::string_view to_string(BatteryState s) {
    switch (s) {
    case BatteryState::charging:
        return "charging";
    case BatteryState::discharging:
        return "discharging";
    case BatteryState::full:
        return "full";
    case BatteryState::not_charging:
        return "not_charging";
    case BatteryState::ac_no_battery:
        return "ac_no_battery";
    case BatteryState::unknown:
        return "unknown";
    }
    return "unknown"; // unreachable — cases are exhaustive so -Wswitch flags enum drift
}

struct BatteryRow {
    bool present{false};
    BatteryState state{BatteryState::unknown};
    int percent{-1};
    int time_to_empty_min{-1};
    int cycle_count{-1};
    int health_percent{-1};
};

[[nodiscard]] inline std::string format_battery_row(const BatteryRow& r) {
    char buf[160];
    std::snprintf(buf, sizeof buf, "battery|%d|%s|%d|%d|%d|%d", r.present ? 1 : 0,
                  std::string(to_string(r.state)).c_str(), r.percent, r.time_to_empty_min,
                  r.cycle_count, r.health_percent);
    return buf;
}

// ── Windows: GetSystemPowerStatus + CallNtPowerInformation(SystemBatteryState) ──
//
// Plain-struct injected view of the two Win32 outputs — never the real
// SYSTEM_POWER_STATUS/SYSTEM_BATTERY_STATE types, so this stays testable
// without <windows.h>. BatteryFlag == 128 is the measured (the-rig,
// 2026-09-04) honest "no system battery" result: ACLineStatus=1,
// BatteryFlag=128, BatteryLifePercent=255, BatteryLifeTime=-1. The
// battery-PRESENT branch below is driven purely through this struct, and that
// injected boundary is what kept it testable — but fixtures only prove the
// mapping you thought to write. A real HP ZBook Firefly run (PR #4009 review)
// found the AC-resting case classified as `unknown`, a state no fixture
// covered; it is `not_charging` now, with its own fixture on each branch.
struct WindowsBatteryRaw {
    uint8_t ac_line_status{0};      // 0 offline, 1 online, 255 unknown
    uint8_t battery_flag{255};      // 128 = no system battery; 255 = unknown
    uint8_t battery_life_percent{255}; // 0-100; 255 = unknown
    int32_t battery_life_time{-1};  // seconds; -1 = unknown
    bool nt_info_valid{false};      // whether CallNtPowerInformation succeeded
    bool nt_battery_present{false};
    bool nt_charging{false};
    bool nt_discharging{false};
};

[[nodiscard]] inline BatteryRow classify_windows_battery(const WindowsBatteryRaw& raw) {
    BatteryRow row;

    // BatteryFlag == 255 is the SYSTEM_POWER_STATUS contract's own "Unknown
    // status — unable to read the battery flag information," NOT a
    // battery-absence signal — but it also satisfies the 0x80 no-battery
    // bitmask below, so it must be special-cased BEFORE that check runs
    // (PH-009: the bitmask alone would otherwise report a genuinely
    // unknown-status host as confidently no-battery). CallNtPowerInformation
    // corroboration, when valid, still wins over an unknown sps flag either
    // way, so this only fires when NT info is itself unavailable.
    if (raw.battery_flag == 0xFF && !raw.nt_info_valid) {
        row.present = true; // never claim confirmed absence from an
                             // explicitly-"can't tell" flag
        row.state = BatteryState::unknown;
        return row; // percent/time/cycle/health all stay -1 — honest, not fabricated
    }

    // BatteryFlag bit 128 is the authoritative "no system battery" signal —
    // measured live on the-rig (a desktop with no battery hardware at all).
    // Never inferred from a zero/255 percent alone, since 255 also means
    // merely "unknown" on a machine that DOES have a battery. `!= 0xFF`
    // excludes the already-handled unknown-flag case above from this
    // bitmask test.
    const bool no_battery = raw.battery_flag != 0xFF && (raw.battery_flag & 0x80) != 0;
    if (no_battery || (raw.nt_info_valid && !raw.nt_battery_present)) {
        row.present = false;
        row.state = BatteryState::ac_no_battery;
        return row; // percent/time/cycle/health all stay -1 — honest, not fabricated
    }

    row.present = true;

    // ACLineStatus: 0 = offline, 1 = online, 255 = unknown. Only an explicit 1
    // licenses `not_charging` — 255 means the OS declined to say whether we are
    // on AC, and a battery that is neither charging nor discharging with no
    // known power source genuinely is `unknown`.
    const bool on_ac = raw.ac_line_status == 1;

    if (raw.nt_info_valid) {
        if (raw.nt_charging)
            row.state = BatteryState::charging;
        else if (raw.nt_discharging)
            row.state = BatteryState::discharging;
        else if (raw.battery_life_percent == 100)
            row.state = BatteryState::full;
        else if (on_ac)
            // Present, on AC, neither charging nor discharging, below 100%:
            // the firmware is holding at a charge stop threshold. This is the
            // MODAL state of a docked laptop, not a corner case, and it was
            // reported as `unknown` until PR #4009's review caught it on real
            // hardware (`battery|1|unknown|99|-1|-1|-1`).
            row.state = BatteryState::not_charging;
        else
            row.state = BatteryState::unknown;
    } else {
        // Fall back to the legacy BatteryFlag bits: 0x08 = charging.
        if (raw.battery_flag & 0x08)
            row.state = BatteryState::charging;
        else if (raw.battery_life_percent == 100 && on_ac)
            row.state = BatteryState::full;
        else if (raw.ac_line_status == 0)
            row.state = BatteryState::discharging;
        else if (on_ac)
            row.state = BatteryState::not_charging; // same resting case, legacy path
        else
            row.state = BatteryState::unknown; // ACLineStatus 255 — no power source known
    }

    row.percent = raw.battery_life_percent <= 100 ? static_cast<int>(raw.battery_life_percent) : -1;
    row.time_to_empty_min = raw.battery_life_time >= 0 ? raw.battery_life_time / 60 : -1;
    // cycle_count/health_percent: neither GetSystemPowerStatus nor
    // CallNtPowerInformation(SystemBatteryState) exposes a design-capacity
    // baseline or a cycle counter — BATTERY_QUERY_INFORMATION IOCTL would,
    // but that is a different acquisition and out of this package's scope.
    // Left at -1 (undeclared) rather than approximated from MaxCapacity
    // alone, which is a current-not-design figure and would misrepresent
    // health.
    return row;
}

// ── macOS: IOPSCopyPowerSourcesInfo/IOPSCopyPowerSourcesList ───────────────
//
// Plain-struct view of ONE power source's IOPS dictionary — never a raw
// CFDictionaryRef. power_health_macos.mm reads the real dictionary via
// IOPSGetPowerSourceDescription and fills this struct; interpret_iops_source
// does the honest classification. Deliberately never reads the
// AppleSmartBattery IORegistry node (spec ruling) — every field below comes
// from the public IOPSKeys.h vocabulary.
struct IopsSourceView {
    bool present{false};        // kIOPSIsPresentKey
    bool is_charging{false};    // kIOPSIsChargingKey
    bool is_ac_power{false};    // kIOPSPowerSourceStateKey == kIOPSACPowerValue
    int current_capacity{-1};   // kIOPSCurrentCapacityKey
    int max_capacity{-1};       // kIOPSMaxCapacityKey
    int time_to_empty_min{-1};  // kIOPSTimeToEmptyKey; -1 == kIOPSTimeRemainingUnknown
};

[[nodiscard]] inline BatteryRow interpret_iops_source(const IopsSourceView& v) {
    BatteryRow row;
    row.present = v.present;
    if (!v.present) {
        row.state = BatteryState::ac_no_battery;
        return row;
    }

    if (v.current_capacity >= 0 && v.max_capacity > 0) {
        row.percent = static_cast<int>(
            (static_cast<long long>(v.current_capacity) * 100) / v.max_capacity);
        row.percent = std::clamp(row.percent, 0, 100);
    }

    if (v.is_charging)
        row.state = BatteryState::charging;
    else if (row.percent == 100 && v.is_ac_power)
        row.state = BatteryState::full;
    else if (!v.is_ac_power)
        row.state = BatteryState::discharging;
    else
        // On AC, present, not charging, not at 100% — the same firmware
        // charge-hold Windows shows, and macOS's own "Battery Not Charging".
        // IOPS answered all three questions, so this is never `unknown`; that
        // sentinel is reserved for a read that told us nothing, and no branch
        // here qualifies.
        row.state = BatteryState::not_charging;

    row.time_to_empty_min = v.time_to_empty_min >= 0 ? v.time_to_empty_min : -1;
    // cycle_count/health_percent: IOPSKeys.h has no public key for either
    // (kIOPSBatteryHealthKey is a coarse Good/Fair/Poor string, not a
    // percentage, and is deprecated) — left -1 rather than mapping a coarse
    // enum onto a number that looks more precise than it is.
    return row;
}

// ── Linux: /sys/class/power_supply/<name>/uevent ───────────────────────────
//
// Parses the raw `KEY=VALUE` line format one supply directory's `uevent`
// file emits. Returns nullopt for a non-battery supply (POWER_SUPPLY_TYPE
// other than "Battery") so the caller can still notice an AC-only host.
[[nodiscard]] inline std::optional<BatteryRow>
parse_linux_power_supply_uevent(std::string_view uevent) {
    auto find_value = [&](std::string_view key) -> std::optional<std::string_view> {
        std::size_t pos = 0;
        while (pos < uevent.size()) {
            const auto eol = uevent.find('\n', pos);
            const auto line = uevent.substr(pos, eol == std::string_view::npos
                                                       ? std::string_view::npos
                                                       : eol - pos);
            const auto eq = line.find('=');
            if (eq != std::string_view::npos && line.substr(0, eq) == key)
                return line.substr(eq + 1);
            if (eol == std::string_view::npos)
                break;
            pos = eol + 1;
        }
        return std::nullopt;
    };

    const auto type = find_value("POWER_SUPPLY_TYPE");
    if (!type || *type != "Battery")
        return std::nullopt;

    BatteryRow row;
    row.present = find_value("POWER_SUPPLY_PRESENT").value_or("1") != "0";
    if (!row.present) {
        row.state = BatteryState::ac_no_battery;
        return row;
    }

    // The kernel's POWER_SUPPLY_STATUS is a CLOSED set of five values
    // (power_supply.h): Unknown, Charging, Discharging, Not charging, Full.
    // All five are handled, and "Not charging" is one of them — dropping it
    // into `unknown` is the same information loss the Windows and macOS legs
    // carried until PR #4009's review found it on real hardware. Linux states
    // it outright rather than leaving it to be inferred from two booleans, so
    // there is nothing to classify: the kernel already answered.
    const auto status = find_value("POWER_SUPPLY_STATUS").value_or("");
    if (status == "Charging")
        row.state = BatteryState::charging;
    else if (status == "Discharging")
        row.state = BatteryState::discharging;
    else if (status == "Full")
        row.state = BatteryState::full;
    else if (status == "Not charging")
        row.state = BatteryState::not_charging;
    else
        // "Unknown", an absent key, or a value outside the documented set —
        // the only cases where the kernel genuinely has not told us.
        row.state = BatteryState::unknown;

    auto to_int = [](std::string_view s) -> std::optional<int> {
        if (s.empty())
            return std::nullopt;
        int v = 0;
        auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
        // Require the WHOLE field to parse as the integer — from_chars on
        // its own accepts a leading-numeric prefix ("71junk" -> 71), which
        // would silently accept a malformed/truncated sysfs value as a
        // real reading (PH-016).
        if (ec != std::errc{} || ptr != s.data() + s.size())
            return std::nullopt;
        return v;
    };

    if (auto cap = find_value("POWER_SUPPLY_CAPACITY"))
        row.percent = to_int(*cap).value_or(-1);
    if (auto cyc = find_value("POWER_SUPPLY_CYCLE_COUNT"))
        row.cycle_count = to_int(*cyc).value_or(-1);
    // Health = current full-charge capacity / design capacity — only
    // honestly derivable when the driver exposes BOTH keys.
    if (auto full = find_value("POWER_SUPPLY_CHARGE_FULL")) {
        if (auto design = find_value("POWER_SUPPLY_CHARGE_FULL_DESIGN")) {
            auto f = to_int(*full);
            auto d = to_int(*design);
            if (f && d && *d > 0)
                row.health_percent = std::clamp(static_cast<int>(
                    (static_cast<long long>(*f) * 100) / *d), 0, 100);
        }
    }
    if (auto tte = find_value("POWER_SUPPLY_TIME_TO_EMPTY_NOW"))
        row.time_to_empty_min = to_int(*tte).transform([](int secs) { return secs / 60; }).value_or(-1);

    return row;
}

// ──────────────────────────────────────────────────────────── thermal ─────

struct ThermalReport {
    std::string status;                             // "ok" | "constrained" | "unavailable"
    std::string detail;                              // explanatory token; "" when status == "ok"
    std::vector<std::pair<std::string, double>> zones; // (zone name, celsius) — status == "ok" only
};

[[nodiscard]] inline std::string format_thermal_line(const ThermalReport& r) {
    if (r.zones.empty())
        return "thermal|" + r.status + "|" + (r.detail.empty() ? std::string("-") : r.detail);
    std::string out;
    for (const auto& [name, celsius] : r.zones) {
        if (!out.empty())
            out += '\n';
        char buf[16];
        std::snprintf(buf, sizeof buf, "%.1f", celsius);
        // Zone names come from firmware, so they are untrusted with respect to
        // the pipe-delimited grammar: an embedded '|' would forge a column.
        out += "thermal|ok|" + yuzu::util::safe_output_field(name) + "|" + buf;
    }
    return out;
}

// ── Windows: PDH `\Thermal Zone Information(*)\Temperature` ────────────────
//
// Zero instances is the MEASURED NORMAL CASE on desktop hardware (the-rig,
// 2026-09-04: counter set registered, 0 live instances) — an explicit
// success, never an error and never a fabricated zero-degree reading.
struct PdhThermalSample {
    std::string instance;
    // \Thermal Zone Information\Temperature reports degrees KELVIN directly
    // (PDH_FMT_DOUBLE on this counter is NOT tenths of a degree — verified
    // against Microsoft's thermal performance-counter documentation; PH-003
    // caught an earlier tenths-of-Kelvin assumption that turned a normal
    // ~310 K reading into an impossible sub-zero Celsius value).
    double kelvin{0};
};

[[nodiscard]] inline ThermalReport
interpret_windows_pdh_thermal(std::span<const PdhThermalSample> samples, bool query_opened_ok) {
    ThermalReport r;
    if (!query_opened_ok) {
        r.status = "unavailable";
        r.detail = "pdh_query_failed";
        return r;
    }
    if (samples.empty()) {
        r.status = "constrained";
        r.detail = "no_thermal_zones_exposed";
        return r;
    }
    r.status = "ok";
    for (const auto& s : samples)
        r.zones.emplace_back(s.instance, s.kelvin - 273.15);
    return r;
}

// ── macOS: NSProcessInfo.thermalState + IOPMGetThermalWarningLevel ─────────
//
// thermalState is the 4-level enum (NEVER degrees) that drives the reported
// state; IOPMGetThermalWarningLevel is a supplementary signal whose
// kIOReturnNotFound return (measured: `pmset -g therm` → "No thermal
// warning level has been recorded" on an idle host, 2026-09-04) maps to
// Normal/no-note, never an error.
enum class MacThermalLevel { nominal, fair, serious, critical, unknown };

[[nodiscard]] constexpr std::string_view to_string(MacThermalLevel l) {
    switch (l) {
    case MacThermalLevel::nominal:
        return "nominal";
    case MacThermalLevel::fair:
        return "fair";
    case MacThermalLevel::serious:
        return "serious";
    case MacThermalLevel::critical:
        return "critical";
    case MacThermalLevel::unknown:
        return "unknown";
    }
    return "unknown";
}

[[nodiscard]] constexpr MacThermalLevel classify_ns_thermal_state(long raw) {
    switch (raw) {
    case 0:
        return MacThermalLevel::nominal;
    case 1:
        return MacThermalLevel::fair;
    case 2:
        return MacThermalLevel::serious;
    case 3:
        return MacThermalLevel::critical;
    default:
        return MacThermalLevel::unknown; // a future SDK level this build predates
    }
}

[[nodiscard]] inline ThermalReport
interpret_macos_thermal(long ns_thermal_state, bool iopm_found, int32_t iopm_warning_level) {
    ThermalReport r;
    r.status = "ok";
    const auto level = classify_ns_thermal_state(ns_thermal_state);
    r.detail = std::string(to_string(level));
    // kIOPMThermalWarningLevelNormal == 0; anything the SDK reports above
    // that when the key WAS found is folded into the detail as a secondary
    // note. "Not found" (no warning ever recorded) is the common, healthy
    // case and adds no note at all — never treated as an error.
    if (iopm_found && iopm_warning_level > 0)
        r.detail += ",iopm_warning=" + std::to_string(iopm_warning_level);
    return r;
}

// ── Linux: /sys/class/thermal/thermal_zone*/{type,temp} ────────────────────
[[nodiscard]] inline std::optional<double> parse_linux_thermal_temp(std::string_view temp_file) {
    // temp file content is millidegrees Celsius, possibly with trailing
    // whitespace/newline.
    while (!temp_file.empty() && (temp_file.back() == '\n' || temp_file.back() == '\r' ||
                                  temp_file.back() == ' '))
        temp_file.remove_suffix(1);
    if (temp_file.empty())
        return std::nullopt;
    long millic = 0;
    auto [ptr, ec] = std::from_chars(temp_file.data(), temp_file.data() + temp_file.size(), millic);
    if (ec != std::errc{} || ptr != temp_file.data() + temp_file.size())
        return std::nullopt;
    return static_cast<double>(millic) / 1000.0;
}

// ─────────────────────────────────────────────────────────── power plan ───

/// Plain 16-byte GUID view — never the Win32 GUID type, so this header stays
/// <windows.h>-free. Field layout matches GUID's own (Data1/Data2/Data3/
/// Data4[8]) so the impure shell can convert with a field-by-field copy.
struct GuidBytes {
    uint32_t data1{0};
    uint16_t data2{0};
    uint16_t data3{0};
    std::array<uint8_t, 8> data4{};
};

[[nodiscard]] inline std::string format_guid(const GuidBytes& g) {
    char buf[40];
    std::snprintf(buf, sizeof buf,
                  "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", g.data1, g.data2, g.data3,
                  g.data4[0], g.data4[1], g.data4[2], g.data4[3], g.data4[4], g.data4[5],
                  g.data4[6], g.data4[7]);
    return buf;
}

namespace detail {
[[nodiscard]] constexpr int hex_val(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}
} // namespace detail

/// Accepts "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" with or without surrounding
/// braces, case-insensitive. Returns nullopt on any malformed input rather
/// than a best-effort partial parse.
[[nodiscard]] inline std::optional<GuidBytes> parse_guid(std::string_view s) {
    if (!s.empty() && s.front() == '{' && s.back() == '}')
        s = s.substr(1, s.size() - 2);
    if (s.size() != 36)
        return std::nullopt;
    if (s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-')
        return std::nullopt;

    auto hex_byte = [&](std::size_t i) -> std::optional<uint8_t> {
        const int hi = detail::hex_val(s[i]);
        const int lo = detail::hex_val(s[i + 1]);
        if (hi < 0 || lo < 0)
            return std::nullopt;
        return static_cast<uint8_t>((hi << 4) | lo);
    };
    auto hex_u16 = [&](std::size_t i) -> std::optional<uint16_t> {
        auto a = hex_byte(i);
        auto b = hex_byte(i + 2);
        if (!a || !b)
            return std::nullopt;
        return static_cast<uint16_t>((*a << 8) | *b);
    };
    auto hex_u32 = [&](std::size_t i) -> std::optional<uint32_t> {
        auto a = hex_u16(i);
        auto b = hex_u16(i + 4);
        if (!a || !b)
            return std::nullopt;
        return (static_cast<uint32_t>(*a) << 16) | *b;
    };

    GuidBytes g;
    auto d1 = hex_u32(0);
    auto d2 = hex_u16(9);
    auto d3 = hex_u16(14);
    if (!d1 || !d2 || !d3)
        return std::nullopt;
    g.data1 = *d1;
    g.data2 = *d2;
    g.data3 = *d3;
    static constexpr std::size_t kByteOffsets[8] = {19, 21, 24, 26, 28, 30, 32, 34};
    for (int i = 0; i < 8; ++i) {
        auto b = hex_byte(kByteOffsets[i]);
        if (!b)
            return std::nullopt;
        g.data4[static_cast<std::size_t>(i)] = *b;
    }
    return g;
}

[[nodiscard]] inline bool is_guid_shaped(std::string_view s) { return parse_guid(s).has_value(); }

[[nodiscard]] inline bool guids_equal(const GuidBytes& a, const GuidBytes& b) {
    return a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4;
}

/// One PowrProf scheme, resolved via PowerEnumerate(ACCESS_SCHEME) +
/// PowerReadFriendlyName — 4 schemes verified live on the-rig, 2026-09-04
/// (powercfg /list agrees).
struct PowerScheme {
    GuidBytes guid;
    std::string friendly_name;
};

/// Result of one PowerEnumerate(ACCESS_SCHEME) sweep. `complete` is true iff
/// the sweep ran to `ERROR_NO_MORE_ITEMS` — an ordinary mid-list error (a
/// transient PowerEnumerate failure at some index > 0) leaves `complete`
/// false with whatever schemes were collected before the failure (PH-004):
/// callers that need EXACTLY-ONE friendly-name matching to be trustworthy
/// (do_set_power_plan_sequence below) must treat an incomplete sweep as
/// unusable for that purpose rather than resolving a name against a
/// partial list that might be missing a duplicate.
struct EnumerateResult {
    std::vector<PowerScheme> schemes;
    bool complete{false};
};

enum class SchemeResolveError { NoMatch, Ambiguous };

/// Resolves a `scheme` param (GUID or friendly name) against the live
/// PowerEnumerate list. A GUID-shaped query is normalized and returned
/// as-is (PowerSetActiveScheme's own failure, and the post-set read-back
/// check, are the backstop for a syntactically-valid-but-nonexistent GUID).
/// A non-GUID query is resolved by EXACT case-insensitive friendly-name
/// match; zero or more-than-one match is refused rather than guessed at
/// (P-012) — e.g. "Balanced" must NOT ambiguously match both "Balanced" and
/// "AMD RyzenT Balanced" on the-rig's real 4-scheme fixture.
[[nodiscard]] inline std::expected<GuidBytes, SchemeResolveError>
resolve_power_scheme(std::span<const PowerScheme> schemes, std::string_view query) {
    if (auto g = parse_guid(query))
        return *g;

    // ASCII-only case folding (PH-014): every friendly name this package
    // has actually observed (the-rig's real 4-scheme PowerEnumerate list)
    // is ASCII, and this stays a plain byte-for-byte compare rather than
    // reaching for locale-dependent std::tolower behaviour or a
    // Windows-only ordinal-compare API from an OS-free header. A
    // non-ASCII localized scheme name (accented characters in a non-en-US
    // Windows build) could under- or over-match here; that is a known,
    // accepted limitation of this header staying OS-free, not a
    // correctness target for this package.
    auto ieq = [](std::string_view a, std::string_view b) {
        if (a.size() != b.size())
            return false;
        for (std::size_t i = 0; i < a.size(); ++i) {
            if (std::tolower(static_cast<unsigned char>(a[i])) !=
                std::tolower(static_cast<unsigned char>(b[i])))
                return false;
        }
        return true;
    };

    std::optional<GuidBytes> match;
    int count = 0;
    for (const auto& s : schemes) {
        if (ieq(s.friendly_name, query)) {
            match = s.guid;
            ++count;
        }
    }
    if (count == 0)
        return std::unexpected(SchemeResolveError::NoMatch);
    if (count > 1)
        return std::unexpected(SchemeResolveError::Ambiguous);
    return *match;
}

// ── set_power_plan sequencing (P-012, P-005) ────────────────────────────
//
// Pure sequencing logic for the plugin's ONE destructive action, driven
// entirely over SetPowerPlanOps — an injected boundary defaulting (in
// power_health_plugin.cpp's real Windows leg) to
// bounded_call_tracked(enumerate_schemes_raw/get_active_scheme_raw/
// set_active_scheme_raw), same "every OS boundary is an injectable
// parameter" shape as resolve_power_scheme above and
// interpret_iops_source's plain-struct view. This is what makes every
// enumerated failure branch — exactly-one-match resolution, prior-read
// BEFORE any mutation, set failure, post-set read-back mismatch, and a
// bounded-call timeout at any step — fixture-testable without a live
// PowrProf call (test_power_health_parsers.cpp's do_set_power_plan_sequence
// cases).
enum class SetPowerPlanOutcome {
    MissingParam,
    Timeout,               // PowerEnumerate itself timed out / was ceiling-rejected
    EnumerationIncomplete, // PowerEnumerate ended on an ordinary error, not ERROR_NO_MORE_ITEMS
    NoMatch,
    Ambiguous,
    ReadPriorFailed,  // includes a timeout reading the prior active scheme
    SetFailed,        // includes a timeout during PowerSetActiveScheme
    ReadbackFailed,   // includes a timeout during the post-set read-back
    ReadbackMismatch,
    Ok,
};

struct SetPowerPlanResult {
    SetPowerPlanOutcome outcome{SetPowerPlanOutcome::Ok};
    std::optional<GuidBytes> previous_guid; // set once the prior-scheme read succeeds
    std::optional<GuidBytes> target_guid;   // set once name/GUID resolution succeeds
    std::optional<GuidBytes> new_guid;      // set once the post-set read-back itself succeeds
    // (whether or not it matches target_guid — a mismatch still needs both
    // GUIDs reported, per P-012).

    [[nodiscard]] bool ok() const noexcept { return outcome == SetPowerPlanOutcome::Ok; }
};

/// Boundary operations the sequence below drives. `enumerate`/`read_active`/
/// `set_active` each return an outer `std::optional` that is `std::nullopt`
/// to model "the bounded call timed out or was ceiling-rejected" — exactly
/// bounded_call()/bounded_call_tracked()'s own `std::optional<T>` shape one
/// level up, so the real leg's bindings are a direct pass-through with no
/// translation layer.
/// Render a set_power_plan result row.
///
/// EVERY branch emits exactly four fields after the `set_power_plan`
/// discriminator, because content/definitions/power_health.yaml declares the
/// result columns POSITIONALLY (status, reason, previous_guid, new_guid). A
/// success row that omitted `reason` shifted previous_guid into reason and
/// new_guid into previous_guid — corrupting the one value an operator needs in
/// order to revert. `-` is the absent-field marker, never an empty field.
[[nodiscard]] inline std::string format_set_power_plan_row(std::string_view status,
                                                            std::string_view reason,
                                                            std::string_view previous_guid,
                                                            std::string_view new_guid) {
    auto dash = [](std::string_view v) { return v.empty() ? std::string_view{"-"} : v; };
    std::string out = "set_power_plan|";
    out += status;
    out += '|';
    out += dash(reason);
    out += '|';
    out += dash(previous_guid);
    out += '|';
    out += dash(new_guid);
    return out;
}

struct SetPowerPlanOps {
    std::function<std::optional<EnumerateResult>()> enumerate;
    std::function<std::optional<std::optional<GuidBytes>>()> read_active;
    std::function<std::optional<bool>(const GuidBytes&)> set_active;
};

/// Drives the full set_power_plan sequence: resolve → read prior (before
/// any mutation) → set → read back and verify. Every branch below returns
/// as soon as its typed outcome is known — nothing past a failure point
/// runs, matching P-012's "no mutation on any pre-set failure" contract and
/// making `set_active` observably the LAST boundary op called before a
/// mutation, never called speculatively.
[[nodiscard]] inline SetPowerPlanResult
do_set_power_plan_sequence(std::string_view scheme_param, const SetPowerPlanOps& ops) {
    SetPowerPlanResult result;
    if (scheme_param.empty()) {
        result.outcome = SetPowerPlanOutcome::MissingParam;
        return result;
    }

    const auto schemes = ops.enumerate();
    if (!schemes) {
        result.outcome = SetPowerPlanOutcome::Timeout;
        return result;
    }
    if (!schemes->complete) {
        result.outcome = SetPowerPlanOutcome::EnumerationIncomplete;
        return result;
    }

    const auto resolved = resolve_power_scheme(schemes->schemes, scheme_param);
    if (!resolved) {
        result.outcome = resolved.error() == SchemeResolveError::Ambiguous
                              ? SetPowerPlanOutcome::Ambiguous
                              : SetPowerPlanOutcome::NoMatch;
        return result;
    }
    result.target_guid = *resolved;

    // Read the prior active scheme BEFORE any mutation (P-012).
    const auto prior = ops.read_active();
    if (!prior || !prior->has_value()) {
        result.outcome = SetPowerPlanOutcome::ReadPriorFailed;
        return result;
    }
    result.previous_guid = **prior;

    const auto set_ok = ops.set_active(*result.target_guid);
    if (!set_ok || !*set_ok) {
        result.outcome = SetPowerPlanOutcome::SetFailed;
        return result;
    }

    // Read back and verify the mutation actually took (P-012) — a mismatch
    // is a typed error naming both GUIDs, never a silent partial success.
    const auto readback = ops.read_active();
    if (!readback || !readback->has_value()) {
        result.outcome = SetPowerPlanOutcome::ReadbackFailed;
        return result;
    }
    result.new_guid = **readback;
    if (!guids_equal(**readback, *result.target_guid)) {
        result.outcome = SetPowerPlanOutcome::ReadbackMismatch;
        return result;
    }

    result.outcome = SetPowerPlanOutcome::Ok;
    return result;
}

#ifdef __APPLE__
// Declared here (not defined — power_health_macos.mm defines these) so both
// power_health_plugin.cpp (an ordinary .cpp TU) and power_health_macos.mm
// (the Objective-C++ TU that actually calls into IOPSCopyPowerSourcesInfo/
// NSProcessInfo/IOPMGetThermalWarningLevel) share one prototype. Plain C++
// signatures only — never a CF/NS type crosses this boundary, so this
// header stays free of any macOS-framework include even under __APPLE__.
// See docs/native-objcpp-conventions.md.
namespace macos_native {
[[nodiscard]] std::vector<IopsSourceView> query_battery_sources();
void query_thermal(long& ns_thermal_state, bool& iopm_found, int32_t& iopm_warning_level);
} // namespace macos_native
#endif

} // namespace yuzu::power_health
