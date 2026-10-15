/**
 * peripherals_win_parsers.hpp — PURE parsing helpers for the Windows
 * SetupAPI leg. No windows.h, no OS calls: everything here is a free
 * function over plain strings, testable off Windows (test_peripherals_win_
 * parsers.cpp reads P91-3's real SetupAPI dump fixtures through these).
 *
 * INPUT SHAPES this header understands:
 *   - a USB HARDWAREID, e.g. "USB\VID_046D&PID_C52B&REV_1201"
 *   - a USB COMPATIBLEID in the documented "Class_XX&SubClass_YY&Prot_ZZ"
 *     form, e.g. "USB\Class_09&SubClass_00&Prot_01" (the short-vendor
 *     "COMPAT_VID_xxxx&DevClass_.." variant some captures also carry is not
 *     targeted -- is_hub below never needs it, see the comment there)
 *   - a PCI HARDWAREID, e.g. "PCI\VEN_8086&DEV_A0ED&SUBSYS_...&REV_20"
 *   - a PCI class-code HARDWAREID, e.g. "PCI\VEN_8086&DEV_A0ED&CC_030000"
 *   - a DEVICEDESC free-text string, for the Thunderbolt/USB4 filter
 *   - one tab-separated line of a the-rig SetupAPI dump capture (the
 *     fixture format tests/unit/fixtures/wave9/peripherals/windows/ uses):
 *     enumerator, instance id, hardware ids (';'-joined), compatible
 *     ids (';'-joined, may be empty), DEVICEDESC, FRIENDLYNAME, MFG, CLASS
 */
#pragma once

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace yuzu::peripherals::win {

namespace detail {

// Reads up to `max_digits` hex characters immediately after the first
// occurrence of `marker` in `s`. nullopt if the marker is absent or is not
// followed by at least one hex digit.
[[nodiscard]] inline std::optional<std::uint32_t> extract_hex_after(std::string_view s,
                                                                     std::string_view marker,
                                                                     std::size_t max_digits) {
    const auto pos = s.find(marker);
    if (pos == std::string_view::npos)
        return std::nullopt;
    const std::size_t start = pos + marker.size();
    std::size_t end = start;
    while (end < s.size() && end - start < max_digits &&
          std::isxdigit(static_cast<unsigned char>(s[end])))
        ++end;
    if (end == start)
        return std::nullopt;
    std::uint32_t v = 0;
    const auto [ptr, ec] = std::from_chars(s.data() + start, s.data() + end, v, 16);
    if (ec != std::errc{})
        return std::nullopt;
    return v;
}

// Splits on a single-char separator, keeping empty leading/trailing fields
// (so a fixture line's blank FRIENDLYNAME column round-trips as "").
[[nodiscard]] inline std::vector<std::string> split(std::string_view s, char sep) {
    std::vector<std::string> out;
    std::size_t start = 0;
    for (;;) {
        const auto pos = s.find(sep, start);
        if (pos == std::string_view::npos) {
            out.emplace_back(s.substr(start));
            break;
        }
        out.emplace_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    return out;
}

} // namespace detail

// ── USB ───────────────────────────────────────────────────────────────────

struct UsbIds {
    std::uint16_t vendor_id = 0;
    std::uint16_t product_id = 0;
};

/// "USB\VID_046D&PID_C52B&REV_1201" -> {0x046D, 0xC52B}. nullopt if either
/// token is missing (a malformed or partial hardware-id string).
///
/// Falls back to the underscore-less "VIDxxxx"/"PIDxxxx" form a USB root
/// hub's hardware id carries (real capture:
/// tests/unit/fixtures/wave9/peripherals/windows/setupapi_usb.txt:7 --
/// "USB\ROOT_HUB30&VID1022&PID149C&REV0000") when the standard "VID_"/"PID_"
/// marker is absent -- the underscored form always wins when present, so
/// this never changes the result for an ordinary device.
[[nodiscard]] inline std::optional<UsbIds> parse_usb_hardware_id(std::string_view hwid) {
    auto vid = detail::extract_hex_after(hwid, "VID_", 4);
    if (!vid)
        vid = detail::extract_hex_after(hwid, "VID", 4);
    auto pid = detail::extract_hex_after(hwid, "PID_", 4);
    if (!pid)
        pid = detail::extract_hex_after(hwid, "PID", 4);
    if (!vid || !pid)
        return std::nullopt;
    UsbIds ids;
    ids.vendor_id = static_cast<std::uint16_t>(*vid);
    ids.product_id = static_cast<std::uint16_t>(*pid);
    return ids;
}

struct UsbClass {
    std::uint8_t usb_class = 0;
    std::uint8_t subclass = 0;
    std::uint8_t protocol = 0; // 0 when the id carries no Prot_ token
};

/// "USB\Class_09&SubClass_00&Prot_01" -> {0x09, 0x00, 0x01}. Class and
/// SubClass are mandatory (nullopt without either); Prot_ is optional.
[[nodiscard]] inline std::optional<UsbClass> parse_usb_compatible_class(std::string_view id) {
    const auto cls = detail::extract_hex_after(id, "Class_", 2);
    const auto sub = detail::extract_hex_after(id, "SubClass_", 2);
    if (!cls || !sub)
        return std::nullopt;
    UsbClass c;
    c.usb_class = static_cast<std::uint8_t>(*cls);
    c.subclass = static_cast<std::uint8_t>(*sub);
    if (const auto prot = detail::extract_hex_after(id, "Prot_", 2))
        c.protocol = static_cast<std::uint8_t>(*prot);
    return c;
}

// ── PCI ───────────────────────────────────────────────────────────────────

struct PciIds {
    std::uint16_t vendor_id = 0;
    std::uint16_t device_id = 0;
};

/// "PCI\VEN_8086&DEV_A0ED&SUBSYS_...&REV_20" -> {0x8086, 0xA0ED}.
[[nodiscard]] inline std::optional<PciIds> parse_pci_hardware_id(std::string_view hwid) {
    const auto ven = detail::extract_hex_after(hwid, "VEN_", 4);
    const auto dev = detail::extract_hex_after(hwid, "DEV_", 4);
    if (!ven || !dev)
        return std::nullopt;
    PciIds ids;
    ids.vendor_id = static_cast<std::uint16_t>(*ven);
    ids.device_id = static_cast<std::uint16_t>(*dev);
    return ids;
}

/// "PCI\CC_0C0330" -> 0x0C0330 (masked to 24 bits, matching hex6() in
/// peripherals_parsers.hpp). nullopt if no CC_ token is present at all --
/// callers should prefer a hardware-id alt that carries the full 6-digit
/// form over a shorter "CC_0C03" alt when several are offered, since the
/// short form is base+subclass only and would silently mask in a
/// misleading value if treated as the full code.
[[nodiscard]] inline std::optional<std::uint32_t> parse_pci_class_code(std::string_view hwid) {
    const auto cc = detail::extract_hex_after(hwid, "CC_", 6);
    if (!cc)
        return std::nullopt;
    return *cc & 0x00FFFFFFu;
}

// ── Thunderbolt/USB4 ─────────────────────────────────────────────────────

/// Case-insensitive substring match on a DEVICEDESC string. This is the
/// entire Wave-2 Thunderbolt detection strategy: SetupAPI's PCI enumerator
/// only ever surfaces the host controller/bridge (never downstream TB
/// devices), so every match is reported with role host_controller by the
/// caller -- see peripherals_win.cpp.
[[nodiscard]] inline bool is_thunderbolt_desc(std::string_view desc) {
    std::string lower(desc);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return lower.find("thunderbolt") != std::string::npos || lower.find("usb4") != std::string::npos;
}

// ── SetupAPI dump-line parsing (test fixtures) ──────────────────────────

struct DeviceDumpRecord {
    std::string enumerator;
    std::string instance_id;
    std::vector<std::string> hardware_ids;
    std::vector<std::string> compatible_ids;
    std::string devicedesc;
    std::string friendlyname;
    std::string mfg;
    std::string device_class;
};

/// Parses one tab-separated line of a the-rig SetupAPI dump capture (the
/// shape probe_wave9_bus_win.exe emits, per the fixtures' provenance
/// files): enumerator, instance id, hardware ids (';'-joined), compatible
/// ids (';'-joined, may be empty), DEVICEDESC, FRIENDLYNAME, MFG, CLASS.
/// nullopt for a blank line or a line that does not carry exactly 8 tab
/// fields (never silently drops or merges columns).
[[nodiscard]] inline std::optional<DeviceDumpRecord> parse_setupapi_dump_line(
    std::string_view line) {
    if (line.empty())
        return std::nullopt;
    const auto fields = detail::split(line, '\t');
    if (fields.size() != 8)
        return std::nullopt;
    DeviceDumpRecord rec;
    rec.enumerator = fields[0];
    rec.instance_id = fields[1];
    if (!fields[2].empty())
        rec.hardware_ids = detail::split(fields[2], ';');
    if (!fields[3].empty())
        rec.compatible_ids = detail::split(fields[3], ';');
    rec.devicedesc = fields[4];
    rec.friendlyname = fields[5];
    rec.mfg = fields[6];
    rec.device_class = fields[7];
    return rec;
}

} // namespace yuzu::peripherals::win
