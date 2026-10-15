#pragma once

/**
 * peripherals_linux_parsers.hpp — INJECTED-BOUNDARY sysfs walks and pure
 * parsers for the Linux leg (usb/pci/thunderbolt bus_inventory).
 *
 * The boundary: every filesystem access goes through a `root` path parameter
 * (real production calls pass "/", the unit suite passes a fixture tree
 * under tests/unit/fixtures/wave9/peripherals/linux/sysfs_tree/), and the
 * walks themselves use only <filesystem> -- no popen/system/exec/fork, no
 * subprocess of any kind (scripts/ci/check-plugin-spawn-lexical.sh enforces
 * this). That is what makes usb_rows_at/pci_rows_at/thunderbolt_rows_at unit
 * -testable without a real /sys tree, the same discipline
 * hardware_linux_parsers.hpp's build_linux_disk_rows() establishes (there,
 * injected read_file/read_link callbacks; here, an injected root path --
 * either shape satisfies the same "OS interaction lives in a shell the unit
 * suites never run" rule, and a direct filesystem walk is the natural fit
 * for a tree-shaped read like a sysfs bus enumeration).
 *
 * Namespace `lnx`, not `linux`: `linux` is a predefined macro under
 * non-strict-ISO GNU extension modes on some toolchains, and this header
 * must compile cleanly on every host (the test file includes it
 * unconditionally on macOS/Windows/Linux alike, mirroring
 * hardware_linux_parsers.hpp's own "Platform-agnostic and header-only"
 * precedent) even though peripherals_linux.cpp only calls it from the
 * `#if defined(__linux__)` leg.
 *
 * FAILURE-TOKEN CONTRACT, one seam shared by all three walks: `failure_token`
 * is set (to a `linux:sysfs:...` string-literal token, matching
 * peripherals_legs.hpp's provenance-string contract) only when the walk
 * could not attempt the read at all -- the bus's own `devices` directory
 * exists but is unreadable (EACCES) or hit some other listing error. A bus
 * directory that simply does not exist (host has no USB/PCI/Thunderbolt bus,
 * or the fixture tree does not model one) is NOT a failure: the walk returns
 * an empty row list with no token, and the caller (peripherals_linux.cpp)
 * reports that as a clean, complete `<kind>|none` result via
 * mark_result_read -- exactly the "rows == 0, no token" branch that helper
 * already documents. Per-attribute reads that come back missing (an optional
 * attribute a given device does not expose) are handled entirely inside
 * read_attr()/the walk itself, falling back to "-"; they never touch
 * failure_token, since one absent optional attribute on one device is not a
 * failure to read the bus.
 */

#include "peripherals_parsers.hpp"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace yuzu::peripherals::lnx {

// ── read_attr: the one file-read primitive every walk below uses ───────────
//
// Bounded (never reads more than `cap` bytes -- a malformed/replaced sysfs
// attribute cannot make this read unbounded), newline-trimmed (sysfs
// attribute files end in exactly one '\n'; a consumer wants the value, not
// the terminator). A missing attribute file (ENOENT -- ordinary: not every
// device exposes every attribute this package reads) or any other reason the
// file could not be opened returns nullopt; callers apply their own "-"
// fallback via value_or, matching every other OS leg's row schema.
[[nodiscard]] inline std::optional<std::string> read_attr(const std::filesystem::path& path,
                                                           std::size_t cap = 4096) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return std::nullopt;
    std::string buf(cap, '\0');
    f.read(buf.data(), static_cast<std::streamsize>(cap));
    buf.resize(static_cast<std::size_t>(f.gcount()));
    while (!buf.empty() && (buf.back() == '\n' || buf.back() == '\r'))
        buf.pop_back();
    return buf;
}

// ── pure parsers ─────────────────────────────────────────────────────────

/// Parses a sysfs hex attribute ("0x8086", "8086", or empty/malformed) into
/// its numeric value. sysfs id attributes (idVendor, idProduct, vendor,
/// device, subsystem_vendor, subsystem_device) are consistently either bare
/// or "0x"-prefixed lowercase hex; nullopt for anything that doesn't parse
/// as a whole hex token (never a partial/best-effort value).
[[nodiscard]] inline std::optional<std::uint32_t> parse_hex_attr(std::string_view s) noexcept {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    while (!s.empty() &&
          (s.back() == ' ' || s.back() == '\t' || s.back() == '\n' || s.back() == '\r'))
        s.remove_suffix(1);
    if (s.starts_with("0x") || s.starts_with("0X"))
        s.remove_prefix(2);
    if (s.empty())
        return std::nullopt;
    std::uint32_t value = 0;
    const auto* begin = s.data();
    const auto* end = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(begin, end, value, 16);
    if (ec != std::errc{} || ptr != end)
        return std::nullopt;
    return value;
}

/// A PCI `class` attribute ("0x0c0330") is the same hex grammar as any other
/// id attribute -- base class / subclass / prog-if packed into 24 bits, read
/// as one hex token. Named separately from parse_hex_attr because the two
/// attributes are semantically distinct fields in the row schema (id vs.
/// class code), not because the parsing differs.
[[nodiscard]] inline std::optional<std::uint32_t> parse_pci_class(std::string_view s) noexcept {
    return parse_hex_attr(s);
}

/// True for a USB interface entry ("1-2.1:1.0") as opposed to a device entry
/// ("1-2.1", "usb1"): every interface name contains a ':' separating the
/// device's own bus path from "<config>.<interface>"; no device entry name
/// ever does. The walk uses this to skip interface entries entirely -- the
/// usb action reports one row per DEVICE, not per interface.
[[nodiscard]] inline bool is_usb_interface_entry(std::string_view name) noexcept {
    return name.find(':') != std::string_view::npos;
}

/// True for a Thunderbolt/USB4 domain entry ("domain0", "domain12"): the
/// literal prefix "domain" followed by one or more decimal digits and
/// nothing else. Every other non-skipped entry ("0-0", "0-1") is a router
/// device instead.
[[nodiscard]] inline bool is_tb_domain_entry(std::string_view name) noexcept {
    static constexpr std::string_view kPrefix = "domain";
    if (!name.starts_with(kPrefix) || name.size() == kPrefix.size())
        return false;
    return std::all_of(name.begin() + static_cast<std::ptrdiff_t>(kPrefix.size()), name.end(),
                       [](char c) { return c >= '0' && c <= '9'; });
}

namespace detail {

/// Classifies a directory_iterator construction error against the shared
/// failure-token contract documented at the top of this file. Returns
/// nullopt for "no failure" (including the not-a-failure "bus absent" case,
/// which the caller distinguishes from "no error" via `ec` itself).
[[nodiscard]] inline std::optional<std::string_view>
classify_bus_dir_error(const std::error_code& ec) {
    if (!ec)
        return std::nullopt;
    if (ec == std::errc::no_such_file_or_directory)
        return std::nullopt; // absent bus -- empty result, not a failure
    if (ec == std::errc::permission_denied)
        return std::string_view{"linux:sysfs:eacces"};
    return std::string_view{"linux:sysfs:read_failed"};
}

/// The `driver` field's two accepted shapes on-disk: a real symlink whose
/// target's basename is the driver name (the live-kernel shape), or a
/// regular file holding the basename as plain text (the fixture-tree
/// substitution this package's spec calls for, since a captured/reconstructed
/// fixture tree may not carry real symlinks). "-" when neither is present or
/// readable.
[[nodiscard]] inline std::string pci_driver_of(const std::filesystem::path& dev_dir) {
    const auto driver_path = dev_dir / "driver";
    std::error_code ec;
    if (std::filesystem::is_symlink(driver_path, ec)) {
        auto target = std::filesystem::read_symlink(driver_path, ec);
        if (!ec && !target.empty())
            return target.filename().string();
    }
    ec.clear();
    if (std::filesystem::is_regular_file(driver_path, ec) && !ec) {
        auto content = read_attr(driver_path);
        if (content.has_value() && !content->empty())
            return *content;
    }
    return "-";
}

} // namespace detail

// ── the three bus walks ──────────────────────────────────────────────────

/// Walks <root>/sys/bus/usb/devices, skipping interface entries
/// (is_usb_interface_entry), and returns one format_usb_row() per remaining
/// (device) entry. is_hub is true iff bDeviceClass == 0x09 (USB hub class).
[[nodiscard]] inline std::vector<std::string>
usb_rows_at(const std::filesystem::path& root, std::optional<std::string_view>& failure_token) {
    failure_token.reset();
    std::vector<std::string> rows;
    const auto bus_dir = root / "sys" / "bus" / "usb" / "devices";
    std::error_code ec;
    std::filesystem::directory_iterator it(bus_dir, ec);
    if (auto token = detail::classify_bus_dir_error(ec)) {
        failure_token = token;
        return rows;
    }
    if (ec)
        return rows; // absent bus, classified above as "no failure"

    try {
        for (const auto& entry : it) {
            const std::string name = entry.path().filename().string();
            if (is_usb_interface_entry(name))
                continue;
            const auto& p = entry.path();
            const auto vendor = parse_hex_attr(read_attr(p / "idVendor").value_or(""));
            const auto product = parse_hex_attr(read_attr(p / "idProduct").value_or(""));
            const auto usb_class = parse_hex_attr(read_attr(p / "bDeviceClass").value_or(""));
            const auto subclass = parse_hex_attr(read_attr(p / "bDeviceSubClass").value_or(""));
            const auto manufacturer = read_attr(p / "manufacturer").value_or("-");
            const auto product_str = read_attr(p / "product").value_or("-");
            const auto serial = read_attr(p / "serial").value_or("-");
            const auto speed = read_attr(p / "speed").value_or("-");
            const bool is_hub = usb_class.value_or(0) == 0x09;
            rows.push_back(format_usb_row(name, static_cast<std::uint16_t>(vendor.value_or(0)),
                                          static_cast<std::uint16_t>(product.value_or(0)),
                                          static_cast<std::uint8_t>(usb_class.value_or(0)),
                                          static_cast<std::uint8_t>(subclass.value_or(0)),
                                          manufacturer, product_str, serial, speed, is_hub));
        }
    } catch (const std::filesystem::filesystem_error&) {
        // A device disappeared mid-enumeration (sysfs TOCTOU, e.g. an unplug
        // racing this walk) -- keep whatever rows were already collected,
        // matching hardware_plugin.cpp's precedent for the same race.
    }
    return rows;
}

/// Walks <root>/sys/bus/pci/devices and returns one format_pci_row() per
/// entry. `description` has no sysfs equivalent this leg reads (that is the
/// PCI ID database's job, out of scope here, same as the Windows/macOS legs'
/// descriptors document) so it is always "-".
[[nodiscard]] inline std::vector<std::string>
pci_rows_at(const std::filesystem::path& root, std::optional<std::string_view>& failure_token) {
    failure_token.reset();
    std::vector<std::string> rows;
    const auto bus_dir = root / "sys" / "bus" / "pci" / "devices";
    std::error_code ec;
    std::filesystem::directory_iterator it(bus_dir, ec);
    if (auto token = detail::classify_bus_dir_error(ec)) {
        failure_token = token;
        return rows;
    }
    if (ec)
        return rows;

    try {
        for (const auto& entry : it) {
            const std::string name = entry.path().filename().string();
            const auto& p = entry.path();
            const auto vendor = parse_hex_attr(read_attr(p / "vendor").value_or(""));
            const auto device = parse_hex_attr(read_attr(p / "device").value_or(""));
            const auto class_code = parse_pci_class(read_attr(p / "class").value_or(""));
            const auto sub_vendor = parse_hex_attr(read_attr(p / "subsystem_vendor").value_or(""));
            const auto sub_device = parse_hex_attr(read_attr(p / "subsystem_device").value_or(""));
            const auto driver = detail::pci_driver_of(p);
            rows.push_back(format_pci_row(name, static_cast<std::uint16_t>(vendor.value_or(0)),
                                          static_cast<std::uint16_t>(device.value_or(0)),
                                          class_code.value_or(0),
                                          static_cast<std::uint16_t>(sub_vendor.value_or(0)),
                                          static_cast<std::uint16_t>(sub_device.value_or(0)), driver,
                                          "-"));
        }
    } catch (const std::filesystem::filesystem_error&) {
        // A device disappeared mid-enumeration (sysfs TOCTOU) -- keep
        // whatever rows were already collected.
    }
    return rows;
}

/// Walks <root>/sys/bus/thunderbolt/devices. A `domainN` entry is the host
/// controller itself (row fields all "-": a domain carries no
/// vendor/model/serial of its own in this package's row schema); a `N-M`
/// entry (no ':') is an attached device/router, read via
/// vendor_name/device_name/unique_id/generation/authorized; any entry
/// containing ':' (a retimer child, "<parent>:<index>.<index>") is skipped
/// entirely -- it is not a distinct row this action's schema models.
[[nodiscard]] inline std::vector<std::string>
thunderbolt_rows_at(const std::filesystem::path& root,
                    std::optional<std::string_view>& failure_token) {
    failure_token.reset();
    std::vector<std::string> rows;
    const auto bus_dir = root / "sys" / "bus" / "thunderbolt" / "devices";
    std::error_code ec;
    std::filesystem::directory_iterator it(bus_dir, ec);
    if (auto token = detail::classify_bus_dir_error(ec)) {
        failure_token = token;
        return rows;
    }
    if (ec)
        return rows;

    try {
        for (const auto& entry : it) {
            const std::string name = entry.path().filename().string();
            if (name.find(':') != std::string::npos)
                continue; // retimer child -- not a modelled row
            const auto& p = entry.path();
            if (is_tb_domain_entry(name)) {
                rows.push_back(format_thunderbolt_row(name, ThunderboltRole::HostController, "-",
                                                       "-", "-", "-", "-"));
                continue;
            }
            const auto vendor = read_attr(p / "vendor_name").value_or("-");
            const auto model = read_attr(p / "device_name").value_or("-");
            const auto unique_id = read_attr(p / "unique_id").value_or("-");
            const auto generation = read_attr(p / "generation").value_or("-");
            const auto authorized = read_attr(p / "authorized").value_or("-");
            rows.push_back(format_thunderbolt_row(name, ThunderboltRole::Device, vendor, model,
                                                  unique_id, generation, authorized));
        }
    } catch (const std::filesystem::filesystem_error&) {
        // A device disappeared mid-enumeration (sysfs TOCTOU) -- keep
        // whatever rows were already collected.
    }
    return rows;
}

} // namespace yuzu::peripherals::lnx
