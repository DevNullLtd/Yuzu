/**
 * peripherals_parsers.hpp — the PURE row-formatting layer for peripherals.
 *
 * Everything here is a free function over plain data: no OS calls, no I/O, no
 * logging, no platform headers. That is the repo's standing test-efficiency
 * discipline (testable logic — parsing, decisions, formatting — lives in a
 * pure `*_parsers.hpp`; the OS interaction lives in a shell the unit suites
 * never run), the sibling shape `disk_actions_legs.hpp`'s formatter section
 * already establishes.
 *
 * SCOPE (Wave 1, this package): three bus-inventory kinds only — usb, pci,
 * thunderbolt (the bus_inventory fold: thunderbolt roles + USB hub rows).
 * displays/bluetooth/audio/camera are PR9.1c, deferred — no EDID parser here.
 *
 * ROW SCHEMAS. Every row of a given kind carries the same field count, with
 * "-" where a value is inapplicable. A consumer keying on position must never
 * have to guess which shape it received.
 *
 *   usb|<bus_path>|<vendor_id hex4>|<product_id hex4>|<class hex2>|<subclass hex2>|<vendor>|<product>|<serial>|<speed>|<is_hub 1/0>
 *   pci|<bus_path>|<vendor_id hex4>|<device_id hex4>|<class hex6>|<subsystem_vendor hex4>|<subsystem_device hex4>|<driver>|<description>
 *   thunderbolt|<path>|<role host_controller|device>|<vendor>|<model>|<unique_id>|<generation>|<authorized 1/0/->
 *
 * `role` is a fixed vocabulary emitted verbatim (never parsed text); every
 * other free-text field is untrusted OS-supplied text and goes through
 * yuzu::util::safe_output_field (sdk/include/yuzu/string_utils.hpp:100).
 *
 * THE EMPTY-RESULT AND FAILURE PLACEHOLDERS. When a leg finds nothing (but
 * did not fail) it emits `format_none_row` rather than silence, so a consumer
 * never reads zero rows and infers "this host has no such device". When a leg
 * cannot even attempt the read, it emits `format_unavailable_row` carrying the
 * provenance token, so the row and the CC-07 status seam always agree.
 */
#pragma once

#include <yuzu/string_utils.hpp>

#include <cstdint>
#include <format>
#include <string>
#include <string_view>

namespace yuzu::peripherals {

// ── hex field helpers ────────────────────────────────────────────────────
//
// Fixed-width, lowercase, zero-padded — the shape the dispatcher test's
// `^[0-9a-f]{n}$` regex pins. hex6 masks to 24 bits: a PCI class code is a
// 3-byte (base/subclass/prog-if) field and never wider.

[[nodiscard]] inline std::string hex2(std::uint8_t v) { return std::format("{:02x}", v); }
[[nodiscard]] inline std::string hex4(std::uint16_t v) { return std::format("{:04x}", v); }
[[nodiscard]] inline std::string hex6(std::uint32_t v) {
    return std::format("{:06x}", v & 0x00FFFFFFu);
}

// ── fixed vocabulary: thunderbolt role ──────────────────────────────────

/// A Thunderbolt/USB4 node is either the host's own controller or an
/// attached device — the two ends of the bus_inventory fold this action
/// exists to report. Emitted verbatim, never through safe_output_field.
enum class ThunderboltRole { HostController, Device };

[[nodiscard]] constexpr std::string_view thunderbolt_role_token(ThunderboltRole r) noexcept {
    switch (r) {
    case ThunderboltRole::HostController: return "host_controller";
    case ThunderboltRole::Device:         return "device";
    }
    return "device";
}

// ── pure row formatters ─────────────────────────────────────────────────
//
// Formatters take already-computed values, perform no OS calls and make no
// decisions, and return the row WITHOUT a trailing newline -- append_output()
// inserts the separator between successive writes, so a formatter-emitted
// '\n' produces blank rows under LocalDispatcher capture.

/// usb|<bus_path>|<vendor_id hex4>|<product_id hex4>|<class hex2>|<subclass hex2>|<vendor>|<product>|<serial>|<speed>|<is_hub 1/0>
[[nodiscard]] inline std::string format_usb_row(std::string_view bus_path, std::uint16_t vendor_id,
                                                std::uint16_t product_id, std::uint8_t usb_class,
                                                std::uint8_t subclass, std::string_view vendor,
                                                std::string_view product, std::string_view serial,
                                                std::string_view speed, bool is_hub) {
    std::string out = "usb|";
    out += yuzu::util::safe_output_field(bus_path);
    out += '|';
    out += hex4(vendor_id);
    out += '|';
    out += hex4(product_id);
    out += '|';
    out += hex2(usb_class);
    out += '|';
    out += hex2(subclass);
    out += '|';
    out += yuzu::util::safe_output_field(vendor);
    out += '|';
    out += yuzu::util::safe_output_field(product);
    out += '|';
    out += yuzu::util::safe_output_field(serial);
    out += '|';
    out += yuzu::util::safe_output_field(speed);
    out += '|';
    out += (is_hub ? '1' : '0');
    return out;
}

/// pci|<bus_path>|<vendor_id hex4>|<device_id hex4>|<class hex6>|<subsystem_vendor hex4>|<subsystem_device hex4>|<driver>|<description>
[[nodiscard]] inline std::string
format_pci_row(std::string_view bus_path, std::uint16_t vendor_id, std::uint16_t device_id,
               std::uint32_t class_code, std::uint16_t subsystem_vendor,
               std::uint16_t subsystem_device, std::string_view driver,
               std::string_view description) {
    std::string out = "pci|";
    out += yuzu::util::safe_output_field(bus_path);
    out += '|';
    out += hex4(vendor_id);
    out += '|';
    out += hex4(device_id);
    out += '|';
    out += hex6(class_code);
    out += '|';
    out += hex4(subsystem_vendor);
    out += '|';
    out += hex4(subsystem_device);
    out += '|';
    out += yuzu::util::safe_output_field(driver);
    out += '|';
    out += yuzu::util::safe_output_field(description);
    return out;
}

/// thunderbolt|<path>|<role host_controller|device>|<vendor>|<model>|<unique_id>|<generation>|<authorized 1/0/->
[[nodiscard]] inline std::string
format_thunderbolt_row(std::string_view path, ThunderboltRole role, std::string_view vendor,
                       std::string_view model, std::string_view unique_id,
                       std::string_view generation, std::string_view authorized) {
    std::string out = "thunderbolt|";
    out += yuzu::util::safe_output_field(path);
    out += '|';
    out.append(thunderbolt_role_token(role)); // fixed vocabulary -- verbatim
    out += '|';
    out += yuzu::util::safe_output_field(vendor);
    out += '|';
    out += yuzu::util::safe_output_field(model);
    out += '|';
    out += yuzu::util::safe_output_field(unique_id);
    out += '|';
    out += yuzu::util::safe_output_field(generation);
    out += '|';
    out += yuzu::util::safe_output_field(authorized); // "1" / "0" / "-", still untrusted text
    return out;
}

// ── empty-result and failure placeholders ───────────────────────────────

/// <kind>|none — the leg attempted the read and found zero devices of this
/// kind. Distinct from `format_unavailable_row`: this is a clean, complete
/// answer, not a degradation.
[[nodiscard]] inline std::string format_none_row(std::string_view kind) {
    std::string out{kind};
    out += "|none";
    return out;
}

/// <kind>|unavailable|<token> — the leg could not attempt the read at all.
/// `token` is always an `<os>:<source>:<detail>` provenance string, and the
/// same value is what CommandContext::set_result_status reports as the
/// reason (see mark_result_read in peripherals_legs.hpp).
[[nodiscard]] inline std::string format_unavailable_row(std::string_view kind,
                                                        std::string_view token) {
    std::string out{kind};
    out += "|unavailable|";
    out += yuzu::util::safe_output_field(token);
    return out;
}

} // namespace yuzu::peripherals
