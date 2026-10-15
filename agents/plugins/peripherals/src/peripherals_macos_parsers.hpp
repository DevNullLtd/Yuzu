/**
 * peripherals_macos_parsers.hpp — PURE decoders for the macOS peripherals
 * leg (peripherals_macos.cpp).
 *
 * Everything here is a free function over plain data: no IOKit call, no
 * CoreFoundation type, no OS call of any kind — the same test-efficiency
 * discipline peripherals_parsers.hpp's own banner states (testable logic
 * lives in a pure `*_parsers.hpp`; the IOKit walk lives in a shell the unit
 * suites never run). tests/unit/test_peripherals_macos_parsers.cpp exercises
 * every function here against REAL CAPTURE values from
 * tests/unit/fixtures/wave9/peripherals/macos/ — no invented fixtures.
 *
 * SCOPE. Three decoders only, each covering one non-trivial conversion the
 * macOS leg needs and that peripherals_parsers.hpp's OS-neutral row
 * formatters don't already provide:
 *
 *   decode_le_u32   — an IOPCIDevice OSData property (vendor-id, device-id,
 *                     class-code, subsystem-vendor-id, subsystem-id) is a
 *                     raw little-endian byte blob, not an integer IOKit
 *                     property; ioreg's own `<e4140000>` hex notation is
 *                     literally those bytes, LSB first, so decoding is a
 *                     length-4 read reinterpreted big-endian-out.
 *   usb_speed_name  — IOUSBHostDevice's numeric `Device Speed` (0-4) maps to
 *                     the low/full/high/super/super+ vocabulary
 *                     format_usb_row's `speed` field carries as text.
 *   uid_to_hex16    — IOThunderboltSwitch's `UID` property is a 64-bit
 *                     integer IOKit already decodes for the caller (unlike
 *                     the PCI OSData fields above); this only re-renders it
 *                     as the fixed-width lowercase hex16 text the
 *                     `unique_id` row field carries.
 */
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>

namespace yuzu::peripherals::macos {

/// The one-line classification `for_each_service` (peripherals_macos.cpp)
/// depends on to route between the real row-emitting path and the
/// `macos:iokit:matching_failed` CONSTRAINED path. Pulled out as a pure
/// function so a unit test can exercise both branches of the mandated
/// "matching failure -> CONSTRAINED, never an empty OK" contract without a
/// real IOKit call.
///
/// Takes a plain `int`, not `kern_return_t`/`KERN_SUCCESS` -- pulling a
/// Mach/IOKit header into this file would break its "builds and runs on
/// every OS, no IOKit/CoreFoundation" contract (see this file's own banner
/// and test_peripherals_macos_parsers.cpp's). `kern_return_t` is itself a
/// plain `int` and `KERN_SUCCESS` is defined as `0`
/// (mach/kern_return.h), so `kr == 0` is the exact, portable equivalent the
/// macOS-only caller needs; the call site passes its `kern_return_t`
/// straight through the implicit int conversion.
[[nodiscard]] constexpr bool matching_succeeded(int kr) noexcept {
    return kr == 0;
}

/// Decodes a 4-byte little-endian buffer (an IOPCIDevice OSData property --
/// vendor-id, device-id, class-code, subsystem-vendor-id, subsystem-id) into
/// the u32 it represents. `bytes.size() != 4` returns 0: a malformed/absent
/// property is a decode failure, not a value this leg can trust, and the
/// caller renders the resulting row field the same way a genuinely-zero
/// property would -- there is no separate "absent" channel for a single
/// numeric field in the usb/pci row schemas.
[[nodiscard]] inline std::uint32_t decode_le_u32(std::string_view bytes) {
    if (bytes.size() != 4)
        return 0;
    return (static_cast<std::uint32_t>(static_cast<std::uint8_t>(bytes[0])) << 0) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(bytes[1])) << 8) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(bytes[2])) << 16) |
           (static_cast<std::uint32_t>(static_cast<std::uint8_t>(bytes[3])) << 24);
}

/// Maps IOUSBHostDevice's `Device Speed` property (0-4) to the vocabulary
/// format_usb_row's `speed` field carries. Anything outside 0-4 (a future
/// USB generation IOKit hasn't been taught yet, or a malformed property) is
/// untrusted text going through safe_output_field at the call site, so
/// returning the numeric value itself as text -- rather than a fixed
/// "unknown" token -- keeps the surprising value visible instead of erasing
/// it.
[[nodiscard]] inline std::string usb_speed_name(std::int64_t device_speed) {
    switch (device_speed) {
    case 0: return "low";
    case 1: return "full";
    case 2: return "high";
    case 3: return "super";
    case 4: return "super+";
    default: return std::to_string(device_speed);
    }
}

/// Renders IOThunderboltSwitch's `UID` (a 64-bit integer IOKit already
/// decodes) as fixed-width lowercase hex16 -- the same fixed-width,
/// zero-padded convention peripherals_parsers.hpp's hex2/hex4/hex6 helpers
/// use for the other row fields.
[[nodiscard]] inline std::string uid_to_hex16(std::uint64_t uid) {
    return std::format("{:016x}", uid);
}

} // namespace yuzu::peripherals::macos
