/**
 * test_peripherals_macos_parsers.cpp — unit coverage for
 * agents/plugins/peripherals/src/peripherals_macos_parsers.hpp.
 *
 * Pure decoders, no IOKit/CoreFoundation, so this TU builds and runs on
 * every OS (no `#ifndef _WIN32`/`#ifdef __APPLE__` guard) -- the same
 * portability the header itself has.
 *
 * Every value below is a REAL CAPTURE this Mac 2026-09-08 (braga.local,
 * macOS 26.6.2/Darwin 25.6.0): the exact bytes/integers
 * tests/unit/fixtures/wave9/peripherals/macos/ captured from
 * `ioreg -a -r -c IOUSBHostDevice -d 1`, `-c IOThunderboltSwitch -d 1`, and
 * the grep-extracted `ioreg -l -r -c IOPCIDevice -d 1` subset -- not
 * invented fixtures.
 */
#include <catch2/catch_test_macros.hpp>

#include "peripherals_macos_parsers.hpp"

#include <cstdint>
#include <string>

using namespace yuzu::peripherals::macos;

// ── matching_succeeded ───────────────────────────────────────────────────
// The contract this classification exists to enforce: "matching failure ->
// CONSTRAINED + macos:iokit:matching_failed, never an empty OK." Isolated
// here because for_each_service (peripherals_macos.cpp) calls the real
// IOKit API directly with no injected boundary, so this is the only path a
// unit test can exercise it. Plain int in (not kern_return_t/KERN_SUCCESS)
// -- see matching_succeeded's own comment: pulling IOKit/Mach headers into
// this file would break its "builds on every OS" contract, so a nonzero int
// stands in for any real IOKit failure code without naming one.

TEST_CASE("matching_succeeded: KERN_SUCCESS (0) is success", "[peripherals][macos]") {
    CHECK(matching_succeeded(0));
}

TEST_CASE("matching_succeeded: any nonzero code is not success", "[peripherals][macos]") {
    CHECK_FALSE(matching_succeeded(1));
    CHECK_FALSE(matching_succeeded(-1));
}

// ── decode_le_u32 ────────────────────────────────────────────────────────
// REAL CAPTURE this Mac 2026-09-08: the wlan@0 IOPCIDevice node's OSData
// properties from ioreg_iopcidevice_extract.txt (Broadcom BCM4364, vendor
// 0x14e4 device 0x4434, subsystem 0x106b/0x4388 -- Apple's own subsystem
// IDs on its wifi/BT combo card).

TEST_CASE("decode_le_u32: REAL CAPTURE this Mac 2026-09-08 vendor-id", "[peripherals][macos]") {
    const std::string bytes{'\xe4', '\x14', '\x00', '\x00'};
    CHECK(decode_le_u32(bytes) == 0x14e4u);
}

TEST_CASE("decode_le_u32: REAL CAPTURE this Mac 2026-09-08 device-id", "[peripherals][macos]") {
    const std::string bytes{'\x34', '\x44', '\x00', '\x00'};
    CHECK(decode_le_u32(bytes) == 0x4434u);
}

TEST_CASE("decode_le_u32: REAL CAPTURE this Mac 2026-09-08 class-code", "[peripherals][macos]") {
    const std::string bytes{'\x00', '\x80', '\x02', '\x00'};
    CHECK(decode_le_u32(bytes) == 0x028000u);
}

TEST_CASE("decode_le_u32: REAL CAPTURE this Mac 2026-09-08 subsystem-vendor-id",
          "[peripherals][macos]") {
    const std::string bytes{'\x6b', '\x10', '\x00', '\x00'};
    CHECK(decode_le_u32(bytes) == 0x106bu);
}

TEST_CASE("decode_le_u32: REAL CAPTURE this Mac 2026-09-08 subsystem-id", "[peripherals][macos]") {
    const std::string bytes{'\x88', '\x43', '\x00', '\x00'};
    CHECK(decode_le_u32(bytes) == 0x4388u);
}

TEST_CASE("decode_le_u32: a short buffer decodes to 0, not garbage", "[peripherals][macos]") {
    CHECK(decode_le_u32("") == 0u);
    CHECK(decode_le_u32(std::string{'\x01', '\x02', '\x03'}) == 0u);
}

// ── usb_speed_name ───────────────────────────────────────────────────────
// REAL CAPTURE this Mac 2026-09-08: ioreg_iousbhostdevice.plist's two
// IOUSBHostDevice nodes carry `Device Speed` 2 (USB2 Hub) and 4 (USB3 Gen2
// Hub) -- the full 0-4 vocabulary is exercised below, not just the two this
// Mac happens to have.

TEST_CASE("usb_speed_name: REAL CAPTURE this Mac 2026-09-08 USB2 Hub (Device Speed 2)",
          "[peripherals][macos]") {
    CHECK(usb_speed_name(2) == "high");
}

TEST_CASE("usb_speed_name: REAL CAPTURE this Mac 2026-09-08 USB3 Gen2 Hub (Device Speed 4)",
          "[peripherals][macos]") {
    CHECK(usb_speed_name(4) == "super+");
}

TEST_CASE("usb_speed_name: full 0-4 vocabulary", "[peripherals][macos]") {
    CHECK(usb_speed_name(0) == "low");
    CHECK(usb_speed_name(1) == "full");
    CHECK(usb_speed_name(3) == "super");
}

TEST_CASE("usb_speed_name: an out-of-range value stays visible as text, not erased",
          "[peripherals][macos]") {
    CHECK(usb_speed_name(-1) == "-1");
    CHECK(usb_speed_name(9) == "9");
}

// ── uid_to_hex16 ─────────────────────────────────────────────────────────
// REAL CAPTURE this Mac 2026-09-08: ioreg_iothunderboltswitch.plist's three
// IOThunderboltSwitchType5 nodes' `UID` integers.

TEST_CASE("uid_to_hex16: REAL CAPTURE this Mac 2026-09-08 first switch UID",
          "[peripherals][macos]") {
    CHECK(uid_to_hex16(408803588609184944ull) == "05ac5cb2a9f494b0");
}

TEST_CASE("uid_to_hex16: REAL CAPTURE this Mac 2026-09-08 second switch UID",
          "[peripherals][macos]") {
    CHECK(uid_to_hex16(408803588609184945ull) == "05ac5cb2a9f494b1");
}

TEST_CASE("uid_to_hex16: REAL CAPTURE this Mac 2026-09-08 third switch UID",
          "[peripherals][macos]") {
    CHECK(uid_to_hex16(408803588609184947ull) == "05ac5cb2a9f494b3");
}

TEST_CASE("uid_to_hex16: zero pads to full width", "[peripherals][macos]") {
    CHECK(uid_to_hex16(0) == "0000000000000000");
}
