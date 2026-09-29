/**
 * test_hardware_macos_bios.cpp — pure macOS Boot ROM / System Firmware
 * Version parser (hardware_macos_bios.hpp).
 *
 * Pins parse_boot_rom_version() against both Apple field labels: "Boot ROM
 * Version" (Intel Macs / older firmware) and "System Firmware Version"
 * (Apple Silicon) — the pre-Wave-3 grep-only implementation matched only the
 * former, silently emitting "unknown" on every Apple Silicon Mac.
 *
 * This header is platform-agnostic (not __APPLE__-gated) so these tests
 * compile and run on every host, matching the hardware_disks_macos.hpp /
 * test_hardware_disks_macos.cpp precedent.
 */

#include "hardware_macos_bios.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::hardware::macos;

TEST_CASE("parse_boot_rom_version: Apple Silicon 'System Firmware Version' label",
          "[hardware][macos][bios]") {
    static constexpr const char* kText =
        "Hardware:\n\n"
        "    Hardware Overview:\n\n"
        "      Model Name: MacBook Pro\n"
        "      Model Identifier: Mac14,9\n"
        "      Chip: Apple M2 Pro\n"
        "      System Firmware Version: 10151.101.3\n"
        "      OS Loader Version: 10151.101.3\n";
    CHECK(parse_boot_rom_version(kText) == "10151.101.3");
}

TEST_CASE("parse_boot_rom_version: Intel/legacy 'Boot ROM Version' label",
          "[hardware][macos][bios]") {
    static constexpr const char* kText =
        "Hardware:\n\n"
        "    Hardware Overview:\n\n"
        "      Model Name: MacBook Pro\n"
        "      Model Identifier: MacBookPro16,1\n"
        "      Boot ROM Version: 1731.140.3.0.0\n"
        "      SMC Version (system): 2.53f18\n";
    CHECK(parse_boot_rom_version(kText) == "1731.140.3.0.0");
}

TEST_CASE("parse_boot_rom_version: 'Boot ROM Version' is checked before 'System Firmware "
          "Version' when both are somehow present",
          "[hardware][macos][bios]") {
    // Not a real-world shape (a single Mac reports only one label), but pins
    // the documented precedence deterministically.
    static constexpr const char* kText =
        "Boot ROM Version: LEGACY.1\n"
        "System Firmware Version: 10151.101.3\n";
    CHECK(parse_boot_rom_version(kText) == "LEGACY.1");
}

TEST_CASE("parse_boot_rom_version: neither label present -> empty", "[hardware][macos][bios]") {
    static constexpr const char* kText = "Hardware:\n\n    Hardware Overview:\n\n      Model "
                                         "Name: MacBook Pro\n      Model Identifier: Mac14,9\n";
    CHECK(parse_boot_rom_version(kText).empty());
}

TEST_CASE("parse_boot_rom_version: empty input -> empty", "[hardware][macos][bios]") {
    CHECK(parse_boot_rom_version("").empty());
}

TEST_CASE("parse_boot_rom_version: label present but value empty (end of string) -> empty",
          "[hardware][macos][bios]") {
    static constexpr const char* kText = "System Firmware Version:";
    CHECK(parse_boot_rom_version(kText).empty());
}

TEST_CASE("parse_boot_rom_version: trailing \\r\\n is not included in the value",
          "[hardware][macos][bios]") {
    static constexpr const char* kText = "System Firmware Version: 10151.101.3\r\nNext Line: x\r\n";
    CHECK(parse_boot_rom_version(kText) == "10151.101.3");
}
