/**
 * test_peripherals_win_parsers.cpp — pure parser tests for
 * peripherals_win_parsers.hpp against P91-3's REAL CAPTURE the-rig
 * 2026-09-08 SetupAPI dumps (tests/unit/fixtures/wave9/peripherals/windows/
 * setupapi_usb.txt, setupapi_pci.txt). No windows.h, no plugin load: this
 * exercises the pure parsing surface directly, same shape
 * test_execution_artifacts_parsers.cpp's fixture_dir()/REQUIRE(exists) uses.
 *
 * Fixtures are REQUIRE(fs::exists) -- never SKIP, per this package's spec.
 */
#include "peripherals_win_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::peripherals::win;
namespace fs = std::filesystem;

namespace {

fs::path fixture_dir() {
    return fs::path{YUZU_TEST_FIXTURE_DIR} / "wave9" / "peripherals" / "windows";
}

std::vector<std::string> read_lines(const fs::path& path) {
    REQUIRE(fs::exists(path));
    std::ifstream f(path);
    REQUIRE(f.is_open());
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            lines.push_back(line);
    }
    return lines;
}

} // namespace

// ── parse_setupapi_dump_line: every line of both captures parses ────────

TEST_CASE("peripherals win: parse_setupapi_dump_line parses every USB capture line",
          "[peripherals][windows][format]") {
    const auto lines = read_lines(fixture_dir() / "setupapi_usb.txt");
    REQUIRE_FALSE(lines.empty());
    for (const auto& line : lines) {
        const auto rec = parse_setupapi_dump_line(line);
        REQUIRE(rec.has_value());
        CHECK(rec->enumerator == "USB");
        CHECK_FALSE(rec->instance_id.empty());
        CHECK_FALSE(rec->hardware_ids.empty());
    }
}

TEST_CASE("peripherals win: parse_setupapi_dump_line parses every PCI capture line",
          "[peripherals][windows][format]") {
    const auto lines = read_lines(fixture_dir() / "setupapi_pci.txt");
    REQUIRE_FALSE(lines.empty());
    for (const auto& line : lines) {
        const auto rec = parse_setupapi_dump_line(line);
        REQUIRE(rec.has_value());
        CHECK(rec->enumerator == "PCI");
        CHECK_FALSE(rec->instance_id.empty());
        CHECK_FALSE(rec->hardware_ids.empty());
    }
}

TEST_CASE("peripherals win: parse_setupapi_dump_line rejects malformed input",
          "[peripherals][windows][format]") {
    CHECK_FALSE(parse_setupapi_dump_line("").has_value());
    CHECK_FALSE(parse_setupapi_dump_line("USB\tonly\ttwo").has_value());
}

// ── parse_usb_hardware_id / parse_usb_compatible_class: real VID/PID ────

TEST_CASE("peripherals win: parse_usb_hardware_id yields a concrete VID/PID from the capture",
          "[peripherals][windows][format]") {
    const auto lines = read_lines(fixture_dir() / "setupapi_usb.txt");
    std::set<std::pair<std::uint16_t, std::uint16_t>> seen;
    for (const auto& line : lines) {
        const auto rec = parse_setupapi_dump_line(line);
        REQUIRE(rec.has_value());
        for (const auto& hwid : rec->hardware_ids) {
            if (const auto ids = parse_usb_hardware_id(hwid))
                seen.emplace(ids->vendor_id, ids->product_id);
        }
    }
    // Logitech receiver, VID_046D&PID_C548, is real capture line 1's primary
    // hardware id -- a concrete, non-fabricated VID/PID pair.
    CHECK(seen.contains(std::pair<std::uint16_t, std::uint16_t>{
        static_cast<std::uint16_t>(0x046D), static_cast<std::uint16_t>(0xC548)}));
    CHECK_FALSE(seen.empty());
}

TEST_CASE("peripherals win: parse_usb_hardware_id rejects a hardware id missing either token",
          "[peripherals][windows][format]") {
    CHECK_FALSE(parse_usb_hardware_id("USB\\VID_046D").has_value());
    CHECK_FALSE(parse_usb_hardware_id("USB\\PID_C548").has_value());
    CHECK_FALSE(parse_usb_hardware_id("USB\\ROOT_HUB30").has_value());
}

TEST_CASE("peripherals win: parse_usb_hardware_id falls back to a root hub's underscore-less "
          "VID/PID form",
          "[peripherals][windows][format]") {
    // Real capture: tests/unit/fixtures/wave9/peripherals/windows/setupapi_usb.txt:7 --
    // "USB\ROOT_HUB30&VID1022&PID149C&REV0000" (no "VID_"/"PID_" marker, unlike every
    // other device on the bus). The standard "VID_"/"PID_" form still wins when present
    // (the primary marker is tried first).
    const auto ids = parse_usb_hardware_id("USB\\ROOT_HUB30&VID1022&PID149C&REV0000");
    REQUIRE(ids.has_value());
    CHECK(ids->vendor_id == 0x1022);
    CHECK(ids->product_id == 0x149C);

    const auto standard = parse_usb_hardware_id("USB\\VID_046D&PID_C548&REV_0503");
    REQUIRE(standard.has_value());
    CHECK(standard->vendor_id == 0x046D);
    CHECK(standard->product_id == 0xC548);
}

TEST_CASE("peripherals win: parse_usb_compatible_class parses the documented Class/SubClass/Prot form",
          "[peripherals][windows][format]") {
    const auto cls = parse_usb_compatible_class("USB\\Class_09&SubClass_00&Prot_01");
    REQUIRE(cls.has_value());
    CHECK(cls->usb_class == 0x09);
    CHECK(cls->subclass == 0x00);
    CHECK(cls->protocol == 0x01);

    // Prot_ is optional -- class/subclass alone still parses.
    const auto no_prot = parse_usb_compatible_class("USB\\Class_08&SubClass_06");
    REQUIRE(no_prot.has_value());
    CHECK(no_prot->usb_class == 0x08);
    CHECK(no_prot->protocol == 0x00);

    CHECK_FALSE(parse_usb_compatible_class("USB\\COMPOSITE").has_value());
}

namespace {

// Mirrors peripherals_win.cpp's emit_usb_row is_hub heuristic exactly (that
// function is file-local and not unit-callable): a ROOT_HUB hardware id, a
// "USB\Class_09" compatible id, or a "..._HUB" compatible id (a non-root
// generic hub's sole compatible id -- real capture lines 8/14/22 --
// "USB\USB20_HUB"/"USB\USB30_HUB", neither of which is Class_09).
bool is_hub_heuristic(const std::vector<std::string>& hardware_ids,
                      const std::vector<std::string>& compatible_ids) {
    for (const auto& h : hardware_ids)
        if (h.find("ROOT_HUB") != std::string::npos)
            return true;
    for (const auto& c : compatible_ids)
        if (c.find("USB\\Class_09") != std::string::npos || c.find("_HUB") != std::string::npos)
            return true;
    return false;
}

} // namespace

TEST_CASE("peripherals win: is_hub recognizes Class_09, a generic hub's _HUB compatible id, "
          "and a root hub's empty-compatible-ids/ROOT_HUB shape",
          "[peripherals][windows][format]") {
    CHECK(is_hub_heuristic({}, {"USB\\Class_09&SubClass_00&Prot_02"}));
    CHECK_FALSE(is_hub_heuristic({}, {"USB\\COMPAT_VID_046d&Class_03&SubClass_00&Prot_00",
                                      "USB\\Class_03&SubClass_00&Prot_00"}));

    // Real capture: setupapi_usb.txt:7 -- root hub, hardware id carries
    // ROOT_HUB, compatible-ids list is EMPTY.
    CHECK(is_hub_heuristic({"USB\\ROOT_HUB30&VID1022&PID149C&REV0000"}, {}));

    // Real capture: setupapi_usb.txt:8 -- generic external hub, compatible-ids
    // is the single literal token "USB\USB30_HUB" (no Class_09 anywhere).
    CHECK(is_hub_heuristic({"USB\\VID_174C&PID_3074&REV_0001"}, {"USB\\USB30_HUB"}));

    // Real capture: setupapi_usb.txt:1 -- an ordinary HID composite child,
    // neither shape should fire.
    CHECK_FALSE(is_hub_heuristic(
        {"USB\\VID_046D&PID_C548&REV_0503&MI_03"},
        {"USB\\COMPAT_VID_046d&Class_03&SubClass_00&Prot_00", "USB\\Class_03&SubClass_00"}));
}

// ── parse_pci_hardware_id / parse_pci_class_code: real VEN/DEV ──────────

TEST_CASE("peripherals win: parse_pci_hardware_id yields a concrete VEN/DEV from the capture",
          "[peripherals][windows][format]") {
    const auto lines = read_lines(fixture_dir() / "setupapi_pci.txt");
    std::set<std::pair<std::uint16_t, std::uint16_t>> seen;
    for (const auto& line : lines) {
        const auto rec = parse_setupapi_dump_line(line);
        REQUIRE(rec.has_value());
        for (const auto& hwid : rec->hardware_ids) {
            if (const auto ids = parse_pci_hardware_id(hwid))
                seen.emplace(ids->vendor_id, ids->device_id);
        }
    }
    // The RTX 3060 Ti, VEN_10DE&DEV_2489, is real capture line 46 -- a
    // concrete, non-fabricated VEN/DEV pair.
    CHECK(seen.contains(std::pair<std::uint16_t, std::uint16_t>{
        static_cast<std::uint16_t>(0x10DE), static_cast<std::uint16_t>(0x2489)}));
    CHECK_FALSE(seen.empty());
}

TEST_CASE("peripherals win: parse_pci_class_code reads the full 6-digit CC_ form",
          "[peripherals][windows][format]") {
    // The USB xHCI host controller's alt id (capture line 9): CC_0C0330 ->
    // base 0C (serial bus controller), sub 03 (USB), prog-if 30 (xHCI).
    const auto cc = parse_pci_class_code("PCI\\VEN_1022&DEV_149C&CC_0C0330");
    REQUIRE(cc.has_value());
    CHECK(*cc == 0x0C0330u);

    CHECK_FALSE(parse_pci_class_code("PCI\\VEN_1022&DEV_149C").has_value());
}

TEST_CASE("peripherals win: parse_pci_hardware_id rejects a hardware id missing either token",
          "[peripherals][windows][format]") {
    CHECK_FALSE(parse_pci_hardware_id("PCI\\VEN_8086").has_value());
    CHECK_FALSE(parse_pci_hardware_id("PCI\\CC_0C0330").has_value());
}

// ── is_thunderbolt_desc ───────────────────────────────────────────────────

TEST_CASE("peripherals win: is_thunderbolt_desc matches Thunderbolt/USB4, case-insensitively",
          "[peripherals][windows][format]") {
    CHECK(is_thunderbolt_desc("Intel(R) Thunderbolt(TM) 4 USB Controller"));
    CHECK(is_thunderbolt_desc("THUNDERBOLT NHI"));
    CHECK(is_thunderbolt_desc("USB4 Host Router"));
    CHECK(is_thunderbolt_desc("usb4 host router"));
    CHECK_FALSE(is_thunderbolt_desc("USB xHCI Compliant Host Controller"));
    CHECK_FALSE(is_thunderbolt_desc("NVIDIA GeForce RTX 3060 Ti"));
    CHECK_FALSE(is_thunderbolt_desc(""));
}

// None of this capture's real PCI descriptions are Thunderbolt controllers
// (the-rig has none), so this asserts the negative against every real
// DEVICEDESC in the fixture rather than fabricating a positive one.
TEST_CASE("peripherals win: is_thunderbolt_desc is false for every real capture description",
          "[peripherals][windows][format]") {
    const auto lines = read_lines(fixture_dir() / "setupapi_pci.txt");
    REQUIRE_FALSE(lines.empty());
    for (const auto& line : lines) {
        const auto rec = parse_setupapi_dump_line(line);
        REQUIRE(rec.has_value());
        CHECK_FALSE(is_thunderbolt_desc(rec->devicedesc));
    }
}
