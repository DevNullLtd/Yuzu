/**
 * test_peripherals_parsers.cpp — pure formatter/hex-helper/parse_kind tests
 * for the peripherals plugin. No plugin load, no OS call: everything here
 * exercises peripherals_parsers.hpp and peripherals_legs.hpp's pure surface
 * directly, mirroring disk_actions's "pure formatter tests" section
 * (test_disk_actions_local_dispatcher.cpp).
 */
#include <catch2/catch_test_macros.hpp>

#include "peripherals_legs.hpp"
#include "peripherals_parsers.hpp"

#include <string>
#include <vector>

namespace {

/// Escape-aware field split, same shape as every other plugin's dispatcher
/// test uses: yuzu::util::safe_output_field escapes a literal '|' as '\|',
/// so a naive split('|') overcounts fields on any row whose text happens to
/// contain a pipe.
std::vector<std::string> split_fields_escape_aware(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            cur += '|';
            ++i;
        } else if (row[i] == '|') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += row[i];
        }
    }
    out.push_back(cur);
    return out;
}

} // namespace

// ── hex helpers ───────────────────────────────────────────────────────────

TEST_CASE("peripherals: hex helpers are fixed-width, lowercase, zero-padded",
          "[peripherals][format]") {
    using namespace yuzu::peripherals;
    CHECK(hex2(0) == "00");
    CHECK(hex2(0xAB) == "ab");
    CHECK(hex2(0xFF) == "ff");
    CHECK(hex4(0) == "0000");
    CHECK(hex4(0x046D) == "046d");
    CHECK(hex4(0xFFFF) == "ffff");
    CHECK(hex6(0) == "000000");
    CHECK(hex6(0x030000) == "030000");
    // Masked to 24 bits: a class code is a 3-byte field and never wider, even
    // if a caller somehow hands in a larger value.
    CHECK(hex6(0xFF030000) == "030000");
}

// ── row formatters ────────────────────────────────────────────────────────

TEST_CASE("peripherals: usb row has the documented 11-field shape",
          "[peripherals][format]") {
    using namespace yuzu::peripherals;
    const auto r = format_usb_row("1-2.1", 0x046D, 0xC52B, 0x09, 0x00, "Logitech",
                                  "USB Receiver", "-", "480", false);
    CHECK(r == "usb|1-2.1|046d|c52b|09|00|Logitech|USB Receiver|-|480|0");
    const auto f = split_fields_escape_aware(r);
    REQUIRE(f.size() == 11);
    CHECK(f[0] == "usb");

    const auto hub = format_usb_row("1-2", 0x8087, 0x0AAA, 0x09, 0x00, "Intel", "Hub", "-",
                                    "5000", true);
    CHECK(hub.ends_with("|1"));
}

TEST_CASE("peripherals: pci row has the documented 9-field shape",
          "[peripherals][format]") {
    using namespace yuzu::peripherals;
    const auto r = format_pci_row("0000:00:02.0", 0x8086, 0x9A49, 0x030000, 0x1028, 0x0A5C,
                                  "i915", "Intel Iris Xe Graphics");
    CHECK(r == "pci|0000:00:02.0|8086|9a49|030000|1028|0a5c|i915|Intel Iris Xe Graphics");
    const auto f = split_fields_escape_aware(r);
    REQUIRE(f.size() == 9);
    CHECK(f[0] == "pci");
}

TEST_CASE("peripherals: thunderbolt row has the documented 8-field shape",
          "[peripherals][format]") {
    using namespace yuzu::peripherals;
    const auto r = format_thunderbolt_row("domain0/0-0", ThunderboltRole::HostController,
                                          "Apple Inc.", "-", "00340000-0044", "4", "1");
    CHECK(r == "thunderbolt|domain0/0-0|host_controller|Apple Inc.|-|00340000-0044|4|1");
    const auto f = split_fields_escape_aware(r);
    REQUIRE(f.size() == 8);
    CHECK(f[0] == "thunderbolt");
    CHECK(f[2] == "host_controller");

    const auto dev = format_thunderbolt_row("domain0/0-0/1-0", ThunderboltRole::Device, "-", "-",
                                             "-", "-", "-");
    const auto fd = split_fields_escape_aware(dev);
    REQUIRE(fd.size() == 8);
    CHECK(fd[2] == "device");
}

TEST_CASE("peripherals: untrusted fields cannot forge a column separator",
          "[peripherals][format]") {
    using namespace yuzu::peripherals;
    // vendor/product are OS-supplied text. If either could inject a bare '|'
    // it would shift every later column for a positional consumer.
    const auto r = format_usb_row("1-1", 0, 0, 0, 0, "EVIL|VENDOR", "p", "s", "sp", false);
    const auto f = split_fields_escape_aware(r);
    REQUIRE(f.size() == 11);
    CHECK(f[6] == "EVIL|VENDOR"); // round-trips through the escape, one field

    // role is a fixed vocabulary and must NOT be escapable at all -- it is
    // never fed untrusted text, only the enum's own token.
    const auto tb = format_thunderbolt_row("p", ThunderboltRole::Device, "EVIL|VENDOR", "-", "-",
                                           "-", "-");
    const auto ft = split_fields_escape_aware(tb);
    REQUIRE(ft.size() == 8);
    CHECK(ft[2] == "device");
    CHECK(ft[3] == "EVIL|VENDOR");
}

// ── none / unavailable placeholders ─────────────────────────────────────

TEST_CASE("peripherals: format_none_row and format_unavailable_row shapes",
          "[peripherals][format]") {
    using namespace yuzu::peripherals;
    CHECK(format_none_row("usb") == "usb|none");
    CHECK(format_none_row("pci") == "pci|none");
    CHECK(format_none_row("thunderbolt") == "thunderbolt|none");

    CHECK(format_unavailable_row("usb", "windows:leg:not_implemented") ==
          "usb|unavailable|windows:leg:not_implemented");
    CHECK(format_unavailable_row("pci", "linux:leg:not_implemented") ==
          "pci|unavailable|linux:leg:not_implemented");
    CHECK(format_unavailable_row("thunderbolt", "macos:leg:not_implemented") ==
          "thunderbolt|unavailable|macos:leg:not_implemented");
}

// ── Kind / kind_name / parse_kind ────────────────────────────────────────

TEST_CASE("peripherals: kind_name and parse_kind round-trip for every kind",
          "[peripherals][kind]") {
    using namespace yuzu::peripherals;
    CHECK(kind_name(Kind::usb) == "usb");
    CHECK(kind_name(Kind::pci) == "pci");
    CHECK(kind_name(Kind::thunderbolt) == "thunderbolt");

    const auto usb = parse_kind("usb");
    REQUIRE(usb.has_value());
    CHECK(*usb == Kind::usb);
    const auto pci = parse_kind("pci");
    REQUIRE(pci.has_value());
    CHECK(*pci == Kind::pci);
    const auto tb = parse_kind("thunderbolt");
    REQUIRE(tb.has_value());
    CHECK(*tb == Kind::thunderbolt);

    CHECK_FALSE(parse_kind("bluetooth").has_value()); // PR9.1c, deferred -- not this plugin
    CHECK_FALSE(parse_kind("").has_value());
    CHECK_FALSE(parse_kind("USB").has_value()); // case-sensitive: exact action-name match only
}
