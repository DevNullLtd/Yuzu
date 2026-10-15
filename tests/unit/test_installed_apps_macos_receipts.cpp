/**
 * test_installed_apps_macos_receipts.cpp — installed_apps_macos_receipts.hpp's
 * pure plist-bytes parser (round-3 sync-speed fix, item 4).
 *
 * TEST-EFFICIENCY JUSTIFICATION (CLAUDE.md unit-suite discipline): this
 * exercises `parse_receipt_plist_bytes`, a PURE function over an in-memory
 * byte buffer — no subprocess, no live /var/db/receipts path, no root. The
 * fixture is a REAL captured receipt (tests/unit/fixtures/
 * com.apple.pkg.CLTools_Executables.plist, copied verbatim from
 * /Library/Apple/System/Library/Receipts/ on a real macOS host with Command
 * Line Tools installed — same discipline as test_autoruns_macos_local.cpp's
 * captured fixtures), not an invented byte layout — matching the "fixtures
 * must come from real captures" rule (three Wave-4 parsers shipped dead
 * against invented fixtures once already). The expected version/install-time
 * values were independently cross-checked against `plutil -p` and
 * `pkgutil --pkg-info com.apple.pkg.CLTools_Executables` on the SAME host
 * that produced the fixture (see the header's own doc comment on
 * cfdate_to_unix_epoch_string for the exact cross-check).
 */
#include <catch2/catch_test_macros.hpp>

#if defined(__APPLE__)

#include "installed_apps_macos_receipts.hpp"

#include <fstream>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> read_fixture(const char* name) {
    const std::string path = std::string(YUZU_TEST_FIXTURE_DIR) + "/" + name;
    std::ifstream f(path, std::ios::binary);
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(f),
                                     std::istreambuf_iterator<char>());
}

} // namespace

TEST_CASE("parse_receipt_plist_bytes decodes a real captured receipt",
          "[installed_apps][macos][receipts]") {
    const auto bytes = read_fixture("com.apple.pkg.CLTools_Executables.plist");
    REQUIRE_FALSE(bytes.empty()); // fixture missing/not checked in — fail loud, never SKIP-as-pass

    auto info = yuzu::installed_apps::macos_receipts::parse_receipt_plist_bytes(bytes);
    REQUIRE(info.has_value());
    // Cross-checked on the capturing host: `pkgutil --pkg-info
    // com.apple.pkg.CLTools_Executables` reported the identical version and
    // install-time for this exact receipt.
    CHECK(info->version == "26.6.0.0.1781586589");
    CHECK(info->install_time == "1787153822");
}

TEST_CASE("parse_receipt_plist_bytes rejects empty/undecodable/malformed input",
          "[installed_apps][macos][receipts]") {
    SECTION("empty buffer") {
        CHECK_FALSE(
            yuzu::installed_apps::macos_receipts::parse_receipt_plist_bytes({}).has_value());
    }
    SECTION("not a plist at all") {
        const std::vector<std::uint8_t> garbage{'n', 'o', 't', ' ', 'a', ' ', 'p', 'l', 'i', 's', 't'};
        CHECK_FALSE(
            yuzu::installed_apps::macos_receipts::parse_receipt_plist_bytes(garbage).has_value());
    }
    SECTION("a well-formed plist missing the expected keys") {
        // <plist><dict><key>Unrelated</key><string>x</string></dict></plist> —
        // decodes fine as a property list, but has neither PackageVersion nor
        // InstallDate, so this must still be a miss (falls back to pkgutil),
        // never a partially-populated PkgutilInfo.
        static const char kXml[] =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            "<plist version=\"1.0\"><dict><key>Unrelated</key><string>x</string></dict></plist>\n";
        const std::vector<std::uint8_t> bytes(kXml, kXml + sizeof(kXml) - 1);
        CHECK_FALSE(
            yuzu::installed_apps::macos_receipts::parse_receipt_plist_bytes(bytes).has_value());
    }
    SECTION("root is an array, not a dictionary") {
        static const char kXml[] =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            "<plist version=\"1.0\"><array/></plist>\n";
        const std::vector<std::uint8_t> bytes(kXml, kXml + sizeof(kXml) - 1);
        CHECK_FALSE(
            yuzu::installed_apps::macos_receipts::parse_receipt_plist_bytes(bytes).has_value());
    }
}

TEST_CASE("read_receipt_plist rejects a path-escaping id", "[installed_apps][macos][receipts]") {
    // id validation runs BEFORE any file I/O attempt — these must never touch
    // the filesystem outside the two fixed receipt directories.
    CHECK_FALSE(yuzu::installed_apps::macos_receipts::read_receipt_plist("").has_value());
    CHECK_FALSE(
        yuzu::installed_apps::macos_receipts::read_receipt_plist("../../etc/passwd").has_value());
    CHECK_FALSE(yuzu::installed_apps::macos_receipts::read_receipt_plist("com.apple.pkg/evil")
                    .has_value());
}

#endif // __APPLE__
