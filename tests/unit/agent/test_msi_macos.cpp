/**
 * test_msi_macos.cpp -- fixture-driven vectors for the macOS msi_packages
 * leg's pure `pkgutil --pkgs` / `pkgutil --pkg-info` parsers
 * (msi_packages_macos.hpp, C-1.21, P8).
 *
 * Everything here runs against captured/synthetic pkgutil text -- no
 * `pkgutil` subprocess, no real package receipts -- because the parser is
 * pure by design (same header-for-testability pattern as
 * installed_apps_inventory.hpp). Pins the honesty contract: a receipt that
 * is missing a field yields an EMPTY field, never a fabricated value, and a
 * malformed/empty receipt still yields a usable PkgInfo carrying the
 * requested id.
 */

#include <catch2/catch_test_macros.hpp>

#include <msi_packages_macos.hpp>

#include <algorithm>
#include <string>

using namespace yuzu::msi_packages::macos;

// ── parse_pkg_ids ──────────────────────────────────────────────────────────

TEST_CASE("parse_pkg_ids splits one identifier per line", "[msi][macos]") {
    const std::string output = "com.apple.pkg.Core\n"
                                "com.apple.pkg.BaseSystemBinaries\n"
                                "com.vendor.myapp\n";

    const auto ids = parse_pkg_ids(output);

    REQUIRE(ids.size() == 3);
    CHECK(ids[0] == "com.apple.pkg.Core");
    CHECK(ids[1] == "com.apple.pkg.BaseSystemBinaries");
    CHECK(ids[2] == "com.vendor.myapp");
}

TEST_CASE("parse_pkg_ids drops blank lines and tolerates CRLF", "[msi][macos]") {
    const std::string output = "com.apple.pkg.Core\r\n"
                                "\r\n"
                                "\n"
                                "com.vendor.myapp\r\n";

    const auto ids = parse_pkg_ids(output);

    REQUIRE(ids.size() == 2);
    CHECK(ids[0] == "com.apple.pkg.Core");
    CHECK(ids[1] == "com.vendor.myapp");
}

TEST_CASE("parse_pkg_ids on empty input yields an empty vector, never a crash",
          "[msi][macos]") {
    CHECK(parse_pkg_ids("").empty());
    CHECK(parse_pkg_ids("\n\n\n").empty());
}

// ── parse_pkg_info ─────────────────────────────────────────────────────────

TEST_CASE("parse_pkg_info parses a full pkg-info receipt", "[msi][macos]") {
    const std::string output = "package-id: com.vendor.myapp\n"
                                "version: 2.3.4\n"
                                "volume: /\n"
                                "location: /Applications/MyApp.app\n"
                                "install-time: 1720000000\n";

    const auto info = parse_pkg_info(output, "com.vendor.myapp");

    CHECK(info.identifier == "com.vendor.myapp");
    CHECK(info.version == "2.3.4");
    // volume "/" + location starting with "/" must NOT double up the slash.
    CHECK(info.install_location == "/Applications/MyApp.app");
}

TEST_CASE("parse_pkg_info joins a non-root volume with its location", "[msi][macos]") {
    const std::string output = "package-id: com.vendor.myapp\n"
                                "version: 1.0\n"
                                "volume: /Volumes/External\n"
                                "location: /Applications/MyApp.app\n";

    const auto info = parse_pkg_info(output, "com.vendor.myapp");

    CHECK(info.install_location == "/Volumes/External/Applications/MyApp.app");
}

TEST_CASE("parse_pkg_info falls back to the requested id when package-id is missing",
          "[msi][macos]") {
    const std::string output = "version: 1.0\n"
                                "volume: /\n"
                                "location: /Applications/MyApp.app\n";

    const auto info = parse_pkg_info(output, "com.vendor.myapp");

    CHECK(info.identifier == "com.vendor.myapp");
    CHECK(info.version == "1.0");
}

TEST_CASE("parse_pkg_info on malformed/empty input still yields a usable PkgInfo",
          "[msi][macos]") {
    SECTION("completely empty output") {
        const auto info = parse_pkg_info("", "com.vendor.myapp");
        CHECK(info.identifier == "com.vendor.myapp"); // requested id, never fabricated
        CHECK(info.version.empty());                  // honestly empty, not "-0" or "unknown"
        CHECK(info.install_location.empty());
    }
    SECTION("garbage lines with no colon separator") {
        const auto info = parse_pkg_info("this is not key: value formatted\nwhatever\n",
                                          "com.vendor.myapp");
        CHECK(info.identifier == "com.vendor.myapp");
    }
    SECTION("only a volume, no location") {
        const auto info = parse_pkg_info("volume: /\n", "com.vendor.myapp");
        CHECK(info.install_location == "/");
    }
}

TEST_CASE("parse_pkg_info ignores unknown keys", "[msi][macos]") {
    const std::string output = "package-id: com.vendor.myapp\n"
                                "receipt-plist-version: 1.2\n"
                                "install-time: 1720000000\n"
                                "version: 3.0\n";

    const auto info = parse_pkg_info(output, "com.vendor.myapp");

    CHECK(info.identifier == "com.vendor.myapp");
    CHECK(info.version == "3.0");
}

// ── derive_display_name ────────────────────────────────────────────────────

TEST_CASE("derive_display_name takes the last dot-segment of a reverse-domain id",
          "[msi][macos]") {
    CHECK(derive_display_name("com.apple.pkg.Core") == "Core");
    CHECK(derive_display_name("com.vendor.myapp") == "myapp");
}

TEST_CASE("derive_display_name falls back to the full identifier when there is no usable dot",
          "[msi][macos]") {
    SECTION("no dot at all") { CHECK(derive_display_name("standalone") == "standalone"); }
    SECTION("trailing dot has nothing after it") {
        CHECK(derive_display_name("com.vendor.") == "com.vendor.");
    }
    SECTION("empty identifier") { CHECK(derive_display_name("") == ""); }
}

// Round-4 review: every dynamic macOS package field must be pipe/newline-escaped
// before entering the positional `msi|...` / `product_code|...` protocol, so a
// pkgutil receipt id, version or install path containing '|' or a newline can't
// shift columns or inject a row downstream (plg-H1). safe_output_field escapes a
// field '|' to "\\|" and a newline to a space, so a positional parser splitting
// on UNESCAPED '|' sees only the structural separators.
namespace {
int count_unescaped_pipes(const std::string& s) {
    int n = 0;
    for (std::size_t i = 0; i < s.size(); ++i)
        if (s[i] == '|' && (i == 0 || s[i - 1] != '\\'))
            ++n;
    return n;
}
} // namespace

TEST_CASE("format_msi_row escapes pipe/newline in every dynamic field", "[msi][macos]") {
    PkgInfo info;
    info.identifier = "com.eviL|corp.pkg\nInjected"; // '|' AND newline in the id
    info.version = "1.0|2.0";
    info.install_location = "/opt/we|ird\npath";

    const std::string row = format_msi_row(info);
    CHECK(count_unescaped_pipes(row) == 4);      // only the 4 structural separators split columns
    CHECK(row.find('\n') == std::string::npos);  // newlines neutralised to spaces (no row injection)
    CHECK(row.starts_with("msi|"));
    CHECK(row.find("eviL\\|corp") != std::string::npos); // the field '|' was escaped, not dropped
}

TEST_CASE("format_product_code_row escapes pipe/newline in both fields", "[msi][macos]") {
    const std::string row = format_product_code_row("com.x|y.z\nrow2");
    CHECK(count_unescaped_pipes(row) == 2); // only the two structural separators
    CHECK(row.find('\n') == std::string::npos);
    CHECK(row.starts_with("product_code|"));
}
