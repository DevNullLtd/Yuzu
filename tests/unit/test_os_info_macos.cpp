// test_os_info_macos.cpp — os_info_macos.hpp's SystemVersion.plist extractor.
//
// Header-only and OS-free (like firewall_parsers.hpp/netprobe_stats.hpp), so
// this runs on every host, not just Darwin.
#include <catch2/catch_test_macros.hpp>

#include <os_info_macos.hpp>

using yuzu::os_info::parse_system_version_plist;

namespace {

// Verbatim /System/Library/CoreServices/SystemVersion.plist from the
// verification host (macOS 26.5.2, build 25F84) — real Apple-authored XML,
// not a hand-simplified stand-in.
constexpr std::string_view kRealPlist = R"(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>BuildID</key>
	<string>3FF138BC-7035-11F1-A491-5FE68ADA1E26</string>
	<key>ProductBuildVersion</key>
	<string>25F84</string>
	<key>ProductCopyright</key>
	<string>1983-2026 Apple Inc.</string>
	<key>ProductName</key>
	<string>macOS</string>
	<key>ProductUserVisibleVersion</key>
	<string>26.5.2</string>
	<key>ProductVersion</key>
	<string>26.5.2</string>
	<key>iOSSupportVersion</key>
	<string>26.5</string>
</dict>
</plist>
)";

} // namespace

TEST_CASE("parse_system_version_plist reads ProductName from the real host plist",
         "[agent][os_info]") {
    auto v = parse_system_version_plist(kRealPlist, "ProductName");
    REQUIRE(v.has_value());
    CHECK(*v == "macOS");
}

TEST_CASE("parse_system_version_plist reads ProductVersion and ProductBuildVersion",
         "[agent][os_info]") {
    auto version = parse_system_version_plist(kRealPlist, "ProductVersion");
    REQUIRE(version.has_value());
    CHECK(*version == "26.5.2");

    auto build = parse_system_version_plist(kRealPlist, "ProductBuildVersion");
    REQUIRE(build.has_value());
    CHECK(*build == "25F84");
}

TEST_CASE("parse_system_version_plist returns nullopt for a missing key", "[agent][os_info]") {
    auto v = parse_system_version_plist(kRealPlist, "NoSuchKey");
    CHECK_FALSE(v.has_value());
}

TEST_CASE("parse_system_version_plist returns nullopt on empty input", "[agent][os_info]") {
    CHECK_FALSE(parse_system_version_plist("", "ProductName").has_value());
}

TEST_CASE("parse_system_version_plist returns nullopt when the key has no following <string>",
         "[agent][os_info]") {
    // <key> present but the very next element is another <key>, not a
    // <string> value -- must not skip ahead to some later unrelated <string>.
    constexpr std::string_view malformed = R"(<dict>
	<key>ProductName</key>
	<key>ProductVersion</key>
	<string>26.5.2</string>
</dict>)";
    CHECK_FALSE(parse_system_version_plist(malformed, "ProductName").has_value());
}

TEST_CASE("parse_system_version_plist returns nullopt on a truncated <string>",
         "[agent][os_info]") {
    constexpr std::string_view truncated = R"(<dict>
	<key>ProductName</key>
	<string>macOS)";
    CHECK_FALSE(parse_system_version_plist(truncated, "ProductName").has_value());
}

TEST_CASE("parse_system_version_plist handles an empty <string> value", "[agent][os_info]") {
    constexpr std::string_view empty_value = R"(<dict>
	<key>ProductName</key>
	<string></string>
</dict>)";
    auto v = parse_system_version_plist(empty_value, "ProductName");
    REQUIRE(v.has_value());
    CHECK(v->empty());
}
