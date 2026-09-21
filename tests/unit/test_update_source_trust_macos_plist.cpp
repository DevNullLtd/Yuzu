/**
 * test_update_source_trust_macos_plist.cpp -- CoreFoundation plist decode tests
 * for the macOS leg (parse_swu_plist_bytes in update_source_trust_macos_parsers.hpp).
 *
 * The TU itself is UNGUARDED (it compiles on every OS); only the test BODIES are
 * `#ifdef __APPLE__`, because CFPropertyListCreateWithData exists nowhere else.
 * The absent / EACCES / tree-walk cases for swu_rows_at are P1d-2's suite.
 *
 * Fixtures (tests/unit/fixtures/wave10/update_source_trust/macos/, see
 * provenance.txt there):
 *   com.apple.SoftwareUpdate.local.plist    REAL CAPTURE of this Mac's
 *                                           /Library/Preferences plist, stored as
 *                                           XML (plutil -convert xml1 of the binary
 *                                           original) so it diffs as text; the
 *                                           binary decode path is exercised by
 *                                           re-encoding it in-test.
 *   com.apple.SoftwareUpdate.managed.plist  RECONSTRUCTION from Apple's documented
 *                                           payload keys -- the managed leg has
 *                                           never run against a real MDM host.
 * Wrong-type and malformed inputs are built inline and are RECONSTRUCTIONS.
 */
#include <catch2/catch_test_macros.hpp>

#ifdef __APPLE__

#include "update_source_trust_macos_parsers.hpp"

#include <CoreFoundation/CoreFoundation.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace ust = yuzu::update_source_trust;

namespace {

std::string read_fixture(const char* name) {
#ifdef YUZU_TEST_FIXTURE_DIR
    const std::filesystem::path p =
        std::filesystem::path(YUZU_TEST_FIXTURE_DIR) / "wave10" / "update_source_trust" / "macos" / name;
#else
    const std::filesystem::path p =
        std::filesystem::path("tests/unit/fixtures/wave10/update_source_trust/macos") / name;
#endif
    std::ifstream f(p, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

// Re-encodes an XML plist as an Apple binary plist ("bplist00"), so the real
// capture reaches parse_swu_plist_bytes in the on-disk format real hosts use.
// Empty string on any CF failure (the calling REQUIRE then fails loudly).
std::string to_binary_plist(const std::string& xml) {
    std::string out;
    CFDataRef in = CFDataCreate(kCFAllocatorDefault, reinterpret_cast<const UInt8*>(xml.data()),
                                static_cast<CFIndex>(xml.size()));
    if (!in)
        return out;
    CFPropertyListRef plist =
        CFPropertyListCreateWithData(kCFAllocatorDefault, in, kCFPropertyListImmutable, nullptr, nullptr);
    CFRelease(in);
    if (!plist)
        return out;
    CFDataRef bin = CFPropertyListCreateData(kCFAllocatorDefault, plist, kCFPropertyListBinaryFormat_v1_0,
                                             0, nullptr);
    CFRelease(plist);
    if (!bin)
        return out;
    out.assign(reinterpret_cast<const char*>(CFDataGetBytePtr(bin)),
               static_cast<std::size_t>(CFDataGetLength(bin)));
    CFRelease(bin);
    return out;
}

std::string xml_plist(const std::string& body) {
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
           "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
           "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
           "<plist version=\"1.0\">\n" +
           body + "\n</plist>\n";
}

} // namespace

TEST_CASE("parse_swu_plist_bytes: REAL CAPTURE local plist yields this host's policy (XML and binary)",
          "[update_source_trust][macos_plist]") {
    const std::string xml = read_fixture("com.apple.SoftwareUpdate.local.plist");
    REQUIRE(xml.size() > 8);
    REQUIRE(xml.substr(0, 5) == "<?xml");
    const std::string bytes = to_binary_plist(xml);
    REQUIRE(bytes.size() > 8);
    REQUIRE(bytes.substr(0, 6) == "bplist"); // proves a BINARY plist went through CF

    const auto facts = ust::mac::parse_swu_plist_bytes(bytes);
    REQUIRE(facts.has_value());
    // The XML form of the same capture decodes to the same facts.
    const auto xml_facts = ust::mac::parse_swu_plist_bytes(xml);
    REQUIRE(xml_facts.has_value());
    CHECK(ust::format_swu_row(ust::SwuScope::local, *xml_facts) ==
          ust::format_swu_row(ust::SwuScope::local, *facts));
    // MUTATION: removing the CFDictionary reads (or a wrong key spelling) turns
    // these `yes` into `unset` and fails the exact row below.
    CHECK(facts->auto_download == ust::Tri::yes);
    CHECK(facts->auto_install_macos == ust::Tri::yes);
    CHECK(facts->config_data_install == ust::Tri::yes);
    CHECK(facts->critical_update_install == ust::Tri::yes);
    // Keys this host does not set are ABSENT, distinct from `no` and `unmodelled`.
    CHECK(facts->auto_check == ust::Tri::unset);
    CHECK(facts->allow_prerelease == ust::Tri::unset);
    CHECK(facts->catalog_url.empty());

    CHECK(ust::format_swu_row(ust::SwuScope::local, *facts) ==
          "macos_swu|local|-|unset|yes|yes|yes|yes|unset");
}

TEST_CASE("parse_swu_plist_bytes: RECONSTRUCTED managed plist populates every field",
          "[update_source_trust][macos_plist]") {
    const std::string bytes = read_fixture("com.apple.SoftwareUpdate.managed.plist");
    REQUIRE_FALSE(bytes.empty());

    const auto facts = ust::mac::parse_swu_plist_bytes(bytes);
    REQUIRE(facts.has_value());
    CHECK(facts->catalog_url ==
          "https://swscan.example.com/content/catalogs/others/index-15-14-13.merged-1.sucatalog");
    CHECK(facts->auto_check == ust::Tri::yes);
    CHECK(facts->auto_download == ust::Tri::yes);
    CHECK(facts->auto_install_macos == ust::Tri::no); // explicit false is `no`, not `unset`
    CHECK(facts->config_data_install == ust::Tri::yes);
    CHECK(facts->critical_update_install == ust::Tri::yes);
    CHECK(facts->allow_prerelease == ust::Tri::no);

    CHECK(ust::format_swu_row(ust::SwuScope::managed, *facts) ==
          "macos_swu|managed|"
          "https://swscan.example.com/content/catalogs/others/index-15-14-13.merged-1.sucatalog|"
          "yes|yes|no|yes|yes|no");
}

TEST_CASE("parse_swu_plist_bytes: a value of the wrong CF type is unmodelled, never coerced",
          "[update_source_trust][macos_plist]") {
    // RECONSTRUCTION: bool keys holding a string / an integer, CatalogURL an integer.
    const auto facts = ust::mac::parse_swu_plist_bytes(xml_plist(
        "<dict>\n"
        "<key>AutomaticDownload</key><string>true</string>\n"
        "<key>AutomaticCheckEnabled</key><integer>1</integer>\n"
        "<key>CatalogURL</key><integer>7</integer>\n"
        "<key>CriticalUpdateInstall</key><true/>\n"
        "</dict>"));
    REQUIRE(facts.has_value());
    CHECK(facts->auto_download == ust::Tri::unmodelled);
    CHECK(facts->auto_check == ust::Tri::unmodelled);
    CHECK(facts->catalog_url == "unmodelled");
    CHECK(facts->critical_update_install == ust::Tri::yes); // a good sibling is unaffected
    CHECK(facts->config_data_install == ust::Tri::unset);   // absent stays absent
}

TEST_CASE("parse_swu_plist_bytes: undecodable bytes and a non-dictionary root are rejected",
          "[update_source_trust][macos_plist]") {
    CHECK_FALSE(ust::mac::parse_swu_plist_bytes("").has_value());
    CHECK_FALSE(ust::mac::parse_swu_plist_bytes("this is not a property list").has_value());
    // Decodes fine as a plist but the root is an array, not a dictionary.
    CHECK_FALSE(ust::mac::parse_swu_plist_bytes(xml_plist("<array><string>x</string></array>")).has_value());
    // Truncated XML.
    CHECK_FALSE(ust::mac::parse_swu_plist_bytes(xml_plist("<dict><key>AutomaticDownload</key>")).has_value());
}

#endif // __APPLE__
