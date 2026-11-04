/**
 * test_pkg_inventory_win_parsers.cpp -- the pkg_inventory Windows legs
 * (pkg_inventory_win_parsers.hpp): the nuspec tag scanner, the Appx PackageFullName
 * parser, the row builders and the three legs, over an injected ops seam.
 *
 * RUNS ON EVERY OS. The legs are templates over a portable-typed ops seam, so the
 * whole decision layer is driven here by a FakeOps on macOS and Linux as well as
 * Windows. Only the `RealOps` cases at the bottom are `_WIN32`-only.
 *
 * PROVENANCE OF THE DATA. REAL = copied from the 2026-11-04 capture of the Windows
 * 11 (10.0.26200) build host kingsley, run as the interactive admin user (not the
 * agent's service account, which is unverified): the 18 chocolatey lib directories
 * and their versions (`choco list --local-only -r`), the loose-nuspec presence per
 * directory (including `chocolatey` having none), the jq nuspec verbatim, the first
 * lines of the 7zip nuspec, the first six `Applications` and `InboxApplications`
 * roster key names with their `Path` shapes, the absent `Deprovisioned` key, and
 * the Microsoft.DesktopAppInstaller 1.29.379.0 package. SYNTHETIC = everything
 * marked so: the other 17 nuspec bodies (a minimal element carrying the captured
 * version), the `Path` value of the DesktopAppInstaller key (the capture recorded
 * its InstallLocation, not the registry value), every degraded, hostile and budget
 * layout. The real service-account (NT SERVICE\YuzuAgent) ACL behaviour is NOT
 * exercised by anything here.
 *
 * TEST-EFFICIENCY: in-memory fakes, no process, no timing; the one temp file and the
 * one HKCU scratch key (Windows only) are justified at their cases.
 */
#include <catch2/catch_test_macros.hpp>

#include "pkg_inventory_legs.hpp"
#include "pkg_inventory_parsers.hpp"
#include "pkg_inventory_win_parsers.hpp"

#include "local_dispatcher.hpp"
#include "pkg_inventory_test_support.hpp"
#include "test_helpers.hpp"

#include <yuzu/plugin.h>

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <win_bounded_file_read.hpp>
#include <win_reg_handle.hpp>

#include <cwchar>
#endif

namespace {

namespace pi = yuzu::pkg_inventory;
namespace pw = yuzu::pkg_inventory::win;
using yuzu::shared::ConstraintAccumulator;
using yuzu::test::pkg_inventory_support::captured_rows;

// -- REAL data ---------------------------------------------------------------------------------

// The jq nuspec, verbatim (1152 bytes on the host).
const char* const kJqNuspec =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<package xmlns=\"http://schemas.microsoft.com/packaging/2011/08/nuspec.xsd\">\n"
    "  <metadata>\n"
    "    <id>jq</id>\n"
    "    <version>1.8.2</version>\n"
    "    <title>jq</title>\n"
    "    <authors>https://github.com/jqlang/jq/blob/master/AUTHORS</authors>\n"
    "    <owners>mjarosie,svnpenn</owners>\n"
    "    <requireLicenseAcceptance>false</requireLicenseAcceptance>\n"
    "    <licenseUrl>https://github.com/jqlang/jq/blob/master/COPYING</licenseUrl>\n"
    "    <projectUrl>https://jqlang.github.io/jq/</projectUrl>\n"
    "    <iconUrl>https://cdn.statically.io/gh/jqlang/jq/jq-1.8.2/docs/public/icon.png</iconUrl>\n"
    "    <description>`jq` is a lightweight and flexible command-line JSON processor.</description>\n"
    "    <summary>Command-line JSON processor</summary>\n"
    "    <copyright>2012 Stephen Dolan</copyright>\n"
    "    <tags>jq json</tags>\n"
    "    <projectSourceUrl>https://github.com/jqlang/jq</projectSourceUrl>\n"
    "    <packageSourceUrl>https://github.com/mjarosie/jq-chocolatey-package</packageSourceUrl>\n"
    "    <docsUrl>https://jqlang.github.io/jq/manual/</docsUrl>\n"
    "    <bugTrackerUrl>https://github.com/jqlang/jq/issues</bugTrackerUrl>\n"
    "  </metadata>\n"
    "</package>\n";

// The first lines of the 7zip nuspec (real; the file is 2910 bytes, cut after <version>).
const char* const k7zipNuspecHead =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<package xmlns=\"http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd\">\n"
    "  <metadata>\n"
    "    <id>7zip</id>\n"
    "    <version>26.5.0</version>\n";

struct ChocoDir {
    const char* dir;
    const char* version; // `choco list --local-only -r` (REAL); "" = no loose nuspec (REAL)
};
// All 18 lib directories of the capture host, in `choco list` order.
const ChocoDir kChocoLib[] = {
    {"7zip", "26.5.0"},
    {"7zip.install", "26.5.0"},
    {"chocolatey", ""}, // lib\chocolatey holds only chocolatey.nupkg
    {"chocolatey-compatibility.extension", "1.0.0"},
    {"chocolatey-core.extension", "1.4.0"},
    {"chocolatey-windowsupdate.extension", "1.0.5"},
    {"dotnet-8.0-runtime", "8.0.33"},
    {"dotnet-9.0-runtime", "9.0.22"},
    {"jq", "1.8.2"},
    {"KB2919355", "1.0.20160915"}, // nuspec file is kb2919355.nuspec on disk (NTFS: case-blind)
    {"KB2919442", "1.0.20160915"},
    {"KB2999226", "1.0.20181019"},
    {"KB3033929", "1.0.5"},
    {"KB3035131", "1.0.3"},
    {"microsoft-openjdk-21", "21.0.12.1"},
    {"notepadplusplus", "8.9.8.1"},
    {"notepadplusplus.install", "8.9.8.1"},
    {"Temurin21", "21.0.13"}, // nuspec file is temurin21.nuspec on disk
    {"vcredist140", "14.51.36247"},
};
// The capture listed 19 lib directories; 18 hold a loose nuspec.
constexpr std::size_t kChocoLibDirs = sizeof(kChocoLib) / sizeof(kChocoLib[0]);

// Roster key names (REAL, first six of each key on the capture host).
const char* const kApplications[] = {
    "AdvancedMicroDevicesInc-RSXCM_22.10.0.0_x64__v2es6h43hjn86",
    "Clipchamp.Clipchamp_4.7.10220.0_neutral_~_yxz26nhyzhsrt",
    "Microsoft.ApplicationCompatibilityEnhancements_1.2511.9.0_neutral_~_8wekyb3d8bbwe",
    "Microsoft.AV1VideoExtension_2.0.35.0_neutral_~_8wekyb3d8bbwe",
    "Microsoft.AVCEncoderVideoExtension_1.1.47.0_neutral_~_8wekyb3d8bbwe",
    "Microsoft.BingNews_4.1.24002.0_neutral_~_8wekyb3d8bbwe",
};
const char* const kInbox[] = {
    "1527c705-839a-4832-9118-54d4Bd6a0c89_10.0.19640.1000_neutral_neutral_cw5n1h2txyewy",
    "c5e2524a-ea46-4f67-841f-6a9465d9d515_10.0.26100.1_neutral_neutral_cw5n1h2txyewy",
    "E2A4F912-2574-4A75-9BB0-0D023378592B_10.0.19640.1000_neutral_neutral_cw5n1h2txyewy",
    "F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_10.0.26100.1_neutral_neutral_cw5n1h2txyewy",
    "Microsoft.AAD.BrokerPlugin_1000.19580.1000.2_neutral_neutral_cw5n1h2txyewy",
    "Microsoft.AccountsControl_10.0.26100.1_neutral__cw5n1h2txyewy",
};
// SYNTHETIC Path value (the real capture recorded the package InstallLocation instead).
const char* const kWingetKey = "Microsoft.DesktopAppInstaller_1.29.379.0_x64__8wekyb3d8bbwe";
const char* const kWingetPath =
    "C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_1.29.379.0_x64__"
    "8wekyb3d8bbwe\\AppxManifest.xml";

// -- the fake seam -----------------------------------------------------------------------------

struct FakeOps {
    std::map<std::string, pw::NameList> reg_lists;                        // store key -> list
    std::map<std::string, std::string> reg_values;                        // "key|subkey|value"
    std::map<std::string, pw::OpStatus> reg_value_status;                 // same key: a non-ok read
    std::map<std::string, pw::NameList> dir_lists;                        // path -> list
    std::map<std::string, pw::FileRead> files;                            // lower-cased path
    mutable std::vector<std::string> file_reads;                          // paths asked for
    mutable std::vector<std::pair<std::string, std::size_t>> list_caps;   // (what, cap)

    static std::string lower(std::string s) {
        for (auto& c : s) c = pw::detail::ascii_lower(c); // NTFS is case-insensitive
        return s;
    }

    [[nodiscard]] pw::NameList list_reg_subkeys(std::string_view key, std::size_t cap) const {
        list_caps.emplace_back(std::string{key}, cap);
        const auto it = reg_lists.find(std::string{key});
        if (it == reg_lists.end()) return {pw::OpStatus::absent, {}, false, false};
        return it->second;
    }
    [[nodiscard]] pw::ValueRead read_reg_string(std::string_view key, std::string_view sub,
                                                std::string_view value) const {
        const auto id = std::string{key} + "|" + std::string{sub} + "|" + std::string{value};
        if (const auto st = reg_value_status.find(id); st != reg_value_status.end())
            return {st->second, {}};
        const auto it = reg_values.find(id);
        if (it == reg_values.end()) return {pw::OpStatus::absent, {}};
        return {pw::OpStatus::ok, it->second};
    }
    [[nodiscard]] pw::NameList list_dir(std::string_view path, std::size_t cap) const {
        list_caps.emplace_back(std::string{path}, cap);
        const auto it = dir_lists.find(std::string{path});
        if (it == dir_lists.end()) return {pw::OpStatus::absent, {}, false, false};
        return it->second;
    }
    [[nodiscard]] pw::FileRead read_file(std::string_view path, std::size_t cap) const {
        file_reads.emplace_back(path);
        (void)cap; // the fake returns whole bodies; cap handling is the seam's
        const auto it = files.find(lower(std::string{path}));
        if (it == files.end()) return {pw::OpStatus::absent, {}};
        return it->second;
    }

    void set_apps(const std::string& key, std::initializer_list<const char*> names) {
        pw::NameList l;
        for (const auto* n : names) l.names.emplace_back(n);
        reg_lists[key] = std::move(l);
    }
    void add_nuspec(const std::string& dir, const std::string& body) {
        files[lower(std::string{pw::kChocolateyLib} + "\\" + dir + "\\" + dir + ".nuspec")] = {
            pw::OpStatus::ok, body};
    }
};

// The captured chocolatey layout.
FakeOps real_choco() {
    FakeOps ops;
    pw::NameList l;
    for (const auto& d : kChocoLib) {
        l.names.emplace_back(d.dir);
        if (*d.version == '\0') continue; // no loose nuspec
        std::string body;
        if (std::string_view{d.dir} == "jq") body = kJqNuspec;
        else if (std::string_view{d.dir} == "7zip") body = k7zipNuspecHead;
        else // SYNTHETIC body carrying the captured version
            body = std::string{"<package><metadata><id>"} + d.dir + "</id><version>" + d.version +
                   "</version></metadata></package>";
        ops.add_nuspec(d.dir, body);
    }
    ops.dir_lists[std::string{pw::kChocolateyLib}] = std::move(l);
    return ops;
}

FakeOps real_appx() {
    FakeOps ops;
    ops.reg_lists["Applications"] = {pw::OpStatus::ok,
                                     {std::begin(kApplications), std::end(kApplications)},
                                     false, false};
    ops.reg_lists["InboxApplications"] = {pw::OpStatus::ok,
                                          {std::begin(kInbox), std::end(kInbox)}, false, false};
    // Deprovisioned: REAL capture says the key is absent (exists=False).
    return ops;
}

bool has_row(const std::vector<std::string>& rows, std::string_view row) {
    return std::find(rows.begin(), rows.end(), row) != rows.end();
}

} // namespace

// -- tag scanner ---------------------------------------------------------------------------------

TEST_CASE("win xml: the real jq nuspec yields its id and version", "[pkg_inventory][windows][xml]") {
    CHECK(pw::extract_xml_text(kJqNuspec, "version") == std::optional<std::string>{"1.8.2"});
    CHECK(pw::extract_xml_text(kJqNuspec, "id") == std::optional<std::string>{"jq"});
    // Cut after <version> (the 7zip capture is a head): still answers.
    CHECK(pw::extract_xml_text(k7zipNuspecHead, "version") == std::optional<std::string>{"26.5.0"});
}

TEST_CASE("win xml: first match only, case-insensitive tag, attributes are not elements",
          "[pkg_inventory][windows][xml]") {
    CHECK(pw::extract_xml_text("<a><version>1</version><version>2</version></a>", "version") ==
          std::optional<std::string>{"1"});
    CHECK(pw::extract_xml_text("<Version>3.0</VERSION>", "version") ==
          std::optional<std::string>{"3.0"});
    // `<dependency id="x" version="9"/>` carries attributes, never an element.
    CHECK_FALSE(pw::extract_xml_text("<dependency id=\"x\" version=\"9\"/>", "version"));
    // A longer tag name that merely starts with the wanted one is not a match.
    CHECK_FALSE(pw::extract_xml_text("<versionInfo>1</versionInfo>", "version"));
    CHECK(pw::extract_xml_text("<versionInfo>1</versionInfo><version>2</version>", "version") ==
          std::optional<std::string>{"2"});
}

TEST_CASE("win xml: markup inside comments, CDATA and declarations never counts",
          "[pkg_inventory][windows][xml]") {
    CHECK(pw::extract_xml_text("<!-- <version>0</version> --><version>1</version>", "version") ==
          std::optional<std::string>{"1"});
    CHECK(pw::extract_xml_text("<d><![CDATA[<version>0</version>]]></d><version>1</version>",
                               "version") == std::optional<std::string>{"1"});
    CHECK(pw::extract_xml_text("<?xml version=\"1.0\"?><!DOCTYPE x><version>1</version>",
                               "version") == std::optional<std::string>{"1"});
}

TEST_CASE("win xml: a value containing an ampersand is refused, never decoded",
          "[pkg_inventory][windows][xml]") {
    CHECK_FALSE(pw::extract_xml_text("<v>1.0 &amp; 2</v>", "v"));
}

TEST_CASE("win xml: empty, structured, unterminated and oversized values read as nothing",
          "[pkg_inventory][windows][xml]") {
    CHECK_FALSE(pw::extract_xml_text("<v/>", "v"));
    CHECK_FALSE(pw::extract_xml_text("<v></v>", "v"));
    CHECK_FALSE(pw::extract_xml_text("<v>  \n </v>", "v"));
    CHECK_FALSE(pw::extract_xml_text("<v><b>1</b></v>", "v"));  // child markup
    CHECK_FALSE(pw::extract_xml_text("<v>1", "v"));             // no end tag
    CHECK_FALSE(pw::extract_xml_text("<v>1</w>", "v"));         // wrong end tag
    CHECK_FALSE(pw::extract_xml_text("<!-- never closed <v>1</v>", "v"));
    CHECK_FALSE(pw::extract_xml_text("", "v"));
    CHECK_FALSE(pw::extract_xml_text("no markup at all", "v"));
    const std::string big(pw::kMaxXmlValueBytes + 1, 'x');
    CHECK_FALSE(pw::extract_xml_text("<v>" + big + "</v>", "v"));
    const std::string at_cap(pw::kMaxXmlValueBytes, 'x');
    CHECK(pw::extract_xml_text("<v>" + at_cap + "</v>", "v")->size() == pw::kMaxXmlValueBytes);
}

TEST_CASE("win xml: plausible_version admits version-shaped text only", "[pkg_inventory][windows][xml]") {
    CHECK(pw::plausible_version("1.0.0-beta+meta.2"));
    CHECK(pw::plausible_version("21.0.12.1"));
    CHECK_FALSE(pw::plausible_version(""));
    CHECK_FALSE(pw::plausible_version("1 0"));
    CHECK_FALSE(pw::plausible_version("1|0"));
    CHECK_FALSE(pw::plausible_version("1\\0"));
    CHECK_FALSE(pw::plausible_version(std::string(pw::kMaxVersionBytes + 1, '1')));
}

// -- PackageFullName -----------------------------------------------------------------------------

TEST_CASE("win appx: every real roster name parses into five parts", "[pkg_inventory][windows][appx]") {
    for (const auto& n : kApplications) {
        INFO(n);
        REQUIRE(pw::parse_package_full_name(n));
    }
    for (const auto& n : kInbox) {
        INFO(n);
        REQUIRE(pw::parse_package_full_name(n));
    }
    REQUIRE(pw::parse_package_full_name(kWingetKey));
}

TEST_CASE("win appx: the awkward real names keep their parts", "[pkg_inventory][windows][appx]") {
    // `~` resource id (a bundle)
    auto p = pw::parse_package_full_name("Clipchamp.Clipchamp_4.7.10220.0_neutral_~_yxz26nhyzhsrt");
    REQUIRE(p);
    CHECK(p->name == "Clipchamp.Clipchamp");
    CHECK(p->version == "4.7.10220.0");
    CHECK(p->arch == "neutral");
    // empty resource id (`neutral__`)
    p = pw::parse_package_full_name("Microsoft.AccountsControl_10.0.26100.1_neutral__cw5n1h2txyewy");
    REQUIRE(p);
    CHECK(p->name == "Microsoft.AccountsControl");
    // GUID-prefixed inbox name, upper-case GUID
    p = pw::parse_package_full_name(
        "E2A4F912-2574-4A75-9BB0-0D023378592B_10.0.19640.1000_neutral_neutral_cw5n1h2txyewy");
    REQUIRE(p);
    CHECK(p->name == "E2A4F912-2574-4A75-9BB0-0D023378592B");
    // x64 arch, hyphenated name
    p = pw::parse_package_full_name("AdvancedMicroDevicesInc-RSXCM_22.10.0.0_x64__v2es6h43hjn86");
    REQUIRE(p);
    CHECK(p->name == "AdvancedMicroDevicesInc-RSXCM");
    CHECK(p->arch == "x64");
    CHECK(p->version == "22.10.0.0");
}

TEST_CASE("win appx: malformed names are refused", "[pkg_inventory][windows][appx]") {
    CHECK_FALSE(pw::parse_package_full_name(""));
    CHECK_FALSE(pw::parse_package_full_name("Name_1.0.0.0_x64_pub"));               // 4 parts
    CHECK_FALSE(pw::parse_package_full_name("Name_1.0.0.0_x64__pub_extra"));        // 6 parts
    CHECK_FALSE(pw::parse_package_full_name("Name_1.0.0.0.0_x64__pub"));            // 5-part version
    CHECK_FALSE(pw::parse_package_full_name("Name_1..0_x64__pub"));
    CHECK_FALSE(pw::parse_package_full_name("Name_a.b_x64__pub"));
    CHECK_FALSE(pw::parse_package_full_name("_1.0_x64__pub"));                       // no name
    CHECK_FALSE(pw::parse_package_full_name("Na|me_1.0_x64__pub"));                  // pipe in name
    CHECK_FALSE(pw::parse_package_full_name("Name_1.0_X64__pub"));                   // arch case
    CHECK_FALSE(pw::parse_package_full_name("Name_1.0__res_pub"));                   // empty arch
    CHECK_FALSE(pw::parse_package_full_name("Name_1.0_x64__"));                      // empty publisher
    CHECK_FALSE(pw::parse_package_full_name("Name_1.0_x64__PUB"));                   // publisher case
    CHECK_FALSE(pw::parse_package_full_name("Name_1.0_x64_re|s_pub"));               // pipe in resource
    CHECK_FALSE(pw::parse_package_full_name("Name_1.0._x64__pub"));                  // trailing dot
    CHECK_FALSE(pw::parse_package_full_name(std::string(300, 'a')));
}

TEST_CASE("win appx: package folder comes off the manifest-file Path value",
          "[pkg_inventory][windows][appx]") {
    // REAL Path shapes
    CHECK(pw::appx_package_folder(
              "C:\\Program Files\\WindowsApps\\AdvancedMicroDevicesInc-RSXCM_22.10.0.0_x64__v2es6h43hjn86"
              "\\AppxManifest.xml") ==
          "C:\\Program Files\\WindowsApps\\AdvancedMicroDevicesInc-RSXCM_22.10.0.0_x64__v2es6h43hjn86");
    CHECK(pw::appx_package_folder("C:\\Program Files\\WindowsApps\\Clipchamp.Clipchamp_4.7.10220.0_"
                                  "neutral_~_yxz26nhyzhsrt\\AppxMetadata\\AppxBundleManifest.xml") ==
          "C:\\Program Files\\WindowsApps\\Clipchamp.Clipchamp_4.7.10220.0_neutral_~_yxz26nhyzhsrt");
    CHECK(pw::appx_package_folder("C:\\Windows\\SystemApps\\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy"
                                  "\\appxmanifest.XML") ==
          "C:\\Windows\\SystemApps\\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy");
    CHECK(pw::appx_package_folder("C:\\somewhere\\other.xml").empty());
    CHECK(pw::appx_package_folder("\\AppxManifest.xml").empty());
    CHECK(pw::appx_package_folder("").empty());
}

// -- rows ----------------------------------------------------------------------------------------

TEST_CASE("win rows: exact wire shape of the three kinds", "[pkg_inventory][windows][rows]") {
    CHECK(pw::appx_store_row("Microsoft.BingNews_4.1.24002.0_neutral_~_8wekyb3d8bbwe",
                             pi::StoreState::active) ==
          "package|appx|Microsoft.BingNews_4.1.24002.0_neutral_~_8wekyb3d8bbwe|4.1.24002.0|app|-|"
          "neutral|-|active");
    CHECK(pw::appx_store_row(kWingetKey, pi::StoreState::deprovisioned) ==
          std::string{"package|appx|"} + kWingetKey + "|1.29.379.0|app|-|x64|-|deprovisioned");
    // An unparsable key name stays in the roster with version and arch `-`.
    CHECK(pw::appx_store_row("not-a-package-name", pi::StoreState::active) ==
          "package|appx|not-a-package-name|-|app|-|-|-|active");
    CHECK(pw::chocolatey_package_row("7zip", "26.5.0") == "package|chocolatey|7zip|26.5.0|pkg");
    CHECK(pw::chocolatey_package_row("chocolatey", "") == "package|chocolatey|chocolatey|-|pkg");
    // A hostile pipe in an id is escaped, never a column shift.
    CHECK(pw::chocolatey_package_row("a|b", "1") == "package|chocolatey|a\\|b|1|pkg");
    // The Homebrew shape is unchanged by the ecosystem parameter.
    CHECK(pi::format_package_row("wget", "1.24.5", pi::PackageKind::formula) ==
          "package|homebrew|wget|1.24.5|formula");
}

// -- store_packages ------------------------------------------------------------------------------

TEST_CASE("win store_packages: the captured roster, sorted, with a missing Deprovisioned key silent",
          "[pkg_inventory][windows][store]") {
    auto ops = real_appx();
    ConstraintAccumulator acc;
    const auto rows = pw::store_package_rows(ops, acc);
    CHECK_FALSE(acc.any_failure());
    REQUIRE(rows.size() == 12);
    CHECK(rows.front() ==
          "package|appx|AdvancedMicroDevicesInc-RSXCM_22.10.0.0_x64__v2es6h43hjn86|22.10.0.0|app|-|"
          "x64|-|active");
    CHECK(has_row(rows, "package|appx|Microsoft.AccountsControl_10.0.26100.1_neutral__"
                        "cw5n1h2txyewy|10.0.26100.1|app|-|neutral|-|active"));
    CHECK(has_row(rows, "package|appx|1527c705-839a-4832-9118-54d4Bd6a0c89_10.0.19640.1000_neutral_"
                        "neutral_cw5n1h2txyewy|10.0.19640.1000|app|-|neutral|-|active"));
    for (const auto& r : rows) CHECK(yuzu::test::pkg_inventory_support::split_fields_escape_aware(r).size() == 9);
}

TEST_CASE("win store_packages: Deprovisioned rows carry their own state", "[pkg_inventory][windows][store]") {
    auto ops = real_appx();                        // Deprovisioned is SYNTHETIC here
    ops.set_apps("Deprovisioned", {kWingetKey});
    ConstraintAccumulator acc;
    const auto rows = pw::store_package_rows(ops, acc);
    CHECK_FALSE(acc.any_failure());
    CHECK(rows.back() ==
          std::string{"package|appx|"} + kWingetKey + "|1.29.379.0|app|-|x64|-|deprovisioned");
}

TEST_CASE("win store_packages: a denied roster key is a constraint, never an empty success",
          "[pkg_inventory][windows][store]") {
    auto ops = real_appx();
    ops.reg_lists["Applications"] = {pw::OpStatus::denied, {}, false, false};
    ConstraintAccumulator acc;
    const auto rows = pw::store_package_rows(ops, acc);
    CHECK(acc.reason() == "windows:pkg_inventory:appx_applications:access_denied");
    CHECK(rows.size() == 6); // the other keys still report
    ops.reg_lists["InboxApplications"] = {pw::OpStatus::error, {}, false, false};
    ConstraintAccumulator acc2;
    (void)pw::store_package_rows(ops, acc2);
    CHECK(acc2.reason() ==
          "windows:pkg_inventory:appx_applications:access_denied,"
          "windows:pkg_inventory:appx_inbox:open_failed");
}

TEST_CASE("win store_packages: no roster key at all is supported with zero rows",
          "[pkg_inventory][windows][store]") {
    FakeOps ops;
    ConstraintAccumulator acc;
    CHECK(pw::store_package_rows(ops, acc).empty());
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("win store_packages: entry cap, enumeration failure and the row budget are tokens",
          "[pkg_inventory][windows][store]") {
    {
        auto ops = real_appx();
        ops.reg_lists["Applications"].truncated = true;
        ConstraintAccumulator acc;
        CHECK(pw::store_package_rows(ops, acc).size() == 12); // names read so far are kept
        CHECK(acc.reason() == "windows:pkg_inventory:appx_applications:entry_cap");
    }
    {
        auto ops = real_appx();
        ops.reg_lists["InboxApplications"].enum_failed = true;
        ConstraintAccumulator acc;
        (void)pw::store_package_rows(ops, acc);
        CHECK(acc.reason() == "windows:pkg_inventory:appx_inbox:enum_failed");
    }
    {
        auto ops = real_appx();
        pw::WinLimits lim;
        lim.max_rows = 7; // 6 Applications + 1 Inbox
        ConstraintAccumulator acc;
        CHECK(pw::store_package_rows(ops, acc, lim).size() == 7);
        CHECK(acc.reason() == "windows:pkg_inventory:appx_inbox:row_cap");
    }
    {
        auto ops = real_appx();
        pw::WinLimits lim;
        lim.max_output_bytes = 300; // two rows of ~120 bytes
        ConstraintAccumulator acc;
        const auto rows = pw::store_package_rows(ops, acc, lim);
        CHECK(rows.size() < 12);
        CHECK(acc.reason() == "windows:pkg_inventory:appx_applications:byte_cap");
    }
    {
        auto ops = real_appx();
        pw::WinLimits lim;
        lim.max_roster_keys = 4;
        ConstraintAccumulator acc;
        (void)pw::store_package_rows(ops, acc, lim);
        // the cap is handed to the seam, which owns the truncation
        for (const auto& [what, cap] : ops.list_caps) CHECK(cap == 4);
    }
}

// -- packages (chocolatey) -----------------------------------------------------------------------

TEST_CASE("win packages: the captured chocolatey lib yields one row per directory with a nuspec",
          "[pkg_inventory][windows][choco]") {
    auto ops = real_choco();
    ConstraintAccumulator acc;
    const auto rows = pw::chocolatey_package_rows(ops, acc);
    CHECK_FALSE(acc.any_failure());
    REQUIRE(rows.size() == kChocoLibDirs - 1); // `chocolatey` has no loose nuspec
    CHECK(has_row(rows, "package|chocolatey|7zip|26.5.0|pkg"));
    CHECK(has_row(rows, "package|chocolatey|jq|1.8.2|pkg"));
    // upper-case directory, lower-case nuspec file name on disk (captured)
    CHECK(has_row(rows, "package|chocolatey|KB2919355|1.0.20160915|pkg"));
    CHECK(has_row(rows, "package|chocolatey|Temurin21|21.0.13|pkg"));
    CHECK(has_row(rows, "package|chocolatey|microsoft-openjdk-21|21.0.12.1|pkg"));
    // the bootstrap package is not a roster entry (it is the managers row)
    for (const auto& r : rows) CHECK(r.find("|chocolatey|chocolatey|") == std::string::npos);
    // every package read is a single bounded read of <lib>\<id>\<id>.nuspec
    CHECK(ops.file_reads.size() == kChocoLibDirs);
    CHECK(ops.file_reads.front() == "C:\\ProgramData\\chocolatey\\lib\\7zip\\7zip.nuspec");
}

TEST_CASE("win packages: an unreadable or unparsable nuspec degrades its own row only",
          "[pkg_inventory][windows][choco]") {
    auto ops = real_choco();                                           // per-item cases SYNTHETIC
    ops.files[FakeOps::lower("C:\\ProgramData\\chocolatey\\lib\\jq\\jq.nuspec")] = {
        pw::OpStatus::denied, {}};
    ops.files[FakeOps::lower("C:\\ProgramData\\chocolatey\\lib\\7zip\\7zip.nuspec")] = {
        pw::OpStatus::error, {}}; // e.g. a reparse point refused by the reader
    ops.add_nuspec("7zip.install", "<package><metadata><id>7zip.install</id></metadata></package>");
    ops.add_nuspec("notepadplusplus", "<package><metadata><version>8.9&#46;8</version></metadata>");
    ConstraintAccumulator acc;
    const auto rows = pw::chocolatey_package_rows(ops, acc);
    CHECK_FALSE(acc.any_failure()); // row-level only: a token would fail the whole sync cycle
    CHECK(rows.size() == kChocoLibDirs - 1);
    CHECK(has_row(rows, "package|chocolatey|jq|-|pkg"));
    CHECK(has_row(rows, "package|chocolatey|7zip|-|pkg"));
    CHECK(has_row(rows, "package|chocolatey|7zip.install|-|pkg"));
    CHECK(has_row(rows, "package|chocolatey|notepadplusplus|-|pkg"));
    CHECK(has_row(rows, "package|chocolatey|dotnet-9.0-runtime|9.0.22|pkg")); // siblings intact
}

TEST_CASE("win packages: a version past the nuspec read cap reads as unknown",
          "[pkg_inventory][windows][choco]") {
    FakeOps ops;
    ops.dir_lists[std::string{pw::kChocolateyLib}] = {pw::OpStatus::ok, {"big"}, false, false};
    // The seam hands back only the first `cap` bytes; a <version> after that is not seen.
    ops.add_nuspec("big", "<package><metadata><description>" + std::string(200, 'x') +
                              "</description>");
    ConstraintAccumulator acc;
    const auto rows = pw::chocolatey_package_rows(ops, acc);
    CHECK(rows == std::vector<std::string>{"package|chocolatey|big|-|pkg"});
}

TEST_CASE("win packages: absent lib is silent, denied or failing lib is a token",
          "[pkg_inventory][windows][choco]") {
    {
        FakeOps ops;
        ConstraintAccumulator acc;
        CHECK(pw::chocolatey_package_rows(ops, acc).empty());
        CHECK_FALSE(acc.any_failure());
    }
    {
        FakeOps ops;
        ops.dir_lists[std::string{pw::kChocolateyLib}] = {pw::OpStatus::denied, {}, false, false};
        ConstraintAccumulator acc;
        CHECK(pw::chocolatey_package_rows(ops, acc).empty());
        CHECK(acc.reason() == "windows:pkg_inventory:chocolatey_lib:access_denied");
    }
    {
        auto ops = real_choco();
        pw::WinLimits lim;
        lim.max_rows = 3;
        ConstraintAccumulator acc;
        CHECK(pw::chocolatey_package_rows(ops, acc, lim).size() == 3);
        CHECK(acc.reason() == "windows:pkg_inventory:chocolatey_lib:row_cap");
    }
    {
        auto ops = real_choco();
        ops.dir_lists[std::string{pw::kChocolateyLib}].truncated = true;
        ConstraintAccumulator acc;
        CHECK(pw::chocolatey_package_rows(ops, acc).size() == kChocoLibDirs - 1);
        CHECK(acc.reason() == "windows:pkg_inventory:chocolatey_lib:entry_cap");
    }
}

// -- managers ------------------------------------------------------------------------------------

TEST_CASE("win managers: captured chocolatey lib and the winget App Installer package",
          "[pkg_inventory][windows][managers]") {
    auto ops = real_choco();
    ops.set_apps("Applications", {kApplications[0], kWingetKey, kApplications[5]});
    ops.reg_values[std::string{"Applications|"} + kWingetKey + "|Path"] = kWingetPath;
    ConstraintAccumulator acc;
    const auto rows = pw::manager_rows(ops, acc);
    CHECK_FALSE(acc.any_failure());
    REQUIRE(rows.size() == 2);
    // The version is `-`: the bootstrap package has no loose nuspec and bin\choco.exe is a shim
    // that reported 0.12.1 against `choco list`'s 2.7.5 (both captured).
    CHECK(rows[0] == "manager|chocolatey|present|-|C:/ProgramData/chocolatey|lib_dirs=19|-");
    CHECK(rows[1] == "manager|winget|present|1.29.379.0|C:/Program Files/WindowsApps/"
                     "Microsoft.DesktopAppInstaller_1.29.379.0_x64__8wekyb3d8bbwe|-|-");
}

TEST_CASE("win managers: an absent manager has no row and no token", "[pkg_inventory][windows][managers]") {
    FakeOps ops;
    ops.set_apps("Applications", {kApplications[0], kApplications[1]}); // roster without App Installer
    ConstraintAccumulator acc;
    CHECK(pw::manager_rows(ops, acc).empty());
    CHECK_FALSE(acc.any_failure());
    FakeOps none; // no Appx store key, no chocolatey
    ConstraintAccumulator acc2;
    CHECK(pw::manager_rows(none, acc2).empty());
    CHECK_FALSE(acc2.any_failure());
}

TEST_CASE("win managers: the highest registered App Installer version wins; a missing Path leaves the root `-`",
          "[pkg_inventory][windows][managers]") {
    FakeOps ops; // SYNTHETIC
    ops.set_apps("Applications", {"Microsoft.DesktopAppInstaller_1.9.100.0_x64__8wekyb3d8bbwe",
                                  "Microsoft.DesktopAppInstaller_1.29.379.0_x64__8wekyb3d8bbwe",
                                  "Microsoft.DesktopAppInstaller_1.29.38.0_x64__8wekyb3d8bbwe",
                                  "Microsoft.DesktopAppInstallerX_9.9.9.9_x64__8wekyb3d8bbwe"});
    ConstraintAccumulator acc;
    const auto rows = pw::manager_rows(ops, acc);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "manager|winget|present|1.29.379.0|-|-|-");
}

TEST_CASE("win managers: an unreadable App Installer Path leaves the root `-` and raises no token",
          "[pkg_inventory][windows][managers]") {
    for (const auto st : {pw::OpStatus::denied, pw::OpStatus::error}) {
        FakeOps ops; // SYNTHETIC
        ops.set_apps("Applications", {kWingetKey});
        ops.reg_value_status[std::string{"Applications|"} + kWingetKey + "|Path"] = st;
        ConstraintAccumulator acc;
        const auto rows = pw::manager_rows(ops, acc);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == "manager|winget|present|1.29.379.0|-|-|-");
        CHECK_FALSE(acc.any_failure());
    }
}

TEST_CASE("win managers: an incomplete Appx roster listing still reports winget and raises its token",
          "[pkg_inventory][windows][managers]") {
    {
        FakeOps ops; // SYNTHETIC: more roster keys existed than the cap
        ops.reg_lists["Applications"] = {pw::OpStatus::ok, {kApplications[0], kWingetKey}, true, false};
        ConstraintAccumulator acc;
        const auto rows = pw::manager_rows(ops, acc);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == "manager|winget|present|1.29.379.0|-|-|-");
        CHECK(acc.reason() == "windows:pkg_inventory:appx_applications:entry_cap");
    }
    {
        FakeOps ops; // SYNTHETIC: the enumeration stopped on an error mid-way
        ops.reg_lists["Applications"] = {pw::OpStatus::ok, {kApplications[0], kWingetKey}, false, true};
        ConstraintAccumulator acc;
        const auto rows = pw::manager_rows(ops, acc);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == "manager|winget|present|1.29.379.0|-|-|-");
        CHECK(acc.reason() == "windows:pkg_inventory:appx_applications:enum_failed");
    }
}

TEST_CASE("win managers: a present-but-unreadable manager is an unavailable row plus a token",
          "[pkg_inventory][windows][managers]") {
    FakeOps ops;
    ops.dir_lists[std::string{pw::kChocolateyLib}] = {pw::OpStatus::denied, {}, false, false};
    ops.reg_lists["Applications"] = {pw::OpStatus::error, {}, false, false};
    ConstraintAccumulator acc;
    const auto rows = pw::manager_rows(ops, acc);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0] == "manager|chocolatey|unavailable|-|C:/ProgramData/chocolatey|-|"
                     "windows:pkg_inventory:chocolatey_lib:access_denied");
    CHECK(rows[1] == "manager|winget|unavailable|-|-|-|windows:pkg_inventory:appx_applications:open_failed");
    CHECK(acc.reason() == "windows:pkg_inventory:chocolatey_lib:access_denied,"
                          "windows:pkg_inventory:appx_applications:open_failed");
}

TEST_CASE("win managers: a truncated lib listing drops the count fact (a lower bound is never a fact)",
          "[pkg_inventory][windows][managers]") {
    auto ops = real_choco();
    ops.dir_lists[std::string{pw::kChocolateyLib}].truncated = true;
    ConstraintAccumulator acc;
    const auto rows = pw::manager_rows(ops, acc);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "manager|chocolatey|present|-|C:/ProgramData/chocolatey|-|-");
    CHECK(acc.reason() == "windows:pkg_inventory:chocolatey_lib:entry_cap");
}

// -- the leg body through a real CommandContext ---------------------------------------------------

namespace {

const FakeOps* g_ops = nullptr;
pi::Action g_action = pi::Action::managers;

int leg_execute(YuzuCommandContext* raw, const char* /*action*/, const YuzuParam* /*params*/,
                std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    return pw::run_windows_with(ctx, g_action, *g_ops);
}

yuzu::agent::LocalDispatcher::Result run_leg(pi::Action a, const FakeOps& ops) {
    g_ops = &ops;
    g_action = a;
    yuzu::test::ScopeExit reset{[] { g_ops = nullptr; }};
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &leg_execute;
    yuzu::agent::LocalDispatcher dispatcher;
    return dispatcher.run(&descriptor, "probe");
}

} // namespace

TEST_CASE("win leg: status row first, then data rows, OK/FULL on a clean read",
          "[pkg_inventory][windows][leg]") {
    auto ops = real_choco();
    ops.set_apps("Applications", {kWingetKey});
    ops.reg_values[std::string{"Applications|"} + kWingetKey + "|Path"] = kWingetPath;
    for (const auto a : {pi::Action::managers, pi::Action::packages, pi::Action::store_packages}) {
        INFO(pi::action_name(a));
        const auto result = run_leg(a, ops);
        CHECK(result.rc == 0);
        const auto rows = captured_rows(result.captured);
        REQUIRE_FALSE(rows.empty());
        CHECK(rows[0] == std::string{"status|"} + std::string{pi::action_name(a)} + "|supported|-");
        CHECK(rows.size() > 1);
        CHECK(result.result_status == YUZU_RESULT_STATUS_OK);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    }
}

TEST_CASE("win leg: a constraint reports constrained on the status row and CONSTRAINED/PARTIAL",
          "[pkg_inventory][windows][leg]") {
    auto ops = real_appx();
    ops.reg_lists["Applications"] = {pw::OpStatus::denied, {}, false, false};
    const auto result = run_leg(pi::Action::store_packages, ops);
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    CHECK(rows[0] ==
          "status|store_packages|constrained|windows:pkg_inventory:appx_applications:access_denied");
    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
}

TEST_CASE("win leg: every emitted token matches the repo grammar", "[pkg_inventory][windows][leg]") {
    // ^(windows|macos|linux):[a-z0-9_]+(:[a-z0-9_]+)*$
    const auto ok = [](const std::string& t) {
        if (t.rfind("windows:", 0) != 0) return false;
        bool seg_start = true;
        for (std::size_t i = 8; i < t.size(); ++i) {
            const char c = t[i];
            if (c == ':') {
                if (seg_start) return false;
                seg_start = true;
            } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
                seg_start = false;
            } else {
                return false;
            }
        }
        return !seg_start;
    };
    for (const auto src : {"appx_applications", "appx_inbox", "appx_deprovisioned", "chocolatey_lib"})
        for (const auto cause : {"access_denied", "open_failed", "entry_cap", "enum_failed", "row_cap",
                                 "byte_cap"})
            CHECK(ok(pw::win_token(src, cause)));
}

// -- the committed sample ---------------------------------------------------------------------------

#ifndef YUZU_PLUGIN_SRC_DIR
#define YUZU_PLUGIN_SRC_DIR "agents/plugins"
#endif

namespace {

// Lines strictly between `== action=<action>` and the next `== action=` / `[result_status]`.
std::vector<std::string> sample_section(std::string_view action) {
    const std::filesystem::path p = std::filesystem::path(YUZU_PLUGIN_SRC_DIR) / "pkg_inventory" /
                                    "docs" / "samples" / "windows.txt";
    REQUIRE(std::filesystem::exists(p));
    std::ifstream in(p);
    std::vector<std::string> out;
    bool on = false;
    for (std::string line; std::getline(in, line);) {
        if (line.rfind("== action=", 0) == 0) {
            on = (line == "== action=" + std::string{action});
            continue;
        }
        if (line.rfind("[result_status]", 0) == 0) {
            on = false;
            continue;
        }
        if (on && !line.empty()) out.push_back(line);
    }
    return out;
}

} // namespace

TEST_CASE("win sample: docs/samples/windows.txt is exactly what the walk emits over the captured data",
          "[pkg_inventory][windows][sample]") {
    auto ops = real_choco();
    ops.reg_lists["Applications"] = {pw::OpStatus::ok,
                                     {std::begin(kApplications), std::end(kApplications)}, false,
                                     false};
    ops.reg_lists["Applications"].names.emplace_back(kWingetKey); // REAL package, see the sample header
    ops.reg_lists["InboxApplications"] = {pw::OpStatus::ok, {std::begin(kInbox), std::end(kInbox)},
                                          false, false};
    ops.reg_values[std::string{"Applications|"} + kWingetKey + "|Path"] = kWingetPath;
    for (const auto a : {pi::Action::managers, pi::Action::packages, pi::Action::store_packages}) {
        INFO(pi::action_name(a));
        const auto result = run_leg(a, ops);
        auto rows = captured_rows(result.captured);
        REQUIRE_FALSE(rows.empty());
        CHECK(rows == sample_section(pi::action_name(a)));
    }
}

// -- Windows only: the real OS seam ---------------------------------------------------------------

#ifdef _WIN32

TEST_CASE("win real ops: a planted Appx roster in an HKCU scratch key decodes through Reg*W",
          "[pkg_inventory][windows][realops]") {
    // The real Reg*W decode path, once: a process-suffixed key under HKCU stands in for HKLM
    // (RealOps takes the root and base as parameters; production reads HKLM only).
    const std::wstring base =
        L"SOFTWARE\\YuzuTest\\PkgInventoryAppx_" + std::to_wstring(GetCurrentProcessId());
    struct Cleanup {
        const std::wstring& base;
        ~Cleanup() {
            RegDeleteTreeW(HKEY_CURRENT_USER, base.c_str());
            RegDeleteKeyW(HKEY_CURRENT_USER, base.c_str());
        }
    } cleanup{base};
    const auto create = [](const std::wstring& path) {
        HKEY k{};
        REQUIRE(RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr, 0, KEY_READ | KEY_WRITE,
                                nullptr, &k, nullptr) == ERROR_SUCCESS);
        return yuzu::win::RegKey{k};
    };
    const auto set_sz = [](HKEY k, const wchar_t* name, const wchar_t* v) {
        const DWORD bytes = static_cast<DWORD>((std::wcslen(v) + 1) * sizeof(wchar_t));
        REQUIRE(RegSetValueExW(k, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(v), bytes) ==
                ERROR_SUCCESS);
    };
    {
        const auto app = create(base + L"\\Applications\\" + L"Microsoft.DesktopAppInstaller_1.29.379.0_x64__8wekyb3d8bbwe");
        set_sz(app.get(), L"Path",
               L"C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_1.29.379.0_x64__"
               L"8wekyb3d8bbwe\\AppxManifest.xml");
        create(base + L"\\Applications\\Clipchamp.Clipchamp_4.7.10220.0_neutral_~_yxz26nhyzhsrt");
    }
    const pw::RealOps ops{HKEY_CURRENT_USER, base};

    const auto list = ops.list_reg_subkeys("Applications", 10);
    REQUIRE(list.status == pw::OpStatus::ok);
    CHECK(list.names.size() == 2);
    CHECK_FALSE(list.truncated);
    CHECK(ops.list_reg_subkeys("Applications", 1).truncated);
    CHECK(ops.list_reg_subkeys("Deprovisioned", 10).status == pw::OpStatus::absent);

    const auto path = ops.read_reg_string("Applications",
                                          "Microsoft.DesktopAppInstaller_1.29.379.0_x64__8wekyb3d8bbwe",
                                          "Path");
    REQUIRE(path.status == pw::OpStatus::ok);
    CHECK(pw::appx_package_folder(path.value) ==
          "C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_1.29.379.0_x64__8wekyb3d8bbwe");
    CHECK(ops.read_reg_string("Applications", "Clipchamp.Clipchamp_4.7.10220.0_neutral_~_yxz26nhyzhsrt",
                              "Path").status == pw::OpStatus::absent);
    CHECK(ops.read_reg_string("Applications", "", "Path").status == pw::OpStatus::error);

    // The chocolatey half of manager_rows reads the host's real lib directory (whatever the runner
    // has), so only the winget row planted above is asserted.
    ConstraintAccumulator acc;
    const auto managers = pw::manager_rows(ops, acc);
    CHECK(std::any_of(managers.begin(), managers.end(), [](const std::string& r) {
        return r.rfind("manager|winget|present|1.29.379.0|", 0) == 0;
    }));
}

TEST_CASE("win real ops: bounded file read and single-level directory listing on a scratch tree",
          "[pkg_inventory][windows][realops]") {
    // First use of the new bounded-read primitive and of FindFirstFileExW listing, neither of which
    // the FakeOps cases reach: one small scratch tree (yuzu_test_ prefix: the Defender exclusion).
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_win_"};
    const auto root = dir.path;
    std::filesystem::create_directories(root / "alpha");
    std::filesystem::create_directories(root / "beta");
    {
        std::ofstream(root / "alpha" / "alpha.nuspec", std::ios::binary)
            << "<package><metadata><version>1.2.3</version></metadata></package>";
        std::ofstream(root / "stray.txt", std::ios::binary) << "x";
    }
    const pw::RealOps ops;
    const auto list = ops.list_dir(root.string(), 10);
    REQUIRE(list.status == pw::OpStatus::ok);
    CHECK(list.names.size() == 2); // the stray file is not listed
    CHECK(ops.list_dir(root.string(), 1).truncated);
    CHECK(ops.list_dir((root / "nope").string(), 10).status == pw::OpStatus::absent);
    CHECK(ops.list_dir("", 10).status == pw::OpStatus::error);

    const auto f = ops.read_file((root / "alpha" / "alpha.nuspec").string(), 4096);
    REQUIRE(f.status == pw::OpStatus::ok);
    CHECK(pw::extract_xml_text(f.bytes, "version") == std::optional<std::string>{"1.2.3"});
    const auto cut = ops.read_file((root / "alpha" / "alpha.nuspec").string(), 10);
    REQUIRE(cut.status == pw::OpStatus::ok);
    CHECK(cut.bytes.size() == 10);
    CHECK(ops.read_file((root / "alpha" / "missing.nuspec").string(), 10).status ==
          pw::OpStatus::absent);
    CHECK(ops.read_file((root / "alpha").string(), 10).status == pw::OpStatus::error); // a directory
    CHECK(ops.read_file("", 10).status == pw::OpStatus::error);
}

#endif // _WIN32
