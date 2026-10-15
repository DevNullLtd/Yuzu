/**
 * test_runtimes_parsers.cpp -- pure-parser tests for the runtimes plugin
 * (runtimes_parsers.hpp, runtimes_legs.hpp's Action mapping). Builds and runs
 * on every OS, unguarded: nothing here touches a real filesystem beyond
 * reading the committed fixtures.
 *
 * Fixtures: tests/unit/fixtures/wave10/runtimes/linux/ -- REAL CAPTURES from
 * command-only Linux containers (see provenance.txt in that directory for the
 * exact commands, images and dates). They are read via YUZU_TEST_FIXTURE_DIR
 * and REQUIREd to exist -- a missing fixture fails, never skips.
 *
 * MUTATION NOTES (each assertion below FAILS if the named wiring is removed):
 *  - vendor: dropping IMPLEMENTOR -> vendor in jvm_row fails the
 *    "Eclipse Adoptium" / "Debian" last-field assertions.
 *  - flavour: dropping IMAGE_TYPE -> flavour in jvm_flavour_from fails the
 *    Temurin `jvm|jdk|...` row; dropping the unmodelled fallback fails the
 *    Debian `jvm|unmodelled|...` row.
 *  - status-first: emitting data rows before the status row fails
 *    compose_output's index-0 assertions.
 *  - failure never absent: dropping the accumulator -> status mapping fails
 *    the `constrained` + token assertions.
 *  - wire grammar: bypassing safe_output_field fails the trailing-backslash
 *    and embedded-pipe field-count assertions.
 */
#include <catch2/catch_test_macros.hpp>

#include "runtimes_legs.hpp"
#include "runtimes_parsers.hpp"

#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace rt = yuzu::runtimes;

namespace {

std::filesystem::path fixture_path(const char* name) {
#ifdef YUZU_TEST_FIXTURE_DIR
    return std::filesystem::path(YUZU_TEST_FIXTURE_DIR) / "wave10" / "runtimes" / "linux" / name;
#else
    return std::filesystem::path("tests/unit/fixtures/wave10/runtimes/linux") / name;
#endif
}

std::string read_fixture(const char* name) {
    const auto p = fixture_path(name);
    REQUIRE(std::filesystem::exists(p));
    std::ifstream in(p, std::ios::binary);
    REQUIRE(in.good());
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

std::vector<std::string> lines_of(const std::string& text) {
    std::vector<std::string> out;
    std::istringstream ss(text);
    std::string l;
    while (std::getline(ss, l)) {
        if (!l.empty()) out.push_back(l);
    }
    return out;
}

/// Escape-aware field split: yuzu::util::safe_output_field escapes a literal
/// '|' as '\|', so a naive split('|') overcounts.
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

// -- parse_release_file -------------------------------------------------------

TEST_CASE("runtimes: parse_release_file reads the real Temurin release file", "[runtimes]") {
    const auto f = rt::parse_release_file(read_fixture("temurin17_release.txt"));
    CHECK(f.java_version == "17.0.20");
    CHECK(f.implementor == "Eclipse Adoptium");
    CHECK(f.java_runtime_version == "17.0.20+8");
    CHECK(f.image_type == "JDK");
}

TEST_CASE("runtimes: parse_release_file reads the real Debian OpenJDK release file", "[runtimes]") {
    const auto f = rt::parse_release_file(read_fixture("debian_openjdk17_release.txt"));
    CHECK(f.java_version == "17.0.20.1");
    CHECK(f.implementor == "Debian");
    CHECK(f.java_runtime_version == "17.0.20.1+1-1-deb12u1-Debian");
    CHECK(f.image_type.empty()); // Debian's release file carries no IMAGE_TYPE
}

TEST_CASE("runtimes: parse_release_file returns empty fields on garbage, never throws",
          "[runtimes]") {
    const std::string binary("\x00\x01\xff\xfe=\x80\n\x00", 8);
    const std::vector<std::string> garbage = {
        "",           "\n\n\n",        "=",          "JAVA_VERSION",
        "=value",     "no equals here\nat all", binary, "JAVA_VERSION=\"",
    };
    for (const auto& g : garbage) {
        const auto f = rt::parse_release_file(g);
        CHECK(f.java_version.empty());
        CHECK(f.implementor.empty());
        CHECK(f.java_runtime_version.empty());
        CHECK(f.image_type.empty());
    }
}

TEST_CASE("runtimes: parse_release_file tolerates CRLF, unquoted values, whitespace and unknown keys",
          "[runtimes]") {
    const auto f = rt::parse_release_file(
        "OS_ARCH=\"x86_64\"\r\n  JAVA_VERSION = 21.0.1  \r\nIMPLEMENTOR=\"Oracle Corporation\"\r\n"
        "IMAGE_TYPE=\"JRE\"\r\nMODULES=\"java.base\"");
    CHECK(f.java_version == "21.0.1");
    CHECK(f.implementor == "Oracle Corporation");
    CHECK(f.image_type == "JRE");
    CHECK(f.java_runtime_version.empty());
}

// -- jvm flavour + row ----------------------------------------------------------

TEST_CASE("runtimes: jvm_flavour_from maps IMAGE_TYPE and otherwise says unmodelled", "[runtimes]") {
    CHECK(rt::jvm_flavour_from("JDK") == rt::JvmFlavour::jdk);
    CHECK(rt::jvm_flavour_from("jre") == rt::JvmFlavour::jre);
    CHECK(rt::jvm_flavour_from(" Jdk ") == rt::JvmFlavour::jdk); // case-insensitive, trimmed
    // No IMAGE_TYPE (Debian, SUSE): unmodelled, never guessed from the path or the module list.
    CHECK(rt::jvm_flavour_from("") == rt::JvmFlavour::unmodelled);
    CHECK(rt::jvm_flavour_from("SOMETHING") == rt::JvmFlavour::unmodelled);
    CHECK(rt::flavour_token(rt::JvmFlavour::unmodelled) == "unmodelled");
}

TEST_CASE("runtimes: jvm_row builds the wire row from the real release fixtures", "[runtimes]") {
    const auto temurin = rt::jvm_row(rt::parse_release_file(read_fixture("temurin17_release.txt")),
                                     "/opt/java/openjdk");
    REQUIRE(temurin.has_value());
    CHECK(*temurin == "jvm|jdk|17.0.20|/opt/java/openjdk|Eclipse Adoptium");

    const auto debian = rt::jvm_row(
        rt::parse_release_file(read_fixture("debian_openjdk17_release.txt")),
        "/usr/lib/jvm/java-17-openjdk-arm64");
    REQUIRE(debian.has_value());
    CHECK(*debian == "jvm|unmodelled|17.0.20.1|/usr/lib/jvm/java-17-openjdk-arm64|Debian");
}

TEST_CASE("runtimes: jvm_row falls back to JAVA_RUNTIME_VERSION and rejects a versionless file",
          "[runtimes]") {
    rt::ReleaseFields f;
    f.java_runtime_version = "11.0.2+9";
    f.image_type = "JDK";
    const auto row = rt::jvm_row(f, "/opt/j");
    REQUIRE(row.has_value());
    CHECK(*row == "jvm|jdk|11.0.2+9|/opt/j|-"); // vendor absent -> "-"

    CHECK_FALSE(rt::jvm_row(rt::parse_release_file("MODULES=\"java.base\"\n"), "/opt/j").has_value());
}

TEST_CASE("runtimes: a release value carrying a control character is ignored, never a row field",
          "[runtimes]") {
    // write_output crosses the C ABI as a C string, so an embedded NUL would truncate the
    // wire row after it. MUTATION: dropping the has_control_char reject in
    // parse_release_file makes java_version below non-empty and yields a row.
    std::string text = "JAVA_VERSION=\"17.0";
    text += '\0';
    text += ".20\"\nIMPLEMENTOR=\"Eclipse Adoptium\"\n";
    const auto f = rt::parse_release_file(text);
    CHECK(f.java_version.empty());
    CHECK(f.implementor == "Eclipse Adoptium");
    CHECK_FALSE(rt::jvm_row(f, "/opt/j").has_value()); // versionless: the leg records a constraint
}

// -- dotnet ---------------------------------------------------------------------------

TEST_CASE("runtimes: dotnet_entry_from_dir handles the real runtime-image listing", "[runtimes]") {
    const auto entries = lines_of(read_fixture("dotnet_shared_listing.txt"));
    REQUIRE(entries.size() == 1);
    // Listing lines are shared/<framework>/<version>.
    const std::string& l = entries[0];
    const auto a = l.find('/');
    const auto b = l.find('/', a + 1);
    REQUIRE(a != std::string::npos);
    REQUIRE(b != std::string::npos);
    CHECK(l.substr(0, a) == "shared");
    const auto fw = l.substr(a + 1, b - a - 1);
    const auto ver = l.substr(b + 1);

    const auto e = rt::dotnet_entry_from_dir(fw, ver);
    REQUIRE(e.has_value());
    CHECK(e->flavour == rt::DotnetFlavour::core);
    CHECK(e->version == "8.0.31");

    const auto row = rt::dotnet_row(fw, ver, "/usr/share/dotnet/" + l);
    REQUIRE(row.has_value());
    CHECK(*row == "dotnet|core|8.0.31|/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.31|-");
}

TEST_CASE("runtimes: dotnet_entry_from_dir maps frameworks, sdk, unmodelled and non-versions",
          "[runtimes]") {
    CHECK(rt::dotnet_entry_from_dir("Microsoft.AspNetCore.App", "8.0.31")->flavour ==
          rt::DotnetFlavour::core);
    CHECK(rt::dotnet_entry_from_dir("Microsoft.WindowsDesktop.App", "8.0.31")->flavour ==
          rt::DotnetFlavour::core);
    const auto sdk = rt::dotnet_entry_from_dir("sdk", "8.0.100");
    REQUIRE(sdk.has_value());
    CHECK(sdk->flavour == rt::DotnetFlavour::sdk);
    CHECK(sdk->version == "8.0.100");
    CHECK(rt::dotnet_entry_from_dir("sdk", "9.0.100-preview.1.24101.2").has_value());
    // A framework this plugin does not model is reported as unmodelled, not dropped.
    const auto odd = rt::dotnet_entry_from_dir("Microsoft.Something.New", "8.0.1");
    REQUIRE(odd.has_value());
    CHECK(odd->flavour == rt::DotnetFlavour::unmodelled);
    CHECK(rt::flavour_token(odd->flavour) == "unmodelled");
    // Not a version at all: no data (nullopt), distinct from unmodelled.
    CHECK_FALSE(rt::dotnet_entry_from_dir("Microsoft.NETCore.App", "").has_value());
    CHECK_FALSE(rt::dotnet_entry_from_dir("Microsoft.NETCore.App", "latest").has_value());
    CHECK_FALSE(rt::dotnet_entry_from_dir("Microsoft.NETCore.App", "8.0 31").has_value());
    CHECK_FALSE(rt::dotnet_entry_from_dir("Microsoft.NETCore.App", "8/../x").has_value());
}

// -- status rows and composition ---------------------------------------------------------

TEST_CASE("runtimes: none found at the standard roots is supported with zero data rows", "[runtimes]") {
    yuzu::shared::ConstraintAccumulator acc;
    const auto out = rt::compose_output("jvm", {}, acc);
    REQUIRE(out.size() == 1);
    CHECK(out[0] == "status|jvm|supported|-");
}

TEST_CASE("runtimes: the status row precedes every data row", "[runtimes]") {
    yuzu::shared::ConstraintAccumulator acc;
    const std::vector<std::string> data = {
        "jvm|jdk|17.0.20|/opt/java/openjdk|Eclipse Adoptium",
        "jvm|unmodelled|17.0.20.1|/usr/lib/jvm/java-17-openjdk-arm64|Debian"};
    const auto out = rt::compose_output("jvm", data, acc);
    REQUIRE(out.size() == 3);
    CHECK(out[0] == "status|jvm|supported|-");
    CHECK(out[1] == data[0]);
    CHECK(out[2] == data[1]);
}

TEST_CASE("runtimes: permission-denied is constrained with its token; success never hides it",
          "[runtimes]") {
    yuzu::shared::ConstraintAccumulator acc;
    acc.add_failure("linux:runtimes:permission_denied"); // first root unreadable
    // A later root read cleanly and contributed a row: that must not erase the failure.
    const auto out = rt::compose_output(
        "dotnet", {"dotnet|core|8.0.31|/usr/lib/dotnet/shared/Microsoft.NETCore.App/8.0.31|-"}, acc);
    REQUIRE(out.size() == 2);
    CHECK(out[0] == "status|dotnet|constrained|linux:runtimes:permission_denied");
    CHECK(out[1].rfind("dotnet|core|8.0.31|", 0) == 0);

    acc.add_failure("linux:runtimes:permission_denied"); // exact-duplicate token dedupes
    acc.add_failure("linux:runtimes:release_unparsable");
    const auto st = rt::status_from_accumulator(acc);
    CHECK(st.level == rt::StatusLevel::constrained);
    CHECK(st.reason == "linux:runtimes:permission_denied,linux:runtimes:release_unparsable");
}

TEST_CASE("runtimes: planned placeholder rows are exact", "[runtimes]") {
    CHECK(rt::format_planned_status_row("dotnet", "macos:planned") ==
          "status|dotnet|unsupported|macos:planned");
    CHECK(rt::format_planned_status_row("jvm", "windows:planned") ==
          "status|jvm|unsupported|windows:planned");
    CHECK(rt::status_token(rt::StatusLevel::supported) == "supported");
    CHECK(rt::status_token(rt::StatusLevel::constrained) == "constrained");
    CHECK(rt::status_token(rt::StatusLevel::unsupported) == "unsupported");
}

// -- wire grammar --------------------------------------------------------------------------

TEST_CASE("runtimes: a trailing backslash or embedded pipe cannot shift the field count",
          "[runtimes]") {
    const auto trailing = rt::format_runtime_row("jvm", "jdk", "17", "C:\\Java\\jdk17\\", "V");
    const auto f1 = split_fields_escape_aware(trailing);
    REQUIRE(f1.size() == 5);
    CHECK(f1[4] == "V");

    const auto piped = rt::format_runtime_row("dotnet", "core", "8.0.31", "/opt/we|ird/", "a|b");
    const auto f2 = split_fields_escape_aware(piped);
    REQUIRE(f2.size() == 5);
    CHECK(f2[3] == "/opt/we|ird/");
    CHECK(f2[4] == "a|b");

    // Untrusted text in the status reason is escaped too.
    const auto st = rt::format_status_row("jvm", rt::StatusLevel::constrained, "bad|token\\");
    CHECK(split_fields_escape_aware(st).size() == 4);
}

TEST_CASE("runtimes: empty free-text fields render as a dash", "[runtimes]") {
    CHECK(rt::format_runtime_row("dotnet", "core", "", "", "") == "dotnet|core|-|-|-");
}

// -- action mapping ---------------------------------------------------------------------------

TEST_CASE("runtimes: action names round-trip and unknown names are rejected", "[runtimes]") {
    for (auto a : {rt::Action::dotnet, rt::Action::jvm}) {
        CHECK(rt::parse_action(rt::action_name(a)) == std::optional<rt::Action>{a});
    }
    CHECK_FALSE(rt::parse_action("java").has_value());
    CHECK_FALSE(rt::parse_action("").has_value());
    CHECK_FALSE(rt::parse_action("DOTNET").has_value());
}

// -- version directories ---------------------------------------------------------------------

TEST_CASE("runtimes: only major.minor.patch (+prerelease/build) names are .NET version dirs",
          "[runtimes]") {
    for (const char* ok : {"8.0.31", "10.0.100", "9.0.100-preview.1.24101.2", "10.0.0-rc.1.25451.107",
                           "8.0.100+abc.1", "6.0.0-alpha+build-5"}) {
        INFO("version: " << ok);
        CHECK(rt::dotnet_entry_from_dir("sdk", ok).has_value());
    }
    // A backup or disabled copy, a date, a bare integer, a two-part version and stray characters
    // are not runtimes: the .NET host would not load them, so reporting them is a false inventory.
    for (const char* bad : {"8.0.31.bak", "6.0.0.disabled", "2024-01-01", "8", "8.0", "8.0.31~",
                            "8.0.31-", "8.0.31+", ".8.0.31", "8..31", "8.0.31 x", "v8.0.31",
                            "8.0.31_1", "NuGetFallbackFolder"}) {
        INFO("name: " << bad);
        CHECK_FALSE(rt::dotnet_entry_from_dir("sdk", bad).has_value());
    }
}

// -- release value bound ---------------------------------------------------------------------

TEST_CASE("runtimes: a recognised release value over the value cap is dropped and flagged",
          "[runtimes]") {
    // MUTATION: raising the cap or dropping the check keeps the 257-byte value and clears the flag.
    static_assert(rt::kMaxReleaseValueBytes == 256);
    const std::string edge(256, 'v');
    const std::string over(257, 'v');
    const auto at = rt::parse_release_file("IMPLEMENTOR=\"" + edge + "\"\nJAVA_VERSION=\"17\"\n");
    CHECK(at.implementor == edge); // exactly 256 bytes is kept
    CHECK_FALSE(at.oversized);
    const auto past = rt::parse_release_file("IMPLEMENTOR=\"" + over + "\"\nJAVA_VERSION=\"17\"\n");
    CHECK(past.implementor.empty());
    CHECK(past.oversized);
    CHECK(past.java_version == "17"); // the other keys are unaffected
    // An unrecognised key's long value is never read, so it is not a defect.
    CHECK_FALSE(rt::parse_release_file("MODULES=\"" + over + "\"\nJAVA_VERSION=\"17\"\n").oversized);
    // A dropped JAVA_VERSION leaves no version: no row (the leg records release_unparsable).
    const auto no_version = rt::parse_release_file("JAVA_VERSION=\"" + over + "\"\n");
    CHECK(no_version.oversized);
    CHECK_FALSE(rt::jvm_row(no_version, "/opt/j").has_value());
}

// -- release-less home and untrusted bytes ---------------------------------------------------

TEST_CASE("runtimes: a release-less home is a row with an unknown version, not silence",
          "[runtimes]") {
    CHECK(rt::jvm_row_release_missing("/usr/lib/jvm/java-8-openjdk-arm64") ==
          "jvm|unmodelled|-|/usr/lib/jvm/java-8-openjdk-arm64|-");
}

TEST_CASE("runtimes: invalid UTF-8 in untrusted text is replaced before it reaches the wire",
          "[runtimes]") {
    // One invalid byte in a proto3 string fails the parse of the whole output chunk, so a planted
    // directory name or release value must never reach the wire raw. MUTATION: dropping
    // sanitize_utf8 from field_or_dash leaves the 0xff / 0xe9 bytes in the row.
    const std::string bad_path = "/usr/lib/jvm/x\xff" "y";
    const std::string latin1_vendor = "Caf\xe9 JDK";
    const auto row = rt::format_runtime_row("jvm", "jdk", "17", bad_path, latin1_vendor);
    CHECK(row == "jvm|jdk|17|/usr/lib/jvm/x?y|Caf? JDK");
}
