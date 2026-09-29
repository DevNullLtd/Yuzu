/**
 * test_installed_apps_parsers.cpp — pure installed_apps parse helpers
 * (installed_apps_parsers.hpp, Wave 4 PR4.3a de-shell migration).
 *
 * The bounded-runner acquisition is the impure shell; the parsing of
 * dpkg-query/rpm/pacman/system_profiler/brew/pkgutil output is header-pure
 * and pinned here on every host (the firewall_parsers.hpp pattern).
 *
 * Fixture provenance, stated per TEST_CASE:
 *   - "real capture" — taken verbatim (or a self-contained excerpt) from a
 *     live command on this macOS 26 host, 2026-08-24.
 *   - "documented-format reconstruction" — no Linux host was available in
 *     this sandbox; these fixtures are hand-built from each tool's
 *     documented output format (dpkg-query(1)/rpm(8)/pacman(8) man pages),
 *     not a live capture. Flagged here, not silently assumed verified —
 *     same discipline as test_firewall_parsers.cpp's ufw fixtures.
 */

#include "installed_apps_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <string>
#include <vector>

using namespace yuzu::installed_apps::parsers;

// ── acquisition-health decision ─────────────────────────────────────────

TEST_CASE("is_degraded_run: every abnormal termination degrades", "[installed_apps]") {
    // Gate-3 remediation. This predicate decides whether a possibly-truncated
    // enumeration is published as the host's authoritative software set, and
    // it had no test because it lived in a static function in the .cpp.
    // The bug it exists to prevent: an earlier cut tested the individual
    // timed_out/tool_ran/output_truncated flags, which are ALL CLEAR for
    // `signaled` (OOM kill), `cancelled` (shutdown) and `line_limit`.
    constexpr bool kExited = true;
    constexpr bool kAbnormal = false; // any termination_reason != exited

    // Abnormal termination degrades regardless of exit code or tolerance.
    CHECK(is_degraded_run(kAbnormal, 0, false, false));
    CHECK(is_degraded_run(kAbnormal, 0, false, true));
    CHECK(is_degraded_run(kAbnormal, 1, false, true));

    // A clean, zero-exit, untruncated run is the ONLY healthy shape.
    CHECK_FALSE(is_degraded_run(kExited, 0, false, false));
    CHECK_FALSE(is_degraded_run(kExited, 0, false, true));

    // Truncation degrades even on a clean exit, and tolerance does not excuse
    // it -- tolerance is about exit codes, never about a cut-short capture.
    CHECK(is_degraded_run(kExited, 0, true, false));
    CHECK(is_degraded_run(kExited, 0, true, true));

    // A nonzero exit degrades a top-level enumerator...
    CHECK(is_degraded_run(kExited, 1, false, false));
    CHECK(is_degraded_run(kExited, 127, false, false));
    // ...but not the one opted-out call shape (per-ID `pkgutil --pkg-info` for
    // a receipt removed between enumeration and lookup, which exits 1).
    CHECK_FALSE(is_degraded_run(kExited, 1, false, true));
}

// ── Linux: dpkg-query ───────────────────────────────────────────────────

TEST_CASE("dpkg list: installed package kept, non-installed dropped — documented-format reconstruction",
          "[installed_apps]") {
    constexpr std::string_view out =
        "vim|2:9.0.1000-4ubuntu2|Debian Vim Maintainers "
        "<pkg-vim-maintainers@lists.alioth.debian.org>|install ok installed\n"
        "cowsay|3.03+dfsg2-8|Jason Spiro <jasonspiro3@gmail.com>|deinstall ok config-files\n";
    auto apps = parse_dpkg_list(out);
    REQUIRE(apps.size() == 1);
    CHECK(apps[0].name == "vim");
    CHECK(apps[0].version == "2:9.0.1000-4ubuntu2");
    CHECK(apps[0].publisher ==
          "Debian Vim Maintainers <pkg-vim-maintainers@lists.alioth.debian.org>");
    CHECK(apps[0].install_date == "-"); // dpkg-query carries no install-date field
}

TEST_CASE("dpkg list: empty output yields zero apps", "[installed_apps]") {
    CHECK(parse_dpkg_list("").empty());
}

// ── Linux: rpm ───────────────────────────────────────────────────────

TEST_CASE("rpm list: fields split and (none) mapped to '-' — documented-format reconstruction",
          "[installed_apps]") {
    constexpr std::string_view out =
        "bash|5.2.15-3.fc38|Fedora Project|Mon 15 Jan 2024 10:00:00 AM UTC\n"
        "gpg-pubkey|(none)|(none)|Tue 01 Aug 2023 09:00:00 AM UTC\n";
    auto apps = parse_rpm_list(out);
    REQUIRE(apps.size() == 2);
    CHECK(apps[0].name == "bash");
    CHECK(apps[0].version == "5.2.15-3.fc38");
    CHECK(apps[0].publisher == "Fedora Project");
    CHECK(apps[0].install_date == "Mon 15 Jan 2024 10:00:00 AM UTC");
    CHECK(apps[1].name == "gpg-pubkey");
    CHECK(apps[1].publisher == "-"); // (none) -> "-"
}

// ── Linux: pacman ───────────────────────────────────────────────────────

TEST_CASE("pacman list: name/version split on first space — documented-format reconstruction",
          "[installed_apps]") {
    constexpr std::string_view out = "linux 6.6.8.arch1-1\nfirefox 121.0-1\n";
    auto apps = parse_pacman_list(out);
    REQUIRE(apps.size() == 2);
    CHECK(apps[0].name == "linux");
    CHECK(apps[0].version == "6.6.8.arch1-1");
    CHECK(apps[1].name == "firefox");
    CHECK(apps[1].version == "121.0-1");
}

TEST_CASE("pacman list: a line with no space is skipped, not crashed on", "[installed_apps]") {
    CHECK(parse_pacman_list("malformed-no-version\n").empty());
}

// ── macOS: system_profiler SPApplicationsDataType -detailLevel mini ────

TEST_CASE("system_profiler apps: real capture — two full app blocks", "[installed_apps]") {
    // Excerpt of `system_profiler SPApplicationsDataType -detailLevel mini`,
    // captured verbatim on this host (macOS 26, arm64, 2026-08-24). Includes
    // the top-level "Applications:" 0-indent header (must be ignored — it
    // never matches the 4-space-header test) and attribute lines
    // (Obtained from/Kind/Signed by) the old grep never selected either.
    constexpr std::string_view out =
        "Applications:\n"
        "\n"
        "    AppleMobileSync:\n"
        "\n"
        "      Version: 5.0\n"
        "      Obtained from: Apple\n"
        "      Last Modified: 21/05/2026, 10:04\n"
        "      Kind: Universal\n"
        "      Signed by: Software Signing, Apple Code Signing Certification Authority, "
        "Apple Root CA\n"
        "      Location: /Library/Apple/System/Library/PrivateFrameworks/MobileDevice.framework/"
        "Versions/A/AppleMobileSync.app\n"
        "\n"
        "    Keynote:\n"
        "\n"
        "      Version: 15.1.1\n"
        "      Obtained from: App Store\n"
        "      Last Modified: 18/07/2026, 01:45\n"
        "      Kind: Universal\n"
        "      Signed by: Apple Mac OS Application Signing, Apple Worldwide Developer "
        "Relations Certification Authority, Apple Root CA\n"
        "      Location: /Applications/Keynote Creator Studio.app\n";

    auto apps = parse_system_profiler_apps(out);
    REQUIRE(apps.size() == 2);

    CHECK(apps[0].name == "AppleMobileSync");
    CHECK(apps[0].version == "5.0");
    CHECK(apps[0].install_date == "21/05/2026, 10:04");
    CHECK(apps[0].location ==
          "/Library/Apple/System/Library/PrivateFrameworks/MobileDevice.framework/Versions/A/"
          "AppleMobileSync.app");
    CHECK(apps[0].publisher.empty()); // system_profiler mini exposes no publisher field

    // Last app in the fixture — proves the eof flush() path (no trailing
    // header/blank line follows it), not just the mid-stream flush #1 needed.
    CHECK(apps[1].name == "Keynote");
    CHECK(apps[1].version == "15.1.1");
    CHECK(apps[1].install_date == "18/07/2026, 01:45");
    CHECK(apps[1].location == "/Applications/Keynote Creator Studio.app");
}

TEST_CASE("system_profiler apps: empty output yields zero apps", "[installed_apps]") {
    CHECK(parse_system_profiler_apps("").empty());
}

TEST_CASE("system_profiler apps: an app header with no body fields is still emitted",
          "[installed_apps]") {
    // A 4-space header immediately followed by another 4-space header (no
    // Version/Last Modified/Location lines in between) — the old grep would
    // still have selected the header line, and the app must still appear
    // (with empty version/date/location), matching the old code's
    // `!current_name.empty()` emit condition (name presence is the only gate).
    constexpr std::string_view out = "    BareApp:\n"
                                     "\n"
                                     "    NextApp:\n"
                                     "\n"
                                     "      Version: 1.0\n";
    auto apps = parse_system_profiler_apps(out);
    REQUIRE(apps.size() == 2);
    CHECK(apps[0].name == "BareApp");
    CHECK(apps[0].version.empty());
    CHECK(apps[1].name == "NextApp");
    CHECK(apps[1].version == "1.0");
}

TEST_CASE("system_profiler apps: a valueless key does not throw and yields an empty field",
          "[installed_apps]") {
    // Gate-1 regression. The value half used to be `trimmed.substr(colon + 2)`,
    // and string_view::substr THROWS std::out_of_range once the offset passes
    // size() -- for a bare "Version:" (size 8, colon at 7) that offset is 9.
    // No host observed emits a valueless key, so this was latent rather than
    // live, but it is reachable from parser input and the sibling parsers in
    // this header promise "never a crash" on malformed input.
    constexpr std::string_view out = "    OddApp:\n"
                                     "      Version:\n"
                                     "      Last Modified:\n"
                                     "      Location:\n";
    std::vector<AppRecord> apps;
    REQUIRE_NOTHROW(apps = parse_system_profiler_apps(out));
    REQUIRE(apps.size() == 1);
    CHECK(apps[0].name == "OddApp");
    CHECK(apps[0].version.empty());
    CHECK(apps[0].install_date.empty());
    CHECK(apps[0].location.empty());
}

TEST_CASE("system_profiler apps: non-ASCII and punctuation-leading names are emitted",
          "[installed_apps]") {
    // Documents the ONE deliberate deviation from byte-identity with the old
    // shell pipeline. The retired `grep -E '^ {4}\w'` matched [A-Za-z0-9_] in
    // the C locale, so it silently DROPPED these apps from list/query
    // entirely; the in-process header test admits them. Additive only -- it
    // cannot change or remove a row the old grep already produced.
    constexpr std::string_view out = "    \xC3\x9C" "bersicht:\n"
                                     "      Version: 2.0\n"
                                     "    .hidden-helper:\n"
                                     "      Version: 3.0\n"
                                     "    Normal:\n"
                                     "      Version: 4.0\n";
    auto apps = parse_system_profiler_apps(out);
    REQUIRE(apps.size() == 3);
    CHECK(apps[0].name == "\xC3\x9C" "bersicht");
    CHECK(apps[0].version == "2.0");
    CHECK(apps[1].name == ".hidden-helper");
    CHECK(apps[2].name == "Normal");
}

TEST_CASE("system_profiler apps: an app named like an attribute key is its own row",
          "[installed_apps]") {
    // Gate-2 regression, found independently by BOTH adversarial reviewers.
    // The attribute prefixes used to be tested before the 4-space header, so a
    // real app named "Location" (or "Version" / "Last Modified") matched the
    // attribute branch: it never flushed, so it vanished from list/query and
    // the inventory, AND its fields landed on the PRECEDING app -- which, via
    // the Location-driven #2273 enrichment, meant the impostor's bundle
    // supplied a legitimate app's publisher and signature_status.
    // Indent, not key name, decides.
    constexpr std::string_view out = "    Keynote:\n"
                                     "      Version: 14.0\n"
                                     "      Location: /Applications/Keynote.app\n"
                                     "    Location:\n"
                                     "      Version: 6.6.6\n"
                                     "      Location: /Applications/Location.app\n"
                                     "    Safari:\n"
                                     "      Version: 18\n"
                                     "      Location: /Applications/Safari.app\n";
    auto apps = parse_system_profiler_apps(out);
    REQUIRE(apps.size() == 3);

    // Keynote keeps its OWN version and path -- not the impostor's.
    CHECK(apps[0].name == "Keynote");
    CHECK(apps[0].version == "14.0");
    CHECK(apps[0].location == "/Applications/Keynote.app");

    // The app named "Location" is present, not concealed.
    CHECK(apps[1].name == "Location");
    CHECK(apps[1].version == "6.6.6");
    CHECK(apps[1].location == "/Applications/Location.app");

    CHECK(apps[2].name == "Safari");
    CHECK(apps[2].version == "18");
}

TEST_CASE("system_profiler apps: an app named Version or Last Modified is its own row",
          "[installed_apps]") {
    constexpr std::string_view out = "    Version:\n"
                                     "      Version: 1.0\n"
                                     "    Last Modified:\n"
                                     "      Version: 2.0\n"
                                     "    Normal:\n"
                                     "      Version: 3.0\n";
    auto apps = parse_system_profiler_apps(out);
    REQUIRE(apps.size() == 3);
    CHECK(apps[0].name == "Version");
    CHECK(apps[0].version == "1.0");
    CHECK(apps[1].name == "Last Modified");
    CHECK(apps[1].version == "2.0");
    CHECK(apps[2].name == "Normal");
    CHECK(apps[2].version == "3.0");
}

TEST_CASE("system_profiler apps: deeper-indented lines are never app headers",
          "[installed_apps]") {
    // The widening above loosens WHICH character may follow the 4 spaces, not
    // the indent rule itself: a 6-space attribute line must still never be
    // mistaken for an app header, or every app would gain phantom siblings.
    constexpr std::string_view out = "Applications:\n"
                                     "\n"
                                     "    RealApp:\n"
                                     "      Obtained from: Apple\n"
                                     "      Kind: Universal\n"
                                     "      Signed by: Software Signing\n"
                                     "      Version: 1.2\n";
    auto apps = parse_system_profiler_apps(out);
    REQUIRE(apps.size() == 1);
    CHECK(apps[0].name == "RealApp");
    CHECK(apps[0].version == "1.2");
}

TEST_CASE("system_profiler apps: a Location value must be absolute and control-byte free",
          "[installed_apps]") {
    // Defence in depth (not a closure -- see the issue on structured
    // system_profiler output). Mutation: removing the guard yields
    // "relative.app" as the location.
    constexpr std::string_view out = "    Rel:\n"
                                     "      Version: 1\n"
                                     "      Location: relative.app\n"
                                     "    Ctl:\n"
                                     "      Version: 1\n"
                                     "      Location: /Applications/x\ty.app\n"
                                     "    Ok:\n"
                                     "      Version: 1\n"
                                     "      Location: /Applications/Ok.app\n";
    const auto apps = parse_system_profiler_apps(out);
    REQUIRE(apps.size() == 3);
    CHECK(apps[0].location.empty());
    CHECK(apps[1].location.empty());
    CHECK(apps[2].location == "/Applications/Ok.app");
}

TEST_CASE("system_profiler apps: a non-ASCII Location is preserved", "[installed_apps]") {
    // Mutation: comparing plain `char` (signed on the macOS targets) instead of
    // `unsigned char` in the guard's byte-below-0x20 test blanks every UTF-8 path.
    constexpr std::string_view out = "    \xC3\x9C" "bersicht:\n"
                                     "      Version: 2.0\n"
                                     "      Location: /Applications/\xC3\x9C" "bersicht.app\n";
    const auto apps = parse_system_profiler_apps(out);
    REQUIRE(apps.size() == 1);
    CHECK(apps[0].location == "/Applications/\xC3\x9C" "bersicht.app");
}

// ── macOS: brew list --versions ─────────────────────────────────────────

TEST_CASE("brew list: name/version split, missing version tolerated — documented-format reconstruction",
          "[installed_apps]") {
    constexpr std::string_view out = "wget 1.21.4\ngit 2.43.0\nnode\n";
    auto apps = parse_brew_list(out);
    REQUIRE(apps.size() == 3);
    CHECK(apps[0].name == "wget");
    CHECK(apps[0].version == "1.21.4");
    CHECK(apps[1].name == "git");
    CHECK(apps[1].version == "2.43.0");
    CHECK(apps[2].name == "node");
    CHECK(apps[2].version.empty());
}

TEST_CASE("brew list: empty output yields zero apps", "[installed_apps]") {
    CHECK(parse_brew_list("").empty());
}

// ── macOS: pkgutil (#2273 enrichment) ───────────────────────────────────

TEST_CASE("pkgutil pkgs: real capture — id list, blank lines dropped", "[installed_apps]") {
    // `pkgutil --pkgs`, real capture on this host (macOS 26, 2026-08-24) --
    // a small excerpt (the real list ran to 65 entries).
    constexpr std::string_view out = "com.apple.pkg.CLTools_SDK_macOS13\n"
                                     "com.apple.pkg.CLTools_Executables\n"
                                     "\n"
                                     "com.apple.pkg.MobileAssets\n";
    auto ids = parse_pkgutil_pkgs(out);
    REQUIRE(ids.size() == 3);
    CHECK(ids[0] == "com.apple.pkg.CLTools_SDK_macOS13");
    CHECK(ids[1] == "com.apple.pkg.CLTools_Executables");
    CHECK(ids[2] == "com.apple.pkg.MobileAssets");
}

TEST_CASE("pkgutil pkgs: empty output yields zero ids", "[installed_apps]") {
    CHECK(parse_pkgutil_pkgs("").empty());
}

TEST_CASE("pkgutil pkg-info: real capture — version + install-time extracted",
          "[installed_apps]") {
    // `pkgutil --pkg-info com.apple.pkg.CLTools_Executables`, real capture
    // on this host (macOS 26, 2026-08-24).
    constexpr std::string_view out = "package-id: com.apple.pkg.CLTools_Executables\n"
                                     "version: 26.6.0.0.1781586589\n"
                                     "volume: /\n"
                                     "location: /\n"
                                     "install-time: 1787153822\n";
    auto info = parse_pkgutil_pkg_info(out);
    CHECK(info.version == "26.6.0.0.1781586589");
    CHECK(info.install_time == "1787153822");
}

TEST_CASE("pkgutil pkg-info: malformed/empty input yields an all-empty result, never a crash",
          "[installed_apps]") {
    auto info = parse_pkgutil_pkg_info("");
    CHECK(info.version.empty());
    CHECK(info.install_time.empty());

    auto garbage = parse_pkgutil_pkg_info("not a key-value line at all\n");
    CHECK(garbage.version.empty());
    CHECK(garbage.install_time.empty());
}

// ── list row formatting (ADR-0028 binding condition) ────────────────────────
// Pure formatter -- no fixture provenance needed; inputs are literals.

TEST_CASE("format_app_row: all six fields present", "[installed_apps]") {
    CHECK(format_app_row({"Safari", "26.0", "Apple", "2026-08-13", "/Applications/Safari.app",
                          "com.apple.Safari"}) ==
          "app|Safari|26.0|Apple|2026-08-13|/Applications/Safari.app|com.apple.Safari");
}

TEST_CASE("format_app_row: absent InstallLocation renders '-', never fabricated",
          "[installed_apps]") {
    CHECK(format_app_row({"Legacy Tool", "1.0", "Acme", "20200101", "", ""}) ==
          "app|Legacy Tool|1.0|Acme|20200101|-|-");
    // bundle_id absent alone (Windows/Linux shape with a location, or a macOS
    // bundle that carries no CFBundleIdentifier).
    CHECK(format_app_row({"Tool", "1.0", "Acme", "20200101", "C:\\Program Files\\Tool", ""}) ==
          "app|Tool|1.0|Acme|20200101|C:/Program Files/Tool|-");
    // location present, bundle id absent.
    CHECK(format_app_row({"Tool", "1.0", "Acme", "20200101", "", "com.acme.tool"}) ==
          "app|Tool|1.0|Acme|20200101|-|com.acme.tool");
}

TEST_CASE("format_app_row: empty optional fields all render '-', always seven fields",
          "[installed_apps]") {
    const auto row = format_app_row({"OnlyName", "", "", "", "", ""});
    CHECK(row == "app|OnlyName|-|-|-|-|-");
    CHECK(std::count(row.begin(), row.end(), '|') == 6);
}

namespace {

// Copy of the escape-aware splitter in test_installed_apps_actions.cpp: backslash-pipe
// is one escaped pipe, a bare '|' is a delimiter -- the shared server decoder's
// find_unescaped_pipe/unescape_pipes grammar (server/core/src/result_parsing.hpp).
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

TEST_CASE("format_app_row: a trailing backslash in install_location cannot swallow the "
          "delimiter",
          "[installed_apps]") {
    // A Windows InstallLocation ends in a backslash (9 of 241 rows in the pre-fix
    // Windows capture). Raw, that backslash plus the following delimiter reads as an
    // escaped pipe: the backslash is deleted and the row loses a field.
    // safe_output_field folds the backslash to '/', so the row keeps seven fields
    // under an escape-aware split.
    const auto row = format_app_row({.name = "7-Zip",
                                     .version = "26.02",
                                     .publisher = "Igor Pavlov",
                                     .install_location = "C:\\Program Files\\7-Zip\\"});
    CHECK(row == "app|7-Zip|26.02|Igor Pavlov|-|C:/Program Files/7-Zip/|-");
    CHECK(split_fields_escape_aware(row).size() == 7);

    // A literal '|' in the two ADR-0028 columns is escaped, not a delimiter.
    const auto piped = format_app_row({.name = "X", .install_location = "a|b"});
    CHECK(piped == "app|X|-|-|-|a\\|b|-");
    const auto fields = split_fields_escape_aware(piped);
    REQUIRE(fields.size() == 7);
    CHECK(fields[5] == "a|b");

    // bundle_id passes through the same escape (dropping safe_output_field on the last
    // column alone must fail too).
    const auto bid = format_app_row({.name = "X", .bundle_id = "a|b\\c"});
    CHECK(bid == "app|X|-|-|-|-|a\\|b/c");
    CHECK(split_fields_escape_aware(bid).size() == 7);

    // install_date is no longer the row's last field, so a trailing backslash in it
    // would swallow the install_location delimiter; every field is escaped (see the
    // next case).
    const auto dated = format_app_row({.name = "X", .install_date = "20260101\\"});
    CHECK(dated == "app|X|-|-|20260101/|-|-");
    CHECK(split_fields_escape_aware(dated).size() == 7);
}

TEST_CASE("format_app_row: the empty-list sentinel is the formatter's own seven-field row",
          "[installed_apps]") {
    // do_list emits this for a healthy-but-empty acquisition; deriving it from
    // format_app_row keeps the sentinel and the row shape defined in one place.
    CHECK(format_app_row({.name = "No applications found"}) ==
          "app|No applications found|-|-|-|-|-");
}

TEST_CASE("format_app_row: hostile bytes in ANY field cannot forge or split a row",
          "[installed_apps]") {
    // Every one of the six fields carries the full hostile alphabet; the row must
    // stay one NUL-free line of exactly seven escape-aware tokens that decode to
    // the folded value. Mutation: dropping list_field on `name` (raw std::string
    // append) fails the first sub-case.
    const std::string hostile = "a|b\\c\r\nd";
    const std::string folded = "a|b/c  d";
    const AppRowFields f{"N", "V", "P", "D", "L", "B"};
    for (std::size_t i = 0; i < 6; ++i) {
        AppRowFields g = f;
        std::string* gslots[] = {&g.name,         &g.version,          &g.publisher,
                                 &g.install_date, &g.install_location, &g.bundle_id};
        *gslots[i] = hostile;
        const auto row = format_app_row(g);
        INFO("field " << i);
        CHECK(row.find('\n') == std::string::npos);
        CHECK(row.find('\r') == std::string::npos);
        const auto fields = split_fields_escape_aware(row);
        REQUIRE(fields.size() == 7);
        CHECK(fields[i + 1] == folded);
    }
}

TEST_CASE("format_app_row: an interior NUL cuts the FIELD, never the row", "[installed_apps]") {
    // write_output hands the row to a C string (plugin.hpp:71); before this fix an
    // interior NUL in publisher truncated the row to the 4-token `query` shape.
    // Mutation: removing the NUL cut in list_field leaves a NUL in the row.
    const auto row = format_app_row({"X", "1", std::string("p\0x", 3), "D", "L", "B"});
    CHECK(row.find('\0') == std::string::npos);
    CHECK(row == "app|X|1|p|D|L|B");
    // A field that is nothing but NUL renders "-".
    CHECK(format_app_row({"X", std::string("\0", 1), "", "", "", ""}) == "app|X|-|-|-|-|-");
}

TEST_CASE("format_app_row: every field is length-bounded at a UTF-8 boundary",
          "[installed_apps]") {
    // CoreFoundation returns a 5 MiB CFBundleIdentifier in full; one such row
    // would exceed the 4 MiB gRPC receive default. Mutation: removing the bound in
    // list_field fails the size check.
    const auto big = format_app_row({.name = "X", .bundle_id = std::string(5u << 20, 'a')});
    const auto fields = split_fields_escape_aware(big);
    REQUIRE(fields.size() == 7);
    CHECK(fields[6].size() == kMaxListFieldBytes);
    // The cut never splits a multi-byte sequence: 4095 ASCII bytes + a 2-byte
    // sequence is cut before the sequence, not inside it.
    const auto edge =
        format_app_row({.name = std::string(kMaxListFieldBytes - 1, 'a') + "\xC3\xA9"});
    const auto edge_fields = split_fields_escape_aware(edge);
    REQUIRE(edge_fields.size() > 1);
    CHECK(edge_fields[1].size() == kMaxListFieldBytes - 1);
    // A field exactly at the bound is untouched.
    const auto exact = format_app_row({.name = std::string(kMaxListFieldBytes, 'a')});
    const auto exact_fields = split_fields_escape_aware(exact);
    REQUIRE(exact_fields.size() > 1);
    CHECK(exact_fields[1].size() == kMaxListFieldBytes);
    // A field of nothing but UTF-8 continuation bytes backs off to empty and renders
    // "-". Mutation: dropping the `cut > 0` guard in list_field walks the back-off
    // past index 0 (out-of-bounds read; the Linux ASan/UBSan legs observe it).
    CHECK(format_app_row({.name = "X",
                          .bundle_id = std::string(kMaxListFieldBytes + 1, '\x80')}) ==
          "app|X|-|-|-|-|-");
}

TEST_CASE("format_app_row: a pipe-filled field is bounded before it is escaped",
          "[installed_apps]") {
    // Mutation: escape-then-bound in list_field. Escaping first can cut between a '\'
    // and its '|'; the stranded '\' swallows the next delimiter and the row loses a
    // token (the odd-offset input), and the bounded field decodes to 2,048 pipes
    // instead of 4,096 (the 5,000-pipe input).
    const auto expect_bounded = [](const std::string& hostile) {
        const auto row = format_app_row({.name = "X", .version = hostile});
        const auto fields = split_fields_escape_aware(row);
        REQUIRE(fields.size() == 7);
        // A decoded token never holds a backslash: none survives folding, so a
        // trailing lone one would be a cut escape.
        for (const auto& token : fields)
            CHECK(token.find('\\') == std::string::npos);
        CHECK(fields[2].size() == kMaxListFieldBytes);
    };
    expect_bounded(std::string(5000, '|'));
    // 4095 ordinary bytes then pipes: the 4096-byte cut falls between an escaping
    // '\' and its '|' if the escape ran first.
    expect_bounded(std::string(kMaxListFieldBytes - 1, 'a') + std::string(10, '|'));
}

// ── Windows registry value types (InstallLocation acceptance) ───────────────
// Pure predicate -- the RegQueryValueExW call it gates is Windows-only, but the
// decision is testable on every host. 1 = REG_SZ, 2 = REG_EXPAND_SZ,
// 3 = REG_BINARY, 7 = REG_MULTI_SZ (installed_apps_registry_utf8.hpp static_asserts the
// first two on Windows).

TEST_CASE("reg_string_type_accepted: REG_SZ always, REG_EXPAND_SZ only when accepted",
          "[installed_apps]") {
    CHECK(reg_string_type_accepted(1, false));
    CHECK_FALSE(reg_string_type_accepted(2, false));
    CHECK(reg_string_type_accepted(2, true));
    CHECK_FALSE(reg_string_type_accepted(3, true));
    CHECK_FALSE(reg_string_type_accepted(7, true));
}

// ── Windows dedupe: the plugin's own pipeline (sort + location layer + unique) ─
// dedupe_uninstall_records is the function the plugin calls, instantiated with
// the same record type (AppInfo aliases AppRowFields), so these cases observe the
// comparator, the placement of the location layer and unique() -- not a mirror.

TEST_CASE("dedupe_uninstall_records: unsorted input is sorted by (name, version) and the "
          "survivor keeps its own fields while gaining a duplicate's location",
          "[installed_apps]") {
    // Mutations: deleting the std::sort leaves Zed first; moving the location
    // layer after unique() leaves Tool 1.0's location empty.
    std::vector<AppRowFields> v{
        {.name = "Zed", .version = "1.0", .install_location = "C:\\Zed\\"},
        {.name = "Tool", .version = "2.0"},
        {.name = "Tool", .version = "1.0", .publisher = "Acme", .install_date = "20200101"},
        {.name = "Tool", .version = "1.0", .publisher = "Acme Inc", .install_date = "20240202",
         .install_location = "C:\\Program Files\\Tool\\"},
    };
    dedupe_uninstall_records(v);
    REQUIRE(v.size() == 3);
    CHECK(v[0].name == "Tool");
    CHECK(v[0].version == "1.0");
    // The survivor is whichever Tool 1.0 record std::sort leaves first (equal-key
    // order is unspecified): its publisher/install_date pair is one input record's
    // pair, never a mix of the two.
    const bool first_record = v[0].publisher == "Acme" && v[0].install_date == "20200101";
    const bool second_record = v[0].publisher == "Acme Inc" && v[0].install_date == "20240202";
    CHECK((first_record || second_record));
    CHECK(v[0].install_location == "C:\\Program Files\\Tool\\");
    CHECK(v[1].version == "2.0");
    CHECK(v[1].install_location.empty()); // never borrowed across versions
    CHECK(v[2].name == "Zed");
}

TEST_CASE("dedupe_uninstall_records: among populated locations the lexicographic minimum wins, "
          "whatever the run order",
          "[installed_apps]") {
    // The value must not depend on the order std::sort leaves equal keys in.
    // Mutation: "first populated wins" fails the permutation whose first record is
    // C:\B\.
    std::vector<AppRowFields> run{
        {.name = "Tool", .version = "1.0", .install_location = "C:\\B\\"},
        {.name = "Tool", .version = "1.0", .install_location = "C:\\A\\"},
        {.name = "Tool", .version = "1.0"},
    };
    const auto by_location = [](const AppRowFields& a, const AppRowFields& b) {
        return a.install_location < b.install_location;
    };
    std::sort(run.begin(), run.end(), by_location);
    do {
        auto v = run;
        dedupe_uninstall_records(v);
        REQUIRE(v.size() == 1);
        CHECK(v[0].install_location == "C:\\A\\");
    } while (std::next_permutation(run.begin(), run.end(), by_location));
}

TEST_CASE("dedupe_uninstall_records: a location never leaks across products sharing a version",
          "[installed_apps]") {
    // Mutation: dropping the `name` compare in the run detection makes A inherit
    // B's location.
    std::vector<AppRowFields> v{
        {.name = "A", .version = "1.0"},
        {.name = "B", .version = "1.0", .install_location = "C:\\B\\"},
    };
    dedupe_uninstall_records(v);
    REQUIRE(v.size() == 2);
    CHECK(v[0].install_location.empty());
    CHECK(v[1].install_location == "C:\\B\\");
}

TEST_CASE("dedupe_uninstall_records: a location never leaks across versions of one product",
          "[installed_apps]") {
    // Mutation: dropping `apps[end].version == apps[i].version` from the run loop
    // makes Tool 1.0 inherit Tool 2.0's location.
    std::vector<AppRowFields> v{
        {.name = "Tool", .version = "1.0"},
        {.name = "Tool", .version = "2.0", .install_location = "C:\\Tool2\\"},
    };
    dedupe_uninstall_records(v);
    REQUIRE(v.size() == 2);
    CHECK(v[0].version == "1.0");
    CHECK(v[0].install_location.empty());
    CHECK(v[1].version == "2.0");
    CHECK(v[1].install_location == "C:\\Tool2\\");
}
