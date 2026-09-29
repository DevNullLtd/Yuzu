/**
 * test_software_actions_parsers.cpp — pure software_actions parse helpers
 * (software_actions_parsers.hpp; software_actions' FIRST test coverage,
 * Wave 4 PR4.3b).
 *
 * The bounded-runner acquisition in software_actions_plugin.cpp is the
 * impure shell; the decision-shaped parsing of winget/apt/yum/
 * softwareupdate/dpkg-query output is header-pure and pinned here on every
 * host (the firewall_parsers.hpp pattern).
 *
 * Fixture provenance, stated honestly:
 *   - the `softwareupdate -l` fixture is a REAL capture from this macOS host
 *     (2026-08-24, `/usr/sbin/softwareupdate -l`, rc=0, empty stderr).
 *   - the 23-row winget fixture in the "REAL capture" case below is a REAL
 *     capture from a live Windows host (`winget upgrade
 *     --accept-source-agreements`), including its two trailer lines.
 *   - the remaining winget/apt/yum/dpkg-query fixtures are RECONSTRUCTED from
 *     each tool's documented output format.
 */

#include "software_actions_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::software_actions;

// ── Windows: winget upgrade ────────────────────────────────────────────────

TEST_CASE("winget upgrade: fixed-width table with two rows — reconstructed from documented format",
          "[software_actions]") {
    constexpr std::string_view out =
        "Name               Id                        Version      Available    Source\n"
        "-----------------------------------------------------------------------------\n"
        "7-Zip 22.01        7zip.7zip                 22.01        23.01        winget\n"
        "Git                Git.Git                   2.40.0       2.42.0       winget\n"
        "\n"
        "2 upgrades available.\n";
    auto parsed = parse_winget_upgrade(out);
    CHECK(parsed.separator_found);
    REQUIRE(parsed.rows.size() == 2);
    CHECK(parsed.rows[0].name == "7-Zip 22.01");
    CHECK(parsed.rows[0].current_version == "22.01");
    CHECK(parsed.rows[0].available_version == "23.01");
    CHECK(parsed.rows[1].name == "Git");
    CHECK(parsed.rows[1].current_version == "2.40.0");
    CHECK(parsed.rows[1].available_version == "2.42.0");
}

TEST_CASE("winget upgrade: two-column row (no version columns) falls back to name-only",
          "[software_actions]") {
    constexpr std::string_view out = "Name               Id\n"
                                     "-----------------------------------------------------------------------------\n"
                                     "SomeApp             some.vendor.app\n";
    auto parsed = parse_winget_upgrade(out);
    REQUIRE(parsed.rows.size() == 1);
    CHECK(parsed.rows[0].name == "SomeApp");
    CHECK(parsed.rows[0].current_version == "-");
    CHECK(parsed.rows[0].available_version == "-");
}

TEST_CASE("winget upgrade: separator found but zero data rows is the up-to-date shape",
          "[software_actions]") {
    constexpr std::string_view out =
        "Name               Id                        Version      Available    Source\n"
        "-----------------------------------------------------------------------------\n"
        "No installed package found matching input criteria.\n";
    auto parsed = parse_winget_upgrade(out);
    CHECK(parsed.separator_found);
    // The "no installed package" line is winget's own nothing-matched message.
    // It is rejected as data because it does not respect the column boundaries,
    // and recognised as a message so it is not counted as a DROPPED row either.
    CHECK(parsed.rows.empty());
    CHECK(parsed.unmapped_lines == 0);
}

TEST_CASE("winget upgrade: empty output never finds the separator", "[software_actions]") {
    auto parsed = parse_winget_upgrade("");
    CHECK_FALSE(parsed.separator_found);
    CHECK(parsed.rows.empty());
}

TEST_CASE("winget upgrade: footer 'N upgrades available' line is skipped, not parsed as a row",
          "[software_actions]") {
    constexpr std::string_view out =
        "Name               Id                        Version      Available    Source\n"
        "-----------------------------------------------------------------------------\n"
        "Git                Git.Git                   2.40.0       2.42.0       winget\n"
        "1 upgrades available.\n";
    auto parsed = parse_winget_upgrade(out);
    REQUIRE(parsed.rows.size() == 1);
    CHECK(parsed.rows[0].name == "Git");
}

// ── Windows: winget upgrade, REAL capture (the column-mis-mapping regression)

/// Verbatim `winget upgrade --accept-source-agreements` output from a live
/// Windows host, trailer lines included. Five of these 23 rows are the
/// pathological shape that broke the old split-on-2+-spaces parser: their
/// Name or Id fills its column completely, leaving a SINGLE space before the
/// next column, so a whitespace split yielded 3 or 4 fields instead of 5.
/// Reading `parts[3]` as the available version then returned the *Source*
/// column — a literal "winget" reported as a version number.
constexpr std::string_view kRealWingetCapture =
    "Name                                             Id                                     Version          Available        Source\n"
    "--------------------------------------------------------------------------------------------------------------------------------\n"
    "CMake                                            Kitware.CMake                          4.3.3            4.4.2            winget\n"
    "Docker Desktop                                   Docker.DockerDesktop                   4.84.0           4.87.0           winget\n"
    "Erlang OTP 28.5.0.1 (16.4.0.1)                   Erlang.ErlangOTP                       28.5.0.1         29.0.5           winget\n"
    "Git                                              Git.Git                                2.54.0           2.55.0.3         winget\n"
    "GitHub CLI                                       GitHub.cli                             2.89.0           2.97.0           winget\n"
    "Google Chrome                                    Google.Chrome                          149.0.7827.201   151.0.7922.170   winget\n"
    "Microsoft 365 Apps for enterprise - en-us        Microsoft.Office                       16.0.19822.20114 16.0.20228.20124 winget\n"
    "Microsoft GameInput                              Microsoft.GameInput                    3.3.221.0        3.4.218          winget\n"
    "Microsoft Visual Studio Code (User)              Microsoft.VisualStudioCode             1.128.1          1.132.0          winget\n"
    "Microsoft Windows Desktop Runtime - 6.0.20 (x86) Microsoft.DotNet.DesktopRuntime.6      6.0.20           6.0.36           winget\n"
    "Microsoft Windows Desktop Runtime - 8.0.28 (x86) Microsoft.DotNet.DesktopRuntime.8      8.0.28           8.0.30           winget\n"
    "Node.js (LTS)                                    OpenJS.NodeJS.LTS                      24.16.0          24.19.0          winget\n"
    "NordVPN                                          NordSecurity.NordVPN                   7.60.1.0         8.9.1.0          winget\n"
    "Notepad++ (64-bit x64)                           Notepad++.Notepad++                    8.9.6.4          8.9.7            winget\n"
    "Outlook for Windows                              Microsoft.Outlook                      1.2026.602.400   1.2026.720.100   winget\n"
    "PlayStation Accessories                          PlayStation.PlayStationAccessories     2.0.0.13         2.2.1.2          winget\n"
    "PostgreSQL 18                                    PostgreSQL.PostgreSQL.18               18.2-1           18.6-1           winget\n"
    "Python Launcher                                  Python.Launcher                        3.12.10          3.13.5           winget\n"
    "Signal 8.18.0                                    OpenWhisperSystems.Signal              8.18.0           8.24.0           winget\n"
    "Visual Studio Build Tools 2022                   Microsoft.VisualStudio.2022.BuildTools < 17.14.35       17.14.39         winget\n"
    "Windows 11 Installation Assistant                Microsoft.WindowsInstallationAssistant 1.4.19041.5003   1.4.19041.6448   winget\n"
    "Windows PC Health Check                          Microsoft.WindowsPCHealthCheck         3.6.2204.08001   4.0.2410.23001   winget\n"
    "Windows Subsystem for Linux                      Microsoft.WSL                          2.6.3.0          2.7.12           winget\n"
    "23 upgrades available.\n"
    "1 package(s) have version numbers that cannot be determined. Use --include-unknown to see all results.\n";

TEST_CASE("winget upgrade: REAL capture — all 23 rows parse, no column is ever mis-mapped",
          "[software_actions]") {
    auto parsed = parse_winget_upgrade(kRealWingetCapture);
    CHECK(parsed.separator_found);
    CHECK_FALSE(parsed.header_unrecognized);
    // Exactly the 23 data rows — neither trailer line becomes a phantom row.
    REQUIRE(parsed.rows.size() == 23);

    // THE regression: "winget" is the Source column. It must never appear as
    // a version on any row.
    for (const auto& row : parsed.rows) {
        CHECK(row.available_version != "winget");
        CHECK(row.current_version != "winget");
        CHECK_FALSE(row.name.empty());
    }
}

TEST_CASE("winget upgrade: REAL capture — the five rows that defeated the whitespace split",
          "[software_actions]") {
    auto parsed = parse_winget_upgrade(kRealWingetCapture);
    REQUIRE(parsed.rows.size() == 23);

    auto row_named = [&](std::string_view name) {
        for (const auto& r : parsed.rows) {
            if (r.name == name)
                return r;
        }
        FAIL("row not found: " << name);
        return parsed.rows.front();
    };

    // Id fills its column, leaving one space before Version. The old parser
    // produced 4 fields and reported available_version == "winget".
    auto dotnet6 = row_named("Microsoft Windows Desktop Runtime - 6.0.20 (x86)");
    CHECK(dotnet6.current_version == "6.0.20");
    CHECK(dotnet6.available_version == "6.0.36");

    auto dotnet8 = row_named("Microsoft Windows Desktop Runtime - 8.0.28 (x86)");
    CHECK(dotnet8.current_version == "8.0.28");
    CHECK(dotnet8.available_version == "8.0.30");

    auto assistant = row_named("Windows 11 Installation Assistant");
    CHECK(assistant.current_version == "1.4.19041.5003");
    CHECK(assistant.available_version == "1.4.19041.6448");

    // Name AND Version both full-width: the old parser produced 3 fields and
    // collapsed this row to name-only.
    auto office = row_named("Microsoft 365 Apps for enterprise - en-us");
    CHECK(office.current_version == "16.0.19822.20114");
    CHECK(office.available_version == "16.0.20228.20124");

    // winget's unknown-version marker contains a SPACE, so no space-delimited
    // split can recover it — only positional slicing can.
    auto buildtools = row_named("Visual Studio Build Tools 2022");
    CHECK(buildtools.current_version == "< 17.14.35");
    CHECK(buildtools.available_version == "17.14.39");
}

TEST_CASE("winget upgrade: an unreadable header degrades to name-only, never a borrowed column",
          "[software_actions]") {
    // No recognisable header above the separator: the parser cannot know
    // where the columns start, so it reports names and "-" versions rather
    // than guessing.
    constexpr std::string_view out =
        "-----------------------------------------------------------------------------\n"
        "Git                Git.Git                   2.40.0       2.42.0       winget\n";
    auto parsed = parse_winget_upgrade(out);
    CHECK(parsed.separator_found);
    CHECK(parsed.header_unrecognized);
    REQUIRE(parsed.rows.size() == 1);
    CHECK(parsed.rows[0].name == "Git");
    CHECK(parsed.rows[0].current_version == "-");
    CHECK(parsed.rows[0].available_version == "-");
}

// ── installed_count emit decision ──────────────────────────────────────────

TEST_CASE("installed_count: a negative sentinel emits NO count line, never a fabricated zero",
          "[software_actions]") {
    // Windows' registry_uninstall_subkey_count() returns -1 when the registry
    // read fails. `count|0` there would assert "zero installed programs".
    CHECK_FALSE(installed_count_line(-1).has_value());

    REQUIRE(installed_count_line(0).has_value());
    CHECK(*installed_count_line(0) == "count|0"); // a genuine, measured zero
    REQUIRE(installed_count_line(214).has_value());
    CHECK(*installed_count_line(214) == "count|214");
}

TEST_CASE("winget upgrade: a data row that cannot be mapped is counted, never borrowed-from",
          "[software_actions]") {
    // Row 2's Id runs straight into the Version column with no gap at all, so
    // the column boundary cannot be trusted. It must NOT be emitted with a
    // value taken from a neighbouring column -- but it must not vanish
    // silently either.
    constexpr std::string_view out =
        "Name               Id                        Version      Available    Source\n"
        "-----------------------------------------------------------------------------\n"
        "Git                Git.Git                   2.40.0       2.42.0       winget\n"
        "Bad                Some.Very.Long.Identifier.That.Overflows 1.0 2.0     winget\n";
    auto parsed = parse_winget_upgrade(out);
    REQUIRE(parsed.rows.size() == 1);
    CHECK(parsed.rows[0].name == "Git");
    CHECK(parsed.unmapped_lines == 1);
}

TEST_CASE("winget upgrade: trailer lines are never counted as dropped data rows",
          "[software_actions]") {
    auto parsed = parse_winget_upgrade(kRealWingetCapture);
    // Both trailers are recognised as trailers, so the real capture reports a
    // fully clean parse rather than a spurious CONSTRAINED result.
    CHECK(parsed.unmapped_lines == 0);
}

TEST_CASE("winget upgrade: unreadable header does not turn the footer into a package",
          "[software_actions]") {
    constexpr std::string_view out =
        "-----------------------------------------------------------------------------\n"
        "Git                Git.Git                   2.40.0       2.42.0       winget\n"
        "1 package(s) have version numbers that cannot be determined.\n";
    auto parsed = parse_winget_upgrade(out);
    CHECK(parsed.header_unrecognized);
    REQUIRE(parsed.rows.size() == 1);
    CHECK(parsed.rows[0].name == "Git");
}

TEST_CASE("winget upgrade: a non-ASCII package name does not drop the row",
          "[software_actions]") {
    // winget pads by DISPLAY width; slicing raw bytes shifted every column
    // right by one byte per multi-byte character, pushing the version past its
    // boundary so the row was dropped. Any non-en-US estate lost pending
    // updates from the report.
    constexpr std::string_view out =
        "Name                                             Id                                     Version          Available        Source\n"
        "--------------------------------------------------------------------------------------------------------------------------------\n"
        "Bitwarden Passw\u00f6rd Manager                       Bitwarden.Bitwarden                    2024.1.0         2024.2.0         winget\n";
    auto parsed = parse_winget_upgrade(out);
    REQUIRE(parsed.rows.size() == 1);
    CHECK(parsed.unmapped_lines == 0);
    CHECK(parsed.rows[0].name == "Bitwarden Passw\u00f6rd Manager");
    CHECK(parsed.rows[0].current_version == "2024.1.0");
    CHECK(parsed.rows[0].available_version == "2024.2.0");
}

// ── Linux: dnf obsoletions are not pending updates ─────────────────────────

TEST_CASE("yum check-update: the Obsoleting Packages section is not upgradable packages",
          "[software_actions]") {
    constexpr std::string_view out = "kernel.x86_64          6.1.0-2   updates\n"
                                     "Obsoleting Packages\n"
                                     "old-pkg.x86_64         1.0-1     updates\n"
                                     "    replaced.x86_64    0.9-1     @System\n";
    auto rows = parse_yum_checkupdate(out);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].name == "kernel.x86_64");
}

// ── macOS: softwareupdate label extraction edge cases ──────────────────────

TEST_CASE("softwareupdate -l: a diagnostic line never becomes a package name",
          "[software_actions]") {
    // The parser used to emit ANY unrecognised line verbatim, so an error
    // printed to stdout became `upgradable|<diagnostic>|-|-`.
    CHECK(parse_softwareupdate_list("Error: Could not contact the update server.\n").empty());
    CHECK(parse_softwareupdate_list("Software Update Tool\n\nSome stray diagnostic\n").empty());
}

TEST_CASE("softwareupdate -l: a bare 'Label:' never throws and yields no label",
          "[software_actions]") {
    // substr(find(':') + 2) on this line runs past the end and throws
    // std::out_of_range, which would cross the plugin's C ABI boundary.
    CHECK(parse_softwareupdate_list("* Label:\n").empty());
    CHECK(parse_softwareupdate_list("* Label:   \n").empty());
}

TEST_CASE("softwareupdate -l: the label is taken after 'Label:', not after the first colon",
          "[software_actions]") {
    auto labels = parse_softwareupdate_list("* Label: macOS Sequoia 15.6.1-24G90\n");
    REQUIRE(labels.size() == 1);
    CHECK(labels[0] == "macOS Sequoia 15.6.1-24G90");
}

// ── capture completeness (pure seam) ───────────────────────────────────────

TEST_CASE("capture_is_complete: only a clean, untruncated, accepted run is usable",
          "[software_actions]") {
    CHECK(capture_is_complete(/*tool_ran=*/true, /*timed_out=*/false,
                              /*output_truncated=*/false, /*exit_ok=*/true));
    // A truncated capture silently undercounts, so it is never usable for a
    // count -- the same reasoning license_scan applies to a truncated rpm -qa.
    CHECK_FALSE(capture_is_complete(true, false, /*output_truncated=*/true, true));
    CHECK_FALSE(capture_is_complete(/*tool_ran=*/false, false, false, true));
    CHECK_FALSE(capture_is_complete(true, /*timed_out=*/true, false, true));
    CHECK_FALSE(capture_is_complete(true, false, false, /*exit_ok=*/false));
}

// ── Linux: apt list --upgradable ───────────────────────────────────────────

TEST_CASE("apt list --upgradable: real-format lines with from-version — reconstructed",
          "[software_actions]") {
    constexpr std::string_view out =
        "Listing...\n"
        "firefox/jammy-updates 118.0+build2-0ubuntu0.22.04.1 amd64 "
        "[upgradable from: 117.0+build1-0ubuntu0.22.04.1]\n"
        "vim/jammy-updates 2:8.2.3995-1ubuntu2.15 amd64 "
        "[upgradable from: 2:8.2.3995-1ubuntu2.14]\n";
    auto rows = parse_apt_list_upgradable(out);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].name == "firefox");
    CHECK(rows[0].new_version == "118.0+build2-0ubuntu0.22.04.1");
    CHECK(rows[0].old_version == "117.0+build1-0ubuntu0.22.04.1");
    CHECK(rows[1].name == "vim");
    CHECK(rows[1].new_version == "2:8.2.3995-1ubuntu2.15");
    CHECK(rows[1].old_version == "2:8.2.3995-1ubuntu2.14");
}

TEST_CASE("apt list --upgradable: 'Listing...' banner and empty output produce zero rows",
          "[software_actions]") {
    CHECK(parse_apt_list_upgradable("Listing...\n").empty());
    CHECK(parse_apt_list_upgradable("").empty());
}

// ── Linux: yum/dnf check-update ────────────────────────────────────────────

TEST_CASE("yum check-update: real-format lines with banner lines skipped — reconstructed",
          "[software_actions]") {
    constexpr std::string_view out = "Loaded plugins: fastestmirror\n"
                                     "Loading mirror speeds from cached hostfile\n"
                                     "Last metadata expiration check: 0:12:34 ago.\n"
                                     "\n"
                                     "bash.x86_64                    4.4.20-4.el8               baseos\n"
                                     "kernel.x86_64                  4.18.0-425.19.2.el8_7       baseos\n";
    auto rows = parse_yum_checkupdate(out);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].name == "bash.x86_64");
    CHECK(rows[0].new_version == "4.4.20-4.el8");
    CHECK(rows[1].name == "kernel.x86_64");
    CHECK(rows[1].new_version == "4.18.0-425.19.2.el8_7");
}

TEST_CASE("yum check-update: exit-code decision — 0 and 100 are BOTH success, others are not",
          "[software_actions]") {
    // 0 = ran, nothing to update; 100 = ran, updates ARE available (a
    // "success with data" exit code the old popen-based code implicitly
    // tolerated by never checking the exit code at all — the migration must
    // not regress into treating 100 as a failure).
    CHECK(yum_checkupdate_is_success(0));
    CHECK(yum_checkupdate_is_success(100));
    CHECK_FALSE(yum_checkupdate_is_success(1));
    CHECK_FALSE(yum_checkupdate_is_success(-1));
    CHECK_FALSE(yum_checkupdate_is_success(127));
}

// ── nonzero-exit-with-partial-rows (pure decision seam, shared by winget and
// softwareupdate -l) ─────────────────────────────────────────────────────

TEST_CASE("nonzero_exit_with_partial_rows: all four truth-table cells",
          "[software_actions]") {
    // THE regression this function exists to prevent, on both call sites:
    // winget exited nonzero (e.g. one configured source like msstore is
    // unreachable) but still printed rows from the sources it could reach,
    // or softwareupdate -l exited nonzero on some macOS release while still
    // printing a valid table -- either way the plugin must not emit those
    // rows with no status set, indistinguishable from a complete result.
    CHECK(nonzero_exit_with_partial_rows(/*exit_code=*/1, /*rows_empty=*/false));

    // A clean exit is never "partial", however many rows parsed.
    CHECK_FALSE(nonzero_exit_with_partial_rows(0, false));
    CHECK_FALSE(nonzero_exit_with_partial_rows(0, true));
    // A nonzero exit with NO rows parsed is the "the query failed" case,
    // handled separately by each call site (an exit_code != 0 branch below
    // the parse) -- not partial, since there is nothing partial to report.
    CHECK_FALSE(nonzero_exit_with_partial_rows(1, true));
}

TEST_CASE("winget_up_to_date_claimable: a degrade already reported blocks the claim",
          "[software_actions]") {
    // THE regression (Governance Gate 4, unhappy-path UP-2): every
    // post-separator line failed the column-alignment check (e.g. every
    // package name is CJK/double-width and this parser's cell model doesn't
    // cover it), so `rows` ends up empty EXACTLY like a genuine clean scan --
    // but a CONSTRAINED status was already set moments earlier for the
    // dropped rows. Without this gate the code fell through to "System is up
    // to date" anyway: a false-clean claim directly contradicting the status
    // it had just set.
    CHECK_FALSE(winget_up_to_date_claimable(/*rows_empty=*/true, /*exit_code=*/0,
                                            /*separator_found=*/true,
                                            /*table_incomplete=*/true));

    // A genuine clean scan -- separator found, nothing dropped, clean exit --
    // is still claimable.
    CHECK(winget_up_to_date_claimable(true, 0, true, false));

    // No recognisable table at all: never claimable, regardless of
    // table_incomplete (a separate, already-handled degrade shape).
    CHECK_FALSE(winget_up_to_date_claimable(true, 0, false, false));

    // A nonzero exit is handled by an earlier branch in the caller and never
    // reaches this decision with rows_empty=true in practice, but the
    // function itself must still refuse it defensively.
    CHECK_FALSE(winget_up_to_date_claimable(true, 1, true, false));

    // Rows non-empty is out of scope for this decision (the caller only asks
    // when parsed.rows.empty()), but the function is still honest about it --
    // "up to date" is a claim about zero pending upgrades.
    CHECK_FALSE(winget_up_to_date_claimable(false, 0, true, false));
}

// ── macOS: softwareupdate -l ────────────────────────────────────────────────

TEST_CASE("softwareupdate -l: one pending update — REAL capture from this host",
          "[software_actions]") {
    // Verbatim `/usr/sbin/softwareupdate -l` stdout, this macOS host,
    // 2026-08-24 (rc=0, stderr empty on this run).
    constexpr std::string_view out =
        "Software Update Tool\n"
        "\n"
        "Finding available software\n"
        "Software Update found the following new or updated software:\n"
        "* Label: macOS Tahoe 26.6.2-25G83\n"
        "\tTitle: macOS Tahoe 26.6.2, Version: 26.6.2, Size: 3833693KiB, Recommended: YES, "
        "Action: restart, \n";
    auto labels = parse_softwareupdate_list(out);
    REQUIRE(labels.size() == 1);
    CHECK(labels[0] == "macOS Tahoe 26.6.2-25G83");
}

TEST_CASE("softwareupdate -l: no updates available — reconstructed from documented format",
          "[software_actions]") {
    constexpr std::string_view out = "Software Update Tool\n"
                                     "\n"
                                     "No new software available.\n";
    CHECK(parse_softwareupdate_list(out).empty());
}

// ── Linux: dpkg-query status-abbrev / generic line counts ─────────────────

TEST_CASE("dpkg status-abbrev count: 2nd char 'i' counts, others (rc/un) don't",
          "[software_actions]") {
    constexpr std::string_view out = "ii\nhi\nrc\nun\nii\n";
    CHECK(count_dpkg_status_abbrev_installed(out) == 3);
}

TEST_CASE("dpkg status-abbrev count: empty output is zero, never fabricated",
          "[software_actions]") {
    CHECK(count_dpkg_status_abbrev_installed("") == 0);
}

TEST_CASE("generic nonempty-line count (rpm -qa / pkgutil --pkgs)", "[software_actions]") {
    CHECK(count_nonempty_lines("pkg.one\npkg.two\npkg.three\n") == 3);
    CHECK(count_nonempty_lines("") == 0);
    // A single trailing blank line must not be counted as a record.
    CHECK(count_nonempty_lines("pkg.one\n\n") == 1);
}
