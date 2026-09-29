/**
 * test_windows_updates_parsers.cpp — pure windows_updates parse/format
 * helpers (windows_updates_parsers.hpp, Wave 2/3 windows_updates migration).
 *
 * The run_bounded_subprocess calls and the Windows COM/WMI plumbing are the
 * impure shell; the shell-output text formats and the WMI/WUA result shapes
 * are header-pure and pinned here on every host (the discovery_parsers.hpp
 * pattern).
 */

#include "windows_updates_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::windows_updates;

// ── format_hotfix_rows ──────────────────────────────────────────────────────

TEST_CASE("format_hotfix_rows: empty input yields empty output", "[windows_updates]") {
    CHECK(format_hotfix_rows({}).empty());
}

TEST_CASE("format_hotfix_rows: single row", "[windows_updates]") {
    auto out = format_hotfix_rows({HotfixRow{"KB5012345", "Security Update", "8/1/2026"}});
    REQUIRE(out.size() == 1);
    CHECK(out[0] == "update|KB5012345|Security Update|8/1/2026");
}

TEST_CASE("format_hotfix_rows: multiple rows preserve order", "[windows_updates]") {
    auto out = format_hotfix_rows({
        HotfixRow{"KB1", "First", "1/1/2026"},
        HotfixRow{"KB2", "Second", "2/2/2026"},
    });
    REQUIRE(out.size() == 2);
    CHECK(out[0] == "update|KB1|First|1/1/2026");
    CHECK(out[1] == "update|KB2|Second|2/2/2026");
}

TEST_CASE("format_hotfix_rows: a pipe in the description is escaped, not left raw",
          "[windows_updates]") {
    auto out = format_hotfix_rows({HotfixRow{"KB1", "Fixes a|b", "1/1/2026"}});
    REQUIRE(out.size() == 1);
    CHECK(out[0] == "update|KB1|Fixes a\\|b|1/1/2026");
}

// ── format_update_rows ──────────────────────────────────────────────────────

TEST_CASE("format_update_rows: empty input yields empty output", "[windows_updates]") {
    CHECK(format_update_rows({}).empty());
}

TEST_CASE("format_update_rows: populated severity", "[windows_updates]") {
    auto out = format_update_rows({UpdateRow{"2026-08 Cumulative Update", "Critical"}});
    REQUIRE(out.size() == 1);
    CHECK(out[0] == "available|2026-08 Cumulative Update|Critical");
}

TEST_CASE("format_update_rows: empty severity still emits a trailing field",
          "[windows_updates]") {
    auto out = format_update_rows({UpdateRow{"Definition Update for Windows Defender", ""}});
    REQUIRE(out.size() == 1);
    CHECK(out[0] == "available|Definition Update for Windows Defender|");
}

TEST_CASE("format_update_rows: several updates, mixed severities", "[windows_updates]") {
    auto out = format_update_rows({
        UpdateRow{"Update A", "Important"},
        UpdateRow{"Update B", ""},
        UpdateRow{"Update C", "Moderate"},
    });
    REQUIRE(out.size() == 3);
    CHECK(out[0] == "available|Update A|Important");
    CHECK(out[1] == "available|Update B|");
    CHECK(out[2] == "available|Update C|Moderate");
}

// ── classify_wmi_error ───────────────────────────────────────────────────────

TEST_CASE("classify_wmi_error: com_init_failed is UNAVAILABLE", "[windows_updates]") {
    auto s = classify_wmi_error("com_init_failed");
    CHECK(s.status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(s.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(s.provenance == "wmi_bounded:com_init_failed");
}

TEST_CASE("classify_wmi_error: wbem_locator_failed is UNAVAILABLE", "[windows_updates]") {
    CHECK(classify_wmi_error("wbem_locator_failed").status == YUZU_RESULT_STATUS_UNAVAILABLE);
}

TEST_CASE("classify_wmi_error: wmi_connect_failed_<hr> is UNAVAILABLE", "[windows_updates]") {
    auto s = classify_wmi_error("wmi_connect_failed_0x80041002");
    CHECK(s.status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(s.provenance == "wmi_bounded:wmi_connect_failed_0x80041002");
}

TEST_CASE("classify_wmi_error: wmi_query_failed_<hr> is CONSTRAINED", "[windows_updates]") {
    auto s = classify_wmi_error("wmi_query_failed_0x80041017");
    CHECK(s.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(s.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
}

TEST_CASE("classify_wmi_error: wmi_next_timeout is CONSTRAINED", "[windows_updates]") {
    CHECK(classify_wmi_error("wmi_next_timeout").status == YUZU_RESULT_STATUS_CONSTRAINED);
}

TEST_CASE("classify_wmi_error: wmi_deadline_exceeded is CONSTRAINED", "[windows_updates]") {
    CHECK(classify_wmi_error("wmi_deadline_exceeded").status == YUZU_RESULT_STATUS_CONSTRAINED);
}

TEST_CASE("classify_wmi_error: wmi_next_failed_<hr> is CONSTRAINED", "[windows_updates]") {
    CHECK(classify_wmi_error("wmi_next_failed_0x8004100e").status ==
          YUZU_RESULT_STATUS_CONSTRAINED);
}

TEST_CASE("classify_wmi_error: an unrecognised token falls to the CONSTRAINED middle ground",
          "[windows_updates]") {
    auto s = classify_wmi_error("some_future_error_shape");
    CHECK(s.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(s.provenance == "wmi_bounded:some_future_error_shape");
}

// ── parse_rpm_last ───────────────────────────────────────────────────────────

TEST_CASE("parse_rpm_last: name/date separated by double space", "[windows_updates]") {
    auto out = parse_rpm_last({"bash-5.1.16-1.fc35.x86_64                    Tue 01 Aug 2026"});
    REQUIRE(out.size() == 1);
    CHECK(out[0] == "package|bash-5.1.16-1.fc35.x86_64|Tue 01 Aug 2026");
}

TEST_CASE("parse_rpm_last: no double space falls back to line|-", "[windows_updates]") {
    auto out = parse_rpm_last({"unexpected-single-space-line"});
    REQUIRE(out.size() == 1);
    CHECK(out[0] == "package|unexpected-single-space-line|-");
}

TEST_CASE("parse_rpm_last: empty input", "[windows_updates]") {
    CHECK(parse_rpm_last({}).empty());
}

// ── parse_apt_list_line / parse_apt_installed / parse_apt_upgradable ───────

TEST_CASE("parse_apt_list_line: standard apt list row", "[windows_updates]") {
    auto e = parse_apt_list_line("bash/stable 5.1-2+b3 amd64 [installed]");
    REQUIRE(e.has_value());
    CHECK(e->name == "bash");
    CHECK(e->version == "5.1-2+b3");
}

TEST_CASE("parse_apt_list_line: Listing header is rejected", "[windows_updates]") {
    CHECK_FALSE(parse_apt_list_line("Listing... Done").has_value());
}

TEST_CASE("parse_apt_list_line: no slash or no space is rejected", "[windows_updates]") {
    CHECK_FALSE(parse_apt_list_line("garbage").has_value());
}

TEST_CASE("parse_apt_installed: header dropped, matches formatted, non-matches fall back",
          "[windows_updates]") {
    auto out = parse_apt_installed({
        "Listing... Done",
        "bash/stable 5.1-2+b3 amd64 [installed]",
        "not-a-normal-line",
    });
    REQUIRE(out.size() == 2);
    CHECK(out[0] == "package|bash|5.1-2+b3");
    CHECK(out[1] == "package|not-a-normal-line|-");
}

TEST_CASE("parse_apt_upgradable: only matching rows are emitted, no fallback",
          "[windows_updates]") {
    auto out = parse_apt_upgradable({
        "Listing... Done",
        "curl/stable 7.88.1-2 amd64 [upgradable from: 7.87.0-1]",
        "not-a-normal-line",
    });
    REQUIRE(out.size() == 1);
    CHECK(out[0] == "available|curl|7.88.1-2");
}

TEST_CASE("parse_apt_upgradable: nothing matching yields empty (triggers the yum fallback)",
          "[windows_updates]") {
    CHECK(parse_apt_upgradable({"Listing... Done"}).empty());
}

// ── parse_yum_checkupdate ────────────────────────────────────────────────────

TEST_CASE("parse_yum_checkupdate: Loaded/Loading banner lines are dropped",
          "[windows_updates]") {
    auto out = parse_yum_checkupdate({
        "Loaded plugins: fastestmirror",
        "Loading mirror speeds from cached hostfile",
        "bash.x86_64  4.4.20-4.el8  BaseOS",
    });
    REQUIRE(out.size() == 1);
    CHECK(out[0] == "available|bash.x86_64  4.4.20-4.el8  BaseOS");
}

TEST_CASE("parse_yum_checkupdate: empty input", "[windows_updates]") {
    CHECK(parse_yum_checkupdate({}).empty());
}

// ── parse_softwareupdate_list ────────────────────────────────────────────────

TEST_CASE("parse_softwareupdate_list: bullet-trimmed data line", "[windows_updates]") {
    auto out = parse_softwareupdate_list({"   * Label: macOS Update-1.0"});
    REQUIRE(out.size() == 1);
    CHECK(out[0] == "available|Label: macOS Update-1.0");
}

TEST_CASE("parse_softwareupdate_list: banner and status lines are dropped",
          "[windows_updates]") {
    auto out = parse_softwareupdate_list({
        "Software Update Tool",
        "Finding available software",
        "No new software available.",
        "   * Label: macOS Update-1.0",
    });
    REQUIRE(out.size() == 1);
    CHECK(out[0] == "available|Label: macOS Update-1.0");
}

TEST_CASE("parse_softwareupdate_list: an all-whitespace/asterisk line is not cleared "
          "(verbatim legacy quirk)",
          "[windows_updates]") {
    // find_first_not_of(" \t*") returns npos for this line, so the original
    // parser left `trimmed` as the full input line unchanged rather than
    // clearing it -- it is neither empty nor prefix-matched by any of the
    // skip checks, so it survives to the output as-is. Preserved verbatim by
    // this migration, not introduced by it.
    auto out = parse_softwareupdate_list({"   ***   "});
    REQUIRE(out.size() == 1);
    CHECK(out[0] == "available|   ***   ");
}

TEST_CASE("parse_softwareupdate_list: empty input", "[windows_updates]") {
    CHECK(parse_softwareupdate_list({}).empty());
}

// ── parse_install_history_macos ──────────────────────────────────────────────

TEST_CASE("parse_install_history_macos: one full record", "[windows_updates]") {
    std::vector<std::string> lines{
        "Install History:",
        "",
        "    Safari:",
        "",
        "      Version: 17.0",
        "      Install Date: 8/1/2026, 10:23:45",
        "      Type: Apple software update",
    };
    auto out = parse_install_history_macos(lines);
    REQUIRE(out.size() == 1);
    CHECK(out[0] == "update|Safari|8/1/2026, 10:23:45");
}

TEST_CASE("parse_install_history_macos: multiple records", "[windows_updates]") {
    std::vector<std::string> lines{
        "    Safari:",
        "      Install Date: 8/1/2026, 10:23:45",
        "    macOS Sequoia Update:",
        "      Install Date: 8/5/2026, 09:00:00",
    };
    auto out = parse_install_history_macos(lines);
    REQUIRE(out.size() == 2);
    CHECK(out[0] == "update|Safari|8/1/2026, 10:23:45");
    CHECK(out[1] == "update|macOS Sequoia Update|8/5/2026, 09:00:00");
}

TEST_CASE("parse_install_history_macos: a trailing name with no Install Date line "
          "still emits a row with a placeholder date",
          "[windows_updates]") {
    std::vector<std::string> lines{"    Orphaned Entry:"};
    auto out = parse_install_history_macos(lines);
    REQUIRE(out.size() == 1);
    CHECK(out[0] == "update|Orphaned Entry|-");
}

TEST_CASE("parse_install_history_macos: a 5-space-indented name line does not match "
          "the exact-4-space filter",
          "[windows_updates]") {
    std::vector<std::string> lines{"     NotATopLevelKey:", "      Install Date: 1/1/2026"};
    // "     NotATopLevelKey:" has 5 leading spaces, so it fails the
    // '^ {4}\w' equivalent -- but it still contains no "Install Date:"
    // substring, so it is filtered out entirely, and the following
    // "Install Date:" line is paired with no name (current_name stays
    // empty), producing no output.
    auto out = parse_install_history_macos(lines);
    CHECK(out.empty());
}

TEST_CASE("parse_install_history_macos: non-matching lines are ignored", "[windows_updates]") {
    std::vector<std::string> lines{
        "Install History:",
        "      Version: 1.0",
        "      Type: Apple software update",
    };
    CHECK(parse_install_history_macos(lines).empty());
}

TEST_CASE("parse_install_history_macos: empty input", "[windows_updates]") {
    CHECK(parse_install_history_macos({}).empty());
}

TEST_CASE("parse_install_history_macos: matched-line cap stops at 100", "[windows_updates]") {
    std::vector<std::string> lines;
    for (int i = 0; i < 60; ++i) {
        lines.push_back(std::format("    Update{}:", i));
        lines.push_back(std::format("      Install Date: {}/1/2026", i + 1));
    }
    // 60 records * 2 matching lines each = 120 matching lines, capped to the
    // first 100 -- i.e. the first 50 complete records survive intact.
    auto out = parse_install_history_macos(lines);
    CHECK(out.size() == 50);
    CHECK(out[0] == "update|Update0|1/1/2026");
    CHECK(out[49] == "update|Update49|50/1/2026");
}
