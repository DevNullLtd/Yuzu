/**
 * test_privacy_permissions_parsers.cpp -- pure tests for privacy_permissions_parsers.hpp and
 * privacy_permissions_linux_parsers.hpp (this plugin's Linux leg; macOS/Windows parsers are
 * covered by their own test file once those legs ship). No OS call, no platform guard. The one
 * file read is the committed YAML definition (the row_kind/column pin).
 */
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "privacy_permissions_linux_parsers.hpp"
#include "privacy_permissions_parsers.hpp"

using namespace yuzu::privacy_permissions;

namespace {

std::size_t field_count(const std::string& row) {
    std::size_t n = 1;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') ++i;
        else if (row[i] == '|') ++n;
    }
    return n;
}

/// The `- name:` entries under `result:` -> `columns:` in the committed YAML definition, in
/// order. Deliberately naive (this one file has exactly one document and one columns list).
std::vector<std::string> yaml_result_column_names() {
    // YUZU_TEST_FIXTURE_DIR is "<source_root>/tests/unit/fixtures" (tests/meson.build).
    const auto path = std::filesystem::path{YUZU_TEST_FIXTURE_DIR} / ".." / ".." / ".." /
                      "content" / "definitions" / "privacy_permissions.yaml";
    std::ifstream in(path);
    REQUIRE(in.is_open());
    std::vector<std::string> names;
    bool in_result = false, in_columns = false;
    for (std::string line; std::getline(in, line);) {
        if (line.rfind("  result:", 0) == 0) { in_result = true; continue; }
        if (in_result && line.rfind("    columns:", 0) == 0) { in_columns = true; continue; }
        if (!in_columns) continue;
        if (!line.empty() && line.find_first_not_of(' ') < 4 && line.find_first_not_of(' ') != std::string::npos)
            break; // left the columns block
        const auto pos = line.find("- name: ");
        if (pos != std::string::npos) names.push_back(line.substr(pos + 8));
    }
    return names;
}

} // namespace


TEST_CASE("state_token: order pinned, matches kStateTokens", "[privacy_permissions][parsers]") {
    CHECK(state_token(PermissionState::allowed) == "allowed");
    CHECK(state_token(PermissionState::denied) == "denied");
    CHECK(state_token(PermissionState::prompt_undetermined) == "prompt_undetermined");
    CHECK(state_token(PermissionState::absent) == "absent");
    CHECK(state_token(PermissionState::unreadable) == "unreadable");
    CHECK(state_token(PermissionState::unsupported) == "unsupported");
}

TEST_CASE("kCategories: exactly the four charter categories, in order", "[privacy_permissions][parsers]") {
    CHECK(kCategories == std::array<std::string_view, 4>{"camera", "microphone", "location",
                                                         "full_disk_access"});
}

TEST_CASE("format_row: 8 fields, always, Windows fields default to '-'", "[privacy_permissions][parsers]") {
    PermissionRow r{"macos", "com.example.App", "camera", PermissionState::allowed, "2", "-", "-", false};
    const auto row = format_row(r);
    CHECK(row == "permissions|macos|com.example.App|camera|allowed|2|-|-");
    CHECK(field_count(row) == 8);
}

TEST_CASE("kColumns equals the YAML definition's result.columns, row_kind first, and every "
          "formatted row -- data and internal_error alike -- has exactly that many fields",
          "[privacy_permissions][parsers][columns]") {
    const auto yaml = yaml_result_column_names();
    REQUIRE(yaml.size() == kColumns.size());
    for (std::size_t i = 0; i < kColumns.size(); ++i) {
        INFO("column " << i);
        CHECK(yaml[i] == kColumns[i]);
    }
    CHECK(kColumns.front() == "row_kind");

    const auto data = format_row(
        {"windows", "alice\\C:\\App\\app.exe", "camera", PermissionState::denied, "Deny", "1", "2", false});
    CHECK(field_count(data) == kColumns.size());
    CHECK(data.rfind(std::string{kRowKindPermissions} + "|windows|", 0) == 0);

    for (const char* os : {"windows", "macos", "linux"}) {
        const auto err = format_internal_error_row(os);
        INFO(err);
        CHECK(field_count(err) == kColumns.size());
        CHECK(err == std::string{"constrained|"} + os + "|-|-|unreadable|internal_error|-|-");
    }
}

TEST_CASE("qualify_app_id: <owner>\\<app_id>; an unresolved owner renders '-', never an empty "
          "prefix that would read as an unqualified machine-wide row",
          "[privacy_permissions][parsers]") {
    CHECK(qualify_app_id("alice", "com.example.App") == "alice\\com.example.App");
    CHECK(qualify_app_id("alice", "-") == "alice\\-");
    CHECK(qualify_app_id("", "x") == "-\\x");
    // On the wire the row sanitizer folds the separator to '/', like every path.
    CHECK(format_row({"macos", qualify_app_id("alice", "com.x"), "camera",
                      PermissionState::allowed, "2", "-", "-", false}) ==
          "permissions|macos|alice/com.x|camera|allowed|2|-|-");
}

TEST_CASE("failure_row: denied promotes read_denied, unreadable does not; both carry the token "
          "in raw and in the accumulator, never absent",
          "[privacy_permissions][parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    const auto d = failure_row("linux", "-", "camera", true, "camera:access_denied", acc);
    CHECK(d.state == PermissionState::denied);
    CHECK(d.read_denied);
    CHECK(d.category == "camera");
    CHECK(d.raw == "camera:access_denied");
    const auto u = failure_row("linux", "-", "microphone", false, "microphone:shape", acc);
    CHECK(u.state == PermissionState::unreadable);
    CHECK_FALSE(u.read_denied);
    CHECK(acc.reason() == "camera:access_denied,microphone:shape");
}

TEST_CASE("fill_uncovered_categories: absent for every uncovered category unless a whole-source "
          "failure row covers it -- a token-only failure never suppresses coverage",
          "[privacy_permissions][parsers]") {
    SECTION("clean read: every uncovered category becomes absent") {
        std::vector<PermissionRow> rows{
            {"windows", "alice\\-", "camera", PermissionState::allowed, "Allow", "-", "-", false}};
        fill_uncovered_categories("windows", rows);
        REQUIRE(rows.size() == 4);
        for (std::size_t i = 1; i < rows.size(); ++i) {
            CHECK(rows[i].state == PermissionState::absent);
            CHECK(rows[i].category != "camera");
        }
    }
    SECTION("a whole-source unreadable row: nothing is filled") {
        yuzu::shared::ConstraintAccumulator acc;
        std::vector<PermissionRow> rows{failure_row("windows", "alice\\-", "-", false,
                                                    "alice:hive_mount_failed", acc)};
        fill_uncovered_categories("windows", rows);
        CHECK(rows.size() == 1);
    }
    SECTION("a whole-source refused row: nothing is filled") {
        yuzu::shared::ConstraintAccumulator acc;
        std::vector<PermissionRow> rows{
            failure_row("windows", "-", "-", true, "hklm:access_denied", acc)};
        fill_uncovered_categories("windows", rows);
        CHECK(rows.size() == 1);
    }
    SECTION("zero profiles + a token-only failure (hive_unload_failed): a row per category") {
        yuzu::shared::ConstraintAccumulator acc;
        acc.add_failure("alice:hive_unload_failed");
        std::vector<PermissionRow> rows;
        fill_uncovered_categories("windows", rows);
        REQUIRE(rows.size() == kCategories.size());
        for (std::size_t i = 0; i < kCategories.size(); ++i) {
            CHECK(rows[i].category == kCategories[i]);
            CHECK(rows[i].state == PermissionState::absent);
        }
    }
    SECTION("a per-category failure row covers only its own category") {
        yuzu::shared::ConstraintAccumulator acc;
        std::vector<PermissionRow> rows{
            failure_row("windows", "-", "camera", false, "hklm\\-:camera:capability:win32_1", acc)};
        fill_uncovered_categories("windows", rows);
        CHECK(rows.size() == 4);
    }
    SECTION("a whole-source ABSENT row (no per-user TCC.db) is not a failure: filling proceeds") {
        std::vector<PermissionRow> rows{
            {"macos", "bob\\-", "-", PermissionState::absent, "-", "-", "-", false}};
        CHECK_FALSE(is_whole_source_failure(rows[0]));
        fill_uncovered_categories("macos", rows);
        CHECK(rows.size() == 5);
    }
}

TEST_CASE("classify_session_bus_open: no session is unavailable, a refused socket is denied, "
          "anything else is a failure -- never all folded into 'no session'",
          "[privacy_permissions][parsers][linux]") {
    using portal::BusOpenOutcome;
    using portal::classify_session_bus_open;
    CHECK(classify_session_bus_open(ENOENT) == BusOpenOutcome::unavailable);
    CHECK(classify_session_bus_open(ECONNREFUSED) == BusOpenOutcome::unavailable);
#if defined(ENOMEDIUM)
    CHECK(classify_session_bus_open(ENOMEDIUM) == BusOpenOutcome::unavailable);
#endif
    CHECK(classify_session_bus_open(EACCES) == BusOpenOutcome::denied);
    CHECK(classify_session_bus_open(EPERM) == BusOpenOutcome::denied);
    CHECK(classify_session_bus_open(ENOMEM) == BusOpenOutcome::failed);
    CHECK(classify_session_bus_open(0) == BusOpenOutcome::failed);
}

TEST_CASE("format_row: Windows row carries real last-used fields", "[privacy_permissions][parsers]") {
    // safe_output_field maps '\' -> '/' (it doubles as the pipe-delimited row's separator
    // sanitizer) -- app_id is checked post-sanitization, matching every other row this
    // plugin's siblings emit.
    PermissionRow r{"windows", "C:\\App\\app.exe", "microphone", PermissionState::denied, "Deny",
                    "1700000000000", "1700000100000", false};
    CHECK(format_row(r) ==
         "permissions|windows|C:/App/app.exe|microphone|denied|Deny|1700000000000|1700000100000");
}

TEST_CASE("sanitize_utf8: valid UTF-8 is unchanged, every invalid byte becomes U+FFFD, and a "
          "row never carries invalid UTF-8",
          "[privacy_permissions][parsers]") {
    for (const std::string_view ok : {"", "plain", "caf\xC3\xA9", "\xE2\x82\xAC", "\xF0\x9F\x98\x80",
                                      "\xED\x9F\xBF", "\xF4\x8F\xBF\xBF"})
        CHECK(sanitize_utf8(ok) == ok);
    const std::string bad = "\xEF\xBF\xBD";
    CHECK(sanitize_utf8("a\xC3(b") == "a" + bad + "(b");           // truncated 2-byte sequence
    CHECK(sanitize_utf8("\xC0\x80") == bad + bad);                 // overlong NUL
    CHECK(sanitize_utf8("\xED\xA0\x80") == bad + bad + bad);       // surrogate
    CHECK(sanitize_utf8("\xF4\x90\x80\x80") == bad + bad + bad + bad); // above U+10FFFF
    CHECK(sanitize_utf8("\xE2\x82") == bad + bad);                 // cut at the end

    const PermissionRow r{"macos", "u\\\xFF", "camera", PermissionState::unreadable,
                          "t:\xC3",   "-",        "-",      false};
    CHECK(format_row(r) == "permissions|macos|u/" + bad + "|camera|unreadable|t:" + bad + "|-|-");
}

TEST_CASE("kInternalErrorRow*: the allocation-free literals equal the formatter, one per OS",
          "[privacy_permissions][parsers]") {
    CHECK(kInternalErrorRowLinux == format_internal_error_row("linux"));
    CHECK(kInternalErrorRowMacos == format_internal_error_row("macos"));
    CHECK(kInternalErrorRowWindows == format_internal_error_row("windows"));
}

TEST_CASE("select_status: denied wins over a mere failure token", "[privacy_permissions][parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    acc.add_failure("x:y");
    const auto st = select_status(acc, true, false);
    CHECK(st.status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(st.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
}

TEST_CASE("select_status: a failure token with no denial is CONSTRAINED", "[privacy_permissions][parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    acc.add_failure("x:y");
    const auto st = select_status(acc, false, false);
    CHECK(st.status == YUZU_RESULT_STATUS_CONSTRAINED);
}

TEST_CASE("select_status: no failure, no denial, reachable mechanism is OK/FULL",
          "[privacy_permissions][parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    CHECK(select_status(acc, false, false).status == YUZU_RESULT_STATUS_OK);
}

TEST_CASE("select_status: no failure, no denial, unavailable mechanism is UNAVAILABLE/FULL",
          "[privacy_permissions][parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    const auto st = select_status(acc, false, true);
    CHECK(st.status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(st.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(st.provenance == kUnavailableProvenance);
}

TEST_CASE("any_denied: true iff at least one row's read was refused", "[privacy_permissions][parsers]") {
    std::vector<PermissionRow> rows{
        {"macos", "-", "camera", PermissionState::allowed, "-", "-", "-", false},
        {"macos", "-", "microphone", PermissionState::denied, "-", "-", "-", true},
    };
    CHECK(any_denied(rows));
    rows.pop_back();
    CHECK_FALSE(any_denied(rows));
}


// ── Linux-specific pure layer (shapes from a real xdg-permission-store, see the header) ─────

namespace {
const portal::PortalTable& table_for(std::string_view category) {
    for (const auto& t : portal::kPortalLookups)
        if (t.category == category) return t;
    FAIL("no portal table for " << category);
    return portal::kPortalLookups[0];
}
} // namespace

TEST_CASE("portal::decode_portal_permissions: devices yes/no/ask; location [accuracy, timestamp] "
          "-- NONE denied, a known accuracy allowed; an empty list is never `denied`",
          "[privacy_permissions][linux_parsers]") {
    using portal::TableKind;
    using V = std::vector<std::string>;
    const auto state = [](TableKind k, V v) { return portal::decode_portal_permissions(k, v).state; };
    // devices -- real reply `({'org.example.CamApp': ['yes']}, <byte 0x00>)`.
    CHECK(state(TableKind::devices, {"yes"}) == PermissionState::allowed);
    CHECK(state(TableKind::devices, {"no"}) == PermissionState::denied);
    CHECK(state(TableKind::devices, {"ask"}) == PermissionState::prompt_undetermined);
    CHECK(state(TableKind::devices, {"maybe"}) == PermissionState::prompt_undetermined);
    CHECK(state(TableKind::devices, {"yes", "no"}) == PermissionState::prompt_undetermined);
    // location -- real reply `({'org.example.MapApp': ['EXACT', '0']}, <byte 0x00>)`.
    CHECK(state(TableKind::location, {"EXACT", "0"}) == PermissionState::allowed);
    for (const char* level : {"COUNTRY", "CITY", "NEIGHBORHOOD", "STREET"})
        CHECK(state(TableKind::location, {level, "1700000000"}) == PermissionState::allowed);
    CHECK(state(TableKind::location, {"NONE", "0"}) == PermissionState::denied);
    CHECK(state(TableKind::location, {"PRECISE", "0"}) == PermissionState::prompt_undetermined);
    CHECK(state(TableKind::location, {"EXACT"}) == PermissionState::prompt_undetermined);
    CHECK(state(TableKind::location, {"yes"}) == PermissionState::prompt_undetermined);
    // Empty: no decision at all -- unreadable with a cause, never a refusal.
    for (const auto k : {TableKind::devices, TableKind::location}) {
        const auto d = portal::decode_portal_permissions(k, V{});
        CHECK(d.state == PermissionState::unreadable);
        CHECK(d.cause == "empty_permissions");
    }
    CHECK(portal::join_permissions(V{"EXACT", "0"}) == "EXACT,0");
    CHECK(portal::join_permissions(V{}) == "-");
}

TEST_CASE("portal::append_lookup_reply_rows: the real location shape reads allowed with the raw "
          "list kept; a partly-read reply is never absent; an empty list is a token row",
          "[privacy_permissions][linux_parsers]") {
    SECTION("the probe's location reply (the grant the old decode reported prompt_undetermined)") {
        yuzu::shared::ConstraintAccumulator acc;
        std::vector<PermissionRow> rows;
        portal::PortalReply r{true, {{"org.example.MapApp", {"EXACT", "0"}}}, false, false};
        portal::append_lookup_reply_rows(table_for("location"), r, rows, acc);
        REQUIRE(rows.size() == 1);
        CHECK(format_row(rows[0]) == "permissions|linux|org.example.MapApp|location|allowed|EXACT,0|-|-");
        CHECK_FALSE(acc.any_failure());
    }
    SECTION("the probe's devices reply") {
        yuzu::shared::ConstraintAccumulator acc;
        std::vector<PermissionRow> rows;
        portal::PortalReply r{true, // out of order on purpose: rows come out by app_id
                              {{"org.example.MicApp", {"no"}}, {"org.example.CamApp", {"yes"}}},
                              false, false};
        portal::append_lookup_reply_rows(table_for("camera"), r, rows, acc);
        REQUIRE(rows.size() == 2);
        CHECK(format_row(rows[0]) == "permissions|linux|org.example.CamApp|camera|allowed|yes|-|-");
        CHECK(format_row(rows[1]) == "permissions|linux|org.example.MicApp|camera|denied|no|-|-");
    }
    SECTION("an empty permission list: unreadable, `<app_id>:<category>:empty_permissions`") {
        yuzu::shared::ConstraintAccumulator acc;
        std::vector<PermissionRow> rows;
        portal::PortalReply r{true, {{"org.example.CamApp", {}}}, false, false};
        portal::append_lookup_reply_rows(table_for("camera"), r, rows, acc);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].state == PermissionState::unreadable);
        CHECK(rows[0].raw == "org.example.CamApp:camera:empty_permissions");
        CHECK(acc.reason() == rows[0].raw);
    }
    SECTION("a cleanly empty table is absent") {
        yuzu::shared::ConstraintAccumulator acc;
        std::vector<PermissionRow> rows;
        portal::append_lookup_reply_rows(table_for("microphone"), portal::PortalReply{true, {}, false, false},
                                         rows, acc);
        REQUIRE(rows.size() == 1);
        CHECK(format_row(rows[0]) == "permissions|linux|-|microphone|absent|-|-|-");
    }
    SECTION("outer array not entered: one shape row, nothing else") {
        yuzu::shared::ConstraintAccumulator acc;
        std::vector<PermissionRow> rows;
        portal::append_lookup_reply_rows(table_for("camera"), portal::PortalReply{}, rows, acc);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].raw == "camera:shape");
    }
    SECTION("a walk that failed part-way and a bad entry: rows kept, failures named, never absent") {
        yuzu::shared::ConstraintAccumulator acc;
        std::vector<PermissionRow> rows;
        portal::PortalReply r{true, {}, true, true};
        portal::append_lookup_reply_rows(table_for("location"), r, rows, acc);
        REQUIRE(rows.size() == 2);
        CHECK(rows[0].raw == "location:shape");
        CHECK(rows[1].raw == "location:entry_shape");
        for (const auto& row : rows) CHECK(row.state != PermissionState::absent);
    }
}

TEST_CASE("portal::classify_lookup_error + append_lookup_error_rows: NotFound absent, AccessDenied "
          "denied, ServiceUnknown deferred (no row), anything else unreadable",
          "[privacy_permissions][linux_parsers]") {
    using portal::LookupError;
    CHECK(portal::classify_lookup_error("org.freedesktop.DBus.Error.ServiceUnknown") ==
          LookupError::service_unknown);
    CHECK(portal::classify_lookup_error("org.freedesktop.portal.Error.NotFound") ==
          LookupError::not_found);
    CHECK(portal::classify_lookup_error("org.freedesktop.DBus.Error.AccessDenied") ==
          LookupError::access_denied);
    CHECK(portal::classify_lookup_error("org.freedesktop.DBus.Error.NoReply") == LookupError::failed);
    CHECK(portal::classify_lookup_error("") == LookupError::failed);
    CHECK(portal::classify_lookup_error("", ETIMEDOUT) == LookupError::timeout);
    CHECK(portal::classify_lookup_error("org.freedesktop.DBus.Error.Timeout") == LookupError::timeout);

    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PermissionRow> rows;
    const auto& cam = table_for("camera");
    CHECK(portal::append_lookup_error_rows(cam, LookupError::service_unknown, rows, acc));
    CHECK(rows.empty());
    CHECK_FALSE(portal::append_lookup_error_rows(cam, LookupError::not_found, rows, acc));
    CHECK_FALSE(portal::append_lookup_error_rows(cam, LookupError::access_denied, rows, acc));
    CHECK_FALSE(portal::append_lookup_error_rows(cam, LookupError::failed, rows, acc));
    REQUIRE(rows.size() == 3);
    CHECK(rows[0].state == PermissionState::absent);
    CHECK(rows[1].read_denied);
    CHECK(rows[1].raw == "camera:access_denied");
    CHECK(rows[2].state == PermissionState::unreadable);
    CHECK(rows[2].raw == "camera:lookup_failed");
    CHECK_FALSE(portal::append_lookup_error_rows(cam, LookupError::timeout, rows, acc));
    REQUIRE(rows.size() == 4);
    CHECK(rows[3].state == PermissionState::unreadable);
    CHECK(rows[3].raw == "camera:timeout");
}

TEST_CASE("portal::remaining_budget_us: one total deadline -- the time left, 0 once spent",
          "[privacy_permissions][linux_parsers]") {
    CHECK(portal::kPortalTotalBudgetUs == 5'000'000);
    CHECK(portal::remaining_budget_us(5'000'000, 0) == 5'000'000);
    CHECK(portal::remaining_budget_us(5'000'000, 1'250'000) == 3'750'000);
    CHECK(portal::remaining_budget_us(5'000'000, 4'999'999) == 1);
    CHECK(portal::remaining_budget_us(5'000'000, 5'000'000) == 0);
    CHECK(portal::remaining_budget_us(5'000'000, 9'000'000) == 0);
}

TEST_CASE("portal::finish_portal_rows: ServiceUnknown on EVERY lookup is whole-mechanism "
          "unavailable; on only SOME it is a per-category failure, never absence",
          "[privacy_permissions][linux_parsers]") {
    SECTION("all three: one unsupported whole-source row, unavailable, no token") {
        yuzu::shared::ConstraintAccumulator acc;
        std::vector<PermissionRow> rows;
        const std::vector<std::string_view> su{"camera", "microphone", "location"};
        CHECK(portal::finish_portal_rows(su, rows, acc));
        REQUIRE(rows.size() == 1);
        CHECK(format_row(rows[0]) == "permissions|linux|-|-|unsupported|-|-|-");
        CHECK_FALSE(acc.any_failure());
    }
    SECTION("only location: its own failure row, and full_disk_access is unsupported") {
        yuzu::shared::ConstraintAccumulator acc;
        std::vector<PermissionRow> rows{
            {"linux", "org.example.CamApp", "camera", PermissionState::allowed, "yes", "-", "-", false}};
        const std::vector<std::string_view> su{"location"};
        CHECK_FALSE(portal::finish_portal_rows(su, rows, acc));
        REQUIRE(rows.size() == 3);
        CHECK(rows[1].category == "location");
        CHECK(rows[1].raw == "location:service_unknown");
        CHECK(format_row(rows[2]) == "permissions|linux|-|full_disk_access|unsupported|-|-|-");
        CHECK(acc.reason() == "location:service_unknown");
    }
}
