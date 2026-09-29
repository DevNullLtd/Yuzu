/**
 * test_privacy_permissions_parsers.cpp -- pure tests for privacy_permissions_parsers.hpp,
 * privacy_permissions_macos_parsers.hpp and privacy_permissions_linux_parsers.hpp (this
 * plugin's Linux and macOS legs; Windows parsers are covered by their own test file once
 * that leg ships). No OS call, no platform guard. The one file read is the committed YAML
 * definition (the row_kind/column pin).
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
#include "privacy_permissions_macos_parsers.hpp"
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
    SECTION("a portal-controlled app_id carrying a literal pipe is escaped in the failure token "
            "-- PR review finding: ConstraintAccumulator's token has no sanitization of its own, "
            "and this token reaches agent-side logging, not just the row. safe_output_field is "
            "this codebase's one sanitizer for output fields (folds backslash/CR/LF, escapes "
            "pipes); it does not strip general control characters, so the assertion below checks "
            "exactly what it actually does, not a broader guarantee it doesn't make.") {
        yuzu::shared::ConstraintAccumulator acc;
        std::vector<PermissionRow> rows;
        const std::string hostile_app_id = "org.example.Evil|App";
        portal::PortalReply r{true, {{hostile_app_id, {}}}, false, false};
        portal::append_lookup_reply_rows(table_for("camera"), r, rows, acc);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].raw == "org.example.Evil\\|App:camera:empty_permissions");
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
    // PR review finding: a raw EACCES/EPERM (no named AccessDenied error attached) must
    // classify the same as classify_session_bus_open treats the same two errnos.
    CHECK(portal::classify_lookup_error("", EACCES) == LookupError::access_denied);
    CHECK(portal::classify_lookup_error("", EPERM) == LookupError::access_denied);

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

// ── macOS-specific pure layer (shapes from real TCC.db captures, see the header) ────────

TEST_CASE("macos: the documented bounds and the tokens a bound produces",
          "[privacy_permissions][macos_parsers]") {
    CHECK(macos::kMaxSchemaBytes == 64 * 1024);
    CHECK(macos::kMaxValueBytes == 1024);
    CHECK(macos::kMaxRowsPerService == 1024);
    CHECK(macos::kMaxSourceBytes == 1024u * 1024u);
    CHECK(macos::kMaxDbBytes == 4LL * 1024 * 1024);
    CHECK(macos::kSourceBudget == std::chrono::milliseconds{500});
    CHECK(macos::kRunBudget == std::chrono::seconds{10});
    CHECK(macos::kCutRowCap == "row_cap");
    CHECK(macos::kCutByteCap == "byte_cap");
    CHECK(macos::kCutValueOversized == "value_oversized");
    CHECK(macos::kCutTimeout == "timeout");
}

TEST_CASE("macos::decode_auth_value: 0 denied, 2/3 allowed, other prompt_undetermined, a "
          "NULL/non-integer column unreadable (never a fabricated 0 = denied)",
          "[privacy_permissions][macos_parsers]") {
    CHECK(macos::decode_auth_value(0) == PermissionState::denied);
    CHECK(macos::decode_auth_value(2) == PermissionState::allowed);
    CHECK(macos::decode_auth_value(3) == PermissionState::allowed);
    CHECK(macos::decode_auth_value(1) == PermissionState::prompt_undetermined);
    CHECK(macos::decode_auth_value(std::nullopt) == PermissionState::unreadable);
    // Past int32: the low bits must not wrap onto 0/2/3.
    CHECK(macos::decode_auth_value(4294967296) == PermissionState::prompt_undetermined);
    CHECK(macos::decode_auth_value(4294967298) == PermissionState::prompt_undetermined);
    CHECK(macos::decode_auth_value(-2) == PermissionState::prompt_undetermined);
}

TEST_CASE("macos::classify_tcc_presence: a missing per-user db is absent, a missing system db "
          "is unreadable, a refused lstat is denied, a non-regular file is refused",
          "[privacy_permissions][macos_parsers]") {
    CHECK_FALSE(macos::classify_tcc_presence(0, true, true).has_value());
    const auto user_missing = macos::classify_tcc_presence(ENOENT, false, true);
    REQUIRE(user_missing);
    CHECK(user_missing->outcome == macos::SourceOutcome::absent);
    CHECK(user_missing->cause.empty());
    const auto sys_missing = macos::classify_tcc_presence(ENOENT, false, false);
    REQUIRE(sys_missing);
    CHECK(sys_missing->outcome == macos::SourceOutcome::unreadable);
    CHECK(sys_missing->cause == "missing");
    for (const int e : {EPERM, EACCES}) {
        const auto d = macos::classify_tcc_presence(e, false, true);
        REQUIRE(d);
        CHECK(d->outcome == macos::SourceOutcome::denied);
    }
    const auto link = macos::classify_tcc_presence(0, false, true);
    REQUIRE(link);
    CHECK(link->outcome == macos::SourceOutcome::unreadable);
    CHECK(link->cause == "not_regular");
    const auto io = macos::classify_tcc_presence(EIO, false, true);
    REQUIRE(io);
    CHECK(io->cause == "lstat_errno_" + std::to_string(EIO));
}

TEST_CASE("macos::classify_tcc_sqlite_rc: AUTH/PERM denied; CANTOPEN denied only when the VFS "
          "syscall failed EPERM/EACCES; any other code or errno unreadable",
          "[privacy_permissions][macos_parsers]") {
    using macos::SourceOutcome;
    CHECK(macos::classify_tcc_sqlite_rc(macos::kSqliteCantOpen, EPERM) == SourceOutcome::denied);
    CHECK(macos::classify_tcc_sqlite_rc(macos::kSqliteCantOpen, EACCES) == SourceOutcome::denied);
    CHECK(macos::classify_tcc_sqlite_rc(macos::kSqliteCantOpen | (1 << 8), EACCES) ==
          SourceOutcome::denied); // extended code, primary byte compared
    CHECK(macos::classify_tcc_sqlite_rc(macos::kSqliteCantOpen, 0) == SourceOutcome::unreadable);
    CHECK(macos::classify_tcc_sqlite_rc(macos::kSqliteCantOpen, ENOENT) == SourceOutcome::unreadable);
    CHECK(macos::classify_tcc_sqlite_rc(macos::kSqliteCantOpen, EMFILE) == SourceOutcome::unreadable);
    CHECK(macos::classify_tcc_sqlite_rc(macos::kSqliteAuth, 0) == SourceOutcome::denied);
    CHECK(macos::classify_tcc_sqlite_rc(macos::kSqlitePerm, 0) == SourceOutcome::denied);
    CHECK(macos::classify_tcc_sqlite_rc(1 /* SQLITE_ERROR */, EPERM) == SourceOutcome::unreadable);
    CHECK(macos::classify_tcc_sqlite_rc(26 /* SQLITE_NOTADB */, 0) == SourceOutcome::unreadable);
}

TEST_CASE("macos::classify_tcc_sqlite_failure: the stage names the cause; a failed PRAGMA "
          "query_only is always unreadable, never a refusal",
          "[privacy_permissions][macos_parsers]") {
    using macos::SqliteStage;
    const auto open_denied = macos::classify_tcc_sqlite_failure(
        SqliteStage::open, macos::kSqliteCantOpen, EPERM, "unable to open database file");
    CHECK(open_denied.outcome == macos::SourceOutcome::denied);
    CHECK(open_denied.cause == "open_failed:unable to open database file");
    const auto prep = macos::classify_tcc_sqlite_failure(SqliteStage::prepare, 1, 0,
                                                         "no such table: access");
    CHECK(prep.outcome == macos::SourceOutcome::unreadable);
    CHECK(prep.cause == "prepare_failed:no such table: access");
    const auto pragma = macos::classify_tcc_sqlite_failure(
        SqliteStage::query_only, macos::kSqliteCantOpen, EPERM, "unable to open database file");
    CHECK(pragma.outcome == macos::SourceOutcome::unreadable);
    CHECK(pragma.cause == "query_only_failed:unable to open database file");
    // As a whole-source row, the pragma failure is a token-bearing unreadable row.
    yuzu::shared::ConstraintAccumulator acc;
    const auto row = macos::tcc_source_failed_row("alice", pragma, acc);
    CHECK(row.state == PermissionState::unreadable);
    CHECK(row.raw == "alice:tcc_db:query_only_failed:unable to open database file");
    CHECK(acc.reason() == row.raw);
}

TEST_CASE("macos::immutable_uri: only % ? # are encoded, so every hostile spelling round-trips",
          "[privacy_permissions][macos_parsers]") {
    CHECK(macos::immutable_uri("/Users/Jane Doe/TCC.db") ==
          "file:/Users/Jane Doe/TCC.db?immutable=1");
    CHECK(macos::immutable_uri("/Users/a%20b/q?x#h/TCC.db") ==
          "file:/Users/a%2520b/q%3Fx%23h/TCC.db?immutable=1");
}

TEST_CASE("macos::classify_tcc_open_errno: a refused open is denied, a symlink and every other "
          "errno unreadable",
          "[privacy_permissions][macos_parsers]") {
    for (const int e : {EPERM, EACCES})
        CHECK(macos::classify_tcc_open_errno(e).outcome == macos::SourceOutcome::denied);
    CHECK(macos::classify_tcc_open_errno(ELOOP).cause == "open_failed:symlink");
    CHECK(macos::classify_tcc_open_errno(ENOENT).outcome == macos::SourceOutcome::unreadable);
}

TEST_CASE("macos::classify_tcc_header: WAL is either version byte; the change counter is bytes "
          "24..27 big-endian",
          "[privacy_permissions][macos_parsers]") {
    std::array<unsigned char, macos::kSqliteHeaderBytes> h{};
    for (std::size_t i = 0; i < macos::kSqliteMagic.size(); ++i)
        h[i] = static_cast<unsigned char>(macos::kSqliteMagic[i]);
    h[18] = h[19] = 1;
    CHECK_FALSE(macos::classify_tcc_header(h));
    h[24] = 1, h[27] = 4;
    CHECK(macos::header_change_counter(h) == 0x01000004u);
    const auto refusal = [](std::span<const unsigned char> bytes) {
        const auto f = macos::classify_tcc_header(bytes);
        REQUIRE(f);
        return f->cause;
    };
    for (const std::size_t i : {18, 19}) {
        auto wal = h;
        wal[i] = 2;
        CHECK(refusal(wal) == "wal_mode");
    }
    CHECK(refusal(std::span{h}.first(99)) == "not_sqlite");
    h[0] = 'X';
    CHECK(refusal(h) == "not_sqlite");
}

TEST_CASE("macos::read_unchanged: every field of the file stamp matters",
          "[privacy_permissions][macos_parsers]") {
    const macos::FileStamp base{7, 4096, 1700000000, 500, 12};
    CHECK(macos::read_unchanged(base, base));
    const auto changed = [&](auto mutate) {
        auto other = base;
        mutate(other);
        return !macos::read_unchanged(base, other);
    };
    CHECK(changed([](auto& s) { s.inode += 1; }));
    CHECK(changed([](auto& s) { s.size += 1; }));
    CHECK(changed([](auto& s) { s.mtime_sec += 1; }));
    CHECK(changed([](auto& s) { s.mtime_nsec += 1; }));
    CHECK(changed([](auto& s) { s.change_counter += 1; }));
}

TEST_CASE("macos::OutputBudget: counts app_id and raw text and is spent at the cap",
          "[privacy_permissions][macos_parsers]") {
    CHECK(macos::kMaxRunOutputBytes == 16u * 1024u * 1024u);
    CHECK(macos::kBudgetExceededToken == "collection:budget_exceeded");
    macos::OutputBudget b;
    b.max_bytes = 10;
    const std::vector<PermissionRow> rows{
        {"macos", "abcd", "camera", PermissionState::allowed, "12", "-", "-", false}};
    b.charge(rows);
    CHECK(b.bytes == 6);
    CHECK_FALSE(b.exhausted());
    b.charge(rows);
    CHECK(b.exhausted());
}

TEST_CASE("macos::is_user_home_entry: a real home is a non-dot name, a directory seen without "
          "following a symlink, owned by uid >= 500",
          "[privacy_permissions][macos_parsers]") {
    CHECK(macos::is_user_home_entry("alice", true, 501));
    CHECK(macos::is_user_home_entry("bob", true, 500));
    CHECK_FALSE(macos::is_user_home_entry("Shared", true, 0));      // root-owned
    CHECK_FALSE(macos::is_user_home_entry("daemon", true, 499));    // below the user range
    CHECK_FALSE(macos::is_user_home_entry("linked", false, 501));   // a symlink (NOFOLLOW) or file
    CHECK_FALSE(macos::is_user_home_entry(".localized", false, 0)); // dotfile
    CHECK_FALSE(macos::is_user_home_entry(".hidden", true, 501));
    CHECK_FALSE(macos::is_user_home_entry("", true, 501));
    CHECK(macos::home_name_eligible("alice"));
    CHECK_FALSE(macos::home_name_eligible("."));
    CHECK_FALSE(macos::home_name_eligible(".."));
}

TEST_CASE("macos::append_tcc_source_rows: per-user rows qualified; every category is a row -- "
          "decoded grants, absent when clean and empty, unreadable when the step failed",
          "[privacy_permissions][macos_parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PermissionRow> rows;
    // Shaped on the real per-user TCC.db rows this Mac returned on 2026-09-23
    // (kTCCServiceMicrophone|com.microsoft.teams2|2).
    const std::vector<macos::TccServiceRead> reads{
        {"camera", {}, false},
        {"microphone", {{"com.microsoft.teams2", 2}, {"com.example.Broken", std::nullopt}}, false},
        {"full_disk_access", {}, true},
    };
    macos::append_tcc_source_rows("alice", reads, rows, acc);
    REQUIRE(rows.size() == 4);
    CHECK(format_row(rows[0]) == "permissions|macos|alice/-|camera|absent|-|-|-");
    CHECK(format_row(rows[1]) == "permissions|macos|alice/com.microsoft.teams2|microphone|allowed|2|-|-");
    CHECK(rows[2].state == PermissionState::unreadable);
    CHECK(rows[2].raw == "alice:tcc_db:microphone:auth_value_unreadable");
    CHECK(rows[3].category == "full_disk_access");
    CHECK(rows[3].state == PermissionState::unreadable);
    CHECK(rows[3].raw == "alice:tcc_db:full_disk_access:query_step_failed");
    CHECK(acc.reason() ==
          "alice:tcc_db:microphone:auth_value_unreadable,alice:tcc_db:full_disk_access:query_step_failed");

    // The system db (empty owner) keeps its unqualified rows.
    std::vector<PermissionRow> sys;
    const std::vector<macos::TccServiceRead> sys_reads{
        {"full_disk_access", {{"com.microsoft.VSCode", 2}}, false}};
    macos::append_tcc_source_rows({}, sys_reads, sys, acc);
    REQUIRE(sys.size() == 1);
    CHECK(format_row(sys[0]) == "permissions|macos|com.microsoft.VSCode|full_disk_access|allowed|2|-|-");
}

TEST_CASE("macos::append_tcc_source_rows: a failed bind is one unreadable row for that category "
          "and never an absent one",
          "[privacy_permissions][macos_parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PermissionRow> rows;
    const std::vector<macos::TccServiceRead> reads{{"camera", {}, false, true}};
    macos::append_tcc_source_rows({}, reads, rows, acc);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].category == "camera");
    CHECK(rows[0].state == PermissionState::unreadable);
    CHECK(rows[0].raw == "tcc_db:camera:query_bind_failed");
    CHECK(acc.reason() == "tcc_db:camera:query_bind_failed");
}

TEST_CASE("macos::tcc_source_failed_row: absent carries no token; denied/unreadable carry "
          "`<source>:<cause>` and are never absent",
          "[privacy_permissions][macos_parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    const auto absent = macos::tcc_source_failed_row("bob", {macos::SourceOutcome::absent, {}}, acc);
    CHECK(format_row(absent) == "permissions|macos|bob/-|-|absent|-|-|-");
    CHECK_FALSE(acc.any_failure());

    const auto denied = macos::tcc_source_failed_row(
        "bob", {macos::SourceOutcome::denied, "access_denied"}, acc);
    CHECK(denied.state == PermissionState::denied);
    CHECK(denied.read_denied);
    CHECK(denied.raw == "bob:tcc_db:access_denied");

    const auto sys = macos::tcc_source_failed_row(
        {}, {macos::SourceOutcome::unreadable, "open_failed:disk I/O error"}, acc);
    CHECK(sys.app_id == "-");
    CHECK(sys.state == PermissionState::unreadable);
    CHECK(sys.raw == "tcc_db:open_failed:disk I/O error");
}
