/**
 * test_privacy_permissions_parsers.cpp -- pure tests for privacy_permissions_parsers.hpp,
 * privacy_permissions_win_parsers.hpp, privacy_permissions_macos_parsers.hpp and
 * privacy_permissions_linux_parsers.hpp (all three legs; every header is OS-free, so every case
 * runs on every host). No OS call, no platform guard. The one file read is the committed YAML
 * definition (the row_kind/column pin).
 */
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

#include "privacy_permissions_linux_parsers.hpp"
#include "privacy_permissions_macos_parsers.hpp"
#include "privacy_permissions_parsers.hpp"
#include "privacy_permissions_win_parsers.hpp"

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


// ── Windows-specific pure layer ──────────────────────────────────────────

TEST_CASE("win::kCapabilities: the four mapped CapabilityName keys, one per category",
          "[privacy_permissions][win_parsers]") {
    REQUIRE(win::kCapabilities.size() == kCategories.size());
    CHECK(win::kCapabilities[0].capability_name == "webcam");
    CHECK(win::kCapabilities[3].capability_name == "broadFileSystemAccess");
    for (std::size_t i = 0; i < kCategories.size(); ++i)
        CHECK(win::kCapabilities[i].category == kCategories[i]);
}

TEST_CASE("win::decode_consent_value: Allow/Deny decode, wrong type or empty is unreadable, "
          "an unknown literal is prompt_undetermined (never silently allowed/denied)",
          "[privacy_permissions][win_parsers]") {
    CHECK(win::decode_consent_value("Allow", true) == PermissionState::allowed);
    CHECK(win::decode_consent_value("Deny", true) == PermissionState::denied);
    CHECK(win::decode_consent_value("Allow", false) == PermissionState::unreadable); // wrong type
    CHECK(win::decode_consent_value("", true) == PermissionState::unreadable);       // empty
    CHECK(win::decode_consent_value("Prompt", true) == PermissionState::prompt_undetermined);
}

TEST_CASE("win::unescape_nonpackaged_app_id: '#' is the path separator and nothing else is "
          "rewritten (the drive colon is literal; a `#3A` stays as written)",
          "[privacy_permissions][win_parsers]") {
    CHECK(win::unescape_nonpackaged_app_id("C:#Program Files#App.exe") ==
          "C:\\Program Files\\App.exe");
    CHECK(win::unescape_nonpackaged_app_id("C#3AUsers#name#app.exe") ==
          "C\\3AUsers\\name\\app.exe");
}

TEST_CASE("win::filetime_to_epoch_ms_string: zero and pre-epoch are '-', a real value converts",
          "[privacy_permissions][win_parsers]") {
    CHECK(win::filetime_to_epoch_ms_string(0) == "-");
    CHECK(win::filetime_to_epoch_ms_string(1) == "-"); // far before the Unix epoch
    // The 1601->1970 epoch boundary itself: exactly epoch_ms=0, and one more 100ns-tick
    // interval (10000 ticks = 1ms) past it converts to exactly 1ms -- both self-verifying
    // (derived from the function's own documented constant, not a separately hand-computed
    // calendar date, which is the trap the first version of this test fell into).
    constexpr std::uint64_t kEpochDiff100ns = 116444736000000000ULL;
    CHECK(win::filetime_to_epoch_ms_string(kEpochDiff100ns) == "0");
    CHECK(win::filetime_to_epoch_ms_string(kEpochDiff100ns + 10000) == "1");
    CHECK(win::filetime_to_epoch_ms_string(kEpochDiff100ns + 86400ULL * 10000000ULL) == "86400000"); // +1 day
}

TEST_CASE("win::decode_last_used: only a REG_QWORD of exactly 8 bytes converts; not-found is "
          "'-'; every other outcome is a visible `unreadable` with a cause",
          "[privacy_permissions][win_parsers]") {
    constexpr std::uint64_t kEpochDiff100ns = 116444736000000000ULL;
    const auto ok = win::decode_last_used(win::kErrorSuccess, win::kRegQword, 8, kEpochDiff100ns + 10000);
    CHECK(ok.value == "1");
    CHECK(ok.cause.empty());

    const auto missing = win::decode_last_used(win::kErrorFileNotFound, 0, 0, 0);
    CHECK(missing.value == "-");
    CHECK(missing.cause.empty());

    const auto short_q = win::decode_last_used(win::kErrorSuccess, win::kRegQword, 4, 0);
    CHECK(short_q.value == "unreadable");
    CHECK(short_q.cause == "size_4");

    const auto wrong_t = win::decode_last_used(win::kErrorSuccess, win::kRegSz, 8, 0);
    CHECK(wrong_t.value == "unreadable");
    CHECK(wrong_t.cause == "type_1");

    const auto denied = win::decode_last_used(win::kErrorAccessDenied, 0, 0, 0);
    CHECK(denied.value == "unreadable");
    CHECK(denied.cause == "access_denied");
    CHECK(denied.denied);

    const auto more_data = win::decode_last_used(234, 3 /* REG_BINARY */, 16, 0);
    CHECK(more_data.cause == "win32_234");
    CHECK_FALSE(more_data.denied);
}

TEST_CASE("win::merge_with_hklm: most restrictive wins -- a successfully read HKLM Deny overrides "
          "the profile, an HKLM Allow never overrides a user Deny/Prompt nor invents a grant, a "
          "failed HKLM read never overrides, and a failed profile entry is never hidden",
          "[privacy_permissions][win_parsers]") {
    using win::RawGrant;
    const auto grant = [](std::string app, PermissionState st, std::string raw,
                          bool read_denied = false, std::string cause = {}) {
        RawGrant g{std::move(app), "camera", st, std::move(raw)};
        g.read_denied = read_denied;
        g.cause = std::move(cause);
        return g;
    };
    const auto merged_state = [&](const RawGrant& user, const RawGrant& machine) {
        const std::vector<RawGrant> profile{user};
        const std::vector<RawGrant> hklm{machine};
        const auto m = win::merge_with_hklm(profile, hklm);
        REQUIRE(m.size() == 1);
        return std::pair{m[0].state, m[0].raw_value};
    };
    const auto allow = grant("app", PermissionState::allowed, "Allow");
    const auto deny = grant("app", PermissionState::denied, "Deny");
    const auto prompt = grant("app", PermissionState::prompt_undetermined, "Prompt");

    SECTION("HKLM Deny (read OK) wins over every successfully read user value") {
        for (const auto& user : {allow, deny, prompt})
            CHECK(merged_state(user, deny) == std::pair{PermissionState::denied, std::string{"Deny"}});
    }
    SECTION("HKLM Allow defers to the user's own value") {
        CHECK(merged_state(deny, allow) == std::pair{PermissionState::denied, std::string{"Deny"}});
        CHECK(merged_state(prompt, allow) ==
              std::pair{PermissionState::prompt_undetermined, std::string{"Prompt"}});
        CHECK(merged_state(allow, allow) == std::pair{PermissionState::allowed, std::string{"Allow"}});
    }
    SECTION("an overriding HKLM Deny keeps the profile row's last-used times") {
        auto user = allow;
        user.last_used_start.value = "133000000000000000";
        user.last_used_stop.value = "133000000010000000";
        const std::vector<RawGrant> profile{user};
        const std::vector<RawGrant> hklm{deny};
        const auto m = win::merge_with_hklm(profile, hklm);
        REQUIRE(m.size() == 1);
        CHECK(m[0].state == PermissionState::denied);
        CHECK(m[0].last_used_start.value == "133000000000000000");
        CHECK(m[0].last_used_stop.value == "133000000010000000");
    }
    SECTION("an unmodelled HKLM literal overrides nothing") {
        CHECK(merged_state(allow, prompt) == std::pair{PermissionState::allowed, std::string{"Allow"}});
    }
    SECTION("an absent, unreadable or refused HKLM entry overrides nothing") {
        for (const auto& h : {grant("app", PermissionState::absent, "-"),
                              grant("app", PermissionState::unreadable, "-", false, "value_empty"),
                              grant("app", PermissionState::denied, "-", true, "value_access_denied")})
            CHECK(merged_state(deny, h) == std::pair{PermissionState::denied, std::string{"Deny"}});
    }
    SECTION("HKLM Deny fills a key the profile lacks; HKLM Allow never invents a user grant") {
        const std::vector<RawGrant> profile{};
        const std::vector<RawGrant> hklm_deny{deny};
        const auto m = win::merge_with_hklm(profile, hklm_deny);
        REQUIRE(m.size() == 1);
        CHECK(m[0].state == PermissionState::denied);
        const std::vector<RawGrant> hklm_allow{allow};
        CHECK(win::merge_with_hklm(profile, hklm_allow).empty());
    }
    SECTION("a failed profile entry is kept, and an overriding HKLM Deny is added beside it") {
        const std::vector<RawGrant> profile{
            grant("app", PermissionState::unreadable, "-", false, "value_empty")};
        const std::vector<RawGrant> hklm{deny};
        const auto m = win::merge_with_hklm(profile, hklm);
        REQUIRE(m.size() == 2);
        CHECK(m[0].state == PermissionState::unreadable);
        CHECK(m[1].state == PermissionState::denied);
        CHECK(m[1].raw_value == "Deny");
    }
}

TEST_CASE("win: the three ConsentStore levels on the-rig's real shapes -- the NonPackaged toggle is "
          "its own row, a Value-less per-app NonPackaged key is absent, `Executables` is a "
          "container, and most-restrictive applies key by key",
          "[privacy_permissions][win_parsers]") {
    using win::RawGrant;
    // Measured 2026-09-23 (HKU\<sid>\...\ConsentStore\location and HKLM\...\ConsentStore\location):
    //   location                      Value REG_SZ Allow   (user capability toggle)
    //   location\NonPackaged          Value REG_SZ Allow   (user "let desktop apps access")
    //   location\NonPackaged\C:#Program Files#Mozilla Firefox#firefox.exe   LastUsedTime* only
    //   location\NonPackaged\Executables\firefox.exe   GlobalPromptShown only (a container)
    //   location\OpenAI.Codex_2p2nqsd0c76g0            Value REG_SZ Prompt
    //   HKLM location Value Allow; HKLM location\NonPackaged (no Value);
    //   HKLM location\NonPackaged\C:#Windows#System32#svchost.exe   LastUsedTime* only
    CHECK(win::kNonPackagedToggleAppId == "NonPackaged");
    const std::string firefox =
        win::unescape_nonpackaged_app_id("C:#Program Files#Mozilla Firefox#firefox.exe");
    CHECK(firefox == "C:\\Program Files\\Mozilla Firefox\\firefox.exe");
    CHECK(win::unescape_nonpackaged_app_id("C:#PROGRA~2#Citrix#ICACLI~1#HdxRtcEngine.exe") ==
          "C:\\PROGRA~2\\Citrix\\ICACLI~1\\HdxRtcEngine.exe");

    const auto g = [](std::string app, PermissionState st, std::string raw) {
        return RawGrant{std::move(app), "location", st, std::move(raw)};
    };
    const std::string toggle{win::kNonPackagedToggleAppId};
    const std::vector<RawGrant> profile{
        g("-", PermissionState::allowed, "Allow"), g(toggle, PermissionState::allowed, "Allow"),
        g(firefox, PermissionState::absent, "-"),
        g("OpenAI.Codex_2p2nqsd0c76g0", PermissionState::prompt_undetermined, "Prompt")};
    const std::vector<RawGrant> hklm{
        g("-", PermissionState::allowed, "Allow"), g(toggle, PermissionState::absent, "-"),
        g("C:\\Windows\\System32\\svchost.exe", PermissionState::absent, "-")};

    SECTION("the real host: nothing overrides, every profile level survives as stored") {
        const auto m = win::merge_with_hklm(profile, hklm);
        REQUIRE(m.size() == profile.size());
        for (const auto& row : m) {
            INFO(row.app_id);
            const auto it = std::find_if(profile.begin(), profile.end(),
                                         [&](const RawGrant& p) { return p.app_id == row.app_id; });
            REQUIRE(it != profile.end());
            CHECK(row.state == it->state);
        }
        // Every HKLM level is reported once as HKLM's own row (the device toggle included);
        // none was applied into the profile.
        for (const auto& h : hklm) CHECK(win::hklm_emitted_once(h, true));
    }
    SECTION("an HKLM NonPackaged Deny overrides only the user's NonPackaged toggle") {
        const std::vector<RawGrant> hklm_deny{g(toggle, PermissionState::denied, "Deny")};
        const auto m = win::merge_with_hklm(profile, hklm_deny);
        REQUIRE(m.size() == profile.size());
        for (const auto& row : m) {
            INFO(row.app_id);
            if (row.app_id == toggle) {
                CHECK(row.state == PermissionState::denied);
                CHECK(row.raw_value == "Deny");
            } else {
                CHECK(row.state != PermissionState::denied);
            }
        }
        CHECK_FALSE(win::hklm_emitted_once(hklm_deny[0], true)); // carried by the profile row
    }
    SECTION("on the wire the toggle is qualified like every per-user row") {
        CHECK(format_row({"windows", qualify_app_id("jsmith", toggle), "location",
                          PermissionState::allowed, "Allow", "-", "-", false}) ==
              "permissions|windows|jsmith/NonPackaged|location|allowed|Allow|-|-");
        CHECK(format_row({"windows", qualify_app_id("jsmith", firefox), "location",
                          PermissionState::absent, "-", "1783980629480", "1783980638651", false}) ==
              "permissions|windows|jsmith/C:/Program Files/Mozilla Firefox/firefox.exe|location|"
              "absent|-|1783980629480|1783980638651");
    }
}

TEST_CASE("win::hklm_emitted_once: an overriding Deny is HKLM's own row only with no reachable "
          "profile; Allow, failures, app-level entries and a capability-level absent always",
          "[privacy_permissions][win_parsers]") {
    win::RawGrant deny{"-", "camera", PermissionState::denied, "Deny"};
    win::RawGrant allow{"-", "camera", PermissionState::allowed, "Allow"};
    win::RawGrant absent_cap{"-", "camera", PermissionState::absent, "-"};
    win::RawGrant absent_app{"C:\\app.exe", "camera", PermissionState::absent, "-"};
    win::RawGrant refused{"-", "camera", PermissionState::denied, "-"};
    refused.read_denied = true;
    refused.cause = "value_access_denied";
    CHECK(win::hklm_overrides_profile(deny));
    CHECK_FALSE(win::hklm_overrides_profile(refused));
    CHECK_FALSE(win::hklm_emitted_once(deny, true));
    CHECK(win::hklm_emitted_once(deny, false));
    CHECK(win::hklm_emitted_once(allow, true));
    CHECK(win::hklm_emitted_once(refused, true));
    CHECK(win::hklm_emitted_once(absent_app, true));
    CHECK(win::hklm_emitted_once(absent_cap, true));
    CHECK(win::hklm_emitted_once(absent_cap, false));
}

TEST_CASE("win: failed profile discovery never suppresses HKLM's definitive capability-level "
          "absences -- they are HKLM's own rows, not left to the backstop",
          "[privacy_permissions][win_parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PermissionRow> rows{
        failure_row("windows", "-", "-", false, "profiles:profile_list_unreadable", acc)};
    for (const auto& cap : win::kCapabilities) { // HKLM ConsentStore root: ERROR_FILE_NOT_FOUND
        const win::RawGrant g{"-", cap.category, PermissionState::absent, "-"};
        if (win::hklm_emitted_once(g, false))
            rows.push_back({"windows", g.app_id, g.category, g.state, g.raw_value, "-", "-", false});
    }
    fill_uncovered_categories("windows", rows); // suppressed by the whole-source row
    REQUIRE(rows.size() == 1 + kCategories.size());
    for (std::size_t i = 0; i < kCategories.size(); ++i) {
        CHECK(rows[i + 1].category == kCategories[i]);
        CHECK(rows[i + 1].state == PermissionState::absent);
    }
}

TEST_CASE("win::profile_discovery_failure: a refused root or mid-walk enumeration is denied; any "
          "other root failure, terminating error or cap overflow is unreadable; only a clean end "
          "(or exactly the cap) is complete",
          "[privacy_permissions][win_parsers]") {
    const long ok = win::kErrorSuccess, done = win::kErrorNoMoreItems, refused = win::kErrorAccessDenied;
    const auto check = [](std::optional<win::EnumFailure> f, std::string cause, bool denied) {
        REQUIRE(f);
        CHECK(f->cause == cause);
        CHECK(f->denied == denied);
    };
    check(win::profile_discovery_failure(refused, ok, done), "profiles:profile_list_access_denied", true);
    check(win::profile_discovery_failure(2, ok, done), "profiles:profile_list_unreadable", false);
    CHECK_FALSE(win::profile_discovery_failure(ok, done, done));       // walk ended cleanly
    CHECK_FALSE(win::profile_discovery_failure(ok, ok, done));         // exactly the cap
    check(win::profile_discovery_failure(ok, ok, ok), "profiles:truncated", false);
    check(win::profile_discovery_failure(ok, refused, done), "profiles:enum_access_denied", true);
    check(win::profile_discovery_failure(ok, 1018, done), "profiles:enum_win32_1018", false);
    check(win::profile_discovery_failure(ok, ok, refused), "profiles:enum_access_denied", true);
    const auto key = win::profile_record_failure(true, refused);
    CHECK(key.cause == "profiles:profile_key_access_denied");
    CHECK(key.denied);
    const auto path = win::profile_record_failure(false, 1018);
    CHECK(path.cause == "profiles:profile_image_path_win32_1018");
    CHECK_FALSE(path.denied);
}

TEST_CASE("win::RetentionBudget: one source at its own cap stops only its own walk -- the next "
          "source starts from zero and retains its Deny; refusal is sticky and never wraps",
          "[privacy_permissions][win_parsers]") {
    CHECK(win::kMaxConsentValueBytes == 64);
    CHECK(win::kMaxConsentValueBytes >= (std::string_view{"Prompt"}.size() + 1) * 2);
    const win::RetentionBudget defaults;
    CHECK(defaults.source.max_rows == 8192);
    CHECK(defaults.source.max_bytes == 2u * 1024u * 1024u);

    win::RetentionBudget b;
    b.source.max_rows = 2;
    b.begin_profile();
    CHECK(b.charge(1));
    CHECK(b.charge(1));
    CHECK_FALSE(b.charge(1)); // the cap-th grant fits, one more is refused
    CHECK(b.source.refused);
    CHECK(b.walk_stopped());
    CHECK_FALSE(b.charge(0)); // sticky for the rest of this source

    b.begin_profile(); // the next source starts from zero
    CHECK_FALSE(b.walk_stopped());
    const win::RawGrant deny{"-", "camera", PermissionState::denied, "Deny"};
    CHECK(b.charge(win::retained_bytes(deny)));
    CHECK(b.source.rows == 1);

    win::RetentionBudget bytes;
    bytes.source.max_bytes = 10;
    CHECK(bytes.charge(6));
    CHECK(bytes.charge(4)); // exactly the cap fits
    CHECK(bytes.source.bytes == 10);
    CHECK_FALSE(bytes.charge(1));
    CHECK(bytes.source.refused);
    CHECK_FALSE(bytes.charge(0)); // sticky per source: even a charge that would fit is refused
    bytes.begin_profile();
    CHECK_FALSE(bytes.charge(static_cast<std::size_t>(-1))); // an oversized grant never wraps
    CHECK(bytes.source.refused);

    const win::RawGrant g{"C:\\a.exe", "camera", PermissionState::allowed, "Allow"};
    CHECK(win::retained_bytes(g) == std::string_view{"C:\\a.exe"}.size() + 5);
}

TEST_CASE("win::RetentionBudget: begin_profile restarts the source counters, never the run's clock",
          "[privacy_permissions][win_parsers]") {
    win::RetentionBudget b;
    b.deadline = std::chrono::steady_clock::now() - std::chrono::seconds{1};
    REQUIRE(b.expired());
    b.begin_profile();
    CHECK(b.timed_out);
    CHECK(b.expired());
}

TEST_CASE("win::RetentionBudget: the run deadline is injectable, inclusive and sticky",
          "[privacy_permissions][win_parsers]") {
    using Clock = std::chrono::steady_clock;
    CHECK(win::kRunBudget == std::chrono::seconds{15});
    CHECK(win::kTimeoutToken == "collection:timeout");
    CHECK(win::run_stop_token(win::kTimeoutToken, 0) == "collection:timeout:profiles_skipped_0");

    win::RetentionBudget b;
    b.deadline = Clock::time_point::max();
    CHECK_FALSE(b.walk_stopped());
    const auto t = Clock::time_point{} + std::chrono::seconds{100};
    b.deadline = t;
    CHECK_FALSE(b.expired(t - std::chrono::nanoseconds{1}));
    CHECK_FALSE(b.timed_out);
    CHECK(b.expired(t));
    b.deadline = Clock::time_point::max();
    CHECK(b.expired(t - std::chrono::nanoseconds{1})); // once tripped it stays tripped
    CHECK(b.walk_stopped());
}

TEST_CASE("win::coarse_failure_token: one token per kind of failure, however many apps share it",
          "[privacy_permissions][win_parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    for (int i = 0; i < 1000; ++i)
        acc.add_failure(win::coarse_failure_token("alice", "camera", "value_oversized"));
    CHECK(acc.reason() == "alice:camera:value_oversized");

    // A number the ConsentStore owner chooses (a value's type, a LastUsedTime size) is not kept.
    yuzu::shared::ConstraintAccumulator typed;
    for (int i = 0; i < 1000; ++i) {
        typed.add_failure(
            win::coarse_failure_token("alice", "camera", "value_type_" + std::to_string(i)));
        typed.add_failure(win::coarse_failure_token("alice", "camera",
                                                    "last_used_start_size_" + std::to_string(i)));
    }
    CHECK(typed.reason() == "alice:camera:value_type,alice:camera:last_used_start_size");
    CHECK(win::coarse_failure_token("alice", "camera", "value_win32_1450") ==
          "alice:camera:value_win32_1450");
}

TEST_CASE("win::nonpackaged_open_failure: a missing NonPackaged key is the toggle row reading "
          "absent; a refusal is denied, any other code unreadable",
          "[privacy_permissions][win_parsers]") {
    const auto missing = win::nonpackaged_open_failure("camera", win::kErrorFileNotFound);
    CHECK(missing.app_id == win::kNonPackagedToggleAppId);
    CHECK(missing.state == PermissionState::absent);
    CHECK(missing.cause.empty());
    CHECK_FALSE(win::grant_failed(missing));
    const auto refused = win::nonpackaged_open_failure("camera", win::kErrorAccessDenied);
    CHECK(refused.app_id == "-");
    CHECK(refused.read_denied);
    CHECK(refused.cause == "nonpackaged_container:access_denied");
    const auto other = win::nonpackaged_open_failure("camera", 1);
    CHECK(other.state == PermissionState::unreadable);
    CHECK(other.cause == "nonpackaged_container:win32_1");
}

TEST_CASE("win::merge_with_hklm: two registry keys decoding to one app id keep both rows plus a "
          "duplicate_app_id row -- neither silently replaces the other",
          "[privacy_permissions][win_parsers]") {
    const std::string id = "X"; // a packaged key `X` and a NonPackaged key `X`
    const std::vector<win::RawGrant> profile{{id, "camera", PermissionState::allowed, "Allow"},
                                             {id, "camera", PermissionState::denied, "Deny"}};
    const auto m = win::merge_with_hklm(profile, {});
    REQUIRE(m.size() == 3);
    CHECK(std::count_if(m.begin(), m.end(), [](const win::RawGrant& g) { return g.raw_value == "Allow"; }) == 1);
    CHECK(std::count_if(m.begin(), m.end(), [](const win::RawGrant& g) { return g.raw_value == "Deny"; }) == 1);
    const auto collision = std::find_if(m.begin(), m.end(), [](const win::RawGrant& g) {
        return g.cause == "duplicate_app_id";
    });
    REQUIRE(collision != m.end());
    CHECK(collision->app_id == id);
    CHECK(collision->state == PermissionState::unreadable);
}

TEST_CASE("win::classify_subkey_enum + enum_failure: exactly the cap is complete (no token), more "
          "than the cap is truncated, a genuine error or a failed probe is a failure",
          "[privacy_permissions][win_parsers]") {
    using win::EnumOutcome;
    // Stopped on its own: NO_MORE_ITEMS is the only clean end.
    const auto clean = win::classify_subkey_enum(win::kErrorNoMoreItems, win::kErrorSuccess);
    CHECK(clean.outcome == EnumOutcome::complete);
    CHECK_FALSE(win::enum_failure("packaged", clean).has_value());
    // Exactly kMaxEnumeratedSubkeys children: the loop stops at the cap (SUCCESS) and the probe
    // finds nothing more -- the false `packaged_enum_0` this used to emit.
    const auto exact = win::classify_subkey_enum(win::kErrorSuccess, win::kErrorNoMoreItems);
    CHECK(exact.outcome == EnumOutcome::complete);
    CHECK_FALSE(win::enum_failure("packaged", exact).has_value());
    // Over the cap: the probe finds a real next child.
    const auto over = win::classify_subkey_enum(win::kErrorSuccess, win::kErrorSuccess);
    CHECK(over.outcome == EnumOutcome::truncated);
    const auto over_f = win::enum_failure("nonpackaged", over);
    REQUIRE(over_f);
    CHECK(over_f->cause == "nonpackaged_enum_truncated");
    CHECK_FALSE(over_f->denied);
    // A genuine mid-walk error, refused and otherwise.
    const auto refused = win::enum_failure(
        "packaged", win::classify_subkey_enum(win::kErrorAccessDenied, win::kErrorSuccess));
    REQUIRE(refused);
    CHECK(refused->cause == "packaged_enum_access_denied");
    CHECK(refused->denied);
    const auto more_data = win::enum_failure("packaged", win::classify_subkey_enum(234, 0));
    REQUIRE(more_data);
    CHECK(more_data->cause == "packaged_enum_win32_234");
    CHECK_FALSE(more_data->denied);
    // The cap-boundary probe itself failed: never read as complete.
    const auto probe = win::enum_failure(
        "packaged", win::classify_subkey_enum(win::kErrorSuccess, win::kErrorAccessDenied));
    REQUIRE(probe);
    CHECK(probe->cause == "packaged_enum_access_denied");
    CHECK(probe->denied);
    // A complete walk that skipped an embedded-NUL name reports it once, not denied; a truncated
    // walk keeps its own (incomplete-source) token.
    auto nul = win::classify_subkey_enum(win::kErrorNoMoreItems, win::kErrorSuccess);
    nul.embedded_nul_names = 2;
    const auto nul_f = win::enum_failure("nonpackaged", nul);
    REQUIRE(nul_f);
    CHECK(nul_f->cause == "nonpackaged:name_embedded_nul");
    CHECK_FALSE(nul_f->denied);
    auto nul_over = over;
    nul_over.embedded_nul_names = 1;
    CHECK(win::enum_failure("nonpackaged", nul_over)->cause == "nonpackaged_enum_truncated");
}

TEST_CASE("win::is_valid_sid_string: only an S-1-<digits>(-<digits>)* SID may be appended to "
          "HKEY_USERS -- empty or malformed never opens the HKU root",
          "[privacy_permissions][win_parsers]") {
    CHECK(win::is_valid_sid_string("S-1-5-21-1111111111-2222222222-3333333333-1013"));
    CHECK(win::is_valid_sid_string("S-1-5-18"));
    CHECK_FALSE(win::is_valid_sid_string(""));
    CHECK_FALSE(win::is_valid_sid_string("S-1-"));
    CHECK_FALSE(win::is_valid_sid_string("S-1-5-"));
    CHECK_FALSE(win::is_valid_sid_string("S-1-5--21"));
    CHECK_FALSE(win::is_valid_sid_string("S-2-5-21"));
    CHECK_FALSE(win::is_valid_sid_string("s-1-5-21"));
    CHECK_FALSE(win::is_valid_sid_string("S-1-5-21\\Software"));
    CHECK_FALSE(win::is_valid_sid_string("S-1-5-21 "));
    CHECK_FALSE(win::is_valid_sid_string("S-1-5-" + std::string(300, '1')));
}

TEST_CASE("OutputBudget reserve: rows charged first always fit, and a later source that would "
          "cross the cap reports it before it is emitted",
          "[privacy_permissions][win_parsers]") {
    const std::vector<PermissionRow> machine{
        {"windows", "-", "camera", PermissionState::allowed, "Allow", "-", "-", false}};
    const std::vector<PermissionRow> profile{
        {"windows", "jsmith/-", "camera", PermissionState::denied, "Deny", "-", "-", false}};
    OutputBudget b;
    b.budget.max_bytes = OutputBudget::cost(machine) + OutputBudget::cost(profile) - 1;
    b.charge(machine); // reserved first
    CHECK_FALSE(b.exhausted());
    CHECK(b.would_exceed(profile)); // the profile does not fit beside the reservation...
    CHECK(b.budget.bytes == OutputBudget::cost(machine)); // ...and the reservation is untouched
    b.budget.max_bytes += 1;
    CHECK_FALSE(b.would_exceed(profile)); // exactly the cap fits
    b.charge(profile);
    CHECK(b.exhausted());
    CHECK(b.would_exceed(machine)); // spent: nothing further fits, and no unsigned wrap
}

TEST_CASE("select_status: a token-only failure with no denied row and no unreadable row is "
          "CONSTRAINED/PARTIAL, never OK",
          "[privacy_permissions][win_parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    acc.add_failure("jsmith:hive_unload_failed");
    const auto st = select_status(acc, false, false);
    CHECK(st.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(st.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(st.provenance == "jsmith:hive_unload_failed");
}

TEST_CASE("win::hive_owner_allowed: exactly the profile SID, LocalSystem and Administrators",
          "[privacy_permissions][win_parsers]") {
    const std::string profile = "S-1-5-21-1-2-3-1001";
    CHECK(win::hive_owner_allowed(profile, profile));
    CHECK(win::hive_owner_allowed("S-1-5-18", profile));
    CHECK(win::hive_owner_allowed("S-1-5-32-544", profile));
    CHECK_FALSE(win::hive_owner_allowed("S-1-5-19", profile));
    CHECK_FALSE(win::hive_owner_allowed("S-1-5-20", profile));
    CHECK_FALSE(win::hive_owner_allowed("S-1-5-21-1-2-3-1002", profile));
    CHECK_FALSE(win::hive_owner_allowed("", profile));
    CHECK_FALSE(win::hive_owner_allowed("", ""));
}

TEST_CASE("win::classify_hive_file: a stock hive is accepted; each refusal fires in its fixed "
          "order",
          "[privacy_permissions][win_parsers]") {
    const std::string profile = "S-1-5-21-1-2-3-1001";
    const auto stock = [&] {
        win::HiveFileFacts f;
        f.depth = 3;
        f.profile_sid = profile;
        f.owner_sid = profile;
        f.size = 1024;
        return f;
    };
    const auto token = [](const win::HiveFileFacts& f) {
        const auto t = win::classify_hive_file(f);
        return t ? *t : std::string{"<accepted>"};
    };

    CHECK(token(stock()) == "<accepted>");
    for (const char* owner : {"S-1-5-18", "S-1-5-32-544"}) {
        auto f = stock();
        f.owner_sid = owner;
        CHECK(token(f) == "<accepted>");
    }
    SECTION("path facts") {
        auto unc = stock();
        unc.path_is_unc = true;
        unc.drive_type = 4; // would also be refused later: the UNC verdict comes first
        CHECK(token(unc) == "hive_path_unc");
        for (const std::uint32_t remote : {4u, 0u, 1u, 2u, 5u}) { // REMOTE, UNKNOWN, NO_ROOT_DIR, ...
            auto f = stock();
            f.drive_type = remote;
            CHECK(token(f) == "hive_path_not_fixed");
        }
        auto deep = stock();
        deep.depth = win::kMaxHivePathDepth + 1;
        CHECK(token(deep) == "hive_path_too_deep");
        deep.depth = win::kMaxHivePathDepth;
        CHECK(token(deep) == "<accepted>");
        auto anc = stock();
        anc.ancestor_reparse = true;
        anc.is_reparse = true; // a leaf fact: the ancestor verdict comes first
        CHECK(token(anc) == "hive_path_reparse_ancestor");
    }
    SECTION("leaf facts") {
        auto rp = stock();
        rp.is_reparse = true;
        CHECK(token(rp) == "hive_reparse_point");
        auto dir = stock();
        dir.is_directory = true;
        CHECK(token(dir) == "hive_not_regular");
        auto pipe = stock();
        pipe.is_disk_file = false;
        CHECK(token(pipe) == "hive_not_regular");
        auto cloud = stock();
        cloud.not_resident = true; // an offline / recall-on-open placeholder is never loaded
        CHECK(token(cloud) == "hive_not_resident");
        cloud.is_directory = true; // not_regular is decided first
        CHECK(token(cloud) == "hive_not_regular");
        auto placeholder = stock(); // not_resident outranks the owner, redirect and size refusals
        placeholder.not_resident = true;
        placeholder.owner_sid = "S-1-5-21-1-2-3-1002";
        placeholder.final_path_matches = false;
        placeholder.size = win::kMaxHiveBytes + 1;
        CHECK(token(placeholder) == "hive_not_resident");
        auto own = stock();
        own.owner_sid = "S-1-5-21-1-2-3-1002";
        CHECK(token(own) == "hive_owner_unexpected");
        auto big = stock();
        big.size = win::kMaxHiveBytes + 1;
        CHECK(token(big) == "hive_oversized");
        big.size = win::kMaxHiveBytes;
        CHECK(token(big) == "<accepted>");
    }
    SECTION("sidecar facts") {
        auto rp = stock();
        rp.sidecar_reparse = true;
        CHECK(token(rp) == "hive_sidecar_reparse");
        auto hl = stock();
        hl.sidecar_hardlinked = true;
        CHECK(token(hl) == "hive_sidecar_hardlinked");
        auto many = stock();
        many.sidecar_count = win::kMaxHiveSidecars;
        CHECK(win::kMaxHiveSidecars == 64);
        CHECK(token(many) == "<accepted>");
        many.sidecar_count = win::kMaxHiveSidecars + 1;
        CHECK(token(many) == "hive_sidecar_count");
    }
    SECTION("the order is pinned: owner before redirect before size before the sidecars") {
        auto f = stock();
        f.owner_sid = "S-1-5-21-1-2-3-1002";
        f.final_path_matches = false;
        f.size = win::kMaxHiveBytes + 1;
        CHECK(token(f) == "hive_owner_unexpected");
        f.owner_sid = profile;
        CHECK(token(f) == "hive_path_redirected");
        f.final_path_matches = true;
        CHECK(token(f) == "hive_oversized");
        f.size = 1024;
        f.sidecar_reparse = f.sidecar_hardlinked = true;
        f.sidecar_count = win::kMaxHiveSidecars + 1;
        CHECK(token(f) == "hive_sidecar_reparse");
        f.sidecar_reparse = false;
        CHECK(token(f) == "hive_sidecar_hardlinked");
        f.sidecar_hardlinked = false;
        CHECK(token(f) == "hive_sidecar_count");
        f.size = win::kMaxHiveBytes + 1; // every earlier refusal outranks a sidecar fact
        CHECK(token(f) == "hive_oversized");
    }
}

TEST_CASE("win::classify_stability: stable only on a created event, an armed watch and a timed-out "
          "wait -- every other outcome refuses the source",
          "[privacy_permissions][win_parsers]") {
    using F = win::StabilityFacts;
    const auto token = [](const F& f) {
        const auto t = win::classify_stability(f);
        return t ? *t : std::string{"<stable>"};
    };
    CHECK(token(F{0, 0, win::kWaitTimeout, 0}) == "<stable>");
    CHECK(token(F{0, 0, win::kWaitObject0, 0}) == win::kChangedDuringRead);
    CHECK(token(F{0, 0, 0xFFFFFFFFul /* WAIT_FAILED */, 6}) == "notify_wait_failed:win32_6");
    CHECK(token(F{0, 0, 0x80ul /* WAIT_ABANDONED */, 0}) == "notify_wait_failed:win32_0");
    CHECK(token(F{8, 0, win::kWaitTimeout, 0}) == "notify_event_failed:win32_8");
    CHECK(token(F{0, 5, win::kWaitTimeout, 0}) == "notify_failed:win32_5");
    CHECK(token(F{0, 87, win::kWaitObject0, 0}) == "notify_failed:win32_87");
    CHECK(token(F{8, 5, win::kWaitObject0, 0}) == "notify_event_failed:win32_8");
}

// ── win::assemble_windows_rows: the collector's decisions, fed injected per-profile reads ─────

namespace {

using yuzu::profiles::HiveAccessStatus;
using yuzu::profiles::ProfileInfo;

constexpr const char* kSidAlice = "S-1-5-21-1-2-3-1001";
constexpr const char* kSidBobby = "S-1-5-21-1-2-3-1002";
constexpr const char* kSidCarol = "S-1-5-21-1-2-3-1003";

ProfileInfo profile_of(std::string name, std::string sid) {
    ProfileInfo p;
    p.sid = std::move(sid);
    p.profile_name = std::move(name);
    p.profile_path = "C:\\Users\\" + p.profile_name;
    return p;
}

/// HKLM as the-rig reads it, except the camera toggle is Deny: the three other capabilities are
/// definitive absences.
win::ConsentWalk hklm_camera_deny() {
    win::ConsentWalk w;
    w.grants.push_back({"-", "camera", PermissionState::denied, "Deny"});
    for (const auto cat : {"microphone", "location", "full_disk_access"})
        w.grants.push_back({"-", cat, PermissionState::absent, "-"});
    return w;
}

/// A reachable profile whose own toggle is Allow on every category.
win::ProfileRead reachable_allow() {
    win::ProfileRead rd;
    rd.status = HiveAccessStatus::ok;
    for (const auto cat : kCategories) rd.walk.grants.push_back({"-", cat, PermissionState::allowed, "Allow"});
    return rd;
}

win::ProfileRead unreachable(HiveAccessStatus st, std::string refusal = {}) {
    win::ProfileRead rd;
    rd.status = st;
    rd.refusal = std::move(refusal);
    return rd;
}

/// One assembled run: the budgets are the test's own, so a test can shrink the output cap or move
/// the deadline, and a fake read can do either mid-run.
struct AssembledRun {
    yuzu::shared::ConstraintAccumulator acc;
    OutputBudget output;
    win::RetentionBudget budget;
    std::vector<PermissionRow> rows;
    std::size_t reads = 0;

    void go(const std::vector<ProfileInfo>& profiles, const win::ConsentWalk& hklm,
            const std::function<win::ProfileRead(const ProfileInfo&)>& read,
            std::vector<PermissionRow> discovery = {}) {
        rows = win::assemble_windows_rows(
            profiles, hklm, std::move(discovery),
            [&](const ProfileInfo& p) {
                ++reads;
                return read(p);
            },
            budget, output, acc);
    }

    [[nodiscard]] std::size_t count(const std::function<bool(const PermissionRow&)>& pred) const {
        return static_cast<std::size_t>(std::count_if(rows.begin(), rows.end(), pred));
    }
    [[nodiscard]] std::size_t markers(std::string_view token) const {
        return count([&](const PermissionRow& r) {
            return r.app_id == "-" && r.category == "-" && r.raw == token;
        });
    }
    /// Run-level stop rows for `base`, whatever their `:profiles_skipped_<n>` count.
    [[nodiscard]] std::size_t stops(std::string_view base) const {
        const std::string prefix = std::string{base} + ":profiles_skipped_";
        return count([&](const PermissionRow& r) {
            return r.app_id == "-" && r.category == "-" && r.raw.rfind(prefix, 0) == 0;
        });
    }
    [[nodiscard]] std::size_t rows_of(std::string_view app_prefix) const {
        return count([&](const PermissionRow& r) { return r.app_id.rfind(app_prefix, 0) == 0; });
    }
};

} // namespace

TEST_CASE("win::assemble_windows_rows: HKLM's overriding Deny is one unqualified row only when no "
          "profile was reachable to carry it",
          "[privacy_permissions][win_parsers]") {
    const auto hklm_row = [](const PermissionRow& r) {
        return format_row(r) == "permissions|windows|-|camera|denied|Deny|-|-";
    };
    AssembledRun run;

    SECTION("every profile unreachable: exactly one unqualified Deny row, plus each profile's failure") {
        run.go({profile_of("alice", kSidAlice), profile_of("bobby", kSidBobby)}, hklm_camera_deny(),
               [](const ProfileInfo& p) {
                   return p.sid == kSidAlice
                              ? unreachable(HiveAccessStatus::file_refused, "hive_path_unc")
                              : unreachable(HiveAccessStatus::mount_failed);
               });
        CHECK(run.count(hklm_row) == 1);
        CHECK(run.count([](const PermissionRow& r) { return r.raw == "alice:hive_path_unc"; }) == 1);
        CHECK(run.count([](const PermissionRow& r) { return r.raw == "bobby:hive_mount_failed"; }) == 1);
        const auto st = select_status(run.acc, any_denied(run.rows), false);
        CHECK(st.status == YUZU_RESULT_STATUS_CONSTRAINED);
    }
    SECTION("one reachable profile carries it: the Deny is that profile's qualified row, never also HKLM's") {
        run.go({profile_of("alice", kSidAlice), profile_of("bobby", kSidBobby)}, hklm_camera_deny(),
               [](const ProfileInfo& p) {
                   return p.sid == kSidAlice ? reachable_allow()
                                             : unreachable(HiveAccessStatus::mount_failed);
               });
        CHECK(run.count(hklm_row) == 0);
        CHECK(run.count([](const PermissionRow& r) {
                  return r.app_id == "alice\\-" && r.category == "camera" &&
                         r.state == PermissionState::denied && r.raw == "Deny";
              }) == 1);
    }
    SECTION("a profile refused as unstable is not reachable: nothing merged, so HKLM keeps the Deny") {
        run.go({profile_of("alice", kSidAlice)}, hklm_camera_deny(), [](const ProfileInfo&) {
            auto rd = reachable_allow();
            rd.walk.refused = std::string{win::kChangedDuringRead};
            return rd;
        });
        CHECK(run.count(hklm_row) == 1);
        CHECK(run.count([](const PermissionRow& r) { return r.raw == "alice:changed_during_read"; }) == 1);
        CHECK(run.rows_of("alice\\-") == 1); // the refusal row alone: no Allow row for the discarded read
    }
    SECTION("a `.bak` ProfileList entry is named, never read, and never `invalid_sid`") {
        const std::string bak = std::string{kSidAlice} + ".bak";
        run.go({profile_of("alice", bak), profile_of("carol", kSidCarol)}, hklm_camera_deny(),
               [](const ProfileInfo&) { return reachable_allow(); });
        CHECK(run.reads == 1); // carol only
        CHECK(run.count([](const PermissionRow& r) {
                  return r.raw == "alice:profile_list_backup";
              }) == 1);
        CHECK(run.count([](const PermissionRow& r) { return r.raw == "alice:invalid_sid"; }) == 0);
        const auto st = select_status(run.acc, any_denied(run.rows), false);
        CHECK(st.status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(st.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    }
    SECTION("a malformed SID is refused before any read is injected, and is not reachable") {
        run.go({profile_of("mallory", "S-1-5-"), profile_of("carol", kSidCarol)}, hklm_camera_deny(),
               [](const ProfileInfo&) { return unreachable(HiveAccessStatus::not_found); });
        CHECK(run.reads == 1); // carol only
        CHECK(run.count([](const PermissionRow& r) { return r.raw == "mallory:invalid_sid"; }) == 1);
        CHECK(run.count(hklm_row) == 1);
    }
}

TEST_CASE("win::assemble_windows_rows: each hive-access outcome is its own row, a refused live "
          "open is a denial, and a failed unload is a token and no row",
          "[privacy_permissions][win_parsers]") {
    AssembledRun run;
    const auto only = [&](win::ProfileRead rd, ProfileInfo p = profile_of("alice", kSidAlice)) {
        run.go({p}, win::ConsentWalk{}, [&](const ProfileInfo&) { return rd; });
    };
    const auto row_raw = [&](std::string_view raw) {
        return run.count([&](const PermissionRow& r) { return r.raw == raw; });
    };

    SECTION("mount_failed is unreadable") {
        only(unreachable(HiveAccessStatus::mount_failed));
        REQUIRE(row_raw("alice:hive_mount_failed") == 1);
        CHECK_FALSE(any_denied(run.rows));
    }
    SECTION("a refused live open turns any failure into access_denied, denied") {
        auto rd = unreachable(HiveAccessStatus::not_found);
        rd.live_open_rc = win::kErrorAccessDenied;
        only(rd);
        REQUIRE(row_raw("alice:access_denied") == 1);
        CHECK(any_denied(run.rows));
    }
    SECTION("a refused live open beneath a hive-file refusal is still the denial") {
        auto rd = unreachable(HiveAccessStatus::file_refused, "hive_reparse_point");
        rd.live_open_rc = win::kErrorAccessDenied;
        only(rd);
        REQUIRE(row_raw("alice:access_denied") == 1);
        CHECK(row_raw("alice:hive_reparse_point") == 0);
        CHECK(any_denied(run.rows));
    }
    SECTION("a missing privilege is a refusal, denied") {
        only(unreachable(HiveAccessStatus::privilege_missing));
        REQUIRE(row_raw("alice:privilege_missing") == 1);
        CHECK(any_denied(run.rows));
    }
    SECTION("not_found names an unreadable ProfileImagePath distinctly") {
        auto p = profile_of("alice", kSidAlice);
        p.profile_path_unreadable = true;
        only(unreachable(HiveAccessStatus::not_found), p);
        CHECK(row_raw("alice:profile_path_unreadable") == 1);
    }
    SECTION("a failed unload after a good read adds a token, never a row") {
        auto rd = reachable_allow();
        rd.unload_failed = true;
        only(rd);
        CHECK(run.acc.reason().find("alice:hive_unload_failed") != std::string::npos);
        CHECK(run.count([](const PermissionRow& r) { return r.raw.find("unload") != std::string::npos; }) == 0);
        CHECK(run.rows_of("alice\\-") == kCategories.size()); // the profile's four rows are all there
    }
}

TEST_CASE("win::assemble_windows_rows: the run-wide output budget reserves HKLM's rows, drops the "
          "profile that would cross the cap, and says so exactly once",
          "[privacy_permissions][win_parsers]") {
    const auto hklm = hklm_camera_deny();
    const auto read = [](const ProfileInfo&) { return reachable_allow(); };
    // The cost of HKLM's reservation (R) and of one profile's rows (c), measured from real runs.
    AssembledRun none;
    none.go({}, hklm, read);
    const std::size_t reserved = none.output.budget.bytes;
    AssembledRun one;
    one.go({profile_of("alice", kSidAlice)}, hklm, read);
    const std::size_t per_profile = one.output.budget.bytes - reserved;
    REQUIRE(reserved > 0);
    REQUIRE(per_profile > 0);
    CHECK(none.stops(kBudgetExceededToken) == 0);
    CHECK(one.stops(kBudgetExceededToken) == 0);

    const std::vector<ProfileInfo> two{profile_of("alice", kSidAlice), profile_of("bobby", kSidBobby)};
    AssembledRun run;

    SECTION("a second profile that would cross the cap is absent; the first and HKLM's rows stay") {
        run.output.budget.max_bytes = reserved + 2 * per_profile - 1;
        run.go(two, hklm, read);
        CHECK(run.markers(win::run_stop_token(kBudgetExceededToken, 1)) == 1);
        CHECK(run.rows_of("alice\\-") == kCategories.size());
        CHECK(run.rows_of("bobby\\") == 0);
        CHECK(run.count([](const PermissionRow& r) { return r.app_id == "-" && r.category == "microphone"; }) == 1);
        const auto st = select_status(run.acc, any_denied(run.rows), false);
        CHECK(st.status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(st.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK(st.provenance.find(std::string{kBudgetExceededToken}) != std::string::npos);
    }
    SECTION("a cap the first profile fills EXACTLY still marks the profiles left unread") {
        run.output.budget.max_bytes = reserved + per_profile;
        run.go(two, hklm, read);
        CHECK(run.output.exhausted());
        CHECK(run.reads == 1); // bobby is never read
        CHECK(run.rows_of("alice\\-") == kCategories.size());
        CHECK(run.rows_of("bobby\\") == 0);
        CHECK(run.markers(win::run_stop_token(kBudgetExceededToken, 1)) == 1);
    }
    SECTION("a `.bak` entry the cap has no room for stops the run and is counted as skipped") {
        run.output.budget.max_bytes = reserved + 1; // HKLM's reservation fits; one more row doesn't
        run.go({profile_of("alice", std::string{kSidAlice} + ".bak"),
                profile_of("carol", kSidCarol)},
               hklm, read);
        CHECK(run.reads == 0);
        CHECK(run.markers(win::run_stop_token(kBudgetExceededToken, 2)) == 1);
    }
    SECTION("a malformed-SID row the cap has no room for stops the run the same way") {
        run.output.budget.max_bytes = reserved + 1;
        run.go({profile_of("mallory", "S-1-5-"), profile_of("carol", kSidCarol)}, hklm, read);
        CHECK(run.reads == 0);
        CHECK(run.markers(win::run_stop_token(kBudgetExceededToken, 2)) == 1);
    }
    SECTION("filling the cap exactly with nothing left to read is complete, not truncated") {
        run.output.budget.max_bytes = reserved + per_profile;
        run.go({profile_of("alice", kSidAlice)}, hklm, read);
        CHECK(run.stops(kBudgetExceededToken) == 0);
        CHECK(run.rows_of("alice\\-") == kCategories.size());
    }
    SECTION("HKLM is charged first: a profile that fits alone is dropped when HKLM's rows leave no room") {
        run.output.budget.max_bytes = per_profile;
        run.go({profile_of("alice", kSidAlice)}, hklm, read);
        CHECK(run.markers(win::run_stop_token(kBudgetExceededToken, 1)) == 1);
        CHECK(run.rows_of("alice\\-") == 0);
        // every HKLM row survived, and its Deny is HKLM's own row since no profile carried it
        CHECK(run.count([](const PermissionRow& r) {
                  return r.app_id == "-" && r.category == "camera" && r.raw == "Deny";
              }) == 1);
        CHECK(run.count([](const PermissionRow& r) { return r.app_id == "-" && r.category != "-"; }) ==
              kCategories.size());
    }
}

TEST_CASE("win::assemble_windows_rows: an expired deadline stops the run with one timeout row and "
          "no later profile is read",
          "[privacy_permissions][win_parsers]") {
    AssembledRun run;
    const std::vector<ProfileInfo> three{profile_of("alice", kSidAlice), profile_of("bobby", kSidBobby),
                                         profile_of("carol", kSidCarol)};

    SECTION("the deadline passing during the first profile ends the run after it") {
        run.go(three, hklm_camera_deny(), [&](const ProfileInfo&) {
            run.budget.deadline = std::chrono::steady_clock::now() - std::chrono::seconds{1};
            return reachable_allow();
        });
        CHECK(run.reads == 1);
        CHECK(run.rows_of("alice\\-") == kCategories.size()); // what was read is kept
        CHECK(run.rows_of("bobby\\") == 0);
        CHECK(run.markers(win::run_stop_token(win::kTimeoutToken, 2)) == 1);
        CHECK(run.stops(kBudgetExceededToken) == 0);
        const auto st = select_status(run.acc, any_denied(run.rows), false);
        CHECK(st.status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(st.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    }
    SECTION("a deadline already past reads no profile at all, and HKLM's rows still stand") {
        run.budget.deadline = std::chrono::steady_clock::now() - std::chrono::seconds{1};
        run.go(three, hklm_camera_deny(), [](const ProfileInfo&) { return reachable_allow(); });
        CHECK(run.reads == 0);
        CHECK(run.markers(win::run_stop_token(win::kTimeoutToken, 3)) == 1);
        CHECK(run.count([](const PermissionRow& r) { return r.app_id == "-" && r.category != "-"; }) ==
              kCategories.size());
    }
    SECTION("a run that finishes in time has no timeout row") {
        run.go(three, hklm_camera_deny(), [](const ProfileInfo&) { return reachable_allow(); });
        CHECK(run.reads == 3);
        CHECK(run.stops(win::kTimeoutToken) == 0);
    }
}

TEST_CASE("win::assemble_windows_rows: the per-source budget marker, source-level failures, "
          "discovery rows and a timeout refusal each have their own row",
          "[privacy_permissions][win_parsers]") {
    AssembledRun run;
    const auto with_raw = [&](std::string_view raw) {
        return run.count([&](const PermissionRow& r) { return r.raw == raw; });
    };
    const auto allow = [](const ProfileInfo&) { return reachable_allow(); };
    const std::vector<ProfileInfo> two{profile_of("alice", kSidAlice), profile_of("bobby", kSidBobby)};

    SECTION("HKLM that hit its own cap is one `hklm:budget_exceeded` row") {
        run.budget.source.refused = true; // as the HKLM walk leaves it when its cap was hit
        run.go({}, win::ConsentWalk{}, allow);
        CHECK(with_raw("hklm:budget_exceeded") == 1);
    }
    SECTION("a profile that hit its own cap is one `<profile>:budget_exceeded` row; the next is untouched") {
        run.go(two, hklm_camera_deny(), [&](const ProfileInfo& p) {
            if (p.sid == kSidAlice) run.budget.source.refused = true; // set after begin_profile()
            return reachable_allow();
        });
        CHECK(with_raw("alice:budget_exceeded") == 1);
        CHECK(with_raw("bobby:budget_exceeded") == 0);
        CHECK(run.rows_of("bobby\\-") == kCategories.size());
    }
    SECTION("an HKLM root that failed to open is a row (a refused one is a denial)") {
        win::ConsentWalk h;
        h.root_rc = win::kErrorAccessDenied;
        run.go({}, h, allow);
        CHECK(with_raw("hklm:access_denied") == 1);
        CHECK(any_denied(run.rows));
    }
    SECTION("an HKLM root that is merely missing is not a failure row") {
        win::ConsentWalk h;
        h.root_rc = win::kErrorFileNotFound;
        run.go({}, h, allow);
        CHECK(with_raw("hklm:win32_2") == 0);
        CHECK_FALSE(any_denied(run.rows));
    }
    SECTION("an HKLM store refused as unstable is one `hklm:<token>` row") {
        win::ConsentWalk h;
        h.refused = std::string{win::kChangedDuringRead};
        run.go({}, h, allow);
        CHECK(with_raw("hklm:changed_during_read") == 1);
    }
    SECTION("a reachable profile's own root failure and structural failure are rows") {
        run.go({profile_of("alice", kSidAlice)}, win::ConsentWalk{}, [](const ProfileInfo&) {
            auto rd = reachable_allow();
            rd.walk.root_rc = 1234;
            rd.walk.structural.push_back(
                win::structural_failure("-", "camera", "capability:win32_9", false));
            return rd;
        });
        CHECK(with_raw("alice:win32_1234") == 1);
        CHECK(run.count([](const PermissionRow& r) {
                  return r.raw.find("capability:win32_9") != std::string::npos && !r.read_denied;
              }) == 1);
    }
    SECTION("discovery rows lead the run and count toward the output budget") {
        AssembledRun bare;
        bare.go({}, hklm_camera_deny(), allow);
        const std::vector<PermissionRow> discovery{
            failure_row("windows", "-", "-", false, "profile_list:win32_5", run.acc)};
        run.go({}, hklm_camera_deny(), allow, discovery);
        REQUIRE_FALSE(run.rows.empty());
        CHECK(run.rows.front().raw == "profile_list:win32_5");
        CHECK(run.output.budget.bytes - bare.output.budget.bytes == OutputBudget::cost(discovery));
    }
    SECTION("a profile refused with `timeout` ends the run: one collection:timeout row, no later read") {
        // The read refuses `timeout` WITHOUT marking the budget (a deadline callback that is a
        // plain clock compare): the assembler itself must mark the run.
        run.go(two, hklm_camera_deny(), [&](const ProfileInfo&) {
            return unreachable(HiveAccessStatus::file_refused, "timeout");
        });
        CHECK(run.reads == 1);
        CHECK(with_raw("alice:timeout") == 1);
        CHECK(run.markers(win::run_stop_token(win::kTimeoutToken, 1)) == 1);
    }
    SECTION("the LAST profile refused with `timeout` still leaves the run-level row") {
        run.go({profile_of("alice", kSidAlice)}, hklm_camera_deny(), [&](const ProfileInfo&) {
            return unreachable(HiveAccessStatus::file_refused, "timeout");
        });
        CHECK(run.reads == 1);
        CHECK(with_raw("alice:timeout") == 1);
        CHECK(run.markers(win::run_stop_token(win::kTimeoutToken, 0)) == 1);
    }
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

TEST_CASE("macos::classify_tcc_missing: a missing per-user db is absent, a missing system db is "
          "unreadable",
          "[privacy_permissions][macos_parsers]") {
    const auto user_missing = macos::classify_tcc_missing(true);
    CHECK(user_missing.outcome == macos::SourceOutcome::absent);
    CHECK(user_missing.cause.empty());
    const auto sys_missing = macos::classify_tcc_missing(false);
    CHECK(sys_missing.outcome == macos::SourceOutcome::unreadable);
    CHECK(sys_missing.cause == "missing");
    // Every other failure of the first open goes through the errno classifier: a refusal is
    // denied, a symlink anywhere in the path (ELOOP) is refused, anything else is unreadable.
    for (const int e : {EPERM, EACCES})
        CHECK(macos::classify_tcc_open_errno(e).outcome == macos::SourceOutcome::denied);
    CHECK(macos::classify_tcc_open_errno(ELOOP).cause == "open_failed:symlink");
    CHECK(macos::classify_tcc_open_errno(EIO).outcome == macos::SourceOutcome::unreadable);
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

TEST_CASE("macos::FileStamp: every field of the file stamp matters",
          "[privacy_permissions][macos_parsers]") {
    const macos::FileStamp base{7, 4096, 1700000000, 500, 12};
    CHECK(base == base);
    const auto changed = [&](auto mutate) {
        auto other = base;
        mutate(other);
        return base != other;
    };
    CHECK(changed([](auto& s) { s.inode += 1; }));
    CHECK(changed([](auto& s) { s.size += 1; }));
    CHECK(changed([](auto& s) { s.mtime_sec += 1; }));
    CHECK(changed([](auto& s) { s.mtime_nsec += 1; }));
    CHECK(changed([](auto& s) { s.change_counter += 1; }));
    // A same-size write that restores mtime and the header counter still moves ctime.
    CHECK(changed([](auto& s) { s.ctime_sec += 1; }));
    CHECK(changed([](auto& s) { s.ctime_nsec += 1; }));
}

TEST_CASE("OutputBudget: counts the formatted row, escapes and separator included, and is "
          "spent at the cap",
          "[privacy_permissions][macos_parsers]") {
    CHECK(kMaxRunOutputBytes == 16u * 1024u * 1024u);
    CHECK(kBudgetExceededToken == "collection:budget_exceeded");
    OutputBudget b;
    b.budget.max_bytes = 10;
    const std::vector<PermissionRow> rows{
        {"macos", "abcd", "camera", PermissionState::allowed, "12", "-", "-", false}};
    b.charge(rows);
    CHECK(b.budget.bytes == format_row(rows[0]).size() + 1);
    CHECK(b.exhausted()); // 45 bytes against a 10-byte cap: every field counts, not two of them
    // Escape expansion is charged: a pipe-dense client costs its escaped length.
    OutputBudget plain, dense;
    const std::vector<PermissionRow> p{{"macos", "aaaa", "camera", PermissionState::allowed, "2",
                                        "-", "-", false}};
    const std::vector<PermissionRow> d{{"macos", "||||", "camera", PermissionState::allowed, "2",
                                        "-", "-", false}};
    plain.charge(p);
    dense.charge(d);
    CHECK(dense.budget.bytes == plain.budget.bytes + 4);
    CHECK_FALSE(OutputBudget{}.exhausted());
}

TEST_CASE("macos::path_under_network_mount: a network mount at or above the path refuses it, on a "
          "segment boundary only",
          "[privacy_permissions][macos_parsers]") {
    const std::vector<macos::MountEntry> mounts{{"/", "apfs"},
                                                {"/Users/alice", "nfs"},
                                                {"/Users/carol", "smbfs"},
                                                {"/Volumes/web", "webdav"},
                                                {"/Users/dave", "apfs"}};
    const auto refused = [&](std::string_view path) {
        return macos::path_under_network_mount(path, mounts);
    };
    CHECK(refused("/Users/alice"));
    CHECK(refused("/Users/alice/Library/Application Support/com.apple.TCC/TCC.db"));
    CHECK(refused("/Users/carol/Library"));
    CHECK(refused("/Volumes/web/x"));
    CHECK_FALSE(refused("/Users/alicia"));   // prefix of the name, not of a segment
    CHECK_FALSE(refused("/Users/al"));
    CHECK_FALSE(refused("/Users/dave/Library")); // a local mount is never a reason
    CHECK_FALSE(refused("/Library/Application Support/com.apple.TCC/TCC.db"));
    CHECK_FALSE(macos::path_under_network_mount("/Users/alice", {}));
    // The shapes the kernel really reports: a mount the system creates on the firmlinked volume
    // (autofs's /home, captured on macOS 26.6.2) carries the /System/Volumes/Data prefix.
    const std::vector<macos::MountEntry> real{{"/", "apfs"},
                                              {"/System/Volumes/Data", "apfs"},
                                              {"/System/Volumes/Data/home", "autofs"},
                                              {"/System/Volumes/Data/Users/carol", "smbfs"}};
    CHECK(macos::path_under_network_mount("/home/dave/Library", real));
    CHECK(macos::path_under_network_mount("/Users/carol/Library/x", real));
    CHECK(macos::path_under_network_mount("/System/Volumes/Data/home/dave", real));
    CHECK_FALSE(macos::path_under_network_mount("/Users/carolyn/Library", real));
    CHECK_FALSE(macos::path_under_network_mount("/Users/alex/Library", real));
    CHECK_FALSE(macos::path_under_network_mount("/homework", real));
    // A network root covers every path.
    CHECK(macos::path_under_network_mount("/Users/x", std::vector<macos::MountEntry>{{"/", "nfs"}}));
    CHECK(macos::is_network_mount_fstype("nfs"));
    CHECK(macos::is_network_mount_fstype("smbfs"));
    CHECK(macos::is_network_mount_fstype("webdav"));
    CHECK(macos::is_network_mount_fstype("afpfs"));
    CHECK(macos::is_network_mount_fstype("macfuse"));
    CHECK(macos::is_network_mount_fstype("osxfuse"));
    CHECK_FALSE(macos::is_network_mount_fstype("apfs"));
    CHECK_FALSE(macos::is_network_mount_fstype("devfs"));
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
        "bob", {macos::SourceOutcome::denied, "open_failed:errno_1"}, acc);
    CHECK(denied.state == PermissionState::denied);
    CHECK(denied.read_denied);
    CHECK(denied.raw == "bob:tcc_db:open_failed:errno_1");

    const auto sys = macos::tcc_source_failed_row(
        {}, {macos::SourceOutcome::unreadable, "open_failed:disk I/O error"}, acc);
    CHECK(sys.app_id == "-");
    CHECK(sys.state == PermissionState::unreadable);
    CHECK(sys.raw == "tcc_db:open_failed:disk I/O error");
}

TEST_CASE("macos::token_safe and tcc_source_key: a name in a provenance token carries no delimiter "
          "or control character",
          "[privacy_permissions][macos_parsers]") {
    CHECK(macos::token_safe("alice") == "alice");
    CHECK(macos::token_safe("a,b|c\\d\ne\x7f") == "a/b/c/d e ");
    CHECK(macos::tcc_source_key({}) == "tcc_db");
    CHECK(macos::tcc_source_key("bob") == "bob:tcc_db");
    // A home named to forge a second token cannot: the comma is folded.
    CHECK(macos::tcc_source_key("x,evil:tcc_db:open_failed:errno_1") == "x/evil:tcc_db:open_failed:errno_1:tcc_db");
}

TEST_CASE("macos::sort_grants: client order, ties broken by auth_value (NULL first), so the wire "
          "order is a total order",
          "[privacy_permissions][macos_parsers]") {
    std::vector<macos::TccGrant> g{{"b", 2}, {"a", 3}, {"a", std::nullopt}, {"a", 0}};
    macos::sort_grants(g);
    REQUIRE(g.size() == 4);
    CHECK(g[0].client == "a");
    CHECK_FALSE(g[0].auth_value.has_value());
    CHECK(g[1].auth_value == 0);
    CHECK(g[2].auth_value == 3);
    CHECK(g[3].client == "b");
}

TEST_CASE("OutputBudget::charge allocates (format_row), so it must not be noexcept",
          "[privacy_permissions][macos_parsers]") {
    OutputBudget b;
    static_assert(!noexcept(b.charge(std::span<const PermissionRow>{})));
    CHECK(b.budget.bytes == 0);
}
