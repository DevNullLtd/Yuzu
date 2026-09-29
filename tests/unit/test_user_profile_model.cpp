/**
 * test_user_profile_model.cpp — pure user-profile / registry-hive discovery
 * model (user_profile_model.hpp, PR1.7).
 *
 * The Reg*W calls (ProfileList enumeration, HKEY_USERS subkey listing,
 * RegLoadKeyW mounting) are the impure Win32 shell; the SID classification,
 * name derivation, hive-state classification, and wire-row rendering below
 * are header-pure and pinned here on every host (the firewall_parsers.hpp /
 * tar_module_etw.hpp pattern). All SIDs in fixtures are synthetic, matching
 * the convention in test_tar_netconn.cpp.
 */

#include "user_profile_model.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

using namespace yuzu::profiles;

namespace {
constexpr std::string_view kAliceSid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
constexpr std::string_view kBobSid = "S-1-5-21-1111111111-2222222222-3333333333-1002";
} // namespace

// ── is_system_sid ────────────────────────────────────────────────────────

TEST_CASE("is_system_sid: the three well-known local-system SIDs", "[profiles]") {
    CHECK(is_system_sid("S-1-5-18"));
    CHECK(is_system_sid("S-1-5-19"));
    CHECK(is_system_sid("S-1-5-20"));
}

TEST_CASE("is_system_sid: a real user SID is not a system SID", "[profiles]") {
    CHECK_FALSE(is_system_sid(kAliceSid));
    CHECK_FALSE(is_system_sid(""));
    CHECK_FALSE(is_system_sid("S-1-5-80-1234"));
}

// ── iequals_ascii ─────────────────────────────────────────────────────────

TEST_CASE("iequals_ascii: identical strings match", "[profiles]") {
    CHECK(iequals_ascii("alice", "alice"));
}

TEST_CASE("iequals_ascii: differing case matches (ordinal, not locale)", "[profiles]") {
    CHECK(iequals_ascii("Alice", "alice"));
    CHECK(iequals_ascii("ALICE", "alice"));
    CHECK(iequals_ascii("aLiCe", "AlIcE"));
}

TEST_CASE("iequals_ascii: different length never matches", "[profiles]") {
    CHECK_FALSE(iequals_ascii("alice", "alices"));
    CHECK_FALSE(iequals_ascii("alice", ""));
}

TEST_CASE("iequals_ascii: different content does not match", "[profiles]") {
    CHECK_FALSE(iequals_ascii("alice", "bob!!"));
}

TEST_CASE("iequals_ascii: two empty strings match", "[profiles]") {
    CHECK(iequals_ascii("", ""));
}

// ── profile_name_from_path ───────────────────────────────────────────────

TEST_CASE("profile_name_from_path: ordinary Windows path", "[profiles]") {
    CHECK(profile_name_from_path("C:\\Users\\alice") == "alice");
}

TEST_CASE("profile_name_from_path: trailing separator is stripped first", "[profiles]") {
    CHECK(profile_name_from_path("C:\\Users\\alice\\") == "alice");
}

TEST_CASE("profile_name_from_path: forward slashes", "[profiles]") {
    CHECK(profile_name_from_path("C:/Users/alice") == "alice");
}

TEST_CASE("profile_name_from_path: UNC-shaped path", "[profiles]") {
    CHECK(profile_name_from_path("\\\\server\\profiles$\\alice") == "alice");
}

TEST_CASE("profile_name_from_path: empty path resolves to empty, never a fallback", "[profiles]") {
    CHECK(profile_name_from_path("").empty());
}

TEST_CASE("profile_name_from_path: separators-only path resolves to empty", "[profiles]") {
    CHECK(profile_name_from_path("\\\\\\").empty());
    CHECK(profile_name_from_path("/").empty());
}

TEST_CASE("profile_name_from_path: no separator treats the whole value as the name", "[profiles]") {
    CHECK(profile_name_from_path("alice") == "alice");
}

// ── classify_hive_state ──────────────────────────────────────────────────

TEST_CASE("classify_hive_state: SID present in HKEY_USERS is loaded", "[profiles]") {
    std::vector<std::string> subkeys{std::string{kAliceSid}, std::string{kAliceSid} + "_Classes"};
    CHECK(classify_hive_state(kAliceSid, subkeys) == HiveState::loaded);
}

TEST_CASE("classify_hive_state: only the _Classes subkey is present", "[profiles]") {
    std::vector<std::string> subkeys{std::string{kAliceSid} + "_Classes"};
    CHECK(classify_hive_state(kAliceSid, subkeys) == HiveState::loaded_classes_only);
}

TEST_CASE("classify_hive_state: neither present", "[profiles]") {
    std::vector<std::string> subkeys{std::string{kBobSid}};
    CHECK(classify_hive_state(kAliceSid, subkeys) == HiveState::not_loaded);
}

TEST_CASE("classify_hive_state: empty HKEY_USERS snapshot", "[profiles]") {
    std::vector<std::string> subkeys{};
    CHECK(classify_hive_state(kAliceSid, subkeys) == HiveState::not_loaded);
}

TEST_CASE("classify_hive_state: the real hive outranks a _Classes-only sighting", "[profiles]") {
    std::vector<std::string> subkeys{std::string{kAliceSid} + "_Classes", std::string{kAliceSid}};
    CHECK(classify_hive_state(kAliceSid, subkeys) == HiveState::loaded);
}

// ── build_profile_list ───────────────────────────────────────────────────

TEST_CASE("build_profile_list: system SIDs are filtered out", "[profiles]") {
    std::vector<RawProfileRecord> records{
        {"S-1-5-18", "C:\\Windows\\system32\\config\\systemprofile"},
        {"S-1-5-19", "C:\\Windows\\ServiceProfiles\\LocalService"},
        {"S-1-5-20", "C:\\Windows\\ServiceProfiles\\NetworkService"},
        {std::string{kAliceSid}, "C:\\Users\\alice"},
    };
    std::vector<std::string> hku{};
    auto profiles = build_profile_list(records, hku);
    REQUIRE(profiles.size() == 1);
    CHECK(profiles[0].sid == kAliceSid);
    CHECK(profiles[0].profile_name == "alice");
}

TEST_CASE("build_profile_list: duplicate SIDs keep only the first occurrence", "[profiles]") {
    std::vector<RawProfileRecord> records{
        {std::string{kAliceSid}, "C:\\Users\\alice"},
        {std::string{kAliceSid}, "C:\\Users\\alice-stale-duplicate"},
    };
    std::vector<std::string> hku{};
    auto profiles = build_profile_list(records, hku);
    REQUIRE(profiles.size() == 1);
    CHECK(profiles[0].profile_path == "C:\\Users\\alice");
}

TEST_CASE("build_profile_list: empty input yields an empty list", "[profiles]") {
    std::vector<RawProfileRecord> records{};
    std::vector<std::string> hku{};
    CHECK(build_profile_list(records, hku).empty());
}

TEST_CASE("build_profile_list: unreadable ProfileImagePath yields an empty name, not a crash",
          "[profiles]") {
    std::vector<RawProfileRecord> records{{std::string{kAliceSid}, ""}};
    std::vector<std::string> hku{};
    auto profiles = build_profile_list(records, hku);
    REQUIRE(profiles.size() == 1);
    CHECK(profiles[0].profile_name.empty());
    CHECK(profiles[0].sid == kAliceSid); // never falls back to the sid (ADR-0024 D11)
}

TEST_CASE("build_profile_list: hive state carries through from the HKU snapshot", "[profiles]") {
    std::vector<RawProfileRecord> records{
        {std::string{kAliceSid}, "C:\\Users\\alice"},
        {std::string{kBobSid}, "C:\\Users\\bob"},
    };
    std::vector<std::string> hku{std::string{kAliceSid}};
    auto profiles = build_profile_list(records, hku);
    REQUIRE(profiles.size() == 2);
    CHECK(profiles[0].state == HiveState::loaded);
    CHECK(profiles[1].state == HiveState::not_loaded);
}

// ── find_sid_by_username ──────────────────────────────────────────────────

TEST_CASE("find_sid_by_username: exact match", "[profiles]") {
    std::vector<ProfileInfo> profiles{
        {std::string{kAliceSid}, "alice", "C:\\Users\\alice", HiveState::loaded},
        {std::string{kBobSid}, "bob", "C:\\Users\\bob", HiveState::not_loaded},
    };
    auto sid = find_sid_by_username(profiles, "bob");
    REQUIRE(sid.has_value());
    CHECK(*sid == kBobSid);
}

TEST_CASE("find_sid_by_username: case-insensitive match (Windows profile folder semantics)",
          "[profiles]") {
    // Regression pin: the pre-PR1.7 code built the NTUSER.DAT path directly
    // against a case-insensitive filesystem, so case never mattered for the
    // case it could reach. A case-sensitive comparison here would regress
    // that behaviour for no benefit.
    std::vector<ProfileInfo> profiles{
        {std::string{kAliceSid}, "alice", "C:\\Users\\alice", HiveState::loaded},
    };
    auto sid = find_sid_by_username(profiles, "Alice");
    REQUIRE(sid.has_value());
    CHECK(*sid == kAliceSid);
}

TEST_CASE("find_sid_by_username: no match", "[profiles]") {
    std::vector<ProfileInfo> profiles{
        {std::string{kAliceSid}, "alice", "C:\\Users\\alice", HiveState::loaded},
    };
    CHECK_FALSE(find_sid_by_username(profiles, "carol").has_value());
}

TEST_CASE("find_sid_by_username: empty username never matches", "[profiles]") {
    std::vector<ProfileInfo> profiles{
        {std::string{kAliceSid}, "alice", "C:\\Users\\alice", HiveState::loaded},
    };
    CHECK_FALSE(find_sid_by_username(profiles, "").has_value());
}

TEST_CASE("find_sid_by_username: an unresolved profile name never matches an empty lookup",
          "[profiles]") {
    std::vector<ProfileInfo> profiles{
        {std::string{kAliceSid}, "", "", HiveState::not_loaded},
    };
    CHECK_FALSE(find_sid_by_username(profiles, "").has_value());
}

TEST_CASE("find_sid_by_username: first match wins on a name collision", "[profiles]") {
    std::vector<ProfileInfo> profiles{
        {std::string{kAliceSid}, "shared", "C:\\Users\\alice", HiveState::loaded},
        {std::string{kBobSid}, "shared", "C:\\Users\\bob", HiveState::not_loaded},
    };
    auto sid = find_sid_by_username(profiles, "shared");
    REQUIRE(sid.has_value());
    CHECK(*sid == kAliceSid);
}

// ── sanitize_field / render_profile_row ──────────────────────────────────

TEST_CASE("sanitize_field: strips pipe, CR, LF", "[profiles]") {
    CHECK(sanitize_field("a|b\r\nc") == "a_b__c");
}

TEST_CASE("sanitize_field: ordinary text passes through unchanged", "[profiles]") {
    CHECK(sanitize_field("alice") == "alice");
}

TEST_CASE("render_profile_row: ordinary profile", "[profiles]") {
    ProfileInfo info{std::string{kAliceSid}, "alice", "C:\\Users\\alice", HiveState::loaded};
    CHECK(render_profile_row(info) == std::string{kAliceSid} + "|alice|C:\\Users\\alice|loaded");
}

TEST_CASE("render_profile_row: empty fields render as '-'", "[profiles]") {
    ProfileInfo info{std::string{kAliceSid}, "", "", HiveState::not_loaded};
    CHECK(render_profile_row(info) == std::string{kAliceSid} + "|-|-|not_loaded");
}

TEST_CASE("render_profile_row: a value containing '|' cannot forge a column", "[profiles]") {
    // Regression pin: registry_plugin.cpp's original sanitize_field only
    // covered the unknown-action error string, so a profile name/path
    // containing '|' could inject a synthetic column into the pipe-delimited
    // output. Every field this renderer emits must be sanitised.
    ProfileInfo info{std::string{kAliceSid}, "ali|ce", "C:\\Users\\a|b", HiveState::loaded};
    auto row = render_profile_row(info);
    CHECK(row.find("ali|ce") == std::string::npos);
    CHECK(row == std::string{kAliceSid} + "|ali_ce|C:\\Users\\a_b|loaded");
}

TEST_CASE("render_profile_row: exhaustive over every HiveState", "[profiles]") {
    CHECK(hive_state_name(HiveState::loaded) == "loaded");
    CHECK(hive_state_name(HiveState::loaded_classes_only) == "loaded_classes_only");
    CHECK(hive_state_name(HiveState::not_loaded) == "not_loaded");
}

// ── #2771: hive-access + user-key output rendering ─────────────────────────
//
// qa-S2 waived a positive test for the unload-failure control flow because it
// was inlined in Win32-dependent code. The renderers below ARE that control
// flow, extracted, so these run on every host. Assertions are exact
// whole-string equality plus an explicit line count: the hp-B1 column-shift
// defect survived a review precisely because the tests used substring
// containment, which cannot see a field landing in the wrong place.

TEST_CASE("render_hive_access_lines: clean success emits nothing", "[profiles]") {
    const auto lines = render_hive_access_lines(HiveAccessStatus::ok, false, "", kAliceSid);
    CHECK(lines.empty());
}

TEST_CASE("render_hive_access_lines: each failure emits exactly one error line", "[profiles]") {
    const std::string sid{kAliceSid};

    auto nf = render_hive_access_lines(HiveAccessStatus::not_found, false, "", kAliceSid);
    REQUIRE(nf.size() == 1);
    CHECK(nf[0] == "error|no reachable hive for sid '" + sid +
                       "' (not logged in and no profile path)");

    auto pm = render_hive_access_lines(HiveAccessStatus::privilege_missing, false, "", kAliceSid);
    REQUIRE(pm.size() == 1);
    CHECK(pm[0] ==
          "error|privilege_missing: SeBackupPrivilege/SeRestorePrivilege could not be enabled");

    auto mf = render_hive_access_lines(HiveAccessStatus::mount_failed, false, "M", kAliceSid);
    REQUIRE(mf.size() == 1);
    CHECK(mf[0] == "error|failed to load hive for sid '" + sid + "'");
}

TEST_CASE("render_hive_access_lines: the unload warning names the ACTUAL mount", "[profiles]") {
    // The mount name is salted per call (up-S1), so reconstructing
    // "YUZU_HIVE_<sid>" would print a name that was never mounted and a
    // remediation command that does nothing.
    const auto lines =
        render_hive_access_lines(HiveAccessStatus::ok, true, "YUZU_HIVE_S-1-5-21-9_beef_7",
                                 kAliceSid);
    REQUIRE(lines.size() == 1);
    CHECK(lines[0] ==
          "warning|hive_unload_failed: HKU\\YUZU_HIVE_S-1-5-21-9_beef_7 for sid '" +
              std::string{kAliceSid} +
              "' may remain mounted; retry `reg unload HKU\\YUZU_HIVE_S-1-5-21-9_beef_7` once any "
              "process holding the branch (Search Indexer, AV, System Restore) releases it");
}

TEST_CASE("render_hive_access_lines: warning precedes the error on a failed mount", "[profiles]") {
    // unload_failed can be true even on mount_failed — RegLoadKeyW can succeed
    // while the subsequent root re-open fails — so a status-first switch that
    // returned early would drop the warning entirely. Order is part of the
    // contract, not incidental.
    const auto lines =
        render_hive_access_lines(HiveAccessStatus::mount_failed, true, "MNT", kAliceSid);
    REQUIRE(lines.size() == 2);
    CHECK(lines[0].starts_with("warning|hive_unload_failed: HKU\\MNT "));
    CHECK(lines[1] == "error|failed to load hive for sid '" + std::string{kAliceSid} + "'");
}

TEST_CASE("render_hive_access_lines: all 8 status x unload combinations, exact strings",
         "[profiles]") {
    // Exhaustive so a future enumerator cannot be added without a decision
    // about what it prints. code-review Spec F4: the plan called for exact
    // whole-string equality on all 8 combinations, not just line count plus
    // a prefix check -- this asserts the full expected vector per case.
    const std::string sid{kAliceSid};
    const std::string warning =
        "warning|hive_unload_failed: HKU\\M for sid '" + sid +
        "' may remain mounted; retry `reg unload HKU\\M` once any process holding the branch "
        "(Search Indexer, AV, System Restore) releases it";
    const std::string not_found_err =
        "error|no reachable hive for sid '" + sid + "' (not logged in and no profile path)";
    const std::string privilege_missing_err =
        "error|privilege_missing: SeBackupPrivilege/SeRestorePrivilege could not be enabled";
    const std::string mount_failed_err = "error|failed to load hive for sid '" + sid + "'";

    struct Case {
        HiveAccessStatus status;
        bool unload_failed;
        std::vector<std::string> expected;
    };
    const Case cases[] = {
        {HiveAccessStatus::ok, false, {}},
        {HiveAccessStatus::ok, true, {warning}},
        {HiveAccessStatus::not_found, false, {not_found_err}},
        {HiveAccessStatus::not_found, true, {warning, not_found_err}},
        {HiveAccessStatus::privilege_missing, false, {privilege_missing_err}},
        {HiveAccessStatus::privilege_missing, true, {warning, privilege_missing_err}},
        {HiveAccessStatus::mount_failed, false, {mount_failed_err}},
        {HiveAccessStatus::mount_failed, true, {warning, mount_failed_err}},
    };
    for (const auto& c : cases) {
        const auto lines = render_hive_access_lines(c.status, c.unload_failed, "M", kAliceSid);
        CHECK(lines == c.expected);
    }
}

TEST_CASE("render_hive_access_lines: a hostile sid cannot forge a column", "[profiles]") {
    const auto lines = render_hive_access_lines(HiveAccessStatus::not_found, false, "", "S-1|evil");
    REQUIRE(lines.size() == 1);
    CHECK(lines[0].find("S-1|evil") == std::string::npos);
    CHECK(lines[0] == "error|no reachable hive for sid 'S-1_evil' (not logged in and no profile "
                      "path)");
}

TEST_CASE("render_user_key_error: every status, exact strings", "[profiles]") {
    CHECK(render_user_key_error(UserKeyStatus::ok, "K").empty());
    // up-S4: an ACL'd key is now distinguishable from an absent one.
    CHECK(render_user_key_error(UserKeyStatus::key_access_denied, "Software\\X") ==
          "error|access denied opening key 'Software\\X' in user hive");
    CHECK(render_user_key_error(UserKeyStatus::value_oversized, "K") ==
          "error|value exceeds 1 MiB limit");
    CHECK(render_user_key_error(UserKeyStatus::value_malformed, "K") ==
          "error|value size too small for its declared type");
    // Key-absent and value-absent stay deliberately identical: up-S4 asks only
    // that INFRASTRUCTURE errors be separated from absence.
    CHECK(render_user_key_error(UserKeyStatus::key_not_found, "K") ==
          "error|key or value not found in user hive");
    CHECK(render_user_key_error(UserKeyStatus::value_not_found, "K") ==
          "error|key or value not found in user hive");
}

TEST_CASE("render_user_key_error: a hostile key name cannot forge a column", "[profiles]") {
    CHECK(render_user_key_error(UserKeyStatus::key_access_denied, "a|b") ==
          "error|access denied opening key 'a_b' in user hive");
}

// ── #2771 up-S3: registry value decoding primitives ────────────────────────

TEST_CASE("reg_type_name: every named type, including the three up-S3 added", "[profiles]") {
    CHECK(reg_type_name(kRegNone) == "REG_NONE");
    CHECK(reg_type_name(kRegSz) == "REG_SZ");
    CHECK(reg_type_name(kRegExpandSz) == "REG_EXPAND_SZ");
    CHECK(reg_type_name(kRegBinary) == "REG_BINARY");
    CHECK(reg_type_name(kRegDword) == "REG_DWORD");
    CHECK(reg_type_name(kRegDwordBigEndian) == "REG_DWORD_BIG_ENDIAN");
    CHECK(reg_type_name(kRegLink) == "REG_LINK");
    CHECK(reg_type_name(kRegMultiSz) == "REG_MULTI_SZ");
    CHECK(reg_type_name(kRegQword) == "REG_QWORD");
    CHECK(reg_type_name(9999) == "REG_UNKNOWN");
}

TEST_CASE("reg_type_name: the constants match the Windows ABI", "[profiles]") {
    // These are mirrored from winnt.h so the header stays windows.h-free; the
    // values are fixed by the ABI and a typo would silently mislabel values.
    CHECK(kRegNone == 0u);
    CHECK(kRegSz == 1u);
    CHECK(kRegExpandSz == 2u);
    CHECK(kRegBinary == 3u);
    CHECK(kRegDword == 4u);
    CHECK(kRegDwordBigEndian == 5u);
    CHECK(kRegLink == 6u);
    CHECK(kRegMultiSz == 7u);
    CHECK(kRegQword == 11u);
}

namespace {
/// Renders multi_sz_records' output as "a|b|c" for compact assertions.
std::string join_records(std::span<const char16_t> data) {
    std::string out;
    bool first = true;
    for (const auto& [off, len] : multi_sz_records(data)) {
        if (!first)
            out += '|';
        first = false;
        for (std::size_t i = 0; i < len; ++i)
            out += static_cast<char>(data[off + i]);
    }
    return out;
}
} // namespace

TEST_CASE("multi_sz_records: well-formed list", "[profiles]") {
    const char16_t data[] = {u'a', u'b', 0, u'c', 0, 0};
    CHECK(join_records(std::span<const char16_t>(data, 6)) == "ab|c");
}

TEST_CASE("multi_sz_records: empty payload yields no records", "[profiles]") {
    CHECK(multi_sz_records(std::span<const char16_t>()).empty());
}

TEST_CASE("multi_sz_records: a lone terminator yields no records", "[profiles]") {
    const char16_t data[] = {0};
    CHECK(multi_sz_records(std::span<const char16_t>(data, 1)).empty());
}

TEST_CASE("multi_sz_records: single record", "[profiles]") {
    const char16_t data[] = {u'x', 0, 0};
    CHECK(join_records(std::span<const char16_t>(data, 3)) == "x");
}

TEST_CASE("multi_sz_records: an unterminated final record is kept, not dropped", "[profiles]") {
    // Malformed but observed. Reporting the last entry is more honest than
    // silently losing it.
    const char16_t data[] = {u'a', 0, u'b'};
    CHECK(join_records(std::span<const char16_t>(data, 3)) == "a|b");
}

TEST_CASE("multi_sz_records: an embedded empty record terminates the list", "[profiles]") {
    // Per the REG_MULTI_SZ contract the first empty record closes the list —
    // trailing bytes after it are padding, not data.
    const char16_t data[] = {u'a', 0, 0, u'b', 0, 0};
    CHECK(join_records(std::span<const char16_t>(data, 6)) == "a");
}

TEST_CASE("hex_encode: empty, low and high-bit bytes", "[profiles]") {
    CHECK(hex_encode(std::span<const std::uint8_t>()).empty());
    const std::uint8_t one[] = {0x00};
    CHECK(hex_encode(one) == "00");
    const std::uint8_t two[] = {0x0f, 0xa0};
    CHECK(hex_encode(two) == "0fa0");
    const std::uint8_t high[] = {0xff};
    CHECK(hex_encode(high) == "ff");
}

// ── #2771 code-review C-M3 / P2-N3: the honest-truncation decision ─────────
//
// The REAL regression: `out.size() >= kMaxProfiles` alone conflated "the cap
// was reached" with "a record was dropped" -- a host with EXACTLY
// kMaxProfiles subkeys got a false truncation warning that license_scan then
// escalated into a false ok=false surface failure. The FIX's own first-round
// regression test (in the Windows-gated test_registry_local_dispatcher.cpp)
// cannot actually discriminate this: it calls enumerate_profile_records on
// whatever real host it runs on, which has far fewer than 512 profiles, so
// BOTH the pre-fix and post-fix implementations report truncated=false there
// -- passing proves nothing about the boundary case a unit test cannot
// fabricate 512 real registry subkeys to exercise. Testing the DECISION
// (extracted pure specifically so this is possible) is what actually pins
// the fix.

TEST_CASE("profile_list_actually_truncated: the exact C-M3 boundary case",
         "[profiles]") {
    // Cap reached, but the probe finds nothing further -- exactly 512
    // subkeys, nothing lost. This is the case the buggy `out.size() >=
    // kMaxProfiles` check got wrong (it would have said "truncated" here).
    CHECK_FALSE(profile_list_actually_truncated(/*cap_reached=*/true,
                                                /*probe_found_more=*/false));
}

TEST_CASE("profile_list_actually_truncated: a genuine drop", "[profiles]") {
    // Cap reached AND the probe confirms a 513th subkey exists -- something
    // really was dropped.
    CHECK(profile_list_actually_truncated(/*cap_reached=*/true, /*probe_found_more=*/true));
}

TEST_CASE("profile_list_actually_truncated: cap never reached", "[profiles]") {
    // The ordinary case on every real dev/CI host. probe_found_more is
    // irrelevant (the shell never probes when the cap wasn't hit) but the
    // function must still be safe to call with either value.
    CHECK_FALSE(profile_list_actually_truncated(false, false));
    CHECK_FALSE(profile_list_actually_truncated(false, true));
}

// ── #2771 up-S2: the unreadable-path signal ────────────────────────────────

TEST_CASE("build_profile_list: carries profile_path_unreadable through", "[profiles]") {
    // Before up-S2 an over-long ProfileImagePath left the path empty, which was
    // indistinguishable from the value being absent. The flag is what makes
    // list_profiles able to say which happened.
    RawProfileRecord absent{std::string{kAliceSid}, "", false};
    RawProfileRecord unreadable{std::string{kBobSid}, "", true};
    const RawProfileRecord recs[] = {absent, unreadable};
    const auto list = build_profile_list(recs, {});
    REQUIRE(list.size() == 2);
    CHECK_FALSE(list[0].profile_path_unreadable);
    CHECK(list[1].profile_path_unreadable);
    // Neither may invent a name from the SID (ADR-0024 D11).
    CHECK(list[0].profile_name.empty());
    CHECK(list[1].profile_name.empty());
}

// ── Column-alignment guard (the hp-B1 lesson) ──────────────────────────────

namespace {
/// Splits on every unescaped '|', mirroring result_parsing.hpp's generic
/// split_fields path — the one registry rows actually take.
std::vector<std::string> split_all_pipes(const std::string& s) {
    std::vector<std::string> out;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == '|') {
            out.push_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    return out;
}
} // namespace

TEST_CASE("render_profile_row: field COUNT and INDEX, not containment", "[profiles]") {
    // hp-B1 was a leading discriminator tag that shifted every column one
    // position right of its header. Substring-containment assertions passed
    // throughout. Assert position.
    ProfileInfo info{std::string{kAliceSid}, "alice", "C:\\Users\\alice", HiveState::loaded};
    const auto fields = split_all_pipes(render_profile_row(info));
    REQUIRE(fields.size() == 4);
    CHECK(fields[0] == std::string{kAliceSid});
    CHECK(fields[1] == "alice");
    CHECK(fields[2] == "C:\\Users\\alice");
    CHECK(fields[3] == "loaded");
}

TEST_CASE("render_profile_row: a pipe in a field cannot add a column", "[profiles]") {
    ProfileInfo info{std::string{kAliceSid}, "a|b", "c|d", HiveState::loaded};
    CHECK(split_all_pipes(render_profile_row(info)).size() == 4);
}

TEST_CASE("installed_apps user_app row: the kKeyValuePlugins contract", "[profiles]") {
    // NOT a pin on installed_apps_plugin.cpp's do_list_per_user -- that
    // formatting call (std::format("user_app|{}|...", ...)) lives inside an
    // #ifdef _WIN32 block in a plugin .cpp this portable test cannot link
    // against or execute, so nothing here would fail if that call site
    // changed. This documents and guards the CONTRACT instead: installed_apps
    // is in result_parsing.hpp's kKeyValuePlugins, so the dashboard's generic
    // splitter treats every row as (key, rest) — the opposite of the registry
    // list_profiles case, where a leading tag caused the hp-B1 column shift.
    // A leading "user_app|" tag is therefore LOAD-BEARING here and must never
    // be stripped by analogy with that fix. Real coverage of the plugin's own
    // output is a Windows-only gap tracked for a follow-up (code-review
    // Functional axis, [F5]/[CFX-5]).
    const std::string row = "user_app|alice|Widget|1.0|Acme|20240101";
    const auto fields = split_all_pipes(row);
    REQUIRE(fields.size() == 6);
    CHECK(fields[0] == "user_app");
    CHECK(fields[1] == "alice");
    // An unresolvable profile name renders "-", never the SID (ADR-0024 D11)
    // and never "" (indistinguishable from a rendering fault).
    const auto anon = split_all_pipes("user_app|-|Widget|1.0|Acme|20240101");
    REQUIRE(anon.size() == 6);
    CHECK(anon[1] == "-");
}
