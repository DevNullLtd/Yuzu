/**
 * test_platform_security_win_parsers.cpp -- pure tests for platform_security_win_parsers.hpp; no
 * platform guard, no OS call. Inputs: fixtures/wave8/platform_security/windows/<name>.reg (UTF-16LE
 * `reg export`; REQUIRE(exists), never skipped): secureboot_state.reg and deviceguard_real.reg are
 * REAL CAPTURE; ci_policy.reg's four values are REAL (a `reg query` capture) but its `reg export`
 * serialisation is RECONSTRUCTION; deviceguard.reg is a full RECONSTRUCTION (see each
 * .provenance.txt for exact status). Inline RECONSTRUCTION strings cover malformed input and
 * Win32 failures. Expected rows are pinned as literals.
 */
#include "platform_security_win_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

using namespace yuzu::platform_security::win;
namespace fs = std::filesystem;

namespace {

std::string fixture_text(const std::string& name) {
    const fs::path p = fs::path{YUZU_TEST_FIXTURE_DIR} / "wave8" / "platform_security" / "windows" / name;
    REQUIRE(fs::exists(p));
    std::ifstream f(p, std::ios::binary);
    const std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(f), {}};
    auto text = decode_utf16le_bom(bytes);
    REQUIRE(text.has_value());
    return *text;
}

RegExport load(const std::string& name) {
    auto e = parse_reg_export(fixture_text(name));
    REQUIRE(e.has_value());
    return *e;
}

KeyRead read_of(const RegExport& e, const KeySpec& spec) {
    return key_read_from_export(find_key(e, spec.path), &spec);
}

std::vector<std::string> lines(const Report& r) {
    std::vector<std::string> out;
    for (const auto& row : r.rows)
        out.push_back(format_row(row));
    return out;
}

using Lines = std::vector<std::string>;

KeyRead absent_key() { return key_read_from_export(nullptr); }

ValueOutcome dword_value(std::string name, std::uint32_t v) {
    ValueOutcome o;
    o.name = std::move(name);
    o.value = {ValueKind::dword, kRegDword, v, {}, 0};
    return o;
}

std::string token_error(std::string_view text) {
    auto r = parse_reg_export(text);
    REQUIRE_FALSE(r.has_value());
    return r.error().token;
}

const std::string kHeader = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\K]\r\n";

} // namespace

TEST_CASE("utf16le decode: BOM required; 1/2/3/4-byte UTF-8; lone surrogate and odd length rejected",
          "[platform_security][win_parsers]") {
    // Fails if the BOM check, the length check or any encoder width is broken.
    CHECK(decode_utf16le_bom(std::vector<std::uint8_t>{0x41, 0x00}).error().token == "no_bom");
    CHECK(decode_utf16le_bom(std::vector<std::uint8_t>{0xFF, 0xFE, 0x41}).error().token == "odd_length");
    CHECK(decode_utf16le_bom(std::vector<std::uint8_t>{0xFF, 0xFE, 0x00, 0xDC}).error().token == "bad_surrogate");
    CHECK(decode_utf16le_bom(std::vector<std::uint8_t>{0xFF, 0xFE, 0x00, 0xD8}).error().token == "bad_surrogate");
    const auto t = decode_utf16le_bom(std::vector<std::uint8_t>{
        0xFF, 0xFE, 0x41, 0x00, 0xE9, 0x00, 0xAC, 0x20, 0x3D, 0xD8, 0x00, 0xDE});
    REQUIRE(t.has_value());
    CHECK(*t == "A\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80"); // A, e-acute, euro, U+1F600
}

TEST_CASE("reg export parser: real CI\\Policy capture", "[platform_security][win_parsers]") {
    const auto e = load("ci_policy.reg");
    REQUIRE(e.size() == 1);
    CHECK(e[0].path == "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy");
    REQUIRE(e[0].values.size() == 4);
    CHECK(e[0].values[2].name == "VerifiedAndReputablePolicyState");
    CHECK(e[0].values[2].value.dword == 0);
    CHECK(e[0].values[3].name == "SAC_PreviousState");
    CHECK(e[0].values[3].value.dword == 4294967295u);
}

TEST_CASE("reg export parser: truncated or malformed input is a token, never a partial parse",
          "[platform_security][win_parsers]") {
    // Each case fails if that branch stops rejecting (the truncated-line cases: cut mid-value).
    const std::string real = fixture_text("ci_policy.reg");
    const auto cut = real.find("dword:ffffffff");
    REQUIRE(cut != std::string::npos);
    CHECK(token_error(real.substr(0, cut + 10)) == "truncated_line"); // dword:ffff
    CHECK(token_error(kHeader + "\"A\"=dword:0000") == "truncated_line");
    CHECK(token_error(kHeader + "\"A\"=\"abc") == "truncated_line");
    CHECK(token_error(kHeader + "\"A\"") == "truncated_line");
    CHECK(token_error(kHeader + "\"A\"=hex:01,02,\\") == "truncated_line"); // ends in a continuation
    CHECK(token_error(kHeader + "\"A\"=hex:01,") == "truncated_line");
    CHECK(token_error("Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\K") == "truncated_line");
    CHECK(token_error("\"A\"=dword:00000001\r\n") == "no_header");
    CHECK(token_error("Windows Registry Editor Version 5.00\r\n\"A\"=dword:00000001\r\n") == "value_before_key");
    CHECK(token_error(kHeader + "\"A\"=dword:zzzzzzzz") == "bad_dword");
    CHECK(token_error(kHeader + "\"A\"=hex:0g") == "bad_hex");
    CHECK(token_error(kHeader + "\"A\"=wat") == "bad_value");
    CHECK(token_error("Windows Registry Editor Version 5.00\r\n\r\n[-HKEY_LOCAL_MACHINE\\K]\r\n") == "bad_key_line");
}

TEST_CASE("reg export parser: strings, hex continuation, default value, comments",
          "[platform_security][win_parsers]") {
    // RECONSTRUCTION of the export grammar.
    const auto r = parse_reg_export(kHeader + "; note\r\n\"S\"=\"a\\\\b\\\"c\"\r\n@=\"d\"\r\n" +
                                    "\"B\"=hex:01,02,\\\r\n  03,04\r\n\"Q\"=hex(b):01,00,00,00,00,00,00,00\r\n");
    REQUIRE(r.has_value());
    const auto& v = (*r)[0].values;
    REQUIRE(v.size() == 4);
    CHECK(v[0].value.text == "a\\b\"c");
    CHECK(v[1].name == "@");
    CHECK(v[2].value.byte_len == 4);
    CHECK(v[2].value.type == 3);
    CHECK(v[3].value.type == 0xb);
}

TEST_CASE("code_integrity over the real CI\\Policy capture", "[platform_security][win_parsers]") {
    // Fails if VerifiedAndReputablePolicyState stops mapping, an enumerated value is dropped, the
    // sort order changes, or an absent DeviceGuard key stops producing rows without a token.
    // `absent_key()` for device_guard/hvci_scenario is a legitimate not-found key (both CAN be
    // absent on a real host, `key_may_be_absent`), producing a token-free `absent` row; the same
    // placeholder for lsa is NOT legitimate (Lsa is foundational, `key_may_be_absent == false`),
    // so it correctly reads `unreadable` + a token and constrains the run.
    const auto e = load("ci_policy.reg");
    const auto rep = build_code_integrity_report(read_of(e, kCiPolicyKey), absent_key(), absent_key(),
                                                 absent_key());
    CHECK(lines(rep) == Lines{
        "code_integrity|windows|ci_policy.EmodePolicyRequired|0|unmodelled",
        "code_integrity|windows|ci_policy.SAC_PreviousState|4294967295|unmodelled",
        "code_integrity|windows|ci_policy.SkuPolicyRequired|0|unmodelled",
        "code_integrity|windows|ci_policy.VerifiedAndReputablePolicyState|0|disabled",
        "code_integrity|windows|deviceguard.EnableVirtualizationBasedSecurity|-|absent",
        "code_integrity|windows|deviceguard.RequirePlatformSecurityFeatures|-|absent",
        "code_integrity|windows|deviceguard.HypervisorEnforcedCodeIntegrity|-|absent",
        "code_integrity|windows|deviceguard.hvci_scenario_enabled|-|absent",
        "code_integrity|windows|lsa.LsaCfgFlags|-|unreadable"});
    CHECK(rep.acc.reason() == "lsa:key_missing");
    CHECK(select_status(rep).status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(select_status(rep).completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
}

TEST_CASE("code_integrity over the DeviceGuard reconstruction", "[platform_security][win_parsers]") {
    // RECONSTRUCTION data; fails if a DeviceGuard mapper or the scenario key wiring breaks. lsa's
    // `absent_key()` placeholder is a not-found KEY, which Lsa can never legitimately be
    // (`key_may_be_absent == false`) -- it correctly reads unreadable and constrains the run.
    const auto e = load("deviceguard.reg");
    const auto rep = build_code_integrity_report(absent_key(), read_of(e, kDeviceGuardKey),
                                                 read_of(e, kHvciScenarioKey), absent_key());
    CHECK(lines(rep) == Lines{
        "code_integrity|windows|ci_policy.VerifiedAndReputablePolicyState|-|absent",
        "code_integrity|windows|deviceguard.EnableVirtualizationBasedSecurity|1|enabled",
        "code_integrity|windows|deviceguard.HypervisorEnforcedCodeIntegrity|1|enabled",
        "code_integrity|windows|deviceguard.RequirePlatformSecurityFeatures|3|enabled",
        "code_integrity|windows|deviceguard.hvci_scenario_enabled|1|enabled",
        "code_integrity|windows|lsa.LsaCfgFlags|-|unreadable"});
    CHECK(select_status(rep).status == YUZU_RESULT_STATUS_CONSTRAINED);
}

TEST_CASE("code_integrity over the-rig's REAL CAPTURE: the configured VBS/HVCI/LSA values are absent",
          "[platform_security][win_parsers]") {
    // REAL CAPTURE (ci_policy.reg + deviceguard_real.reg): a default host that does not configure
    // VBS/HVCI has none of the configured DeviceGuard values and no HypervisorEnforcedCodeIntegrity
    // scenario key -- each is a definitive `absent` row. Lsa is modelled inline (no .reg export of
    // it exists; the win.cpp banner's real probe was `reg query`, verbatim): the KEY was opened and
    // held LsaCfgFlagsDefault 0x0 -- only the specific LsaCfgFlags VALUE was absent, a per-value
    // absence untouched by the key-level `key_may_be_absent` gate, so it still reads `absent`, no
    // token. Fails if any absent reads as a failure, a value from the KeyGuard/CredentialGuard
    // scenarios leaks into a row, or the Lsa key-open itself is mistaken for not-found.
    const auto ci = load("ci_policy.reg");
    const auto dg = load("deviceguard_real.reg");
    KeyRead lsa; // Control\Lsa opened; LsaCfgFlagsDefault present (unmodelled -- not in `expected`),
                 // LsaCfgFlags absent (per-value, real capture).
    ValueOutcome lsa_default;
    lsa_default.name = "LsaCfgFlagsDefault";
    lsa_default.value = {ValueKind::dword, kRegDword, 0, {}, 0};
    lsa.values = {lsa_default};
    const auto rep = build_code_integrity_report(read_of(ci, kCiPolicyKey), read_of(dg, kDeviceGuardKey),
                                                 read_of(dg, kHvciScenarioKey), lsa);
    CHECK(lines(rep) == Lines{
        "code_integrity|windows|ci_policy.EmodePolicyRequired|0|unmodelled",
        "code_integrity|windows|ci_policy.SAC_PreviousState|4294967295|unmodelled",
        "code_integrity|windows|ci_policy.SkuPolicyRequired|0|unmodelled",
        "code_integrity|windows|ci_policy.VerifiedAndReputablePolicyState|0|disabled",
        "code_integrity|windows|deviceguard.EnableVirtualizationBasedSecurity|-|absent",
        "code_integrity|windows|deviceguard.HypervisorEnforcedCodeIntegrity|-|absent",
        "code_integrity|windows|deviceguard.RequirePlatformSecurityFeatures|-|absent",
        "code_integrity|windows|deviceguard.hvci_scenario_enabled|-|absent",
        "code_integrity|windows|lsa.LsaCfgFlagsDefault|0|unmodelled",
        "code_integrity|windows|lsa.LsaCfgFlags|-|absent"});
    CHECK(select_status(rep).status == YUZU_RESULT_STATUS_OK);
    CHECK(select_status(rep).completeness == YUZU_RESULT_COMPLETENESS_FULL);
}

TEST_CASE("code_integrity: LsaCfgFlags is read from Control\\Lsa", "[platform_security][win_parsers]") {
    // RECONSTRUCTION (inline): Microsoft Learn "Configure Credential Guard" puts LsaCfgFlags under
    // Control\Lsa. Fails if kLsaKey's path moves, its row key reverts to deviceguard.*, or 2 stops
    // mapping to `enabled`.
    const auto e = parse_reg_export(
        "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa]\r\n"
        "\"LsaCfgFlags\"=dword:00000002\r\n");
    REQUIRE(e.has_value());
    const auto rep = build_code_integrity_report(absent_key(), absent_key(), absent_key(), read_of(*e, kLsaKey));
    CHECK(lines(rep).back() == "code_integrity|windows|lsa.LsaCfgFlags|2|enabled");
}

TEST_CASE("code_integrity: a not-found Lsa KEY is unreadable, never absent, unlike its siblings",
          "[platform_security][win_parsers]") {
    // Regression pin for the absent-vs-unreadable possibility gate (`KeySpec::key_may_be_absent`):
    // Lsa is foundational NT infrastructure with no evidenced legitimate not-found-key case, unlike
    // SecureBoot\State (BIOS/CSM), CI\Policy (non-SAC editions) and the HVCI scenario subkey
    // (VBS/HVCI not configured) -- all four keys are opened the same way and would misclassify
    // identically if this gate regressed to a single shared rule. Fails if Lsa's not-found reads
    // absent again, or if any of its three siblings stops reading absent.
    CHECK(kSecureBootKey.key_may_be_absent);
    CHECK(kCiPolicyKey.key_may_be_absent);
    CHECK(kHvciScenarioKey.key_may_be_absent);
    CHECK_FALSE(kLsaKey.key_may_be_absent);

    const auto rep = build_code_integrity_report(absent_key(), absent_key(), absent_key(), absent_key());
    CHECK(lines(rep) == Lines{
        "code_integrity|windows|ci_policy.VerifiedAndReputablePolicyState|-|absent",
        "code_integrity|windows|deviceguard.EnableVirtualizationBasedSecurity|-|absent",
        "code_integrity|windows|deviceguard.RequirePlatformSecurityFeatures|-|absent",
        "code_integrity|windows|deviceguard.HypervisorEnforcedCodeIntegrity|-|absent",
        "code_integrity|windows|deviceguard.hvci_scenario_enabled|-|absent",
        "code_integrity|windows|lsa.LsaCfgFlags|-|unreadable"});
    CHECK(rep.acc.reason() == "lsa:key_missing");
    CHECK(select_status(rep).status == YUZU_RESULT_STATUS_CONSTRAINED);
}

TEST_CASE("secure_boot: on, off, unmodelled, absent and unreadable are five distinct rows",
          "[platform_security][win_parsers]") {
    // on = REAL CAPTURE (Secure Boot ON on the-rig); off/unmodelled rewrite its dword text. Fails if any pair
    // collapses (absent vs unreadable is the "failure never reads as absent" pin).
    const std::string on = fixture_text("secureboot_state.reg");
    const auto rows = [&](const std::string& text) {
        auto e = parse_reg_export(text);
        REQUIRE(e.has_value());
        return lines(build_secure_boot_report(read_of(*e, kSecureBootKey)));
    };
    const auto swap = [&](const std::string& to) {
        std::string t = on;
        t.replace(t.find("00000001"), 8, to);
        return t;
    };
    CHECK(rows(on) == Lines{"secure_boot|windows|UEFISecureBootEnabled|1|enabled"});
    CHECK(rows(swap("00000000")) == Lines{"secure_boot|windows|UEFISecureBootEnabled|0|disabled"});
    CHECK(rows(swap("00000002")) == Lines{"secure_boot|windows|UEFISecureBootEnabled|2|unmodelled"});

    const auto absent = build_secure_boot_report(absent_key());
    CHECK(lines(absent) == Lines{"secure_boot|windows|UEFISecureBootEnabled|-|absent"});
    CHECK(select_status(absent).status == YUZU_RESULT_STATUS_OK); // BIOS/CSM boot is not a failure

    KeyRead denied;
    denied.opened = false;
    denied.failure = classify_win32_failure("secureboot_state", 5);
    const auto unreadable = build_secure_boot_report(denied);
    CHECK(lines(unreadable) == Lines{"secure_boot|windows|UEFISecureBootEnabled|-|unreadable"});
    CHECK(unreadable.acc.reason() == "secureboot_state:access_denied");
    CHECK(select_status(unreadable).status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
}

TEST_CASE("mappers: every listed value pinned, everything else unmodelled",
          "[platform_security][win_parsers]") {
    // Fails if a mapper's table entry moves or a fallthrough coerces an unknown value.
    struct C { Map m; std::uint32_t v; State s; };
    const C cases[] = {
        {Map::secure_boot, 0, State::disabled}, {Map::secure_boot, 1, State::enabled},
        {Map::secure_boot, 2, State::unmodelled}, {Map::secure_boot, 0xffffffffu, State::unmodelled},
        {Map::toggle, 0, State::disabled}, {Map::toggle, 1, State::enabled}, {Map::toggle, 2, State::unmodelled},
        {Map::sac, 0, State::disabled}, {Map::sac, 1, State::enabled}, {Map::sac, 2, State::evaluation},
        {Map::sac, 3, State::unmodelled},
        {Map::platform_features, 0, State::disabled}, {Map::platform_features, 1, State::enabled},
        {Map::platform_features, 2, State::unmodelled}, {Map::platform_features, 3, State::enabled},
        {Map::platform_features, 4, State::unmodelled},
        {Map::lsa_cfg, 0, State::disabled}, {Map::lsa_cfg, 1, State::enabled_locked},
        {Map::lsa_cfg, 2, State::enabled}, {Map::lsa_cfg, 3, State::unmodelled},
    };
    for (const auto& c : cases)
        CHECK(apply_map(c.m, c.v) == c.s);
}

TEST_CASE("win32 classification and read plan", "[platform_security][win_parsers]") {
    // Fails if ERROR_ACCESS_DENIED ever reads absent, absence ever carries a token, or the plan
    // reads an opaque value / accepts a mis-sized 32-bit value.
    for (std::uint32_t nf : {2u, 3u}) {
        const auto f = classify_win32_failure("k", nf);
        CHECK(f.state == State::absent);
        CHECK(f.token.empty());
        CHECK_FALSE(f.access_denied);
    }
    const auto denied = classify_win32_failure("k", 5);
    CHECK(denied.state == State::unreadable);
    CHECK(denied.token == "k:access_denied");
    CHECK(denied.access_denied);
    CHECK(classify_win32_failure("k", 234).token == "k:oversized");
    CHECK(classify_win32_failure("k", 1005).token == "k:win32_1005");
    CHECK(classify_win32_failure("k", 1005).state == State::unreadable);

    CHECK(plan_value_read(4, 4) == ReadPlan::dword);
    CHECK(plan_value_read(4, 8) == ReadPlan::bad_size);
    CHECK(plan_value_read(1, 4096) == ReadPlan::text);
    CHECK(plan_value_read(2, 4097) == ReadPlan::oversized);
    CHECK(plan_value_read(3, 100000) == ReadPlan::opaque);
}

TEST_CASE("row builder: wrong type, opaque, text escaping, case, incomplete enumeration, denial",
          "[platform_security][win_parsers]") {
    // RECONSTRUCTION. Each expectation fails if that branch of add_key_rows / select_status changes.
    KeyRead ci;
    ValueOutcome typed; // a modelled 32-bit value that is a string
    typed.name = "verifiedandreputablepolicystate"; // registry names are case-insensitive
    typed.value = {ValueKind::text, kRegSz, 0, "1", 0};
    ValueOutcome blob;
    blob.name = "Blob";
    blob.value = {ValueKind::other, 3, 0, {}, 7};
    ValueOutcome txt;
    txt.name = "Path";
    txt.value = {ValueKind::text, kRegSz, 0, "C:\\a|b", 0};
    ci.values = {typed, blob, txt};
    ci.complete = false;
    // lsa's absent_key() placeholder is a not-found KEY, which Lsa can never legitimately be, so
    // it contributes its own trailing `lsa:key_missing` token here (dg/hvci_scenario's absent_key()
    // placeholders stay silent -- both CAN legitimately be a not-found key).
    auto rep = build_code_integrity_report(ci, absent_key(), absent_key(), absent_key());
    const auto got = lines(rep);
    CHECK(got[0] == "code_integrity|windows|ci_policy.Blob|opaque_7B|unmodelled");
    CHECK(got[1] == "code_integrity|windows|ci_policy.Path|C:/a\\|b|unmodelled");
    CHECK(got[2] == "code_integrity|windows|ci_policy.VerifiedAndReputablePolicyState|-|unreadable");
    CHECK(rep.acc.reason() ==
          "ci_policy.VerifiedAndReputablePolicyState:type_1,ci_policy:enumeration_incomplete,"
          "lsa:key_missing");
    CHECK(select_status(rep).status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(select_status(rep).completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);

    // Fails under: an incomplete enumeration reading an UNSEEN expected value as `absent`
    // (a definitive claim the enumeration cannot make) instead of `unreadable`.
    {
        KeyRead partial;
        partial.values = {dword_value("EnableVirtualizationBasedSecurity", 1)};
        partial.complete = false; // more values existed than were enumerated
        // ci/hvci_scenario keys absent (1 expected value each -> 1 absent row each, both CAN
        // legitimately be a not-found key); lsa's same absent_key() placeholder is `unreadable`
        // instead (Lsa can never legitimately be a not-found key). The deviceguard key is the
        // partial one under test, in between them (call order in build_code_integrity_report: ci,
        // device_guard, hvci_scenario, lsa).
        auto dg_rep = build_code_integrity_report(absent_key(), partial, absent_key(), absent_key());
        const auto dg_got = lines(dg_rep);
        REQUIRE(dg_got.size() == 6);
        CHECK(dg_got[1] == "code_integrity|windows|deviceguard.EnableVirtualizationBasedSecurity|1|enabled");
        // The two expected values NOT among the partial enumeration are `unreadable`, never `absent`:
        // the enumeration didn't finish, so it never established that they don't exist.
        CHECK(dg_got[2] ==
              "code_integrity|windows|deviceguard.RequirePlatformSecurityFeatures|-|unreadable");
        CHECK(dg_got[3] ==
              "code_integrity|windows|deviceguard.HypervisorEnforcedCodeIntegrity|-|unreadable");
        CHECK(dg_got[5] == "code_integrity|windows|lsa.LsaCfgFlags|-|unreadable");
        CHECK(dg_rep.acc.reason() ==
              "deviceguard.RequirePlatformSecurityFeatures:enumeration_incomplete,"
              "deviceguard.HypervisorEnforcedCodeIntegrity:enumeration_incomplete,"
              "deviceguard:enumeration_incomplete,lsa:key_missing");
        CHECK(select_status(dg_rep).status == YUZU_RESULT_STATUS_CONSTRAINED);
    }

    // One refused value outranks other tokens and the healthy keys: PERMISSION_DENIED.
    KeyRead dg;
    dg.values = {dword_value("EnableVirtualizationBasedSecurity", 1)};
    KeyRead lsa;
    ValueOutcome refused;
    refused.name = "LsaCfgFlags";
    refused.ok = false;
    refused.failure = classify_win32_failure("lsa.LsaCfgFlags", 5);
    lsa.values = {refused};
    rep = build_code_integrity_report(ci, dg, absent_key(), lsa);
    CHECK(select_status(rep).status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(select_status(rep).provenance.find("lsa.LsaCfgFlags:access_denied") != std::string::npos);

    // A value the OS says is absent is a row without a token.
    KeyRead quiet;
    ValueOutcome gone;
    gone.name = "UEFISecureBootEnabled";
    gone.ok = false;
    gone.failure = classify_win32_failure("UEFISecureBootEnabled", 2);
    quiet.values = {gone};
    rep = build_secure_boot_report(quiet);
    CHECK(lines(rep) == Lines{"secure_boot|windows|UEFISecureBootEnabled|-|absent"});
    CHECK(select_status(rep).status == YUZU_RESULT_STATUS_OK);
}
