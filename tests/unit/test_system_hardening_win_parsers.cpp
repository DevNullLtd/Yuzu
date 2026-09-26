/**
 * test_system_hardening_win_parsers.cpp -- pure tests for
 * system_hardening_win_parsers.hpp. No platform guard, no <windows.h>, no OS
 * call. Inputs are REAL CAPTURE (fixtures/wave8/system_hardening/windows/
 * mitigation_options.hex from the-rig `reg query`; its .provenance.txt holds
 * `Get-ProcessMitigation -System` as `expect.<policy>=<on|off|default>` lines;
 * REQUIRE(exists), never skipped) or RECONSTRUCTION (bytes built from the
 * kernel option-map nibble table in the header, for table mechanics and
 * malformed input). Only the five options that capture enabled (nibbles 0, 1,
 * 4, 5, 10 = dep, sehop, aslr_bottom_up, aslr_high_entropy, cfg) are confirmed
 * on hardware; the other nibble positions are inferred, so a RECONSTRUCTION
 * case proves table mechanics, not what Windows does for that policy. The
 * Win32 failure classifier is pinned by RECONSTRUCTION too: the error numbers
 * are the winerror.h constants, and the Windows-only shell that applies them
 * (system_hardening_win.cpp) is exercised on the Windows CI leg.
 */
#include "system_hardening_win_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::system_hardening::mitigation;
namespace fs = std::filesystem;

namespace {

fs::path fixture_path(const std::string& rel) {
    return fs::path{YUZU_TEST_FIXTURE_DIR} / "wave8" / "system_hardening" / "windows" / rel;
}

std::string read_fixture_text(const std::string& rel) {
    const fs::path p = fixture_path(rel);
    REQUIRE(fs::exists(p));
    std::ifstream f(p, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

/// RECONSTRUCTION: a little-endian blob of `size` zero bytes with the given
/// (nibble index, nibble value) pairs set in the first QWORD.
std::vector<uint8_t> make_blob(std::size_t size,
                               std::initializer_list<std::pair<unsigned, unsigned>> nibbles) {
    std::vector<uint8_t> b(size, 0);
    for (const auto& [idx, val] : nibbles)
        b[idx / 2] = static_cast<uint8_t>(b[idx / 2] | ((val & 0xF) << (4 * (idx % 2))));
    return b;
}

std::map<std::string, MitigationRow> by_policy(const std::vector<MitigationRow>& rows) {
    std::map<std::string, MitigationRow> m;
    for (const auto& r : rows)
        m.emplace(r.policy, r);
    return m;
}

std::vector<MitigationRow> decode_ok(const std::vector<uint8_t>& blob,
                                     std::string_view prefix = "mitigation.") {
    auto r = decode_mitigation_options(blob, prefix);
    REQUIRE(r.has_value());
    return *r;
}

} // namespace

TEST_CASE("system_hardening win: decode: every nibble value maps 0/1/2/3+ to "
          "default/on/off/unmodelled",
          "[system_hardening][win_parsers]") {
    // RECONSTRUCTION; drives kPolicyTable itself. EVERY nibble (dep at 0 and
    // sehop at 1 included) is two-bit; 3..15 are all per-policy meanings.
    for (const auto& def : detail::kPolicyTable) {
        const std::pair<unsigned, PolicyState> cases[] = {{0, PolicyState::default_state},
                                                          {1, PolicyState::on},
                                                          {2, PolicyState::off},
                                                          {3, PolicyState::unmodelled},
                                                          {0xF, PolicyState::unmodelled}};
        for (const auto& [nib, want] : cases) {
            const auto rows = by_policy(decode_ok(make_blob(16, {{def.nibble, nib}})));
            const auto it = rows.find("mitigation." + std::string{def.name});
            REQUIRE(it != rows.end());
            INFO(def.name << " nibble=" << nib);
            CHECK(it->second.state == want);
            CHECK(it->second.raw == "0x" + std::string(1, "0123456789abcdef"[nib]));
            // No other table policy moves.
            for (const auto& [name, row] : rows) {
                if (name != it->first && row.raw != "0x0" && name.find("ext_q") == std::string::npos)
                    FAIL("unexpected non-default row " << name);
            }
        }
    }
}

TEST_CASE("system_hardening win: decode: prefix is applied to every row",
          "[system_hardening][win_parsers]") {
    // RECONSTRUCTION: nibble 1 is sehop (a defined policy, not reserved).
    const auto rows = decode_ok(make_blob(16, {{1, 0x2}}), "mitigation_audit.");
    const auto by = by_policy(rows);
    REQUIRE(by.count("mitigation_audit.sehop") == 1);
    CHECK(by.at("mitigation_audit.sehop").state == PolicyState::off);
    CHECK(by.count("mitigation.sehop") == 0);
    CHECK(by.count("mitigation_audit.dep") == 1);
    for (const auto& r : rows)
        CHECK(r.policy.rfind("mitigation_audit.", 0) == 0);
}

TEST_CASE("system_hardening win: REAL CAPTURE: the captured blob decodes exactly the five "
          "enabled policies on",
          "[system_hardening][win_parsers][fixture]") {
    // Derived from the REAL CAPTURE (mitigation_options.hex, the-rig). Its
    // .provenance.txt records that only `Set-ProcessMitigation -System -Enable
    // DEP,SEHOP,BottomUp,HighEntropy,CFG` was applied to a host where every
    // mitigation was NOTSET, and that Get-ProcessMitigation -System then read
    // those five ON and the rest NOTSET. So: five `on` (nibble value 1), every
    // other policy `default`, and no reserved_* rows -- the old bit-flag model
    // read sehop as `default` here.
    const auto blob = parse_hex_blob(read_fixture_text("mitigation_options.hex"));
    REQUIRE(blob.has_value());
    REQUIRE(blob->size() == 24);
    const auto rows = decode_ok(*blob);
    const auto decoded = by_policy(rows);

    const std::set<std::string> enabled{"dep", "sehop", "aslr_bottom_up", "aslr_high_entropy",
                                        "cfg"};
    for (const auto& def : detail::kPolicyTable) {
        const std::string name{def.name};
        const auto it = decoded.find("mitigation." + name);
        INFO("policy " << name);
        REQUIRE(it != decoded.end());
        if (enabled.count(name) != 0) {
            CHECK(it->second.state == PolicyState::on);
            CHECK(it->second.raw == "0x1");
        } else {
            CHECK(it->second.state == PolicyState::default_state);
            CHECK(it->second.raw == "0x0");
        }
    }
    // Guards a typo in `enabled`: every name in it must be a real table row.
    for (const auto& name : enabled)
        CHECK(decoded.count("mitigation." + name) == 1);

    // Nothing but the table rows plus the two (all-zero) trailing QWORDs.
    CHECK(rows.size() == detail::kPolicyTable.size() + 2);
    for (const auto& r : rows)
        CHECK(r.policy.find("reserved") == std::string::npos);
    CHECK(decoded.at("mitigation.ext_q1").state == PolicyState::default_state);
    CHECK(decoded.at("mitigation.ext_q2").state == PolicyState::default_state);
}

TEST_CASE("system_hardening win: decode: QWORDs beyond the documented table are unmodelled "
          "when non-zero",
          "[system_hardening][win_parsers]") {
    // RECONSTRUCTION: 24-byte blob, third QWORD non-zero.
    auto blob = make_blob(24, {});
    blob[16] = 0x12;
    const auto rows = by_policy(decode_ok(blob));
    CHECK(rows.at("mitigation.ext_q1").state == PolicyState::default_state);
    CHECK(rows.at("mitigation.ext_q2").state == PolicyState::unmodelled);
    CHECK(rows.at("mitigation.ext_q2").raw == "0x0000000000000012");
    CHECK(by_policy(decode_ok(make_blob(16, {}))).count("mitigation.ext_q2") == 0);
}

TEST_CASE("system_hardening win: decode: malformed blobs return a typed error, never a partial "
          "decode",
          "[system_hardening][win_parsers]") {
    // RECONSTRUCTION negatives.
    const auto err = [](std::size_t n) {
        auto r = decode_mitigation_options(std::vector<uint8_t>(n, 0), "mitigation.");
        REQUIRE_FALSE(r.has_value());
        return r.error().token;
    };
    CHECK(err(0) == "empty_blob");
    CHECK(err(7) == "odd_length");
    CHECK(err(15) == "odd_length");
    CHECK(err(12) == "not_qword_aligned");
    CHECK(err(kMaxBlobBytes + 1) == "oversized"); // 257: odd AND over the cap; the cap wins
    CHECK(err(kMaxBlobBytes + 8) == "oversized");
    CHECK(decode_mitigation_options(std::vector<uint8_t>(16, 0), "").has_value());
    CHECK(decode_mitigation_options(std::vector<uint8_t>(24, 0), "").has_value());
}

TEST_CASE("system_hardening win: self policy: Flags bits map to on/off rows, never default",
          "[system_hardening][win_parsers]") {
    // RECONSTRUCTION: layouts from <winnt.h> PROCESS_MITIGATION_*_POLICY.
    auto dep = decode_self_policy(SelfPolicy::dep, 0x1);
    REQUIRE(dep.size() == 1);
    CHECK(dep[0].policy == "self.dep");
    CHECK(dep[0].state == PolicyState::on);
    CHECK(dep[0].raw == "1");
    CHECK(decode_self_policy(SelfPolicy::dep, 0x2)[0].state == PolicyState::off);

    const auto aslr = by_policy(decode_self_policy(SelfPolicy::aslr, 0x5));
    CHECK(aslr.at("self.aslr_bottom_up").state == PolicyState::on);
    CHECK(aslr.at("self.aslr_force_relocate").state == PolicyState::off);
    CHECK(aslr.at("self.aslr_high_entropy").state == PolicyState::on);

    const auto cfg = by_policy(decode_self_policy(SelfPolicy::cfg, 0x3));
    CHECK(cfg.at("self.cfg").state == PolicyState::on);
    CHECK(cfg.at("self.cfg_export_suppression").state == PolicyState::on);
    CHECK(cfg.at("self.cfg_strict_mode").state == PolicyState::off);
    CHECK(cfg.at("self.cfg").raw == "3");
}

TEST_CASE("system_hardening win: hex parsing: bare hex, 0x prefix, reg query line, and "
          "malformed input",
          "[system_hardening][win_parsers]") {
    // RECONSTRUCTION of the two accepted spellings + negatives.
    const std::vector<uint8_t> want{0x00, 0x22, 0xAB, 0xff};
    CHECK(*parse_hex_blob("0022abFF\n") == want);
    CHECK(*parse_hex_blob("0x00 22 ab ff") == want);
    CHECK(*parse_hex_blob("\r\nHKEY_LOCAL_MACHINE\\...\\kernel\r\n"
                          "    MitigationOptions    REG_BINARY    0022ABFF\r\n\r\n") == want);
    CHECK(parse_hex_blob("").error().token == "no_hex_digits");
    CHECK(parse_hex_blob("   \n").error().token == "no_hex_digits");
    CHECK(parse_hex_blob("002").error().token == "odd_hex_digits");
    CHECK(parse_hex_blob("00zz").error().token == "bad_hex");
}

TEST_CASE("system_hardening win: row format: posture|windows|<policy>|<raw>|<state>",
          "[system_hardening][win_parsers]") {
    CHECK(format_posture_row(MitigationRow{"mitigation.cfg", "0x1", PolicyState::on}) ==
          "posture|windows|mitigation.cfg|0x1|on");
    CHECK(format_posture_row("mitigation_options", "-", "absent") ==
          "posture|windows|mitigation_options|-|absent");
}

TEST_CASE("system_hardening win: win32 failures: not found is absent with NO token, on the "
          "registry and the policy call",
          "[system_hardening][win_parsers]") {
    // The default Windows 11 state (the rig capture): MitigationOptions / MitigationAuditOptions
    // do not exist. That is a modal state, not a failure: no token, so the run stays OK/FULL.
    for (const auto err : {kErrorFileNotFound, kErrorPathNotFound}) {
        for (const auto src : {ReadSource::registry, ReadSource::process_policy}) {
            const auto f = classify_win32_failure("mitigation_options", err, src);
            INFO("err=" << err);
            CHECK(f.state == "absent");
            CHECK(f.token.empty());
            CHECK_FALSE(f.access_denied);
            CHECK(format_posture_row("mitigation_options", "-", f.state) ==
                  "posture|windows|mitigation_options|-|absent");
        }
    }
}

// Fails under: a not-found Session Manager\kernel KEY reading as a clean absent (the key exists
// on every install -- rig-verified), the gate leaking onto a missing VALUE (which must stay a
// token-free absent), or the structural source changing access-denied / other-error handling.
TEST_CASE("system_hardening win: win32 failures: a not-found structural KEY is unreadable "
          "key_missing, never absent",
          "[system_hardening][win_parsers]") {
    for (const auto err : {kErrorFileNotFound, kErrorPathNotFound}) {
        INFO("err=" << err);
        const auto key = classify_win32_failure("mitigation_options", err, ReadSource::structural_key);
        CHECK(key.state == "unreadable");
        CHECK(key.token == "mitigation_options:key_missing");
        CHECK_FALSE(key.access_denied);
        CHECK(format_posture_row("mitigation_options", "-", key.state) ==
              "posture|windows|mitigation_options|-|unreadable");

        const auto value = classify_win32_failure("mitigation_options", err, ReadSource::registry);
        CHECK(value.state == "absent");
        CHECK(value.token.empty());
    }
    const auto denied =
        classify_win32_failure("mitigation_options", kErrorAccessDenied, ReadSource::structural_key);
    CHECK(denied.state == "unreadable");
    CHECK(denied.token == "mitigation_options:access_denied");
    CHECK(denied.access_denied);
    const auto other = classify_win32_failure("mitigation_options", 1005, ReadSource::structural_key);
    CHECK(other.token == "mitigation_options:win32_1005");
    CHECK_FALSE(other.access_denied);
}

// Fails under: the Win32 shell's key-open path classifying through anything but the
// structural-key rule, a registry row missing from (or reordered in) the open-failure set, or a
// row name drifting from the value it reads.
TEST_CASE("system_hardening win: win32 failures: a failed kernel-key open fails every registry "
          "row as the key",
          "[system_hardening][win_parsers]") {
    REQUIRE(kRegistryRows.size() == 2);
    CHECK(kRegistryRows[0].row_name == "mitigation_options");
    CHECK(kRegistryRows[0].value_name == L"MitigationOptions");
    CHECK(kRegistryRows[1].row_name == "mitigation_audit_options");
    CHECK(kRegistryRows[1].value_name == L"MitigationAuditOptions");

    const auto missing = kernel_key_open_failures(kErrorFileNotFound);
    for (std::size_t i = 0; i < missing.size(); ++i) {
        INFO(missing[i].row_name);
        CHECK(missing[i].row_name == kRegistryRows[i].row_name);
        CHECK(missing[i].failure.state == "unreadable");
        CHECK(missing[i].failure.token == std::string{kRegistryRows[i].row_name} + ":key_missing");
        CHECK_FALSE(missing[i].failure.access_denied);
    }
    const auto denied = kernel_key_open_failures(kErrorAccessDenied);
    CHECK(denied[1].failure.token == "mitigation_audit_options:access_denied");
    CHECK(denied[1].failure.access_denied);
}

// Fails under: GetProcessMitigationPolicy ERROR_INVALID_PARAMETER reading as a clean `absent`
// (on every supported target DEP/ASLR/CFG exist, so it is a malformed call and would otherwise
// hide as OK/FULL), or ERROR_NOT_SUPPORTED -- the OS saying the policy does not exist -- gaining
// a token.
TEST_CASE("system_hardening win: win32 failures: GetProcessMitigationPolicy NOT_SUPPORTED is "
          "absent, INVALID_PARAMETER is unreadable win32_87; both fail a registry read",
          "[system_hardening][win_parsers]") {
    const auto unsupported =
        classify_win32_failure("self.dep", kErrorNotSupported, ReadSource::process_policy);
    CHECK(unsupported.state == "absent");
    CHECK(unsupported.token.empty()); // the retired `:unsupported` token must not come back
    CHECK_FALSE(unsupported.access_denied);

    const auto invalid =
        classify_win32_failure("self.aslr", kErrorInvalidParameter, ReadSource::process_policy);
    CHECK(invalid.state == "unreadable");
    CHECK(invalid.token == "self.aslr:win32_87");
    CHECK_FALSE(invalid.access_denied);

    for (const auto err : {kErrorInvalidParameter, kErrorNotSupported}) {
        INFO("err=" << err);
        const auto reg = classify_win32_failure("mitigation_options", err, ReadSource::registry);
        CHECK(reg.state == "unreadable");
        CHECK(reg.token == "mitigation_options:win32_" + std::to_string(err));
    }
}

// Fails under: rejecting the REG_QWORD Microsoft's documented font-blocking steps write (all
// sixteen rows lost to `type_11`), decoding it differently from the same 8 bytes as REG_BINARY,
// or guessing a decode for a REG_DWORD / a REG_QWORD that is not 8 bytes.
TEST_CASE("system_hardening win: registry value: REG_BINARY and an 8-byte REG_QWORD decode alike; "
          "any other type is type_<n>",
          "[system_hardening][win_parsers]") {
    // 0x1000000000000 as a little-endian QWORD: nibble 12 (font_disable) = 1.
    const std::vector<std::uint8_t> qword{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
    const auto as_qword = decode_registry_value(kRegQword, qword, "mitigation.");
    REQUIRE(as_qword.has_value());
    const auto rows = by_policy(*as_qword);
    CHECK(as_qword->size() == detail::kPolicyTable.size()); // one QWORD: no ext_q rows
    CHECK(rows.at("mitigation.font_disable").state == PolicyState::on);
    CHECK(rows.at("mitigation.font_disable").raw == "0x1");
    for (const auto& [name, row] : rows)
        if (name != "mitigation.font_disable")
            CHECK(row.state == PolicyState::default_state);

    const auto as_binary = decode_registry_value(kRegBinary, qword, "mitigation.");
    REQUIRE(as_binary.has_value());
    REQUIRE(as_binary->size() == as_qword->size());
    for (std::size_t i = 0; i < as_qword->size(); ++i) {
        CHECK((*as_binary)[i].policy == (*as_qword)[i].policy);
        CHECK((*as_binary)[i].raw == (*as_qword)[i].raw);
        CHECK((*as_binary)[i].state == (*as_qword)[i].state);
    }

    // REG_BINARY keeps the documented 16/24-byte form and the decoder's own errors.
    CHECK(decode_registry_value(kRegBinary, make_blob(24, {}), "mitigation.").has_value());
    CHECK(decode_registry_value(kRegBinary, std::vector<std::uint8_t>{}, "mitigation.")
              .error()
              .token == "empty_blob");

    // Anything that is not REG_BINARY or an 8-byte REG_QWORD is its type, never a guessed decode.
    CHECK(decode_registry_value(4, std::vector<std::uint8_t>(4, 0), "mitigation.").error().token ==
          "type_4"); // REG_DWORD
    CHECK(decode_registry_value(kRegQword, std::vector<std::uint8_t>(4, 0), "mitigation.")
              .error()
              .token == "type_11");
    CHECK(decode_registry_value(kRegQword, make_blob(16, {}), "mitigation.").error().token ==
          "type_11");
    CHECK(decode_registry_value(1, qword, "mitigation.").error().token == "type_1"); // REG_SZ
    CHECK(kRegBinary == 3u);  // REG_BINARY
    CHECK(kRegQword == 11u);  // REG_QWORD
}

TEST_CASE("system_hardening win: win32 failures: access denied and any other error are unreadable "
          "with exactly one token",
          "[system_hardening][win_parsers]") {
    for (const auto src : {ReadSource::registry, ReadSource::process_policy}) {
        const auto denied = classify_win32_failure("mitigation_options", kErrorAccessDenied, src);
        CHECK(denied.state == "unreadable");
        CHECK(denied.token == "mitigation_options:access_denied");
        CHECK(denied.access_denied); // the PERMISSION_DENIED case

        // ERROR_INVALID_FUNCTION (1), ERROR_MORE_DATA (234), an arbitrary code: all real failures.
        for (const std::uint32_t err : {1u, 234u, 1450u}) {
            const auto other = classify_win32_failure("self.cfg", err, src);
            INFO("err=" << err);
            CHECK(other.state == "unreadable");
            CHECK(other.token == "self.cfg:win32_" + std::to_string(err));
            CHECK_FALSE(other.access_denied);
        }
    }
    // Absent and unreadable never share a state, and only the failure carries a token.
    const auto absent = classify_win32_failure("k", kErrorFileNotFound, ReadSource::registry);
    const auto failed = classify_win32_failure("k", kErrorAccessDenied, ReadSource::registry);
    CHECK(absent.state != failed.state);
    CHECK(absent.token.empty());
    CHECK_FALSE(failed.token.empty());
}

TEST_CASE("system_hardening win: win32 failures: a cause the shell detects itself is unreadable "
          "with exactly one token, "
          "never a denial",
          "[system_hardening][win_parsers]") {
    // ERROR_MORE_DATA, a non-REG_BINARY type and a decoder token are found by the Windows shell,
    // not classified from an error number; this pins the token text that reaches the status reason.
    const auto oversized = unreadable_failure("mitigation_options", "oversized");
    CHECK(oversized.state == "unreadable");
    CHECK(oversized.token == "mitigation_options:oversized");
    CHECK_FALSE(oversized.access_denied);
    CHECK(unreadable_failure("mitigation_audit_options", "type_3").token ==
          "mitigation_audit_options:type_3");
    CHECK(unreadable_failure("mitigation_options", "odd_length").token ==
          "mitigation_options:odd_length");
}

TEST_CASE("system_hardening win: win32 failures: the classified error numbers are the winerror.h "
          "constants",
          "[system_hardening][win_parsers]") {
    // system_hardening_win.cpp static_asserts these against the SDK on Windows; pinned here on
    // every OS so a typo in the pure header fails loudly on the fast suites too.
    CHECK(kErrorFileNotFound == 2u);      // ERROR_FILE_NOT_FOUND
    CHECK(kErrorPathNotFound == 3u);      // ERROR_PATH_NOT_FOUND
    CHECK(kErrorAccessDenied == 5u);      // ERROR_ACCESS_DENIED
    CHECK(kErrorNotSupported == 50u);     // ERROR_NOT_SUPPORTED
    CHECK(kErrorInvalidParameter == 87u); // ERROR_INVALID_PARAMETER
}

TEST_CASE("system_hardening win: REAL CAPTURE: decoded DEP/ASLR/CFG match "
          "Get-ProcessMitigation -System",
          "[system_hardening][win_parsers][fixture]") {
    // REAL CAPTURE from the-rig. The provenance file records the ground truth
    // as `expect.<short policy>=<on|off|default>` lines (Get-ProcessMitigation
    // -System: ON -> on, OFF -> off, NOTSET -> default).
    const auto blob = parse_hex_blob(read_fixture_text("mitigation_options.hex"));
    REQUIRE(blob.has_value());
    const auto rows = decode_ok(*blob);
    const auto decoded = by_policy(rows);

    std::map<std::string, std::string> expect;
    {
        std::istringstream in(read_fixture_text("mitigation_options.hex.provenance.txt"));
        std::string line;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            constexpr std::string_view kTag = "expect.";
            if (line.rfind(kTag, 0) != 0)
                continue;
            const auto eq = line.find('=');
            REQUIRE(eq != std::string::npos);
            expect[line.substr(kTag.size(), eq - kTag.size())] = line.substr(eq + 1);
        }
    }
    // The three headline policies must be asserted -- an unpopulated
    // provenance file is a failed capture, not a vacuous pass.
    for (const char* required : {"dep", "aslr_bottom_up", "cfg"})
        REQUIRE(expect.count(required) == 1);

    for (const auto& [name, state] : expect) {
        const auto it = decoded.find("mitigation." + name);
        INFO("policy " << name);
        REQUIRE(it != decoded.end());
        CHECK(std::string{state_token(it->second.state)} == state);
    }
}
