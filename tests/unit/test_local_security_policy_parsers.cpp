/**
 * test_local_security_policy_parsers.cpp -- pure tests for the local_security_policy
 * plugin's PAM/login.defs/auditd parsers, the sudoers lexer, the secedit export decode and row
 * mapping, the Windows scratch-sweep decisions and the pwpolicy row mapping. Runs on every OS:
 * nothing here touches the filesystem, the registry or a process.
 *
 * No REAL CAPTURE fixtures here (unlike app_control/autoruns/runtimes): this plugin's
 * inputs are host-specific system files (a live pwpolicy plist) that vary machine to
 * machine, not a stable binary/text format worth freezing as a committed capture. Every
 * input below is either a small, clearly labelled inline reconstruction of the documented
 * shape (the pwpolicy plist bridge's PwPolicyItem contract) or a direct call into the
 * injected FileReader/DirLister seam collect_file_policy takes, per this repo's existing
 * fixture-avoidance precedent for host-varying sources.
 */
#include <catch2/catch_test_macros.hpp>

#include "../../agents/plugins/local_security_policy/src/local_security_policy_parsers.hpp"

#include "../../agents/plugins/local_security_policy/src/local_security_policy_scratch_sweep.hpp"
#if defined(__APPLE__)
#include "../../agents/plugins/local_security_policy/src/local_security_policy_legs.hpp"
#endif

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::local_security_policy;

namespace {

FileReader reader_from(std::map<std::string, std::string> files) {
    return [files = std::move(files)](const std::string& path) -> FileRead {
        auto it = files.find(path);
        if (it == files.end()) return {ENOENT, {}};
        return {0, it->second};
    };
}

DirLister empty_dir() {
    return [](const std::string&) -> DirList { return {}; };
}

} // namespace

// ── text helpers ──────────────────────────────────────────────────────────────────


TEST_CASE("local_security_policy text helpers: trim and line splitting",
          "[local_security_policy][parsers]") {
    CHECK(trim_ws(" \t a b \r") == "a b");
    CHECK(trim_ws("") == "");
    CHECK(trim_ws("\t\r") == "");
    CHECK(split_lines("a\nb\n\nc") == std::vector<std::string_view>{"a", "b", "", "c"});
    CHECK(split_lines("").empty());
    CHECK(split_lines("a") == std::vector<std::string_view>{"a"});
}

// ── secedit export helpers (UTF-16LE INI) ──────────────────────────────────────────
// Pure, OS-independent parsing/comparison primitives the Windows leg wires up
// (local_security_policy_win.cpp). Tested on every OS, matching platform_security's own
// tested decode_utf16le_bom precedent.

TEST_CASE("local_security_policy decode_utf16le_bom: BOM required, exact round-trip, "
          "malformed input is nullopt never a truncated guess",
          "[local_security_policy][parsers][secedit]") {
    // "AB" as UTF-16LE with a mandatory FF FE BOM.
    const std::vector<std::uint8_t> ab_bom{0xFF, 0xFE, 0x41, 0x00, 0x42, 0x00};
    const auto ab = decode_utf16le_bom(ab_bom);
    REQUIRE(ab.has_value());
    CHECK(*ab == "AB");

    // A non-ASCII BMP codepoint (U+00E9 'é', UTF-8 0xC3 0xA9) -- 2-byte UTF-8 output.
    const std::vector<std::uint8_t> e_acute{0xFF, 0xFE, 0xE9, 0x00};
    const auto e = decode_utf16le_bom(e_acute);
    REQUIRE(e.has_value());
    CHECK(*e == "\xC3\xA9");

    // A 3-byte-UTF-8 BMP codepoint (U+20AC '€', UTF-8 0xE2 0x82 0xAC) -- the middle encoding
    // width (< 0x800 is 2-byte, this is 3-byte, >= 0x10000 is 4-byte) had no test before.
    const std::vector<std::uint8_t> euro{0xFF, 0xFE, 0xAC, 0x20};
    const auto eu = decode_utf16le_bom(euro);
    REQUIRE(eu.has_value());
    CHECK(*eu == "\xE2\x82\xAC");

    // A complete, valid surrogate pair (U+10000, the first supplementary-plane codepoint) --
    // 4-byte UTF-8 output. High surrogate 0xD800 then low surrogate 0xDC00, both LE.
    const std::vector<std::uint8_t> supplementary{0xFF, 0xFE, 0x00, 0xD8, 0x00, 0xDC};
    const auto supp = decode_utf16le_bom(supplementary);
    REQUIRE(supp.has_value());
    CHECK(*supp == "\xF0\x90\x80\x80");

    // No BOM at all.
    const std::vector<std::uint8_t> no_bom{0x41, 0x00, 0x42, 0x00};
    CHECK_FALSE(decode_utf16le_bom(no_bom).has_value());

    // Odd length (a truncated UTF-16 code unit).
    const std::vector<std::uint8_t> odd{0xFF, 0xFE, 0x41, 0x00, 0x42};
    CHECK_FALSE(decode_utf16le_bom(odd).has_value());

    // Unpaired high surrogate: buffer ends right after it, so there's no room left at all for
    // a low surrogate. Hits the truncation check (i+3 >= size), not the value-range check.
    const std::vector<std::uint8_t> unpaired_high{0xFF, 0xFE, 0x00, 0xD8};
    CHECK_FALSE(decode_utf16le_bom(unpaired_high).has_value());

    // High surrogate followed by a PRESENT but INVALID low surrogate (another high surrogate,
    // not a low one) -- exercises the distinct `lo < 0xDC00 || lo > 0xDFFF` value-range check,
    // never reached by unpaired_high above since that case is too short to get there at all.
    const std::vector<std::uint8_t> invalid_low_pair{0xFF, 0xFE, 0x00, 0xD8, 0x00, 0xD8};
    CHECK_FALSE(decode_utf16le_bom(invalid_low_pair).has_value());

    // Low surrogate with no preceding high surrogate.
    const std::vector<std::uint8_t> bare_low{0xFF, 0xFE, 0x00, 0xDC};
    CHECK_FALSE(decode_utf16le_bom(bare_low).has_value());

    // Too short to even carry the BOM.
    const std::vector<std::uint8_t> tiny{0xFF};
    CHECK_FALSE(decode_utf16le_bom(tiny).has_value());
}

TEST_CASE("local_security_policy CaseInsensitiveLess: orders and matches by folded case only",
          "[local_security_policy][parsers][secedit]") {
    const CaseInsensitiveLess less{};
    CHECK(less("abc", "ABD"));      // 'c' < 'd' after folding
    CHECK_FALSE(less("ABC", "abc")); // equal under folding -> neither is less
    CHECK_FALSE(less("abc", "ABC"));
    CHECK(less("ab", "abc")); // shorter prefix sorts first when the shared prefix matches
    CHECK_FALSE(less("abc", "ab"));

    // is_transparent: a std::map keyed on this comparator is looked up by string_view
    // without constructing a temporary std::string, and a differently-cased key finds it.
    std::map<std::string, int, CaseInsensitiveLess> m;
    m["MinimumPasswordLength"] = 14;
    REQUIRE(m.find("minimumpasswordlength") != m.end());
    CHECK(m.find("minimumpasswordlength")->second == 14);
    REQUIRE(m.find("MINIMUMPASSWORDLENGTH") != m.end());
}

TEST_CASE("local_security_policy parse_inf_sections: sections, comments, case-insensitive "
          "repeated-key-keeps-last, pre-section lines ignored",
          "[local_security_policy][parsers][secedit]") {
    const auto sections = parse_inf_sections(
        "; a comment before any section, ignored\n"
        "OrphanKey = should be ignored, no section yet\n"
        "[System Access]\n"
        "; a comment inside a section\n"
        "MinimumPasswordLength = 8\n"
        "minimumpasswordlength = 14\n" // repeated, differently-cased -> keeps this last value
        "PasswordComplexity = 1\n"
        "\n"
        "[Event Audit]\n"
        "AuditLogonEvents = 3\n");

    REQUIRE(sections.size() == 2);
    // Section lookup is itself case-insensitive.
    const auto sys = sections.find("system access");
    REQUIRE(sys != sections.end());
    REQUIRE(sys->second.size() == 2); // MinimumPasswordLength + PasswordComplexity, not 3
    CHECK(sys->second.at("MinimumPasswordLength") == "14"); // last write wins
    CHECK(sys->second.at("PasswordComplexity") == "1");

    const auto audit = sections.find("Event Audit");
    REQUIRE(audit != sections.end());
    CHECK(audit->second.at("AuditLogonEvents") == "3");

    // No section named for the pre-section orphan key -- it was silently dropped, not
    // attributed to a synthetic/default section.
    CHECK(sections.find("") == sections.end());

    CHECK(parse_inf_sections("").empty());
    CHECK(parse_inf_sections("; only comments\n; nothing else\n").empty());
}

TEST_CASE("local_security_policy parse_inf_sections: a section header missing its closing ']' "
          "is never treated as a real section -- either silently dropped, or (if it happens to "
          "contain '=' while a section is already open) attributed as an ordinary key into that "
          "section, never as a new section of its own",
          "[local_security_policy][parsers][secedit]") {
    // No '=' on the malformed header line, and no section open yet: dropped outright, same as
    // any other line before the first real section.
    const auto no_section_yet = parse_inf_sections("[Unterminated\nReal = 1\n");
    CHECK(no_section_yet.empty()); // "Real = 1" is also dropped -- still no section open

    // A malformed header line that happens to contain '=', while a real section IS already
    // open: front()=='[' but back()!=']' fails the section-header check, so it falls through
    // to the key=value branch and is recorded as an ordinary key (literal leading '[' and all)
    // in the currently-open section -- never creates a new section. This is the plugin's actual
    // parsing behavior today (locked in by this test), not a defect this PR introduces or fixes.
    const auto misattributed = parse_inf_sections(
        "[System Access]\n"
        "RealKey = 1\n"
        "[Unterminated = oops\n"
        "AnotherKey = 2\n");
    REQUIRE(misattributed.size() == 1); // never created a second section
    const auto& sys = misattributed.at("System Access");
    CHECK(sys.at("RealKey") == "1");
    CHECK(sys.at("AnotherKey") == "2");
    // The malformed line's whole "[Unterminated" prefix became the key, verbatim.
    REQUIRE(sys.find("[Unterminated") != sys.end());
    CHECK(sys.at("[Unterminated") == "oops");
}

// ── kv / PAM / auditd (Linux/macOS file sources) ──────────────────────────────────

TEST_CASE("local_security_policy parse_kv_lines: separators, comments, valueless keys",
          "[local_security_policy][parsers]") {
    const auto kv = parse_kv_lines("# comment\nPASS_MAX_DAYS   99999\n\nFLAG\nEMPTY \t\n", " \t");
    REQUIRE(kv.size() == 3);
    CHECK(kv[0] == std::pair<std::string, std::string>{"PASS_MAX_DAYS", "99999"});
    CHECK(kv[1] == std::pair<std::string, std::string>{"FLAG", ""});
    CHECK(kv[2] == std::pair<std::string, std::string>{"EMPTY", ""});
    const auto eq = parse_kv_lines("minlen = 14\ndcredit=-1\n", " \t=");
    CHECK(eq == KvList{{"minlen", "14"}, {"dcredit", "-1"}});
}

TEST_CASE("local_security_policy PAM: logical-line joining and stack parsing",
          "[local_security_policy][parsers]") {
    // A trailing backslash joins the next physical line with one blank; a bare '#'
    // (even mid-continuation) cuts the rest of the physical line and ENDS the logical
    // line -- no further continuation.
    const auto lines = pam_logical_lines("password requisite pam_pwquality.so \\\n"
                                          "    retry=3 # a trailing comment\n"
                                          "password required pam_unix.so\n");
    REQUIRE(lines.size() == 2);
    CHECK(lines[0] == "password requisite pam_pwquality.so retry=3");
    CHECK(lines[1] == "password required pam_unix.so");

    const auto pam = parse_pam_lines(
        "password requisite pam_pwquality.so retry=3\n"
        "password [success=1 default=ignore] pam_unix.so obscure use_authtok\n"
        "@include common-auth\n"
        "malformed line\n" // fewer than 3 tokens: module ends up empty, dropped
        "-account required pam_unix.so\n");
    REQUIRE(pam.size() == 3);
    CHECK(pam[0].type == "password");
    CHECK(pam[0].control == "requisite");
    CHECK(pam[0].module == "pam_pwquality.so");
    CHECK(pam[0].args == "retry=3");
    CHECK(pam[1].control == "[success=1 default=ignore]");
    CHECK(pam[1].module == "pam_unix.so");
    CHECK(pam[1].args == "obscure use_authtok");
    CHECK(pam[2].type == "account"); // leading '-' (silence-on-failure) is dropped
    CHECK(pam[2].module == "pam_unix.so");
}

TEST_CASE("local_security_policy auditd: rule vs control-directive counting",
          "[local_security_policy][parsers]") {
    const auto c = parse_auditd_rules_count(
        "# audit rules\n"
        "-D\n"
        "-b 8192\n"
        "-w /etc/shadow -p wa -k identity\n"
        "-a always,exit -F arch=b64 -S execve\n"
        "-e 1\n"
        "some_unknown_directive foo\n");
    CHECK(c.total == 6);
    CHECK(c.watches == 1);
    CHECK(c.syscalls == 1);
    CHECK(c.control == 3); // -D, -b, -e
    CHECK(c.unmodelled == 1);
    CHECK(c.rules() == 3); // watches + syscalls + unmodelled, never counting -D/-b/-e
    REQUIRE(c.enabled.has_value());
    CHECK(*c.enabled == "1");

    CHECK(audit_enabled_token("0") == "disabled");
    CHECK(audit_enabled_token("1") == "enabled");
    CHECK(audit_enabled_token("2") == "immutable");
    CHECK(audit_enabled_token("9") == "unmodelled:9");

    const auto none = parse_auditd_rules_count("# nothing but comments\n\n");
    CHECK(none.total == 0);
    CHECK_FALSE(none.enabled.has_value());
}

TEST_CASE("local_security_policy errno classification: absent vs denied vs failed",
          "[local_security_policy][parsers]") {
    for (const int e : {ENOENT, ENOTDIR}) {
        const auto o = classify_read_errno(e);
        CHECK(o.cls == ReadClass::Absent);
        CHECK(o.token.empty());
    }
    for (const int e : {EACCES, EPERM}) {
        const auto o = classify_read_errno(e);
        CHECK(o.cls == ReadClass::Denied);
        CHECK(o.token == "permission_denied");
    }
    CHECK(classify_read_errno(ELOOP).token == "symlink_loop");
    CHECK(classify_read_errno(EIO).token == "io_error");
    CHECK(classify_read_errno(kReadOversized).token == "oversized");
    CHECK(classify_read_errno(kReadNotRegular).token == "not_regular");
    CHECK(classify_read_errno(kReadEmbeddedNul).token == "embedded_nul");
    const auto other = classify_read_errno(9999);
    CHECK(other.cls == ReadClass::Failed);
    CHECK(other.token == "errno_9999");
}

TEST_CASE("local_security_policy select_status: PERMISSION_DENIED only when nothing else failed",
          "[local_security_policy][parsers]") {
    CHECK(select_status(3, 0, 0) == PolicyStatus::Ok);
    CHECK(select_status(0, 2, 0) == PolicyStatus::PermissionDenied);
    CHECK(select_status(0, 0, 1) == PolicyStatus::Constrained);
    CHECK(select_status(1, 1, 0) == PolicyStatus::Constrained); // some readable, some denied
    CHECK(select_status(1, 1, 1) == PolicyStatus::Constrained);
    CHECK(select_status(0, 0, 0) == PolicyStatus::Ok);
}

// ── row formatters ─────────────────────────────────────────────────────────────────

TEST_CASE("local_security_policy row formatters: escaping and shape",
          "[local_security_policy][parsers]") {
    CHECK(format_kv_row("password_policy", "PASS_MAX_DAYS", "99999", "/etc/login.defs") ==
          "password_policy|PASS_MAX_DAYS|99999|/etc/login.defs");
    CHECK(format_kv_row("password_policy", "FLAG", "", "/etc/login.defs") ==
          "password_policy|FLAG|present|/etc/login.defs"); // empty value -> "present"
    CHECK(format_kv_row("audit_policy", "a|b", "c\r\nd", "/etc/x") ==
          "audit_policy|a\\|b|c  d|/etc/x"); // pipe escaped, newline folded to spaces
}

// ── collect_file_policy (injected FileReader/DirLister) ───────────────────────────

TEST_CASE("local_security_policy collect_file_policy: password_policy over injected files",
          "[local_security_policy][parsers]") {
    auto rd = reader_from({{"/etc/login.defs", "PASS_MAX_DAYS 99999\nPASS_MIN_DAYS 0\n"}});
    // pwquality.conf and every PAM alternative are absent (ENOENT via reader_from's default).
    const auto c = collect_file_policy(FileFlavor::Linux, LocalPolicyAction::Password, rd, empty_dir());
    CHECK(c.status == PolicyStatus::Ok); // absence is not a failure
    bool saw_max_days = false, saw_pam_absent = false;
    for (const auto& r : c.rows) {
        if (r == "password_policy|PASS_MAX_DAYS|99999|/etc/login.defs") saw_max_days = true;
        if (r == "password_policy|source_state|absent|/etc/pam.d") saw_pam_absent = true;
    }
    CHECK(saw_max_days);
    CHECK(saw_pam_absent); // every PAM alternative absent collapses to one absent row
}


TEST_CASE("local_security_policy collect_file_policy: a refused read is PERMISSION_DENIED, never absent",
          "[local_security_policy][parsers]") {
    auto rd = [](const std::string& path) -> FileRead {
        if (path == "/etc/login.defs") return {EACCES, {}};
        return {ENOENT, {}}; // everything else genuinely absent
    };
    const auto c = collect_file_policy(FileFlavor::Linux, LocalPolicyAction::Password, rd, empty_dir());
    CHECK(c.status == PolicyStatus::PermissionDenied);
    bool saw_denied = false;
    for (const auto& r : c.rows)
        if (r == "password_policy|source_state|unreadable:permission_denied|/etc/login.defs")
            saw_denied = true;
    CHECK(saw_denied);
}

TEST_CASE("local_security_policy collect_file_policy: macOS never reads Linux password/lockout paths",
          "[local_security_policy][parsers]") {
    // FAIL CLOSED: this arm is unreachable via the real macOS leg (it routes to pwpolicy
    // first), but collect_file_policy itself must still refuse rather than silently read
    // /etc/login.defs on a Mac.
    bool called = false;
    auto rd = [&](const std::string&) -> FileRead {
        called = true;
        return {ENOENT, {}};
    };
    const auto c = collect_file_policy(FileFlavor::Macos, LocalPolicyAction::Password, rd, empty_dir());
    CHECK(c.status == PolicyStatus::Constrained);
    CHECK(c.reason == "unsupported_action");
    CHECK(c.rows.empty());
    CHECK_FALSE(called);
}

TEST_CASE("local_security_policy collect_file_policy: Linux audit_policy over injected audit.rules",
          "[local_security_policy][parsers]") {
    // Same fixture shape as the "auditd: rule vs control-directive counting" pure-parser
    // case above, driven this time through the actual collect_file_policy(Audit) wiring --
    // nothing previously exercised this switch arm (only the underlying parser helper).
    auto rd = reader_from({{"/etc/audit/audit.rules", "# audit rules\n"
                                                       "-D\n"
                                                       "-b 8192\n"
                                                       "-w /etc/shadow -p wa -k identity\n"
                                                       "-a always,exit -F arch=b64 -S execve\n"
                                                       "-e 1\n"
                                                       "some_unknown_directive foo\n"}});
    const auto c = collect_file_policy(FileFlavor::Linux, LocalPolicyAction::Audit, rd, empty_dir());
    CHECK(c.status == PolicyStatus::Ok);
    const std::vector<std::string> expect = {
        "audit_policy|rules|3|/etc/audit/audit.rules",
        "audit_policy|watch_rules|1|/etc/audit/audit.rules",
        "audit_policy|syscall_rules|1|/etc/audit/audit.rules",
        "audit_policy|unmodelled_lines|1|/etc/audit/audit.rules",
        "audit_policy|control_lines|3|/etc/audit/audit.rules",
        "audit_policy|enabled|enabled|/etc/audit/audit.rules",
    };
    for (const auto& row : expect) CHECK(c.rows.end() != std::find(c.rows.begin(), c.rows.end(), row));
    CHECK(c.rows.size() == expect.size()); // arithmetic closes: exactly these six, nothing else
}

TEST_CASE("local_security_policy collect_file_policy: macOS audit_policy over injected audit_control",
          "[local_security_policy][parsers]") {
    // The macOS Audit arm takes a distinct code path from Linux (":" kv lines, not the
    // rule-counting parser) -- previously unexercised at the collector level.
    auto rd = reader_from({{"/etc/security/audit_control", "dir:/var/audit\nflags:lo,aa\n"}});
    const auto c = collect_file_policy(FileFlavor::Macos, LocalPolicyAction::Audit, rd, empty_dir());
    CHECK(c.status == PolicyStatus::Ok);
    bool saw_dir = false, saw_flags = false;
    for (const auto& r : c.rows) {
        if (r == "audit_policy|dir|/var/audit|/etc/security/audit_control") saw_dir = true;
        if (r == "audit_policy|flags|lo,aa|/etc/security/audit_control") saw_flags = true;
    }
    CHECK(saw_dir);
    CHECK(saw_flags);
}

TEST_CASE("local_security_policy collect_file_policy: an embedded NUL is embedded_nul, never a "
          "truncated value",
          "[local_security_policy][parsers]") {
    // checked_read() (read_source's one call site) auto-detects a NUL in an otherwise
    // successful read and converts it to kReadEmbeddedNul -- exercised here through the
    // real injected-reader path, not just the classify_read_errno token-mapping test.
    using namespace std::string_literals;
    auto rd = reader_from({{"/etc/login.defs", "PASS_MAX_DAYS 99999\0trailing"s}});
    const auto c = collect_file_policy(FileFlavor::Linux, LocalPolicyAction::Password, rd, empty_dir());
    CHECK(c.status == PolicyStatus::Constrained);
    bool saw_embedded_nul = false;
    for (const auto& r : c.rows)
        if (r == "password_policy|source_state|unreadable:embedded_nul|/etc/login.defs")
            saw_embedded_nul = true;
    CHECK(saw_embedded_nul);
}

TEST_CASE("local_security_policy Tally: the row cap reserves its own slot for the truncation marker",
          "[local_security_policy][parsers]") {
    detail::Tally t;
    t.marker_prefix = "password_policy";
    for (std::size_t i = 0; i < kMaxRows; ++i) t.row("password_policy|k" + std::to_string(i) + "|v|src");
    REQUIRE(t.rows.size() == kMaxRows); // never exceeds the cap, even by one
    CHECK(t.rows.back() == "password_policy|source_state|unreadable:row_cap|password_policy");
    CHECK(t.capped);
    CHECK(t.acc.reason() == "row_cap");
    // A further row is dropped outright, not appended past the cap.
    t.row("password_policy|extra|v|src");
    CHECK(t.rows.size() == kMaxRows);
}

TEST_CASE("local_security_policy Tally: the sudoers row cap emits its own 7-field marker",
          "[local_security_policy][parsers][sudoers]") {
    detail::Tally t;
    t.marker_prefix = "sudoers";
    t.marker_fields = 7;
    for (std::size_t i = 0; i < kMaxRows; ++i)
        t.row(format_sudoers_row("/etc/sudoers", {"user_spec", "u" + std::to_string(i), "-", "-", "-"}));
    REQUIRE(t.rows.size() == kMaxRows);
    // The marker keeps the action's own 7-field wire shape: a 4-field kv row here would
    // break the column contract of every sudoers consumer.
    CHECK(t.rows.back() == "sudoers|-|unreadable|-|-|-|row_cap");
    CHECK(std::count(t.rows.back().begin(), t.rows.back().end(), '|') == 6);
    CHECK(t.capped);
    CHECK(t.acc.reason() == "row_cap");
}


// ── pwpolicy (macOS) ───────────────────────────────────────────────────────────────

TEST_CASE("local_security_policy pwpolicy: strip_to_xml drops the banner line",
          "[local_security_policy][parsers][pwpolicy]") {
    const auto stripped = strip_to_xml("Getting global account policies\n<?xml version=\"1.0\"?><plist/>");
    REQUIRE(stripped.has_value());
    CHECK(stripped->starts_with("<?xml"));
    CHECK_FALSE(strip_to_xml("no xml banner here").has_value());
}

TEST_CASE("local_security_policy pwpolicy: run classification", "[local_security_policy][parsers][pwpolicy]") {
    CHECK(classify_pwpolicy_run(RunEnd::SpawnError, false, 0) == "pwpolicy:spawn_error");
    CHECK(classify_pwpolicy_run(RunEnd::Deadline, false, 0) == "pwpolicy:deadline");
    CHECK(classify_pwpolicy_run(RunEnd::Cancelled, false, 0) == "pwpolicy:cancelled");
    CHECK(classify_pwpolicy_run(RunEnd::Signaled, false, 0) == "pwpolicy:signaled");
    CHECK(classify_pwpolicy_run(RunEnd::Other, false, 0) == "pwpolicy:unexpected_termination");
    CHECK(classify_pwpolicy_run(RunEnd::Exited, true, 0) == "pwpolicy:output_truncated");
    CHECK(classify_pwpolicy_run(RunEnd::Exited, false, 1) == "pwpolicy:exit_1");
    CHECK(classify_pwpolicy_run(RunEnd::Exited, false, 0).empty());
}

TEST_CASE("local_security_policy pwpolicy: minimum-length extraction is exact, never guessed",
          "[local_security_policy][parsers][pwpolicy]") {
    CHECK(pwpolicy_min_length("policyAttributePassword matches '.{14,}'") == std::optional<unsigned>{14});
    CHECK(pwpolicy_min_length("policyAttributePassword matches '.{0,}'") == std::optional<unsigned>{0});
    CHECK_FALSE(pwpolicy_min_length("no length expression here").has_value());
    CHECK_FALSE(pwpolicy_min_length(".{,}").has_value());       // no digits
    CHECK_FALSE(pwpolicy_min_length(".{14}").has_value());      // missing the comma
}

TEST_CASE("local_security_policy pwpolicy_rows: category routing, defects, and the clean-none row",
          "[local_security_policy][parsers][pwpolicy]") {
    const PwPolicyItem lock{.category = "policyCategoryAuthentication",
                            .identifier = "loginRateLimit",
                            .content = "policyAttributeFailedAuthentications < 5",
                            .has_content = true};
    const PwPolicyItem pw{.category = "policyCategoryPasswordContent",
                          .identifier = "requireAlpha",
                          .content = "policyAttributePassword matches '.{14,}'",
                          .has_content = true,
                          .params = {{"policyAttributePassword", "x"}, {"autoEnableInSeconds", "300"}}};
    const PwPolicyItem unmodelled_cat{.category = "policyCategorySomethingElse"};
    const PwPolicyItem defective{.category = "policyCategoryPasswordContent",
                                 .identifier = "broken",
                                 .defects = {"malformed_content"}};

    const auto lockout = pwpolicy_rows(LocalPolicyAction::Lockout, {lock, pw, unmodelled_cat});
    bool saw_content = false, saw_unmodelled = false;
    for (const auto& r : lockout.rows) {
        if (r.find("policy_content|policyAttributeFailedAuthentications < 5") != std::string::npos)
            saw_content = true;
        if (r.rfind("lockout_policy|unmodelled_category|policyCategorySomethingElse|", 0) == 0)
            saw_unmodelled = true;
        CHECK(r.find("requireAlpha") == std::string::npos); // the password item never leaks into lockout
    }
    CHECK(saw_content);
    CHECK(saw_unmodelled);
    CHECK(lockout.status == PolicyStatus::Ok);

    const auto password = pwpolicy_rows(LocalPolicyAction::Password, {pw});
    bool saw_attr = false, saw_min_len = false, saw_unmodelled_param = false;
    for (const auto& r : password.rows) {
        if (r.find("policyAttributePassword|x|") != std::string::npos) saw_attr = true;
        if (r.find("minimum_length|14|") != std::string::npos) saw_min_len = true;
        if (r.find("unmodelled_parameter|autoEnableInSeconds=300|") != std::string::npos)
            saw_unmodelled_param = true;
    }
    CHECK(saw_attr);
    CHECK(saw_min_len);
    CHECK(saw_unmodelled_param);

    const auto with_defect = pwpolicy_rows(LocalPolicyAction::Password, {defective});
    CHECK(with_defect.status == PolicyStatus::Constrained);
    CHECK(with_defect.reason.find("pwpolicy:malformed_content") != std::string::npos);
    bool saw_defect_row = false;
    for (const auto& r : with_defect.rows)
        if (r.find("unreadable:malformed_content") != std::string::npos) saw_defect_row = true;
    CHECK(saw_defect_row);

    // An item carrying nothing this action can report is its own shape defect: content genuinely
    // absent (has_content still default-false), no params, no defects.
    const PwPolicyItem empty_item{.category = "policyCategoryPasswordContent", .identifier = "id"};
    const auto empty_result = pwpolicy_rows(LocalPolicyAction::Password, {empty_item});
    CHECK(empty_result.status == PolicyStatus::Constrained);
    bool saw_missing_content = false;
    for (const auto& r : empty_result.rows)
        if (r.find("unreadable:missing_content") != std::string::npos) saw_missing_content = true;
    CHECK(saw_missing_content);

    // A policyContent key that IS present but holds an empty string is a real, present value --
    // never the missing_content shape defect (regression for the has_content/content.empty()
    // conflation this PR's own /code-review functional pass caught, FV-codex-5).
    const PwPolicyItem present_empty_content{
        .category = "policyCategoryPasswordContent", .identifier = "id", .content = "", .has_content = true};
    const auto present_empty_result = pwpolicy_rows(LocalPolicyAction::Password, {present_empty_content});
    CHECK(present_empty_result.status == PolicyStatus::Ok);
    bool saw_present_content = false, saw_false_missing_content = false;
    for (const auto& r : present_empty_result.rows) {
        if (r.find("policy_content|present|") != std::string::npos) saw_present_content = true;
        if (r.find("unreadable:missing_content") != std::string::npos) saw_false_missing_content = true;
    }
    CHECK(saw_present_content);
    CHECK_FALSE(saw_false_missing_content);

    // No matching item and no defect: the clean modal "none" row, never an empty vector.
    const auto none = pwpolicy_rows(LocalPolicyAction::Lockout, {});
    CHECK(none.rows == std::vector<std::string>{"lockout_policy|policies|none|pwpolicy"});
    CHECK(none.status == PolicyStatus::Ok);
}

TEST_CASE("local_security_policy pwpolicy_rows: row growth is capped, mirroring Tally::row "
          "(adversarial-review regression -- a single item's identifier previously repeated "
          "into an unbounded number of parameter rows with no cap at all)",
          "[local_security_policy][parsers][pwpolicy]") {
    KvList many_params;
    for (std::size_t i = 0; i < kMaxRows + 500; ++i)
        many_params.emplace_back("policyAttribute" + std::to_string(i), "x");
    const PwPolicyItem huge{.category = "policyCategoryPasswordContent",
                            .identifier = "huge",
                            .has_content = false,
                            .params = many_params};
    const auto capped = pwpolicy_rows(LocalPolicyAction::Password, {huge});
    CHECK(capped.rows.size() == kMaxRows); // never grows past the cap, ever
    CHECK(capped.status == PolicyStatus::Constrained);
    CHECK(capped.reason.find("row_cap") != std::string::npos);
    CHECK(capped.rows.back() == "password_policy|source_state|unreadable:row_cap|pwpolicy");
}

TEST_CASE("local_security_policy pwpolicy_rows: the row cap's boundary is exact, mirroring "
          "Tally::row's own exact-boundary test (quality-engineer finding -- the overshoot-by-500 "
          "case above proves a cap exists but not that push_row's own `>=` comparison is correct "
          "to the row, the way Tally's sibling test does)",
          "[local_security_policy][parsers][pwpolicy]") {
    // Exactly kMaxRows-1 params -> exactly kMaxRows-1 rows, never triggering the cap at all.
    KvList just_under;
    for (std::size_t i = 0; i < kMaxRows - 1; ++i)
        just_under.emplace_back("policyAttribute" + std::to_string(i), "x");
    const PwPolicyItem under{.category = "policyCategoryPasswordContent",
                             .identifier = "under",
                             .has_content = false,
                             .params = just_under};
    const auto under_result = pwpolicy_rows(LocalPolicyAction::Password, {under});
    CHECK(under_result.rows.size() == kMaxRows - 1); // no marker: never hit the boundary
    CHECK(under_result.status == PolicyStatus::Ok);

    // Exactly kMaxRows params -> the cap triggers on the very last one: kMaxRows-1 real rows
    // plus the marker, exactly kMaxRows total, never kMaxRows+1.
    KvList exactly_at;
    for (std::size_t i = 0; i < kMaxRows; ++i)
        exactly_at.emplace_back("policyAttribute" + std::to_string(i), "x");
    const PwPolicyItem at{.category = "policyCategoryPasswordContent",
                          .identifier = "at",
                          .has_content = false,
                          .params = exactly_at};
    const auto at_result = pwpolicy_rows(LocalPolicyAction::Password, {at});
    CHECK(at_result.rows.size() == kMaxRows);
    CHECK(at_result.status == PolicyStatus::Constrained);
    CHECK(at_result.rows.back() == "password_policy|source_state|unreadable:row_cap|pwpolicy");
}

TEST_CASE("local_security_policy pwpolicy_rows: a huge identifier is truncated before it "
          "becomes `src`, bounding row BYTES independent of the row-count cap "
          "(governance SRE regression -- kMaxRows alone bounds how many times an oversized "
          "identifier repeats, not how large each repetition is)",
          "[local_security_policy][parsers][pwpolicy]") {
    const std::string huge_identifier(kMaxSourceIdentifierBytes * 10, 'x');
    const PwPolicyItem huge_id{.category = "policyCategoryPasswordContent",
                               .identifier = huge_identifier,
                               .content = "no length clause here",
                               .has_content = true};
    const auto result = pwpolicy_rows(LocalPolicyAction::Password, {huge_id});
    REQUIRE(result.rows.size() == 1); // just the policy_content row -- no minimum_length match
    // The row's `src` field carries at most kMaxSourceIdentifierBytes of the identifier plus
    // the "pwpolicy:" prefix -- never the full 2560-byte identifier.
    CHECK(result.rows[0].size() < kMaxSourceIdentifierBytes + 64);
    CHECK(result.rows[0].find(std::string(kMaxSourceIdentifierBytes + 1, 'x')) == std::string::npos);
}

TEST_CASE("local_security_policy pwpolicy_rows: identifier truncation never splits a multibyte "
          "UTF-8 sequence (fjarvis review finding, PR #5069 -- the byte-256 cut previously could "
          "sever a character mid-sequence, reaching the wire as invalid UTF-8)",
          "[local_security_policy][parsers][pwpolicy]") {
    // 254 ASCII bytes, then a 3-byte U+20AC straddling the 256-byte cap (bytes 254-256), then
    // more content so truncation actually triggers. The boundary-safe cut backs off to 254 --
    // the euro sign is excluded WHOLE, never split into dangling continuation bytes.
    std::string identifier(254, 'x');
    identifier += "\xE2\x82\xAC"; // U+20AC
    identifier += "trailing content past the cap, never reached";
    const PwPolicyItem huge_id{.category = "policyCategoryPasswordContent",
                               .identifier = identifier,
                               .content = "no length clause here",
                               .has_content = true};
    const auto result = pwpolicy_rows(LocalPolicyAction::Password, {huge_id});
    REQUIRE(result.rows.size() == 1);
    const std::string expected_src = "pwpolicy:" + std::string(254, 'x');
    CHECK(result.rows[0] == "password_policy|policy_content|no length clause here|" + expected_src);
}

TEST_CASE("local_security_policy join_row: invalid UTF-8 in a value field is sanitized before it "
          "reaches the wire (fjarvis review finding, PR #5069 -- raw /etc file bytes previously "
          "passed through format_kv_row/join_row completely unsanitized)",
          "[local_security_policy][parsers]") {
    // A lone continuation byte (0x80) is never valid UTF-8 on its own -- the shape a
    // non-UTF-8-encoded config file value (Latin-1, or simply corrupt) could carry through
    // e.g. login.defs.
    const std::string invalid_value = std::string("before") + '\x80' + "after";
    const auto row =
        format_kv_row("password_policy", "PASS_MAX_DAYS", invalid_value, "/etc/login.defs");
    CHECK(row.find('\x80') == std::string::npos); // the raw invalid byte never reaches the wire
    CHECK(row == "password_policy|PASS_MAX_DAYS|before?after|/etc/login.defs");
}

TEST_CASE("local_security_policy pwpolicy_rows: minimum_length never leaks into lockout_policy "
          "even when an Authentication item's content coincidentally matches the .{N,} shape "
          "(fjarvis review finding, PR #5069)",
          "[local_security_policy][parsers][pwpolicy]") {
    const PwPolicyItem lock_coincidence{.category = "policyCategoryAuthentication",
                                        .identifier = "coincidence",
                                        .content = "policyAttributeSomething matches '.{14,}'",
                                        .has_content = true};
    const auto result = pwpolicy_rows(LocalPolicyAction::Lockout, {lock_coincidence});
    for (const auto& r : result.rows)
        CHECK(r.find("minimum_length") == std::string::npos);
}

#if defined(__APPLE__)
// ── pwpolicy_plist_to_items (the real CF-XML bridge, macOS only) ───────────────────────────
// Governance quality-engineer finding: every test above drives pwpolicy_rows() with hand-built
// PwPolicyItem structs -- proving the CONSUMER side, never the CF-parsing PRODUCER that actually
// assigns identifier/content/params/defects from real plist bytes. These tests drive real XML
// through CFPropertyListCreateWithData via the actual function, on this real Mac.

TEST_CASE("local_security_policy pwpolicy_plist_to_items: a well-formed plist yields exact "
          "identifier/content/params, no defects",
          "[local_security_policy][parsers][pwpolicy][macos]") {
    using namespace yuzu::local_security_policy;
    static constexpr std::string_view kXml = R"(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>policyCategoryPasswordContent</key>
    <array>
        <dict>
            <key>policyIdentifier</key>
            <string>com.example.minlen</string>
            <key>policyContent</key>
            <string>policyAttributePassword matches '.{8,}+'</string>
            <key>policyParameters</key>
            <dict>
                <key>policyAttributePassword</key>
                <string>x</string>
                <key>autoEnableInSeconds</key>
                <integer>300</integer>
            </dict>
        </dict>
    </array>
</dict>
</plist>)";
    const auto items = pwpolicy_plist_to_items(kXml);
    REQUIRE(items.has_value());
    REQUIRE(items->size() == 1);
    const auto& it = (*items)[0];
    CHECK(it.category == "policyCategoryPasswordContent");
    CHECK(it.identifier == "com.example.minlen");
    CHECK(it.has_content);
    CHECK(it.content == "policyAttributePassword matches '.{8,}+'");
    CHECK(it.defects.empty());
    REQUIRE(it.params.size() == 2);
    std::map<std::string, std::string> params(it.params.begin(), it.params.end());
    CHECK(params.at("policyAttributePassword") == "x");
    CHECK(params.at("autoEnableInSeconds") == "300"); // CFNumber -> text, via cf_scalar_text
}

TEST_CASE("local_security_policy pwpolicy_plist_to_items: every documented defect shape is "
          "recorded on an item, never dropped and never guessed",
          "[local_security_policy][parsers][pwpolicy][macos]") {
    using namespace yuzu::local_security_policy;
    static constexpr std::string_view kXml = R"(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>policyCategoryMalformed</key>
    <string>a category value that is not an array is itself the defect</string>
    <key>policyCategoryPasswordContent</key>
    <array>
        <string>an array element that is not a dictionary</string>
        <dict>
            <key>policyIdentifier</key>
            <dict><key>nested</key><string>not a scalar</string></dict>
            <key>policyContent</key>
            <array><string>also not a scalar</string></array>
            <key>policyParameters</key>
            <string>not a dictionary either</string>
        </dict>
        <dict>
            <key>policyParameters</key>
            <dict>
                <key>badParam</key>
                <array><string>a param value that is not a scalar</string></array>
            </dict>
        </dict>
    </array>
</dict>
</plist>)";
    const auto items = pwpolicy_plist_to_items(kXml);
    REQUIRE(items.has_value());
    REQUIRE(items->size() == 4); // 1 malformed_category + 3 array elements

    // Category-level defect: the whole category's value was not an array.
    const auto cat_defect =
        std::find_if(items->begin(), items->end(),
                    [](const auto& it) { return it.category == "policyCategoryMalformed"; });
    REQUIRE(cat_defect != items->end());
    CHECK(cat_defect->defects == std::vector<std::string>{"malformed_category"});

    // Array-element-level defect: a non-dictionary element in an otherwise-valid array.
    const auto policy_defect = std::find_if(
        items->begin(), items->end(), [](const auto& it) {
            return it.category == "policyCategoryPasswordContent" && !it.defects.empty() &&
                   it.defects.front() == "malformed_policy";
        });
    REQUIRE(policy_defect != items->end());

    // Field-shape defects: identifier/content/parameters each present but the wrong CF type.
    const auto shape_defect =
        std::find_if(items->begin(), items->end(), [](const auto& it) {
            return std::find(it.defects.begin(), it.defects.end(), "malformed_identifier") !=
                   it.defects.end();
        });
    REQUIRE(shape_defect != items->end());
    CHECK(std::find(shape_defect->defects.begin(), shape_defect->defects.end(),
                    "malformed_content") != shape_defect->defects.end());
    CHECK(std::find(shape_defect->defects.begin(), shape_defect->defects.end(),
                    "malformed_parameters") != shape_defect->defects.end());
    CHECK_FALSE(shape_defect->has_content); // malformed_content never sets has_content

    // A parameter value that is present but not a scalar.
    const auto param_defect =
        std::find_if(items->begin(), items->end(), [](const auto& it) {
            return std::find(it.defects.begin(), it.defects.end(), "malformed_parameter_value") !=
                   it.defects.end();
        });
    REQUIRE(param_defect != items->end());
    CHECK(param_defect->params.empty()); // the one param present was the malformed one
}

TEST_CASE("local_security_policy pwpolicy_plist_to_items: a non-dictionary root and unparseable "
          "bytes are both nullopt, never an empty-but-successful result",
          "[local_security_policy][parsers][pwpolicy][macos]") {
    using namespace yuzu::local_security_policy;
    CHECK_FALSE(pwpolicy_plist_to_items("not xml at all").has_value());
    CHECK_FALSE(pwpolicy_plist_to_items("").has_value());
    static constexpr std::string_view kArrayRoot = R"(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array><string>the root is an array, not the documented dictionary shape</string></array>
</plist>)";
    CHECK_FALSE(pwpolicy_plist_to_items(kArrayRoot).has_value());
}
#endif // defined(__APPLE__)

TEST_CASE("local_security_policy sudoers: correctly-spelled aliases are their own kind",
          "[local_security_policy][parsers][sudoers]") {
    for (const auto& [kw, name] :
         {std::pair{std::string{"User_Alias"}, std::string{"ADMINS"}},
          std::pair{std::string{"Host_Alias"}, std::string{"WEBSERVERS"}},
          std::pair{std::string{"Runas_Alias"}, std::string{"OP"}},
          std::pair{std::string{"Cmnd_Alias"}, std::string{"SHELLS"}}}) {
        const auto rows = parse_sudoers(kw + " " + name + " = /bin/sh\n");
        INFO("keyword: " << kw);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].kind == "alias");
        CHECK(rows[0].subject == kw + ":" + name);
        CHECK(rows[0].commands == "/bin/sh");
    }
}

// Regression for #4997 finding 2: `Cmd_Alias` (sudo-legal alternate spelling of
// `Cmnd_Alias`) was NOT in the alias-keyword set, so this line fell through to
// parse_user_spec and was silently accepted as an ordinary user grant for a
// fictitious principal "Cmd_Alias" on host "SHELLS" -- under a clean OK/FULL result,
// no failure token anywhere.
TEST_CASE("local_security_policy sudoers: Cmd_Alias is recognised, never a fictitious grant",
          "[local_security_policy][parsers][sudoers]") {
    const auto rows = parse_sudoers("Cmd_Alias SHELLS = /bin/sh\n");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].kind == "alias");
    CHECK(rows[0].subject == "Cmd_Alias:SHELLS");
    CHECK(rows[0].commands == "/bin/sh");
    CHECK_FALSE(rows[0].kind == "user_spec"); // the bug this closes
    CHECK_FALSE(rows[0].subject == "Cmd_Alias@SHELLS");
}

TEST_CASE("local_security_policy sudoers: Defaults, includes, comments",
          "[local_security_policy][parsers][sudoers]") {
    const auto rows = parse_sudoers(
        "Defaults env_reset\n"
        "Defaults:alice !authenticate\n"
        "#include /etc/sudoers.extra\n"
        "@includedir /etc/sudoers.d\n"
        "# a whole-line comment, never a row\n"
        // A trailing `#1000` (a digit follows the '#') is a uid reference, not a
        // comment -- so it is lexed as its own trailing word, which the user_spec
        // grammar has no place for after the command list; the whole line is
        // unmodelled, but with the `#1000` text kept, never swallowed as a comment.
        "alice ALL = /bin/ls #1000\n");
    REQUIRE(rows.size() == 5);
    CHECK(rows[0].kind == "defaults");
    CHECK(rows[0].subject == "-");
    CHECK(rows[0].commands == "env_reset");
    CHECK(rows[1].kind == "defaults");
    CHECK(rows[1].subject == "user:alice");
    CHECK(rows[1].commands == "!authenticate");
    CHECK(rows[2].kind == "include");
    CHECK(rows[2].commands == "/etc/sudoers.extra");
    CHECK(rows[3].kind == "includedir");
    CHECK(rows[3].commands == "/etc/sudoers.d");
    CHECK(rows[4].kind == "unmodelled");
    CHECK(rows[4].commands.find("#1000") != std::string::npos); // kept, not treated as a comment
}

// Regression for #4997 finding 3: command_args's break set wrongly included `=`
// (correct only for command()'s own PATH-name scan just above it), truncating a
// legal `--flag=value` sudoers command argument at the `=`.
TEST_CASE("local_security_policy sudoers: command_args keeps '=' in an argument",
          "[local_security_policy][parsers][sudoers]") {
    const auto rows =
        parse_sudoers("deploy ALL=(root) NOPASSWD: /usr/bin/rsync --rsync-path=x\n");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].kind == "user_spec");
    CHECK(rows[0].subject == "deploy@ALL");
    CHECK(rows[0].runas == "root");
    CHECK(rows[0].nopasswd == "true");
    CHECK(rows[0].commands == "/usr/bin/rsync --rsync-path=x"); // NOT cut at '='

    // A VAR=value environment-style argument survives the same way.
    const auto env_rows = parse_sudoers("alice ALL = /usr/bin/make VAR=value target\n");
    REQUIRE(env_rows.size() == 1);
    CHECK(env_rows[0].commands == "/usr/bin/make VAR=value target");
}

TEST_CASE("local_security_policy sudoers: NOPASSWD/PASSWD clause splitting, runas carry-over",
          "[local_security_policy][parsers][sudoers]") {
    const auto rows = parse_sudoers("alice ALL = (root) NOPASSWD: /bin/ls, PASSWD: /bin/cat\n");
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].subject == "alice@ALL");
    CHECK(rows[0].runas == "root");
    CHECK(rows[0].nopasswd == "true");
    CHECK(rows[0].commands == "/bin/ls");
    CHECK(rows[1].subject == "alice@ALL");
    CHECK(rows[1].runas == "root"); // carried across the same clause
    CHECK(rows[1].nopasswd == "false");
    CHECK(rows[1].commands == "/bin/cat");

    // Same NOPASSWD state, several commands: one entry, comma-joined.
    const auto same = parse_sudoers("bob ALL = NOPASSWD: /bin/ls, /bin/cat\n");
    REQUIRE(same.size() == 1);
    CHECK(same[0].commands == "/bin/ls, /bin/cat");

    // Two Host_List clauses on one line (colon-separated) are two independent entries.
    const auto multi = parse_sudoers("carol HOST1 = /bin/ls : HOST2 = /bin/cat\n");
    REQUIRE(multi.size() == 2);
    CHECK(multi[0].subject == "carol@HOST1");
    CHECK(multi[1].subject == "carol@HOST2");
}

// Regression for #4997 finding 2 (the fail-safe half): a grammatically malformed
// grant that still carries an undecoded NOPASSWD:/PASSWD: tag is reported `unmodelled`
// with the tag intact in its text -- the caller (sudoers_file) must treat this as a
// failure, never a silent `false`.
TEST_CASE("local_security_policy sudoers: an undecoded NOPASSWD tag is unmodelled, tag intact",
          "[local_security_policy][parsers][sudoers]") {
    // No command follows the tag -- ungrammatical, so parse_user_spec returns nullopt
    // and the NOPASSWD: tag (already lexed into the statement text) survives verbatim.
    const auto rows = parse_sudoers("alice ALL = NOPASSWD:\n");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].kind == "unmodelled");
    CHECK(rows[0].commands.find("NOPASSWD:") != std::string::npos);
    CHECK(detail::has_passwd_tag(rows[0].commands));
}

TEST_CASE("local_security_policy sudoers: has_passwd_tag word-boundary and spacing",
          "[local_security_policy][parsers][sudoers]") {
    CHECK(detail::has_passwd_tag("NOPASSWD:"));
    CHECK(detail::has_passwd_tag("PASSWD:"));
    CHECK(detail::has_passwd_tag("NOPASSWD  :")); // blanks before the colon still count
    CHECK_FALSE(detail::has_passwd_tag("MYNOPASSWD:")); // part of a longer identifier
    CHECK_FALSE(detail::has_passwd_tag("/bin/ls"));
    CHECK_FALSE(detail::has_passwd_tag(""));
}

TEST_CASE("local_security_policy sudoers: quoted strings, IPv6 hosts, digests, negation",
          "[local_security_policy][parsers][sudoers]") {
    const auto rows = parse_sudoers(
        R"(alice ::1 = CWD="/tmp:x" sha256:abcd1234 !!/bin/ls)"
        "\n");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].subject == "alice@::1"); // an IPv6 host, colon kept intact
    CHECK(rows[0].commands.find(R"(CWD="/tmp:x")") != std::string::npos); // quoted value untouched
    CHECK(rows[0].commands.find("sha256:abcd1234") != std::string::npos);
    CHECK(rows[0].commands.find("/bin/ls") != std::string::npos); // even '!' count cancels out
}

TEST_CASE("local_security_policy sudoers.d: name filtering", "[local_security_policy][parsers][sudoers]") {
    CHECK_FALSE(sudoers_dir_entry_ignored("readable"));
    CHECK(sudoers_dir_entry_ignored("webadmins.rpmnew"));
    CHECK(sudoers_dir_entry_ignored("backup~"));
    CHECK_FALSE(sudoers_dir_entry_ignored(""));
}

// ── errno classification / status selection ───────────────────────────────────────

TEST_CASE("local_security_policy collect_file_policy: sudoers end to end, undecoded tag is CONSTRAINED",
          "[local_security_policy][parsers]") {
    auto rd = reader_from({{"/etc/sudoers", "alice ALL = NOPASSWD:\n"}});
    const auto c = collect_file_policy(FileFlavor::Linux, LocalPolicyAction::Sudoers, rd, empty_dir());
    CHECK(c.status == PolicyStatus::Constrained);
    CHECK(c.reason.find("/etc/sudoers:undecoded_passwd_tag") != std::string::npos);
    bool saw_unmodelled = false;
    for (const auto& r : c.rows)
        if (r.rfind("sudoers|/etc/sudoers|unmodelled|", 0) == 0) saw_unmodelled = true;
    CHECK(saw_unmodelled);
}

TEST_CASE("local_security_policy collect_file_policy: sudoers.d name filtering and per-file reads",
          "[local_security_policy][parsers]") {
    auto rd = reader_from({{"/etc/sudoers", "alice ALL = /bin/ls\n"},
                           {"/etc/sudoers.d/readable", "bob ALL = /bin/cat\n"}});
    const auto dl = [](const std::string& path) -> DirList {
        if (path == "/etc/sudoers.d")
            return {0, {"backup~", "readable", "webadmins.rpmnew"}, false};
        return {};
    };
    const auto c = collect_file_policy(FileFlavor::Linux, LocalPolicyAction::Sudoers, rd, dl);
    CHECK(c.status == PolicyStatus::Ok);
    int ignored = 0, real = 0;
    for (const auto& r : c.rows) {
        if (r.find("|ignored|") != std::string::npos) ++ignored;
        if (r.rfind("sudoers|/etc/sudoers.d/readable|user_spec|", 0) == 0) ++real;
    }
    CHECK(ignored == 2); // backup~ (trailing '~') and webadmins.rpmnew (a '.')
    CHECK(real == 1);
}

TEST_CASE("local_security_policy collect_file_policy: sudoers.d listing failure is a 7-field unreadable row",
          "[local_security_policy][parsers][sudoers]") {
    auto rd = reader_from({{"/etc/sudoers", "alice ALL = /bin/ls\n"}});
    const auto dl = [](const std::string& path) -> DirList {
        if (path == "/etc/sudoers.d") return {EACCES, {}, false};
        return {};
    };
    const auto c = collect_file_policy(FileFlavor::Linux, LocalPolicyAction::Sudoers, rd, dl);
    // /etc/sudoers itself read fine, so a refused directory is CONSTRAINED, not PERMISSION_DENIED.
    CHECK(c.status == PolicyStatus::Constrained);
    CHECK(c.reason.find("sudoers.d:permission_denied") != std::string::npos);
    bool saw = false;
    for (const auto& r : c.rows)
        if (r == "sudoers|/etc/sudoers.d|unreadable|-|-|-|permission_denied") saw = true;
    CHECK(saw); // never a failure without its row, never a 4-field fallback
}

TEST_CASE("local_security_policy collect_file_policy: a truncated sudoers.d listing is put on the wire",
          "[local_security_policy][parsers][sudoers]") {
    auto rd = reader_from({{"/etc/sudoers", "alice ALL = /bin/ls\n"},
                           {"/etc/sudoers.d/readable", "bob ALL = /bin/cat\n"}});
    const auto dl = [](const std::string& path) -> DirList {
        if (path == "/etc/sudoers.d") return {0, {"readable"}, true};
        return {};
    };
    const auto c = collect_file_policy(FileFlavor::Linux, LocalPolicyAction::Sudoers, rd, dl);
    CHECK(c.status == PolicyStatus::Constrained);
    CHECK(c.reason.find("sudoers.d:truncated") != std::string::npos);
    bool saw_marker = false, saw_real = false;
    for (const auto& r : c.rows) {
        if (r == "sudoers|/etc/sudoers.d|unreadable|-|-|-|truncated") saw_marker = true;
        if (r.rfind("sudoers|/etc/sudoers.d/readable|user_spec|", 0) == 0) saw_real = true;
    }
    CHECK(saw_marker);
    CHECK(saw_real); // the names that WERE listed are still read
}

// sudo's lexer: an escaped separator inside a command never splits the clause, and a `#`
// comment -- glued to the previous word or not -- ends the line even when it ends in a
// backslash, so the next physical line is its own statement. Checked against sudo 1.9.16.
TEST_CASE("local_security_policy sudoers: escaped separators and comments before a continuation",
          "[local_security_policy][parsers][sudoers]") {
    for (const char* text : {"alice ALL=NOPASSWD:/bin/ls#comment\\\nbob ALL=/bin/cat\n",
                             "alice ALL=NOPASSWD:/bin/ls # comment\\\nbob ALL=/bin/cat\n"}) {
        INFO(text);
        const auto rows = parse_sudoers(text);
        REQUIRE(rows.size() == 2);
        CHECK(rows[0].subject == "alice@ALL");
        CHECK(rows[0].nopasswd == "true");
        CHECK(rows[0].commands == "/bin/ls");
        CHECK(rows[1].subject == "bob@ALL"); // not swallowed into the comment's continuation
        CHECK(rows[1].nopasswd == "false");
        CHECK(rows[1].commands == "/bin/cat");
    }
    const auto colon = parse_sudoers("alice ALL=(root) NOPASSWD:/bin/echo a\\:b, /bin/cat\n");
    REQUIRE(colon.size() == 1); // the escaped ':' is not a tag separator
    CHECK(colon[0].runas == "root");
    CHECK(colon[0].nopasswd == "true");
    CHECK(colon[0].commands == "/bin/echo a\\:b, /bin/cat");
    const auto comma = parse_sudoers("alice ALL=/bin/echo a\\,b, NOPASSWD:/bin/id\n");
    REQUIRE(comma.size() == 2); // the escaped ',' stays inside the first command
    CHECK(comma[0].commands == "/bin/echo a\\,b");
    CHECK(comma[0].nopasswd == "false");
    CHECK(comma[1].commands == "/bin/id");
    CHECK(comma[1].nopasswd == "true");
    const auto hash = parse_sudoers("alice ALL=/bin/echo a\\#b\n");
    REQUIRE(hash.size() == 1); // an escaped '#' is not a comment
    CHECK(hash[0].commands == "/bin/echo a\\#b");
}

TEST_CASE("local_security_policy secedit: audit setting bitmask", "[local_security_policy][parsers][secedit]") {
    CHECK(secedit_audit_setting("0") == "none");
    CHECK(secedit_audit_setting("1") == "success");
    CHECK(secedit_audit_setting("2") == "failure");
    CHECK(secedit_audit_setting("3") == "success_failure");
    CHECK(secedit_audit_setting("9") == "unmodelled:9");
}

TEST_CASE("local_security_policy secedit: export completeness requires the signed final [Version]",
          "[local_security_policy][parsers][secedit]") {
    const std::string full =
        "[System Access]\nMinimumPasswordLength = 8\n"
        "[Event Audit]\nAuditSystemEvents = 3\n"
        "[Version]\nsignature=\"$CHICAGO$\"\nRevision=1\n";
    CHECK(secedit_export_complete(full));
    // Case-insensitive section/key names -- the INF rule.
    const std::string lower =
        "[system access]\nminimumpasswordlength = 8\n"
        "[event audit]\n"
        "[version]\nSIGNATURE=\"$CHICAGO$\"\n";
    CHECK(secedit_export_complete(lower));
    CHECK_FALSE(secedit_export_complete("[System Access]\n[Version]\nsignature=\"$CHICAGO$\"\n")); // no Event Audit
    CHECK_FALSE(secedit_export_complete(full + "[Extra]\nx=1\n")); // Version not the FINAL section
    CHECK_FALSE(secedit_export_complete("[System Access]\n[Event Audit]\n[Version]\n")); // unsigned
    CHECK_FALSE(secedit_export_complete(""));
}

TEST_CASE("local_security_policy secedit_policy_rows: audit, password, lockout, unsupported",
          "[local_security_policy][parsers][secedit]") {
    const auto sections = parse_inf_sections(
        "[System Access]\nMinimumPasswordLength = 14\nLockoutBadCount = 0\n"
        "[Event Audit]\nAuditSystemEvents = 3\nAuditLogonEvents = 1\n");
    const auto pw = secedit_policy_rows("password_policy", sections);
    CHECK(pw.failure_token.empty());
    bool saw_len = false, saw_absent_history = false;
    for (const auto& r : pw.rows) {
        if (r == "password_policy|MinimumPasswordLength|14|secedit") saw_len = true;
        if (r == "password_policy|PasswordHistorySize|absent|secedit") saw_absent_history = true;
    }
    CHECK(saw_len);
    CHECK(saw_absent_history); // a key the export doesn't carry reads the modal "absent"

    const auto lock = secedit_policy_rows("lockout_policy", sections);
    bool saw_zero = false;
    for (const auto& r : lock.rows)
        if (r == "lockout_policy|LockoutBadCount|0|secedit") saw_zero = true;
    CHECK(saw_zero);

    const auto audit = secedit_policy_rows("audit_policy", sections);
    CHECK(audit.rows == std::vector<std::string>{"audit_policy|AuditLogonEvents|success|secedit",
                                                  "audit_policy|AuditSystemEvents|success_failure|secedit"});

    const auto unsup = secedit_policy_rows("sudoers", sections);
    CHECK(unsup.failure_token == "secedit:unsupported_action");
    CHECK(unsup.rows.empty());

    const auto missing = secedit_policy_rows("audit_policy", InfSections{});
    CHECK(missing.failure_token == "secedit:section_missing_event_audit");
}

// Regression for #4997 finding 4: the per-key row lookup used a plain
// std::map<std::string,...> ordered/looked-up by exact bytes, so a present but
// differently-cased section or key silently read as the modal "absent" under a
// clean OK/FULL result.
TEST_CASE("local_security_policy secedit: case-insensitive section/key lookup",
          "[local_security_policy][parsers][secedit]") {
    const auto sections = parse_inf_sections("[system access]\nminimumpasswordlength = 14\n");
    const auto pw = secedit_policy_rows("password_policy", sections);
    CHECK(pw.failure_token.empty());
    bool saw_len = false;
    for (const auto& r : pw.rows) {
        CHECK(r != "password_policy|MinimumPasswordLength|absent|secedit"); // the bug this closes
        if (r == "password_policy|MinimumPasswordLength|14|secedit") saw_len = true;
    }
    CHECK(saw_len);
}

TEST_CASE("local_security_policy sweep: scratch directory name validation",
          "[local_security_policy][parsers][sweep]") {
    CHECK(is_scratch_dir_name("local_security_policy-0123456789abcdef0123456789ABCDEF"));
    CHECK_FALSE(is_scratch_dir_name("local_security_policy-tooshort"));
    CHECK_FALSE(is_scratch_dir_name("local_security_policy-0123456789abcdef0123456789abcdeg")); // 'g' not hex
    CHECK_FALSE(is_scratch_dir_name("other_plugin-0123456789abcdef0123456789abcdef"));
    CHECK_FALSE(is_scratch_dir_name("local_security_policy-"));
    CHECK_FALSE(is_scratch_dir_name(""));
}

TEST_CASE("local_security_policy sweep: staleness is strict, exact equality is fresh",
          "[local_security_policy][parsers][sweep]") {
    CHECK_FALSE(is_stale(1000, 1000 + 3600, 3600));       // exactly the threshold: fresh
    CHECK(is_stale(1000, 1000 + 3601, 3600));             // one second past: stale
    CHECK_FALSE(is_stale(1000, 500, 3600));               // a future-dated mtime (clock skew): fresh
}

TEST_CASE("local_security_policy sweep: candidate classification covers all four states",
          "[local_security_policy][parsers][sweep]") {
    const std::string name = "local_security_policy-0123456789abcdef0123456789abcdef";
    CHECK(classify_sweep_candidate("not_a_match", true, 0, 4000, 3600) == SweepCandidate::NotCandidate);
    CHECK(classify_sweep_candidate(name, false, 0, 4000, 3600) == SweepCandidate::NotCandidate); // not a directory
    CHECK(classify_sweep_candidate(name, true, std::nullopt, 4000, 3600) == SweepCandidate::NoMtime);
    CHECK(classify_sweep_candidate(name, true, 3999, 4000, 3600) == SweepCandidate::Fresh);
    CHECK(classify_sweep_candidate(name, true, 0, 3601, 3600) == SweepCandidate::Stale);
}

TEST_CASE("local_security_policy sweep: ownership gate and log-worthiness",
          "[local_security_policy][parsers][sweep]") {
    CHECK(sweep_may_remove(true));
    CHECK_FALSE(sweep_may_remove(false));

    CHECK_FALSE(sweep_worth_logging({})); // an all-zero steady-state pass says nothing
    ScratchSweepResult removed_one;
    removed_one.removed = 1;
    CHECK(sweep_worth_logging(removed_one));
    ScratchSweepResult failed_one;
    failed_one.failed = 1;
    CHECK(sweep_worth_logging(failed_one));
    ScratchSweepResult foreign;
    foreign.skipped_not_ours = 1;
    CHECK(sweep_worth_logging(foreign));
    ScratchSweepResult deferred;
    deferred.deferred = 1;
    CHECK(sweep_worth_logging(deferred));
    ScratchSweepResult fresh_only;
    fresh_only.skipped_fresh = 3; // fresh candidates alone are not worth a log line
    CHECK_FALSE(sweep_worth_logging(fresh_only));

    ScratchSweepResult r;
    r.removed = 2;
    r.failed = 1;
    r.skipped_fresh = 3;
    r.skipped_not_ours = 1;
    r.deferred = 1;
    CHECK(format_sweep_summary(r) ==
          "scratch_sweep: removed 2 failed 1 fresh 3 not_ours 1 deferred 1");
}

TEST_CASE("local_security_policy sweep: secedit run/read classification",
          "[local_security_policy][parsers][sweep]") {
    CHECK(classify_export_run(RunEnd::SpawnError, 0) == "secedit:spawn_error");
    CHECK(classify_export_run(RunEnd::Deadline, 0) == "secedit:deadline");
    CHECK(classify_export_run(RunEnd::Cancelled, 0) == "secedit:cancelled");
    CHECK(classify_export_run(RunEnd::Signaled, 0) == "secedit:signaled");
    CHECK(classify_export_run(RunEnd::Other, 0) == "secedit:unexpected_termination");
    CHECK(classify_export_run(RunEnd::Exited, 0).empty());
    CHECK(classify_export_run(RunEnd::Exited, 1) == "secedit:exit_1");

    const auto denied = classify_export_read_error(kWin32AccessDenied);
    CHECK(denied.permission_denied);
    CHECK(denied.token == "secedit:access_denied");
    for (const auto err : {kWin32FileNotFound, kWin32PathNotFound}) {
        const auto missing = classify_export_read_error(err);
        CHECK_FALSE(missing.permission_denied);
        CHECK(missing.token == "secedit:output_missing");
    }
    const auto other = classify_export_read_error(1234);
    CHECK_FALSE(other.permission_denied);
    CHECK(other.token == "secedit:read_1234");

    CHECK_FALSE(classify_export_object(false, 100).has_value()); // usable
    REQUIRE(classify_export_object(true, 100).has_value());
    CHECK(classify_export_object(true, 100)->token == "secedit:output_not_regular");
    REQUIRE(classify_export_object(false, kExportMaxBytes + 1).has_value());
    CHECK(classify_export_object(false, kExportMaxBytes + 1)->token == "secedit:output_oversized");

    CHECK(classify_export_read_length(100, 100).empty());
    CHECK(classify_export_read_length(100, 50) == "secedit:output_short_read");

    CHECK(classify_decoded_export(std::nullopt) == "secedit:decode_failed");
    CHECK(classify_decoded_export(std::optional<std::string>{""}) == "secedit:decode_failed");
    CHECK(classify_decoded_export(std::optional<std::string>{std::string("a\0b", 3)}) ==
          "secedit:embedded_nul");
    CHECK(classify_decoded_export(std::optional<std::string>{"clean text"}).empty());
}
