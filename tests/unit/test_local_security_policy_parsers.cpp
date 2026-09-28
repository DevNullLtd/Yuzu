/**
 * test_local_security_policy_parsers.cpp -- pure tests for the local_security_policy
 * plugin's PAM/login.defs/auditd parsers and pwpolicy row mapping. Runs on every OS:
 * nothing here touches the filesystem, the registry or a process.
 *
 * The sudoers lexer, secedit INI decode/mapping and Windows scratch-sweep decisions are
 * PLANNED, follow as their own PR (see local_security_policy_legs.hpp's banner) -- their
 * tests are not in this file; PR4 restores them.
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
    // The 7-field sudoers truncation-marker shape is PLANNED, follows as its own PR (the
    // Sudoers action is out of scope for this PR's Tally -- see legs.hpp's banner).
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

