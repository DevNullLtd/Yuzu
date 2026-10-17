/**
 * test_remote_access_audit_config_parsers.cpp -- pure tests for the remote_access_audit
 * plugin's sshd_config tokeniser, directive-order parser, Include pattern expansion, service
 * output parsers and row formatters. Portable, no I/O.
 *
 * Fixture provenance (labelled per case):
 *   REAL CAPTURE   -- kDebianSshdConfig: /etc/ssh/sshd_config from openssh-server 1:10.0p1-7+deb13u4
 *                     on Debian GNU/Linux 13 (trixie) aarch64, 2026-10-17; kMacSshd* : /etc/ssh/
 *                     sshd_config, sshd_config.d/100-macos.conf and the target of the
 *                     crypto.conf symlink on macOS 26.6.2 (OpenSSH_10.3p1), 2026-10-17; the
 *                     `launchctl print-disabled system` output from the same Mac. Comment lines
 *                     (which the parser ignores) and third-party launchd labels are elided.
 *                     The `systemctl is-enabled` strings and exit codes were captured on Ubuntu
 *                     26.04.1, systemd 259.5 (kingsley WSL), 2026-10-17.
 *   CONSTRUCTED    -- every other specimen, built from sshd_config(5) and the OpenSSH source
 *                     (servconf.c, misc.c); none is a capture.
 */
#include <catch2/catch_test_macros.hpp>

#include "remote_access_audit_config_parsers.hpp"

#include <map>
#include <string>
#include <vector>

using namespace yuzu::remote_access_audit;

namespace {

// REAL CAPTURE (Debian 13, comments elided)
constexpr const char* kDebianSshdConfig =
    "Include /etc/ssh/sshd_config.d/*.conf\n"
    "KbdInteractiveAuthentication no\n"
    "UsePAM yes\n"
    "X11Forwarding yes\n"
    "PrintMotd no\n"
    "AcceptEnv LANG LC_* COLORTERM NO_COLOR\n"
    "Subsystem\tsftp\t/usr/lib/openssh/sftp-server\n";

// REAL CAPTURE (macOS 26.6.2, comments elided; tabs preserved)
constexpr const char* kMacSshdConfig =
    "Include /etc/ssh/sshd_config.d/*\n"
    "AuthorizedKeysFile\t.ssh/authorized_keys\n"
    "Subsystem\tsftp\t/usr/libexec/sftp-server\n";
constexpr const char* kMacSshd100 =
    "UsePAM yes\n"
    "AcceptEnv LANG LC_*\n"
    "Include /etc/ssh/crypto.conf\n";
constexpr const char* kMacCrypto =
    "Ciphers ^aes128-gcm@openssh.com,aes256-gcm@openssh.com\n"
    "KexAlgorithms ^ecdh-sha2-nistp256\n"
    "MACs ^hmac-sha2-256-etm@openssh.com,hmac-sha2-256\n";

// REAL CAPTURE (macOS 26.6.2 `launchctl print-disabled system`; third-party labels elided)
constexpr const char* kLaunchctlPrintDisabled =
    "disabled services = {\n"
    "\t\"com.apple.AEServer\" => enabled\n"
    "\t\"com.apple.screensharing\" => enabled\n"
    "\t\"com.apple.CSCSupportd\" => disabled\n"
    "\t\"com.apple.ftpd\" => disabled\n"
    "\t\"com.openssh.sshd\" => enabled\n"
    "}\n";

/// Parses `text`, resolving each Include from `files` SYNCHRONOUSLY at the directive's
/// position (what audit_config's sink does), and records every directive seen.
struct Run {
    SshdConfigState st;
    std::vector<IncludeDirective> seen;
};

void parse_into(Run& run, const std::map<std::string, std::string>& files, std::string_view text,
                std::string_view origin) {
    parse_sshd_config(text, origin, run.st, [&](const IncludeDirective& d) {
        run.seen.push_back(d);
        if (d.in_match)
            return;
        const auto it = files.find(d.pattern);
        if (it != files.end())
            parse_into(run, files, it->second, include_origin(d.pattern));
    });
}

Run parse(std::string_view text, const std::map<std::string, std::string>& files = {}) {
    Run r;
    parse_into(r, files, text, "sshd_config");
    return r;
}

const ScalarSlot& slot(const SshdConfigState& st, std::string_view key) {
    for (std::size_t i = 0; i < kScalarKeys.size(); ++i) {
        if (kScalarKeys[i] == key)
            return st.scalar[i];
    }
    FAIL("unknown scalar key");
    return st.scalar[0];
}

std::string row_for(const std::vector<std::string>& rows, std::string_view key) {
    for (const auto& r : rows) {
        if (r.rfind("config|" + std::string(key) + "|", 0) == 0)
            return r;
    }
    return {};
}

} // namespace

TEST_CASE("remote_access_audit config: the Debian 13 stock sshd_config parses to its effective lines",
          "[remote_access_audit][config]") {
    const auto run = parse(kDebianSshdConfig);
    CHECK(slot(run.st, "kbdinteractiveauthentication").value == "no");
    CHECK(slot(run.st, "usepam").value == "yes");
    CHECK_FALSE(slot(run.st, "permitrootlogin").set);
    CHECK(run.st.match_blocks == 0);
    REQUIRE(run.seen.size() == 1);
    CHECK(run.seen[0].pattern == "/etc/ssh/sshd_config.d/*.conf");
    CHECK_FALSE(run.seen[0].in_match);
    bool ov = false;
    const auto rows = config_rows(run.st, true, ov);
    CHECK(rows.size() == 13);
    CHECK(row_for(rows, "usepam") == "config|usepam|yes|sshd_config");
    CHECK(row_for(rows, "permitrootlogin") == "config|permitrootlogin|-|-");
    CHECK(row_for(rows, "authorizedkeysfile") == "config|authorizedkeysfile|default|-");
}

TEST_CASE("remote_access_audit config: the macOS stock config, followed through both Includes, in order",
          "[remote_access_audit][config]") {
    const std::map<std::string, std::string> files{
        {"/etc/ssh/sshd_config.d/*", kMacSshd100}, {"/etc/ssh/crypto.conf", kMacCrypto}};
    // The glob is resolved by the caller as 100-macos.conf; this fake keys by the pattern.
    const auto run = parse(kMacSshdConfig, files);
    CHECK(slot(run.st, "usepam").value == "yes");
    CHECK(slot(run.st, "usepam").origin == "include:*"); // fake keys by pattern
    CHECK(run.st.akf_set);
    CHECK(akf_summary(run.st) == "custom:1");
    REQUIRE(run.seen.size() == 2);
    CHECK(run.seen[1].pattern == "/etc/ssh/crypto.conf");
    CHECK(run.seen[1].origin == "include:*");
}

TEST_CASE("remote_access_audit config: first value wins in DIRECTIVE ORDER across an Include",
          "[remote_access_audit][config]") {
    // CONSTRUCTED: servconf.c parses the included file at the Include directive's position.
    const std::map<std::string, std::string> files{{"a.conf", "PermitRootLogin no\n"}};
    const auto before = parse("Include a.conf\nPermitRootLogin yes\n", files);
    CHECK(slot(before.st, "permitrootlogin").value == "no");
    CHECK(slot(before.st, "permitrootlogin").origin == "include:a.conf");
    const auto after = parse("PermitRootLogin yes\nInclude a.conf\n", files);
    CHECK(slot(after.st, "permitrootlogin").value == "yes");
    CHECK(slot(after.st, "permitrootlogin").origin == "sshd_config");
}

TEST_CASE("remote_access_audit config: Key=Value, quotes, comments, CR, case-insensitive keywords",
          "[remote_access_audit][config]") {
    // CONSTRUCTED
    const auto run = parse(
        "permitrootlogin=prohibit-password\r\n"
        "PasswordAuthentication = \"no\"\n"
        "PUBKEYAUTHENTICATION yes # trailing comment\n"
        "  \t PermitEmptyPasswords\tno\n"
        "UsePAM \"y\\\"es\"\n"
        "# ChallengeResponseAuthentication yes\n"
        "ChallengeResponseAuthentication no\n"
        "\n");
    CHECK(slot(run.st, "permitrootlogin").value == "prohibit-password");
    CHECK(slot(run.st, "passwordauthentication").value == "no");
    CHECK(slot(run.st, "pubkeyauthentication").value == "yes");
    CHECK(slot(run.st, "permitemptypasswords").value == "no");
    CHECK(slot(run.st, "usepam").value == "y\"es");
    // the deprecated alias fills the kbdinteractiveauthentication slot
    CHECK(slot(run.st, "kbdinteractiveauthentication").value == "no");
    CHECK_FALSE(run.st.invalid_quotes);
}

TEST_CASE("remote_access_audit config: an unterminated quote skips the line and says so",
          "[remote_access_audit][config]") {
    const auto run = parse("PermitRootLogin \"yes\nPasswordAuthentication no\n");
    CHECK(run.st.invalid_quotes);
    CHECK_FALSE(slot(run.st, "permitrootlogin").set);
    CHECK(slot(run.st, "passwordauthentication").value == "no");
    // a keyword with an unmatched quote is skipped without the invalid-quotes flag (sshd: NULL keyword)
    const auto kw = parse("\"PermitRootLogin yes\n");
    CHECK_FALSE(slot(kw.st, "permitrootlogin").set);
}

TEST_CASE("remote_access_audit config: list keywords sum their arguments, Port appends",
          "[remote_access_audit][config]") {
    const auto run = parse(
        "AllowUsers alice bob\nAllowUsers carol\nDenyGroups wheel\nPort 22\nPort 2222\n");
    CHECK(run.st.lists[0].n == 3);
    CHECK(run.st.lists[3].n == 1);
    CHECK(run.st.lists[1].n == 0);
    bool ov = false;
    const auto rows = config_rows(run.st, true, ov);
    CHECK(row_for(rows, "port") == "config|port|22,2222|sshd_config");
    CHECK(row_for(rows, "allowusers_count") == "config|allowusers_count|3|sshd_config");
    CHECK(row_for(rows, "allowgroups_count") == "config|allowgroups_count|0|-");
}

TEST_CASE("remote_access_audit config: a Match block is counted and nothing in it is applied",
          "[remote_access_audit][config]") {
    const auto run = parse(
        "Match User bob\n"
        "  PermitRootLogin yes\n"
        "  AuthorizedKeysFile /srv/keys/%u\n"
        "  Include extra.conf\n");
    CHECK(run.st.match_blocks == 1);
    CHECK_FALSE(slot(run.st, "permitrootlogin").set);
    CHECK(run.st.akf_in_match);
    CHECK_FALSE(run.st.akf_set);
    REQUIRE(run.seen.size() == 1);
    CHECK(run.seen[0].in_match);
    // Match state is per file: the line before it still applies, and a new file starts global.
    const std::map<std::string, std::string> files{{"m.conf", "Match all\n"}};
    const auto lk = parse("Include m.conf\nPermitRootLogin no\n", files);
    CHECK(slot(lk.st, "permitrootlogin").value == "no");
}

TEST_CASE("remote_access_audit config: the authorizedkeysfile row never carries a path",
          "[remote_access_audit][config]") {
    bool ov = false;
    auto text_of = [&](std::string_view cfg) {
        const auto run = parse(cfg);
        return row_for(config_rows(run.st, true, ov), "authorizedkeysfile");
    };
    CHECK(text_of("") == "config|authorizedkeysfile|default|-");
    CHECK(text_of("AuthorizedKeysFile none\n") == "config|authorizedkeysfile|none|sshd_config");
    CHECK(text_of("AuthorizedKeysFile NONE\n") == "config|authorizedkeysfile|none|sshd_config");
    const auto custom = text_of("AuthorizedKeysFile /etc/ssh/customer-alice/authorized_keys %h/.ssh/k\n");
    CHECK(custom == "config|authorizedkeysfile|custom:2|sshd_config");
    CHECK(custom.find("customer-alice") == std::string::npos);
    // "none" must stand alone, and the first global directive wins as a whole
    CHECK(text_of("AuthorizedKeysFile a none\n") == "config|authorizedkeysfile|default|-");
    CHECK(text_of("AuthorizedKeysFile a b c\nAuthorizedKeysFile none\n") ==
          "config|authorizedkeysfile|custom:3|sshd_config");
}

TEST_CASE("remote_access_audit config: a missing sshd_config reports every value as absent",
          "[remote_access_audit][config]") {
    const auto run = parse("PermitRootLogin yes\n");
    bool ov = false;
    const auto rows = config_rows(run.st, /*config_read=*/false, ov);
    REQUIRE(rows.size() == 13);
    CHECK(row_for(rows, "permitrootlogin") == "config|permitrootlogin|-|-");
    CHECK(row_for(rows, "match_blocks") == "config|match_blocks|-|-");
}

TEST_CASE("remote_access_audit config: expand_include_pattern", "[remote_access_audit][config]") {
    using K = IncludeSpec::Kind;
    CHECK(expand_include_pattern("a.conf").kind == K::single);
    CHECK(expand_include_pattern("a.conf").path == "/etc/ssh/a.conf"); // sshd prefixes SSHDIR
    const auto g = expand_include_pattern("/etc/ssh/sshd_config.d/*.conf");
    CHECK(g.kind == K::glob);
    CHECK(g.dir == "/etc/ssh/sshd_config.d");
    CHECK(g.leaf == "*.conf");
    const auto rel = expand_include_pattern("conf.d/*");
    CHECK(rel.dir == "/etc/ssh/conf.d");
    CHECK(expand_include_pattern("/etc/ssh/crypto.conf").kind == K::single);
    CHECK(expand_include_pattern("~/x.conf").kind == K::unsupported);
    CHECK(expand_include_pattern("/etc/*/x.conf").kind == K::unsupported); // wildcard in a directory
    CHECK(expand_include_pattern("/etc/ssh/a\\*.conf").kind == K::unsupported);
    CHECK(expand_include_pattern("").kind == K::unsupported);
}

TEST_CASE("remote_access_audit config: systemctl is-enabled output", "[remote_access_audit][service]") {
    // REAL CAPTURE strings (Ubuntu 26.04.1, systemd 259.5): enabled / disabled / not-found / static /
    // masked-runtime / indirect / alias / generated / transient. Exit codes are NOT consulted.
    for (const char* s : {"enabled", "disabled", "not-found", "static", "masked-runtime", "indirect", "alias",
                          "generated", "transient"}) {
        const auto f = parse_systemctl_is_enabled(std::string(s) + "\n");
        CHECK(f.state == s);
        CHECK(f.cause.empty());
    }
    // CONSTRUCTED from systemctl(1): the states the capture host did not show
    for (const char* s : {"enabled-runtime", "linked", "linked-runtime", "masked", "bad"}) {
        const auto f = parse_systemctl_is_enabled(std::string(s) + "\n");
        CHECK(f.state == s);
        CHECK(f.cause.empty());
    }
    CHECK(kSystemctlStates.size() == 14);
    CHECK(parse_systemctl_is_enabled("enabled\r\n").state == "enabled");
    CHECK(parse_systemctl_is_enabled("  disabled \n").state == "disabled");
    const auto empty = parse_systemctl_is_enabled("");
    CHECK(empty.state == "unknown");
    CHECK(empty.cause == "no_output");
    const auto junk = parse_systemctl_is_enabled("enabled-junk\n");
    CHECK(junk.state == "unknown");
    CHECK(junk.cause == "unrecognised_output");
    CHECK(parse_systemctl_is_enabled("Enabled\n").cause == "unrecognised_output"); // case-sensitive
    CHECK(parse_systemctl_is_enabled("\nenabled\n").cause == "no_output");          // first line only
}

TEST_CASE("remote_access_audit config: launchctl print-disabled for one exact label",
          "[remote_access_audit][service]") {
    CHECK(looks_like_print_disabled(kLaunchctlPrintDisabled));
    CHECK(parse_print_disabled_label(kLaunchctlPrintDisabled, "com.openssh.sshd") == LaunchState::enabled);
    CHECK(parse_print_disabled_label(kLaunchctlPrintDisabled, "com.apple.ftpd") == LaunchState::disabled);
    CHECK(parse_print_disabled_label(kLaunchctlPrintDisabled, "com.openssh.ssh") == LaunchState::absent);
    CHECK(parse_print_disabled_label(kLaunchctlPrintDisabled, "com.openssh.sshdx") == LaunchState::absent);
    // CONSTRUCTED: exact value tokens, CR trimmed
    CHECK(parse_print_disabled_label("\"x\" => enabled\r\n", "x") == LaunchState::enabled);
    CHECK(parse_print_disabled_label("\"x\" => enabledx\n", "x") == LaunchState::absent);
    CHECK(parse_print_disabled_label("\"x\" => disabled-junk\n", "x") == LaunchState::absent);
    CHECK(parse_print_disabled_label("", "x") == LaunchState::absent);
    CHECK_FALSE(looks_like_print_disabled("usage: launchctl ...\n"));
}

TEST_CASE("remote_access_audit config: row formatters escape and cut", "[remote_access_audit][config]") {
    bool ov = false;
    CHECK(config_row("k", "a|b", "sshd_config", ov) == "config|k|a\\|b|sshd_config");
    CHECK_FALSE(ov);
    const auto big = config_row("k", std::string(5000, 'x'), "o", ov);
    CHECK(ov);
    CHECK(big.size() == std::string("config|k||o").size() + kMaxFieldBytes);
    CHECK(config_row("k", "", "", ov) == "config|k|-|-");
    CHECK(config_row("k", std::string("a\0b", 3), "o", ov) == "config|k|a?b|o"); // NUL scrubbed
    CHECK(service_row("ssh.service", "enabled", "systemctl_is_enabled") ==
          "service|ssh.service|enabled|systemctl_is_enabled");
    CHECK(source_row("homes", SourceState::read, 3) == "source|homes|read|3");
    CHECK(source_row("homes", SourceState::refused, std::nullopt) == "source|homes|refused|-");
}
