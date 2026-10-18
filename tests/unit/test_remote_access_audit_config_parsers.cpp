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
 *                     26.04.1, systemd 259.5 (kingsley WSL), 2026-10-17; the missing-unit line on
 *                     debian:12 (systemd 252.39) and ubuntu:22.04 (systemd 249.11) containers,
 *                     2026-10-17, where it is printed on STDERR with stdout empty and exit 1.
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
    CHECK(rows.size() == 14);
    CHECK(row_for(rows, "gssapiauthentication") == "config|gssapiauthentication|-|-");
    CHECK(row_for(rows, "usepam") == "config|usepam|yes|sshd_config");
    CHECK(row_for(rows, "permitrootlogin") == "config|permitrootlogin|-|-");
}

TEST_CASE("remote_access_audit config: the macOS stock config, followed through both Includes, in order",
          "[remote_access_audit][config]") {
    const std::map<std::string, std::string> files{
        {"/etc/ssh/sshd_config.d/*", kMacSshd100}, {"/etc/ssh/crypto.conf", kMacCrypto}};
    // The glob is resolved by the caller as 100-macos.conf; this fake keys by the pattern.
    const auto run = parse(kMacSshdConfig, files);
    CHECK(slot(run.st, "usepam").value == "yes");
    CHECK(akf_summary(run.st) == "custom:1");
    REQUIRE(run.seen.size() == 2);
    CHECK(run.seen[1].pattern == "/etc/ssh/crypto.conf");
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

TEST_CASE("remote_access_audit config: AuthorizedKeysFile tokens are capped, the count stays honest",
          "[remote_access_audit][config]") {
    std::string at_cap = "AuthorizedKeysFile";
    for (std::size_t i = 0; i < kMaxAuthorizedKeysFileTokens; ++i)
        at_cap += " .ssh/k" + std::to_string(i);
    auto run = parse(at_cap + "\n");
    CHECK(run.st.akf.size() == kMaxAuthorizedKeysFileTokens);
    CHECK(run.st.akf_count == kMaxAuthorizedKeysFileTokens);

    // one over the cap: the first kMaxAuthorizedKeysFileTokens are kept, the rest dropped and flagged
    run = parse(at_cap + " .ssh/extra\n");
    CHECK(run.st.akf.size() == kMaxAuthorizedKeysFileTokens);
    CHECK(run.st.akf.back() == ".ssh/k99");
    CHECK(run.st.akf_count == kMaxAuthorizedKeysFileTokens + 1);
    bool ov = false;
    CHECK(row_for(config_rows(run.st, true, ov), "authorizedkeysfile") == "config|authorizedkeysfile|custom:101|sshd_config");
}

// MUTATION: dropping a keyword from kOtherCredentialKeys, or reading its value instead of its first
// occurrence, leaves a host that trusts a CA / runs a key command reading as fully `supported`.
TEST_CASE("remote_access_audit config: credential sources the plugin does not read are flagged by presence",
          "[remote_access_audit][config]") {
    // live: each keyword at global scope, with a real-looking value, sets the flag
    for (const char* line : {"TrustedUserCAKeys /etc/ssh/ca.pub", "AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys",
                             "AuthorizedPrincipalsFile .ssh/principals", "AuthorizedPrincipalsCommand /usr/bin/p %u",
                             "AuthenticationMethods publickey,password", "HostbasedAuthentication yes",
                             "trustedusercakeys=/etc/ssh/ca.pub", "  authorizedkeyscommand /x"}) {
        INFO(line);
        const auto run = parse(std::string(line) + "\n");
        CHECK(run.st.other_credential_sources);
    }
    // inert: absent, the disabling/default value, a commented line
    for (const char* text : {"", "PermitRootLogin no\n", "AuthorizedKeysCommand none\n", "AuthorizedKeysCommand NONE\n",
                             "AuthorizedPrincipalsFile none\n", "AuthorizedPrincipalsCommand none\n",
                             "AuthenticationMethods any\n", "HostbasedAuthentication no\n",
                             "#TrustedUserCAKeys /etc/ssh/ca.pub\n", "TrustedUserCAKeys\n"}) {
        INFO(text);
        CHECK_FALSE(parse(text).st.other_credential_sources);
    }
    // first occurrence wins, as for every sshd keyword: `none` first leaves a later value ignored
    CHECK_FALSE(parse("AuthorizedKeysCommand none\nAuthorizedKeysCommand /x\n").st.other_credential_sources);
    CHECK(parse("AuthorizedKeysCommand /x\nAuthorizedKeysCommand none\n").st.other_credential_sources);
    // a Match-scoped directive is not global: counted by match_blocks, not flagged
    CHECK_FALSE(parse("Match User bob\n  TrustedUserCAKeys /etc/ssh/ca.pub\n").st.other_credential_sources);
    // an Include'd file is part of the global config
    const std::map<std::string, std::string> files{{"/etc/ssh/ca.conf", "TrustedUserCAKeys /etc/ssh/ca.pub\n"}};
    CHECK(parse("Include /etc/ssh/ca.conf\n", files).st.other_credential_sources);
    // the flag carries no value or path into any row
    const auto run = parse("TrustedUserCAKeys /etc/ssh/zq-ca-9731.pub\n");
    bool ov = false;
    for (const auto& r : config_rows(run.st, true, ov))
        CHECK(r.find("zq-ca-9731") == std::string::npos);
}

TEST_CASE("remote_access_audit config: a missing sshd_config reports every value as absent",
          "[remote_access_audit][config]") {
    const auto run = parse("PermitRootLogin yes\n");
    bool ov = false;
    const auto rows = config_rows(run.st, /*config_read=*/false, ov);
    REQUIRE(rows.size() == 14);
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
    // The first nine are REAL CAPTURE strings (Ubuntu 26.04.1, systemd 259.5); the last five are
    // CONSTRUCTED from systemctl(1). A state word is read whatever the exit code.
    for (const char* s :
         {"enabled", "disabled", "not-found", "static", "masked-runtime", "indirect", "alias",
          "generated", "transient", "enabled-runtime", "linked", "linked-runtime", "masked", "bad"}) {
        const auto f = parse_systemctl_is_enabled(std::string(s) + "\n", 0, "ssh.service");
        CHECK(f.state == s);
        CHECK(f.cause.empty());
    }
    CHECK(kSystemctlStates.size() == 14);
    CHECK(parse_systemctl_is_enabled("enabled\r\n", 0, "ssh.service").state == "enabled");
    CHECK(parse_systemctl_is_enabled("  disabled \n", 1, "ssh.service").state == "disabled");
    const auto empty = parse_systemctl_is_enabled("", 1, "ssh.service");
    CHECK(empty.state == "unknown");
    CHECK(empty.cause == "no_output");
    const auto junk = parse_systemctl_is_enabled("enabled-junk\n", 0, "ssh.service");
    CHECK(junk.state == "unknown");
    CHECK(junk.cause == "unrecognised_output");
    CHECK(parse_systemctl_is_enabled("Enabled\n", 0, "ssh.service").cause == "unrecognised_output"); // case-sensitive
    CHECK(parse_systemctl_is_enabled("\nenabled\n", 0, "ssh.service").cause == "no_output");          // first line only
}

// MUTATION: dropping the stderr branch (or reading stdout only) makes every unit of a host without
// that sshd unit `no_output`, so a Debian/Ubuntu/RHEL host with sshd.service absent was permanently CONSTRAINED.
TEST_CASE("remote_access_audit config: a missing unit is not-found only on systemd's exact stderr line",
          "[remote_access_audit][service]") {
    // REAL CAPTURE (debian:12 systemd 252.39 and ubuntu:22.04 systemd 249.11): stdout empty, exit 1,
    // this single line on stderr (the runner merges it into the captured output).
    constexpr const char* kMissing = "Failed to get unit file state for ssh.service: No such file or directory\n";
    const auto f = parse_systemctl_is_enabled(kMissing, 1, "ssh.service");
    CHECK(f.state == "not-found");
    CHECK(f.cause.empty());
    CHECK(parse_systemctl_is_enabled("Failed to get unit file state for ssh.socket: No such file or directory\n", 1,
                                     "ssh.socket")
              .state == "not-found");
    // narrow: the unit must be the one asked about, the exit non-zero, and the line exactly that
    CHECK(parse_systemctl_is_enabled(kMissing, 1, "sshd.service").cause == "unrecognised_output");
    CHECK(parse_systemctl_is_enabled(kMissing, 0, "ssh.service").cause == "unrecognised_output");
    CHECK(parse_systemctl_is_enabled(kMissing, 1, "").cause == "unrecognised_output");
    CHECK(parse_systemctl_is_enabled("Failed to connect to bus: No such file or directory\n", 1, "ssh.service")
              .cause == "unrecognised_output");
    CHECK(parse_systemctl_is_enabled("Failed to get unit file state for ssh.service: Permission denied\n", 1,
                                     "ssh.service")
              .cause == "unrecognised_output");
    CHECK(parse_systemctl_is_enabled("xFailed to get unit file state for ssh.service: No such file or directory\n", 1,
                                     "ssh.service")
              .cause == "unrecognised_output");
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
    // the homes row alone carries the skipped-home count: `-` is "no eligibility probe" or "not listed"
    CHECK(homes_source_row(SourceState::read, 3, 1) == "source|homes|read|3|1");
    CHECK(homes_source_row(SourceState::read, 3, 0) == "source|homes|read|3|0");
    CHECK(homes_source_row(SourceState::read, 3, std::nullopt) == "source|homes|read|3|-");
    CHECK(homes_source_row(SourceState::refused, std::nullopt, std::nullopt) == "source|homes|refused|-|-");
}
