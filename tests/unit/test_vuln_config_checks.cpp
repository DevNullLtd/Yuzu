/**
 * test_vuln_config_checks.cpp -- Pure Linux config-check decisions (#4961).
 *
 * A read that failed must surface as UNREADABLE (the check could not run), never
 * as the empty/unexpected-value finding. Covers the pure checks in
 * config_checks.hpp and the portable stream readers' fault detection. Portable:
 * no file or process access, so it runs on every OS.
 */

#include "config_checks.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cerrno>
#include <sstream>
#include <string>
#include <vector>

using namespace yuzu::vuln;

namespace {

const ReadResult kEacces = std::unexpected(EACCES);

LinesResult lines(std::vector<std::string> v) {
    return v;
}

} // namespace

TEST_CASE("errno_name: known table and fallback", "[vuln][config]") {
    CHECK(errno_name(EACCES) == "eacces");
    CHECK(errno_name(EPERM) == "eperm");
    CHECK(errno_name(ENOENT) == "enoent");
    CHECK(errno_name(EIO) == "eio");
    CHECK(errno_name(ENOTDIR) == "enotdir");
    CHECK(errno_name(EISDIR) == "eisdir");
    CHECK(errno_name(12345) == "errno_12345");
}

// ── ASLR ────────────────────────────────────────────────────────────────────

TEST_CASE("aslr_check: unreadable is UNREADABLE with path and cause", "[vuln][config]") {
    auto r = aslr_check(kEacces);
    CHECK(r.severity == "UNREADABLE");
    CHECK(r.title == "ASLR (Address Space Layout Randomization)");
    CHECK(r.detail == "/proc/sys/kernel/randomize_va_space: eacces");
    CHECK_FALSE(r.passed);
}

TEST_CASE("aslr_check: read values keep today's rows", "[vuln][config]") {
    auto ok = aslr_check(ReadResult{"2"});
    CHECK(ok.severity == "INFO");
    CHECK(ok.detail == "Full randomization enabled (value=2)");
    CHECK(ok.passed);

    auto bad = aslr_check(ReadResult{"1"});
    CHECK(bad.severity == "HIGH");
    CHECK(bad.title == "ASLR (Address Space Layout Randomization)");
    CHECK(bad.detail == "Not fully enabled (value=1) - should be 2");
    CHECK_FALSE(bad.passed);

    auto empty = aslr_check(ReadResult{""});
    CHECK(empty.severity == "HIGH");
    CHECK(empty.detail == "Not fully enabled (value=) - should be 2");
    CHECK_FALSE(empty.passed);
}

// ── suid_dumpable ───────────────────────────────────────────────────────────

TEST_CASE("suid_dumpable_check: unreadable is UNREADABLE with path and cause", "[vuln][config]") {
    auto r = suid_dumpable_check(kEacces);
    CHECK(r.severity == "UNREADABLE");
    CHECK(r.title == "SUID Core Dumps");
    CHECK(r.detail == "/proc/sys/fs/suid_dumpable: eacces");
    CHECK_FALSE(r.passed);
}

TEST_CASE("suid_dumpable_check: read values keep today's rows", "[vuln][config]") {
    auto ok = suid_dumpable_check(ReadResult{"0"});
    CHECK(ok.severity == "INFO");
    CHECK(ok.detail == "Restricted (suid_dumpable=0)");
    CHECK(ok.passed);

    auto bad = suid_dumpable_check(ReadResult{"2"});
    CHECK(bad.severity == "MEDIUM");
    CHECK(bad.title == "SUID Core Dumps");
    CHECK(bad.detail == "Not restricted (suid_dumpable=2) - SUID programs may dump core");
    CHECK_FALSE(bad.passed);

    auto empty = suid_dumpable_check(ReadResult{""});
    CHECK(empty.severity == "MEDIUM");
    CHECK(empty.detail == "Not restricted (suid_dumpable=) - SUID programs may dump core");
}

// ── SSH root login ──────────────────────────────────────────────────────────

TEST_CASE("ssh_root_login_check: directives", "[vuln][config]") {
    auto yes = ssh_root_login_check(lines({"Port 22", "PermitRootLogin yes"}));
    CHECK(yes.severity == "HIGH");
    CHECK(yes.title == "SSH Root Login");
    CHECK(yes.detail == "PermitRootLogin is set to yes - direct root access via SSH is enabled");
    CHECK_FALSE(yes.passed);

    auto no = ssh_root_login_check(lines({"PermitRootLogin no"}));
    CHECK(no.severity == "INFO");
    CHECK(no.detail == "PermitRootLogin is set to no");
    CHECK(no.passed);

    auto neither = ssh_root_login_check(lines({}));
    CHECK(neither.severity == "MEDIUM");
    CHECK(neither.detail ==
          "PermitRootLogin not explicitly set - may default to prohibit-password");
    CHECK_FALSE(neither.passed);
}

TEST_CASE("ssh_root_login_check: commented-out line is ignored", "[vuln][config]") {
    auto r = ssh_root_login_check(lines({"# PermitRootLogin yes", "  \t#PermitRootLogin yes"}));
    CHECK(r.severity == "MEDIUM");
}

TEST_CASE("ssh_root_login_check: absent config is not applicable, other errors UNREADABLE",
          "[vuln][config]") {
    auto absent = ssh_root_login_check(LinesResult{std::unexpected(ENOENT)});
    CHECK(absent.severity == "INFO");
    CHECK(absent.detail == "/etc/ssh/sshd_config not present; check not applicable");
    CHECK(absent.passed);

    auto eio = ssh_root_login_check(LinesResult{std::unexpected(EIO)});
    CHECK(eio.severity == "UNREADABLE");
    CHECK(eio.detail == "/etc/ssh/sshd_config: eio");
    CHECK_FALSE(eio.passed);

    auto denied = ssh_root_login_check(LinesResult{std::unexpected(EACCES)});
    CHECK(denied.severity == "UNREADABLE");
    CHECK(denied.detail == "/etc/ssh/sshd_config: eacces");
}

// ── SSH password authentication ─────────────────────────────────────────────

TEST_CASE("ssh_password_auth_check: neither directive emits no row", "[vuln][config]") {
    CHECK_FALSE(ssh_password_auth_check(lines({"Port 22", "# PasswordAuthentication yes"}))
                    .has_value());
    CHECK_FALSE(ssh_password_auth_check(lines({})).has_value());
}

TEST_CASE("ssh_password_auth_check: directives", "[vuln][config]") {
    auto yes = ssh_password_auth_check(lines({"PasswordAuthentication yes"}));
    REQUIRE(yes.has_value());
    CHECK(yes->severity == "MEDIUM");
    CHECK(yes->title == "SSH Password Authentication");
    CHECK(yes->detail == "Enabled - consider using key-based authentication only");
    CHECK_FALSE(yes->passed);

    auto no = ssh_password_auth_check(lines({"PasswordAuthentication no"}));
    REQUIRE(no.has_value());
    CHECK(no->severity == "INFO");
    CHECK(no->detail == "Disabled - key-based auth only");
    CHECK(no->passed);
}

TEST_CASE("ssh_password_auth_check: absent config is not applicable, other errors UNREADABLE",
          "[vuln][config]") {
    auto absent = ssh_password_auth_check(LinesResult{std::unexpected(ENOENT)});
    REQUIRE(absent.has_value());
    CHECK(absent->severity == "INFO");
    CHECK(absent->detail == "/etc/ssh/sshd_config not present; check not applicable");
    CHECK(absent->passed);

    auto eio = ssh_password_auth_check(LinesResult{std::unexpected(EIO)});
    REQUIRE(eio.has_value());
    CHECK(eio->severity == "UNREADABLE");
    CHECK(eio->detail == "/etc/ssh/sshd_config: eio");
    CHECK_FALSE(eio->passed);
}

// ── Stream readers: fault detection ─────────────────────────────────────────

TEST_CASE("read_value_from: clean, empty and faulted streams", "[vuln][config]") {
    std::istringstream clean("2\n");
    auto v = read_value_from(clean, EIO);
    REQUIRE(v.has_value());
    CHECK(*v == "2");

    std::istringstream empty("");
    auto e = read_value_from(empty, EIO);
    REQUIRE(e.has_value()); // failbit+eofbit on an empty file is a value, not a fault
    CHECK(e->empty());

    std::istringstream faulted("2\n");
    faulted.setstate(std::ios::badbit);
    auto f = read_value_from(faulted, EIO);
    REQUIRE_FALSE(f.has_value());
    CHECK(f.error() == EIO);
    CHECK(aslr_check(f).severity == "UNREADABLE");
    CHECK(suid_dumpable_check(f).severity == "UNREADABLE");
}

TEST_CASE("read_lines_from: clean, empty and faulted streams", "[vuln][config]") {
    std::istringstream clean("a\nb\n");
    auto v = read_lines_from(clean, EIO);
    REQUIRE(v.has_value());
    CHECK(*v == std::vector<std::string>{"a", "b"});

    std::istringstream empty("");
    auto e = read_lines_from(empty, EIO);
    REQUIRE(e.has_value());
    CHECK(e->empty());

    std::istringstream faulted("PermitRootLogin no\n");
    faulted.setstate(std::ios::badbit);
    auto f = read_lines_from(faulted, EIO);
    REQUIRE_FALSE(f.has_value());
    CHECK(f.error() == EIO);
    CHECK(ssh_root_login_check(f).severity == "UNREADABLE");
    auto pw = ssh_password_auth_check(f);
    REQUIRE(pw.has_value());
    CHECK(pw->severity == "UNREADABLE");
}
