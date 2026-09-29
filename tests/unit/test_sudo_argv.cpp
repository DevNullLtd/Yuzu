// The Decision-8 canonical sudo argv FORM is what the sudoers grants from
// scripts/install-agent-user.sh match — pinned here by test, not convention
// (ADR-3002 :443-464). sudo_argv.hpp's pure two-argument sudo_wrap is portable
// as of #3406 (so macos_console_user.hpp, which compiles under MSVC, can use
// THE canonical builder rather than a second copy of it); only the
// one-argument geteuid() convenience is POSIX-only, and the last case below
// exercises it -- which is what the #ifndef _WIN32 guard rests on. The
// portable two-arg cases matter most on the MSVC leg, because that is where
// macos_console_user.hpp's argv builder now depends on this form; they are
// pinned there by test_certificates_macos.cpp's exact-argv vectors, which do
// compile on Windows.
#ifndef _WIN32

#include <catch2/catch_test_macros.hpp>

#include <sudo_argv.hpp>

#include <unistd.h> // geteuid() -- the one-arg overload's case below

#include <string>
#include <vector>

using yuzu::shared::sudo_wrap;

TEST_CASE("sudo_wrap emits the canonical Decision-8 form", "[agent][sudo_argv]") {
    const std::vector<std::string> tool_argv{"/usr/sbin/iptables", "-L", "INPUT", "-n"};
    const auto argv = sudo_wrap(tool_argv, false);
    REQUIRE(argv.size() == tool_argv.size() + 3);
    CHECK(argv[0] == "/usr/bin/sudo");
    CHECK(argv[1] == "-n");
    CHECK(argv[2] == "--");
    CHECK(argv[3] == "/usr/sbin/iptables");
    CHECK(argv[4] == "-L");
    CHECK(argv[5] == "INPUT");
    CHECK(argv[6] == "-n");
}

TEST_CASE("sudo_wrap preserves the root skip-sudo conditional", "[agent][sudo_argv]") {
    const std::vector<std::string> tool_argv{"/sbin/pfctl", "-s", "rules"};
    const auto argv = sudo_wrap(tool_argv, true);
    REQUIRE(argv == tool_argv);
}

// The one-argument overload -- the only POSIX-dependent part of the header
// (it calls geteuid()), and therefore the reason this TU is guarded. Without a
// case for it the guard would rest on a false premise.
TEST_CASE("sudo_wrap's one-argument overload agrees with the live euid",
         "[agent][sudo_argv]") {
    std::vector<std::string> tool_argv{"/usr/sbin/iptables", "-L"};
    const bool root = (::geteuid() == 0);
    CHECK(sudo_wrap(tool_argv) == sudo_wrap(tool_argv, root));
    // And it really is the conditional, not a constant: the two branches differ.
    CHECK(sudo_wrap(tool_argv, false) != sudo_wrap(tool_argv, true));
}

TEST_CASE("sudo_wrap wraps a bare tool with no arguments", "[agent][sudo_argv]") {
    const std::vector<std::string> tool_argv{"/usr/bin/dscacheutil", "-flushcache"};
    const auto argv = sudo_wrap(tool_argv, false);
    REQUIRE(argv.size() == tool_argv.size() + 3);
    CHECK(argv[3] == "/usr/bin/dscacheutil");
    CHECK(argv[4] == "-flushcache");
}

#endif // !_WIN32
