/**
 * test_firewall_local_dispatcher.cpp -- code-review gate-1 remediation.
 *
 * Loads the ACTUAL built firewall plugin (firewall.dylib/.so/.dll, the same
 * artifact the agent daemon loads in production) via PluginHandle::load and
 * drives it through yuzu::agent::LocalDispatcher -- the same in-process
 * dispatch mechanism used elsewhere in this codebase for real-plugin action
 * tests (test_registry_local_dispatcher.cpp on Windows, test_users_posix_
 * actions.cpp on POSIX). test_firewall_parsers.cpp exercises only the pure
 * parsing helpers; this exercises the acquisition call sites (do_state_macos
 * / do_rules_macos -- socketfilterfw + pfctl through run_bounded_subprocess)
 * end to end against this real host.
 *
 * Scope, deliberately: macOS only for now. Windows (INetFwPolicy2 COM) and
 * Linux (firewalld D-Bus / ufw / iptables) acquisition are not exercised by
 * this file -- they need a real Windows host / a Linux host with a
 * configurable firewalld+ufw+iptables backend to drive the equivalent
 * end-to-end probe, and are tracked as follow-up (matches this PR's own
 * commit-message disclosure that the Linux/Windows legs were verified by
 * compile and unit test only in this environment).
 *
 * Assumes an unprivileged run: pf (read via pfctl) requires root, so a
 * pf|unknown state field and an empty rules capture are both expected and
 * correct here, not failures -- do_rules_macos silently emitting nothing on
 * a permission-denied pfctl read is pre-existing, unchanged-by-this-PR
 * behaviour (see the function's own comment), not something this test
 * exists to pin.
 */

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#if defined(__APPLE__)

namespace {

namespace fs = std::filesystem;

// Splits captured output (newline-joined per LocalDispatcher::run) into
// individual rows, dropping empty lines.
std::vector<std::string> split_lines(std::string_view captured) {
    std::vector<std::string> lines;
    std::istringstream iss{std::string(captured)};
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty())
            lines.push_back(line);
    }
    return lines;
}

bool is_non_negative_integer(std::string_view s) {
    return !s.empty() && std::all_of(s.begin(), s.end(),
                                     [](unsigned char c) { return std::isdigit(c) != 0; });
}

// Mirrors test_new_plugins.cpp's load_plugin() search-dir list: the test
// binary's CWD varies (direct invocation from the build dir vs. `meson
// test`'s own working directory vs. the tests-build-* symlink invocation),
// so every plausible relative root is tried rather than assuming one.
std::expected<yuzu::agent::PluginHandle, yuzu::agent::LoadError> load_firewall_dylib() {
    std::vector<fs::path> search_dirs{
        fs::path{"agents"} / "plugins" / "firewall",
        fs::path{".."} / "agents" / "plugins" / "firewall",
        fs::path{"builddir"} / "agents" / "plugins" / "firewall",
    };
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        search_dirs.push_back(fs::path{build_root} / "agents" / "plugins" / "firewall");
    }
    for (const char* os_dir : {"build-macos", "build-linux", "build-windows"}) {
        search_dirs.push_back(fs::path{os_dir} / "agents" / "plugins" / "firewall");
    }

    for (const auto& dir : search_dirs) {
        fs::path candidate = dir / "firewall.dylib";
        std::error_code ec;
        if (fs::exists(candidate, ec) && !ec) {
            return yuzu::agent::PluginHandle::load(candidate);
        }
    }
    return yuzu::agent::PluginHandle::load("agents/plugins/firewall/firewall.dylib");
}

} // namespace

TEST_CASE("firewall macOS 'state' acquires through the real bounded-subprocess call sites",
          "[firewall][local_dispatcher][macos]") {
    auto ph = load_firewall_dylib();
    if (!ph) {
        WARN("firewall plugin dylib not found in build tree -- skipping "
             "(build with -Dbuild_agent=true)");
        SUCCEED();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(ph->descriptor(), "state");

    CHECK(result.rc == 0);
    CHECK(result.captured.find("backend|appfirewall") != std::string::npos);
    // "backend|appfirewall" is written unconditionally regardless of whether
    // socketfilterfw actually ran, so it alone cannot discriminate a broken
    // acquisition call from a working one -- a false-green risk an external
    // adversarial review flagged. socketfilterfw --getglobalstate is an
    // UNPRIVILEGED read (do_state_macos's own comment), so on any real macOS
    // host this must resolve to a definite enabled/disabled, never fall back
    // to "unknown": requiring the specific value here is what makes this
    // assertion fail if the argv/deadline/parsing wiring silently breaks,
    // where a presence-only check on "state|" would still pass.
    CHECK((result.captured.find("state|enabled") != std::string::npos ||
          result.captured.find("state|disabled") != std::string::npos));
    // pf (read via pfctl) DOES require root, so pf|unknown is the correct,
    // expected value on an unprivileged run -- presence-only here is
    // intentional, not the same gap as the state check above.
    CHECK(result.captured.find("pf|") != std::string::npos);
    CHECK(result.captured.find("error|") == std::string::npos);

    // ruleset| and anchor| wiring (do_state_macos) had no assertion at all
    // (code-review r1, FV-codex-01/F1) -- same shape-not-value discipline as
    // "rules" below: ruleset| must always appear as unknown-or-integer (pf
    // needs root, so unknown is the correct unprivileged value); an anchor|
    // row, if pf happened to be readable, must have a non-empty name after
    // the prefix. This pins the gate wiring, not a specific privilege level.
    const auto state_lines = split_lines(result.captured);
    bool saw_state_ruleset_row = false;
    for (const auto& line : state_lines) {
        if (line.rfind("ruleset|", 0) == 0) {
            saw_state_ruleset_row = true;
            const std::string value = line.substr(std::string_view("ruleset|").size());
            CHECK((value == "unknown" || is_non_negative_integer(value)));
        } else if (line.rfind("anchor|", 0) == 0) {
            CHECK(line.size() > std::string_view("anchor|").size());
        }
    }
    CHECK(saw_state_ruleset_row);
}

TEST_CASE("firewall macOS 'rules' acquires through the real bounded-subprocess call site",
          "[firewall][local_dispatcher][macos]") {
    auto ph = load_firewall_dylib();
    if (!ph) {
        WARN("firewall plugin dylib not found in build tree -- skipping "
             "(build with -Dbuild_agent=true)");
        SUCCEED();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(ph->descriptor(), "rules");

    // Unprivileged: pfctl -s rules needs root, so ruleset|unknown (not a
    // count) is the expected, correct value here -- what this pins is that
    // the call completes cleanly (rc==0, no error| line), not any
    // particular rule-row count.
    CHECK(result.rc == 0);
    CHECK(result.captured.find("error|") == std::string::npos);

    const auto lines = split_lines(result.captured);

    // socketfilterfw --listapps IS unprivileged (unlike pfctl), so a
    // cleanly-completed read never yields error| -- already checked above.
    // Whether it yields ANY app| rows depends on this host's actual
    // Application Firewall allow-list, which is real host state, not a
    // fixture this test controls (BR-01: an earlier version of this test
    // hard-required at least one row, which is only true on a host whose
    // allow-list happens to be non-empty -- a genuinely empty list is a
    // valid, honestly-reported outcome too, and the assertion must hold on
    // both). What's pinned is the shape of whatever rows are present, not
    // their count: every row's decision field must be exactly
    // allow|block|unknown -- never dropped, never a fabricated value
    // (review R6). Value-checked, not presence-only: a find("app|") alone
    // would still pass if the decision field were wrong or malformed.
    for (const auto& line : lines) {
        if (line.rfind("app|", 0) != 0)
            continue;
        const auto last_sep = line.rfind('|');
        REQUIRE(last_sep != std::string::npos);
        const std::string decision = line.substr(last_sep + 1);
        CHECK((decision == "allow" || decision == "block" || decision == "unknown"));
    }

    // anchor| rows (do_rules_macos) had no assertion at all (code-review r1,
    // FV-codex-01/F1) -- same host-state-dependent shape check as app|
    // above: whether any anchor rows appear depends on real pf anchors and
    // privilege, neither of which this test controls, but every row that
    // DOES appear must have a non-empty name after the prefix.
    for (const auto& line : lines) {
        if (line.rfind("anchor|", 0) != 0)
            continue;
        CHECK(line.size() > std::string_view("anchor|").size());
    }

    // ruleset| must always appear, and be either a non-negative integer (a
    // cleanly-completed `pfctl -s rules` read) or exactly "unknown" (the
    // completeness gate tripped). Which of the two depends on whether THIS
    // process can read pf -- root can, an unprivileged euid cannot -- so the
    // test checks the shape, not a specific value hardcoded to one euid
    // (BR-01, same fragility class as the app| row check above: a CI runner
    // executing this test as root would otherwise fail a perfectly correct
    // run).
    bool saw_ruleset_row = false;
    for (const auto& line : lines) {
        if (line.rfind("ruleset|", 0) != 0)
            continue;
        saw_ruleset_row = true;
        const std::string value = line.substr(std::string_view("ruleset|").size());
        CHECK((value == "unknown" || is_non_negative_integer(value)));
    }
    CHECK(saw_ruleset_row);
}

#endif // __APPLE__
