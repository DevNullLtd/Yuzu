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
 * Scope: macOS (socketfilterfw + pfctl through run_bounded_subprocess) and
 * Windows (INetFwPolicy2 COM, firewall.dll). Linux (firewalld D-Bus / ufw /
 * iptables / nftables netlink) acquisition is not exercised by this file: it
 * needs a Linux host with a configurable backend, and its decisions are pinned
 * on the pure layer in test_firewall_parsers.cpp. The Windows cases compile and
 * run only on Windows.
 *
 * Assumes an unprivileged run on macOS: pf (read via pfctl) requires root, so a
 * pf|unknown state field is expected there, and the plugin says WHY with an
 * `error|pf:...` row (#4891, #6611) instead of an unexplained unknown. The
 * pairing is what the macOS cases pin: `pf|unknown` if and only if the pf info
 * error row, `ruleset|unknown` if and only if the pf rules error row, so an
 * unprivileged and a privileged run both pass.
 */

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#if defined(__APPLE__) || defined(_WIN32)

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

#if defined(_WIN32)
constexpr const char* kPluginFile = "firewall.dll";
#else
constexpr const char* kPluginFile = "firewall.dylib";
#endif

// True when `captured` has a row that starts with `prefix`.
bool has_row_starting_with(const std::vector<std::string>& rows, std::string_view prefix) {
    return std::any_of(rows.begin(), rows.end(),
                       [&](const std::string& r) { return r.rfind(prefix, 0) == 0; });
}

#if defined(__APPLE__)
// An error row the macOS shell may write: `error|<tool>:<read>:<token>`.
bool is_macos_read_error_row(const std::string& row) {
    constexpr std::string_view kPrefixes[] = {"error|appfirewall:globalstate:",
                                              "error|appfirewall:listapps:", "error|pf:info:",
                                              "error|pf:anchors:", "error|pf:rules:"};
    for (const auto prefix : kPrefixes) {
        if (row.rfind(prefix, 0) != 0)
            continue;
        const std::string token = row.substr(prefix.size());
        if (token == "not_run" || token == "timeout" || token == "truncated")
            return true;
        return token.rfind("exit:", 0) == 0 && token.size() > 5;
    }
    return false;
}
#endif

// Mirrors test_new_plugins.cpp's load_plugin() search-dir list: the test
// binary's CWD varies (direct invocation from the build dir vs. `meson
// test`'s own working directory vs. the tests-build-* symlink invocation),
// so every plausible relative root is tried rather than assuming one.
std::expected<yuzu::agent::PluginHandle, yuzu::agent::LoadError> load_firewall_plugin() {
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
        fs::path candidate = dir / kPluginFile;
        std::error_code ec;
        if (fs::exists(candidate, ec) && !ec) {
            return yuzu::agent::PluginHandle::load(candidate);
        }
    }
    return yuzu::agent::PluginHandle::load(fs::path{"agents"} / "plugins" / "firewall" / kPluginFile);
}

} // namespace

#if defined(__APPLE__)

TEST_CASE("firewall macOS 'state' acquires through the real bounded-subprocess call sites",
          "[firewall][local_dispatcher][macos]") {
    auto ph = load_firewall_plugin();
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

    const auto rows = split_lines(result.captured);
    CHECK(has_row_starting_with(rows, "pf|"));

    // Every error row is one of the documented `error|<tool>:<read>:<token>` rows: nothing else
    // may appear, and the unprivileged globalstate read never errors.
    for (const auto& row : rows)
        if (row.rfind("error|", 0) == 0) {
            INFO(row);
            CHECK(is_macos_read_error_row(row));
        }
    CHECK_FALSE(has_row_starting_with(rows, "error|appfirewall:globalstate:"));

    // pf (read via pfctl) DOES require root. Which of the two is true depends on this process's
    // privilege, which the test does not control, so what is pinned is the PAIRING: an unreadable
    // pf is `pf|unknown` with the row that says why (an unprivileged `pfctl -s info` exits
    // non-zero, #4891), and a readable pf has neither. The same holds for the rule count.
    const bool pf_unknown = std::find(rows.begin(), rows.end(), "pf|unknown") != rows.end();
    CHECK(pf_unknown == has_row_starting_with(rows, "error|pf:info:"));
    const bool ruleset_unknown = std::find(rows.begin(), rows.end(), "ruleset|unknown") != rows.end();
    CHECK(ruleset_unknown == has_row_starting_with(rows, "error|pf:rules:"));

    // ruleset| must always appear, as unknown-or-integer; an anchor| row, if pf happened to be
    // readable, must have a non-empty name after the prefix.
    bool saw_state_ruleset_row = false;
    for (const auto& line : rows) {
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
    auto ph = load_firewall_plugin();
    if (!ph) {
        WARN("firewall plugin dylib not found in build tree -- skipping "
             "(build with -Dbuild_agent=true)");
        SUCCEED();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(ph->descriptor(), "rules");

    // The call completes cleanly (rc == 0); an unprivileged pfctl read is reported as an error
    // row, not as a failure of the action.
    CHECK(result.rc == 0);

    const auto lines = split_lines(result.captured);
    for (const auto& row : lines)
        if (row.rfind("error|", 0) == 0) {
            INFO(row);
            CHECK(is_macos_read_error_row(row));
        }

    // socketfilterfw --listapps IS unprivileged (unlike pfctl), so a cleanly-completed read never
    // yields its error row. Whether it yields ANY app| rows depends on this host's actual
    // Application Firewall allow-list, which is real host state, not a fixture this test controls
    // (BR-01: a genuinely empty list is a valid, honestly-reported outcome). What's pinned is the
    // shape of whatever rows are present: every row's decision field must be exactly
    // allow|block|unknown -- never dropped, never a fabricated value (review R6).
    CHECK_FALSE(has_row_starting_with(lines, "error|appfirewall:listapps:"));
    for (const auto& line : lines) {
        if (line.rfind("app|", 0) != 0)
            continue;
        const auto last_sep = line.rfind('|');
        REQUIRE(last_sep != std::string::npos);
        const std::string decision = line.substr(last_sep + 1);
        CHECK((decision == "allow" || decision == "block" || decision == "unknown"));
    }

    // anchor| rows depend on real pf anchors and privilege; every row that DOES appear must have a
    // non-empty name after the prefix. An unreadable anchor list is its own error row, and then no
    // anchor row exists.
    for (const auto& line : lines) {
        if (line.rfind("anchor|", 0) != 0)
            continue;
        CHECK(line.size() > std::string_view("anchor|").size());
        CHECK_FALSE(has_row_starting_with(lines, "error|pf:anchors:"));
    }

    // ruleset| must always appear, and be either a non-negative integer (a cleanly-completed
    // `pfctl -s rules` read) or exactly "unknown" (the completeness gate tripped), and `unknown`
    // comes with the row that says why. Which of the two depends on whether THIS process can read
    // pf, so the test checks the pairing, not a value hardcoded to one euid (BR-01). A readable
    // `rule|` row can only exist next to a count.
    bool saw_ruleset_row = false;
    for (const auto& line : lines) {
        if (line.rfind("ruleset|", 0) != 0)
            continue;
        saw_ruleset_row = true;
        const std::string value = line.substr(std::string_view("ruleset|").size());
        CHECK((value == "unknown" || is_non_negative_integer(value)));
        CHECK((value == "unknown") == has_row_starting_with(lines, "error|pf:rules:"));
    }
    CHECK(saw_ruleset_row);
    if (has_row_starting_with(lines, "error|pf:rules:"))
        CHECK_FALSE(has_row_starting_with(lines, "rule|"));
}

#elif defined(_WIN32)

// The Windows legs go through INetFwPolicy2 COM in process. COM can fail on a restricted host
// (a profile read, the rules collection), and each failure is a row of its own, so what is
// pinned is the shape every outcome must take, not one outcome (#4375). The row text itself is
// built by pure functions that test_firewall_parsers.cpp pins on every host.

TEST_CASE("firewall Windows 'state' reports three profiles and a rule count, or one honest error",
          "[firewall][local_dispatcher][windows]") {
    auto ph = load_firewall_plugin();
    if (!ph) {
        WARN("firewall plugin dll not found in build tree -- skipping "
             "(build with -Dbuild_agent=true)");
        SUCCEED();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(ph->descriptor(), "state");
    CHECK(result.rc == 0);

    const auto lines = split_lines(result.captured);
    std::size_t profiles = 0, counts = 0, count_errors = 0, com_errors = 0;
    for (const auto& line : lines) {
        INFO(line);
        if (line.rfind("profile|", 0) == 0) {
            ++profiles;
        } else if (line.rfind("ruleset|", 0) == 0) {
            ++counts;
            CHECK(is_non_negative_integer(line.substr(std::string_view("ruleset|").size())));
        } else if (line.rfind("error|rules_count:0x", 0) == 0) {
            ++count_errors;
        } else if (line == "error|com_init" || line.rfind("error|policy2_create:0x", 0) == 0) {
            ++com_errors;
        } else {
            FAIL("unexpected row in the Windows state output");
        }
    }
    if (com_errors > 0) {
        // COM could not start or the policy object could not be created: that one row, nothing else
        CHECK(lines.size() == 1);
        CHECK(profiles == 0);
    } else {
        CHECK(profiles == 3);
        CHECK(counts + count_errors == 1); // exactly one of the count and its error row
    }
}

TEST_CASE("firewall Windows 'rules' lists at most 100 rules, with a count that matches",
          "[firewall][local_dispatcher][windows]") {
    auto ph = load_firewall_plugin();
    if (!ph) {
        WARN("firewall plugin dll not found in build tree -- skipping "
             "(build with -Dbuild_agent=true)");
        SUCCEED();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(ph->descriptor(), "rules");
    CHECK(result.rc == 0);

    const auto lines = split_lines(result.captured);
    std::size_t rule_rows = 0;
    std::optional<std::size_t> count;
    bool ruleset_unknown = false, enum_error = false, truncated = false, com_error = false;
    for (const auto& line : lines) {
        INFO(line);
        if (line.rfind("rule|", 0) == 0) {
            ++rule_rows;
        } else if (line == "ruleset|unknown") {
            ruleset_unknown = true;
        } else if (line.rfind("ruleset|", 0) == 0) {
            const std::string value = line.substr(std::string_view("ruleset|").size());
            REQUIRE(is_non_negative_integer(value));
            count = static_cast<std::size_t>(std::stoull(value));
        } else if (line == "truncated|true") {
            truncated = true;
        } else if (line.rfind("error|enum_next:0x", 0) == 0) {
            enum_error = true;
        } else if (line.rfind("error|", 0) == 0) {
            com_error = true; // com_init, policy2_create, rules_create, enum_create, enum_variant
        } else {
            FAIL("unexpected row in the Windows rules output");
        }
    }
    CHECK(rule_rows <= 100);
    if (com_error) {
        CHECK(rule_rows == 0);
        return;
    }
    if (enum_error) {
        // a failed enumeration step is never reported as a count
        CHECK(ruleset_unknown);
        CHECK_FALSE(count.has_value());
        return;
    }
    REQUIRE(count.has_value());
    CHECK(*count == rule_rows); // the trailing count is the number of rows written
    // the cap row appears only when a rule past the cap exists, and then the count is the cap
    CHECK((!truncated || *count == 100));
}

#endif // __APPLE__ / _WIN32

#endif // __APPLE__ || _WIN32
