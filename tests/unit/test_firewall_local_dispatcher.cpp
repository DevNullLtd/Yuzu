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
 * on the pure layer in test_firewall_parsers.cpp. The one Linux piece that runs here is the
 * snapshot broker's socket client (firewall_snapshot_reader.hpp), against an in-process listener.
 * The Windows cases compile and run only on Windows.
 *
 * Runs as whatever account the suite runs as on macOS. pf is read through `sudo -n --` (the
 * installer's exact read-only pfctl lines; direct when root), so an account with no such grant
 * (a developer Mac, the CI runner account) gets a refused sudo, a pf|unknown state field and
 * the row that says WHY (`error|pf:...`, #4891, #6611) instead of an unexplained unknown, while
 * root and the granted account read pf. The pairing is what the macOS cases pin, on a live
 * host: `pf|unknown` if and only if the pf info error row (a `pfctl -s info` that completes
 * always names Enabled or Disabled; the completed-but-unrecognised read, where `pf|unknown`
 * comes alone, is the pure layer's case), `ruleset|unknown` if and only if the pf rules error
 * row, so a refused and a granted run both pass.
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

#if defined(__linux__)
#include "firewall_snapshot_reader.hpp"
#include "test_helpers.hpp"

#include <yuzu/agent/scoped_fd.hpp>

#include <chrono>
#include <cstring>
#include <functional>
#include <thread>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

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

// True when `captured` has a row that starts with `prefix`. Used by the macOS cases only.
[[maybe_unused]] bool has_row_starting_with(const std::vector<std::string>& rows, std::string_view prefix) {
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

// True when the plugin is not available and the case should skip. Under `meson test`
// (MESON_BUILD_ROOT set) the agent shards depend on the plugin build, so a plugin that is
// missing or does not load is a defect and FAILs: a green skip there would let a partial build
// pass these cases without running one. A bare run of the test binary outside meson has no such
// guarantee and skips. Not quite the rule of firewall_plugin_built() in
// test_firewall_quarantine_live.cpp: that one REQUIREs a plugin file that is present to load even on
// a bare run, while this skips there when the plugin is present but does not load.
[[nodiscard]] bool skip_without_plugin(
    const std::expected<yuzu::agent::PluginHandle, yuzu::agent::LoadError>& ph) {
    if (ph)
        return false;
    if (std::getenv("MESON_BUILD_ROOT") != nullptr)
        FAIL("firewall plugin missing or unloadable under MESON_BUILD_ROOT: the agent shards "
             "depend on its build, so it must load");
    WARN("firewall plugin not found in build tree -- skipping (build with -Dbuild_agent=true)");
    return true;
}

} // namespace

#if defined(__APPLE__)

TEST_CASE("firewall macOS 'state' acquires through the real bounded-subprocess call sites",
          "[firewall][local_dispatcher][macos]") {
    auto ph = load_firewall_plugin();
    if (skip_without_plugin(ph)) {
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

    // pf is read through `sudo -n -- /sbin/pfctl` (direct when root). Which of the two is true
    // depends on this process's grant, which the test does not control, so what is pinned is the
    // PAIRING: an unreadable pf is `pf|unknown` with the row that says why (a refused sudo or a
    // failed `pfctl -s info` exits non-zero, #4891), and a readable pf has neither. The same
    // holds for the rule count.
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
    if (skip_without_plugin(ph)) {
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
    if (skip_without_plugin(ph)) {
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
    if (skip_without_plugin(ph)) {
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
    std::optional<std::size_t> property_error_rules;
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
        } else if (line.rfind("error|rule_property:", 0) == 0) {
            // Some rules had a property that could not be read: their rows say `unknown` for it.
            // Not a COM-start failure (the rule rows are still expected), so it is classified
            // before the generic `error|` branch: `error|rule_property:<rules>:0x<hr>`.
            const auto rest = line.substr(std::string_view("error|rule_property:").size());
            const auto colon = rest.find(':');
            REQUIRE(colon != std::string::npos);
            REQUIRE(is_non_negative_integer(rest.substr(0, colon)));
            property_error_rules = static_cast<std::size_t>(std::stoull(rest.substr(0, colon)));
            CHECK(rest.substr(colon + 1).rfind("0x", 0) == 0);
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
    // the rows with a property that failed are still rows, and are counted
    if (property_error_rules)
        CHECK((*property_error_rules >= 1 && *property_error_rules <= rule_rows));
    REQUIRE(count.has_value());
    CHECK(*count == rule_rows); // the trailing count is the number of rows written
    // the cap row appears only when a rule past the cap exists, and then the count is the cap
    CHECK((!truncated || *count == 100));
}

#endif // __APPLE__ / _WIN32

#endif // __APPLE__ || _WIN32

// ── Linux: the snapshot broker's socket client ────────────────────────────────────────────────
//
// read_fw_snapshot is the plugin's only code that talks to the broker's AF_UNIX socket, and its
// bounds (reassembly, the 1 MiB cap, the deadline, the peer check) are otherwise pinned only
// lexically. These cases run it against an in-process listener in a `yuzu_test_` temp directory. This
// is the justification the test rules ask for: the cost is a socket in a temp directory and one joined
// thread per case, nothing is spawned, and no case waits on a clock but the 50 ms deadline whose
// expiry is the subject of one of them.

#if defined(__linux__)

namespace {

using namespace std::chrono_literals;

/// A listening AF_UNIX socket whose one accepted connection is handed to `serve` on a thread that the
/// destructor joins. Every case connects exactly once, so accept() always returns. The listener is made
/// by this process, so its peer credentials are this process's own uid: a case passes that uid to the
/// reader as the uid the listener must have (the plugin passes 0), or a different one to see it refused.
class SnapshotListener {
public:
    explicit SnapshotListener(std::function<void(int)> serve) : dir_("yuzu_test_fwsock_") {
        std::filesystem::create_directories(dir_.path);
        path_ = (dir_.path / "s.sock").string();
        sockaddr_un addr{};
        REQUIRE(path_.size() < sizeof(addr.sun_path));
        addr.sun_family = AF_UNIX;
        std::memcpy(addr.sun_path, path_.data(), path_.size());
        fd_.reset(::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
        REQUIRE(fd_);
        // sockaddr_un is passed as a sockaddr for the call only; nothing reads through the cast
        REQUIRE(::bind(fd_.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0);
        REQUIRE(::listen(fd_.get(), 1) == 0);
        thread_ = std::thread([this, serve = std::move(serve)] {
            const int conn = ::accept(fd_.get(), nullptr, nullptr);
            if (conn < 0)
                return;
            serve(conn);
            ::close(conn);
        });
    }
    ~SnapshotListener() {
        if (thread_.joinable())
            thread_.join();
    }
    SnapshotListener(const SnapshotListener&) = delete;
    SnapshotListener& operator=(const SnapshotListener&) = delete;
    [[nodiscard]] const std::string& path() const { return path_; }

private:
    yuzu::test::TempDir dir_;
    std::string path_;
    yuzu::agent::ScopedFd fd_;
    std::thread thread_;
};

/// Writes all of `data`, never raising SIGPIPE when the reader has already gone.
void send_all(int conn, std::string_view data) {
    while (!data.empty()) {
        const ssize_t n = ::send(conn, data.data(), data.size(), MSG_NOSIGNAL);
        if (n <= 0)
            return;
        data.remove_prefix(static_cast<std::size_t>(n));
    }
}

/// Reads until the peer closes, so a listener that sends nothing stays open exactly as long as the reader.
void drain(int conn) {
    char buf[64];
    while (::read(conn, buf, sizeof(buf)) > 0) {
    }
}

std::chrono::steady_clock::time_point in(std::chrono::milliseconds budget) {
    return std::chrono::steady_clock::now() + budget;
}

} // namespace

TEST_CASE("read_fw_snapshot: a reply sent in pieces is assembled, across reads of the reader's buffer",
          "[firewall][snapshot_reader]") {
    // 40,000 bytes in five writes: more than the reader's 16 KiB buffer, so at least three reads
    std::string reply;
    for (int i = 0; i < 5; ++i)
        reply += std::string(8000, static_cast<char>('a' + i));
    SnapshotListener listener([&reply](int conn) {
        for (std::size_t at = 0; at < reply.size(); at += 8000)
            send_all(conn, std::string_view{reply}.substr(at, 8000));
    });
    const auto got = yuzu::firewall::read_fw_snapshot(listener.path(), in(10s), ::geteuid());
    REQUIRE(got.has_value());
    CHECK(*got == reply);
}

TEST_CASE("read_fw_snapshot: a listener that sends nothing and closes is an empty reply", "[firewall][snapshot_reader]") {
    SnapshotListener listener([](int) {});
    const auto got = yuzu::firewall::read_fw_snapshot(listener.path(), in(10s), ::geteuid());
    REQUIRE(got.has_value());
    CHECK(got->empty()); // the framing parser reads it as `empty`
}

TEST_CASE("read_fw_snapshot: a reply longer than 1 MiB is oversized", "[firewall][snapshot_reader]") {
    SnapshotListener listener([](int conn) {
        const std::string chunk(64 * 1024, 'x');
        for (std::size_t sent = 0; sent <= yuzu::firewall::kFwSnapshotMaxBytes + chunk.size(); sent += chunk.size())
            send_all(conn, chunk);
    });
    const auto got = yuzu::firewall::read_fw_snapshot(listener.path(), in(10s), ::geteuid());
    REQUIRE_FALSE(got.has_value());
    CHECK(got.error() == "oversized");
}

TEST_CASE("read_fw_snapshot: a listener that accepts and sends nothing is a timeout at the deadline",
          "[firewall][snapshot_reader]") {
    SnapshotListener listener(drain); // stays open until the reader gives up and closes
    const auto started = std::chrono::steady_clock::now();
    const auto got = yuzu::firewall::read_fw_snapshot(listener.path(), in(50ms), ::geteuid());
    REQUIRE_FALSE(got.has_value());
    CHECK(got.error() == "timeout");
    CHECK(std::chrono::steady_clock::now() - started < 10s); // bounded: it did not wait for the listener
}

TEST_CASE("read_fw_snapshot: a listener not made by the expected uid is refused before a byte is read",
          "[firewall][snapshot_reader]") {
    SnapshotListener listener(drain);
    const auto got = yuzu::firewall::read_fw_snapshot(listener.path(), in(10s), ::geteuid() + 1);
    REQUIRE_FALSE(got.has_value());
    CHECK(got.error() == "peer_not_root");
}

TEST_CASE("read_fw_snapshot: no socket is the empty token, a socket nothing listens on is refused",
          "[firewall][snapshot_reader]") {
    yuzu::test::TempDir dir("yuzu_test_fwsock_");
    std::filesystem::create_directories(dir.path);
    const auto missing = (dir.path / "absent.sock").string();
    const auto none = yuzu::firewall::read_fw_snapshot(missing, in(10s), ::geteuid());
    REQUIRE_FALSE(none.has_value());
    CHECK(none.error().empty()); // no broker installed: silent

    // a socket file left behind with no listener behind it
    const auto stale = (dir.path / "stale.sock").string();
    sockaddr_un addr{};
    REQUIRE(stale.size() < sizeof(addr.sun_path));
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, stale.data(), stale.size());
    {
        yuzu::agent::ScopedFd fd(::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
        REQUIRE(fd);
        REQUIRE(::bind(fd.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0);
    } // closed without listen(): the file stays
    const auto refused = yuzu::firewall::read_fw_snapshot(stale, in(10s), ::geteuid());
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error() == "connect:refused");

    // a path that cannot fit sockaddr_un is an I/O error, never a truncated connect
    const auto too_long = yuzu::firewall::read_fw_snapshot(std::string(200, 'a'), in(10s), ::geteuid());
    REQUIRE_FALSE(too_long.has_value());
    CHECK(too_long.error() == "io_error");
}

#endif // __linux__
