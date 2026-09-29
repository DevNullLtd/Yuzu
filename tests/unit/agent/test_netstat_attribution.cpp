/**
 * test_netstat_attribution.cpp -- gate-1 (/code-review) remediation: the
 * #3403 sockwho->netstat.attribution fold-in and the shared macOS libproc
 * walk shipped with zero tests discriminating netstat's two action output
 * shapes -- a wiring bug (dropped process_name/process_path columns, pid
 * migrating back to sockwho's old 1st-column position, a UDP row fabricating
 * a state) would compile clean and pass every existing test.
 *
 * Loads the ACTUAL built netstat.dylib via PluginHandle::load and drives it
 * through yuzu::agent::LocalDispatcher -- the same pattern
 * test_wave3_pr31_macos_actions.cpp established for os_info/processes/
 * network_diag/ioc. Darwin-only: netstat's "attribution" action is macOS
 * libproc-specific in this file (Linux/Windows have their own enrichment
 * paths, exercised by CI on those hosts, not here).
 *
 * netstat_plugin.cpp's own file header states the contract this file exists
 * to pin: "attribution" emits netstat_list's 7 columns as a prefix with
 * process_name/process_path appended (9 total); pid stays in its
 * netstat_list position (6th field after proto), NOT sockwho's old
 * 1st-column layout. TEST_CASE 3 below asserts exactly that prefix
 * relationship against two REAL dispatches of the same live socket, rather
 * than trusting the comment.
 */
#ifdef __APPLE__

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/agent/scoped_fd.hpp>
#include <yuzu/plugin.h>

#include <macos_socket_walk.hpp> // yuzu::shared::resolve_proc_name_path -- netstat.attribution's
                                 // sole consumer (agents/plugins/netstat/src/netstat_plugin.cpp)

#include "local_dispatcher.hpp"

#include <arpa/inet.h>
#include <libproc.h>
#include <netinet/in.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <format>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

// Mirrors test_wave3_pr31_macos_actions.cpp's find_plugin()/load_plugin() --
// duplicated rather than shared, matching that file's own "separate
// translation unit" convention (see test_socket_walk.cpp's EphemeralListener
// comment for the same reasoning applied to fixtures).
fs::path find_plugin(const std::string& plugin_name) {
    const std::string lib_name = plugin_name + ".dylib";

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / plugin_name /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / plugin_name / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / plugin_name / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / plugin_name /
                            lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor;
};

// tests/meson.build's link_depends on netstat_plugin_lib makes the dylib a
// hard build prerequisite of this test binary, so "file not found" should
// never legitimately happen in a real build -- a load failure or null
// descriptor hard-fails rather than silently WARN-and-skip (the exact
// false-green class test_wave3_pr31_macos_actions.cpp's gate-2 remediation
// closed for its own four plugins).
LoadedPlugin load_plugin(const std::string& plugin_name) {
    auto plugin_path = find_plugin(plugin_name);
    if (plugin_path.empty()) {
        FAIL("plugin '" << plugin_name << "' .dylib not found under any search candidate -- "
             "tests/meson.build's link_depends should have built it ahead of this test binary");
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    if (!handle.has_value()) {
        FAIL("PluginHandle::load() failed for '" << plugin_path.string() << "'");
    }
    const auto* descriptor = handle->descriptor();
    if (!descriptor) {
        FAIL("plugin '" << plugin_name << "' loaded but returned a null descriptor");
    }
    return LoadedPlugin{std::move(*handle), descriptor};
}

// RAII ephemeral TCP listener bound to 127.0.0.1:0 -- same shape as
// test_socket_walk.cpp's EphemeralListener / test_wave3_pr31_macos_actions.cpp's
// EphemeralTcpListener (ScopedFd assigned immediately on acquisition so a
// failing REQUIRE below it still closes the fd during stack unwind).
struct EphemeralTcpListener {
    yuzu::agent::ScopedFd fd;
    uint16_t port{0};

    EphemeralTcpListener() {
        fd = yuzu::agent::ScopedFd(::socket(AF_INET, SOCK_STREAM, 0));
        REQUIRE(fd.valid());
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = 0;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        REQUIRE(::bind(fd.get(), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0);
        REQUIRE(::listen(fd.get(), 1) == 0);
        struct sockaddr_in bound{};
        socklen_t len = sizeof(bound);
        REQUIRE(::getsockname(fd.get(), reinterpret_cast<struct sockaddr*>(&bound), &len) == 0);
        port = ntohs(bound.sin_port);
        REQUIRE(port != 0);
    }
    EphemeralTcpListener(const EphemeralTcpListener&) = delete;
    EphemeralTcpListener& operator=(const EphemeralTcpListener&) = delete;
};

// RAII bound-but-unconnected UDP socket -- same shape as
// test_wave3_pr31_macos_actions.cpp's BoundUdpSocket. Connectionless, so
// bind() alone is enough for it to show up in the libproc walk with an
// empty (never fabricated) state.
struct BoundUdpSocket {
    yuzu::agent::ScopedFd fd;
    uint16_t port{0};

    BoundUdpSocket() {
        fd = yuzu::agent::ScopedFd(::socket(AF_INET, SOCK_DGRAM, 0));
        REQUIRE(fd.valid());
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = 0;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        REQUIRE(::bind(fd.get(), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0);
        struct sockaddr_in bound{};
        socklen_t len = sizeof(bound);
        REQUIRE(::getsockname(fd.get(), reinterpret_cast<struct sockaddr*>(&bound), &len) == 0);
        port = ntohs(bound.sin_port);
        REQUIRE(port != 0);
    }
    BoundUdpSocket(const BoundUdpSocket&) = delete;
    BoundUdpSocket& operator=(const BoundUdpSocket&) = delete;
};

// Returns the single line of `captured` (LocalDispatcher's newline-joined
// output) that contains `needle`, or an empty string if none matches. Every
// caller below REQUIREs a non-empty result before using it, so a silent miss
// fails loudly rather than indexing an empty vector.
std::string find_line(const std::string& captured, const std::string& needle) {
    std::string::size_type start = 0;
    while (start <= captured.size()) {
        auto end = captured.find('\n', start);
        auto line = captured.substr(start, end == std::string::npos ? std::string::npos
                                                                     : end - start);
        if (line.find(needle) != std::string::npos)
            return line;
        if (end == std::string::npos)
            break;
        start = end + 1;
    }
    return {};
}

// Splits a pipe-delimited row into its fields. Deliberately dumb (no
// escape-aware unmerge of "\|") -- every field this file asserts on is a
// plain proto/addr/port/state/pid/name/path with no literal '|' in it, so a
// naive split is the right tool for pinning column COUNT and POSITION,
// which is exactly what these tests exist to catch a regression in.
std::vector<std::string> split_fields(const std::string& line) {
    std::vector<std::string> fields;
    std::string::size_type start = 0;
    while (true) {
        auto pipe = line.find('|', start);
        fields.push_back(line.substr(start, pipe == std::string::npos ? std::string::npos
                                                                       : pipe - start));
        if (pipe == std::string::npos)
            break;
        start = pipe + 1;
    }
    return fields;
}

} // namespace

TEST_CASE("netstat plugin: netstat_list reports this process's own real TCP LISTEN socket as a "
          "7-column row (attribution's prefix baseline)",
          "[agent][netstat][netstat_attribution]") {
    auto plugin = load_plugin("netstat");
    EphemeralTcpListener listener;
    const pid_t self = getpid();

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin.descriptor, "netstat_list");
    CHECK(result.rc == 0);

    auto line = find_line(result.captured, std::format("tcp|127.0.0.1|{}|", listener.port));
    REQUIRE_FALSE(line.empty());

    auto fields = split_fields(line);
    // proto|local_addr|local_port|remote_addr|remote_port|state|pid -- exactly 7.
    REQUIRE(fields.size() == 7);
    CHECK(fields[0] == "tcp");
    CHECK(fields[1] == "127.0.0.1");
    CHECK(fields[2] == std::to_string(listener.port));
    CHECK(fields[5] == "LISTEN");
    CHECK(fields[6] == std::to_string(self));
}

TEST_CASE("netstat plugin: attribution reports this process's own real TCP LISTEN socket as a "
          "9-column row with resolved process name/path",
          "[agent][netstat][netstat_attribution]") {
    auto plugin = load_plugin("netstat");
    EphemeralTcpListener listener;
    const pid_t self = getpid();

    // Ground truth for the name/path assertions, read independently of the
    // plugin under test via the same libproc calls
    // yuzu::shared::resolve_proc_name_path() wraps -- an objective
    // cross-check, not a re-assertion of the plugin's own claimed value.
    char name_buf[PROC_PIDPATHINFO_MAXSIZE]{};
    proc_name(self, name_buf, sizeof(name_buf));
    char path_buf[PROC_PIDPATHINFO_MAXSIZE]{};
    proc_pidpath(self, path_buf, sizeof(path_buf));
    const std::string expected_name(name_buf);
    const std::string expected_path(path_buf);
    REQUIRE_FALSE(expected_name.empty());
    REQUIRE_FALSE(expected_path.empty());

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin.descriptor, "attribution");
    CHECK(result.rc == 0);

    auto line = find_line(result.captured, std::format("tcp|127.0.0.1|{}|", listener.port));
    REQUIRE_FALSE(line.empty());

    auto fields = split_fields(line);
    // proto|local_addr|local_port|remote_addr|remote_port|state|pid|process_name|process_path.
    // Reverting to sockwho's old pid-first layout, or dropping a column,
    // either shifts this count or misplaces pid -- this only matches the
    // documented 9-column, pid-stays-put contract.
    REQUIRE(fields.size() == 9);
    CHECK(fields[0] == "tcp");
    CHECK(fields[1] == "127.0.0.1");
    CHECK(fields[2] == std::to_string(listener.port));
    CHECK(fields[5] == "LISTEN");
    CHECK(fields[6] == std::to_string(self));
    CHECK(fields[7] == expected_name);
    CHECK(fields[8] == expected_path);
}

TEST_CASE("netstat plugin: attribution's row is netstat_list's row plus exactly two appended "
          "columns, for the same live socket",
          "[agent][netstat][netstat_attribution]") {
    // Direct regression pin for netstat_plugin.cpp's own file-header claim
    // ("attribution emits netstat_list's 7 columns as a prefix ... pid stays
    // in its netstat_list position") -- asserted against two real dispatches
    // of the identical live listener rather than trusted from the comment.
    auto plugin = load_plugin("netstat");
    EphemeralTcpListener listener;

    yuzu::agent::LocalDispatcher dispatcher;
    auto list_result = dispatcher.run(plugin.descriptor, "netstat_list");
    auto attrib_result = dispatcher.run(plugin.descriptor, "attribution");
    CHECK(list_result.rc == 0);
    CHECK(attrib_result.rc == 0);

    auto needle = std::format("tcp|127.0.0.1|{}|", listener.port);
    auto list_line = find_line(list_result.captured, needle);
    auto attrib_line = find_line(attrib_result.captured, needle);
    REQUIRE_FALSE(list_line.empty());
    REQUIRE_FALSE(attrib_line.empty());

    auto list_fields = split_fields(list_line);
    auto attrib_fields = split_fields(attrib_line);
    REQUIRE(list_fields.size() == 7);
    REQUIRE(attrib_fields.size() == 9);
    for (size_t i = 0; i < list_fields.size(); ++i) {
        CHECK(attrib_fields[i] == list_fields[i]);
    }
}

TEST_CASE("netstat plugin: attribution reports an empty (never fabricated) state for a real UDP "
          "socket, still as a 9-column row",
          "[agent][netstat][netstat_attribution]") {
    // Edge case macos_socket_walk.hpp handles specially: UDP is
    // connectionless, so SocketInfo::state stays default-constructed empty
    // rather than a fabricated "LISTEN" (the same UDP contract
    // test_wave3_pr31_macos_actions.cpp's ioc test regression-pins for
    // network_diag/ioc). This proves netstat.attribution's own row assembly
    // preserves that empty state through the extra pid/name/path columns
    // instead of, say, off-by-one-shifting them into the state slot.
    auto plugin = load_plugin("netstat");
    BoundUdpSocket sock;
    const pid_t self = getpid();

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin.descriptor, "attribution");
    CHECK(result.rc == 0);

    auto line = find_line(result.captured, std::format("udp|127.0.0.1|{}|", sock.port));
    REQUIRE_FALSE(line.empty());

    auto fields = split_fields(line);
    REQUIRE(fields.size() == 9);
    CHECK(fields[0] == "udp");
    CHECK(fields[5].empty()); // state
    CHECK(fields[6] == std::to_string(self));
}

TEST_CASE("resolve_proc_name_path returns nullopt when the process cannot be resolved",
          "[agent][netstat][netstat_attribution]") {
    // netstat.attribution's macOS enrichment (netstat_plugin.cpp's
    // enumerate_and_stream_attribution) treats a nullopt return from
    // resolve_proc_name_path() as "leave process_name/process_path empty for
    // this row" -- it does NOT substitute an "unknown" sentinel the way the
    // Windows WMI bounded-migration now deliberately does (see
    // changelog.d/3404-hardware-wmi-bounded.fixed.md and the code comment at
    // the sentinel-row emission site in hardware_plugin.cpp). This pins the
    // "process lookup fails" branch itself: a pid libproc can't resolve a
    // name OR a path for -- the deterministic proxy for that scenario in a
    // process-owned-unprivileged test binary, since a real "socket present
    // but owning process gone" row can't be forced from here (macOS closes a
    // process's fds, sockets included, the moment it exits, so there is no
    // window in which the socket walk can still see a since-vanished pid;
    // forcing a permission-denied case instead would depend on other users'
    // processes existing on the CI host, which isn't guaranteed).
    constexpr pid_t kDefinitelyNonexistentPid = 999999999;
    auto resolved = yuzu::shared::resolve_proc_name_path(kDefinitelyNonexistentPid);
    REQUIRE_FALSE(resolved.has_value());
}

#endif // __APPLE__
