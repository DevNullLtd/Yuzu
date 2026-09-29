/**
 * test_wave3_pr31_macos_actions.cpp -- gate-1 remediation (code-review
 * finding: the syscall-promotion migration's new pure helpers
 * (macos_socket_walk.hpp, os_info_macos.hpp) were tested, but nothing
 * proved the actual migrated plugin ACTIONS -- os_info::os_name/os_version/
 * os_build, processes::list, network_diag::listening, ioc::check -- reach
 * those helpers correctly when dispatched for real. A wiring bug (wrong
 * sysctl key, wrong descriptor rung, wrong action name, a dropped mapping
 * rule) would compile clean and pass every existing test.
 *
 * Loads the ACTUAL built .dylib for each of the four plugins via
 * PluginHandle::load and drives it through yuzu::agent::LocalDispatcher --
 * the same pattern test_users_posix_actions.cpp established (Wave 2 WP-A
 * remediation, same root cause: "migrated but never proven to actually
 * run"). Darwin-only: all four plugins' migrated acquisition paths in this
 * PR are macOS-specific.
 *
 * The ioc/check case additionally regression-pins the check_ports() UDP fix
 * from this same gate pass: macos_socket_walk.hpp deliberately leaves UDP
 * rows with an empty state (never a fabricated "LISTEN"), and check_ports()
 * originally required state=="LISTEN"||"ESTABLISHED" -- so a live UDP
 * listener silently stopped matching. check_ports() now also accepts an
 * empty state; this test binds a real UDP socket and would fail without
 * that fix.
 *
 * gate-2 (/adversarial-review) remediation, on top of the above: two HIGH
 * findings, each independently confirmed by both reviewers via live
 * reproduction --
 *   (1) load_plugin() returning nullopt on a load/descriptor failure and
 *       every call site WARN-ing and returning let the "proof the plugin
 *       actually runs" tests pass with zero assertions when the .dylib
 *       exists but fails to load (bad ABI, missing export, null
 *       descriptor) -- a false-green on exactly the wiring-bug class this
 *       file exists to catch (tests/meson.build's link_depends on the four
 *       *_plugin_lib targets already makes "file not found" close to
 *       unreachable in a real build, but does nothing for a load-time
 *       failure). load_plugin() now hard-fails via FAIL() with a message
 *       naming which step failed, instead of returning std::nullopt for a
 *       caller to silently skip.
 *   (2) EphemeralTcpListener/BoundUdpSocket stored a raw `int fd` and
 *       issued REQUIRE()s (bind/listen/getsockname/port) *inside* their
 *       constructors, after `::socket()` already succeeded -- a failing
 *       REQUIRE throws and unwinds before the constructor completes, and a
 *       not-fully-constructed object never runs its own destructor, so the
 *       fd leaked for the rest of the ~1800-case test process. Both now
 *       store `yuzu::agent::ScopedFd` (agents/core/include/yuzu/agent/
 *       scoped_fd.hpp) and assign it immediately after `::socket()` --
 *       a member subobject that finished constructing IS destroyed during
 *       stack unwind even when the owning object's constructor does not
 *       complete, so this closes the leak on every REQUIRE below it.
 */
#ifdef __APPLE__

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/agent/scoped_fd.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

// Generalizes test_users_posix_actions.cpp's find_users_plugin() to any
// plugin name -- same search order (env-provided build root, meson's
// CWD=build-root convention, a couple of relative fallbacks).
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

// Loads `plugin_name`'s real built .dylib or fails the current test case
// outright. tests/meson.build's link_depends on os_info_plugin_lib /
// processes_plugin_lib / network_diag_plugin_lib / ioc_plugin_lib makes the
// dylib a hard build prerequisite of this very test binary, so "file not
// found" should never legitimately happen in a real build; a load failure
// (bad ABI, missing export) or a null descriptor is exactly the class of
// wiring regression this file exists to catch, not an optional capability
// to skip past.
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

// Ground truth for the os_info assertions, read independently of the
// plugin under test via the same sysctlbyname() the plugin's fallback
// chain uses -- an objective cross-check, not a re-assertion of the
// plugin's own claimed value.
std::string sysctl_string(const char* name) {
    size_t len = 0;
    if (::sysctlbyname(name, nullptr, &len, nullptr, 0) != 0 || len == 0)
        return {};
    std::string value(len, '\0');
    if (::sysctlbyname(name, value.data(), &len, nullptr, 0) != 0)
        return {};
    if (!value.empty() && value.back() == '\0')
        value.pop_back();
    return value;
}

// RAII ephemeral TCP listener bound to 127.0.0.1:0 -- mirrors
// test_socket_walk.cpp's EphemeralListener (separate translation unit, so
// duplicated rather than shared). The socket fd is a ScopedFd assigned
// immediately on acquisition: a REQUIRE below it that fails throws and
// unwinds before this constructor completes, and C++ never runs a
// not-fully-constructed object's OWN destructor -- but an already-
// constructed member subobject (this ScopedFd) IS destroyed during that
// same unwind, so the fd still gets closed instead of leaking.
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

// RAII bound-but-unconnected UDP socket -- connectionless, so bind() alone
// is enough for it to show up in the libproc walk (SOCKINFO_IN, no LISTEN
// concept). No listen()/accept() involved. Same ScopedFd-on-acquisition
// reasoning as EphemeralTcpListener above.
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

// A real ESTABLISHED TCP pair (client + accepted server side), both ends on
// 127.0.0.1 -- the only way to prove network_diag's "connections" action
// (migrated in this PR alongside "listening", but previously untested: gate-3
// /governance quality-engineer finding). Same ScopedFd-on-acquisition
// reasoning as the other fixtures above; three sockets (listener, accepted,
// client), each its own ScopedFd.
struct ConnectedTcpPair {
    yuzu::agent::ScopedFd listener;
    yuzu::agent::ScopedFd server_side;
    yuzu::agent::ScopedFd client_side;
    uint16_t listen_port{0};
    uint16_t client_port{0};

    ConnectedTcpPair() {
        listener = yuzu::agent::ScopedFd(::socket(AF_INET, SOCK_STREAM, 0));
        REQUIRE(listener.valid());
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = 0;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        REQUIRE(::bind(listener.get(), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) ==
               0);
        REQUIRE(::listen(listener.get(), 1) == 0);
        struct sockaddr_in bound{};
        socklen_t len = sizeof(bound);
        REQUIRE(::getsockname(listener.get(), reinterpret_cast<struct sockaddr*>(&bound), &len) ==
               0);
        listen_port = ntohs(bound.sin_port);
        REQUIRE(listen_port != 0);

        client_side = yuzu::agent::ScopedFd(::socket(AF_INET, SOCK_STREAM, 0));
        REQUIRE(client_side.valid());
        struct sockaddr_in connect_addr{};
        connect_addr.sin_family = AF_INET;
        connect_addr.sin_port = htons(listen_port);
        connect_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        REQUIRE(::connect(client_side.get(), reinterpret_cast<struct sockaddr*>(&connect_addr),
                          sizeof(connect_addr)) == 0);

        server_side = yuzu::agent::ScopedFd(::accept(listener.get(), nullptr, nullptr));
        REQUIRE(server_side.valid());

        struct sockaddr_in client_bound{};
        socklen_t client_len = sizeof(client_bound);
        REQUIRE(::getsockname(client_side.get(),
                              reinterpret_cast<struct sockaddr*>(&client_bound),
                              &client_len) == 0);
        client_port = ntohs(client_bound.sin_port);
        REQUIRE(client_port != 0);
    }
    ConnectedTcpPair(const ConnectedTcpPair&) = delete;
    ConnectedTcpPair& operator=(const ConnectedTcpPair&) = delete;
};

} // namespace

TEST_CASE("os_info plugin: os_name/os_version/os_build read the real host plist/sysctl chain",
          "[agent][os_info][wave3_pr31]") {
    auto plugin = load_plugin("os_info");

    const auto expected_product_version = sysctl_string("kern.osproductversion");
    const auto expected_build = sysctl_string("kern.osversion");
    if (expected_product_version.empty() || expected_build.empty()) {
        // Genuine environment-capability gap (sysctlbyname unavailable),
        // not a plugin-load failure -- WARN-and-skip stays correct here.
        WARN("sysctlbyname(kern.osproductversion/kern.osversion) unavailable on this host -- "
             "skipping content cross-check");
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;

    {
        auto result = dispatcher.run(plugin.descriptor, "os_name");
        CHECK(result.rc == 0);
        // Reverting the migrated chain (wrong plist path, dropped fallback,
        // wrong descriptor wiring) either fails this call or falls all the
        // way to the "macOS unknown" literal fallback -- this only matches
        // if the real plist/sysctl chain actually ran.
        CHECK(result.captured.find("os_name|macOS " + expected_product_version) !=
             std::string::npos);
    }
    {
        auto result = dispatcher.run(plugin.descriptor, "os_version");
        CHECK(result.rc == 0);
        CHECK(result.captured.find("os_product_version|" + expected_product_version) !=
             std::string::npos);
    }
    {
        auto result = dispatcher.run(plugin.descriptor, "os_build");
        CHECK(result.rc == 0);
        CHECK(result.captured.find("os_build|" + expected_build) != std::string::npos);
    }
}

TEST_CASE("processes plugin: list enumerates this process, skips pid 0, sorts ascending by pid",
          "[agent][processes][wave3_pr31]") {
    auto plugin = load_plugin("processes");

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin.descriptor, "list");
    CHECK(result.rc == 0);

    const pid_t self = getpid();
    // Reverting to the raw p_comm/no-filter pass-through, or wiring the
    // action to the wrong enumerator, either omits this row or truncates
    // its name -- this only matches the real KERN_PROC_ALL + proc_pidpath
    // mapping.
    CHECK(result.captured.find("proc|" + std::to_string(self) + "|") != std::string::npos);
    CHECK(result.captured.find("proc|0|") == std::string::npos);

    // Parse every "proc|<pid>|" row and assert strictly non-decreasing pid
    // order (ps's contract, per the migration's own mapping comment).
    std::vector<long> pids;
    std::string::size_type pos = 0;
    while ((pos = result.captured.find("proc|", pos)) != std::string::npos) {
        pos += 5; // skip "proc|"
        auto pipe = result.captured.find('|', pos);
        if (pipe == std::string::npos)
            break;
        pids.push_back(std::strtol(result.captured.substr(pos, pipe - pos).c_str(), nullptr, 10));
        pos = pipe;
    }
    REQUIRE(pids.size() > 1);
    CHECK(std::is_sorted(pids.begin(), pids.end()));
}

TEST_CASE("network_diag plugin: listening finds this process's own real TCP listener",
          "[agent][network_diag][wave3_pr31]") {
    auto plugin = load_plugin("network_diag");

    EphemeralTcpListener listener;
    const pid_t self = getpid();

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin.descriptor, "listening");
    CHECK(result.rc == 0);

    // Reverting the lsof->walk_sockets migration, or wiring "listening" to
    // the wrong filter/output, either drops this row or misreports its
    // pid/port -- this only matches the real dispatch -> walk_sockets ->
    // filter(LISTEN) -> output chain.
    const std::string expect =
        std::format("listen|tcp|127.0.0.1|{}|{}", listener.port, self);
    CHECK(result.captured.find(expect) != std::string::npos);
}

TEST_CASE("network_diag plugin: connections finds this process's own real ESTABLISHED TCP pair",
          "[agent][network_diag][wave3_pr31]") {
    auto plugin = load_plugin("network_diag");

    ConnectedTcpPair conn;
    const pid_t self = getpid();

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin.descriptor, "connections");
    CHECK(result.rc == 0);

    // Reverting the lsof->walk_sockets migration for "connections", or
    // wiring it to the wrong filter/output, either drops this row or
    // misreports local/remote addr:port/pid -- this only matches the real
    // dispatch -> walk_sockets -> filter(ESTABLISHED) -> output chain, from
    // the accepted server-side socket's point of view.
    const std::string expect = std::format("conn|tcp|127.0.0.1|{}|127.0.0.1|{}|{}",
                                           conn.listen_port, conn.client_port, self);
    CHECK(result.captured.find(expect) != std::string::npos);
}

TEST_CASE("ioc plugin: check matches a real TCP listener and a real UDP socket by port",
          "[agent][ioc][wave3_pr31]") {
    auto plugin = load_plugin("ioc");

    EphemeralTcpListener tcp_listener;
    BoundUdpSocket udp_socket;

    const std::string ports_csv =
        std::to_string(tcp_listener.port) + "," + std::to_string(udp_socket.port);
    std::vector<YuzuParam> params{{"ports", ports_csv.c_str()}};

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin.descriptor, "check", params);
    CHECK(result.rc == 0);

    // TCP: real listener must match via its real LISTEN state -- proves the
    // migrated get_connections()/walk_sockets() chain reaches check_ports().
    CHECK(result.captured.find(std::format("port|{}|true|", tcp_listener.port)) !=
         std::string::npos);

    // UDP: regression pin for this gate's check_ports() fix. Before the
    // fix, walk_sockets()'s deliberately-empty UDP state made every real
    // UDP listener silently unmatched (a false negative in an IOC/port
    // check tool) -- this line fails without that fix.
    CHECK(result.captured.find(std::format("port|{}|true|", udp_socket.port)) !=
         std::string::npos);
}

#endif // __APPLE__
