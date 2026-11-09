/**
 * test_firewall_quarantine_live.cpp -- the BUILT firewall plugin's containment
 * actions, driven through its descriptor. Two kinds of case live here:
 *
 *  - "action boundary" cases, tagged [agent][firewall_quarantine]: they run in the
 *    normal agent suite on every OS, need no privilege and never reach the host
 *    firewall -- each one dispatches along a path the plugin refuses (or answers)
 *    BEFORE its first OS call, over a fresh KV store. They prove the action
 *    routing, parameter checks, record read and result emission of the real
 *    plugin, which the pure-core tests cannot.
 *  - live cases, tagged [.][firewall_quarantine_live]: HIDDEN, so the shard
 *    partition never selects them; they change the firewall of the machine they
 *    run on and need root / Administrator. The rest of this comment is about
 *    those.
 *
 * Running the live tag WITHOUT YUZU_FIREWALL_QUARANTINE_LIVE=1 skips every case
 * and Catch2 then exits 4 (all tests skipped), not 0: a harness that checks for
 * rc == 0 must set the variable first (rc 4 means the environment is unset, or an
 * OS filter matched nothing).
 *
 * Run (on a disposable or operator-attended host):
 *   YUZU_FIREWALL_QUARANTINE_LIVE=1 \
 *   YUZU_FQ_SERVER_ADDRESS=<ip:port reachable control endpoint> \
 *   YUZU_FQ_PROBE_TARGET=<ip:port reachable BEFORE the quarantine> \
 *   [YUZU_FQ_STREAM_TARGET=<ip:port of an HTTP server, for the pre-established-stream case>] \
 *     (the control-stream case opens a stream to YUZU_FQ_SERVER_ADDRESS the same way and
 *     SKIPs when that endpoint is not an HTTP server) \
 *   [YUZU_FQ_OPERATOR_EXCEPTION=<addr[:port][/proto][/dir], e.g. 10.0.0.5:22/tcp/in>] \
 *   yuzu_agent_tests '[firewall_quarantine_live]'
 *
 * A host that is quarantined over SSH loses the session unless the operator's
 * source is passed as YUZU_FQ_OPERATOR_EXCEPTION. A 120 s watchdog releases the
 * quarantine if a case hangs (the standalone harness has no trigger engine, so
 * the plugin's own TTL trigger cannot fire here).
 *
 * Loads the BUILT plugin (firewall.dll / firewall.so / firewall.dylib) the way
 * the agent does and drives it through LocalDispatcher. With
 * YUZU_FIREWALL_QUARANTINE_LIVE=1 set, a plugin that cannot be loaded is a hard
 * FAILURE, never a skip: a live run that silently tested nothing is the failure
 * mode this guard exists for.
 *
 * macOS: the pf sub-anchor leg runs for real here and ONLY here: this TU is
 * hidden and gated on YUZU_FIREWALL_QUARANTINE_LIVE=1, and the live capture is
 * taken on a disposable macOS VM (never on a shared build host), because the
 * apply flushes every pf state on the machine and the cases below switch pf off
 * and on behind the plugin's back to prove the repair and the token handling.
 */

#include <catch2/catch_test_macros.hpp>

#include "firewall_quarantine_parsers.hpp"
#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <yuzu/agent/kv_store.hpp>
#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/agent/subprocess_runner.hpp>
#include <yuzu/plugin.hpp>

#include <icmp_probe.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif
#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

namespace fq = yuzu::firewall::quarantine;
namespace fs = std::filesystem;

namespace {

using namespace std::chrono_literals;

[[nodiscard]] std::string env_or(const char* name) {
    const char* v = std::getenv(name);
    return v ? v : "";
}

[[nodiscard]] bool live_enabled() { return env_or("YUZU_FIREWALL_QUARANTINE_LIVE") == "1"; }

#if defined(_WIN32)
constexpr const char* kPluginFile = "firewall.dll";
#elif defined(__APPLE__)
constexpr const char* kPluginFile = "firewall.dylib";
#else
constexpr const char* kPluginFile = "firewall.so";
#endif

std::expected<yuzu::agent::PluginHandle, yuzu::agent::LoadError> load_firewall() {
    std::vector<fs::path> dirs{
        fs::path{"agents"} / "plugins" / "firewall",
        fs::path{".."} / "agents" / "plugins" / "firewall",
        fs::path{"builddir"} / "agents" / "plugins" / "firewall",
    };
    if (auto* root = std::getenv("MESON_BUILD_ROOT"))
        dirs.push_back(fs::path{root} / "agents" / "plugins" / "firewall");
    for (const char* os_dir : {"build-macos", "build-linux", "build-windows"})
        dirs.push_back(fs::path{os_dir} / "agents" / "plugins" / "firewall");
    for (const auto& d : dirs) {
        std::error_code ec;
        const auto candidate = d / kPluginFile;
        if (fs::exists(candidate, ec) && !ec)
            return yuzu::agent::PluginHandle::load(candidate);
    }
    return yuzu::agent::PluginHandle::load(fs::path{"agents"} / "plugins" / "firewall" / kPluginFile);
}

[[nodiscard]] std::vector<std::string> rows_of(const std::string& captured) {
    std::vector<std::string> rows;
    std::size_t pos = 0;
    while (pos < captured.size()) {
        const auto nl = captured.find('\n', pos);
        auto line = captured.substr(pos, nl == std::string::npos ? nl : nl - pos);
        if (!line.empty())
            rows.push_back(std::move(line));
        if (nl == std::string::npos)
            break;
        pos = nl + 1;
    }
    return rows;
}

[[nodiscard]] bool has_row(const std::string& captured, const std::string& row) {
    for (const auto& r : rows_of(captured))
        if (r == row)
            return true;
    return false;
}

[[nodiscard]] bool has_prefix(const std::string& captured, const std::string& prefix) {
    for (const auto& r : rows_of(captured))
        if (r.rfind(prefix, 0) == 0)
            return true;
    return false;
}

/// Runs a tool and returns its combined output ("" when it did not run).
[[nodiscard, maybe_unused]] std::string capture(const std::vector<std::string>& argv) {
    auto res = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = 60s, .merge_stderr = true});
    return res.tool_ran ? res.output : std::string{};
}

#ifdef _WIN32
/// `netsh advfirewall firewall show rule` prints `Enabled:  Yes|No`; the column
/// padding varies, so look at the value after the label, not at the spacing.
[[nodiscard]] std::optional<bool> netsh_rule_enabled(const std::string& text) {
    const auto at = text.find("Enabled:");
    if (at == std::string::npos)
        return std::nullopt;
    const auto eol = text.find('\n', at);
    const auto line = text.substr(at, eol == std::string::npos ? eol : eol - at);
    return line.find("Yes") != std::string::npos;
}
#endif

/// The host firewall as text, for the byte-identical-after-release check.
[[nodiscard]] std::string firewall_snapshot() {
#if defined(_WIN32)
    const std::string netsh = "C:\\Windows\\System32\\netsh.exe";
    return capture({netsh, "advfirewall", "show", "allprofiles"}) +
           capture({netsh, "advfirewall", "firewall", "show", "rule", "name=all"});
#elif defined(__linux__)
    return capture({"/usr/sbin/nft", "list", "ruleset"}) + capture({"/usr/sbin/iptables-save"}) +
           capture({"/usr/sbin/ip6tables-save"});
#else
    // pf: the main ruleset, the Status line and the enable-reference count. `-s info`
    // also carries counters and uptime, which are never byte-identical, so only the
    // Status line is compared; the reference rows are counted, not compared as text.
    std::string out = capture({"/sbin/pfctl", "-s", "rules"});
    out += fq::pf_enabled(capture({"/sbin/pfctl", "-s", "info"})) ? "\nStatus: Enabled" : "\nStatus: Disabled";
    out += "\nreferences=" +
           std::to_string(fq::parse_pf_references(capture({"/sbin/pfctl", "-s", "References"})).size());
    return out;
#endif
}

/// The rules the containment put in force, as text, for "this address is (not) in
/// the live ruleset". macOS reads our anchor: `pfctl -s rules` lists only the main
/// ruleset.
[[nodiscard, maybe_unused]] std::string contained_rules_text() {
#if defined(__APPLE__)
    return capture({"/sbin/pfctl", "-a", std::string{fq::kPfAnchor}, "-s", "rules"});
#else
    return firewall_snapshot();
#endif
}

// ── a tiny portable TCP client (probe + pre-established stream) ─────────────

#ifdef _WIN32
struct WinsockOnce {
    WSADATA data{};
    bool ok = WSAStartup(MAKEWORD(2, 2), &data) == 0;
};
[[nodiscard]] bool net_init() {
    static const WinsockOnce w;
    return w.ok;
}
using SockT = SOCKET;
constexpr SockT kBadSock = INVALID_SOCKET;
void close_sock(SockT s) { ::closesocket(s); }
#else
[[nodiscard]] bool net_init() { return true; }
using SockT = int;
constexpr SockT kBadSock = -1;
void close_sock(SockT s) { ::close(s); }
#endif

[[nodiscard]] std::optional<std::pair<std::string, int>> split_endpoint(const std::string& s) {
    const auto ip = fq::parse_probe_target(s);
    if (!ip)
        return std::nullopt;
    return std::make_pair(fq::format_ip(ip->ip), ip->port);
}

/// One TCP connect to ip:port with a bounded wait; the tri-state outcome.
[[nodiscard]] fq::ProbeOutcome probe(const std::string& endpoint, int timeout_ms = 3000) {
    const auto ep = split_endpoint(endpoint);
    if (!ep || !net_init())
        return fq::ProbeOutcome::timeout;
    auto dst = yuzu::shared::resolve_first(ep->first, AF_UNSPEC);
    if (!dst)
        return fq::ProbeOutcome::timeout;
    yuzu::shared::set_port(*dst, ep->second);
    const auto r = yuzu::shared::tcp_sample(*dst, timeout_ms);
    return r.rtt_ms ? fq::ProbeOutcome::connected
                    : (r.refused ? fq::ProbeOutcome::refused : fq::ProbeOutcome::timeout);
}

/// A kept-open HTTP/1.1 connection: proves whether an ESTABLISHED stream survives.
class KeptStream {
public:
    ~KeptStream() {
        if (s_ != kBadSock)
            close_sock(s_);
    }
    [[nodiscard]] bool open(const std::string& endpoint) {
        const auto ep = split_endpoint(endpoint);
        if (!ep || !net_init())
            return false;
        auto dst = yuzu::shared::resolve_first(ep->first, AF_UNSPEC);
        if (!dst)
            return false;
        yuzu::shared::set_port(*dst, ep->second);
        s_ = ::socket(dst->family, SOCK_STREAM, IPPROTO_TCP);
        if (s_ == kBadSock)
            return false;
        set_timeouts(5000);
        return ::connect(s_, reinterpret_cast<const sockaddr*>(&dst->addr), dst->addr_len) == 0;
    }
    /// Sends one request and reports whether ANY reply byte comes back in time.
    [[nodiscard]] bool answers(int wait_ms) {
        static const char kReq[] = "GET / HTTP/1.1\r\nHost: yuzu-live\r\nConnection: keep-alive\r\n\r\n";
        set_timeouts(wait_ms);
        if (::send(s_, kReq, static_cast<int>(sizeof(kReq) - 1), 0) <= 0)
            return false;
        char buf[256];
        return ::recv(s_, buf, sizeof(buf), 0) > 0;
    }

private:
    void set_timeouts(int ms) {
#ifdef _WIN32
        const DWORD t = static_cast<DWORD>(ms);
        ::setsockopt(s_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&t), sizeof(t));
        ::setsockopt(s_, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&t), sizeof(t));
#else
        timeval tv{ms / 1000, (ms % 1000) * 1000};
        ::setsockopt(s_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ::setsockopt(s_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
    }
    SockT s_ = kBadSock;
};

/// Releases a quarantine the test left behind if a case hangs or throws: the
/// standalone harness has no trigger engine, so the plugin's TTL cannot do it.
class Watchdog {
public:
    template <class Fn> explicit Watchdog(std::chrono::seconds after, Fn&& release)
        : thread_([this, after, release = std::forward<Fn>(release)] {
              std::unique_lock lk(m_);
              if (!cv_.wait_for(lk, after, [this] { return done_; }))
                  release();
          }) {}
    ~Watchdog() {
        {
            std::lock_guard lk(m_);
            done_ = true;
        }
        cv_.notify_all();
        thread_.join();
    }
    Watchdog(const Watchdog&) = delete;
    Watchdog& operator=(const Watchdog&) = delete;

private:
    std::mutex m_;
    std::condition_variable cv_;
    bool done_ = false;
    std::thread thread_;
};

/// The plugin, loaded and init()-ed over a real KV store, the way the agent does.
/// Teardown shuts the plugin down and nothing else: the action-boundary cases use
/// this directly because they must never reach the OS (a `release` here would).
struct PluginRig {
    yuzu::test::TempDbFile db{"yuzu_test_fq_"};
    yuzu::test::TempDir data_dir{"yuzu_test_fq_data_"}; // agent.data_dir: the private staging dir lives here
    std::optional<yuzu::agent::KvStore> kv;
    std::optional<yuzu::agent::PluginHandle> plugin;
    std::unique_ptr<yuzu::agent::StandalonePluginContext> ctx;
    yuzu::agent::LocalDispatcher dispatcher;

    PluginRig(const std::string& server_address, const std::string& resolved_ip) {
        std::error_code mk_ec;
        fs::create_directories(data_dir.path, mk_ec);
        REQUIRE_FALSE(mk_ec);
        auto opened = yuzu::agent::KvStore::open(db.path);
        REQUIRE(opened.has_value());
        kv.emplace(std::move(*opened));
        auto loaded = load_firewall();
        // Hard FAIL, not a skip: with the live flag set a missing plugin means the run tested nothing.
        REQUIRE(loaded.has_value());
        plugin.emplace(std::move(*loaded));
        ctx = std::make_unique<yuzu::agent::StandalonePluginContext>(
            "firewall",
            std::unordered_map<std::string, std::string>{
                {"agent.server_address", server_address},
                {"agent.server_address_resolved", resolved_ip},
                {"agent.data_dir", data_dir.path.string()}},
            &*kv);
        REQUIRE(plugin->descriptor()->init(ctx->get()) == 0);
    }
    ~PluginRig() {
        if (plugin && ctx)
            plugin->descriptor()->shutdown(ctx->get());
    }
    PluginRig(const PluginRig&) = delete;
    PluginRig& operator=(const PluginRig&) = delete;

    /// Re-runs the plugin's init() the way an agent restart does.
    void restart() {
        plugin->descriptor()->shutdown(ctx->get());
        REQUIRE(plugin->descriptor()->init(ctx->get()) == 0);
    }
    yuzu::agent::LocalDispatcher::Result
    run(const char* action, std::vector<std::pair<std::string, std::string>> params = {}) {
        std::vector<YuzuParam> raw;
        raw.reserve(params.size());
        for (const auto& [k, v] : params)
            raw.push_back({k.c_str(), v.c_str()});
        return dispatcher.run(plugin->descriptor(), action, raw);
    }
    [[nodiscard]] std::optional<fq::QuarantineState> record() {
        auto v = kv->get("firewall", std::string{fq::kStateKey});
        return v ? fq::parse_state(*v) : std::nullopt;
    }
    void put_record(const fq::QuarantineState& s) {
        REQUIRE(kv->set("firewall", std::string{fq::kStateKey}, fq::serialize_state(s)));
    }
};

/// The live rig: releases whatever a case left applied, then shuts the plugin down.
struct LiveRig : PluginRig {
    using PluginRig::PluginRig;
    ~LiveRig() {
        if (plugin && ctx)
            (void)run("release");
    }
};

struct LiveEnv {
    std::string server = env_or("YUZU_FQ_SERVER_ADDRESS");
    std::string probe_target = env_or("YUZU_FQ_PROBE_TARGET");
    std::string stream_target = env_or("YUZU_FQ_STREAM_TARGET");
    std::string operator_exception = env_or("YUZU_FQ_OPERATOR_EXCEPTION");

    [[nodiscard]] std::string server_ip() const { return yuzu::agent::extract_server_host(server); }
    [[nodiscard]] bool complete() const { return !server.empty() && !probe_target.empty(); }
    [[nodiscard]] std::vector<std::pair<std::string, std::string>>
    quarantine_params(bool with_probe = true) const {
        std::vector<std::pair<std::string, std::string>> p;
        if (with_probe)
            p.emplace_back("probe_target", probe_target);
        if (!operator_exception.empty())
            p.emplace_back("exceptions", operator_exception);
        return p;
    }
};

/// Common gate for every live case.
#define LIVE_OR_SKIP(env)                                                                          \
    if (!live_enabled())                                                                           \
        SKIP("set YUZU_FIREWALL_QUARANTINE_LIVE=1 to run against this host's firewall");           \
    LiveEnv env;                                                                                   \
    if (!env.complete())                                                                           \
        FAIL("YUZU_FQ_SERVER_ADDRESS and YUZU_FQ_PROBE_TARGET are required under "                 \
             "YUZU_FIREWALL_QUARANTINE_LIVE=1")

/// Is the built plugin in this tree? A partial build (no agent plugins) has none,
/// and the neighbouring local-dispatcher tests skip the same way.
[[nodiscard]] bool firewall_plugin_built() { return load_firewall().has_value(); }

#define PLUGIN_RIG_OR_RETURN(rig)                                                                  \
    if (!firewall_plugin_built()) {                                                                \
        WARN("firewall plugin not found in the build tree -- skipping (build with "                \
             "-Dbuild_agent=true)");                                                               \
        SUCCEED();                                                                                 \
        return;                                                                                    \
    }                                                                                              \
    PluginRig rig("203.0.113.7:50051", "203.0.113.7")

/// A refusal as the plugin reports it: rc 1, `status|refused|<reason>` plus the
/// `refused|<reason>` row, and the typed result UNAVAILABLE / PARTIAL.
void check_refused(const yuzu::agent::LocalDispatcher::Result& r, const std::string& reason) {
    INFO(r.captured);
    CHECK(r.rc == 1);
    CHECK(has_row(r.captured, "status|refused|" + reason));
    CHECK(has_row(r.captured, "refused|" + reason));
    CHECK(r.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(r.result_provenance == "firewall:refused");
}

} // namespace

// ── the built plugin's action boundary: runs in the normal suite, never reaches the OS ──
//
// Every dispatch below is refused (or answered) before the plugin's first call
// into the host firewall: the checks precede the OS leg's construction, or the
// record they read is absent. The success and failure DECISIONS of an update are
// pinned on the pure core (test_firewall_quarantine_parsers.cpp); what only the
// built plugin can show is that the action is routed, its parameters are checked,
// the KV record is read and the result is emitted.

TEST_CASE("quarantine_allow: the plugin action refuses bad input and an inactive host",
          "[agent][firewall_quarantine]") {
    PLUGIN_RIG_OR_RETURN(rig);

    SECTION("an unknown or missing op") {
        check_refused(rig.run("quarantine_allow", {{"op", "bogus"}, {"exceptions", "198.18.0.9"}}),
                      "op_invalid");
        check_refused(rig.run("quarantine_allow", {{"exceptions", "198.18.0.9"}}), "op_invalid");
        check_refused(rig.run("quarantine_allow", {{"op", "ADD"}, {"exceptions", "198.18.0.9"}}),
                      "op_invalid");
    }
    SECTION("exceptions that do not parse") {
        const auto r = rig.run("quarantine_allow", {{"op", "add"}, {"exceptions", "garbage"}});
        INFO(r.captured);
        CHECK(r.rc == 1);
        CHECK(has_prefix(r.captured, "status|refused|exceptions_invalid:"));
        CHECK(has_prefix(r.captured, "refused|exceptions_invalid:"));
        CHECK(r.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        // one bad entry spoils the whole list: nothing is half-applied
        const auto mixed = rig.run("quarantine_allow",
                                   {{"op", "add"}, {"exceptions", "198.18.0.9:22/tcp/in,garbage"}});
        CHECK(has_prefix(mixed.captured, "status|refused|exceptions_invalid:"));
    }
    SECTION("no exceptions at all") {
        check_refused(rig.run("quarantine_allow", {{"op", "add"}}), "exceptions_required");
        check_refused(rig.run("quarantine_allow", {{"op", "remove"}, {"exceptions", ""}}),
                      "exceptions_required");
    }
    SECTION("a valid add or remove on a host that is not contained") {
        // This is the case that tells a working handler from one that refuses everything:
        // op, exceptions, the KV read and the record check all pass, and only the missing
        // containment refuses.
        check_refused(
            rig.run("quarantine_allow", {{"op", "add"}, {"exceptions", "198.18.0.9:22/tcp/in"}}),
            "not_active");
        check_refused(
            rig.run("quarantine_allow", {{"op", "remove"}, {"exceptions", "198.18.0.9:22/tcp/in"}}),
            "not_active");
        CHECK_FALSE(rig.record().has_value()); // a refusal writes nothing
    }
    SECTION("a record that is not active is not contained either") {
        // phase=applying and phase=releasing are both "an operation in progress": no update
        fq::QuarantineState st;
        st.phase = fq::Phase::releasing;
        st.generation = 3;
        st.backend = fq::BackendKind::nft;
        st.allow = *fq::build_allow_set("203.0.113.7", "203.0.113.7:50051", {}, {});
        rig.put_record(st);
        const auto r = rig.run("quarantine_allow", {{"op", "add"}, {"exceptions", "198.18.0.9"}});
        // a host without the recorded backend's tool has no leg at all, and refuses the same way
        CHECK(has_row(r.captured, "status|refused|not_active"));
        const auto after = rig.record();
        REQUIRE(after.has_value());
        CHECK(after->phase == fq::Phase::releasing); // untouched
        CHECK(after->generation == 3);
    }
}

TEST_CASE("quarantine: the plugin action checks its parameters before it touches anything",
          "[agent][firewall_quarantine]") {
    PLUGIN_RIG_OR_RETURN(rig);

    // below 60 s, above 30 days, and not a number
    check_refused(rig.run("quarantine", {{"ttl_seconds", "5"}}), "ttl_out_of_bounds");
    check_refused(rig.run("quarantine", {{"ttl_seconds", "59"}}), "ttl_out_of_bounds");
    check_refused(rig.run("quarantine", {{"ttl_seconds", "2592001"}}), "ttl_out_of_bounds");
    check_refused(rig.run("quarantine", {{"ttl_seconds", "soon"}}), "ttl_out_of_bounds");
    const auto bad = rig.run("quarantine", {{"exceptions", "garbage"}});
    CHECK(has_prefix(bad.captured, "status|refused|exceptions_invalid:"));
    CHECK(bad.rc == 1);
    CHECK_FALSE(rig.record().has_value()); // no recovery record was even started
}

TEST_CASE("release if_ttl_expired: with nothing contained, the trigger's firing is a clean no-op",
          "[agent][firewall_quarantine]") {
    PLUGIN_RIG_OR_RETURN(rig);

    // this is what the TTL interval trigger dispatches every 30 s; with no record it
    // must answer inactive and touch nothing (a bare `release` would run the OS undo)
    const auto r = rig.run("release", {{"if_ttl_expired", "1"}});
    INFO(r.captured);
    CHECK(r.rc == 0);
    CHECK(has_row(r.captured, "status|inactive"));
    CHECK(r.result_status == YUZU_RESULT_STATUS_OK);
    CHECK(r.result_provenance == "firewall:inactive");
    CHECK_FALSE(rig.record().has_value());
}

TEST_CASE("live: apply, verify the block, release restores the host byte-identical",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    const auto before = firewall_snapshot();
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    REQUIRE(probe(env.probe_target) != fq::ProbeOutcome::timeout); // reachable before
    const auto q = rig.run("quarantine", env.quarantine_params());
    INFO(q.captured);
    CHECK(q.rc == 0);
    CHECK(has_row(q.captured, "status|active"));
    CHECK(has_row(q.captured, "verify|control=ok|probe=blocked"));
    CHECK(probe(env.probe_target) == fq::ProbeOutcome::timeout); // blocked by the host itself

    const auto st = rig.run("quarantine_status");
    CHECK(has_row(st.captured, "status|active"));

    const auto rel = rig.run("release");
    INFO(rel.captured);
    CHECK(has_row(rel.captured, "status|inactive"));
    CHECK(probe(env.probe_target) != fq::ProbeOutcome::timeout); // reachable again
    CHECK(firewall_snapshot() == before);                        // nothing left behind, nothing lost
    CHECK_FALSE(rig.record().has_value());
}

TEST_CASE("live: a pre-established prohibited stream stops carrying data on apply",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    const auto target = env.stream_target.empty() ? env.probe_target : env.stream_target;
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    KeptStream stream;
    if (!stream.open(target))
        SKIP("YUZU_FQ_STREAM_TARGET (or the probe target) did not accept a connection");
    if (!stream.answers(3000))
        SKIP("the stream target is not an HTTP server that answers a keep-alive request");

    const auto q = rig.run("quarantine", env.quarantine_params());
    REQUIRE(has_row(q.captured, "status|active"));
    // The stream was ESTABLISHED before the apply; a second request on it must go unanswered.
    CHECK_FALSE(stream.answers(3000));
}

#ifdef _WIN32
TEST_CASE("live: an unrelated enabled allow rule is disabled for the duration and restored",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    const auto ep = split_endpoint(env.probe_target);
    REQUIRE(ep.has_value());
    const std::string netsh = "C:\\Windows\\System32\\netsh.exe";
    const std::string rule = "yuzu_test_fq_unrelated_allow";
    // An explicit Allow rule for exactly the probe target: a profile default-block alone would leave it live.
    (void)capture({netsh, "advfirewall", "firewall", "delete", "rule", "name=" + rule});
    REQUIRE(capture({netsh, "advfirewall", "firewall", "add", "rule", "name=" + rule, "dir=out",
                     "action=allow", "protocol=tcp", "remoteip=" + ep->first,
                     "remoteport=" + std::to_string(ep->second)})
                .find("Ok.") != std::string::npos);
    struct Cleanup {
        std::string netsh, rule;
        ~Cleanup() { (void)capture({netsh, "advfirewall", "firewall", "delete", "rule", "name=" + rule}); }
    } cleanup{netsh, rule};

    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });
    REQUIRE(probe(env.probe_target) != fq::ProbeOutcome::timeout);
    const auto q = rig.run("quarantine", env.quarantine_params());
    INFO(q.captured);
    CHECK((has_row(q.captured, "status|active") || has_row(q.captured, "status|partial")));
    // blocked although an Allow rule names it: the rule was disabled
    CHECK(probe(env.probe_target) == fq::ProbeOutcome::timeout);
    CHECK(netsh_rule_enabled(capture({netsh, "advfirewall", "firewall", "show", "rule",
                                      "name=" + rule})) == std::optional<bool>{false});

    (void)rig.run("release");
    CHECK(probe(env.probe_target) != fq::ProbeOutcome::timeout);
    CHECK(netsh_rule_enabled(capture({netsh, "advfirewall", "firewall", "show", "rule",
                                      "name=" + rule})) == std::optional<bool>{true});
}
#endif

TEST_CASE("live: a control-channel stream open before the apply keeps carrying data across the flush",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    KeptStream stream;
    if (!stream.open(env.server))
        SKIP("the control endpoint did not accept a connection");
    if (!stream.answers(3000))
        SKIP("the control endpoint is not an HTTP server that answers a keep-alive request");

    const auto q = rig.run("quarantine", env.quarantine_params());
    REQUIRE(has_row(q.captured, "status|active"));
    // The stream predates the apply and, on macOS, the `pfctl -F states` that follows the load.
    // The control rules are stateless in both directions, so the flush cannot touch it: no
    // reconnect, the reply still arrives. (A rebuilt state would lose the TCP window scale.)
    CHECK(stream.answers(3000));
}

TEST_CASE("live: a control channel that cannot be reached rolls the apply back",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    const auto before = firewall_snapshot();
    // Both inputs name a TEST-NET address nothing answers on: the verify's control check must fail.
    LiveRig rig("203.0.113.1:50051", "203.0.113.1");
    const auto q = rig.run("quarantine", env.quarantine_params());
    INFO(q.captured);
    CHECK(q.rc == 1);
    CHECK(has_row(q.captured, "rolled_back|control_unreachable"));
    CHECK_FALSE(rig.record().has_value());
    CHECK(firewall_snapshot() == before);
}

TEST_CASE("live: quarantine_allow adds and removes an exception through the plugin action",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    REQUIRE(has_row(rig.run("quarantine", env.quarantine_params()).captured, "status|active"));
    REQUIRE(rig.record().has_value());
    const auto gen0 = rig.record()->generation;
    const std::string exception = "198.18.0.9:22/tcp/in";
    CHECK(contained_rules_text().find("198.18.0.9") == std::string::npos);

    const auto add = rig.run("quarantine_allow", {{"op", "add"}, {"exceptions", exception}});
    INFO(add.captured);
    CHECK(add.rc == 0);
    CHECK(has_row(add.captured, "status|active"));
    CHECK(has_prefix(add.captured, "allow|exception|198.18.0.9"));
    REQUIRE(rig.record().has_value());
    CHECK(rig.record()->generation == gen0 + 1);
    CHECK(rig.record()->phase == fq::Phase::active);
    CHECK(contained_rules_text().find("198.18.0.9") != std::string::npos); // live, not just recorded
    CHECK(probe(env.probe_target) == fq::ProbeOutcome::timeout);           // still contained

    const auto rm = rig.run("quarantine_allow", {{"op", "remove"}, {"exceptions", exception}});
    INFO(rm.captured);
    CHECK(rm.rc == 0);
    CHECK(has_row(rm.captured, "status|active"));
    CHECK_FALSE(has_prefix(rm.captured, "allow|exception|198.18.0.9"));
    REQUIRE(rig.record().has_value());
    CHECK(rig.record()->generation == gen0 + 2);
    CHECK(contained_rules_text().find("198.18.0.9") == std::string::npos);
    CHECK(probe(env.probe_target) == fq::ProbeOutcome::timeout);

    CHECK(has_row(rig.run("release").captured, "status|inactive"));
}

TEST_CASE("live: quarantine_status shapes", "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    CHECK(has_row(rig.run("quarantine_status").captured, "status|inactive"));

    // no probe target: contained, but the block is reported as not proven
    const auto q = rig.run("quarantine", env.quarantine_params(/*with_probe=*/false));
    CHECK(has_row(q.captured, "status|active_unproven"));
    CHECK(has_row(q.captured, "verify|control=ok|probe=unproven"));
    CHECK(has_row(rig.run("quarantine_status").captured, "status|active_unproven"));

    // a record that remembers rules the policy store refused to disable is partial, never active
    auto rec = rig.record();
    REQUIRE(rec.has_value());
    auto partial = *rec;
    partial.os.rules_not_disabled = 2;
    rig.put_record(partial);
    CHECK(has_row(rig.run("quarantine_status").captured, "status|partial|rules_not_disabled"));
    rig.put_record(*rec);

    // the OS no longer enforces what the record says: degraded
#if defined(__linux__)
    (void)capture({"/usr/sbin/nft", "delete", "table", "inet", "yuzu_quarantine"});
    (void)capture({"/usr/sbin/iptables", "-D", "INPUT", "-j", "yuzu-fwq-" + std::to_string(rec->os.ipt_gen)});
#elif defined(_WIN32)
    (void)capture({"C:\\Windows\\System32\\netsh.exe", "advfirewall", "set", "allprofiles",
                   "firewallpolicy", "blockinbound,allowoutbound"});
#elif defined(__APPLE__)
    (void)capture({"/sbin/pfctl", "-a", std::string{fq::kPfAnchor}, "-F", "rules"});
#endif
    const auto degraded = rig.run("quarantine_status");
    CHECK(has_prefix(degraded.captured, "status|degraded|"));
}

TEST_CASE("live: init completes an interrupted release and re-applies a lost containment",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    const auto before = firewall_snapshot();
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    REQUIRE(has_row(rig.run("quarantine", env.quarantine_params()).captured, "status|active"));
    auto rec = rig.record();
    REQUIRE(rec.has_value());

    // an agent that died half-way through a release: phase `releasing`, rules still present
    auto releasing = *rec;
    releasing.phase = fq::Phase::releasing;
    rig.put_record(releasing);
    rig.restart();
    CHECK_FALSE(rig.record().has_value());
    CHECK(firewall_snapshot() == before);

    // a reboot: the record says active, the OS lost the rules; init restores them before any dispatch
    REQUIRE(has_row(rig.run("quarantine", env.quarantine_params()).captured, "status|active"));
    rec = rig.record();
    REQUIRE(rec.has_value());
#if defined(__linux__)
    (void)capture({"/usr/sbin/nft", "delete", "table", "inet", "yuzu_quarantine"});
#elif defined(_WIN32)
    (void)capture({"C:\\Windows\\System32\\netsh.exe", "advfirewall", "set", "allprofiles",
                   "firewallpolicy", "blockinbound,allowoutbound"});
#elif defined(__APPLE__)
    // the anchor is gone and pf is off while our (same-boot) token is still on record:
    // the repair path -- release the dead token, take a fresh one, reload
    (void)capture({"/sbin/pfctl", "-a", std::string{fq::kPfAnchor}, "-F", "rules"});
    (void)capture({"/sbin/pfctl", "-a", std::string{fq::kPfAnchor}, "-F", "nat"});
    (void)capture({"/sbin/pfctl", "-d"});
#endif
    rig.restart();
    CHECK(has_row(rig.run("quarantine_status").captured, "status|active"));
    CHECK(probe(env.probe_target) == fq::ProbeOutcome::timeout);
}

TEST_CASE("live: a ttl release is a no-op before expiry and releases after",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    auto params = env.quarantine_params();
    params.emplace_back("ttl_seconds", "60");
    const auto q = rig.run("quarantine", params);
    // the standalone harness has no trigger engine, so the TTL trigger cannot register:
    // the quarantine stays applied and says so, deterministically (the registration
    // contract itself is pinned against the engine's own parser in
    // test_firewall_quarantine_parsers.cpp)
    CHECK(has_row(q.captured, "status|partial"));
    CHECK(has_row(q.captured, "note|ttl_trigger_unregistered=1"));
    auto rec = rig.record();
    REQUIRE(rec.has_value());
    REQUIRE(rec->ttl_expires > 0);

    const auto early = rig.run("release", {{"if_ttl_expired", "1"}});
    CHECK(has_row(early.captured, "note|ttl_not_expired=1"));
    CHECK(rig.record().has_value());

    auto expired = *rec;
    expired.ttl_expires = 1; // long past
    rig.put_record(expired);
    const auto late = rig.run("release", {{"if_ttl_expired", "1"}});
    CHECK(has_row(late.captured, "status|inactive"));
    CHECK_FALSE(rig.record().has_value());
}

#if defined(__linux__) || defined(__APPLE__)
namespace {

/// Real nft / pfctl, real temp files, but every ruleset load after the first fails:
/// a runner forced to fail in the middle of an update. A load is `nft -f <file>` or
/// `pfctl -a <anchor> -f <file>`.
struct FlakyLoadRunner {
    int loads = 0;
    int fail_from_load = 2;
    fq::Runner fn() {
        return [this](const fq::Argv& argv, std::chrono::milliseconds budget) {
            const bool is_load = argv.size() > 1 && (argv[1] == "-f" || (argv.size() == 5 && argv[3] == "-f"));
            if (is_load && ++loads >= fail_from_load) {
                fq::ToolResult t;
                t.ran = true;
                t.exit_code = 1;
                t.output = "Error: forced failure";
                return t;
            }
            auto res = yuzu::agent::run_bounded_subprocess(
                argv, yuzu::agent::SubprocessOptions{.deadline = budget, .merge_stderr = true});
            fq::ToolResult t;
            t.ran = res.tool_ran;
            t.exit_code = res.exit_code;
            t.timed_out = res.timed_out;
            t.truncated = res.output_truncated;
            t.output = std::move(res.output);
            return t;
        };
    }
};

struct MemStore final : fq::StateStore {
    std::optional<fq::QuarantineState> s;
    fq::StateLoad load() override {
        fq::StateLoad l;
        if (s) {
            l.kind = fq::StateLoad::Kind::ok;
            l.state = *s;
        }
        return l;
    }
    bool save(const fq::QuarantineState& st) override {
        s = st;
        return true;
    }
    bool erase() override {
        s.reset();
        return true;
    }
};

fq::Stage real_stage() {
    return [](std::string_view stem, std::string_view suffix,
              std::string_view contents) -> std::optional<fq::StagedFile> {
        auto tmp = yuzu::TempFile::create(stem, suffix);
        if (!tmp)
            return std::nullopt;
        {
            std::ofstream f(tmp->path(), std::ios::binary | std::ios::trunc);
            f.write(contents.data(), static_cast<std::streamsize>(contents.size()));
        }
        auto holder = std::make_shared<yuzu::TempFile>(std::move(*tmp));
        return fq::StagedFile{holder->path(), holder};
    };
}

} // namespace
#endif

#if defined(__linux__)
TEST_CASE("live (linux nft): a failed update keeps the previous generation in force",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    if (::access("/usr/sbin/nft", X_OK) != 0)
        SKIP("nft is not installed on this host");
    FlakyLoadRunner runner;
    fq::NftLeg leg(runner.fn(), real_stage());
    MemStore store;
    fq::Env fenv{leg, store,
                 [](const std::string& ip, int port, std::chrono::milliseconds t) {
                     return probe(ip + ":" + std::to_string(port), static_cast<int>(t.count()));
                 },
                 [] { return static_cast<std::int64_t>(std::time(nullptr)); }};
    const auto exceptions =
        env.operator_exception.empty() ? std::vector<fq::Endpoint>{} : *fq::parse_exceptions_csv(env.operator_exception);
    auto allow = fq::build_allow_set(env.server_ip(), env.server, {}, exceptions);
    REQUIRE(allow.has_value());

    Watchdog dog(120s, [&] {
        fq::Deadline dl;
        (void)fq::release(fenv, fq::ReleaseRequest{}, dl);
    });
    fq::Deadline dl;
    fq::ApplyRequest req;
    req.allow = *allow;
    req.probe_target = env.probe_target;
    const auto applied = fq::apply_and_verify(fenv, req, dl);
    REQUIRE((applied.status == "active"));
    const auto table_before = capture({"/usr/sbin/nft", "list", "table", "inet", "yuzu_quarantine"});

    fq::Deadline dl2;
    const auto upd = fq::update(fenv, true, {*fq::parse_exception("198.18.0.9:22/tcp/in")}, dl2);
    CHECK(upd.status == "update_failed");
    CHECK(capture({"/usr/sbin/nft", "list", "table", "inet", "yuzu_quarantine"}) == table_before);
    CHECK(probe(env.probe_target) == fq::ProbeOutcome::timeout); // still blocked
    REQUIRE(store.s.has_value());
    CHECK(store.s->phase == fq::Phase::active);

    fq::Deadline dl3;
    CHECK(fq::release(fenv, fq::ReleaseRequest{}, dl3).status == "inactive");
}
#endif

#if defined(__APPLE__)
namespace {

/// The same value the plugin reads in-process, for a PfLeg built directly by a test.
std::optional<std::string> live_boot_time() {
    struct timeval tv{};
    size_t len = sizeof(tv);
    if (::sysctlbyname("kern.boottime", &tv, &len, nullptr, 0) != 0 || len != sizeof(tv))
        return std::nullopt;
    return std::to_string(static_cast<long long>(tv.tv_sec)) + "." +
           std::to_string(static_cast<long long>(tv.tv_usec));
}

[[nodiscard]] std::string pf_anchor_capture(const char* what) {
    return capture({"/sbin/pfctl", "-a", std::string{fq::kPfAnchor}, "-s", what});
}

} // namespace

TEST_CASE("live (macOS pf): the sub-anchor loads, sorts first, and release restores pf byte-identical",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    const auto before = firewall_snapshot();
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    const auto q = rig.run("quarantine", env.quarantine_params());
    INFO(q.captured);
    // `active` means pfctl accepted the whole anchor, `no nat all` and `no rdr all` included
    REQUIRE(has_row(q.captured, "status|active"));

    // Captured for the PR narrative: design-note open questions 3 (References layout),
    // 6 (Anchors layout) and 7 (a flush of an anchor that does not exist).
    const auto anchors = capture({"/sbin/pfctl", "-a", "com.apple", "-s", "Anchors"});
    INFO("-a com.apple -s Anchors:\n" << anchors);
    INFO("-s References:\n" << capture({"/sbin/pfctl", "-s", "References"}));
    INFO("anchor -s rules:\n" << pf_anchor_capture("rules"));
    INFO("anchor -s nat:\n" << pf_anchor_capture("nat"));
    CHECK(anchors.find(std::string{fq::kPfAnchorLeaf}) != std::string::npos);
    CHECK(fq::pf_siblings_before(anchors).empty()); // nothing is evaluated before us
    CHECK(fq::pf_anchor_referenced(capture({"/sbin/pfctl", "-s", "rules"})));
    CHECK(fq::pf_anchor_enforcing(pf_anchor_capture("rules")));
    CHECK(has_row(rig.run("quarantine_status").captured, "status|active"));

    const auto rel = rig.run("release");
    INFO(rel.captured);
    CHECK(has_row(rel.captured, "status|inactive"));
    // main ruleset, Status line and reference count equal their pre-quarantine values
    CHECK(firewall_snapshot() == before);
    // our anchor is empty, not merely unreferenced
    CHECK_FALSE(fq::pf_anchor_enforcing(pf_anchor_capture("rules")));
}

TEST_CASE("live (macOS pf): pf switched off behind the plugin's back is reported, then repaired",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    REQUIRE(has_row(rig.run("quarantine", env.quarantine_params()).captured, "status|active"));
    const auto old_token = rig.record() ? rig.record()->os.pf_token : std::string{};
    REQUIRE_FALSE(old_token.empty());

    (void)capture({"/sbin/pfctl", "-d"}); // another actor
    const auto st = rig.run("quarantine_status");
    INFO(st.captured);
    CHECK(has_row(st.captured, "status|degraded|pf_disabled"));
    CHECK(probe(env.probe_target) != fq::ProbeOutcome::timeout); // honestly uncontained

    const auto fixed = rig.run("quarantine", env.quarantine_params());
    INFO(fixed.captured);
    CHECK(has_row(fixed.captured, "status|active"));
    CHECK(has_row(fixed.captured, "note|repaired=1"));
    CHECK(probe(env.probe_target) == fq::ProbeOutcome::timeout);
    REQUIRE(rig.record().has_value());
    CHECK(rig.record()->os.pf_token != old_token); // a fresh reference, recorded

    CHECK(has_row(rig.run("release").captured, "status|inactive"));
}

TEST_CASE("live (macOS pf): a failed update keeps the previous generation in force",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    FlakyLoadRunner runner;
    fq::PfLeg leg(runner.fn(), real_stage(), live_boot_time);
    MemStore store;
    fq::Env fenv{leg, store,
                 [](const std::string& ip, int port, std::chrono::milliseconds t) {
                     return probe(ip + ":" + std::to_string(port), static_cast<int>(t.count()));
                 },
                 [] { return static_cast<std::int64_t>(std::time(nullptr)); }};
    const auto exceptions =
        env.operator_exception.empty() ? std::vector<fq::Endpoint>{} : *fq::parse_exceptions_csv(env.operator_exception);
    auto allow = fq::build_allow_set(env.server_ip(), env.server, {}, exceptions);
    REQUIRE(allow.has_value());

    Watchdog dog(120s, [&] {
        fq::Deadline dl;
        (void)fq::release(fenv, fq::ReleaseRequest{}, dl);
    });
    fq::Deadline dl;
    fq::ApplyRequest req;
    req.allow = *allow;
    req.probe_target = env.probe_target;
    REQUIRE(fq::apply_and_verify(fenv, req, dl).status == "active");
    const auto rules_before = pf_anchor_capture("rules");

    fq::Deadline dl2;
    const auto upd = fq::update(fenv, true, {*fq::parse_exception("198.18.0.9:22/tcp/in")}, dl2);
    CHECK(upd.status == "update_failed");
    CHECK(pf_anchor_capture("rules") == rules_before); // the anchor load is atomic: nothing changed
    CHECK(probe(env.probe_target) == fq::ProbeOutcome::timeout); // still blocked
    REQUIRE(store.s.has_value());
    CHECK(store.s->phase == fq::Phase::active);

    fq::Deadline dl3;
    CHECK(fq::release(fenv, fq::ReleaseRequest{}, dl3).status == "inactive");
}
#endif
