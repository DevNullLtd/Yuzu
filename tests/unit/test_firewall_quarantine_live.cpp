/**
 * test_firewall_quarantine_live.cpp -- real-host runs of the firewall plugin's
 * containment actions. HIDDEN: tagged [.][firewall_quarantine_live], so the
 * shard partition never selects it; it changes the firewall of the machine it
 * runs on and needs root / Administrator.
 *
 * Run (on a disposable or operator-attended host):
 *   YUZU_FIREWALL_QUARANTINE_LIVE=1 \
 *   YUZU_FQ_SERVER_ADDRESS=<ip:port reachable control endpoint> \
 *   YUZU_FQ_PROBE_TARGET=<ip:port reachable BEFORE the quarantine> \
 *   [YUZU_FQ_STREAM_TARGET=<ip:port of an HTTP server, for the pre-established-stream case>] \
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
 * macOS: the pf-anchor leg follows the design note's review. Until then the
 * only live assertion is the typed unsupported row; the cases below SKIP.
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
    return {};
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
    return std::make_pair(ip->ip_text(), ip->port);
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
struct LiveRig {
    yuzu::test::TempDbFile db{"yuzu_test_fq_"};
    std::optional<yuzu::agent::KvStore> kv;
    std::optional<yuzu::agent::PluginHandle> plugin;
    std::unique_ptr<yuzu::agent::StandalonePluginContext> ctx;
    yuzu::agent::LocalDispatcher dispatcher;

    LiveRig(const std::string& server_address, const std::string& resolved_ip) {
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
                {"agent.server_address_resolved", resolved_ip}},
            &*kv);
        REQUIRE(plugin->descriptor()->init(ctx->get()) == 0);
    }
    ~LiveRig() {
        if (plugin && ctx) {
            (void)run("release");
            plugin->descriptor()->shutdown(ctx->get());
        }
    }
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

#if defined(__APPLE__)
#define LIVE_NOT_ON_MACOS() SKIP("macOS pf-anchor leg follows the design note's review")
#else
#define LIVE_NOT_ON_MACOS() (void)0
#endif

} // namespace

TEST_CASE("live: macOS answers one typed unsupported row until the pf-anchor leg lands",
          "[.][firewall_quarantine_live]") {
#if defined(__APPLE__)
    if (!live_enabled())
        SKIP("set YUZU_FIREWALL_QUARANTINE_LIVE=1");
    auto loaded = load_firewall();
    REQUIRE(loaded.has_value());
    yuzu::agent::LocalDispatcher d;
    for (const char* action : {"quarantine", "release", "quarantine_status", "quarantine_allow"}) {
        const auto r = d.run(loaded->descriptor(), action);
        INFO(action);
        CHECK(r.rc == 1);
        CHECK(has_row(r.captured, "status|refused|unsupported_platform"));
        CHECK(r.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    }
#else
    SKIP("macOS only");
#endif
}

TEST_CASE("live: apply, verify the block, release restores the host byte-identical",
          "[.][firewall_quarantine_live]") {
    LIVE_NOT_ON_MACOS();
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
    LIVE_NOT_ON_MACOS();
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

TEST_CASE("live: a control channel that cannot be reached rolls the apply back",
          "[.][firewall_quarantine_live]") {
    LIVE_NOT_ON_MACOS();
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

TEST_CASE("live: quarantine_status shapes", "[.][firewall_quarantine_live]") {
    LIVE_NOT_ON_MACOS();
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
#endif
    const auto degraded = rig.run("quarantine_status");
    CHECK(has_prefix(degraded.captured, "status|degraded|"));
}

TEST_CASE("live: init completes an interrupted release and re-applies a lost containment",
          "[.][firewall_quarantine_live]") {
    LIVE_NOT_ON_MACOS();
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
#endif
    rig.restart();
    CHECK(has_row(rig.run("quarantine_status").captured, "status|active"));
    CHECK(probe(env.probe_target) == fq::ProbeOutcome::timeout);
}

TEST_CASE("live: a ttl release is a no-op before expiry and releases after",
          "[.][firewall_quarantine_live]") {
    LIVE_NOT_ON_MACOS();
    LIVE_OR_SKIP(env);
    LiveRig rig(env.server, env.server_ip());
    Watchdog dog(120s, [&] { (void)rig.run("release"); });

    auto params = env.quarantine_params();
    params.emplace_back("ttl_seconds", "60");
    const auto q = rig.run("quarantine", params);
    // the standalone harness has no trigger engine, so the TTL trigger cannot register:
    // the quarantine stays applied and says so
    CHECK((has_row(q.captured, "status|active") || has_row(q.captured, "status|partial")));
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

#if defined(__linux__)
namespace {

/// Real nft, real temp files, but every `nft -f` after the first fails: a
/// runner forced to fail in the middle of an update.
struct FlakyNftRunner {
    int loads = 0;
    int fail_from_load = 2;
    fq::Runner fn() {
        return [this](const fq::Argv& argv, std::chrono::milliseconds budget) {
            if (argv.size() > 1 && argv[1] == "-f" && ++loads >= fail_from_load) {
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

TEST_CASE("live (linux nft): a failed update keeps the previous generation in force",
          "[.][firewall_quarantine_live]") {
    LIVE_OR_SKIP(env);
    if (::access("/usr/sbin/nft", X_OK) != 0)
        SKIP("nft is not installed on this host");
    FlakyNftRunner runner;
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
