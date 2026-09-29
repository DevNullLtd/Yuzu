/// HA WS-8 (ADR-2002 §12): `/readyz`'s runtime Postgres-reachability signal —
/// the pure rule (pg_reachability_rules.hpp), the probe's publication/loop
/// contract with an injected ping, the real libpq probe's client-side deadlines
/// against a peer that never answers, and the real probe against Postgres
/// (terminated backend, simulated standby, unreachable port). Plus the pure
/// drain-wait rule behind `--shutdown-drain-seconds` (shutdown_drain_rules.hpp).

#include "pg_reachability_probe.hpp"
#include "pg_reachability_rules.hpp"
#include "shutdown_drain_rules.hpp"

#include "../test_helpers.hpp"
#include "pg/multi_host_dsn.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <atomic>
#include <chrono>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <filesystem>
#include <fstream>
#include <tuple>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#endif

using namespace yuzu::server;
namespace pr = yuzu::server::pg_reachability;
using namespace std::chrono_literals;

namespace {

/// Host-list probes in these tests use a 3s pool connect_timeout default
/// (production: PgPool's 10s), so the probe waits 3s on each silent host —
/// exactly as a pool built with that default would — and the tests stay fast.
constexpr int kTestPoolConnectTimeoutS = 3;
constexpr std::chrono::seconds kTestHostWait{kTestPoolConnectTimeoutS};
/// Before libpq 17 its blocking connect — and so the probe, which reproduces it
/// — times connect_timeout in whole wall-clock seconds, so a host-list wait lands
/// anywhere in (timeout - 1s, timeout + 1s). Lower bounds allow for that.
constexpr std::chrono::seconds kWallJitter{1};

std::unique_ptr<PgReachabilityProbe> make_host_list_probe(const std::string& dsn) {
    return PgReachabilityProbe::make_libpq(dsn, {}, std::string(PgReachabilityProbe::kProbeSql),
                                           kTestPoolConnectTimeoutS);
}

constexpr std::int64_t ns(std::chrono::nanoseconds d) {
    return d.count();
}

using PingResult = PgReachabilityProbe::PingResult;
using Kind = PingResult::Kind;

/// A ping whose next outcome the test sets.
struct ScriptedPing {
    std::atomic<int> kind{static_cast<int>(Kind::Ok)};
    std::atomic<int> calls{0};
    PgReachabilityProbe::PingFn fn() {
        return [this](const std::atomic<bool>&) {
            ++calls;
            return PingResult{static_cast<Kind>(kind.load()), "scripted"};
        };
    }
    void set(Kind k) { kind.store(static_cast<int>(k)); }
};

/// Append `key=value` to a libpq DSN, keyword or URI form.
std::string dsn_with(const std::string& dsn, const std::string& key, const std::string& value) {
    const bool uri = dsn.rfind("postgres://", 0) == 0 || dsn.rfind("postgresql://", 0) == 0;
    if (uri)
        return dsn + (dsn.find('?') == std::string::npos ? "?" : "&") + key + "=" + value;
    return dsn + " " + key + "=" + value;
}

/// Run one parameterised statement on a fresh admin connection; RAII-owned
/// (pg::PgConn / pg::PgResult), so a throwing assertion cannot leak either.
/// Returns the first cell, or nullopt on any failure.
std::optional<std::string> admin_scalar(const std::string& admin_dsn, const char* sql,
                                        const std::string& param) {
    yuzu::server::pg::PgConn c{PQconnectdb(admin_dsn.c_str())};
    if (PQstatus(c.get()) != CONNECTION_OK)
        return std::nullopt;
    const char* params[] = {param.c_str()};
    yuzu::server::pg::PgResult r{
        PQexecParams(c.get(), sql, 1, nullptr, params, nullptr, nullptr, 0)};
    if (r.status() != PGRES_TUPLES_OK && r.status() != PGRES_COMMAND_OK)
        return std::nullopt;
    if (PQntuples(r.get()) < 1 || PQnfields(r.get()) < 1)
        return std::string{};
    return std::string(PQgetvalue(r.get(), 0, 0));
}

/// Backends connected to the test database under `app` (excluding the caller).
int count_backends(const std::string& admin_dsn, const std::string& app) {
    const auto v = admin_scalar(admin_dsn,
                                "SELECT count(*) FROM pg_stat_activity WHERE datname = "
                                "current_database() AND application_name = $1 AND pid <> "
                                "pg_backend_pid()",
                                app);
    return v && !v->empty() ? std::stoi(*v) : -1;
}

int wait_for_backends(const std::string& admin_dsn, const std::string& app, int want) {
    int n = -1;
    for (int i = 0; i < 50; ++i) { // ≤5s: backend exit after a client close is asynchronous
        n = count_backends(admin_dsn, app);
        if (n == want)
            break;
        std::this_thread::sleep_for(100ms);
    }
    return n;
}

} // namespace

// ---------------------------------------------------------------------------
// The pure rule
// ---------------------------------------------------------------------------

TEST_CASE("pg_reachability rule: verdict table", "[server][readyz][pg_reachability]") {
    const std::int64_t t0 = ns(1000s);
    pr::Snapshot s;

    SECTION("nothing probed yet is NotYetProbed (not ready)") {
        CHECK(pr::classify(s, t0) == pr::Verdict::NotYetProbed);
    }
    SECTION("a failure before any success is Unreachable") {
        s.consecutive_failures = 1;
        s.last_failure = pr::FailureKind::Unreachable;
        CHECK(pr::classify(s, t0) == pr::Verdict::Unreachable);
    }
    SECTION("a fresh success is Ready") {
        s.last_success_ns = t0;
        CHECK(pr::classify(s, t0 + ns(1s)) == pr::Verdict::Ready);
    }
    SECTION("ONE unreachable failure after a success stays Ready (a blip)") {
        s.last_success_ns = t0;
        s.consecutive_failures = 1;
        s.last_failure = pr::FailureKind::Unreachable;
        CHECK(pr::classify(s, t0 + ns(3s)) == pr::Verdict::Ready);
    }
    SECTION("kFailThreshold consecutive failures is Unreachable") {
        s.last_success_ns = t0;
        s.consecutive_failures = pr::kFailThreshold;
        s.last_failure = pr::FailureKind::Unreachable;
        CHECK(pr::classify(s, t0 + ns(5s)) == pr::Verdict::Unreachable);
    }
    SECTION("ReadOnly is immediate — one observation") {
        s.last_success_ns = t0;
        s.consecutive_failures = 1;
        s.last_failure = pr::FailureKind::ReadOnly;
        CHECK(pr::classify(s, t0 + ns(1s)) == pr::Verdict::ReadOnly);
    }
    SECTION("no success within kStaleAfter is Stale, even with no failure counted") {
        // A tick that never completes (wedged outside the probe's deadlines):
        // the counter never advances, so staleness is what turns /readyz red.
        s.last_success_ns = t0;
        CHECK(pr::classify(s, t0 + ns(pr::kStaleAfter)) == pr::Verdict::Ready);
        CHECK(pr::classify(s, t0 + ns(pr::kStaleAfter) + 1) == pr::Verdict::Stale);
    }
    SECTION("a clock reading before the last success does not overflow into Stale") {
        s.last_success_ns = t0;
        CHECK(pr::classify(s, t0 - ns(1s)) == pr::Verdict::Ready);
    }
}

TEST_CASE("pg_reachability rule: the timing budget never reds a healthy replica",
          "[server][readyz][pg_reachability]") {
    // The longest healthy gap between two successes is one full interval plus
    // a tick that uses its whole connect and query deadlines. It must sit
    // inside kStaleAfter, or a slow-but-healthy replica flaps.
    STATIC_REQUIRE(pr::kProbeInterval + pr::kConnectDeadline + pr::kQueryDeadline <
                   pr::kStaleAfter);
    STATIC_REQUIRE(pr::kFailThreshold >= 2);
}

TEST_CASE("pg_reachability rule: reason tokens are stable and carry no detail",
          "[server][readyz][pg_reachability]") {
    CHECK(std::string(pr::reason(pr::Verdict::Ready)) == "ok");
    CHECK(std::string(pr::reason(pr::Verdict::NotYetProbed)) == "not_yet_probed");
    CHECK(std::string(pr::reason(pr::Verdict::Unreachable)) == "unreachable");
    CHECK(std::string(pr::reason(pr::Verdict::ReadOnly)) == "read_only");
    CHECK(std::string(pr::reason(pr::Verdict::Stale)) == "stale");
}

// ---------------------------------------------------------------------------
// The drain rule
// ---------------------------------------------------------------------------

TEST_CASE("shutdown drain rule: minimum grace, then the execution cap",
          "[server][readyz][shutdown_drain]") {
    using shutdown_drain::keep_draining;
    using shutdown_drain::kExecutionDrainCap;

    SECTION("default grace 0 with nothing running stops immediately (unchanged behaviour)") {
        CHECK_FALSE(keep_draining(0s, 0s, false));
    }
    SECTION("a grace holds even with nothing running") {
        CHECK(keep_draining(0s, 10s, false));
        CHECK(keep_draining(9s, 10s, false));
        CHECK_FALSE(keep_draining(10s, 10s, false));
    }
    SECTION("running executions extend past the grace, up to the cap") {
        CHECK(keep_draining(12s, 10s, true));
        CHECK(keep_draining(kExecutionDrainCap - 1s, 0s, true));
        CHECK_FALSE(keep_draining(kExecutionDrainCap, 0s, true));
    }
    SECTION("a grace longer than the cap is honoured whether or not work is running") {
        CHECK(keep_draining(45s, 50s, true));
        CHECK(keep_draining(45s, 50s, false));
        CHECK_FALSE(keep_draining(50s, 50s, true));
    }
}

// ---------------------------------------------------------------------------
// The probe with an injected ping
// ---------------------------------------------------------------------------

TEST_CASE("PgReachabilityProbe: publication follows the ping outcomes",
          "[server][readyz][pg_reachability]") {
    ScriptedPing ping;
    int failures_seen = 0;
    PgReachabilityProbe probe(ping.fn(), {.on_failure = [&] { ++failures_seen; }});

    CHECK(probe.verdict() == pr::Verdict::NotYetProbed);

    probe.probe_once();
    CHECK(probe.verdict() == pr::Verdict::Ready);

    ping.set(Kind::Failed);
    probe.probe_once();
    CHECK(probe.verdict() == pr::Verdict::Ready); // one blip
    probe.probe_once();
    CHECK(probe.verdict() == pr::Verdict::Unreachable);
    CHECK(failures_seen == 2);

    ping.set(Kind::Ok);
    probe.probe_once();
    CHECK(probe.verdict() == pr::Verdict::Ready); // one success recovers

    ping.set(Kind::ReadOnly);
    probe.probe_once();
    CHECK(probe.verdict() == pr::Verdict::ReadOnly); // immediate
    CHECK(failures_seen == 3);

    ping.set(Kind::Ok);
    probe.probe_once();
    CHECK(probe.verdict() == pr::Verdict::Ready);
    CHECK(probe.snapshot().consecutive_failures == 0);
    CHECK(probe.snapshot().last_failure == pr::FailureKind::None);
}

TEST_CASE("PgReachabilityProbe: a success older than kStaleAfter reads Stale",
          "[server][readyz][pg_reachability]") {
    ScriptedPing ping;
    PgReachabilityProbe probe(ping.fn());
    probe.probe_once();
    const auto now = PgReachabilityProbe::now_ns();
    CHECK(probe.verdict_at(now) == pr::Verdict::Ready);
    CHECK(probe.verdict_at(now + ns(pr::kStaleAfter) + ns(1s)) == pr::Verdict::Stale);
}

TEST_CASE("PgReachabilityProbe: a throwing ping counts as a failure, never escapes",
          "[server][readyz][pg_reachability]") {
    PgReachabilityProbe probe(
        [](const std::atomic<bool>&) -> PingResult { throw std::runtime_error("boom"); });
    probe.probe_once();
    probe.probe_once();
    CHECK(probe.verdict() == pr::Verdict::Unreachable);
}

TEST_CASE("PgReachabilityProbe: the loop probes on its interval and stop() is prompt and sticky",
          "[server][readyz][pg_reachability]") {
    ScriptedPing ping;
    PgReachabilityProbe probe(ping.fn(), {}, 20ms);
    probe.start();
    for (int i = 0; i < 200 && ping.calls.load() < 3; ++i)
        std::this_thread::sleep_for(10ms);
    CHECK(ping.calls.load() >= 3);
    CHECK(probe.verdict() == pr::Verdict::Ready);

    const auto t = std::chrono::steady_clock::now();
    probe.stop();
    CHECK(std::chrono::steady_clock::now() - t < 1s);

    const int after = ping.calls.load();
    probe.start(); // sticky: no restart after stop
    std::this_thread::sleep_for(100ms);
    CHECK(ping.calls.load() == after);
    probe.stop(); // idempotent
}

TEST_CASE("PgReachabilityProbe: stop() interrupts a ping blocked past its deadline",
          "[server][readyz][pg_reachability]") {
    // A ping that honours the stop flag but would otherwise block for 30s — the
    // shape of the real probe against a frozen backend.
    std::atomic<bool> entered{false};
    PgReachabilityProbe probe(
        [&](const std::atomic<bool>& stop) {
            entered = true;
            for (int i = 0; i < 3000 && !stop.load(); ++i)
                std::this_thread::sleep_for(10ms);
            return PingResult{Kind::Failed, "stopped"};
        },
        {}, 10ms);
    probe.start();
    for (int i = 0; i < 200 && !entered.load(); ++i)
        std::this_thread::sleep_for(10ms);
    REQUIRE(entered.load());

    const auto t = std::chrono::steady_clock::now();
    probe.stop();
    CHECK(std::chrono::steady_clock::now() - t < 1s);
    // A probe cut short by stop() publishes nothing.
    CHECK(probe.verdict() == pr::Verdict::NotYetProbed);
}

// ---------------------------------------------------------------------------
// The real libpq probe — no Postgres needed
// ---------------------------------------------------------------------------

TEST_CASE("PgReachabilityProbe (libpq): a refused port is Unreachable after the threshold",
          "[server][readyz][pg_reachability]") {
    // Port 1 on loopback: nothing listens, so connect is refused at once.
    auto probe = PgReachabilityProbe::make_libpq(
        "host=127.0.0.1 port=1 dbname=yuzu user=yuzu connect_timeout=2");
    const auto t = std::chrono::steady_clock::now();
    probe->probe_once();
    CHECK(probe->verdict() == pr::Verdict::Unreachable); // never succeeded
    probe->probe_once();
    CHECK(probe->snapshot().consecutive_failures == 2);
    // Refused, not timed out: well inside two deadlines even where the OS retries
    // a refused loopback SYN (Windows, ~2s per attempt).
    CHECK(std::chrono::steady_clock::now() - t < 2 * pr::kConnectDeadline);
}

#ifndef _WIN32
namespace {
/// A TCP listener that completes the handshake (kernel backlog) and then never
/// reads or writes — a peer that ACKs but never answers, like a paused primary.
/// Owns one POSIX fd: closed exactly once, on every path (incl. a throwing ctor).
struct UniqueFd {
    int v{-1};
    UniqueFd() = default;
    explicit UniqueFd(int f) : v(f) {}
    ~UniqueFd() {
        if (v >= 0)
            ::close(v);
    }
    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
};

/// A loopback listener on an ephemeral port — salted per process, safe on shared
/// CI runners. The port is 0 on any failure; callers REQUIRE port > 0.
std::pair<std::unique_ptr<UniqueFd>, int> loopback_listener() {
    auto fd = std::make_unique<UniqueFd>(::socket(AF_INET, SOCK_STREAM, 0));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    socklen_t len = sizeof(a);
    if (fd->v < 0 || ::bind(fd->v, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 ||
        ::listen(fd->v, 8) != 0 ||
        ::getsockname(fd->v, reinterpret_cast<sockaddr*>(&a), &len) != 0)
        return {std::move(fd), 0};
    return {std::move(fd), ntohs(a.sin_port)};
}

/// A TCP listener that completes the handshake (kernel backlog) and then never
/// reads or writes — a peer that ACKs but never answers, like a paused primary.
struct SilentListener {
    std::unique_ptr<UniqueFd> fd;
    int port{0};
    SilentListener() { std::tie(fd, port) = loopback_listener(); }
    std::string dsn() const {
        return "host=127.0.0.1 port=" + std::to_string(port) + " dbname=yuzu user=yuzu";
    }
};
} // namespace

TEST_CASE("PgReachabilityProbe (libpq): a peer that never answers fails at the connect "
          "deadline, not the OS timeout",
          "[server][readyz][pg_reachability]") {
    SilentListener peer;
    REQUIRE(peer.port > 0);
    auto probe = PgReachabilityProbe::make_libpq(peer.dsn());
    const auto t = std::chrono::steady_clock::now();
    probe->probe_once();
    const auto took = std::chrono::steady_clock::now() - t;
    CHECK(took >= pr::kConnectDeadline - 100ms);
    CHECK(took < pr::kConnectDeadline + 5s); // slack for sanitizer / contended CI legs
    CHECK(probe->snapshot().consecutive_failures == 1);
}

TEST_CASE("PgReachabilityProbe (libpq): stop() returns promptly while a connect is stuck",
          "[server][readyz][pg_reachability]") {
    SilentListener peer;
    REQUIRE(peer.port > 0);
    auto probe = PgReachabilityProbe::make_libpq(peer.dsn());
    probe->start(); // the loop's first tick blocks in the connect wait
    std::this_thread::sleep_for(300ms);
    const auto t = std::chrono::steady_clock::now();
    probe->stop();
    CHECK(std::chrono::steady_clock::now() - t < 1s);
}
#endif

// ---------------------------------------------------------------------------
// The real libpq probe against Postgres
// ---------------------------------------------------------------------------

TEST_CASE("PgReachabilityProbe (libpq, pg): a reachable primary is Ready and keeps one connection",
          "[server][readyz][pg_reachability][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    const std::string app = "yuzu_ws8_probe_ok";
    auto probe = PgReachabilityProbe::make_libpq(dsn_with(db.dsn(), "application_name", app));
    probe->probe_once();
    CHECK(probe->verdict() == pr::Verdict::Ready);
    probe->probe_once();
    CHECK(probe->verdict() == pr::Verdict::Ready);
    // One dedicated connection, reused across ticks.
    CHECK(wait_for_backends(db.dsn(), app, 1) == 1);
}

TEST_CASE("PgReachabilityProbe (libpq, pg): a terminated backend is one blip, then a reconnect",
          "[server][readyz][pg_reachability][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    const std::string app = "yuzu_ws8_probe_blip";
    auto probe = PgReachabilityProbe::make_libpq(dsn_with(db.dsn(), "application_name", app));
    probe->probe_once();
    REQUIRE(probe->verdict() == pr::Verdict::Ready);

    REQUIRE(admin_scalar(db.dsn(),
                         "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity "
                         "WHERE application_name = $1 AND datname = current_database()",
                         app)
                .has_value());
    REQUIRE(wait_for_backends(db.dsn(), app, 0) == 0);

    probe->probe_once(); // the dead session fails ...
    CHECK(probe->snapshot().consecutive_failures == 1);
    CHECK(probe->verdict() == pr::Verdict::Ready); // ... below the threshold
    probe->probe_once();                           // ... and the next tick reconnects
    CHECK(probe->verdict() == pr::Verdict::Ready);
    CHECK(probe->snapshot().consecutive_failures == 0);
}

TEST_CASE("PgReachabilityProbe (libpq, pg): reaching a standby is ReadOnly AND drops the "
          "connection so the next tick re-resolves",
          "[server][readyz][pg_reachability][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    const std::string app = "yuzu_ws8_probe_standby";
    // `SELECT true` stands in for pg_is_in_recovery() on a standby.
    auto probe = PgReachabilityProbe::make_libpq(dsn_with(db.dsn(), "application_name", app), {},
                                                 "SELECT true");
    probe->probe_once();
    CHECK(probe->verdict() == pr::Verdict::ReadOnly);
    // Not pinned to a standby: no connection is held between ticks.
    CHECK(wait_for_backends(db.dsn(), app, 0) == 0);
    probe->probe_once(); // reconnects, still a "standby"
    CHECK(probe->verdict() == pr::Verdict::ReadOnly);
    CHECK(wait_for_backends(db.dsn(), app, 0) == 0);
}

TEST_CASE("PgReachabilityProbe (libpq, pg): a primary with default_transaction_read_only is "
          "ReadOnly",
          "[server][readyz][pg_reachability][pg]") {
    // Managed Postgres flips this on a full disk: not in recovery, yet refuses
    // writes — the probe must not call it writable (Gate 4 UP-4).
    YUZU_REQUIRE_PG_DB(db);
    const std::string app = "yuzu_ws8_probe_ro_primary";
    {
        yuzu::server::pg::PgConn c{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        const std::string dbname = PQdb(c.get());
        yuzu::server::pg::PgResult r{PQexec(
            c.get(),
            ("ALTER DATABASE \"" + dbname + "\" SET default_transaction_read_only = on").c_str())};
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    auto probe = PgReachabilityProbe::make_libpq(dsn_with(db.dsn(), "application_name", app));
    probe->probe_once();
    CHECK(probe->verdict() == pr::Verdict::ReadOnly);
    CHECK(wait_for_backends(db.dsn(), app, 0) == 0); // dropped, re-resolves next tick
}

TEST_CASE("PgReachabilityProbe (libpq, pg): a query that outlives kQueryDeadline fails at the "
          "deadline on the real query path",
          "[server][readyz][pg_reachability][pg]") {
    // The frozen-after-connect shape the probe exists for: the connection is up,
    // the reply never comes in time. pg_sleep stands in for a frozen backend.
    YUZU_REQUIRE_PG_DB(db);
    const std::string app = "yuzu_ws8_probe_slow";
    auto probe = PgReachabilityProbe::make_libpq(dsn_with(db.dsn(), "application_name", app), {},
                                                 "SELECT pg_sleep(30)");
    const auto t = std::chrono::steady_clock::now();
    probe->probe_once();
    const auto took = std::chrono::steady_clock::now() - t;
    CHECK(took >= pr::kQueryDeadline - 100ms);
    CHECK(took < pr::kQueryDeadline + 5s);
    CHECK(probe->snapshot().consecutive_failures == 1);
    // The busy connection is dropped, never reused: the next tick opens a FRESH
    // backend. (The first backend lingers server-side, still sleeping, until it
    // next writes to its closed socket — so the proof is a second backend, not zero.)
    probe->probe_once();
    CHECK(probe->snapshot().consecutive_failures == 2);
    CHECK(wait_for_backends(db.dsn(), app, 2) == 2);
}

TEST_CASE("PgReachabilityProbe (libpq, pg): stop() interrupts a real in-flight query promptly",
          "[server][readyz][pg_reachability][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    auto probe = PgReachabilityProbe::make_libpq(
        dsn_with(db.dsn(), "application_name", "yuzu_ws8_probe_stopq"), {}, "SELECT pg_sleep(30)");
    probe->start();
    // Wait until the probe's query is actually running server-side, so stop()
    // lands in the QUERY wait, not the connect wait.
    bool active = false;
    for (int i = 0; i < 100 && !active; ++i) {
        const auto n = admin_scalar(db.dsn(),
                                    "SELECT count(*) FROM pg_stat_activity WHERE "
                                    "application_name = $1 AND state = 'active' AND "
                                    "datname = current_database()",
                                    "yuzu_ws8_probe_stopq");
        active = n && !n->empty() && *n != "0";
        if (!active)
            std::this_thread::sleep_for(100ms);
    }
    REQUIRE(active);
    const auto t = std::chrono::steady_clock::now();
    probe->stop();
    CHECK(std::chrono::steady_clock::now() - t < 1s);
}

TEST_CASE("PgReachabilityProbe (libpq, pg): the probe tags its connection unless the DSN names one",
          "[server][readyz][pg_reachability][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    auto probe = PgReachabilityProbe::make_libpq(db.dsn());
    probe->probe_once();
    REQUIRE(probe->verdict() == pr::Verdict::Ready);
    CHECK(wait_for_backends(db.dsn(), "yuzu-readyz-probe", 1) == 1);
}

#ifndef _WIN32
namespace {
/// The test database's own keyword DSN with `host`/`port` replaced by lists.
std::string multi_host_dsn(const std::string& dsn, const std::string& hosts,
                           const std::string& ports) {
    char* err = nullptr;
    std::unique_ptr<PQconninfoOption, decltype(&PQconninfoFree)> opts(
        PQconninfoParse(dsn.c_str(), &err), &PQconninfoFree);
    const std::unique_ptr<char, decltype(&PQfreemem)> err_owner(err, &PQfreemem);
    // Keyword-DSN quoting: a value is single-quoted, and ' and \ inside it are
    // backslash-escaped (libpq conninfo syntax).
    auto quote = [](const char* v) {
        std::string q = "'";
        for (const char* c = v; *c; ++c) {
            if (*c == '\'' || *c == '\\')
                q += '\\';
            q += *c;
        }
        return q + "'";
    };
    std::string out = "host=" + hosts + " port=" + ports;
    for (const PQconninfoOption* o = opts.get(); o && o->keyword; ++o) {
        const std::string k = o->keyword;
        if (!o->val || k == "host" || k == "hostaddr" || k == "port")
            continue;
        out += " " + k + "=" + quote(o->val);
    }
    // What production's multi-host guard adds to every DSN host list (the
    // probe's own per-connection settings check refuses a list without it).
    return out + " target_session_attrs=read-write";
}
} // namespace

TEST_CASE("PgReachabilityProbe (libpq, pg): a frozen FIRST host of a multi-host DSN costs one "
          "deadline, then the next host serves",
          "[server][readyz][pg_reachability][pg]") {
    // Gate 4 UP-1: libpq's non-blocking connect never advances past a host that
    // accepts TCP and goes silent; the probe gives each host its own deadline and
    // restarts libpq's walk over the hosts not yet tried.
    YUZU_REQUIRE_PG_DB(db);
    SilentListener frozen;
    REQUIRE(frozen.port > 0);
    char* err = nullptr;
    std::unique_ptr<PQconninfoOption, decltype(&PQconninfoFree)> opts(
        PQconninfoParse(db.dsn().c_str(), &err), &PQconninfoFree);
    const std::unique_ptr<char, decltype(&PQfreemem)> err_owner(err, &PQfreemem);
    REQUIRE(opts);
    std::string pg_host = "localhost", pg_port = "5432";
    for (const PQconninfoOption* o = opts.get(); o->keyword; ++o) {
        if (o->val && std::string(o->keyword) == "host")
            pg_host = o->val;
        if (o->val && std::string(o->keyword) == "port")
            pg_port = o->val;
    }
    const std::string dsn = multi_host_dsn(db.dsn(), "127.0.0.1," + pg_host,
                                           std::to_string(frozen.port) + "," + pg_port);
    auto probe = make_host_list_probe(dsn);
    const auto t = std::chrono::steady_clock::now();
    probe->probe_once();
    const auto took = std::chrono::steady_clock::now() - t;
    CHECK(probe->verdict() == pr::Verdict::Ready);
    CHECK(took >= kTestHostWait - kWallJitter - 100ms); // paid the frozen host's timeout once
    CHECK(took < kTestHostWait + 5s);
    // The connection is now held on the second host: the next tick is fast.
    const auto t2 = std::chrono::steady_clock::now();
    probe->probe_once();
    CHECK(probe->verdict() == pr::Verdict::Ready);
    CHECK(std::chrono::steady_clock::now() - t2 < 1s);

    // A RECONNECT walks the hosts as libpq does for a fresh pool connection:
    // kill the probe's backend; the next tick fails on the dead session, the
    // one after pays the frozen host's deadline again, then reaches the second
    // host (Gate 8 round 4: the probe mirrors the pool's host choice).
    REQUIRE(admin_scalar(db.dsn(),
                         "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity "
                         "WHERE application_name = $1 AND datname = current_database()",
                         "yuzu-readyz-probe")
                .has_value());
    REQUIRE(wait_for_backends(db.dsn(), "yuzu-readyz-probe", 0) == 0);
    probe->probe_once(); // dead session → one failure
    const auto t3 = std::chrono::steady_clock::now();
    probe->probe_once(); // reconnect: frozen host first, then the second host
    CHECK(probe->verdict() == pr::Verdict::Ready);
    CHECK(std::chrono::steady_clock::now() - t3 >= kTestHostWait - kWallJitter - 100ms);
}
#endif

#ifndef _WIN32
namespace {
/// A minimal fake Postgres: answers SSL/GSS negotiation with 'N', then sends one
/// FATAL ErrorResponse with the given SQLSTATE to the startup packet — what a
/// real server sends for a failed login (28P01) or "cannot connect now" (57P03).
struct FakePostgres {
    std::unique_ptr<UniqueFd> fd;
    int port{0};
    std::string sqlstate;
    /// Delay before answering the FIRST SSL/GSSENC request (a slow handshake).
    std::chrono::milliseconds negotiate_delay{0};
    std::atomic<bool> stop{false};
    std::thread thread; // declared last: started only once everything above exists

    /// `code`: the SQLSTATE of the FATAL reply to the startup packet; "close" =
    /// hang up without a reply; "silent" = keep the connection open, say nothing.
    explicit FakePostgres(std::string code, std::chrono::milliseconds delay = {})
        : sqlstate(std::move(code)), negotiate_delay(delay) {
        std::tie(fd, port) = loopback_listener();
        if (port > 0)
            thread = std::thread([this] { serve(); });
    }
    ~FakePostgres() {
        stop = true;
        if (thread.joinable())
            thread.join();
    }
    FakePostgres(const FakePostgres&) = delete;
    FakePostgres& operator=(const FakePostgres&) = delete;

    /// Never raises SIGPIPE (a probe that drops the connection first must not
    /// kill the test binary): MSG_NOSIGNAL where it exists, SO_NOSIGPIPE on Darwin.
    static void send_all(int c, const void* p, std::size_t n) {
#ifdef MSG_NOSIGNAL
        (void)::send(c, p, n, MSG_NOSIGNAL);
#else
        (void)::send(c, p, n, 0);
#endif
    }
    static bool read_all(int c, unsigned char* p, std::size_t n) {
        while (n > 0) {
            const ssize_t r = ::read(c, p, n);
            if (r <= 0)
                return false;
            p += r;
            n -= static_cast<std::size_t>(r);
        }
        return true;
    }
    static std::uint32_t be32(const unsigned char* p) {
        return (std::uint32_t{p[0]} << 24) | (std::uint32_t{p[1]} << 16) |
               (std::uint32_t{p[2]} << 8) | std::uint32_t{p[3]};
    }
    void handle(int c) {
        bool delayed = false;
        for (;;) {
            unsigned char hdr[8];
            if (!read_all(c, hdr, sizeof(hdr)))
                return;
            const std::uint32_t len = be32(hdr), code = be32(hdr + 4);
            if (code == 80877103 || code == 80877104) { // SSLRequest / GSSENCRequest
                if (negotiate_delay.count() > 0 && !delayed) {
                    delayed = true;
                    std::this_thread::sleep_for(negotiate_delay);
                }
                const char n = 'N';
                send_all(c, &n, 1);
                continue;
            }
            std::vector<unsigned char> rest(len > 8 ? len - 8 : 0);
            if (!rest.empty() && !read_all(c, rest.data(), rest.size()))
                return;
            if (sqlstate == "close")
                return; // accept, read the startup packet, hang up without a word
            if (sqlstate == "silent") { // hold the connection open, say nothing
                // Until the peer closes: incoming bytes are ignored, a read timeout
                // (SO_RCVTIMEO) or EINTR keeps it open; EOF or a real error ends it.
                unsigned char b;
                for (;;) {
                    if (stop.load())
                        break;
                    const ssize_t r = ::read(c, &b, 1);
                    if (r > 0)
                        continue;
                    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
                        continue;
                    break;
                }
                return;
            }
            std::string body;
            for (const auto& [f, v] : {std::pair<char, std::string>{'S', "FATAL"},
                                       {'V', "FATAL"},
                                       {'C', sqlstate},
                                       {'M', "fake server refusal"}}) {
                if (f == 'C' && v.empty())
                    continue; // an ErrorResponse with no SQLSTATE at all
                body += f;
                body += v;
                body += '\0';
            }
            body += '\0';
            const std::uint32_t n = htonl(static_cast<std::uint32_t>(body.size() + 4));
            std::string msg = "E";
            msg.append(reinterpret_cast<const char*>(&n), 4);
            msg += body;
            send_all(c, msg.data(), msg.size());
            return;
        }
    }
    void serve() {
        while (!stop.load()) {
            pollfd p{fd->v, POLLIN, 0};
            if (::poll(&p, 1, 100) <= 0)
                continue;
            const UniqueFd c{::accept(fd->v, nullptr, nullptr)};
            if (c.v < 0)
                continue;
            // A peer that sends half a packet and stays open must not wedge join().
            timeval tv{};
            tv.tv_sec = 5;
            (void)::setsockopt(c.v, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#ifdef SO_NOSIGPIPE
            const int one = 1;
            (void)::setsockopt(c.v, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
            handle(c.v);
        }
    }
};

std::pair<std::string, std::string> pg_host_port(const std::string& dsn) {
    char* err = nullptr;
    std::unique_ptr<PQconninfoOption, decltype(&PQconninfoFree)> opts(
        PQconninfoParse(dsn.c_str(), &err), &PQconninfoFree);
    const std::unique_ptr<char, decltype(&PQfreemem)> err_owner(err, &PQfreemem);
    std::string host = "localhost", port = "5432";
    for (const PQconninfoOption* o = opts.get(); o && o->keyword; ++o) {
        if (o->val && std::string(o->keyword) == "host")
            host = o->val;
        if (o->val && std::string(o->keyword) == "port")
            port = o->val;
    }
    return {host, port};
}
} // namespace

TEST_CASE("PgReachabilityProbe (libpq, pg): a silent first host from a PGHOST list costs one "
          "deadline, then the next host is tried",
          "[server][readyz][pg_reachability][pg]") {
    // The host list libpq walks can come from the environment; the probe reads
    // it back from libpq (PQconninfo), so it moves past a silent host there too.
    YUZU_REQUIRE_PG_DB(db);
    SilentListener frozen;
    REQUIRE(frozen.port > 0);
    const auto [pg_host, pg_port] = pg_host_port(db.dsn());
    std::string no_hosts; // the test DSN without host/hostaddr/port
    {
        char* err = nullptr;
        std::unique_ptr<PQconninfoOption, decltype(&PQconninfoFree)> opts(
            PQconninfoParse(db.dsn().c_str(), &err), &PQconninfoFree);
        const std::unique_ptr<char, decltype(&PQfreemem)> err_owner(err, &PQfreemem);
        REQUIRE(opts);
        for (const PQconninfoOption* o = opts.get(); o->keyword; ++o) {
            const std::string k = o->keyword;
            if (!o->val || k == "host" || k == "hostaddr" || k == "port")
                continue;
            std::string q = "'";
            for (const char* c = o->val; *c; ++c) {
                if (*c == '\'' || *c == '\\')
                    q += '\\';
                q += *c;
            }
            no_hosts += k + "=" + q + "' ";
        }
    }
    struct EnvRestore {
        const char* name;
        std::optional<std::string> saved;
        explicit EnvRestore(const char* n) : name(n) {
            if (const char* v = std::getenv(n))
                saved = v;
        }
        ~EnvRestore() {
            if (saved)
                ::setenv(name, saved->c_str(), 1);
            else
                ::unsetenv(name);
        }
    } restore_host{"PGHOST"}, restore_port{"PGPORT"};
    ::setenv("PGHOST", ("127.0.0.1," + pg_host).c_str(), 1);
    ::setenv("PGPORT", (std::to_string(frozen.port) + "," + pg_port).c_str(), 1);
    // The multi-host guard adds read-write for a PGHOST list; so must this test.
    auto probe = make_host_list_probe(no_hosts + " target_session_attrs=read-write");
    const auto t = std::chrono::steady_clock::now();
    probe->probe_once();
    const auto took = std::chrono::steady_clock::now() - t;
    CHECK(probe->verdict() == pr::Verdict::Ready);
    CHECK(took >= kTestHostWait - kWallJitter - 100ms);
    CHECK(took < kTestHostWait + 5s);
}

TEST_CASE("PgReachabilityProbe (libpq, pg): an empty host entry whose default socket is silent "
          "still costs one deadline, not an endless restart",
          "[server][readyz][pg_reachability][pg]") {
    // Gate 8 round 6 (cross-platform): libpq shows an EMPTY host entry as its
    // built-in default (a Unix socket directory, /tmp for this libpq), so a
    // name-based "already tried" check never matched it and a silent default
    // socket restarted forever. A silent Unix listener at that default path
    // (salted by an ephemeral TCP port number) reproduces it.
    YUZU_REQUIRE_PG_DB(db);
    SilentListener port_salt; // only its unique port number is used
    REQUIRE(port_salt.port > 0);
    const std::string sock_path = "/tmp/.s.PGSQL." + std::to_string(port_salt.port);
    UniqueFd unix_fd{::socket(AF_UNIX, SOCK_STREAM, 0)};
    REQUIRE(unix_fd.v >= 0);
    sockaddr_un ua{};
    ua.sun_family = AF_UNIX;
    REQUIRE(sock_path.size() < sizeof(ua.sun_path));
    std::memcpy(ua.sun_path, sock_path.c_str(), sock_path.size() + 1);
    ::unlink(sock_path.c_str());
    REQUIRE(::bind(unix_fd.v, reinterpret_cast<sockaddr*>(&ua), sizeof(ua)) == 0);
    struct Unlink {
        std::string path;
        ~Unlink() { ::unlink(path.c_str()); }
    } unlink_after{sock_path};
    REQUIRE(::listen(unix_fd.v, 8) == 0);

    const auto [pg_host, pg_port] = pg_host_port(db.dsn());
    auto probe = make_host_list_probe(
        multi_host_dsn(db.dsn(), "," + pg_host, std::to_string(port_salt.port) + "," + pg_port));
    const auto t = std::chrono::steady_clock::now();
    probe->probe_once();
    const auto took = std::chrono::steady_clock::now() - t;
    CHECK(probe->verdict() == pr::Verdict::Ready);
    CHECK(took >= kTestHostWait - kWallJitter - 100ms); // really reached the silent socket
    CHECK(took < 2 * kTestHostWait + 5s);
}

TEST_CASE("PgReachabilityProbe (libpq, pg): the per-host deadline follows the DSN's "
          "connect_timeout, as the pool's connect does",
          "[server][readyz][pg_reachability][pg]") {
    // Gate 8 round 6 (security-guardian + architect): the pool gives up on a
    // host after connect_timeout — never at all when it is 0. A probe that
    // waited longer, or moved on where the pool waits for ever, reported ready
    // while the pool could not connect.
    YUZU_REQUIRE_PG_DB(db);
    SilentListener frozen;
    REQUIRE(frozen.port > 0);
    const auto [pg_host, pg_port] = pg_host_port(db.dsn());
    const std::string dsn = multi_host_dsn(db.dsn(), "127.0.0.1," + pg_host,
                                           std::to_string(frozen.port) + "," + pg_port);
    SECTION("connect_timeout=2: the silent host is abandoned after ~2s, as the pool does") {
        auto probe = PgReachabilityProbe::make_libpq(dsn + " connect_timeout=2");
        const auto t = std::chrono::steady_clock::now();
        probe->probe_once();
        const auto took = std::chrono::steady_clock::now() - t;
        CHECK(probe->verdict() == pr::Verdict::Ready);
        CHECK(took >= 2s - kWallJitter - 100ms);
        CHECK(took < pr::kConnectDeadline - 1s);
    }
    SECTION("connect_timeout=8: the probe waits the full 8s on the silent host, as the pool does") {
        // Round 6 (unhappy-path UP6-1): moving on sooner than the pool passes a
        // host that fails the pool's connects a little later, and reports ready.
        auto probe = PgReachabilityProbe::make_libpq(dsn + " connect_timeout=8");
        const auto t = std::chrono::steady_clock::now();
        probe->probe_once();
        const auto took = std::chrono::steady_clock::now() - t;
        CHECK(probe->verdict() == pr::Verdict::Ready);
        CHECK(took >= 8s - kWallJitter - 100ms);
        CHECK(took < 8s + 5s);
    }
    SECTION("PGCONNECT_TIMEOUT applies when the DSN sets none, as it does for the pool") {
        struct EnvRestore {
            std::optional<std::string> saved;
            EnvRestore() {
                if (const char* v = std::getenv("PGCONNECT_TIMEOUT"))
                    saved = v;
            }
            ~EnvRestore() {
                if (saved)
                    ::setenv("PGCONNECT_TIMEOUT", saved->c_str(), 1);
                else
                    ::unsetenv("PGCONNECT_TIMEOUT");
            }
        } restore;
        ::setenv("PGCONNECT_TIMEOUT", "2", 1);
        auto probe = make_host_list_probe(dsn); // pool default 3s, overridden by the env
        const auto t = std::chrono::steady_clock::now();
        probe->probe_once();
        const auto took = std::chrono::steady_clock::now() - t;
        CHECK(probe->verdict() == pr::Verdict::Ready);
        CHECK(took >= 2s - kWallJitter - 100ms);
        CHECK(took < 3s + kWallJitter);
    }
    SECTION("a SINGLE host is capped at kConnectDeadline even with a longer connect_timeout") {
        auto probe = PgReachabilityProbe::make_libpq(
            "host=127.0.0.1 port=" + std::to_string(frozen.port) +
            " dbname=yuzu user=yuzu connect_timeout=30");
        const auto t = std::chrono::steady_clock::now();
        probe->probe_once();
        const auto took = std::chrono::steady_clock::now() - t;
        CHECK(probe->verdict() == pr::Verdict::Unreachable);
        CHECK(took >= pr::kConnectDeadline - 100ms);
        CHECK(took < pr::kConnectDeadline + 3s);
    }
    SECTION("connect_timeout=0: the pool would wait for ever, so the probe does not move on") {
        auto probe = PgReachabilityProbe::make_libpq(dsn + " connect_timeout=0");
        probe->probe_once();
        probe->probe_once();
        CHECK(probe->verdict() == pr::Verdict::Unreachable);
    }
    SECTION("no connect_timeout: the pool's default applies (3s here, 10s in production)") {
        auto probe = make_host_list_probe(dsn);
        const auto t = std::chrono::steady_clock::now();
        probe->probe_once();
        const auto took = std::chrono::steady_clock::now() - t;
        CHECK(probe->verdict() == pr::Verdict::Ready);
        CHECK(took >= 3s - kWallJitter - 100ms);
        CHECK(took < pr::kConnectDeadline - 1s);
    }
}

TEST_CASE("PgReachabilityProbe (libpq, pg): the restart over untried hosts — all silent, "
          "duplicates, a hostaddr-only list",
          "[server][readyz][pg_reachability][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    SilentListener a, b;
    REQUIRE(a.port > 0);
    REQUIRE(b.port > 0);
    const auto [pg_host, pg_port] = pg_host_port(db.dsn());
    const std::string pa = std::to_string(a.port), pb = std::to_string(b.port);
    SECTION("every host silent: one deadline each, then the probe fails") {
        auto probe = make_host_list_probe(
            multi_host_dsn(db.dsn(), "127.0.0.1,127.0.0.1", pa + "," + pb));
        const auto t = std::chrono::steady_clock::now();
        probe->probe_once();
        const auto took = std::chrono::steady_clock::now() - t;
        CHECK(probe->verdict() == pr::Verdict::Unreachable);
        CHECK(took >= 2 * (kTestHostWait - kWallJitter) - 200ms);
        CHECK(took < 3 * kTestHostWait + 2s);
    }
    SECTION("a silent host listed twice costs one deadline, not two") {
        auto probe = make_host_list_probe(multi_host_dsn(
            db.dsn(), "127.0.0.1,127.0.0.1," + pg_host, pa + "," + pa + "," + pg_port));
        const auto t = std::chrono::steady_clock::now();
        probe->probe_once();
        const auto took = std::chrono::steady_clock::now() - t;
        CHECK(probe->verdict() == pr::Verdict::Ready);
        CHECK(took < 2 * kTestHostWait - 1s);
    }
    SECTION("a hostaddr-only list is walked the same way") {
        if (pg_host != "localhost" && pg_host != "127.0.0.1")
            SKIP("test Postgres is not on loopback; hostaddr needs a numeric address");
        // multi_host_dsn() sets host=; replace it with a hostaddr list.
        std::string dsn = multi_host_dsn(db.dsn(), "x,y", pa + "," + pg_port);
        dsn.replace(dsn.find("host=x,y"), 8, "hostaddr=127.0.0.1,127.0.0.1");
        auto probe = make_host_list_probe(dsn);
        probe->probe_once();
        CHECK(probe->verdict() == pr::Verdict::Ready);
    }
}

TEST_CASE("PgReachabilityProbe (libpq, pg): a restart keeps an EMPTY list entry (the default) "
          "instead of dropping it",
          "[server][readyz][pg_reachability][pg]") {
    // Gate 8 round 7 (cross-platform, cpp-safety, unhappy-path): the restart
    // passed host/hostaddr/port as separate array entries, and libpq drops an
    // empty one — so an untried entry whose value is EMPTY (the default) lost it
    // and the DSN's original list came back. Here the second entry's hostaddr is
    // empty (resolve the host name); the old restart re-sent hostaddr=127.0.0.1,
    // for one host and libpq refused the mismatched lists.
    YUZU_REQUIRE_PG_DB(db);
    SilentListener frozen;
    REQUIRE(frozen.port > 0);
    const auto [pg_host, pg_port] = pg_host_port(db.dsn());
    std::string dsn = multi_host_dsn(db.dsn(), "127.0.0.1," + pg_host,
                                     std::to_string(frozen.port) + "," + pg_port);
    dsn += " hostaddr='127.0.0.1,'";
    auto probe = make_host_list_probe(dsn);
    probe->probe_once();
    CHECK(probe->verdict() == pr::Verdict::Ready);
}

TEST_CASE("check_effective_connection: a service file's load_balance_hosts or read-write-less "
          "host list refuses the connection settings",
          "[server][readyz][multi_host_dsn][pg]") {
    // Gate 8 round 7 (architect, consistency-auditor, cpp-expert,
    // security-guardian, unhappy-path): the DSN-only guard cannot see a
    // service file, which libpq applies at connect time. main.cpp checks what
    // libpq resolved on the first pooled connection.
    YUZU_REQUIRE_PG_DB(db);
    const auto [pg_host, pg_port] = pg_host_port(db.dsn());
    yuzu::test::TempDir dir("yuzu_test_readyz_svc_");
    std::filesystem::create_directories(dir.path);
    const auto svc_file = dir.path / "pg_service.conf";
    std::string no_hosts; // the test DSN without host/hostaddr/port
    {
        char* err = nullptr;
        std::unique_ptr<PQconninfoOption, decltype(&PQconninfoFree)> opts(
            PQconninfoParse(db.dsn().c_str(), &err), &PQconninfoFree);
        const std::unique_ptr<char, decltype(&PQfreemem)> err_owner(err, &PQfreemem);
        REQUIRE(opts);
        for (const PQconninfoOption* o = opts.get(); o->keyword; ++o) {
            const std::string k = o->keyword;
            if (!o->val || k == "host" || k == "hostaddr" || k == "port")
                continue;
            no_hosts += k + "=" + yuzu::server::pg::quote_conninfo_value(o->val) + " ";
        }
    }
    struct EnvRestore {
        const char* name;
        std::optional<std::string> saved;
        explicit EnvRestore(const char* n) : name(n) {
            if (const char* v = std::getenv(n))
                saved = v;
        }
        ~EnvRestore() {
            if (saved)
                ::setenv(name, saved->c_str(), 1);
            else
                ::unsetenv(name);
        }
    } restore{"PGSERVICEFILE"};
    ::setenv("PGSERVICEFILE", svc_file.string().c_str(), 1);
    auto check_with = [&](const std::string& entry) {
        {
            std::ofstream f(svc_file, std::ios::trunc);
            f << "[yzsvc]\n" << entry;
        }
        yuzu::server::pg::PgConn c{PQconnectdb((no_hosts + "service=yzsvc").c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        return yuzu::server::pg::check_effective_connection(c.get());
    };
    const std::string hosts = "host=" + pg_host + "," + pg_host + "\nport=" + pg_port + "\n";
    SECTION("load_balance_hosts=random in the service file is refused") {
        const auto r = check_with(hosts + "target_session_attrs=read-write\n"
                                          "load_balance_hosts=random\n");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("load_balance_hosts") != std::string::npos);
    }
    SECTION("a service-file host list without target_session_attrs is refused") {
        const auto r = check_with(hosts);
        REQUIRE_FALSE(r.has_value());
        // PQconninfo reports libpq's default "any" for an unset attribute; the
        // message says so rather than implying the operator set it.
        CHECK(r.error().find("any (or none set)") != std::string::npos);
    }
    SECTION("a restart narrowed to one host still applies the full list's read-write rule") {
        // Round 9 (self-review): the probe's restart after a silent host narrows
        // the list; the check must follow the list the pool walks.
        {
            std::ofstream f(svc_file, std::ios::trunc);
            f << "[yzsvc]\n" << hosts;
        }
        yuzu::server::pg::PgConn c{PQconnectdb((no_hosts + "service=yzsvc host=" + pg_host +
                                                " port=" + pg_port)
                                                   .c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        CHECK(yuzu::server::pg::check_effective_connection(c.get()).has_value()); // 1 host
        CHECK_FALSE(yuzu::server::pg::check_effective_connection(c.get(), 2).has_value());
    }
    SECTION("the readiness probe re-checks on every connection: a service file edited to set "
            "load_balance_hosts turns it red") {
        // Gate 8 round 8 (consistency-auditor, unhappy-path, cpp-expert): libpq
        // re-reads the service file on each connect, so the boot check alone is
        // not enough.
        REQUIRE(check_with(hosts + "target_session_attrs=read-write\n").has_value());
        {
            std::ofstream f(svc_file, std::ios::trunc);
            f << "[yzsvc]\n"
              << hosts << "target_session_attrs=read-write\nload_balance_hosts=random\n";
        }
        auto probe = make_host_list_probe(no_hosts + "service=yzsvc");
        probe->probe_once();
        CHECK(probe->verdict() == pr::Verdict::Unreachable);
    }
    SECTION("a service-file host list with read-write is accepted") {
        CHECK(check_with(hosts + "target_session_attrs=read-write\n").has_value());
    }
    SECTION("a single host from the service file is accepted") {
        CHECK(check_with("host=" + pg_host + "\nport=" + pg_port + "\n").has_value());
    }
}

TEST_CASE("PgReachabilityProbe (libpq, pg): before libpq 17 a host-list wait follows libpq's "
          "whole-second connect_timeout arithmetic",
          "[server][readyz][pg_reachability][pg]") {
    // Gate 8 round 8 (quality-engineer): the ±1s bounds elsewhere accept a probe
    // that never emulates libpq 16 at all. This case discriminates. libpq < 17's
    // blocking connect sets finish = time(NULL) + connect_timeout and derives
    // each wait in whole seconds; a host that answers the SSL request 0.4 s
    // after a start 0.75 s into a wall-clock second (so the answer lands just
    // past the boundary) and then goes silent is given up about 1.4 s in —
    // not after the full 2 s an exact deadline would wait.
    if (PQlibVersion() >= 170000)
        SKIP("libpq 17+ times connect_timeout exactly");
    YUZU_REQUIRE_PG_DB(db);
    FakePostgres slow{"silent", 400ms};
    REQUIRE(slow.port > 0);
    const auto [pg_host, pg_port] = pg_host_port(db.dsn());
    const std::string dsn = multi_host_dsn(db.dsn(), "127.0.0.1," + pg_host,
                                           std::to_string(slow.port) + "," + pg_port) +
                            " connect_timeout=2 sslmode=prefer gssencmode=disable";
    auto probe = make_host_list_probe(dsn);
    // Start 0.75 s into a wall-clock second.
    const auto frac = [] {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count() %
               1000;
    };
    while (frac() < 700 || frac() > 760)
        std::this_thread::sleep_for(5ms);
    const auto t = std::chrono::steady_clock::now();
    probe->probe_once();
    const auto took = std::chrono::steady_clock::now() - t;
    CHECK(probe->verdict() == pr::Verdict::Ready); // moved on to the real server
    CHECK(took >= 1100ms);
    CHECK(took < 1800ms); // an exact 2 s deadline would take >= 2 s
}

TEST_CASE("PgReachabilityProbe (libpq, pg): a failure libpq treats as final ends the host walk "
          "— a later host is never tried",
          "[server][readyz][pg_reachability][pg]") {
    // Gate 8 rounds 4–5: libpq moves to the next host only on a connect failure
    // or timeout, 57P03, or a target_session_attrs rejection; anything else — a
    // failed login, too many clients, an error with no SQLSTATE, a peer that
    // hangs up — ends the attempt. A probe that walked on reached a later host
    // the pool never tries and reported ready while the pool could not connect.
    YUZU_REQUIRE_PG_DB(db);
    const auto [pg_host, pg_port] = pg_host_port(db.dsn());
    // 28P01 = a failed login; 53300 = too many clients, the likelier one in
    // production (sre, round 5); "" = an ErrorResponse with no SQLSTATE, which
    // libpq also treats as final — a probe that decided from the SQLSTATE walked
    // on past it (cpp-expert, round 5).
    // "close" = TCP accepted then closed with no reply (e.g. a proxy with no
    // healthy backend) — final for libpq too (unhappy-path, round 5).
    for (const char* code : {"28P01", "53300", "", "close"}) {
        INFO(code);
        FakePostgres refuses{code};
        REQUIRE(refuses.port > 0);
        auto probe = PgReachabilityProbe::make_libpq(multi_host_dsn(
            db.dsn(), "127.0.0.1," + pg_host, std::to_string(refuses.port) + "," + pg_port));
        probe->probe_once();
        CHECK(probe->verdict() == pr::Verdict::Unreachable);
        CHECK(wait_for_backends(db.dsn(), "yuzu-readyz-probe", 0) == 0); // host 2 never reached
    }
}

TEST_CASE("PgReachabilityProbe (libpq, pg): load_balance_hosts=random is refused by the probe's "
          "own per-connection settings check",
          "[server][readyz][pg_reachability][pg]") {
    // Boot refuses load_balance_hosts (pg/multi_host_dsn.hpp); the probe
    // re-checks every connection it makes, so a fresh probe connection never
    // reads green under it (a service file edited after boot shows at the
    // probe's next reconnect — contract residual (2)).
    YUZU_REQUIRE_PG_DB(db);
    const auto [pg_host, pg_port] = pg_host_port(db.dsn());
    const std::string dsn = multi_host_dsn(db.dsn(), pg_host + "," + pg_host,
                                           pg_port + "," + pg_port) +
                            " load_balance_hosts=random";
    for (int i = 0; i < 3; ++i) {
        auto probe = PgReachabilityProbe::make_libpq(dsn);
        probe->probe_once();
        CHECK(probe->verdict() == pr::Verdict::Unreachable);
    }
}

TEST_CASE("PgReachabilityProbe (libpq, pg): 57P03 (cannot connect now) moves on to the next "
          "host, as libpq's walk does",
          "[server][readyz][pg_reachability][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    FakePostgres starting{"57P03"};
    REQUIRE(starting.port > 0);
    const auto [pg_host, pg_port] = pg_host_port(db.dsn());
    auto probe = PgReachabilityProbe::make_libpq(multi_host_dsn(
        db.dsn(), "127.0.0.1," + pg_host, std::to_string(starting.port) + "," + pg_port));
    probe->probe_once();
    CHECK(probe->verdict() == pr::Verdict::Ready);
}
#endif

TEST_CASE("pg_reachability: libpq < 17's whole-second connect wait",
          "[server][readyz][pg_reachability]") {
    STATIC_REQUIRE(pr::libpq_wall_wait_seconds(110, 100) == 10);
    STATIC_REQUIRE(pr::libpq_wall_wait_seconds(110, 109) == 1);
    STATIC_REQUIRE(pr::libpq_wall_wait_seconds(110, 110) == 0); // due: poll once with 0 ms
    STATIC_REQUIRE(pr::libpq_wall_wait_seconds(110, 111) == 0);
}
