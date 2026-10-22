// test_gateway_route_wiring.cpp — HA WS-4 slice 4.1 SERVER WIRING coverage.
//
// GatewayRouteStore's own methods are already pinned in isolation
// (test_gateway_route_store.cpp, [gateway_route]). What that file does NOT
// cover is GatewayUpstreamServiceImpl (gateway_service_impl.cpp) actually
// DRIVING the store — in particular the one genuinely NEW decision branch
// this slice introduced:
//
//   ProxyRegister re-announce vs fresh. When the caller presents a
//   x-yuzu-session-id metadata value AND that session is still known
//   server-side (gateway_sessions_), ProxyRegister must REUSE it (renew_leases)
//   rather than mint a fresh session+epoch (register_fresh) — the latter would
//   let a delayed circuit-recovery replay clobber a route a newer connection
//   already won.
//
// Plus the CONNECTED -> announce_connected, DISCONNECTED -> deregister, and
// BatchHeartbeat -> renew_leases call sites, and the fail-OPEN posture (a
// degraded directory write never fails the RPC).
//
// Every assertion below is against the store's OBSERVABLE row state
// (lookup_route), not just "the RPC returned OK" — an RPC returning OK proves
// nothing about which store call actually fired.
//
// The re-announce / unknown-session cases need a REAL grpc::ServerContext
// carrying client_metadata() — that cannot be constructed outside an actual
// RPC (see test_grpc_on_behalf_enforce.cpp's note to the same effect), so
// this file spins a real grpc::Server + stub for those two cases only. Every
// other case drives the handler directly with context=nullptr, exactly like
// the existing ProxyRegister suite in test_agent_service_impl.cpp.

#include "gateway_service_impl.hpp"
#include "test_auth_db_pg_helper.hpp" // WS-6 6.2: enrollment state is PG-backed

#include <catch2/catch_test_macros.hpp>

#include <grpcpp/grpcpp.h>

#include "agent_registry.hpp"
#include "agent_service_impl.hpp"
#include "audit_store.hpp"
#include "event_bus.hpp"
#include "fleet_topology_store.hpp"
#include "gateway_route_store.hpp"
#include "heartbeat_ingestion.hpp"
#include "offline_endpoint_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>

#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

#include <algorithm>

#include <libpq-fe.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::AgentServiceImpl;
using yuzu::server::detail::EventBus;
using yuzu::server::detail::GatewayUpstreamServiceImpl;
using yuzu::server::GatewayRouteStore;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;
namespace apb = ::yuzu::agent::v1;
namespace gw = ::yuzu::gateway::v1;

namespace {

// Template-cloned per fixture, mirroring test_gateway_route_store.cpp's own
// template (kept as a separate key — "gwroutewiring" vs "gatewayroute" — so
// the two files' fixtures never share a clone lineage).
yuzu::test::PgTestTemplate gwroutewiring_tpl{"gwroutewiring", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    GatewayRouteStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("gwroutewiring template: store failed to migrate");
}};

// #5678: both GatewayRouteStore and OfflineEndpointStore migrated ONCE in the
// template (no per-test DDL) for the DISCONNECTED -> presence-clear cases.
yuzu::test::PgTestTemplate gwpresence_tpl{"gwpresence", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    GatewayRouteStore route_store{pool};
    yuzu::server::OfflineEndpointStore offline_store{pool};
    if (!route_store.is_open() || !offline_store.is_open())
        throw std::runtime_error("gwpresence template: a store failed to migrate");
}};

/// An AuthManager wired to a PG-backed AuthDB (WS-6 6.2: enrollment/pending state
/// lives only in Postgres, so ProxyRegister needs one). The DB member is
/// destroyed BEFORE the AuthManager base, which only holds a non-owning pointer
/// it never dereferences in its destructor.
class PgAuthManager : public yuzu::server::auth::AuthManager {
public:
    PgAuthManager() { set_auth_db(db_.get()); }

private:
    yuzu::test::AuthDbPgShared db_;
};

// A minimal-but-valid gateway-proxied RegisterRequest, carrying a fresh
// unlimited-use enrollment token so ProxyRegister accepts it outright. Mirrors
// make_gw_register in test_agent_service_impl.cpp (PR5d).
apb::RegisterRequest make_gw_register(yuzu::server::auth::AuthManager& auth_mgr,
                                      const std::string& agent_id) {
    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id(agent_id);
    req.mutable_info()->set_hostname("gw-wiring-host");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");
    {
        // WS-6 6.2: enrollment tokens are minted through the PG-backed AuthDB.
        auto created = auth_mgr.create_enrollment_token("test", 0, std::chrono::hours(1), "test-admin");
        REQUIRE(created.has_value());
        req.set_enrollment_token(created->raw_token);
    }
    return req;
}

// Directly overwrite a row's (connection_epoch, session_id) on a second
// connection — mirrors test_gateway_route_store.cpp's own `raw_bump_epoch`
// helper (kept as a separate copy: that file's fixture is a class member
// function, this file's tests construct the store inline per-case). Used to
// deterministically force a SUBSEQUENT register_fresh call to LOSE its epoch
// race (its freshly-minted epoch, drawn from the store's own sequence, ends
// up lower than this artificially-bumped value) — the 4.2a #8
// lost_race_sessions_ scenario, which single-threaded/in-order test calls
// cannot otherwise reach (each real register_fresh call naturally mints a
// strictly higher epoch than the last).
void raw_bump_epoch(const std::string& dsn, const std::string& agent_id, std::int64_t epoch,
                    const std::string& session_id) {
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    const std::string epoch_s = std::to_string(epoch);
    const char* p1 = agent_id.c_str();
    const char* p2 = epoch_s.c_str();
    const char* p3 = session_id.c_str();
    const char* params[3] = {p1, p2, p3};
    pg::PgResult r{PQexecParams(conn.get(),
                                "UPDATE gateway_route_store.agent_routes SET "
                                "connection_epoch=$2::bigint, session_id=$3 WHERE agent_id=$1",
                                3, nullptr, params, nullptr, nullptr, 0)};
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

// Runs one raw statement on a second connection; used for the scoped
// RENAME COLUMN read-failure seam and for direct row surgery.
void raw_exec(const std::string& dsn, const char* sql) {
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult r{PQexec(conn.get(), sql)};
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

// RAII: `gateway_node` is renamed away so every directory READ fails with a
// db_error while renew_leases (which never names it) keeps succeeding.
struct ScopedReadBreak {
    std::string dsn;
    explicit ScopedReadBreak(std::string d) : dsn(std::move(d)) {
        raw_exec(dsn, "ALTER TABLE gateway_route_store.agent_routes "
                      "RENAME COLUMN gateway_node TO gateway_node_x");
    }
    ~ScopedReadBreak() {
        pg::PgConn conn{PQconnectdb(dsn.c_str())};
        if (PQstatus(conn.get()) == CONNECTION_OK) {
            pg::PgResult r{PQexec(conn.get(), "ALTER TABLE gateway_route_store.agent_routes "
                                              "RENAME COLUMN gateway_node_x TO gateway_node")};
        }
    }
    ScopedReadBreak(const ScopedReadBreak&) = delete;
    ScopedReadBreak& operator=(const ScopedReadBreak&) = delete;
};

// Raw read of `updated_at` (epoch-ms) for one row — GatewayRouteStore's own
// RouteRow deliberately does not expose this column (nothing production-side
// consumes it), so a test that needs to pin the sec-H1 fix's "freeze
// updated_at too, not just lease_until" behavior reads it directly, mirroring
// raw_bump_epoch's direct-connection pattern above.
std::int64_t raw_read_updated_at_ms(const std::string& dsn, const std::string& agent_id) {
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    const char* p1 = agent_id.c_str();
    const char* params[1] = {p1};
    pg::PgResult r{PQexecParams(
        conn.get(),
        "SELECT (extract(epoch FROM updated_at) * 1000)::bigint FROM "
        "gateway_route_store.agent_routes WHERE agent_id=$1",
        1, nullptr, params, nullptr, nullptr, 0)};
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(r.get()) == 1);
    return std::stoll(PQgetvalue(r.get(), 0, 0));
}

/// Real grpc::Server hosting a GatewayUpstreamServiceImpl wired to a
/// caller-supplied GatewayRouteStore. Needed ONLY for the two cases that
/// depend on a real x-yuzu-session-id client_metadata() value — every other
/// case in this file drives the handler directly.
struct LiveGatewayWiringHarness {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl svc{registry, bus, auth_mgr, auto_approve, &metrics};

    std::unique_ptr<grpc::Server> server_;
    int port_ = 0;
    std::unique_ptr<gw::GatewayUpstream::Stub> stub_;

    explicit LiveGatewayWiringHarness(GatewayRouteStore& store) {
        svc.set_gateway_route_store(&store);

        grpc::ServerBuilder builder;
        // Port 0 -> OS assigns an ephemeral free port (avoids fixed-port
        // flakiness under parallel tests, mirrors test_grpc_on_behalf_enforce.cpp).
        builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port_);
        builder.RegisterService(&svc);
        server_ = builder.BuildAndStart();
        REQUIRE(server_ != nullptr);
        REQUIRE(port_ != 0);

        auto channel = grpc::CreateChannel("127.0.0.1:" + std::to_string(port_),
                                           grpc::InsecureChannelCredentials());
        stub_ = gw::GatewayUpstream::NewStub(channel);
    }

    ~LiveGatewayWiringHarness() {
        if (server_) server_->Shutdown();
    }

    LiveGatewayWiringHarness(const LiveGatewayWiringHarness&) = delete;
    LiveGatewayWiringHarness& operator=(const LiveGatewayWiringHarness&) = delete;

    /// Drives a real ProxyRegister RPC, optionally carrying `presented_session`
    /// as the x-yuzu-session-id client metadata value (the only way to
    /// exercise the re-announce/unknown-session branches — see file header).
    apb::RegisterResponse register_agent(const std::string& agent_id,
                                         const std::string& presented_session = {}) {
        auto [status, resp] = register_agent_status(agent_id, presented_session);
        REQUIRE(status.ok());
        return resp;
    }

    /// Like register_agent, but for a call expected to be REFUSED (HA WS-4
    /// 4.4's stale/zombie-replay FAILED_PRECONDITION path) — returns the raw
    /// status instead of REQUIRE-asserting it ok.
    std::pair<grpc::Status, apb::RegisterResponse>
    register_agent_status(const std::string& agent_id, const std::string& presented_session = {}) {
        auto req = make_gw_register(auth_mgr, agent_id);
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
        if (!presented_session.empty())
            ctx.AddMetadata(std::string(AgentServiceImpl::kSessionMetadataKey), presented_session);
        apb::RegisterResponse resp;
        auto status = stub_->ProxyRegister(&ctx, req, &resp);
        return {status, resp};
    }
};

/// Direct-call fixture for the BatchHeartbeat unknown-session verdict cases
/// (#1197): a PG-backed GatewayRouteStore wired into a GatewayUpstreamServiceImpl
/// the test drives without a real grpc::Server (BatchHeartbeat reads no client
/// metadata). Postgres-gated through PgAuthManager; the no-store case below that
/// needs no database builds its own bare service instead.
struct BatchHbFixture {
    PgPool pool;
    GatewayRouteStore store;
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl svc{registry, bus, auth_mgr, auto_approve, &metrics};

    explicit BatchHbFixture(const std::string& dsn)
        : pool{{.conninfo = dsn, .size = 4}}, store{pool} {
        REQUIRE(store.is_open());
        svc.set_gateway_route_store(&store);
    }

    /// ProxyRegister a fresh agent and return its minted session id.
    std::string register_live(const std::string& agent_id) {
        auto req = make_gw_register(auth_mgr, agent_id);
        apb::RegisterResponse resp;
        REQUIRE(svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
        return resp.session_id();
    }

    gw::BatchHeartbeatResponse heartbeat(const std::vector<std::string>& session_ids) {
        gw::BatchHeartbeatRequest batch;
        batch.set_gateway_node("node-hb-verdict");
        for (const auto& id : session_ids)
            batch.add_heartbeats()->set_session_id(id);
        gw::BatchHeartbeatResponse resp;
        REQUIRE(svc.BatchHeartbeat(/*context=*/nullptr, &batch, &resp).ok());
        return resp;
    }

    double desync(const char* op, const char* outcome) {
        return metrics
            .counter("yuzu_server_gateway_route_desync_total", {{"op", op}, {"outcome", outcome}})
            .value();
    }
};

std::vector<std::string> listed_unknown(const gw::BatchHeartbeatResponse& r) {
    return {r.unknown_session_ids().begin(), r.unknown_session_ids().end()};
}

// Mirrors kMaxUnknownSessionIdsPerResponse / kMaxGatewaySessionIdLen in
// gateway_service_impl.hpp; pinned to them below so a changed bound forces a
// deliberate edit of these cases.
constexpr int kTestUnknownCap = 4096;
constexpr std::size_t kTestMaxSessionIdLen = 64;
static_assert(kTestUnknownCap == yuzu::server::detail::kMaxUnknownSessionIdsPerResponse);
static_assert(kTestMaxSessionIdLen == yuzu::server::detail::kMaxGatewaySessionIdLen);

// A well-formed gateway-minted session id: "gw-session-" + 32 lowercase hex.
inline std::string wf_sid(char hex) { return "gw-session-" + std::string(32, hex); }

} // namespace

// ── ProxyRegister: fresh path (no live server needed — context=nullptr means
//    presented_session is always empty, i.e. always fresh) ──────────────────

TEST_CASE("ProxyRegister: fresh register mints a route row; a second fresh register "
          "mints a STRICTLY GREATER epoch (new connection wins)",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    auto req1 = make_gw_register(auth_mgr, "agent-fresh-1");
    apb::RegisterResponse resp1;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req1, &resp1).ok());
    REQUIRE(resp1.accepted());
    const std::string session1 = resp1.session_id();
    REQUIRE_FALSE(session1.empty());

    auto row1 = store.lookup_route("agent-fresh-1");
    REQUIRE(row1.has_value());
    REQUIRE(row1->has_value());
    CHECK((*row1)->session_id == session1);
    const auto epoch1 = (*row1)->connection_epoch;
    CHECK(epoch1 > 0);

    // Second ProxyRegister, still no metadata (context=nullptr => presented
    // session always empty) — a client that never carries x-yuzu-session-id
    // takes the fresh path every time, exactly as before this slice.
    auto req2 = make_gw_register(auth_mgr, "agent-fresh-1");
    apb::RegisterResponse resp2;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req2, &resp2).ok());
    REQUIRE(resp2.accepted());
    const std::string session2 = resp2.session_id();
    CHECK(session2 != session1); // a NEW session was minted, not reused

    auto row2 = store.lookup_route("agent-fresh-1");
    REQUIRE(row2.has_value());
    REQUIRE(row2->has_value());
    CHECK((*row2)->session_id == session2);
    CHECK((*row2)->connection_epoch > epoch1); // strictly greater: new connection wins
}

// ── ProxyRegister: the NEW re-announce-vs-fresh decision branch ─────────────

TEST_CASE("ProxyRegister: presenting a KNOWN x-yuzu-session-id re-announces (renew_leases) "
          "instead of minting a fresh session+epoch — the anti-replay guarantee",
          "[pg][gateway_route_wiring][grpc]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());
    LiveGatewayWiringHarness h(store);

    auto resp1 = h.register_agent("agent-reannounce-1");
    REQUIRE(resp1.accepted());
    const std::string session1 = resp1.session_id();
    REQUIRE_FALSE(session1.empty());

    auto row1 = store.lookup_route("agent-reannounce-1");
    REQUIRE(row1.has_value());
    REQUIRE(row1->has_value());
    const auto epoch1 = (*row1)->connection_epoch;
    // register_fresh never sets a lease (only announce_connected/renew_leases do).
    CHECK_FALSE((*row1)->lease_until_ms.has_value());

    // Simulate the agent's own CONNECTED landing (HA WS-4 4.4 round-2 review
    // fix, sec-H1: renew_leases now leaves lease_until untouched for a
    // cluster_id-IS-NULL row, so a converged placement is required here for
    // the renewal assertion below to mean what it says).
    REQUIRE(store.announce_connected("agent-reannounce-1", session1, "zone-a", "node-a", 90)
                .has_value());

    // Re-announce: present the SAME session id via x-yuzu-session-id metadata.
    auto resp2 = h.register_agent("agent-reannounce-1", session1);
    REQUIRE(resp2.accepted());
    CHECK(resp2.session_id() == session1); // REUSED, not a fresh mint

    auto row2 = store.lookup_route("agent-reannounce-1");
    REQUIRE(row2.has_value());
    REQUIRE(row2->has_value());
    // The core anti-replay guarantee: no new epoch, no session clobber.
    CHECK((*row2)->connection_epoch == epoch1);
    CHECK((*row2)->session_id == session1);
    // renew_leases fired instead of register_fresh.
    REQUIRE((*row2)->lease_until_ms.has_value());
}

TEST_CASE("ProxyRegister: renew_leases does NOT extend the lease for a row still lacking a "
          "converged cluster_id — HA WS-4 4.4 round-2 review fix (sec-H1): an ADOPTED-but-"
          "never-converged row must be able to EXPIRE via the ordinary reaper, not be kept "
          "artificially alive forever by renewals",
          "[pg][gateway_route_wiring][grpc]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());
    LiveGatewayWiringHarness h(store);

    auto resp1 = h.register_agent("agent-unconverged-renew");
    REQUIRE(resp1.accepted());
    const std::string session1 = resp1.session_id();

    // No announce_connected call — cluster_id stays NULL, exactly the state
    // a replay-ADOPTED session sits in when its reannounce/2-triggered
    // CONNECTED was dropped (MAX_NOTIFY_INFLIGHT capacity / circuit-open).
    auto row_before = store.lookup_route("agent-unconverged-renew");
    REQUIRE(row_before.has_value());
    REQUIRE(row_before->has_value());
    CHECK_FALSE((*row_before)->cluster_id.has_value());
    CHECK_FALSE((*row_before)->lease_until_ms.has_value());
    const std::int64_t updated_at_before =
        raw_read_updated_at_ms(db.dsn(), "agent-unconverged-renew");

    // A replay re-announce (the same session, still known in-memory) is the
    // ordinary BatchHeartbeat-equivalent renewal path for this row.
    auto resp2 = h.register_agent("agent-unconverged-renew", session1);
    REQUIRE(resp2.accepted());

    auto row_after = store.lookup_route("agent-unconverged-renew");
    REQUIRE(row_after.has_value());
    REQUIRE(row_after->has_value());
    CHECK_FALSE((*row_after)->cluster_id.has_value()); // still unconverged
    // The core fix: no lease was granted just because the session was
    // renewed — a stuck row must be able to reach its OWN natural
    // lease-expiry (never having had one extended) so reap_stale_routes can
    // eventually tombstone it and give a later reclaim another chance.
    CHECK_FALSE((*row_after)->lease_until_ms.has_value());
    // The completing half of the same fix: `updated_at` must ALSO stay frozen
    // for this row, not just `lease_until` — a `register_fresh` row's
    // `lease_until` is already NULL from creation, so freezing only
    // `lease_until` does nothing to protect it from sweep (b)'s
    // `updated_at`-keyed tombstone-purge predicate (reap_stale_routes,
    // `kTombstonePurgeAgeSecs`). Without this half a row stuck exactly in
    // this state has its purge clock reset on every renewal forever, so it
    // NEVER ages out for a later reclaim to find.
    CHECK(raw_read_updated_at_ms(db.dsn(), "agent-unconverged-renew") == updated_at_before);

    // Once the SAME session's CONNECTED actually lands, convergence and
    // leasing resume completely normally — the fix has no lasting effect on
    // a session that eventually does confirm placement.
    REQUIRE(store.announce_connected("agent-unconverged-renew", session1, "zone-c", "node-c", 90)
                .has_value());
    auto row_converged = store.lookup_route("agent-unconverged-renew");
    REQUIRE(row_converged.has_value());
    REQUIRE(row_converged->has_value());
    CHECK((*row_converged)->cluster_id == "zone-c");
    REQUIRE((*row_converged)->lease_until_ms.has_value());
    // announce_connected stamps its own updated_at=now() — convergence is not
    // itself frozen by this fix.
    CHECK(raw_read_updated_at_ms(db.dsn(), "agent-unconverged-renew") >= updated_at_before);
}

TEST_CASE("ProxyRegister: an UNKNOWN presented x-yuzu-session-id with NO existing row RECLAIMS "
          "it — the row is created under the PRESENTED session, never a fresh mint (HA WS-4 "
          "4.4, `#4246` #6)",
          "[pg][gateway_route_wiring][grpc]") {
    // Pre-4.4 behavior (now fixed): an unknown-locally presented session fell
    // through to minting a throwaway fresh session S' that the directory
    // never learned about, while the caller's own replay logic went on
    // believing it still held the ORIGINAL presented session S — a
    // server/gateway desync (`#4246` #6). Now the server ADOPTS S outright:
    // since no row exists yet for this agent at all, reclaim_tombstoned_session
    // treats that exactly like a tombstone (nothing to protect) and creates
    // one under S, seeded at epoch 0.
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());
    LiveGatewayWiringHarness h(store);

    // First call for this agent ever, so this session id is (and can only be)
    // unknown server-side — precisely the "presented but not in
    // gateway_sessions_" case, distinct from the no-metadata-at-all case
    // above.
    auto resp = h.register_agent("agent-unknown-session", wf_sid('a'));
    REQUIRE(resp.accepted());
    // The response now ADOPTS the presented session — no more S'-vs-S gap.
    CHECK(resp.session_id() == wf_sid('a'));

    auto row = store.lookup_route("agent-unknown-session");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value()); // a row WAS created — reclaimed, not skipped
    CHECK((*row)->session_id == wf_sid('a'));
    CHECK((*row)->connection_epoch == 0); // seeded below anything register_fresh can mint
    REQUIRE((*row)->lease_until_ms.has_value()); // reclaim seeds a fresh lease

    // No desync signal for a clean reclaim — this is the intended, successful
    // path, not a guard rejection.
    CHECK(h.metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "proxy_register"}, {"outcome", "session_superseded"}})
              .value() == 0);
}

TEST_CASE("ProxyRegister: presenting a TOMBSTONED session (the agent disconnected, then a "
          "delayed circuit-recovery replay arrives) RE-ARMS the row under the same session — "
          "the core-restart/post-DISCONNECT-eviction case `#4246` #6 names",
          "[pg][gateway_route_wiring][grpc]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    // Register + connect, then deregister (tombstones the row: session_id/
    // lease_until/cluster_id/gateway_node -> NULL, connection_epoch retained).
    const std::string session_id = wf_sid('b');
    REQUIRE(store.register_fresh("agent-tombstone-replay", session_id).has_value());
    REQUIRE(store.announce_connected("agent-tombstone-replay", session_id, "zone-a", "node-a", 90)
                .has_value());
    REQUIRE(store.deregister("agent-tombstone-replay", session_id).has_value());

    auto tombstoned = store.lookup_route("agent-tombstone-replay");
    REQUIRE(tombstoned.has_value());
    REQUIRE(tombstoned->has_value());
    CHECK_FALSE((*tombstoned)->session_id.has_value()); // confirmed tombstoned

    // A fresh replica (this replica's gateway_sessions_ never learned this
    // session) now receives a delayed replay presenting the SAME, now-
    // tombstoned session — must be reclaimed, not refused.
    LiveGatewayWiringHarness h(store);
    auto resp = h.register_agent("agent-tombstone-replay", session_id);
    REQUIRE(resp.accepted());
    CHECK(resp.session_id() == session_id); // adopted, not a fresh mint

    auto row = store.lookup_route("agent-tombstone-replay");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->session_id == session_id);
    REQUIRE((*row)->lease_until_ms.has_value()); // re-armed with a fresh lease
}

TEST_CASE("#4669: a CLEAN-DEREGISTER tombstone's home_cluster_id survives reclaim, and a "
          "reclaimed session presenting a DIFFERENT cluster is still refused — the priority "
          "item Gate 2 security-guardian asked to convert from code-reading to a test",
          "[pg][gateway_route_wiring][affinity]") {
    // security-guardian's Gate 2 review verified BY READING CODE that
    // reclaim_tombstoned_session never touches home_cluster_id, so the SAME
    // affinity guard covers a reclaimed session too — but flagged that no
    // test chained deregister -> reclaim -> mismatched-cluster-announce
    // end-to-end. This test is that chain.
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    const std::string session_id = wf_sid('c');
    REQUIRE(store.register_fresh("agent-4669-reclaim-clean", session_id).has_value());
    auto bind = store.announce_connected("agent-4669-reclaim-clean", session_id, "cluster-real",
                                         "node-real", 90);
    REQUIRE(bind.has_value());
    CHECK(bind->matched);
    CHECK_FALSE(bind->cluster_affinity_violation);

    // Clean deregister — a real DISCONNECTED, not a reap sweep.
    REQUIRE(store.deregister("agent-4669-reclaim-clean", session_id).has_value());
    auto tombstoned = store.lookup_route("agent-4669-reclaim-clean");
    REQUIRE(tombstoned.has_value());
    REQUIRE(tombstoned->has_value());
    CHECK_FALSE((*tombstoned)->session_id.has_value()); // confirmed tombstoned
    REQUIRE((*tombstoned)->home_cluster_id.has_value()); // #4669: survives a CLEAN deregister
    CHECK(*(*tombstoned)->home_cluster_id == "cluster-real");

    // Reclaim via a fresh replica's ProxyRegister replay presenting the SAME
    // (now-tombstoned) session — the pre-existing, already-tested reclaim
    // mechanism. This does NOT touch home_cluster_id (verified by reading
    // gateway_route_store.cpp's reclaim SQL — it sets only session_id/
    // lease_until/updated_at/connection_epoch).
    LiveGatewayWiringHarness h(store);
    auto resp = h.register_agent("agent-4669-reclaim-clean", session_id);
    REQUIRE(resp.accepted());
    CHECK(resp.session_id() == session_id);

    auto reclaimed = store.lookup_route("agent-4669-reclaim-clean");
    REQUIRE(reclaimed.has_value());
    REQUIRE(reclaimed->has_value());
    REQUIRE((*reclaimed)->home_cluster_id.has_value()); // survived the reclaim too
    CHECK(*(*reclaimed)->home_cluster_id == "cluster-real");

    // The reclaimed session now announces from a DIFFERENT cluster — a
    // rogue that won the session-identity race (the pre-existing, accepted
    // register_fresh/reclaim weakness) still cannot move this agent's
    // affinity, because home_cluster_id survived intact through the whole
    // deregister->reclaim chain.
    auto rogue = store.announce_connected("agent-4669-reclaim-clean", session_id, "cluster-rogue",
                                          "node-rogue", 90);
    REQUIRE(rogue.has_value());
    CHECK_FALSE(rogue->matched);
    CHECK(rogue->cluster_affinity_violation);

    auto final_row = store.lookup_route("agent-4669-reclaim-clean");
    REQUIRE(final_row.has_value());
    REQUIRE(final_row->has_value());
    CHECK(*(*final_row)->home_cluster_id == "cluster-real"); // untouched by the rogue's attempt
}

TEST_CASE("#4669: a REAP-SWEEP-origin tombstone clears home_cluster_id, so a reclaimed session "
          "correctly TOFU-rebinds to whatever cluster next announces — the same 'genuine "
          "staleness' re-home path the design accepts, reached via reclaim rather than a fresh "
          "register_fresh, distinguishing it from the clean-deregister case above",
          "[pg][gateway_route_wiring][affinity]") {
    // Unhappy-path UP-3 (Gate 4): reclaim_tombstoned_session's protection is
    // ORIGIN-DEPENDENT — a clean deregister leaves home_cluster_id intact
    // (test above), but a reap-sweep tombstone clears it (reap_stale_routes'
    // sweep (a) NULLs home_cluster_id alongside the rest, per its own
    // header comment). This is INTENDED: a reap-origin tombstone requires
    // genuine unreachability for the full grace window, matching the
    // design's own accepted "genuine staleness" re-home trigger — this test
    // documents that the SAME acceptance applies whether the next binder
    // arrives via a fresh register_fresh OR a reclaim of the (now
    // unprotected) tombstoned session_id.
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    const std::string session_id = wf_sid('d');
    REQUIRE(store.register_fresh("agent-4669-reclaim-reap", session_id).has_value());
    REQUIRE(store.announce_connected("agent-4669-reclaim-reap", session_id, "cluster-real",
                                     "node-real", 90)
                .has_value());

    // Simulate the reaper's expired-lease sweep tombstoning the row
    // out-of-band (mirroring the existing "mem-vs-store-tombstone" test's
    // pattern of calling deregister directly to simulate the reaper —
    // reap_stale_routes' sweep (a) UPDATE and deregister's tombstone SET
    // clause differ only in that (a) ALSO NULLs home_cluster_id).
    REQUIRE(store.deregister("agent-4669-reclaim-reap", session_id).has_value());
    REQUIRE(store.clear_cluster_affinity("agent-4669-reclaim-reap").has_value());
    auto tombstoned = store.lookup_route("agent-4669-reclaim-reap");
    REQUIRE(tombstoned.has_value());
    REQUIRE(tombstoned->has_value());
    CHECK_FALSE((*tombstoned)->home_cluster_id.has_value()); // reap-origin: cleared

    LiveGatewayWiringHarness h(store);
    auto resp = h.register_agent("agent-4669-reclaim-reap", session_id);
    REQUIRE(resp.accepted());

    // Whichever cluster next legitimately announces for this reclaimed
    // session TOFU-rebinds — by design, matching the accepted re-home path.
    auto rebind = store.announce_connected("agent-4669-reclaim-reap", session_id, "cluster-new",
                                           "node-new", 90);
    REQUIRE(rebind.has_value());
    CHECK(rebind->matched);
    CHECK_FALSE(rebind->cluster_affinity_violation);

    auto final_row = store.lookup_route("agent-4669-reclaim-reap");
    REQUIRE(final_row.has_value());
    REQUIRE(final_row->has_value());
    REQUIRE((*final_row)->home_cluster_id.has_value());
    CHECK(*(*final_row)->home_cluster_id == "cluster-new"); // TOFU-bound to the new claimant
}

TEST_CASE("ProxyRegister: the STORE governs even when the session is KNOWN IN MEMORY — a "
          "tombstoned-out-from-under-it row still gets reclaimed (HA WS-4 4.4 round-2 review "
          "fix F1: a >270s gateway-uplink partition, core itself never restarted)",
          "[pg][gateway_route_wiring][grpc]") {
    // F1 (round-2 Fable review, BLOCKING): the FIRST cut of this decision
    // ADOPTED a presented session outright whenever this replica's
    // in-memory gateway_sessions_ already knew it, WITHOUT ever consulting
    // the store. gateway_sessions_ is erased ONLY by a DISCONNECTED
    // (NotifyStreamStatus) — so a session this replica installed can stay
    // "known in memory" long after GatewayRouteStore::reap_stale_routes
    // has tombstoned (and would eventually hard-delete) its row, e.g. a
    // gateway<->core network partition outlasting the 270s reap grace
    // window while core itself never restarts. Adopting on memory alone in
    // that window installed a fresh AgentSession (wiping placement) and
    // then had announce_connected's fallback INSERT no-op against the
    // still-tombstoned row (ON CONFLICT DO NOTHING) — the route never
    // recovered. This test reproduces exactly that: the SAME harness
    // (so gateway_sessions_ still knows the session) whose STORE row is
    // separately tombstoned out-of-band (simulating the reaper), and
    // asserts the replay still reclaims it instead of silently adopting.
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());
    LiveGatewayWiringHarness h(store);

    auto resp1 = h.register_agent("agent-mem-vs-store-tombstone");
    REQUIRE(resp1.accepted());
    const std::string session_id = resp1.session_id();

    // Simulate the reaper tombstoning the row out from under a replica
    // that still believes (via gateway_sessions_) it owns this session —
    // a direct store call, bypassing NotifyStreamStatus entirely, so the
    // harness's in-memory session map is untouched.
    REQUIRE(store.deregister("agent-mem-vs-store-tombstone", session_id).has_value());
    auto tombstoned = store.lookup_route("agent-mem-vs-store-tombstone");
    REQUIRE(tombstoned.has_value());
    REQUIRE(tombstoned->has_value());
    CHECK_FALSE((*tombstoned)->session_id.has_value());

    // The SAME harness (session_id still "known in memory") replays.
    auto resp2 = h.register_agent("agent-mem-vs-store-tombstone", session_id);
    REQUIRE(resp2.accepted());
    CHECK(resp2.session_id() == session_id); // adopted via reclaim, not silently via memory

    auto row = store.lookup_route("agent-mem-vs-store-tombstone");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->session_id == session_id); // RE-ARMED — the bug left this tombstoned forever
    REQUIRE((*row)->lease_until_ms.has_value());
}

TEST_CASE("ProxyRegister: the STORE governs even when the session is KNOWN IN MEMORY — a row "
          "LIVE under a DIFFERENT session REFUSES the replay instead of zombie-overwriting it "
          "(HA WS-4 4.4 round-2 review fix F1: cross-node zombie session)",
          "[pg][gateway_route_wiring][grpc]") {
    // F1's second half: an agent that reconnected to a DIFFERENT gateway
    // node under a NEW session S2 (installing a correct, live directory
    // row) while THIS replica's stale local gateway_sessions_ entry for
    // the OLD session S1 was still intact used to ADOPT S1 on memory
    // alone and overwrite S2's live placement. The store already knows
    // the right answer (REFUSE) and must be asked.
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());
    LiveGatewayWiringHarness h(store);

    auto resp1 = h.register_agent("agent-mem-vs-store-zombie");
    REQUIRE(resp1.accepted());
    const std::string s1 = resp1.session_id();

    // Simulate the agent reconnecting to a DIFFERENT gateway node: a
    // direct store call installs a NEW, live session S2 for the same
    // agent — bypassing this harness's ProxyRegister/gateway_sessions_
    // entirely, so THIS replica's map still (incorrectly) believes S1 is
    // current.
    const std::string s2 = "gw-session-zombie-winner";
    auto fresh = store.register_fresh("agent-mem-vs-store-zombie", s2);
    REQUIRE(fresh.has_value());
    REQUIRE(fresh->won);
    REQUIRE(store.announce_connected("agent-mem-vs-store-zombie", s2, "zone-b", "node-b", 90)
                .has_value());

    // The SAME harness (s1 still "known in memory") replays presenting
    // the now-superseded s1.
    auto [status, resp2] = h.register_agent_status("agent-mem-vs-store-zombie", s1);
    CHECK_FALSE(status.ok());
    CHECK(status.error_code() == grpc::StatusCode::FAILED_PRECONDITION);

    auto row = store.lookup_route("agent-mem-vs-store-zombie");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->session_id == s2); // S2's live placement survives untouched
    CHECK((*row)->cluster_id == "zone-b");
    CHECK((*row)->gateway_node == "node-b");
}

TEST_CASE("ProxyRegister: a ZOMBIE unknown presented session (the agent's row belongs to a "
          "DIFFERENT, LIVE current session) is REFUSED outright (FAILED_PRECONDITION) and "
          "leaves the live row untouched — HA WS-4 4.4 (`#4246` #6)",
          "[pg][gateway_route_wiring][grpc]") {
    // Pre-4.4 behavior (now fixed): this case fell through to minting a
    // throwaway fresh session and returning grpc::Status::OK, so the gateway
    // had no signal that its replay was stale — it just kept using an
    // orphaned session forever. Now the server refuses the RPC outright
    // (FAILED_PRECONDITION), which the gateway-side fix (HA WS-4 4.4,
    // yuzu_gw_upstream.erl) uses to force the agent to reconnect fresh,
    // and installs NOTHING (no register_agent, no store write) on this path.
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());
    LiveGatewayWiringHarness h(store);

    // Establish a real, current route via a genuine (no-metadata) fresh
    // registration.
    auto resp1 = h.register_agent("agent-zombie-1");
    REQUIRE(resp1.accepted());
    const std::string current_session = resp1.session_id();

    auto row_before = store.lookup_route("agent-zombie-1");
    REQUIRE(row_before.has_value());
    REQUIRE(row_before->has_value());
    CHECK((*row_before)->session_id == current_session);
    const auto epoch_before = (*row_before)->connection_epoch;

    // Present a DIFFERENT, forged session — never seen by this replica's
    // gateway_sessions_ (case 3: unknown locally) AND not the row's current
    // LIVE session either (the "zombie" shape) — reclaim_tombstoned_session's
    // guard (`session_id IS NULL`) can never win against it.
    auto [status, resp2] =
        h.register_agent_status("agent-zombie-1", wf_sid('e'));
    CHECK_FALSE(status.ok());
    CHECK(status.error_code() == grpc::StatusCode::FAILED_PRECONDITION);

    auto row_after = store.lookup_route("agent-zombie-1");
    REQUIRE(row_after.has_value());
    REQUIRE(row_after->has_value());
    CHECK((*row_after)->session_id == current_session); // untouched
    CHECK((*row_after)->connection_epoch == epoch_before); // untouched

    CHECK(h.metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "proxy_register"}, {"outcome", "session_superseded"}})
              .value() == 1);
    CHECK(h.metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "proxy_register"}, {"outcome", "session_held_by_other_agent"}})
              .value() == 0);
}

TEST_CASE("ProxyRegister: replaying a session a real second registration replaced is refused "
          "as superseded and the live session keeps the row",
          "[pg][gateway_route_wiring][grpc][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());
    LiveGatewayWiringHarness h(store);

    const std::string agent = "yuzu_test_ws5_real_supersede";
    const std::string s1 = h.register_agent(agent).session_id();
    const std::string s2 = h.register_agent(agent).session_id();
    REQUIRE(s1 != s2);

    auto [status, resp] = h.register_agent_status(agent, s1);
    CHECK(status.error_code() == grpc::StatusCode::FAILED_PRECONDITION);
    CHECK(h.metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "proxy_register"}, {"outcome", "session_superseded"}})
              .value() == 1);
    CHECK(h.metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "proxy_register"}, {"outcome", "session_held_by_other_agent"}})
              .value() == 0);

    gw::StreamStatusNotification disc;
    disc.set_agent_id(agent);
    disc.set_session_id(s1);
    disc.set_event(gw::StreamStatusNotification::DISCONNECTED);
    gw::StreamStatusAck ack;
    REQUIRE(h.svc.NotifyStreamStatus(/*context=*/nullptr, &disc, &ack).ok());
    auto row = store.lookup_route(agent);
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->session_id == s2);
    CHECK(h.registry.session_is(agent, s2));
}

// ── #8 desync counters: announce_connected / deregister mismatch ───────────

TEST_CASE("NotifyStreamStatus: a STALE CONNECTED for a session already superseded by a genuine "
          "newer registration is REJECTED outright and never reaches announce_connected — HA "
          "WS-4 4.4 post-build review fix (PR #4636 FortitudeEtc BLOCKER 2): "
          "AgentRegistry::set_gateway_route is now session-checked, so a delayed reannounce for "
          "a superseded session can no longer clobber the CURRENT session's in-memory "
          "gateway_node/capabilities/stream_home_id",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    // session1 legitimately WINS its own register_fresh epoch race (this is
    // NOT the lost_race_sessions_ scenario) — it is only superseded LATER by
    // session2's own genuine fresh registration.
    auto req1 = make_gw_register(auth_mgr, "agent-mismatch-1");
    apb::RegisterResponse resp1;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req1, &resp1).ok());
    const std::string session1 = resp1.session_id();

    auto req2 = make_gw_register(auth_mgr, "agent-mismatch-1");
    apb::RegisterResponse resp2;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req2, &resp2).ok());
    const std::string session2 = resp2.session_id();
    REQUIRE(session2 != session1);

    // session2's OWN legitimate CONNECTED — establishes a known-good baseline
    // in the in-memory registry to assert against below.
    gw::StreamStatusNotification good_notif;
    good_notif.set_agent_id("agent-mismatch-1");
    good_notif.set_session_id(session2);
    good_notif.set_event(gw::StreamStatusNotification::CONNECTED);
    good_notif.set_cluster_id("cluster-2");
    good_notif.set_gateway_node("node-2");
    good_notif.add_wire_capabilities("cap-real");
    good_notif.set_stream_home_id("home-2");
    gw::StreamStatusAck good_ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &good_notif, &good_ack).ok());
    REQUIRE(good_ack.acknowledged());

    // A stale, DELAYED CONNECTED for the now-superseded session1 — still a
    // live entry in gateway_sessions_ (passes that check), but no longer the
    // CURRENT session for this agent.
    gw::StreamStatusNotification notif;
    notif.set_agent_id("agent-mismatch-1");
    notif.set_session_id(session1);
    notif.set_event(gw::StreamStatusNotification::CONNECTED);
    notif.set_cluster_id("cluster-stale");
    notif.set_gateway_node("node-stale");
    notif.add_wire_capabilities("should-not-apply");
    notif.set_stream_home_id("home-stale");
    gw::StreamStatusAck ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack).ok());
    // The core fix: rejected outright, not silently accepted.
    CHECK_FALSE(ack.acknowledged());

    // Rejected BEFORE reaching announce_connected at all — the store's row
    // stays exactly as session2's own legitimate CONNECTED left it.
    auto row = store.lookup_route("agent-mismatch-1");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->session_id == session2);
    CHECK((*row)->cluster_id == "cluster-2"); // session2's write, untouched by the stale attempt

    // The registry-level assertion this finding's own regression test was
    // missing: session2's in-memory gateway_node/capabilities/stream_home_id
    // are UNCHANGED by the stale CONNECTED, not merely the store row.
    CHECK(registry.gateway_has_wire_capability("agent-mismatch-1", "cap-real"));
    CHECK_FALSE(registry.gateway_has_wire_capability("agent-mismatch-1", "should-not-apply"));
    auto home2 = registry.gateway_stream_home_id("agent-mismatch-1", session2);
    REQUIRE(home2.has_value());
    CHECK(*home2 == "home-2");
    // session1 is no longer the installed session at all, so this accessor's
    // own session guard returns nullopt for it — a second, independent proof
    // the stale CONNECTED never became "current" in the registry either.
    CHECK_FALSE(registry.gateway_stream_home_id("agent-mismatch-1", session1).has_value());

    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "notify_stream_status"}, {"outcome", "stale_connected_session"}})
              .value() == 1);
    // Never reached announce_connected, so the old outcome this test used to
    // pin never fires for this scenario anymore.
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "announce_connected"}, {"outcome", "session_mismatch"}})
              .value() == 0);
}

TEST_CASE("ProxyRegister: a session that LOSES its register_fresh epoch race does NOT bump the "
          "desync counter when its follow-up CONNECTED arrives (benign race loss, not a desync)",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    auto req1 = make_gw_register(auth_mgr, "agent-race-1");
    apb::RegisterResponse resp1;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req1, &resp1).ok());
    auto row1 = store.lookup_route("agent-race-1");
    REQUIRE(row1.has_value());
    REQUIRE(row1->has_value());

    // Artificially bump the row's epoch far above whatever the store's own
    // sequence will mint next, simulating a newer connection that already
    // won — deterministic single-threaded stand-in for the real concurrent
    // race (see raw_bump_epoch's header comment).
    raw_bump_epoch(db.dsn(), "agent-race-1", (*row1)->connection_epoch + 1000,
                  "gw-session-already-won");

    // A SECOND fresh registration (no metadata — same "fresh" branch) now
    // mints a lower epoch than the artificially-bumped row and LOSES the
    // race.
    auto req2 = make_gw_register(auth_mgr, "agent-race-1");
    apb::RegisterResponse resp2;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req2, &resp2).ok());
    const std::string losing_session = resp2.session_id();

    auto row2 = store.lookup_route("agent-race-1");
    REQUIRE(row2.has_value());
    REQUIRE(row2->has_value());
    CHECK((*row2)->session_id == "gw-session-already-won"); // the losing register_fresh did NOT win

    // The losing session's own follow-up CONNECTED must skip
    // announce_connected entirely (lost_race_sessions_) rather than call it
    // and observe matched=false.
    gw::StreamStatusNotification notif;
    notif.set_agent_id("agent-race-1");
    notif.set_session_id(losing_session);
    notif.set_event(gw::StreamStatusNotification::CONNECTED);
    notif.set_cluster_id("cluster-loser");
    notif.set_gateway_node("node-loser");
    gw::StreamStatusAck ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack).ok());
    CHECK(ack.acknowledged());

    // The winning row is completely untouched by the loser's CONNECTED.
    auto row3 = store.lookup_route("agent-race-1");
    REQUIRE(row3.has_value());
    REQUIRE(row3->has_value());
    CHECK((*row3)->session_id == "gw-session-already-won");
    CHECK_FALSE((*row3)->cluster_id.has_value());

    // The core assertion: no desync counter increment for this benign race loss.
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "announce_connected"}, {"outcome", "session_mismatch"}})
              .value() == 0);
}

// ── NotifyStreamStatus: unknown-session reject counter ──────────────────────

TEST_CASE("NotifyStreamStatus: an unknown session (never registered on this replica) is "
          "rejected and bumps the desync counter",
          "[gateway_route_wiring]") {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    // No gateway_route_store wired at all — this case exercises the
    // in-memory gateway_sessions_ guard purely, unrelated to the store.

    gw::StreamStatusNotification notif;
    notif.set_agent_id("agent-never-registered");
    notif.set_session_id("gw-session-never-seen");
    notif.set_event(gw::StreamStatusNotification::CONNECTED);
    gw::StreamStatusAck ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack).ok());
    CHECK_FALSE(ack.acknowledged());

    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "notify_stream_status"}, {"outcome", "unknown_session"}})
              .value() == 1);
}

TEST_CASE("NotifyStreamStatus: the unknown-session warning prints the agent id neutralised",
          "[gateway_route_wiring][log_injection]") {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};

    gw::StreamStatusNotification notif;
    notif.set_agent_id("agent x=1\nfake");
    notif.set_session_id("gw-session-never-seen");
    notif.set_event(gw::StreamStatusNotification::CONNECTED);
    gw::StreamStatusAck ack;
    yuzu::test::LogCapture cap;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack).ok());
    cap.stop();
    CHECK_FALSE(ack.acknowledged());

    // The id is folded to the closed character set (space, '=' and the line break become '_').
    CHECK(cap.text().find("unknown session gw-session-never-seen for agent agent_x_1_fake") !=
          std::string::npos);
    CHECK(cap.text().find("agent x=1") == std::string::npos);
    CHECK(yuzu::test::stray_control_bytes(cap.text()) == 0);
}

// ── NotifyStreamStatus: CONNECTED / DISCONNECTED ────────────────────────────

TEST_CASE("NotifyStreamStatus: CONNECTED fills cluster_id/gateway_node for the matching session",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    auto req = make_gw_register(auth_mgr, "agent-connect-1");
    apb::RegisterResponse resp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
    const std::string session_id = resp.session_id();

    gw::StreamStatusNotification notif;
    notif.set_agent_id("agent-connect-1");
    notif.set_session_id(session_id);
    notif.set_event(gw::StreamStatusNotification::CONNECTED);
    notif.set_cluster_id("cluster-a");
    notif.set_gateway_node("node-a");
    gw::StreamStatusAck ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack).ok());
    CHECK(ack.acknowledged());

    auto row = store.lookup_route("agent-connect-1");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->cluster_id == "cluster-a");
    CHECK((*row)->gateway_node == "node-a");
    CHECK((*row)->lease_until_ms.has_value()); // announce_connected sets the lease
}

// ── #4669: agent<->cluster affinity (WS-9-style scenario) ──────────────────

TEST_CASE("NotifyStreamStatus: a CONNECTED claiming a DIFFERENT cluster than the agent's "
          "durably-bound home affinity is REFUSED outright — #4669, closes the "
          "'rogue cluster claims an agent already live elsewhere' shape (the issue's own "
          "acceptance-criteria scenario)",
          "[pg][gateway_route_wiring][affinity]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    // The agent is live on the REAL cluster ("cluster-x") — a normal
    // ProxyRegister + CONNECTED, binding the agent's home affinity.
    auto req1 = make_gw_register(auth_mgr, "agent-hijack-1");
    apb::RegisterResponse resp1;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req1, &resp1).ok());
    const std::string real_session = resp1.session_id();

    gw::StreamStatusNotification real_notif;
    real_notif.set_agent_id("agent-hijack-1");
    real_notif.set_session_id(real_session);
    real_notif.set_event(gw::StreamStatusNotification::CONNECTED);
    real_notif.set_cluster_id("cluster-x");
    real_notif.set_gateway_node("node-real");
    gw::StreamStatusAck real_ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &real_notif, &real_ack).ok());
    REQUIRE(real_ack.acknowledged());

    // A SECOND gateway process calls ProxyRegister for the SAME
    // already-approved agent_id — no per-agent secret required (the issue's
    // finding), and no presented x-yuzu-session-id (context=nullptr means
    // the "fresh" register_fresh branch, which unconditionally wins the
    // epoch race — a pre-existing, accepted weakness #4669 does not attempt
    // to close by itself). It then tries to CONFIRM its own, different
    // cluster.
    auto req2 = make_gw_register(auth_mgr, "agent-hijack-1");
    apb::RegisterResponse resp2;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req2, &resp2).ok());
    const std::string rogue_session = resp2.session_id();
    REQUIRE(rogue_session != real_session);

    gw::StreamStatusNotification rogue_notif;
    rogue_notif.set_agent_id("agent-hijack-1");
    rogue_notif.set_session_id(rogue_session);
    rogue_notif.set_event(gw::StreamStatusNotification::CONNECTED);
    rogue_notif.set_cluster_id("cluster-rogue");
    rogue_notif.set_gateway_node("node-rogue");
    rogue_notif.add_wire_capabilities("rogue-cap");
    rogue_notif.set_stream_home_id("home-rogue");
    gw::StreamStatusAck rogue_ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &rogue_notif, &rogue_ack).ok());

    // THE MITIGATION: refused outright, not silently re-homed.
    CHECK_FALSE(rogue_ack.acknowledged());

    // The durable row: session_id reflects register_fresh's own
    // unconditional epoch win (pre-existing, undisputed by this fix) but
    // cluster_id was NEVER confirmed for the rogue (still NULL — register_
    // fresh nulled it, and the refused announce_connected never wrote it),
    // and home_cluster_id is UNCHANGED.
    auto row = store.lookup_route("agent-hijack-1");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->session_id == rogue_session);
    CHECK_FALSE((*row)->cluster_id.has_value());
    REQUIRE((*row)->home_cluster_id.has_value());
    CHECK(*(*row)->home_cluster_id == "cluster-x");

    // The PRIMARY dispatch path (AgentRegistry::set_gateway_route ->
    // AgentSession::cluster_id, read by send_to/send_to_all) was ALSO never
    // published for the rogue session — proven via the stream_home_id/
    // wire-capability accessors (the only publicly-observable fields
    // set_gateway_route writes): if set_gateway_route had been called with
    // the rogue's payload, gateway_stream_home_id would read back
    // "home-rogue" and the wire capability "rogue-cap" would be present.
    // Neither happened — the #4669 reorder (announce_connected gates
    // set_gateway_route) closed the split this fix exists to prevent.
    auto rogue_home = registry.gateway_stream_home_id("agent-hijack-1", rogue_session);
    REQUIRE(rogue_home.has_value()); // the session IS installed (register_fresh always wins)
    CHECK(rogue_home->empty());      // but set_gateway_route was never called for it
    CHECK_FALSE(registry.gateway_has_wire_capability("agent-hijack-1", "rogue-cap"));

    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "announce_connected"}, {"outcome", "cluster_affinity_violation"}})
              .value() == 1);

    // The REAL agent's own later reconnect self-heals: a fresh
    // register_fresh always wins the epoch race, and its CONNECTED presents
    // the matching cluster.
    auto req3 = make_gw_register(auth_mgr, "agent-hijack-1");
    apb::RegisterResponse resp3;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req3, &resp3).ok());
    const std::string real_session2 = resp3.session_id();

    gw::StreamStatusNotification real_notif2;
    real_notif2.set_agent_id("agent-hijack-1");
    real_notif2.set_session_id(real_session2);
    real_notif2.set_event(gw::StreamStatusNotification::CONNECTED);
    real_notif2.set_cluster_id("cluster-x");
    real_notif2.set_gateway_node("node-real-2");
    gw::StreamStatusAck real_ack2;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &real_notif2, &real_ack2).ok());
    CHECK(real_ack2.acknowledged());

    auto row2 = store.lookup_route("agent-hijack-1");
    REQUIRE(row2.has_value());
    REQUIRE(row2->has_value());
    REQUIRE((*row2)->cluster_id.has_value());
    CHECK(*(*row2)->cluster_id == "cluster-x");
}

TEST_CASE("a rogue's ORIGINAL still-live session resending CONNECTED after the round-1 "
          "soft-tombstone sweep orphans its session_id is STILL refused — #4669 pr-rev round 2 "
          "(FortitudeEtc/Codex+Kimi, CRITICAL, empirically reproduced twice independently)",
          "[pg][gateway_route_wiring][affinity]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    // 1. The real agent binds cluster-x — an ordinary ProxyRegister + CONNECTED.
    auto req1 = make_gw_register(auth_mgr, "agent-orv2-1");
    apb::RegisterResponse resp1;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req1, &resp1).ok());
    const std::string real_session = resp1.session_id();

    gw::StreamStatusNotification real_notif;
    real_notif.set_agent_id("agent-orv2-1");
    real_notif.set_session_id(real_session);
    real_notif.set_event(gw::StreamStatusNotification::CONNECTED);
    real_notif.set_cluster_id("cluster-x");
    real_notif.set_gateway_node("node-real");
    gw::StreamStatusAck real_ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &real_notif, &real_ack).ok());
    REQUIRE(real_ack.acknowledged());

    // 2. A rogue's ProxyRegister unconditionally wins the epoch race (pre-existing,
    // accepted weakness), installing its OWN session in gateway_sessions_. Its
    // first CONNECTED, claiming a different cluster, is correctly refused
    // (the round-1 mechanism this test does not re-litigate) — but the rogue's
    // session stays live: nothing invalidates a gateway_sessions_ entry merely
    // because a CONNECTED for it was refused.
    auto req2 = make_gw_register(auth_mgr, "agent-orv2-1");
    apb::RegisterResponse resp2;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req2, &resp2).ok());
    const std::string rogue_session = resp2.session_id();
    REQUIRE(rogue_session != real_session);

    gw::StreamStatusNotification rogue_notif1;
    rogue_notif1.set_agent_id("agent-orv2-1");
    rogue_notif1.set_session_id(rogue_session);
    rogue_notif1.set_event(gw::StreamStatusNotification::CONNECTED);
    rogue_notif1.set_cluster_id("cluster-y");
    rogue_notif1.set_gateway_node("node-rogue");
    gw::StreamStatusAck rogue_ack1;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &rogue_notif1, &rogue_ack1).ok());
    REQUIRE_FALSE(rogue_ack1.acknowledged());

    auto row_before_reap = store.lookup_route("agent-orv2-1");
    REQUIRE(row_before_reap.has_value());
    REQUIRE(row_before_reap->has_value());
    CHECK((*row_before_reap)->session_id == rogue_session);
    REQUIRE((*row_before_reap)->home_cluster_id.has_value());
    CHECK(*(*row_before_reap)->home_cluster_id == "cluster-x");

    // 3. Age the row past the tombstone-purge age and reap. The round-1 fix's
    // soft-tombstone sweep (b') fires: session_id/cluster_id/gateway_node/
    // stream_home_id -> NULL, but home_cluster_id is PRESERVED (this is the
    // round-1 fix working exactly as designed).
    {
        pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const char* p1 = "agent-orv2-1";
        const char* params[1] = {p1};
        pg::PgResult r{PQexecParams(conn.get(),
                                    "UPDATE gateway_route_store.agent_routes SET "
                                    "  updated_at = now() - interval '400 seconds' "
                                    "WHERE agent_id=$1",
                                    1, nullptr, params, nullptr, nullptr, 0)};
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    auto reap_out = store.reap_stale_routes();
    REQUIRE(reap_out.has_value());
    CHECK(reap_out->tombstones_reaped == 0); // NOT hard-deleted (round-1 fix)
    CHECK(reap_out->affinity_preserved_soft_tombstones == 1);

    auto row_after_reap = store.lookup_route("agent-orv2-1");
    REQUIRE(row_after_reap.has_value());
    REQUIRE(row_after_reap->has_value());
    CHECK_FALSE((*row_after_reap)->session_id.has_value());
    REQUIRE((*row_after_reap)->home_cluster_id.has_value());
    CHECK(*(*row_after_reap)->home_cluster_id == "cluster-x"); // preserved, as designed

    // 4. THE ATTACK: the rogue's ORIGINAL session (still live in this
    // replica's gateway_sessions_ — never invalidated by the earlier refusal)
    // resends CONNECTED, still claiming cluster-y. Before the round-2 fix,
    // both affinity probes matched only `session_id=$2` exactly, which the
    // now-NULL durable session_id could never satisfy, so this fell through
    // to an ordinary, unaudited session_mismatch and the rogue's cluster was
    // published to the in-memory dispatch route regardless.
    gw::StreamStatusNotification rogue_notif2;
    rogue_notif2.set_agent_id("agent-orv2-1");
    rogue_notif2.set_session_id(rogue_session);
    rogue_notif2.set_event(gw::StreamStatusNotification::CONNECTED);
    rogue_notif2.set_cluster_id("cluster-y");
    rogue_notif2.set_gateway_node("node-rogue-2");
    rogue_notif2.add_wire_capabilities("rogue-cap-2");
    rogue_notif2.set_stream_home_id("home-rogue-2");
    gw::StreamStatusAck rogue_ack2;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &rogue_notif2, &rogue_ack2).ok());

    // THE FIX: still refused, not silently re-homed.
    CHECK_FALSE(rogue_ack2.acknowledged());

    // The in-memory dispatch route was never published for the rogue's resend.
    auto rogue_home = registry.gateway_stream_home_id("agent-orv2-1", rogue_session);
    REQUIRE(rogue_home.has_value()); // the session IS still installed
    CHECK(rogue_home->empty());      // but set_gateway_route was never called for this resend
    CHECK_FALSE(registry.gateway_has_wire_capability("agent-orv2-1", "rogue-cap-2"));

    // The durable row's affinity is untouched.
    auto row_final = store.lookup_route("agent-orv2-1");
    REQUIRE(row_final.has_value());
    REQUIRE(row_final->has_value());
    REQUIRE((*row_final)->home_cluster_id.has_value());
    CHECK(*(*row_final)->home_cluster_id == "cluster-x");

    // Classified as a real affinity violation (caught by the PRE-CHECK this
    // time, not the write-time branch — same op/outcome label either way,
    // per gateway_service_impl.cpp's own comment on why they share one
    // label), not folded into the benign session_mismatch bucket. Two
    // increments total across this test: the rogue's FIRST CONNECTED
    // (session-matched violation) and this resend (session-orphaned
    // violation, the fix this test exists for).
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "announce_connected"}, {"outcome", "cluster_affinity_violation"}})
              .value() == 2);

    // The real cluster can still reconnect successfully afterwards.
    auto req3 = make_gw_register(auth_mgr, "agent-orv2-1");
    apb::RegisterResponse resp3;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req3, &resp3).ok());
    const std::string real_session2 = resp3.session_id();

    gw::StreamStatusNotification real_notif2;
    real_notif2.set_agent_id("agent-orv2-1");
    real_notif2.set_session_id(real_session2);
    real_notif2.set_event(gw::StreamStatusNotification::CONNECTED);
    real_notif2.set_cluster_id("cluster-x");
    real_notif2.set_gateway_node("node-real-2");
    gw::StreamStatusAck real_ack2;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &real_notif2, &real_ack2).ok());
    CHECK(real_ack2.acknowledged());
}

TEST_CASE("AgentRegistry::unpublish_gateway_route reverts exactly what set_gateway_route just "
          "published for a matching session (#4669 pr-rev Blocker 2, the write-time-violation "
          "revert this method exists for)",
          "[pg][gateway_route_wiring][affinity]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    auto req = make_gw_register(auth_mgr, "agent-unpublish-1");
    apb::RegisterResponse resp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
    const std::string session = resp.session_id();

    // A legitimate CONNECTED publishes gateway_node/wire_capabilities/
    // stream_home_id/cluster_id in-memory via set_gateway_route — the exact
    // publish unpublish_gateway_route must be able to revert.
    gw::StreamStatusNotification notif;
    notif.set_agent_id("agent-unpublish-1");
    notif.set_session_id(session);
    notif.set_event(gw::StreamStatusNotification::CONNECTED);
    notif.set_cluster_id("cluster-x");
    notif.set_gateway_node("node-x");
    notif.add_wire_capabilities("cap-x");
    notif.set_stream_home_id("home-x");
    gw::StreamStatusAck ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack).ok());
    REQUIRE(ack.acknowledged());

    // Sanity: the publish actually landed before we revert it.
    auto home_before = registry.gateway_stream_home_id("agent-unpublish-1", session);
    REQUIRE(home_before.has_value());
    CHECK(*home_before == "home-x");
    CHECK(registry.gateway_has_wire_capability("agent-unpublish-1", "cap-x"));

    // THE METHOD UNDER TEST: revert it, simulating what NotifyStreamStatus's
    // write-time cluster_affinity_violation branch does after
    // set_gateway_route already ran but announce_connected's own guarded
    // write definitively refused the claim.
    CHECK(registry.unpublish_gateway_route("agent-unpublish-1", session));

    auto home_after = registry.gateway_stream_home_id("agent-unpublish-1", session);
    REQUIRE(home_after.has_value()); // session still matches — just unstamped
    CHECK(home_after->empty());
    CHECK_FALSE(registry.gateway_has_wire_capability("agent-unpublish-1", "cap-x"));

    // A SECOND call for the SAME still-installed session is a harmless,
    // idempotent no-op — still `true` (the session_id match is what the
    // return value reports, not whether there was anything left to clear),
    // not an error, not a crash.
    CHECK(registry.unpublish_gateway_route("agent-unpublish-1", session));

    // A session_id that does not match the currently-installed one (a
    // superseded/foreign session) is refused — reverting it would silently
    // tear down a DIFFERENT, possibly newer, live publish.
    CHECK_FALSE(registry.unpublish_gateway_route("agent-unpublish-1", "some-other-session"));

    // An unknown agent_id is refused the same way — nothing to revert.
    CHECK_FALSE(registry.unpublish_gateway_route("agent-never-registered", session));
}

TEST_CASE("#4669: a refused cross-cluster claim emits an audited gateway.cluster_affinity_"
          "violation row with the correct principal/target/detail — Gate 4 consistency-auditor "
          "SHOULD: the new AuditEvent construction was previously exercised by no test at all "
          "(audit_store_ stayed nullptr in the hijack-scenario test)",
          "[pg][gateway_route_wiring][affinity]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());
    yuzu::server::AuditStore audit{pool};
    REQUIRE(audit.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);
    gateway_svc.set_audit_store(&audit);

    auto req1 = make_gw_register(auth_mgr, "agent-audit-1");
    apb::RegisterResponse resp1;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req1, &resp1).ok());
    const std::string real_session = resp1.session_id();

    gw::StreamStatusNotification real_notif;
    real_notif.set_agent_id("agent-audit-1");
    real_notif.set_session_id(real_session);
    real_notif.set_event(gw::StreamStatusNotification::CONNECTED);
    real_notif.set_cluster_id("cluster-audit-real");
    real_notif.set_gateway_node("node-real");
    gw::StreamStatusAck real_ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &real_notif, &real_ack).ok());
    REQUIRE(real_ack.acknowledged());

    // The pre-check catches this (the common case): a same-session CONNECTED
    // claiming a different cluster, refused BEFORE set_gateway_route.
    gw::StreamStatusNotification rogue_notif;
    rogue_notif.set_agent_id("agent-audit-1");
    rogue_notif.set_session_id(real_session);
    rogue_notif.set_event(gw::StreamStatusNotification::CONNECTED);
    rogue_notif.set_cluster_id("cluster-audit-rogue");
    rogue_notif.set_gateway_node("node-rogue");
    gw::StreamStatusAck rogue_ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &rogue_notif, &rogue_ack).ok());
    CHECK_FALSE(rogue_ack.acknowledged());

    auto rows = audit.query({});
    REQUIRE(rows.has_value());
    auto matching = std::ranges::count_if(*rows, [](const auto& r) {
        return r.action == "gateway.cluster_affinity_violation";
    });
    REQUIRE(matching == 1); // exactly one violation audited for this one refusal

    auto it = std::ranges::find_if(*rows, [](const auto& r) {
        return r.action == "gateway.cluster_affinity_violation";
    });
    REQUIRE(it != rows->end());
    CHECK(it->principal == "gateway_cluster:cluster-audit-rogue");
    CHECK(it->principal_role == "gateway");
    CHECK(it->target_type == "agent");
    CHECK(it->target_id == "agent-audit-1");
    CHECK(it->result == "failure");
    CHECK(it->detail.find("session=" + real_session) != std::string::npos);
    CHECK(it->detail.find("claimed_cluster_id=cluster-audit-rogue") != std::string::npos);
    CHECK(it->detail.find("detected_at=pre_check") != std::string::npos);
}

TEST_CASE("NotifyStreamStatus: single-gateway/non-multi-cluster deployments are unaffected by "
          "the #4669 affinity guard — the SAME stable cluster_id across repeated reconnects "
          "keeps succeeding",
          "[pg][gateway_route_wiring][affinity]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    // A single-cluster-mode gateway build announces the SAME literal
    // cluster_id ("default", per YUZU_GW_CLUSTER_ID's own default) on every
    // connection — ADR-2002 §7d.
    for (int i = 0; i < 3; ++i) {
        auto req = make_gw_register(auth_mgr, "agent-single-gw-1");
        apb::RegisterResponse resp;
        REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
        const std::string session_id = resp.session_id();

        gw::StreamStatusNotification notif;
        notif.set_agent_id("agent-single-gw-1");
        notif.set_session_id(session_id);
        notif.set_event(gw::StreamStatusNotification::CONNECTED);
        notif.set_cluster_id("default");
        notif.set_gateway_node("node-" + std::to_string(i));
        gw::StreamStatusAck ack;
        REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack).ok());
        CHECK(ack.acknowledged());

        auto row = store.lookup_route("agent-single-gw-1");
        REQUIRE(row.has_value());
        REQUIRE(row->has_value());
        REQUIRE((*row)->cluster_id.has_value());
        CHECK(*(*row)->cluster_id == "default");

        // A clean DISCONNECTED between reconnects, mirroring an ordinary
        // agent restart cycle.
        gw::StreamStatusNotification dnotif;
        dnotif.set_agent_id("agent-single-gw-1");
        dnotif.set_session_id(session_id);
        dnotif.set_event(gw::StreamStatusNotification::DISCONNECTED);
        gw::StreamStatusAck dack;
        REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &dnotif, &dack).ok());
    }

    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "announce_connected"}, {"outcome", "cluster_affinity_violation"}})
              .value() == 0);
}

TEST_CASE("NotifyStreamStatus: DISCONNECTED tombstones the route only for the matching "
          "session — a stale/superseded session does not tear it down",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    auto req1 = make_gw_register(auth_mgr, "agent-disconnect-1");
    apb::RegisterResponse resp1;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req1, &resp1).ok());
    const std::string session1 = resp1.session_id();

    // A second (context-less, hence still "fresh path") ProxyRegister mints a
    // NEWER session that wins the epoch race and overwrites the row's
    // session_id — simulating a reconnect that has already superseded
    // session1's route.
    auto req2 = make_gw_register(auth_mgr, "agent-disconnect-1");
    apb::RegisterResponse resp2;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req2, &resp2).ok());
    const std::string session2 = resp2.session_id();
    REQUIRE(session2 != session1);

    // A stale DISCONNECTED for the now-superseded session1 must NOT tear down
    // session2's row (session-guarded deregister in gateway_route_store.cpp).
    gw::StreamStatusNotification stale;
    stale.set_agent_id("agent-disconnect-1");
    stale.set_session_id(session1);
    stale.set_event(gw::StreamStatusNotification::DISCONNECTED);
    gw::StreamStatusAck stale_ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &stale, &stale_ack).ok());

    auto row_after_stale = store.lookup_route("agent-disconnect-1");
    REQUIRE(row_after_stale.has_value());
    REQUIRE(row_after_stale->has_value());              // still present
    CHECK((*row_after_stale)->session_id == session2);  // untouched — still session2

    // 4.2a #8: the store's session-guarded UPDATE matched zero rows
    // (removed=false) — the stale session1 no-op is exactly the guard
    // rejection this counter exists to make visible.
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "deregister"}, {"outcome", "session_mismatch"}})
              .value() == 1);

    // The matching DISCONNECTED for session2 DOES tombstone it (4.2a:
    // deregister is a session-guarded UPDATE-to-tombstone, not a DELETE — see
    // gateway_route_store.hpp "SLICE 4.2a" — so the row stays present with
    // session_id/lease_until/cluster_id/gateway_node nulled, not gone).
    gw::StreamStatusNotification real;
    real.set_agent_id("agent-disconnect-1");
    real.set_session_id(session2);
    real.set_event(gw::StreamStatusNotification::DISCONNECTED);
    gw::StreamStatusAck real_ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &real, &real_ack).ok());

    auto row_after_real = store.lookup_route("agent-disconnect-1");
    REQUIRE(row_after_real.has_value());
    REQUIRE(row_after_real->has_value()); // tombstoned, not removed
    CHECK_FALSE((*row_after_real)->session_id.has_value());
    CHECK_FALSE((*row_after_real)->lease_until_ms.has_value());

    // The matching (removed=true) deregister must NOT bump the desync
    // counter — still exactly the one count from the stale attempt above.
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "deregister"}, {"outcome", "session_mismatch"}})
              .value() == 1);
}

TEST_CASE("NotifyStreamStatus #4324: a fresh session's OWN DISCONNECTED reaching the server "
          "BEFORE its own paired CONNECTED still tears down normally — the reorder/"
          "lost-CONNECTED regression from PR #4492's review, HIGH",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    // NO re-home involved — this is the FIRST and ONLY CONNECTED/DISCONNECTED
    // pair this session will ever have. The gateway dispatches the two as
    // independently spawn_monitor'd RPC workers with no ordering guarantee
    // between them (see gateway_route_store.hpp's PREDICATE FIX note), so an
    // ordinary fast connect/disconnect can have its DISCONNECTED reach this
    // server before its own paired CONNECTED — which is what this test
    // simulates by simply never sending the CONNECTED at all before the
    // DISCONNECTED arrives.
    auto req = make_gw_register(auth_mgr, "agent-reorder-1");
    apb::RegisterResponse resp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
    const std::string session_id = resp.session_id();

    gw::StreamStatusNotification disc;
    disc.set_agent_id("agent-reorder-1");
    disc.set_session_id(session_id);
    disc.set_event(gw::StreamStatusNotification::DISCONNECTED);
    disc.set_stream_home_id("home-first-and-only");
    gw::StreamStatusAck ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &disc, &ack).ok());
    CHECK(ack.acknowledged());

    // Must NOT be misclassified as stale_home — this is a genuine, matching
    // (if oddly-ordered) DISCONNECTED for this session's only ever home.
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "deregister"}, {"outcome", "stale_home"}})
              .value() == 0);

    // The DISCONNECTED's own teardown must have actually RUN, not been
    // skipped: (1) the AgentRegistry entry is gone (remove_agent_if_session
    // erases it outright on a match), and (2) the durable row is tombstoned.
    // The ORIGINAL bug skipped all three teardown effects on this exact
    // sequence, leaving both of these looking live.
    CHECK(registry.get_session("agent-reorder-1") == nullptr);
    auto row_after_disc = store.lookup_route("agent-reorder-1");
    REQUIRE(row_after_disc.has_value());
    REQUIRE(row_after_disc->has_value()); // tombstoned, not removed
    CHECK_FALSE((*row_after_disc)->session_id.has_value());

    // The delayed CONNECTED that eventually arrives for a stream that's
    // already gone must NOT be able to publish a live-looking route for it.
    // AgentRegistry::set_gateway_route no-ops on an agent_id it can't find
    // (the DISCONNECTED already erased it), and announce_connected's
    // session-guarded UPDATE misses the now-tombstoned row (session_id is
    // NULL) with its ON CONFLICT fallback correctly no-opping against the
    // existing tombstone (SLICE 4.2a) — so the delayed CONNECTED must leave
    // BOTH sides exactly as the DISCONNECTED left them: gone, not live.
    gw::StreamStatusNotification connected;
    connected.set_agent_id("agent-reorder-1");
    connected.set_session_id(session_id);
    connected.set_event(gw::StreamStatusNotification::CONNECTED);
    connected.set_cluster_id("cluster-late");
    connected.set_gateway_node("node-late");
    connected.set_stream_home_id("home-first-and-only");
    gw::StreamStatusAck conn_ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &connected, &conn_ack).ok());

    CHECK(registry.get_session("agent-reorder-1") == nullptr);
    auto row_after_late_connected = store.lookup_route("agent-reorder-1");
    REQUIRE(row_after_late_connected.has_value());
    REQUIRE(row_after_late_connected->has_value());
    CHECK_FALSE((*row_after_late_connected)->session_id.has_value());
}

// ── #4324: the per-home stream-generation fence ─────────────────────────────
//
// The scenario #4324 exists to prevent: a session is CONNECTED under home A,
// then RE-HOMED to home B while REUSING the same session_id (a live
// circuit-recovery reconnect), and a stale DISCONNECTED from the now-torn-down
// home A arrives afterward. Constructed here via the REAL production call
// sequence — ProxyRegister's re-announce mechanism (needs a live grpc
// context to carry x-yuzu-session-id metadata, hence LiveGatewayWiringHarness)
// followed by a second CONNECTED for the reused session — rather than poking
// registry/store internals directly: ProxyRegister always calls
// register_agent() unconditionally (gateway_service_impl.cpp), even on the
// re-announce branch, so the re-announce INSTALLS A NEW AgentSession object
// that happens to be re-mapped onto the SAME session_id string — exactly the
// "new home, reused session id" shape, and the one thing the shipped gateway
// cannot produce today (at most one CONNECTED(S)/one DISCONNECTED(S) per
// session — see gateway_route_store.hpp's SESSION GUARDS LIMIT note).

TEST_CASE("NotifyStreamStatus #4324: a stale DISCONNECTED from a torn-down home does NOT tear "
          "down a session re-homed under the SAME session id (registry, store, AND the "
          "session map all survive)",
          "[pg][gateway_route_wiring][grpc]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());
    LiveGatewayWiringHarness h(store);

    const std::string agent_id = "agent-stale-home-1";

    // 1. Fresh registration — mints session1.
    auto resp1 = h.register_agent(agent_id);
    REQUIRE(resp1.accepted());
    const std::string session1 = resp1.session_id();
    REQUIRE_FALSE(session1.empty());

    // 2. CONNECTED under home1 — the FIRST home.
    gw::StreamStatusNotification connected1;
    connected1.set_agent_id(agent_id);
    connected1.set_session_id(session1);
    connected1.set_event(gw::StreamStatusNotification::CONNECTED);
    connected1.set_cluster_id("cluster-a");
    connected1.set_gateway_node("node-a");
    connected1.set_stream_home_id("home-1");
    gw::StreamStatusAck ack1;
    REQUIRE(h.svc.NotifyStreamStatus(/*context=*/nullptr, &connected1, &ack1).ok());
    CHECK(ack1.acknowledged());
    CHECK(h.registry.gateway_stream_home_id(agent_id, session1) == "home-1");

    // 3. Re-announce: present the SAME session1 via x-yuzu-session-id metadata
    // (a live circuit-recovery reconnect). ProxyRegister's re-announce branch
    // reuses session1 in the RESPONSE, but register_agent() unconditionally
    // installs a NEW AgentSession object underneath — that new object's own
    // gateway_stream_home_id starts back at empty until its own CONNECTED
    // arrives, below.
    auto resp2 = h.register_agent(agent_id, session1);
    REQUIRE(resp2.accepted());
    REQUIRE(resp2.session_id() == session1); // reused, not a fresh mint

    // 4. CONNECTED under home2 — the SAME session_id, a NEW home. This is the
    // real re-home: same session, new stream_home_id. cluster_id stays
    // "cluster-a" (the SAME cluster as step 2) — a live circuit-recovery
    // reconnect is agent-pinned to its zone's cluster (ADR-2002 §7) and
    // never legitimately crosses clusters under a REUSED session_id; #4669's
    // affinity guard would (correctly) refuse a same-session cluster CHANGE,
    // which is not what THIS scenario (the stream_home_id fence) is testing.
    gw::StreamStatusNotification connected2;
    connected2.set_agent_id(agent_id);
    connected2.set_session_id(session1);
    connected2.set_event(gw::StreamStatusNotification::CONNECTED);
    connected2.set_cluster_id("cluster-a");
    connected2.set_gateway_node("node-b");
    connected2.set_stream_home_id("home-2");
    gw::StreamStatusAck ack2;
    REQUIRE(h.svc.NotifyStreamStatus(/*context=*/nullptr, &connected2, &ack2).ok());
    CHECK(ack2.acknowledged());
    CHECK(h.registry.gateway_stream_home_id(agent_id, session1) == "home-2");

    auto row_after_rehome = store.lookup_route(agent_id);
    REQUIRE(row_after_rehome.has_value());
    REQUIRE(row_after_rehome->has_value());
    CHECK((*row_after_rehome)->gateway_node == "node-b");
    CHECK((*row_after_rehome)->session_id == session1);

    // 5. A STALE DISCONNECTED from the now-torn-down home1 arrives (delayed
    // delivery from the old gateway process instance).
    gw::StreamStatusNotification stale_disc;
    stale_disc.set_agent_id(agent_id);
    stale_disc.set_session_id(session1); // SAME session_id — reused
    stale_disc.set_event(gw::StreamStatusNotification::DISCONNECTED);
    stale_disc.set_gateway_node("node-a");
    stale_disc.set_stream_home_id("home-1"); // STALE — the torn-down home
    gw::StreamStatusAck stale_ack;
    REQUIRE(h.svc.NotifyStreamStatus(/*context=*/nullptr, &stale_disc, &stale_ack).ok());
    // Acked exactly as a successful DISCONNECTED would be — the fence is a
    // silent no-op from the gateway's point of view, not an error.
    CHECK(stale_ack.acknowledged());

    // Assertion 1: the durable directory route is UNCHANGED — home2's
    // placement survives (not tombstoned, still session1/node-b).
    auto row_after_stale = store.lookup_route(agent_id);
    REQUIRE(row_after_stale.has_value());
    REQUIRE(row_after_stale->has_value());
    CHECK((*row_after_stale)->session_id == session1);
    CHECK((*row_after_stale)->gateway_node == "node-b");
    REQUIRE((*row_after_stale)->lease_until_ms.has_value()); // NOT tombstoned

    // Assertion 2: the registry's in-memory session state ALSO survives — the
    // naive "fence the registry/store writes but still erase the session map"
    // shape the design review flagged would fail THIS check even though
    // assertion 1 above would pass. Prove it by sending the SUBSEQUENT
    // genuine DISCONNECTED for the live re-homed session and confirming it is
    // NOT rejected as unknown_session.
    CHECK(h.registry.gateway_stream_home_id(agent_id, session1) == "home-2");
    gw::StreamStatusNotification real_disc;
    real_disc.set_agent_id(agent_id);
    real_disc.set_session_id(session1);
    real_disc.set_event(gw::StreamStatusNotification::DISCONNECTED);
    real_disc.set_gateway_node("node-b");
    real_disc.set_stream_home_id("home-2"); // matches the CURRENT home
    gw::StreamStatusAck real_ack;
    REQUIRE(h.svc.NotifyStreamStatus(/*context=*/nullptr, &real_disc, &real_ack).ok());
    CHECK(real_ack.acknowledged());
    // Not rejected as unknown_session — the fix this scenario exists to prove.
    CHECK(h.metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "notify_stream_status"}, {"outcome", "unknown_session"}})
              .value() == 0);
    auto row_after_real = store.lookup_route(agent_id);
    REQUIRE(row_after_real.has_value());
    REQUIRE(row_after_real->has_value());
    CHECK_FALSE((*row_after_real)->session_id.has_value()); // now genuinely tombstoned

    // Assertion 3: the desync counter recorded exactly the one stale-home
    // rejection above (not the genuine, matching teardown).
    CHECK(h.metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "deregister"}, {"outcome", "stale_home"}})
              .value() == 1);
}

TEST_CASE("NotifyStreamStatus #4324: a legacy (empty stream_home_id) DISCONNECTED for a legacy "
          "(empty stream_home_id) CONNECTED still tombstones normally — backward compatibility "
          "for a gateway build predating #4324",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    const std::string agent_id = "agent-legacy-home-1";
    auto req = make_gw_register(auth_mgr, agent_id);
    apb::RegisterResponse resp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
    const std::string session_id = resp.session_id();

    // Legacy CONNECTED — stream_home_id left unset (defaults to empty, the
    // pre-#4324 wire shape).
    gw::StreamStatusNotification connected;
    connected.set_agent_id(agent_id);
    connected.set_session_id(session_id);
    connected.set_event(gw::StreamStatusNotification::CONNECTED);
    connected.set_gateway_node("node-legacy");
    gw::StreamStatusAck connected_ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &connected, &connected_ack).ok());
    CHECK(connected_ack.acknowledged());
    CHECK(registry.gateway_stream_home_id(agent_id, session_id) == "");

    // Legacy DISCONNECTED — also unset. Both empty ⇒ the fence's "both are
    // legacy" clause admits it, exactly as if #4324 never shipped.
    gw::StreamStatusNotification disconnected;
    disconnected.set_agent_id(agent_id);
    disconnected.set_session_id(session_id);
    disconnected.set_event(gw::StreamStatusNotification::DISCONNECTED);
    disconnected.set_gateway_node("node-legacy");
    gw::StreamStatusAck disconnected_ack;
    REQUIRE(
        gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &disconnected, &disconnected_ack)
            .ok());
    CHECK(disconnected_ack.acknowledged());

    auto row = store.lookup_route(agent_id);
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK_FALSE((*row)->session_id.has_value());     // tombstoned
    CHECK_FALSE((*row)->lease_until_ms.has_value());  // tombstoned

    // No stale-home rejection — legacy-vs-legacy is not a mismatch.
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "deregister"}, {"outcome", "stale_home"}})
              .value() == 0);
}

TEST_CASE("NotifyStreamStatus #4324: an oversized stream_home_id is treated as malformed and "
          "clamped to empty, not used unbounded or rejecting the RPC",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    const std::string agent_id = "agent-oversized-home-1";
    auto req = make_gw_register(auth_mgr, agent_id);
    apb::RegisterResponse resp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
    const std::string session_id = resp.session_id();

    gw::StreamStatusNotification connected;
    connected.set_agent_id(agent_id);
    connected.set_session_id(session_id);
    connected.set_event(gw::StreamStatusNotification::CONNECTED);
    connected.set_gateway_node("node-oversized");
    connected.set_stream_home_id(std::string(65, 'x')); // 1 over the 64-byte bound
    gw::StreamStatusAck ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &connected, &ack).ok());
    CHECK(ack.acknowledged()); // malformed input degrades to legacy, never rejects the RPC

    // Clamped to empty, not stored unbounded.
    CHECK(registry.gateway_stream_home_id(agent_id, session_id) == "");
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "announce_connected"}, {"outcome", "malformed_home_id"}})
              .value() == 1);

    // A subsequent legacy-shaped (empty) DISCONNECTED still tears it down
    // normally — the clamp behaves exactly like an honestly-empty value.
    gw::StreamStatusNotification disconnected;
    disconnected.set_agent_id(agent_id);
    disconnected.set_session_id(session_id);
    disconnected.set_event(gw::StreamStatusNotification::DISCONNECTED);
    disconnected.set_gateway_node("node-oversized");
    gw::StreamStatusAck disc_ack;
    REQUIRE(
        gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &disconnected, &disc_ack).ok());
    CHECK(disc_ack.acknowledged());
    auto row = store.lookup_route(agent_id);
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK_FALSE((*row)->session_id.has_value()); // tombstoned normally
}

TEST_CASE("NotifyStreamStatus #4324: an oversized stream_home_id on DISCONNECTED is ALSO "
          "clamped to empty (symmetric with the CONNECTED-path clamp above), and a legacy "
          "(never-stamped) row still tombstones normally",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    const std::string agent_id = "agent-oversized-home-disc-1";
    auto req = make_gw_register(auth_mgr, agent_id);
    apb::RegisterResponse resp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
    const std::string session_id = resp.session_id();

    // Legacy-shaped CONNECTED -- stream_home_id left unset (empty), exactly like
    // a pre-#4324 gateway build.
    gw::StreamStatusNotification connected;
    connected.set_agent_id(agent_id);
    connected.set_session_id(session_id);
    connected.set_event(gw::StreamStatusNotification::CONNECTED);
    connected.set_gateway_node("node-oversized-disc");
    gw::StreamStatusAck conn_ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &connected, &conn_ack).ok());
    CHECK(conn_ack.acknowledged());
    CHECK(registry.gateway_stream_home_id(agent_id, session_id) == "");

    // DISCONNECTED carries an oversized (>64 byte) stream_home_id this time --
    // the clamp lives in the SAME `if (stream_home_id.size() > kMaxStreamHomeIdLen)`
    // shape duplicated in both branches of gateway_service_impl.cpp; this proves
    // the DISCONNECTED copy is genuinely reachable and behaves identically to the
    // CONNECTED-path clamp asserted above, not merely "structurally identical by
    // inspection" (Gate 2/3's LOW finding).
    gw::StreamStatusNotification disconnected;
    disconnected.set_agent_id(agent_id);
    disconnected.set_session_id(session_id);
    disconnected.set_event(gw::StreamStatusNotification::DISCONNECTED);
    disconnected.set_gateway_node("node-oversized-disc");
    disconnected.set_stream_home_id(std::string(65, 'y')); // 1 over the 64-byte bound
    gw::StreamStatusAck disc_ack;
    REQUIRE(
        gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &disconnected, &disc_ack).ok());
    CHECK(disc_ack.acknowledged());

    // Clamped to empty before the fence comparison -- the fence then sees
    // stored="" (legacy CONNECTED) vs incoming="" (clamped), which matches the
    // asymmetric predicate's both-empty legacy branch, so this tombstones
    // normally rather than being (incorrectly) rejected as a stale-home mismatch.
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "deregister"}, {"outcome", "malformed_home_id"}})
              .value() == 1);
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "deregister"}, {"outcome", "stale_home"}})
              .value() == 0);
    auto row = store.lookup_route(agent_id);
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK_FALSE((*row)->session_id.has_value()); // tombstoned normally, not leaked
}

// ── BatchHeartbeat: renew_leases ────────────────────────────────────────────

TEST_CASE("BatchHeartbeat: renews the route lease for the carried session ids in one call",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    auto req = make_gw_register(auth_mgr, "agent-hb-1");
    apb::RegisterResponse resp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
    const std::string session_id = resp.session_id();

    auto row_before = store.lookup_route("agent-hb-1");
    REQUIRE(row_before.has_value());
    REQUIRE(row_before->has_value());
    CHECK_FALSE((*row_before)->lease_until_ms.has_value()); // register_fresh sets no lease
    const auto epoch_before = (*row_before)->connection_epoch;

    // HA WS-4 4.4 round-2 review fix (sec-H1): renew_leases now leaves
    // lease_until untouched for a cluster_id-IS-NULL row, so this agent's
    // CONNECTED must land (converging placement) before BatchHeartbeat's
    // renewal below is expected to actually grant a lease.
    REQUIRE(store.announce_connected("agent-hb-1", session_id, "zone-hb", "node-hb", 90)
                .has_value());

    gw::BatchHeartbeatRequest batch;
    batch.set_gateway_node("node-hb");
    auto* hb = batch.add_heartbeats();
    hb->set_session_id(session_id);
    gw::BatchHeartbeatResponse batch_resp;
    REQUIRE(gateway_svc.BatchHeartbeat(/*context=*/nullptr, &batch, &batch_resp).ok());

    auto row_after = store.lookup_route("agent-hb-1");
    REQUIRE(row_after.has_value());
    REQUIRE(row_after->has_value());
    CHECK((*row_after)->lease_until_ms.has_value());       // renewed by BatchHeartbeat
    CHECK((*row_after)->connection_epoch == epoch_before); // unaffected
    CHECK((*row_after)->session_id == session_id);
}

TEST_CASE("BatchHeartbeat: a duplicate session id in one batch and a lost-epoch-race session "
          "do NOT inflate the shortfall desync counter (PR #4299 review SHOULD 2)",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    // A genuinely live session — its row is real, so renewing it matches
    // exactly one row no matter how many times its id appears in the batch.
    auto req_live = make_gw_register(auth_mgr, "agent-hb-dup-1");
    apb::RegisterResponse resp_live;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req_live, &resp_live).ok());
    const std::string live_session = resp_live.session_id();
    // HA WS-4 4.4 round-2 review fix (sec-H1): converge placement so the
    // renewal assertion below (a converged row IS granted a lease) is
    // meaningful under the new cluster_id-gated renew_leases semantics.
    REQUIRE(store.announce_connected("agent-hb-dup-1", live_session, "zone-dup", "node-dup", 90)
                .has_value());

    // A session that LOSES its register_fresh epoch race — deterministic
    // single-threaded stand-in via raw_bump_epoch, mirrors the existing
    // "does NOT bump the desync counter" NotifyStreamStatus case above.
    auto req_race1 = make_gw_register(auth_mgr, "agent-hb-race-1");
    apb::RegisterResponse resp_race1;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req_race1, &resp_race1).ok());
    auto row_race = store.lookup_route("agent-hb-race-1");
    REQUIRE(row_race.has_value());
    REQUIRE(row_race->has_value());
    raw_bump_epoch(db.dsn(), "agent-hb-race-1", (*row_race)->connection_epoch + 1000,
                  "gw-session-already-won");
    auto req_race2 = make_gw_register(auth_mgr, "agent-hb-race-1");
    apb::RegisterResponse resp_race2;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req_race2, &resp_race2).ok());
    const std::string losing_session = resp_race2.session_id();
    auto row_after_race = store.lookup_route("agent-hb-race-1");
    REQUIRE(row_after_race.has_value());
    REQUIRE(row_after_race->has_value());
    CHECK((*row_after_race)->session_id == "gw-session-already-won"); // the loser did NOT win

    // A batch carrying the live session TWICE (a retried-batch duplicate,
    // per the Erlang heartbeat buffer's no-dedup prepend) plus the losing
    // session once. renew_leases matches exactly ONE row (the live session
    // — the losing session's row belongs to a DIFFERENT session and matches
    // zero). Pre-fix, the raw comparison (3 requested vs 1 matched) would
    // report a shortfall of 2; post-fix, deduping to {live, losing} and
    // dropping the known race-loser leaves only {live}, matching 1-for-1.
    gw::BatchHeartbeatRequest batch;
    batch.set_gateway_node("node-hb-dup");
    batch.add_heartbeats()->set_session_id(live_session);
    batch.add_heartbeats()->set_session_id(live_session); // duplicate
    batch.add_heartbeats()->set_session_id(losing_session);
    gw::BatchHeartbeatResponse batch_resp;
    REQUIRE(gateway_svc.BatchHeartbeat(/*context=*/nullptr, &batch, &batch_resp).ok());

    auto row_live_after = store.lookup_route("agent-hb-dup-1");
    REQUIRE(row_live_after.has_value());
    REQUIRE(row_live_after->has_value());
    CHECK((*row_live_after)->lease_until_ms.has_value()); // genuinely renewed

    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "renew_leases"}, {"outcome", "shortfall"}})
              .value() == 0);
}

TEST_CASE("BatchHeartbeat: a session this replica's gateway_sessions_ doesn't recognize is "
          "excluded from the renew batch but counted as unknown_session, not silently dropped "
          "(#4246 #3/#10)",
          "[pg][gateway_route_wiring]") {
    // #4246 #10's renew correlation resolves agent_id from the per-replica
    // gateway_sessions_ map (the wire carries no agent_id) — a session this
    // replica never registered has nothing to correlate against, so it's
    // excluded from renew_leases entirely. That must still be OBSERVABLE via
    // the desync counter (op="renew_leases", outcome="unknown_session"),
    // never a silent drop — the exact regression this test pins.
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    // A genuinely live, locally-known session, to prove the unknown one
    // doesn't disturb its renewal.
    auto req_live = make_gw_register(auth_mgr, "agent-hb-unknown-1");
    apb::RegisterResponse resp_live;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req_live, &resp_live).ok());
    const std::string live_session = resp_live.session_id();
    // HA WS-4 4.4 round-2 review fix (sec-H1): converge placement so the
    // "still renews normally" assertion below is meaningful under the new
    // cluster_id-gated renew_leases semantics.
    REQUIRE(store.announce_connected("agent-hb-unknown-1", live_session, "zone-unk", "node-unk",
                                     90)
                .has_value());

    gw::BatchHeartbeatRequest batch;
    batch.set_gateway_node("node-hb-unknown");
    batch.add_heartbeats()->set_session_id(live_session);
    // Never registered on this replica — this session_id is in no
    // gateway_sessions_ entry at all.
    batch.add_heartbeats()->set_session_id("gw-session-never-registered-here");
    gw::BatchHeartbeatResponse batch_resp;
    REQUIRE(gateway_svc.BatchHeartbeat(/*context=*/nullptr, &batch, &batch_resp).ok());

    // The known session still renews normally.
    auto row_live_after = store.lookup_route("agent-hb-unknown-1");
    REQUIRE(row_live_after.has_value());
    REQUIRE(row_live_after->has_value());
    CHECK((*row_live_after)->lease_until_ms.has_value());

    // No shortfall — the unknown session was never added to the renew batch
    // in the first place, so it can't manifest as a SQL-level mismatch.
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "renew_leases"}, {"outcome", "shortfall"}})
              .value() == 0);
    // But it IS surfaced, distinctly, as unknown_session.
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "renew_leases"}, {"outcome", "unknown_session"}})
              .value() == 1);
    // #1197: the verdict names exactly the session this replica does not
    // hold; the live session is absent; nothing was truncated.
    CHECK(batch_resp.acknowledged_count() == 1);
    CHECK(listed_unknown(batch_resp) ==
          std::vector<std::string>{"gw-session-never-registered-here"});
    CHECK_FALSE(batch_resp.unknown_session_ids_truncated());
}

// ── #1197: BatchHeartbeatResponse.unknown_session_ids ───────────────────────
//
// A concurrent BatchHeartbeat-vs-ProxyRegister/Deregister test is deliberately
// not written here: the unknown set and counters are function-local and
// sessions_mu_ use is unchanged. The nightly TSan lane runs the existing
// BatchHeartbeat cases.

TEST_CASE("BatchHeartbeat verdict: a batch of only known sessions lists nothing and is not "
          "truncated (#1197)",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture f(db.dsn());
    const auto s1 = f.register_live("agent-verdict-known-1");
    const auto s2 = f.register_live("agent-verdict-known-2");

    auto resp = f.heartbeat({s1, s2});
    CHECK(resp.acknowledged_count() == 2);
    CHECK(resp.unknown_session_ids_size() == 0);
    CHECK_FALSE(resp.unknown_session_ids_truncated());
    CHECK(f.desync("renew_leases", "unknown_session") == 0);
}

TEST_CASE("BatchHeartbeat verdict: the same unknown id repeated is listed once and counted once "
          "(#1197)",
          "[pg][gateway_route_wiring]") {
    // The Erlang buffer retains a failed batch and prepends the next with no
    // dedup, so duplicates are a real input shape.
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture f(db.dsn());

    auto resp = f.heartbeat(
        {"gw-session-dup-unknown", "gw-session-dup-unknown", "gw-session-dup-unknown"});
    CHECK(resp.acknowledged_count() == 0);
    CHECK(listed_unknown(resp) == std::vector<std::string>{"gw-session-dup-unknown"});
    CHECK_FALSE(resp.unknown_session_ids_truncated());
    CHECK(f.desync("renew_leases", "unknown_session") == 1);
}

TEST_CASE("BatchHeartbeat verdict: the listed unknown set is capped, truncation is flagged, and "
          "exactly the cap is NOT truncation (#1197)",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture f(db.dsn());

    auto make_ids = [](int n) {
        std::vector<std::string> ids;
        ids.reserve(static_cast<std::size_t>(n));
        for (int i = 0; i < n; ++i)
            ids.push_back("gw-session-unk-" + std::to_string(i));
        return ids;
    };

    SECTION("exactly the cap: all listed, not truncated") {
        auto resp = f.heartbeat(make_ids(kTestUnknownCap));
        CHECK(resp.unknown_session_ids_size() == kTestUnknownCap);
        CHECK_FALSE(resp.unknown_session_ids_truncated());
        CHECK(f.desync("renew_leases", "unknown_session") == kTestUnknownCap);
    }
    SECTION("cap + 1: cap listed (distinct), truncated, desync counts the full set") {
        const auto input = make_ids(kTestUnknownCap + 1);
        auto resp = f.heartbeat(input);
        CHECK(resp.unknown_session_ids_size() == kTestUnknownCap);
        CHECK(resp.unknown_session_ids_truncated());
        auto listed = listed_unknown(resp);
        // Every listed id came from the input (nothing invented or mangled).
        const std::set<std::string> input_set(input.begin(), input.end());
        CHECK(std::all_of(listed.begin(), listed.end(),
                          [&](const std::string& id) { return input_set.contains(id); }));
        std::sort(listed.begin(), listed.end());
        CHECK(std::adjacent_find(listed.begin(), listed.end()) == listed.end());
        CHECK(f.desync("renew_leases", "unknown_session") == kTestUnknownCap + 1);
    }
}

TEST_CASE("BatchHeartbeat verdict: an empty session id is neither acked nor listed (#1197)",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture f(db.dsn());
    const auto live = f.register_live("agent-verdict-empty-1");

    auto resp = f.heartbeat({live, "", "gw-session-unknown-beside-empty"});
    CHECK(resp.acknowledged_count() == 1);
    CHECK(listed_unknown(resp) == std::vector<std::string>{"gw-session-unknown-beside-empty"});
    CHECK(f.desync("renew_leases", "unknown_session") == 1);
}

TEST_CASE("BatchHeartbeat verdict: an over-length UNKNOWN id is neither acked nor listed and is "
          "counted malformed_session_id, never unknown_session (#1197)",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture f(db.dsn());
    const auto live = f.register_live("agent-verdict-long-1");
    const std::string too_long(kTestMaxSessionIdLen + 1, 'x');
    const std::string at_limit(kTestMaxSessionIdLen, 'y');

    auto resp = f.heartbeat({live, too_long, too_long, at_limit});
    CHECK(resp.acknowledged_count() == 1);
    // The boundary: exactly 64 bytes is still a listable unknown.
    CHECK(listed_unknown(resp) == std::vector<std::string>{at_limit});
    // The counter is advanced by the number of malformed entries (the
    // duplicate over-length id is two entries).
    CHECK(f.desync("batch_heartbeat", "malformed_session_id") == 2);
    CHECK(f.desync("renew_leases", "unknown_session") == 1);
}

TEST_CASE("BatchHeartbeat verdict: a lost-race session is KNOWN, so it is never listed "
          "(#1197)",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture f(db.dsn());

    // Same deterministic lost-race stand-in as the dedup case above.
    f.register_live("agent-verdict-race-1");
    auto row = f.store.lookup_route("agent-verdict-race-1");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    raw_bump_epoch(db.dsn(), "agent-verdict-race-1", (*row)->connection_epoch + 1000,
                   "gw-session-already-won");
    const auto losing = f.register_live("agent-verdict-race-1");

    auto resp = f.heartbeat({losing});
    CHECK(resp.unknown_session_ids_size() == 0);
    CHECK_FALSE(resp.unknown_session_ids_truncated());
    CHECK(f.desync("renew_leases", "unknown_session") == 0);
}

TEST_CASE("ProxyRegister: an over-length or malformed presented session id is refused and counted "
          "without touching the directory (Fix 8a)",
          "[pg][gateway_route_wiring][grpc]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());
    LiveGatewayWiringHarness h(store);

    const std::string long_id = "gw-session-" + std::string(kTestMaxSessionIdLen + 1 - 11, 'a');
    REQUIRE(long_id.size() == kTestMaxSessionIdLen + 1);
    for (const auto& bad : {long_id, std::string("gw-session-not-hex"),
                            "gw-session-" + std::string(32, 'G'), std::string("x") + wf_sid('a')}) {
        auto [status, resp] = h.register_agent_status("agent-malformed-presented", bad);
        CHECK(status.error_code() == grpc::StatusCode::FAILED_PRECONDITION);
    }
    CHECK(h.metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "proxy_register"}, {"outcome", "malformed_session_id"}})
              .value() == 4);
    CHECK(h.registry.get_session("agent-malformed-presented") == nullptr);
    auto row = store.lookup_route("agent-malformed-presented");
    REQUIRE(row.has_value());
    CHECK_FALSE(row->has_value());
}

TEST_CASE("BatchHeartbeat verdict: a mixed batch lists exactly the distinct unknown ids and "
          "counts the rest correctly (#1197)",
          "[pg][gateway_route_wiring][grpc]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());
    LiveGatewayWiringHarness h(store);

    // known: a normally minted session.
    const auto known = h.register_agent("agent-mixed-known").session_id();
    // known: a session that lost its register_fresh epoch race.
    h.register_agent("agent-mixed-race");
    auto row = store.lookup_route("agent-mixed-race");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    raw_bump_epoch(db.dsn(), "agent-mixed-race", (*row)->connection_epoch + 1000,
                   "gw-session-mixed-already-won");
    const auto losing = h.register_agent("agent-mixed-race").session_id();
    auto row_after_race = store.lookup_route("agent-mixed-race");
    REQUIRE(row_after_race.has_value());
    REQUIRE(row_after_race->has_value());
    CHECK((*row_after_race)->session_id == "gw-session-mixed-already-won"); // the loser did NOT win

    const std::string too_long(kTestMaxSessionIdLen + 1, 'x');
    gw::BatchHeartbeatRequest batch;
    batch.set_gateway_node("node-hb-mixed");
    for (const auto& id : std::vector<std::string>{known, "gw-session-mixed-unknown",
                                                   "gw-session-mixed-unknown", losing, "",
                                                   too_long, too_long})
        batch.add_heartbeats()->set_session_id(id);
    gw::BatchHeartbeatResponse resp;
    REQUIRE(h.svc.BatchHeartbeat(/*context=*/nullptr, &batch, &resp).ok());

    // The two known sessions are acked; the empty, over-length and unknown
    // entries are not.
    CHECK(resp.acknowledged_count() == 2);
    CHECK(listed_unknown(resp) == std::vector<std::string>{"gw-session-mixed-unknown"});
    CHECK_FALSE(resp.unknown_session_ids_truncated());
    // Counted per entry (the duplicate over-length id is two entries).
    CHECK(h.metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "batch_heartbeat"}, {"outcome", "malformed_session_id"}})
              .value() == 2);
    // Distinct unknown ids only.
    CHECK(h.metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "renew_leases"}, {"outcome", "unknown_session"}})
              .value() == 1);
}

TEST_CASE("BatchHeartbeat verdict: with no route store and no metrics the verdict is still "
          "filled for unknown, over-length and empty ids (#1197)",
          "[gateway_route_wiring]") {
    // The verdict reflects only the in-memory session map, so it must not be
    // gated on a wired GatewayRouteStore or MetricsRegistry. Non-PG: a bare
    // AuthManager is enough because nothing is registered.
    EventBus bus;
    yuzu::MetricsRegistry registry_metrics;
    AgentRegistry registry{bus, registry_metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl svc{registry, bus, auth_mgr, auto_approve, /*metrics=*/nullptr};

    const std::string too_long(kTestMaxSessionIdLen + 1, 'x');
    gw::BatchHeartbeatRequest batch;
    batch.set_gateway_node("node-hb-nostore");
    for (const auto& id : std::vector<std::string>{"gw-session-nostore-a", "gw-session-nostore-a",
                                                   "", too_long, "gw-session-nostore-b"})
        batch.add_heartbeats()->set_session_id(id);
    gw::BatchHeartbeatResponse resp;
    REQUIRE(svc.BatchHeartbeat(/*context=*/nullptr, &batch, &resp).ok());

    CHECK(resp.acknowledged_count() == 0);
    auto listed = listed_unknown(resp);
    std::sort(listed.begin(), listed.end());
    CHECK(listed == std::vector<std::string>{"gw-session-nostore-a", "gw-session-nostore-b"});
    CHECK_FALSE(resp.unknown_session_ids_truncated());
}

TEST_CASE("BatchHeartbeat verdict: with no route store a KNOWN session is still acked and the "
          "unknown one still listed (#1197)",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr; // PG only for the enrollment token; NO route store is wired
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl svc{registry, bus, auth_mgr, auto_approve, &metrics};

    auto req = make_gw_register(auth_mgr, "agent-nostore-known");
    apb::RegisterResponse reg;
    REQUIRE(svc.ProxyRegister(/*context=*/nullptr, &req, &reg).ok());

    gw::BatchHeartbeatRequest batch;
    batch.set_gateway_node("node-hb-nostore-known");
    batch.add_heartbeats()->set_session_id(reg.session_id());
    batch.add_heartbeats()->set_session_id("gw-session-nostore-unknown");
    gw::BatchHeartbeatResponse resp;
    REQUIRE(svc.BatchHeartbeat(/*context=*/nullptr, &batch, &resp).ok());

    CHECK(resp.acknowledged_count() == 1);
    CHECK(listed_unknown(resp) == std::vector<std::string>{"gw-session-nostore-unknown"});
}

// ── Fail-open posture ────────────────────────────────────────────────────────

TEST_CASE("ProxyRegister: a degraded GatewayRouteStore register_fresh write FAILS the RPC "
          "(fail-CLOSED — Task B, 4.2b)",
          "[gateway_route_wiring]") {
    // register_fresh is the ONE fail-CLOSED record_route_store_failure call
    // site (Task B, 4.2b): it CREATES the row, so a missed create must refuse
    // the registration rather than let the agent connect unrouteable.
    //
    // A deliberately unparseable conninfo makes PgPool::valid() false, so
    // GatewayRouteStore's construction-time acquire() fails FAST — no network
    // I/O at all (pg_pool.cpp: `if (!valid_) return {};`) — and the store
    // stays permanently open_==false. The write below therefore degrades
    // with store_unavailable without touching a real Postgres instance, so
    // this case runs even when YUZU_TEST_POSTGRES_DSN is unset.
    PgPool broken_pool{{.conninfo = "not a valid conninfo string ===", .size = 1}};
    GatewayRouteStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&broken_store);

    // Post-merge review #4344 follow-up (MEDIUM finding 1): before this fix, register_agent's
    // side effects (connected gauge, agent-online publish, root-group membership) survived a
    // failed register_fresh with no rollback — a contextless "ghost" AgentSession
    // (reap_stale_sessions can never TryCancel it: a gateway-proxied session carries no
    // server_context). Collect the bus events this call publishes to assert BOTH agent-online
    // (register_agent installing) AND agent-offline (the rollback tearing it back down) fire, in
    // that order.
    std::vector<std::string> events;
    auto sub = bus.subscribe([&events](const yuzu::server::detail::SseEvent& ev) {
        events.push_back(ev.event_type + ":" + ev.data);
    });

    auto req = make_gw_register(auth_mgr, "agent-failclosed-1");
    apb::RegisterResponse resp;
    auto status = gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp);
    CHECK_FALSE(status.ok()); // fail-CLOSED: register_fresh degraded, RPC refused
    CHECK(status.error_code() == grpc::StatusCode::UNAVAILABLE);
    CHECK(metrics
              .counter("yuzu_server_gateway_route_write_failed_total",
                       {{"op", "register_fresh"}, {"reason", "store_unavailable"}})
              .value() == 1);

    // The ghost-session rollback: no session left on record, the connected gauge back at 0, and
    // an agent-offline event published for the rollback (following register_agent's own
    // agent-online publish). Pre-fix, `get_session` here returned a live (if useless — no stream,
    // no session_id) AgentSession forever, and the gauge stayed at 1.
    CHECK(registry.get_session("agent-failclosed-1") == nullptr);
    CHECK(metrics.gauge("yuzu_agents_connected").value() == 0);
    REQUIRE(events.size() == 2);
    CHECK(events[0] == "agent-online:agent-failclosed-1");
    CHECK(events[1] == "agent-offline:agent-failclosed-1");

    bus.unsubscribe(sub);
}

TEST_CASE("ProxyRegister: a degraded GatewayRouteStore during the replay-ADOPT decision "
          "REFUSES the RPC (fail-CLOSED) rather than trusting an unverified session — HA WS-4 "
          "4.4 round-2 review fix (UP-4/COMP-6)",
          "[gateway_route_wiring][grpc]") {
    // UP-4 (round-2 Fable review, BLOCKING): the first cut of the ADOPT
    // decision fail-OPENED on a degraded renew_leases/reclaim_tombstoned_session
    // call (adopt=true), converting every replay in a degraded-store window
    // into an unconditional, uncheckable ADOPT — bypassing the entire
    // stale/zombie-refusal mechanism this slice exists to add, at exactly
    // the moment (fleet-wide reconnect storm stressing Postgres) a genuine
    // zombie replay is most likely. Fixed to fail-CLOSED, mirroring
    // register_fresh's own established precedent for a decision whose wrong
    // answer is more dangerous than a refusal (the row-CREATING write is
    // fail-closed for exactly the same reason).
    //
    // Same broken-pool technique as the register_fresh fail-closed test
    // above: an unparseable conninfo makes the store permanently
    // `!open_` with no network I/O, so `renew_leases`/
    // `reclaim_tombstoned_session` degrade immediately and deterministically.
    PgPool broken_pool{{.conninfo = "not a valid conninfo string ===", .size = 1}};
    GatewayRouteStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());
    // A real grpc::Server + stub is required here (unlike the register_fresh
    // test above) because reaching the replay-ADOPT branch at all needs a
    // REAL x-yuzu-session-id client_metadata() value — context=nullptr
    // always takes the fresh-registration branch (file header note).
    LiveGatewayWiringHarness h(broken_store);

    auto [status, resp] =
        h.register_agent_status("agent-degraded-store-replay", wf_sid('f'));
    CHECK_FALSE(status.ok()); // fail-CLOSED: the decision could not be verified
    CHECK(status.error_code() == grpc::StatusCode::UNAVAILABLE);
    CHECK(h.metrics
              .counter("yuzu_server_gateway_route_write_failed_total",
                       {{"op", "renew_leases"}, {"reason", "store_unavailable"}})
              .value() == 1);
    // Nothing was installed: no ghost session, no root-group membership.
    CHECK(h.registry.get_session("agent-degraded-store-replay") == nullptr);
}

TEST_CASE("AgentRegistry::remove_agent_if_same: pointer identity, not session_id, is the "
          "rollback key — a concurrent registration that already superseded the rolled-back "
          "session survives untouched (HA WS-4 4.2b follow-up, #4344 MEDIUM finding 1)",
          "[gateway_route_wiring]") {
    // Both sessions installed below have an EMPTY session_id (map_session, which only runs on a
    // live Subscribe stream, never fires here) — the exact state ProxyRegister's own `installed`
    // capture is in when a rollback would fire (register_fresh runs long before any stream is
    // established). A session_id-STRING-keyed rollback ("" == "") could not tell these two
    // sessions apart and would delete whichever is current regardless of which one the caller
    // actually meant to undo — this test's second SECTION is the case that would fail under that
    // (hypothetical, pre-fix-shaped) implementation.
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};

    apb::AgentInfo info;
    info.set_agent_id("agent-rollback-identity");
    info.set_hostname("host-1");
    info.mutable_platform()->set_os("linux");
    info.mutable_platform()->set_arch("x86_64");

    auto first = registry.register_agent(info);
    REQUIRE(first.has_value());
    auto installed_first = *first;
    REQUIRE(installed_first->session_id.empty());

    SECTION("no concurrent registration: rollback removes the session it installed") {
        registry.remove_agent_if_same("agent-rollback-identity", installed_first);
        CHECK(registry.get_session("agent-rollback-identity") == nullptr);
        CHECK(metrics.gauge("yuzu_agents_connected").value() == 0);
    }

    SECTION("a concurrent registration already superseded it: rollback is a NO-OP, the newer "
            "session survives") {
        info.set_hostname("host-2"); // distinguishes the second session for the assertion below
        auto second = registry.register_agent(info);
        REQUIRE(second.has_value());
        auto installed_second = *second;
        REQUIRE(installed_second != installed_first); // genuinely a different object
        REQUIRE(installed_second->session_id.empty()); // same empty-session_id shape as the first

        // Roll back using the FIRST call's captured pointer, exactly as ProxyRegister's
        // register_fresh-failure branch would (it only ever holds the pointer from its OWN
        // register_agent call, never a later caller's).
        registry.remove_agent_if_same("agent-rollback-identity", installed_first);

        auto current = registry.get_session("agent-rollback-identity");
        REQUIRE(current != nullptr); // NOT removed — the no-op case
        CHECK(current == installed_second); // the SECOND (still-current) session, untouched
        CHECK(current->hostname == "host-2");
        CHECK(metrics.gauge("yuzu_agents_connected").value() == 1); // still 1, not decremented
    }
}

TEST_CASE("ProxyRegister: a session that LOSES its register_fresh epoch race still leaves its "
          "OWN session installed on the registry (only the DIRECTORY row is lost, never the "
          "in-memory session — the epoch-race branch is NOT the register_fresh-FAILURE branch "
          "and must not roll anything back)",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    auto req1 = make_gw_register(auth_mgr, "agent-race-noop-rollback");
    apb::RegisterResponse resp1;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req1, &resp1).ok());
    auto row1 = store.lookup_route("agent-race-noop-rollback");
    REQUIRE(row1.has_value());
    REQUIRE(row1->has_value());

    // Force the SECOND ProxyRegister's register_fresh to lose its epoch race (see
    // raw_bump_epoch's header comment above).
    raw_bump_epoch(db.dsn(), "agent-race-noop-rollback", (*row1)->connection_epoch + 1000,
                  "gw-session-already-won");

    auto req2 = make_gw_register(auth_mgr, "agent-race-noop-rollback");
    apb::RegisterResponse resp2;
    auto status = gateway_svc.ProxyRegister(/*context=*/nullptr, &req2, &resp2);
    CHECK(status.ok()); // still OK — losing the epoch race is NOT a register_fresh failure
    CHECK(resp2.accepted());

    // The losing call's OWN session is still on the registry — `!res->won` never calls
    // remove_agent_if_same. (This is a DIFFERENT agent_id from the desync-counter race test
    // above, so this registry entry is exclusively this call's.)
    CHECK(registry.get_session("agent-race-noop-rollback") != nullptr);
    CHECK(metrics.gauge("yuzu_agents_connected").value() == 1);
}

TEST_CASE("NotifyStreamStatus: a degraded GatewayRouteStore session_lookup read still "
          "acknowledges the locally registered CONNECTED and the write stays fail-OPEN",
          "[pg][gateway_route_wiring]") {
    // A REAL store is needed first so ProxyRegister (fail-CLOSED on
    // register_fresh) succeeds and mints a session; the store is then SWAPPED
    // for a broken one so the NotifyStreamStatus session_lookup read degrades.
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    auto req = make_gw_register(auth_mgr, "agent-failopen-1");
    apb::RegisterResponse resp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());

    PgPool broken_pool{{.conninfo = "not a valid conninfo string ===", .size = 1}};
    GatewayRouteStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());
    gateway_svc.set_gateway_route_store(&broken_store);

    gw::StreamStatusNotification notif;
    notif.set_agent_id("agent-failopen-1");
    notif.set_session_id(resp.session_id());
    notif.set_event(gw::StreamStatusNotification::CONNECTED);
    gw::StreamStatusAck ack;
    auto notif_status = gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack);
    CHECK(notif_status.ok());
    // HA WS-5: the degraded session_lookup read is counted; this replica holds
    // the matching local session, so the CONNECTED proceeds and the
    // announce_connected write degrades fail-OPEN (counted once).
    CHECK(ack.acknowledged());
    CHECK(metrics
              .counter("yuzu_server_gateway_route_write_failed_total",
                       {{"op", "session_lookup"}, {"reason", "store_unavailable"}})
              .value() == 1);
    CHECK(metrics
              .counter("yuzu_server_gateway_route_write_failed_total",
                       {{"op", "announce_connected"}, {"reason", "store_unavailable"}})
              .value() == 1);
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "notify_stream_status"}, {"outcome", "connected_unverified"}})
              .value() == 0);
}

TEST_CASE("ProxyRegister: a concurrent FRESH registration completing between a REPLAY's "
          "decide-phase and its own install cannot be clobbered — HA WS-4 4.4 post-build review "
          "fix (PR #4636 FortitudeEtc BLOCKER 1): registration_lock_for serializes "
          "decide->install per agent_id, so the two can never interleave in memory and the "
          "durable store the way the finding described",
          "[pg][gateway_route_wiring][grpc]") {
    // NOTE: no Catch2 assertion macro (REQUIRE/CHECK) may run on any thread
    // other than this test's own — Catch2's assertion machinery is not
    // thread-safe. Every value the interleave hook and the spawned thread
    // below observe is captured into a plain/atomic variable and asserted
    // on ONLY after both the replay's own gRPC call (this thread, blocking
    // on the stub as usual) and t_b (joined below) have returned.
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());
    LiveGatewayWiringHarness h(store);

    auto resp_old = h.register_agent("agent-concurrent-race");
    const std::string session_old = resp_old.session_id();

    std::atomic<bool> b_finished{false};
    std::atomic<bool> b_finished_during_hook_window{false};
    std::string session_new;
    std::thread t_b;

    h.svc.set_proxy_register_interleave_hook_for_test([&] {
        // Fires INSIDE the replay's (session_old's) critical section — after
        // its decide-phase confirmed adopt via renew_leases, before
        // register_agent installs anything (the exact window BLOCKER 1
        // described). Spawn a competing FRESH registration for the SAME
        // agent_id: pre-fix, this thread would very likely install AND
        // register_fresh well within the sleep below, since nothing blocked
        // it; post-fix, it must block trying to acquire the SAME per-agent
        // mutex this call already holds, and cannot possibly finish before
        // this call's own critical section ends.
        t_b = std::thread([&] {
            auto result = h.register_agent_status("agent-concurrent-race");
            if (result.first.ok()) session_new = result.second.session_id();
            b_finished.store(true, std::memory_order_release);
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        b_finished_during_hook_window.store(b_finished.load(std::memory_order_acquire),
                                            std::memory_order_release);
    });

    auto [replay_status, replay_resp] =
        h.register_agent_status("agent-concurrent-race", session_old);
    REQUIRE(replay_status.ok());
    CHECK(replay_resp.session_id() == session_old); // adopted, not re-minted

    REQUIRE(t_b.joinable());
    t_b.join();

    // The deterministic proof: t_b could NOT complete during the 200ms the
    // replay's own critical section held the per-agent lock (its own hook's
    // sleep, executed WHILE still holding that lock).
    CHECK_FALSE(b_finished_during_hook_window.load());
    REQUIRE(b_finished.load());
    REQUIRE_FALSE(session_new.empty());
    REQUIRE(session_new != session_old);

    // Because the lock fully serializes the two calls, the fresh
    // registration's install (which necessarily ran SECOND, after the
    // replay's own install completed and released the lock) is never
    // clobbered by anything running afterward — there is nothing left to
    // interleave with. Both the in-memory registry AND the durable store
    // agree on session_new as current; pre-fix, the finding's own
    // interleaving could leave these disagreeing (store on the fresh
    // session, registry on the stale replay).
    auto home_new = h.registry.gateway_stream_home_id("agent-concurrent-race", session_new);
    CHECK(home_new.has_value());
    CHECK_FALSE(
        h.registry.gateway_stream_home_id("agent-concurrent-race", session_old).has_value());

    auto row = store.lookup_route("agent-concurrent-race");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->session_id == session_new);
}

// ── HA WS-5 (#4246 #3): durable cross-replica session resolution ─────────────
//
// A "non-owning replica" is a second GatewayUpstreamServiceImpl with its OWN
// AgentRegistry / gateway_sessions_ map but the SAME GatewayRouteStore: the
// agent's ProxyRegister ran on the OTHER replica (the fixture's `svc`), so the
// directory row exists while this replica holds no local AgentSession.

namespace {

struct NonOwningReplica {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl svc;

    NonOwningReplica(yuzu::server::auth::AuthManager& auth_mgr, GatewayRouteStore& store)
        : svc{registry, bus, auth_mgr, auto_approve, &metrics} {
        svc.set_gateway_route_store(&store);
    }

    double desync(const char* op, const char* outcome) {
        return metrics
            .counter("yuzu_server_gateway_route_desync_total", {{"op", op}, {"outcome", outcome}})
            .value();
    }
};

gw::BatchHeartbeatResponse batch_hb(GatewayUpstreamServiceImpl& svc,
                                    const std::vector<std::string>& session_ids) {
    gw::BatchHeartbeatRequest batch;
    batch.set_gateway_node("node-ws5");
    for (const auto& id : session_ids)
        batch.add_heartbeats()->set_session_id(id);
    gw::BatchHeartbeatResponse resp;
    REQUIRE(svc.BatchHeartbeat(/*context=*/nullptr, &batch, &resp).ok());
    return resp;
}

bool offline_row_present(yuzu::server::OfflineEndpointStore& s, const std::string& agent_id) {
    const auto roster = s.query_stale_within(std::chrono::hours(1));
    REQUIRE(roster.has_value()); // #5531: the read is typed; a store fault is not "absent"
    for (const auto& e : *roster)
        if (e.agent_id == agent_id)
            return true;
    return false;
}

// Cross-replica PRESENCE (query_live_ids), distinct from the roster row above:
// a graceful disconnect clears this while the roster row stays (#5678).
bool live_present(yuzu::server::OfflineEndpointStore& s, const std::string& agent_id) {
    auto r = s.query_live_ids(std::chrono::hours(1));
    REQUIRE(r.has_value());
    for (const auto& p : *r)
        if (p.agent_id == agent_id)
            return true;
    return false;
}

} // namespace

TEST_CASE("WS-5 BatchHeartbeat: a NON-OWNING replica resolves a session known only to the "
          "directory; an unknown session is still listed",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    NonOwningReplica other(owner.auth_mgr, owner.store);

    const std::string sid = owner.register_live("yuzu_test_ws5_hb_agent");
    // Precondition: the second replica holds no local session for this agent.
    REQUIRE_FALSE(other.registry.get_session("yuzu_test_ws5_hb_agent"));

    auto resp = batch_hb(other.svc, {sid, "gw-session-ws5-nobody"});
    CHECK(resp.acknowledged_count() == 1);
    // The directory-known id with no local session is listed so the gateway
    // replays it; the directory-unknown id is listed as before.
    auto listed = listed_unknown(resp);
    std::sort(listed.begin(), listed.end());
    auto want = std::vector<std::string>{sid, "gw-session-ws5-nobody"};
    std::sort(want.begin(), want.end());
    CHECK(listed == want);
    CHECK(other.desync("session_lookup", "ambiguous_session") == 0);
    // Only the directory-UNKNOWN id is a desync; the replay-listed one is not.
    CHECK(other.desync("renew_leases", "unknown_session") == 1);
}

TEST_CASE("WS-5 BatchHeartbeat: server-only restart reconcile lists the directory-known "
          "session once then the replayed ProxyRegister repopulates the local registry",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    LiveGatewayWiringHarness other(owner.store); // the restarted replica: empty local state

    const std::string agent = "yuzu_test_ws5_restart_agent";
    const std::string sid = owner.register_live(agent);
    REQUIRE(owner.store.announce_connected(agent, sid, "zone-ws5", "node-ws5", 90).has_value());
    REQUIRE_FALSE(other.registry.get_session(agent));
    auto before = owner.store.lookup_route(agent);
    REQUIRE(before.has_value());
    REQUIRE(before->has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(30));

    auto resp = batch_hb(other.svc, {sid});
    CHECK(resp.acknowledged_count() == 1);
    CHECK(listed_unknown(resp) == std::vector<std::string>{sid});
    auto after = owner.store.lookup_route(agent);
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    REQUIRE((*before)->lease_until_ms.has_value());
    REQUIRE((*after)->lease_until_ms.has_value());
    CHECK(*(*after)->lease_until_ms > *(*before)->lease_until_ms);
    CHECK((*after)->connection_epoch == (*before)->connection_epoch);

    // The gateway replays ProxyRegister carrying the listed id: adopted, no re-mint.
    auto replay = other.register_agent(agent, sid);
    CHECK(replay.session_id() == sid);
    CHECK(other.registry.get_session(agent));

    auto resp2 = batch_hb(other.svc, {sid});
    CHECK(resp2.acknowledged_count() == 1);
    CHECK(listed_unknown(resp2).empty());
}

TEST_CASE("WS-5 BatchHeartbeat: a non-owning replica threads the directory-resolved session id "
          "into the presence row",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    NonOwningReplica other(owner.auth_mgr, owner.store);
    yuzu::server::OfflineEndpointStore offline{owner.pool};
    REQUIRE(offline.is_open());
    yuzu::server::HeartbeatIngestion ingestion{other.registry, nullptr, nullptr, &other.metrics,
                                               &offline};
    other.svc.set_heartbeat_ingestion(&ingestion);

    const std::string agent = "yuzu_test_ws5_hb_presence";
    const std::string sid = owner.register_live(agent);

    auto resp = batch_hb(other.svc, {sid});
    CHECK(resp.acknowledged_count() == 1);
    // The presence row exists (this replica has no local session) and carries
    // the resolved session id, so the session-guarded clear matches it.
    CHECK(offline_row_present(offline, agent));
    CHECK(offline.remove_if_session(agent, sid));
}

TEST_CASE("WS-5 BatchHeartbeat: a session id carried by TWO directory rows is refused "
          "and counted and neither acked nor listed unknown",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    NonOwningReplica other(owner.auth_mgr, owner.store);

    const std::string sid1 = owner.register_live("yuzu_test_ws5_dup_a");
    (void)owner.register_live("yuzu_test_ws5_dup_b");
    auto row_b = owner.store.lookup_route("yuzu_test_ws5_dup_b");
    REQUIRE(row_b.has_value());
    REQUIRE(row_b->has_value());
    // Force the duplicate: agent b's row now carries agent a's session id. The
    // v5 unique index would refuse it, so model a hand-dropped index by dropping
    // it (defense-in-depth: the ambiguity refusal must keep working).
    raw_exec(db.dsn(), "DROP INDEX gateway_route_store.ux_agent_routes_session_id");
    raw_bump_epoch(db.dsn(), "yuzu_test_ws5_dup_b", (*row_b)->connection_epoch + 1, sid1);

    auto resp = batch_hb(other.svc, {sid1});
    CHECK(resp.acknowledged_count() == 0);
    CHECK(listed_unknown(resp).empty()); // listing would make the gateway re-register
    CHECK(other.desync("session_lookup", "ambiguous_session") == 1);

    // Ambiguity is refused even on the replica that DOES hold sid1 locally.
    auto resp_owner = batch_hb(owner.svc, {sid1});
    CHECK(resp_owner.acknowledged_count() == 0);
    CHECK(listed_unknown(resp_owner).empty());
    CHECK(owner.desync("session_lookup", "ambiguous_session") == 1);
}

TEST_CASE("WS-5 BatchHeartbeat: a degraded directory acks locally-resolvable entries and never "
          "lists degraded-unresolved sessions unknown and still returns OK",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    const std::string sid_local = owner.register_live("yuzu_test_ws5_degr_local");

    PgPool broken_pool{{.conninfo = "not a valid conninfo string ===", .size = 1}};
    GatewayRouteStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());
    owner.svc.set_gateway_route_store(&broken_store);

    // sid_local is in this replica's local hint map; the other id is
    // "cannot tell", NOT "unknown".
    auto resp = batch_hb(owner.svc, {sid_local, "gw-session-ws5-degraded-other"});
    CHECK(resp.acknowledged_count() == 1);
    CHECK(listed_unknown(resp).empty());
    // The hinted renewal also failed (the whole store is down), so the batch is
    // not counted as a degraded renewal.
    CHECK(owner.metrics
              .counter("yuzu_server_gateway_route_degraded_renewal_total",
                       {{"op", "batch_heartbeat"}})
              .value() == 0);
    CHECK(owner.metrics
              .counter("yuzu_server_gateway_route_write_failed_total",
                       {{"op", "renew_leases"}, {"reason", "store_unavailable"}})
              .value() == 1);
    CHECK(owner.metrics
              .counter("yuzu_server_gateway_route_write_failed_total",
                       {{"op", "session_lookup"}, {"reason", "store_unavailable"}})
              .value() == 1);
}

TEST_CASE("WS-5 BatchHeartbeat: a degraded directory read still renews the locally hinted pair "
          "and never an unhinted one",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    NonOwningReplica other(owner.auth_mgr, owner.store);

    const std::string hinted_agent = "yuzu_test_ws5_degr_renew_hinted";
    const std::string unhinted_agent = "yuzu_test_ws5_degr_renew_unhinted";
    const std::string sid_hinted = owner.register_live(hinted_agent);
    std::string sid_unhinted;
    {
        auto req = make_gw_register(owner.auth_mgr, unhinted_agent);
        apb::RegisterResponse rr;
        REQUIRE(other.svc.ProxyRegister(/*context=*/nullptr, &req, &rr).ok());
        sid_unhinted = rr.session_id();
    }
    REQUIRE(owner.store.announce_connected(hinted_agent, sid_hinted, "zone", "node", 90).has_value());
    REQUIRE(owner.store.announce_connected(unhinted_agent, sid_unhinted, "zone", "node", 90)
                .has_value());
    auto lease_of = [&](const std::string& agent) {
        auto r = owner.store.lookup_route(agent);
        REQUIRE(r.has_value());
        REQUIRE(r->has_value());
        REQUIRE((*r)->lease_until_ms.has_value());
        return *(*r)->lease_until_ms;
    };
    const auto hinted_before = lease_of(hinted_agent);
    const auto unhinted_before = lease_of(unhinted_agent);
    std::this_thread::sleep_for(std::chrono::milliseconds(30));

    {
        ScopedReadBreak broken(db.dsn());
        auto resp = batch_hb(owner.svc, {sid_hinted, sid_unhinted});
        CHECK(resp.acknowledged_count() == 1);
        CHECK(listed_unknown(resp).empty());
        CHECK(owner.metrics
                  .counter("yuzu_server_gateway_route_degraded_renewal_total",
                           {{"op", "batch_heartbeat"}})
                  .value() == 1);
        CHECK(owner.metrics
                  .counter("yuzu_server_gateway_route_write_failed_total",
                           {{"op", "session_lookup"}, {"reason", "db_error"}})
                  .value() == 1);
    }
    CHECK(lease_of(hinted_agent) > hinted_before);
    CHECK(lease_of(unhinted_agent) == unhinted_before);
}

TEST_CASE("WS-5 ProxyInventory: a non-owning replica accepts a directory-known session; "
          "an unknown session still gets received=false",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    NonOwningReplica other(owner.auth_mgr, owner.store);

    const std::string sid = owner.register_live("yuzu_test_ws5_inv_agent");

    apb::InventoryReport known;
    known.set_session_id(sid);
    apb::InventoryAck ack_known;
    REQUIRE(other.svc.ProxyInventory(/*context=*/nullptr, &known, &ack_known).ok());
    CHECK(ack_known.received());
    CHECK(other.desync("proxy_inventory", "unknown_session") == 0);

    apb::InventoryReport unknown;
    unknown.set_session_id("gw-session-ws5-inv-nobody");
    apb::InventoryAck ack_unknown;
    REQUIRE(other.svc.ProxyInventory(/*context=*/nullptr, &unknown, &ack_unknown).ok());
    CHECK_FALSE(ack_unknown.received());
    CHECK(other.desync("proxy_inventory", "unknown_session") == 1);
}

TEST_CASE("WS-5 ProxyInventory: a degraded directory answers received=false (retryable) and is "
          "not counted as an unknown_session desync",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    NonOwningReplica other(owner.auth_mgr, owner.store);
    const std::string sid = owner.register_live("yuzu_test_ws5_inv_degraded");

    PgPool broken_pool{{.conninfo = "not a valid conninfo string ===", .size = 1}};
    GatewayRouteStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());
    other.svc.set_gateway_route_store(&broken_store);

    apb::InventoryReport rpt;
    rpt.set_session_id(sid);
    apb::InventoryAck ack;
    REQUIRE(other.svc.ProxyInventory(/*context=*/nullptr, &rpt, &ack).ok());
    CHECK_FALSE(ack.received());
    CHECK(other.desync("proxy_inventory", "unknown_session") == 0);
    CHECK(other.metrics
              .counter("yuzu_server_gateway_route_write_failed_total",
                       {{"op", "session_lookup"}, {"reason", "store_unavailable"}})
              .value() == 1);
}

TEST_CASE("WS-5 NotifyStreamStatus: CONNECTED on a replica with a directory row but NO local "
          "session is acknowledged and announces placement (no stale_connected_session desync)",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    NonOwningReplica other(owner.auth_mgr, owner.store);

    const std::string agent = "yuzu_test_ws5_conn_agent";
    const std::string sid = owner.register_live(agent);
    REQUIRE_FALSE(other.registry.get_session(agent));

    gw::StreamStatusNotification notif;
    notif.set_agent_id(agent);
    notif.set_session_id(sid);
    notif.set_event(gw::StreamStatusNotification::CONNECTED);
    notif.set_cluster_id("cluster-ws5");
    notif.set_gateway_node("node-ws5");
    gw::StreamStatusAck ack;
    REQUIRE(other.svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack).ok());
    CHECK(ack.acknowledged());
    CHECK(other.desync("notify_stream_status", "stale_connected_session") == 0);
    CHECK(other.desync("notify_stream_status", "unknown_session") == 0);

    auto row = owner.store.lookup_route(agent);
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->cluster_id == "cluster-ws5");
    CHECK((*row)->gateway_node == "node-ws5");
    // The non-owning replica did not publish into a local registry entry.
    CHECK_FALSE(other.registry.get_session(agent));
}

TEST_CASE("WS-5 NotifyStreamStatus: a session_id that does not match the directory row is "
          "rejected and leaves the row untouched",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    NonOwningReplica other(owner.auth_mgr, owner.store);

    const std::string agent = "yuzu_test_ws5_mismatch_agent";
    (void)owner.register_live(agent);

    gw::StreamStatusNotification notif;
    notif.set_agent_id(agent);
    notif.set_session_id("gw-session-ws5-not-the-row");
    notif.set_event(gw::StreamStatusNotification::CONNECTED);
    notif.set_cluster_id("cluster-rogue");
    notif.set_gateway_node("node-rogue");
    gw::StreamStatusAck ack;
    REQUIRE(other.svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack).ok());
    CHECK_FALSE(ack.acknowledged());
    CHECK(other.desync("notify_stream_status", "unknown_session") == 1);

    auto row = owner.store.lookup_route(agent);
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK_FALSE((*row)->cluster_id.has_value()); // rogue placement never landed
}

TEST_CASE("WS-5 NotifyStreamStatus: a degraded directory read with no local session refuses "
          "CONNECTED as connected_unverified and is counted under op=session_lookup",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    NonOwningReplica other(owner.auth_mgr, owner.store);
    const std::string agent = "yuzu_test_ws5_notify_degraded";
    const std::string sid = owner.register_live(agent);

    PgPool broken_pool{{.conninfo = "not a valid conninfo string ===", .size = 1}};
    GatewayRouteStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());
    other.svc.set_gateway_route_store(&broken_store);

    gw::StreamStatusNotification notif;
    notif.set_agent_id(agent);
    notif.set_session_id(sid);
    notif.set_event(gw::StreamStatusNotification::CONNECTED);
    gw::StreamStatusAck ack;
    REQUIRE(other.svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack).ok());
    CHECK_FALSE(ack.acknowledged());
    CHECK(other.desync("notify_stream_status", "connected_unverified") == 1);
    CHECK(other.desync("notify_stream_status", "unknown_session") == 0);
    CHECK(other.metrics
              .counter("yuzu_server_gateway_route_write_failed_total",
                       {{"op", "session_lookup"}, {"reason", "store_unavailable"}})
              .value() == 1);
}

TEST_CASE("WS-5 NotifyStreamStatus: a degraded directory read still acknowledges CONNECTED for "
          "the session this replica registered and publishes its placement",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    const std::string agent = "yuzu_test_ws5_conn_degraded_local";
    const std::string sid = owner.register_live(agent);

    gw::StreamStatusNotification notif;
    notif.set_agent_id(agent);
    notif.set_session_id(sid);
    notif.set_event(gw::StreamStatusNotification::CONNECTED);
    notif.set_cluster_id("cluster-ws5");
    notif.set_gateway_node("node-ws5-degraded");
    notif.add_wire_capabilities("cap-ws5-degraded");
    gw::StreamStatusAck ack;
    {
        ScopedReadBreak broken(db.dsn());
        REQUIRE(owner.svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack).ok());
    }
    CHECK(ack.acknowledged());
    CHECK(owner.desync("notify_stream_status", "connected_unverified") == 0);
    CHECK(owner.desync("notify_stream_status", "stale_connected_session") == 0);
    CHECK(owner.metrics
              .counter("yuzu_server_gateway_route_write_failed_total",
                       {{"op", "session_lookup"}, {"reason", "db_error"}})
              .value() == 1);
    auto sess = owner.registry.get_session(agent);
    REQUIRE(sess);
    {
        std::lock_guard lk(sess->stream_mu);
        CHECK(sess->gateway_node == "node-ws5-degraded");
    }
    CHECK(owner.registry.gateway_has_wire_capability(agent, "cap-ws5-degraded"));
}

TEST_CASE("WS-5 NotifyStreamStatus: DISCONNECTED on a non-owning replica tombstones the "
          "directory row and clears presence (row kept for the roster) on the directory's proof alone",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    NonOwningReplica other(owner.auth_mgr, owner.store);
    yuzu::server::OfflineEndpointStore offline{owner.pool};
    REQUIRE(offline.is_open());
    yuzu::server::HeartbeatIngestion ingestion{other.registry, nullptr, nullptr, &other.metrics,
                                               &offline};
    other.svc.set_heartbeat_ingestion(&ingestion);

    const std::string agent = "yuzu_test_ws5_disc_agent";
    const std::string sid = owner.register_live(agent);
    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    REQUIRE(offline.upsert(agent, "h", "linux", now_ms, 0, "", "", sid));
    REQUIRE(offline_row_present(offline, agent));

    gw::StreamStatusNotification notif;
    notif.set_agent_id(agent);
    notif.set_session_id(sid);
    notif.set_event(gw::StreamStatusNotification::DISCONNECTED);
    gw::StreamStatusAck ack;
    REQUIRE(other.svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack).ok());
    CHECK(ack.acknowledged());

    auto row = owner.store.lookup_route(agent);
    REQUIRE(row.has_value());
    REQUIRE(row->has_value()); // tombstone, not gone
    CHECK_FALSE((*row)->session_id.has_value());
    CHECK(offline_row_present(offline, agent));
    CHECK_FALSE(live_present(offline, agent));
}

namespace {

bool notify(GatewayUpstreamServiceImpl& svc, const std::string& agent, const std::string& sid,
            gw::StreamStatusNotification::Event event) {
    gw::StreamStatusNotification notif;
    notif.set_agent_id(agent);
    notif.set_session_id(sid);
    notif.set_event(event);
    if (event == gw::StreamStatusNotification::CONNECTED) {
        notif.set_cluster_id("zone-ws5");
        notif.set_gateway_node("node-ws5");
    }
    gw::StreamStatusAck ack;
    REQUIRE(svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack).ok());
    return ack.acknowledged();
}

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string presence_hostname(yuzu::server::OfflineEndpointStore& s, const std::string& agent_id) {
    const auto roster = s.query_stale_within(std::chrono::hours(1));
    REQUIRE(roster.has_value()); // #5531: the read is typed; a store fault is not "absent"
    for (const auto& e : *roster)
        if (e.agent_id == agent_id)
            return e.hostname;
    return {};
}

} // namespace

TEST_CASE("WS-5 NotifyStreamStatus: a superseded session is refused CONNECTED and its "
          "DISCONNECTED leaves the live presence row and directory row alone",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    yuzu::server::OfflineEndpointStore offline{owner.pool};
    REQUIRE(offline.is_open());
    yuzu::server::HeartbeatIngestion ingestion{owner.registry, nullptr, nullptr, &owner.metrics,
                                               &offline};
    owner.svc.set_heartbeat_ingestion(&ingestion);

    const std::string agent = "yuzu_test_ws5_superseded";
    const std::string stale = owner.register_live(agent);
    const std::string winner = wf_sid('9');
    auto row = owner.store.lookup_route(agent);
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    raw_bump_epoch(db.dsn(), agent, (*row)->connection_epoch + 1000, winner);
    REQUIRE(offline.upsert(agent, "h", "linux", now_ms(), 0, "", "", winner));

    CHECK_FALSE(notify(owner.svc, agent, stale, gw::StreamStatusNotification::CONNECTED));
    CHECK(owner.desync("notify_stream_status", "stale_connected_session") == 1);
    auto after_connect = owner.store.lookup_route(agent);
    REQUIRE(after_connect.has_value());
    REQUIRE(after_connect->has_value());
    CHECK((*after_connect)->session_id == winner);

    CHECK(notify(owner.svc, agent, stale, gw::StreamStatusNotification::DISCONNECTED));
    CHECK(owner.desync("deregister", "session_mismatch") == 1);
    auto after_disc = owner.store.lookup_route(agent);
    REQUIRE(after_disc.has_value());
    REQUIRE(after_disc->has_value());
    CHECK((*after_disc)->session_id == winner);
    CHECK(offline_row_present(offline, agent));
    CHECK(live_present(offline, agent)); // the stale DISCONNECTED must not clear the winner's presence
    CHECK_FALSE(owner.registry.get_session(agent));
}

TEST_CASE("WS-5 NotifyStreamStatus: the presence clear gate honours each half separately",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    yuzu::server::OfflineEndpointStore offline{owner.pool};
    REQUIRE(offline.is_open());
    yuzu::server::HeartbeatIngestion ingestion{owner.registry, nullptr, nullptr, &owner.metrics,
                                               &offline};
    owner.svc.set_heartbeat_ingestion(&ingestion);

    SECTION("local half: the registry held the session so its presence is cleared (row kept)") {
        const std::string agent = "yuzu_test_ws5_gate_local";
        const std::string sid = owner.register_live(agent);
        auto row = owner.store.lookup_route(agent);
        REQUIRE(row.has_value());
        REQUIRE(row->has_value());
        raw_bump_epoch(db.dsn(), agent, (*row)->connection_epoch + 1000, wf_sid('8'));
        REQUIRE(offline.upsert(agent, "h", "linux", now_ms(), 0, "", "", sid));

        CHECK(notify(owner.svc, agent, sid, gw::StreamStatusNotification::DISCONNECTED));
        CHECK(owner.desync("deregister", "session_mismatch") == 1);
        CHECK(offline_row_present(offline, agent));
        CHECK_FALSE(live_present(offline, agent));
    }

    SECTION("neither half: no local session and a directory mismatch leaves the presence row") {
        const std::string agent = "yuzu_test_ws5_gate_neither";
        const std::string sid = owner.register_live(agent);
        auto row = owner.store.lookup_route(agent);
        REQUIRE(row.has_value());
        REQUIRE(row->has_value());
        raw_bump_epoch(db.dsn(), agent, (*row)->connection_epoch + 1000, wf_sid('8'));
        owner.registry.remove_agent(agent);
        REQUIRE(offline.upsert(agent, "h", "linux", now_ms(), 0, "", "", sid));

        CHECK(notify(owner.svc, agent, sid, gw::StreamStatusNotification::DISCONNECTED));
        CHECK(owner.desync("deregister", "session_mismatch") == 1);
        CHECK(offline_row_present(offline, agent));
        CHECK(live_present(offline, agent)); // neither half fired: presence is untouched
    }
}

TEST_CASE("WS-5 NotifyStreamStatus: a degraded directory read lets CONNECTED and DISCONNECTED "
          "proceed for the session this replica registered",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    const std::string agent = "yuzu_test_ws5_notify_degraded_local";
    const std::string sid = owner.register_live(agent);
    REQUIRE(owner.registry.get_session(agent));

    PgPool broken_pool{{.conninfo = "not a valid conninfo string ===", .size = 1}};
    GatewayRouteStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());
    owner.svc.set_gateway_route_store(&broken_store);

    CHECK(notify(owner.svc, agent, sid, gw::StreamStatusNotification::CONNECTED));
    CHECK(owner.desync("notify_stream_status", "connected_unverified") == 0);
    CHECK(owner.registry.get_session(agent));

    CHECK(notify(owner.svc, agent, sid, gw::StreamStatusNotification::DISCONNECTED));
    CHECK_FALSE(owner.registry.get_session(agent));
    CHECK(owner.metrics
              .counter("yuzu_server_gateway_route_write_failed_total",
                       {{"op", "session_lookup"}, {"reason", "store_unavailable"}})
              .value() >= 1);
}

TEST_CASE("WS-5 ProxyInventory: a degraded read with a local hint still ingests and an "
          "ambiguous session is refused",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());

    SECTION("degraded with a local hint") {
        const std::string sid = owner.register_live("yuzu_test_ws5_inv_hint");
        PgPool broken_pool{{.conninfo = "not a valid conninfo string ===", .size = 1}};
        GatewayRouteStore broken_store{broken_pool};
        REQUIRE_FALSE(broken_store.is_open());
        owner.svc.set_gateway_route_store(&broken_store);

        apb::InventoryReport rpt;
        rpt.set_session_id(sid);
        apb::InventoryAck ack;
        REQUIRE(owner.svc.ProxyInventory(/*context=*/nullptr, &rpt, &ack).ok());
        CHECK(ack.received());
    }

    SECTION("ambiguous session") {
        const std::string sid1 = owner.register_live("yuzu_test_ws5_inv_amb_a");
        (void)owner.register_live("yuzu_test_ws5_inv_amb_b");
        auto row_b = owner.store.lookup_route("yuzu_test_ws5_inv_amb_b");
        REQUIRE(row_b.has_value());
        REQUIRE(row_b->has_value());
        raw_exec(db.dsn(), "DROP INDEX gateway_route_store.ux_agent_routes_session_id");
        raw_bump_epoch(db.dsn(), "yuzu_test_ws5_inv_amb_b", (*row_b)->connection_epoch + 1, sid1);

        apb::InventoryReport rpt;
        rpt.set_session_id(sid1);
        apb::InventoryAck ack;
        REQUIRE(owner.svc.ProxyInventory(/*context=*/nullptr, &rpt, &ack).ok());
        CHECK_FALSE(ack.received());
        CHECK(owner.desync("session_lookup", "ambiguous_session") == 1);
    }
}

TEST_CASE("#5683 ProxyRegister: racing replay adopts of one unheld id by two agents land "
          "exactly once over gRPC",
          "[pg][gateway_route_wiring][ws5][unique_session]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    LiveGatewayWiringHarness harness(owner.store);

    constexpr int kPairs = 40;
    int bad_pairs = 0;
    int doubles = 0;
    for (int i = 0; i < kPairs; ++i) {
        char hex[40];
        std::snprintf(hex, sizeof(hex), "%032x", 0x5683u + static_cast<unsigned>(i));
        const std::string sid = std::string("gw-session-") + hex;
        const std::string a = "yuzu_test_us_grpc_a" + std::to_string(i);
        const std::string b = "yuzu_test_us_grpc_b" + std::to_string(i);
        auto req_a = make_gw_register(harness.auth_mgr, a);
        auto req_b = make_gw_register(harness.auth_mgr, b);

        std::atomic<bool> go{false};
        grpc::Status status_a;
        grpc::Status status_b;
        auto call = [&](const apb::RegisterRequest& req, grpc::Status& out) {
            grpc::ClientContext ctx;
            ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(10));
            ctx.AddMetadata(std::string(AgentServiceImpl::kSessionMetadataKey), sid);
            apb::RegisterResponse resp;
            while (!go.load(std::memory_order_acquire))
                std::this_thread::yield();
            out = harness.stub_->ProxyRegister(&ctx, req, &resp);
        };
        std::thread ta(call, std::cref(req_a), std::ref(status_a));
        std::thread tb(call, std::cref(req_b), std::ref(status_b));
        // Declared AFTER the threads: on any unwind the release flag is set
        // first (so a spinning thread can finish), then both are joined. A
        // plain std::thread plus guards, not std::jthread (Apple libc++ has
        // none); a throwing REQUIRE would otherwise destroy a joinable thread.
        struct JoinGuard {
            std::thread& t;
            ~JoinGuard() {
                if (t.joinable())
                    t.join();
            }
        } join_a{ta}, join_b{tb};
        struct ReleaseOnExit {
            std::atomic<bool>& flag;
            ~ReleaseOnExit() { flag.store(true, std::memory_order_release); }
        } release_on_exit{go};
        go.store(true, std::memory_order_release);
        ta.join();
        tb.join();

        const int ok = status_a.ok() + status_b.ok();
        const int refused = (status_a.error_code() == grpc::StatusCode::FAILED_PRECONDITION) +
                            (status_b.error_code() == grpc::StatusCode::FAILED_PRECONDITION);
        if (ok != 1 || refused != 1)
            ++bad_pairs;

        pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult r{PQexec(conn.get(),
                              ("SELECT count(*) FROM gateway_route_store.agent_routes "
                               "WHERE session_id = '" + sid + "'").c_str())};
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        if (std::stoi(PQgetvalue(r.get(), 0, 0)) > 1)
            ++doubles;
    }
    CHECK(doubles == 0);
    CHECK(bad_pairs == 0);
}

TEST_CASE("#5683 NotifyStreamStatus CONNECTED: a fallback insert refused by the unique session "
          "index unpublishes the placement and is counted and audited",
          "[pg][gateway_route_wiring][ws5][unique_session]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());
    yuzu::server::AuditStore audit{pool};
    REQUIRE(audit.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl svc{registry, bus, auth_mgr, auto_approve, &metrics};
    svc.set_gateway_route_store(&store);
    svc.set_audit_store(&audit);

    auto req_a = make_gw_register(auth_mgr, "yuzu_test_us_ntf_a");
    auto req_b = make_gw_register(auth_mgr, "yuzu_test_us_ntf_b");
    apb::RegisterResponse resp_a;
    apb::RegisterResponse resp_b;
    REQUIRE(svc.ProxyRegister(/*context=*/nullptr, &req_a, &resp_a).ok());
    REQUIRE(svc.ProxyRegister(/*context=*/nullptr, &req_b, &resp_b).ok());
    const std::string sid_b = resp_b.session_id();

    // b's row is gone (purged) while its local session lives; a's row now
    // carries b's session id, so b's fallback insert collides on the index.
    raw_exec(db.dsn(), "DELETE FROM gateway_route_store.agent_routes "
                       "WHERE agent_id = 'yuzu_test_us_ntf_b'");
    raw_bump_epoch(db.dsn(), "yuzu_test_us_ntf_a", 7, sid_b);

    gw::StreamStatusNotification notif;
    notif.set_agent_id("yuzu_test_us_ntf_b");
    notif.set_session_id(sid_b);
    notif.set_event(gw::StreamStatusNotification::CONNECTED);
    notif.set_cluster_id("cluster-us");
    notif.set_gateway_node("node-us");
    notif.add_wire_capabilities("cap-us");
    gw::StreamStatusAck ack;
    yuzu::test::LogCapture capture;
    REQUIRE(svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack).ok());
    capture.stop();

    // A refused CONNECTED is not acknowledged and must not log the common-tail
    // "stream CONNECTED" line for a stream the directory just refused.
    CHECK_FALSE(ack.acknowledged());
    CHECK(capture.text().find("stream CONNECTED") == std::string::npos);
    CHECK(capture.text().find("that another agent's route already holds (#5683)") !=
          std::string::npos);

    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "announce_connected"}, {"outcome", "session_held_by_other_agent"}})
              .value() == 1);
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "announce_connected"}, {"outcome", "session_mismatch"}})
              .value() == 0);
    CHECK_FALSE(registry.gateway_has_wire_capability("yuzu_test_us_ntf_b", "cap-us"));
    auto row_b = store.lookup_route("yuzu_test_us_ntf_b");
    REQUIRE(row_b.has_value());
    CHECK_FALSE(row_b->has_value());

    auto rows = audit.query({});
    REQUIRE(rows.has_value());
    auto it = std::ranges::find_if(*rows, [](const auto& r) {
        return r.action == "gateway.session_held_by_other_agent";
    });
    REQUIRE(it != rows->end());
    CHECK(it->target_id == "yuzu_test_us_ntf_b");
    CHECK(it->result == "failure");
    CHECK(it->detail.find(sid_b) == std::string::npos);
}

// UP-2 / CH-1 pin: the CONNECTED refusal only covers a presenter with NO directory row.
// A presenter whose row still exists (here a tombstone: session NULL) hits the fallback
// INSERT's ON CONFLICT (agent_id) DO NOTHING arbiter before the unique index can fire, so the
// CONNECTED lands as session_mismatch and the in-memory placement stays published. That is
// the documented tombstoned-victim residual (ADR-2002 7f "Still open", #5685 area), pinned
// here so the narrowed doc claim (gateway.md, the alert, the changelog) stays true.
TEST_CASE("#5683 NotifyStreamStatus CONNECTED: a presenter with a tombstoned row for an id "
          "another agent holds is a session_mismatch and not a held_by_other_agent refusal",
          "[pg][gateway_route_wiring][ws5][unique_session]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl svc{registry, bus, auth_mgr, auto_approve, &metrics};
    svc.set_gateway_route_store(&store);

    auto req_y = make_gw_register(auth_mgr, "yuzu_test_us_tomb_y");
    auto req_x = make_gw_register(auth_mgr, "yuzu_test_us_tomb_x");
    apb::RegisterResponse resp_y;
    apb::RegisterResponse resp_x;
    REQUIRE(svc.ProxyRegister(/*context=*/nullptr, &req_y, &resp_y).ok());
    REQUIRE(svc.ProxyRegister(/*context=*/nullptr, &req_x, &resp_x).ok());
    const std::string sid_x = resp_x.session_id();

    // X's row becomes a tombstone (session NULL) while its local session lives,
    // and Y's row now carries X's session id.
    raw_exec(db.dsn(), "UPDATE gateway_route_store.agent_routes SET session_id = NULL, "
                       "lease_until = NULL WHERE agent_id = 'yuzu_test_us_tomb_x'");
    raw_bump_epoch(db.dsn(), "yuzu_test_us_tomb_y", 7, sid_x);

    gw::StreamStatusNotification notif;
    notif.set_agent_id("yuzu_test_us_tomb_x");
    notif.set_session_id(sid_x);
    notif.set_event(gw::StreamStatusNotification::CONNECTED);
    notif.set_cluster_id("cluster-us");
    notif.set_gateway_node("node-us");
    notif.add_wire_capabilities("cap-us");
    gw::StreamStatusAck ack;
    REQUIRE(svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack).ok());

    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "announce_connected"}, {"outcome", "session_mismatch"}})
              .value() == 1);
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "announce_connected"}, {"outcome", "session_held_by_other_agent"}})
              .value() == 0);
    // Not unpublished: the residual (a CONNECTED for a presenter that still has a row).
    CHECK(registry.gateway_has_wire_capability("yuzu_test_us_tomb_x", "cap-us"));
}

// qe-F1: the new desync label value is pre-seeded at construction (a rate() over a series
// that does not exist yet is silent), so a fresh service already serialises it at 0.
TEST_CASE("GatewayUpstreamServiceImpl: the #5683 desync series exists before any traffic",
          "[pg][gateway_route_wiring][ws5][unique_session]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture f(db.dsn());
    // Deliberately no metrics.counter() for this series before serialising: that call
    // would create it and make the assertion vacuous.
    const std::string text = f.metrics.serialize();
    CHECK(text.find("yuzu_server_gateway_route_desync_total{op=\"announce_connected\","
                    "outcome=\"session_held_by_other_agent\"} 0") != std::string::npos);
    CHECK(text.find("yuzu_server_gateway_route_desync_total{op=\"proxy_register\","
                    "outcome=\"session_held_by_other_agent\"} 0") != std::string::npos);
}

TEST_CASE("WS-5 ProxyRegister: an attacker presenting a victim's session id is refused and the "
          "victim's lease keeps renewing",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    const std::string victim = "yuzu_test_ws5_victim";
    const std::string victim_sid = owner.register_live(victim);
    REQUIRE(owner.store.announce_connected(victim, victim_sid, "zone-ws5", "node-ws5", 90)
                .has_value());
    auto lease_of = [&](const std::string& agent) {
        auto r = owner.store.lookup_route(agent);
        REQUIRE(r.has_value());
        REQUIRE(r->has_value());
        return (*r)->lease_until_ms;
    };
    const auto before = lease_of(victim);
    const std::string attacker = "yuzu_test_ws5_attacker";
    bool attacker_holds_tombstone = false;

    SECTION("the attacker has no row of its own") {}
    SECTION("the attacker holds its own tombstoned row") {
        const std::string own = owner.register_live(attacker);
        REQUIRE(owner.store.deregister(attacker, own).value().removed);
        attacker_holds_tombstone = true;
    }

    LiveGatewayWiringHarness attacker_side(owner.store);
    auto [status, resp] = attacker_side.register_agent_status(attacker, victim_sid);
    CHECK(status.error_code() == grpc::StatusCode::FAILED_PRECONDITION);
    CHECK(attacker_side.metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "proxy_register"}, {"outcome", "session_held_by_other_agent"}})
              .value() == 1);
    CHECK(attacker_side.metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "proxy_register"}, {"outcome", "session_superseded"}})
              .value() == 0);
    auto attacker_row = owner.store.lookup_route(attacker);
    REQUIRE(attacker_row.has_value());
    if (attacker_holds_tombstone) {
        REQUIRE(attacker_row->has_value());
        CHECK_FALSE((*attacker_row)->session_id.has_value());
    } else {
        CHECK_FALSE(attacker_row->has_value());
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    auto hb = batch_hb(owner.svc, {victim_sid});
    CHECK(hb.acknowledged_count() == 1);
    CHECK(hb.unknown_session_ids_size() == 0);
    CHECK(lease_of(victim) > before);
    CHECK(owner.desync("session_lookup", "ambiguous_session") == 0);
}

TEST_CASE("WS-5 BatchHeartbeat: a directory with no row for the session lists it even when a "
          "stale local hint exists and writes no presence row",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    yuzu::server::OfflineEndpointStore offline{owner.pool};
    REQUIRE(offline.is_open());
    yuzu::server::HeartbeatIngestion ingestion{owner.registry, nullptr, nullptr, &owner.metrics,
                                               &offline};
    owner.svc.set_heartbeat_ingestion(&ingestion);

    const std::string agent = "yuzu_test_ws5_norow";
    const std::string sid = owner.register_live(agent);
    raw_exec(db.dsn(),
             "DELETE FROM gateway_route_store.agent_routes WHERE agent_id='yuzu_test_ws5_norow'");

    auto resp = batch_hb(owner.svc, {sid});
    CHECK(resp.acknowledged_count() == 0);
    CHECK(listed_unknown(resp) == std::vector<std::string>{sid});
    CHECK(owner.desync("renew_leases", "unknown_session") == 1);
    CHECK_FALSE(offline_row_present(offline, agent));

    apb::InventoryReport rpt;
    rpt.set_session_id(sid);
    apb::InventoryAck ack;
    REQUIRE(owner.svc.ProxyInventory(/*context=*/nullptr, &rpt, &ack).ok());
    CHECK_FALSE(ack.received());
}

TEST_CASE("WS-5 BatchHeartbeat: a lost-race session never overrides the presence row's local "
          "session id",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture f(db.dsn());
    yuzu::server::OfflineEndpointStore offline{f.pool};
    REQUIRE(offline.is_open());
    yuzu::server::HeartbeatIngestion ingestion{f.registry, nullptr, nullptr, &f.metrics, &offline};
    f.svc.set_heartbeat_ingestion(&ingestion);

    const std::string agent = "yuzu_test_ws5_lostrace_presence";
    f.register_live(agent);
    auto row = f.store.lookup_route(agent);
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    const std::string winning = wf_sid('7');
    raw_bump_epoch(db.dsn(), agent, (*row)->connection_epoch + 1000, winning);
    const std::string losing = f.register_live(agent);

    auto resp = batch_hb(f.svc, {losing});
    CHECK(resp.unknown_session_ids_size() == 0);
    REQUIRE(offline_row_present(offline, agent));
    CHECK_FALSE(offline.remove_if_session(agent, winning));
    CHECK(offline_row_present(offline, agent));
    CHECK(offline.remove_if_session(agent, losing));
}

TEST_CASE("WS-5 BatchHeartbeat: reaching the lost-race bound clears the set so an evicted "
          "lost-race session is listed for replay",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture f(db.dsn());
    f.svc.set_max_lost_race_sessions_for_test(1);

    auto lose_race = [&](const std::string& agent, char winner_hex) {
        f.register_live(agent);
        auto row = f.store.lookup_route(agent);
        REQUIRE(row.has_value());
        REQUIRE(row->has_value());
        raw_bump_epoch(db.dsn(), agent, (*row)->connection_epoch + 1000, wf_sid(winner_hex));
        return f.register_live(agent);
    };

    const std::string first = lose_race("yuzu_test_ws5_lostcap_a", '6');
    CHECK(f.heartbeat({first}).unknown_session_ids_size() == 0);

    const std::string second = lose_race("yuzu_test_ws5_lostcap_b", '5');
    auto resp = f.heartbeat({first, second});
    CHECK(listed_unknown(resp) == std::vector<std::string>{first});
    CHECK(resp.acknowledged_count() == 1);
    CHECK(f.desync("renew_leases", "unknown_session") == 1);
}

TEST_CASE("WS-5 BatchHeartbeat: a non-owning replica keeps the last-known hostname and a "
          "re-registered agent's old session is listed",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture owner(db.dsn());
    NonOwningReplica other(owner.auth_mgr, owner.store);
    yuzu::server::OfflineEndpointStore offline{owner.pool};
    REQUIRE(offline.is_open());
    yuzu::server::HeartbeatIngestion ingestion{other.registry, nullptr, nullptr, &other.metrics,
                                               &offline};
    other.svc.set_heartbeat_ingestion(&ingestion);

    const std::string agent = "yuzu_test_ws5_hostname";
    const std::string sid = owner.register_live(agent);
    REQUIRE(offline.upsert(agent, "keep-me-host", "linux", now_ms(), 0, "", "", sid));
    REQUIRE_FALSE(other.registry.get_session(agent));

    auto resp = batch_hb(other.svc, {sid});
    CHECK(resp.acknowledged_count() == 1);
    CHECK(presence_hostname(offline, agent) == "keep-me-host");

    SECTION("a re-registered agent's previous session is listed as unknown") {
        const std::string newer = owner.register_live(agent);
        REQUIRE(newer != sid);
        auto resp2 = batch_hb(owner.svc, {sid, newer});
        CHECK(resp2.acknowledged_count() == 1);
        CHECK(listed_unknown(resp2) == std::vector<std::string>{sid});
    }
}

// ── #5678: DISCONNECTED drives the shared presence-clear helper ─────────────

TEST_CASE("NotifyStreamStatus DISCONNECTED for the CURRENT session clears presence but keeps the "
          "endpoint row (#5678)",
          "[pg][gateway_route_wiring][presence]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwpresence_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore route_store{pool};
    yuzu::server::OfflineEndpointStore offline_store{pool};
    REQUIRE(route_store.is_open());
    REQUIRE(offline_store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    yuzu::server::HeartbeatIngestion hi{registry, nullptr, nullptr, &metrics, &offline_store};
    gateway_svc.set_gateway_route_store(&route_store);
    gateway_svc.set_heartbeat_ingestion(&hi);
    // #5678 gateway evict_pushed parity: a real store so the evict is observable.
    yuzu::server::FleetTopologyStore topo{[](std::chrono::milliseconds) {
        return std::vector<yuzu::server::RawAgentSnapshot>{};
    }};
    gateway_svc.set_fleet_topology_store(&topo);

    auto req = make_gw_register(auth_mgr, "agent-presence-1");
    apb::RegisterResponse resp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
    const std::string session = resp.session_id();

    gw::StreamStatusNotification conn;
    conn.set_agent_id("agent-presence-1");
    conn.set_session_id(session);
    conn.set_event(gw::StreamStatusNotification::CONNECTED);
    conn.set_stream_home_id("home-1");
    gw::StreamStatusAck conn_ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &conn, &conn_ack).ok());
    REQUIRE(conn_ack.acknowledged());

    const auto t = now_ms();
    REQUIRE(offline_store.upsert("agent-presence-1", "host-presence", "linux", t, 0, "1.0.0",
                                 "x86_64", session));
    REQUIRE(live_present(offline_store, "agent-presence-1"));
    {
        yuzu::server::RawAgentSnapshot snap;
        snap.agent_id = "agent-presence-1";
        snap.hostname = "host-presence";
        snap.os = "linux";
        snap.local_ips = {"10.5.0.1"};
        topo.push_snapshot(std::move(snap));
    }
    REQUIRE(topo.pushed_map_size() == 1);

    gw::StreamStatusNotification disc;
    disc.set_agent_id("agent-presence-1");
    disc.set_session_id(session);
    disc.set_event(gw::StreamStatusNotification::DISCONNECTED);
    disc.set_stream_home_id("home-1");
    gw::StreamStatusAck disc_ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &disc, &disc_ack).ok());
    REQUIRE(disc_ack.acknowledged());

    CHECK_FALSE(live_present(offline_store, "agent-presence-1"));
    // The CURRENT-session DISCONNECTED also evicts the pushed viz snapshot.
    CHECK(topo.pushed_map_size() == 0);
    const auto roster = offline_store.query_stale_within(std::chrono::hours(1));
    REQUIRE(roster.has_value()); // #5531: the roster read is typed; a store fault is not "absent"
    const yuzu::server::OfflineEndpoint* row = nullptr;
    for (const auto& e : *roster)
        if (e.agent_id == "agent-presence-1")
            row = &e;
    REQUIRE(row != nullptr);
    CHECK(row->hostname == "host-presence");
    CHECK(row->last_heartbeat_ms == t);
}

TEST_CASE("NotifyStreamStatus: a STALE DISCONNECTED (superseded session) leaves the live "
          "presence row untouched (#5678)",
          "[pg][gateway_route_wiring][presence]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwpresence_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore route_store{pool};
    yuzu::server::OfflineEndpointStore offline_store{pool};
    REQUIRE(route_store.is_open());
    REQUIRE(offline_store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    PgAuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    yuzu::server::HeartbeatIngestion hi{registry, nullptr, nullptr, &metrics, &offline_store};
    gateway_svc.set_gateway_route_store(&route_store);
    gateway_svc.set_heartbeat_ingestion(&hi);
    // #5678 gateway evict_pushed parity: a real store so the evict is observable.
    yuzu::server::FleetTopologyStore topo{[](std::chrono::milliseconds) {
        return std::vector<yuzu::server::RawAgentSnapshot>{};
    }};
    gateway_svc.set_fleet_topology_store(&topo);

    auto req1 = make_gw_register(auth_mgr, "agent-presence-2");
    apb::RegisterResponse resp1;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req1, &resp1).ok());
    const std::string session1 = resp1.session_id();
    auto req2 = make_gw_register(auth_mgr, "agent-presence-2");
    apb::RegisterResponse resp2;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req2, &resp2).ok());
    const std::string session2 = resp2.session_id();
    REQUIRE(session2 != session1);

    gw::StreamStatusNotification conn;
    conn.set_agent_id("agent-presence-2");
    conn.set_session_id(session2);
    conn.set_event(gw::StreamStatusNotification::CONNECTED);
    conn.set_stream_home_id("home-2");
    gw::StreamStatusAck conn_ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &conn, &conn_ack).ok());

    REQUIRE(offline_store.upsert("agent-presence-2", "h", "linux", now_ms(), 0, "", "", session2));
    REQUIRE(live_present(offline_store, "agent-presence-2"));
    {
        yuzu::server::RawAgentSnapshot snap;
        snap.agent_id = "agent-presence-2";
        snap.hostname = "h";
        snap.os = "linux";
        snap.local_ips = {"10.5.0.2"};
        topo.push_snapshot(std::move(snap));
    }
    REQUIRE(topo.pushed_map_size() == 1);

    gw::StreamStatusNotification stale;
    stale.set_agent_id("agent-presence-2");
    stale.set_session_id(session1);
    stale.set_event(gw::StreamStatusNotification::DISCONNECTED);
    gw::StreamStatusAck stale_ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &stale, &stale_ack).ok());

    // removed_current_session was false: presence untouched, and the stored
    // session_id is still session2 (a clear with session2 would now succeed).
    CHECK(live_present(offline_store, "agent-presence-2"));
    // A stale DISCONNECTED must not evict a live re-registered agent's pushed slot.
    CHECK(topo.pushed_map_size() == 1);
    CHECK(offline_store.remove_if_session("agent-presence-2", session2));
}

// #5686: a saturated presence pool costs a handful of bounded acquire waits per
// batch (at most floor(log2 N)+1), not one per heartbeat. The presence store has
// its own one-connection pool whose only lease is held, so every upsert would
// time out; the route store's pool is untouched, so acks and lease renewal
// must be unaffected.
//
// Probe schedule for the 4 sessions with the store failing throughout: entry 1
// is attempted and fails; entry 2 (right after the first failure) is the
// half-open probe and fails; entry 3 is skipped; entry 4 is the next probe and
// fails (the one after would be entry 8). So failed==3, skipped==1.
TEST_CASE("BatchHeartbeat: after a presence upsert fails the batch skips theirs except "
          "spaced probes while every entry is still acked and renewed (#5686)",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture f(db.dsn());
    PgPool presence_pool{{.conninfo = db.dsn(), .size = 1}};
    yuzu::server::OfflineEndpointStore offline{presence_pool};
    REQUIRE(offline.is_open());
    offline.set_metrics(&f.metrics);
    yuzu::server::HeartbeatIngestion ingestion{f.registry, nullptr, nullptr, &f.metrics, &offline};
    f.svc.set_heartbeat_ingestion(&ingestion);

    std::vector<std::string> agents;
    std::vector<std::string> sids;
    for (int i = 0; i < 4; ++i) {
        agents.push_back("yuzu_test_5686_agent_" + std::to_string(i));
        sids.push_back(f.register_live(agents.back()));
        REQUIRE(
            f.store.announce_connected(agents.back(), sids.back(), "zone", "node", 90).has_value());
    }
    // Expire every lease so a renewal is visible without waiting on the clock.
    raw_exec(db.dsn(), "UPDATE gateway_route_store.agent_routes SET lease_until = now() - "
                       "interval '1 hour' WHERE agent_id LIKE 'yuzu_test_5686_agent_%'");
    auto lease_of = [&](const std::string& agent) {
        auto r = f.store.lookup_route(agent);
        REQUIRE(r.has_value());
        REQUIRE(r->has_value());
        REQUIRE((*r)->lease_until_ms.has_value());
        return *(*r)->lease_until_ms;
    };
    std::vector<std::int64_t> expired;
    for (const auto& a : agents)
        expired.push_back(lease_of(a));

    auto presence_failed = [&] {
        return f.metrics
            .counter("yuzu_server_agent_presence_store_failed_total",
                     {{"op", "upsert"}, {"reason", "store_unavailable"}})
            .value();
    };
    auto skipped = [&] {
        return f.metrics.counter("yuzu_server_agent_presence_upsert_skipped_total").value();
    };
    auto batches = [&](const char* outcome) {
        return f.metrics
            .histogram("yuzu_server_gateway_batch_heartbeat_duration_seconds",
                       {{"outcome", outcome}})
            .snapshot()
            .count;
    };

    {
        auto held = presence_pool.acquire();
        REQUIRE(held);
        auto resp = batch_hb(f.svc, sids);
        CHECK(resp.acknowledged_count() == 4);
        CHECK(listed_unknown(resp).empty());
        CHECK(presence_failed() == 3);
        CHECK(skipped() == 1);
        CHECK(f.metrics.counter("yuzu_heartbeats_received_total", {{"via", "gateway"}}).value() ==
              4);
        CHECK(batches("degraded") == 1);
        CHECK(batches("ok") == 0);
    }
    for (std::size_t i = 0; i < agents.size(); ++i) {
        CHECK(lease_of(agents[i]) > expired[i]);
        CHECK_FALSE(offline_row_present(offline, agents[i]));
    }

    // Per batch, not sticky: the next batch on a healthy pool writes every row.
    auto resp = batch_hb(f.svc, sids);
    CHECK(resp.acknowledged_count() == 4);
    for (const auto& a : agents)
        CHECK(offline_row_present(offline, a));
    CHECK(presence_failed() == 3);
    CHECK(skipped() == 1);
    CHECK(batches("ok") == 1);
    CHECK(batches("degraded") == 1);
}

// #5686 governance G-1: a presence failure on the LAST entry of a batch leaves
// nothing to skip (and a probe is not even reached), but the batch is still
// labelled degraded and counts the failed attempt.
TEST_CASE("BatchHeartbeat: a presence failure on the last entry still labels the batch "
          "degraded (#5686)",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture f(db.dsn());
    PgPool presence_pool{{.conninfo = db.dsn(), .size = 1}};
    yuzu::server::OfflineEndpointStore offline{presence_pool};
    REQUIRE(offline.is_open());
    offline.set_metrics(&f.metrics);
    yuzu::server::HeartbeatIngestion ingestion{f.registry, nullptr, nullptr, &f.metrics, &offline};
    f.svc.set_heartbeat_ingestion(&ingestion);

    // One-entry batch: the only (= last) upsert fails.
    const std::string agent = "yuzu_test_5686_last_agent";
    const std::string sid = f.register_live(agent);
    REQUIRE(f.store.announce_connected(agent, sid, "zone", "node", 90).has_value());

    auto histo = [&](const char* outcome) {
        return f.metrics
            .histogram("yuzu_server_gateway_batch_heartbeat_duration_seconds",
                       {{"outcome", outcome}})
            .snapshot()
            .count;
    };
    {
        auto held = presence_pool.acquire();
        REQUIRE(held);
        auto resp = batch_hb(f.svc, {sid});
        CHECK(resp.acknowledged_count() == 1);
    }
    CHECK(f.metrics
              .counter("yuzu_server_agent_presence_store_failed_total",
                       {{"op", "upsert"}, {"reason", "store_unavailable"}})
              .value() == 1);
    CHECK(f.metrics.counter("yuzu_server_agent_presence_upsert_skipped_total").value() == 0);
    CHECK(histo("degraded") == 1);
    CHECK(histo("ok") == 0);
}

// #5686: the new series are pre-seeded at construction (a rate() over a series
// that does not exist yet is silent) and carry the corrected HELP text.
TEST_CASE("GatewayUpstreamServiceImpl: the #5686 series and HELP lines exist before any batch",
          "[pg][gateway_route_wiring][ws5]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    BatchHbFixture f(db.dsn());
    const std::string text = f.metrics.serialize();
    auto has = [&](std::string_view needle) { return text.find(needle) != std::string::npos; };
    CHECK(has("# HELP yuzu_server_gateway_batch_heartbeat_duration_seconds "));
    CHECK(has("# HELP yuzu_server_agent_presence_upsert_skipped_total "));
    CHECK(has("the spacing doubles on each further consecutive failure"));
    CHECK(has("yuzu_server_gateway_batch_heartbeat_duration_seconds_count{outcome=\"ok\"} 0"));
    CHECK(has("yuzu_server_gateway_batch_heartbeat_duration_seconds_count{outcome=\"degraded\"} "
              "0"));
    CHECK(has("\nyuzu_server_agent_presence_upsert_skipped_total 0\n"));
}
