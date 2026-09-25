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

#include <catch2/catch_test_macros.hpp>

#include <grpcpp/grpcpp.h>

#include "agent_registry.hpp"
#include "agent_service_impl.hpp"
#include "audit_store.hpp"
#include "event_bus.hpp"
#include "gateway_route_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>

#include "../test_helpers.hpp"

#include <algorithm>

#include <libpq-fe.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

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
    req.set_enrollment_token(auth_mgr.create_enrollment_token("test", 0, std::chrono::hours(1)));
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
    yuzu::server::auth::AuthManager auth_mgr;
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
    yuzu::server::auth::AuthManager auth_mgr;
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
    auto resp = h.register_agent("agent-unknown-session", "gw-session-forged-not-real");
    REQUIRE(resp.accepted());
    // The response now ADOPTS the presented session — no more S'-vs-S gap.
    CHECK(resp.session_id() == "gw-session-forged-not-real");

    auto row = store.lookup_route("agent-unknown-session");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value()); // a row WAS created — reclaimed, not skipped
    CHECK((*row)->session_id == "gw-session-forged-not-real");
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
    const std::string session_id = "gw-session-tombstone-replay";
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

    const std::string session_id = "gw-session-4669-reclaim-clean";
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

    const std::string session_id = "gw-session-4669-reclaim-reap";
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
        h.register_agent_status("agent-zombie-1", "gw-session-zombie-not-current");
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
    yuzu::server::auth::AuthManager auth_mgr;
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
    yuzu::server::auth::AuthManager auth_mgr;
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
    yuzu::server::auth::AuthManager auth_mgr;
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
    yuzu::server::auth::AuthManager auth_mgr;
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
    yuzu::server::auth::AuthManager auth_mgr;
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
    yuzu::server::auth::AuthManager auth_mgr;
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
    yuzu::server::auth::AuthManager auth_mgr;
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
    yuzu::server::auth::AuthManager auth_mgr;
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
    yuzu::server::auth::AuthManager auth_mgr;
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
    yuzu::server::auth::AuthManager auth_mgr;
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
    yuzu::server::auth::AuthManager auth_mgr;
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
    yuzu::server::auth::AuthManager auth_mgr;
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
    yuzu::server::auth::AuthManager auth_mgr;
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
    yuzu::server::auth::AuthManager auth_mgr;
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
    yuzu::server::auth::AuthManager auth_mgr;
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
    yuzu::server::auth::AuthManager auth_mgr;
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
    yuzu::server::auth::AuthManager auth_mgr;
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
        h.register_agent_status("agent-degraded-store-replay", "gw-session-presented-but-unverifiable");
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
    yuzu::server::auth::AuthManager auth_mgr;
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

TEST_CASE("NotifyStreamStatus: a degraded GatewayRouteStore announce_connected write does NOT "
          "fail the RPC (fail-OPEN — Task B, 4.2b) and is counted",
          "[pg][gateway_route_wiring]") {
    // announce_connected stays fail-OPEN (Task B, 4.2b): the CONNECTED notify
    // is a droppable gen_server:cast and registry_.set_gateway_route has
    // already published the in-memory route by the time this write runs. A
    // REAL store is needed first so ProxyRegister (now fail-CLOSED on
    // register_fresh) succeeds and mints a session; the store is then SWAPPED
    // for a broken one so only the FOLLOW-UP announce_connected write
    // degrades.
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
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
    CHECK(ack.acknowledged());
    CHECK(metrics
              .counter("yuzu_server_gateway_route_write_failed_total",
                       {{"op", "announce_connected"}, {"reason", "store_unavailable"}})
              .value() == 1);
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
