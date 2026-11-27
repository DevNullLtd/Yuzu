// test_guardian_directory_route.cpp - HA WS-5 (#5685): the route-directory decision behind the
// Guardian heartbeat reconcile's send (guardian_directory_route.hpp).
//
// Drives the decision against a REAL AgentRegistry and a REAL GatewayRouteStore on Postgres, so
// every guard is asserted on the store's actual row state, not on a stub. The outcomes pinned:
//   not_needed - the local session can deliver, or no store is wired;
//   routed     - the row is routable, names a cluster, and names THIS replica's session;
//   no_route   - no row, a tombstone, an expired lease, an unplaced row, or a row for ANOTHER
//                session (a push would reach a superseded registration's cluster);
//   unreadable - a degraded directory read (never read as "no route").

#include "guardian_directory_route.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "gateway_route_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include <yuzu/metrics.hpp>

#include "../test_helpers.hpp"

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

using yuzu::server::GatewayRouteStore;
using yuzu::server::GuardianDirectoryRoute;
using yuzu::server::resolve_guardian_directory_route;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
namespace pg = yuzu::server::pg;
namespace agent_pb = ::yuzu::agent::v1;

namespace {

yuzu::test::PgTestTemplate guardian_dir_route_tpl{"guardiandirroute", [](const std::string& dsn) {
    pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    GatewayRouteStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("guardian_directory_route template: store failed to migrate");
}};

class DirRoutePg {
public:
    DirRoutePg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr)
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        db_.emplace(guardian_dir_route_tpl);
        REQUIRE(db_->available());
        pool_.emplace(pg::PgPool::Options{.conninfo = db_->dsn(), .size = 2});
        REQUIRE(pool_->valid());
        store_ = std::make_unique<GatewayRouteStore>(*pool_);
        REQUIRE(store_->is_open());
    }
    GatewayRouteStore& store() { return *store_; }
    void raw_exec(const char* sql) {
        pg::PgConn conn{PQconnectdb(db_->dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult r{PQexec(conn.get(), sql)};
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

private:
    std::optional<yuzu::test::PostgresTestDb> db_;
    std::optional<pg::PgPool> pool_;
    std::unique_ptr<GatewayRouteStore> store_;
};

agent_pb::AgentInfo info_for(const std::string& id) {
    agent_pb::AgentInfo info;
    info.set_agent_id(id);
    info.set_hostname("host.local");
    return info;
}

struct Rig {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};

    // A local session for `id` with session id `sid` and NO delivery path (the shape a
    // replay-adopted session has until its CONNECTED reaches this replica).
    void adopt(const std::string& id, const std::string& sid) {
        auto reg = registry.register_agent(info_for(id));
        REQUIRE(reg.has_value());
        registry.map_session(sid, id);
        REQUIRE(registry.needs_directory_consult(id));
    }
};

// Publish a routable row {session, cluster} for `id`.
void publish(GatewayRouteStore& store, const std::string& id, const std::string& sid,
             const std::string& cluster, int ttl_s = 60) {
    auto fresh = store.register_fresh(id, sid);
    REQUIRE(fresh.has_value());
    REQUIRE(fresh->won);
    auto ann = store.announce_connected(id, sid, cluster, "node-1", ttl_s);
    REQUIRE(ann.has_value());
    REQUIRE(ann->matched);
}

} // namespace

TEST_CASE("guardian directory route: a routable row for THIS replica's session is routed to its cluster",
          "[server][guardian][ha][pg]") {
    DirRoutePg db;
    Rig rig;
    rig.adopt("agent-1", "sess-1");
    publish(db.store(), "agent-1", "sess-1", "cluster-a");
    const auto r = resolve_guardian_directory_route(rig.registry, &db.store(), "agent-1");
    CHECK(r.kind == GuardianDirectoryRoute::Kind::routed);
    CHECK(r.cluster_id == "cluster-a");
}

TEST_CASE("guardian directory route: a row naming ANOTHER session is no_route, never the other session's cluster",
          "[server][guardian][ha][pg]") {
    DirRoutePg db;
    Rig rig;
    rig.adopt("agent-1", "sess-old");
    publish(db.store(), "agent-1", "sess-new", "cluster-b"); // the agent re-homed under a new session
    const auto r = resolve_guardian_directory_route(rig.registry, &db.store(), "agent-1");
    CHECK(r.kind == GuardianDirectoryRoute::Kind::no_route);
    CHECK(r.cluster_id.empty());
}

TEST_CASE("guardian directory route: no row, an unplaced row and a tombstone are no_route",
          "[server][guardian][ha][pg]") {
    DirRoutePg db;
    Rig rig;
    rig.adopt("agent-none", "sess-n");
    CHECK(resolve_guardian_directory_route(rig.registry, &db.store(), "agent-none").kind ==
          GuardianDirectoryRoute::Kind::no_route);

    rig.adopt("agent-unplaced", "sess-u");
    REQUIRE(db.store().register_fresh("agent-unplaced", "sess-u").has_value()); // no CONNECTED yet
    CHECK(resolve_guardian_directory_route(rig.registry, &db.store(), "agent-unplaced").kind ==
          GuardianDirectoryRoute::Kind::no_route);

    rig.adopt("agent-tomb", "sess-t");
    publish(db.store(), "agent-tomb", "sess-t", "cluster-a");
    db.raw_exec("UPDATE gateway_route_store.agent_routes SET session_id = NULL, lease_until = NULL "
                "WHERE agent_id = 'agent-tomb'");
    CHECK(resolve_guardian_directory_route(rig.registry, &db.store(), "agent-tomb").kind ==
          GuardianDirectoryRoute::Kind::no_route);
}

TEST_CASE("guardian directory route: an expired lease is no_route", "[server][guardian][ha][pg]") {
    DirRoutePg db;
    Rig rig;
    rig.adopt("agent-1", "sess-1");
    publish(db.store(), "agent-1", "sess-1", "cluster-a");
    db.raw_exec("UPDATE gateway_route_store.agent_routes SET lease_until = now() - interval '1 hour' "
                "WHERE agent_id = 'agent-1'");
    CHECK(resolve_guardian_directory_route(rig.registry, &db.store(), "agent-1").kind ==
          GuardianDirectoryRoute::Kind::no_route);
}

TEST_CASE("guardian directory route: a degraded directory read is unreadable, never no_route",
          "[server][guardian][ha][pg]") {
    DirRoutePg db;
    Rig rig;
    rig.adopt("agent-1", "sess-1");
    publish(db.store(), "agent-1", "sess-1", "cluster-a");
    db.raw_exec("ALTER TABLE gateway_route_store.agent_routes "
                "RENAME COLUMN gateway_node TO gateway_node_x");
    const auto r = resolve_guardian_directory_route(rig.registry, &db.store(), "agent-1");
    CHECK(r.kind == GuardianDirectoryRoute::Kind::unreadable);
    CHECK(r.cluster_id.empty());
}

TEST_CASE("guardian directory route: a session that can deliver, or no store, never consults the directory",
          "[server][guardian][ha][pg]") {
    DirRoutePg db;
    Rig rig;
    rig.adopt("agent-1", "sess-1");
    publish(db.store(), "agent-1", "sess-1", "cluster-a");
    // No store wired: the registry send is the whole story.
    CHECK(resolve_guardian_directory_route(rig.registry, nullptr, "agent-1").kind ==
          GuardianDirectoryRoute::Kind::not_needed);
    // A live stream means the local session can deliver, even with a routable row present.
    auto sess = rig.registry.get_session("agent-1");
    REQUIRE(sess != nullptr);
    alignas(std::max_align_t) char stream_stand_in = 0; // never dereferenced: only null-checked
    {
        std::lock_guard lock(sess->stream_mu);
        sess->stream = reinterpret_cast<decltype(sess->stream)>(&stream_stand_in);
    }
    CHECK(resolve_guardian_directory_route(rig.registry, &db.store(), "agent-1").kind ==
          GuardianDirectoryRoute::Kind::not_needed);
    {
        std::lock_guard lock(sess->stream_mu);
        sess->stream = nullptr; // the registry must not see the stand-in again
    }
}

TEST_CASE("guardian directory route: an agent with no local session at all is no_route, never routed",
          "[server][guardian][ha][pg]") {
    DirRoutePg db;
    Rig rig;
    publish(db.store(), "agent-remote", "sess-r", "cluster-a");
    // This replica holds nothing for it: there is no local session id to compare, so the row cannot
    // be shown to describe a session this replica knows.
    CHECK(resolve_guardian_directory_route(rig.registry, &db.store(), "agent-remote").kind ==
          GuardianDirectoryRoute::Kind::no_route);
}

TEST_CASE("guardian directory route: an empty row session never matches an agent with no local session",
          "[server][guardian][ha][pg]") {
    DirRoutePg db;
    Rig rig; // no local session: its session id reads as empty
    publish(db.store(), "agent-remote", "sess-r", "cluster-a");
    // A row whose session id is the empty string equals the empty local id by string comparison,
    // so equality alone would route it. The explicit empty-local guard refuses it.
    db.raw_exec("UPDATE gateway_route_store.agent_routes SET session_id = '' "
                "WHERE agent_id = 'agent-remote'");
    CHECK(resolve_guardian_directory_route(rig.registry, &db.store(), "agent-remote").kind ==
          GuardianDirectoryRoute::Kind::no_route);
}
