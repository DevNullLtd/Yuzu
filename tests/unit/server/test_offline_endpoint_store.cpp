// OfflineEndpointStore tests (#1320 PR 3): upsert idempotency, RETURNING
// mutate-and-return, the stale-within window query, and the empty-pool
// fail-soft contract. Born-on-Postgres store, schema `endpoint_state`.

#include <catch2/catch_test_macros.hpp>

#include "offline_endpoint_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <chrono>
#include <stdexcept>
#include <string>

using yuzu::server::OfflineEndpoint;
using yuzu::server::OfflineEndpointStore;
using yuzu::server::PresenceIdentity;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp). The
// migration-failure test stays on plain YUZU_REQUIRE_PG_DB — it pre-seeds a
// conflicting schema and needs the store's schema to NOT exist yet.
yuzu::test::PgTestTemplate offline_tpl{"offline", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    OfflineEndpointStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("offline template: store failed to migrate");
}};

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

const OfflineEndpoint* find(const std::vector<OfflineEndpoint>& v, const std::string& id) {
    for (const auto& e : v)
        if (e.agent_id == id)
            return &e;
    return nullptr;
}

const PresenceIdentity* find_presence(const std::vector<PresenceIdentity>& v,
                                      const std::string& id) {
    for (const auto& e : v)
        if (e.agent_id == id)
            return &e;
    return nullptr;
}

} // namespace

TEST_CASE("OfflineEndpointStore migrates and upserts", "[pg][offline]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    const auto t = now_ms();

    SECTION("insert then read back within window") {
        REQUIRE(store.upsert("agent-a", "host-a", "linux", t, 1234));
        auto rows = store.query_stale_within(std::chrono::hours(1));
        const auto* a = find(rows, "agent-a");
        REQUIRE(a != nullptr);
        CHECK(a->hostname == "host-a");
        CHECK(a->os == "linux");
        CHECK(a->agent_ts == 1234);
        CHECK(a->last_heartbeat_ms == t);
    }

    SECTION("upsert is idempotent on agent_id and overwrites fields") {
        REQUIRE(store.upsert("agent-b", "old-host", "linux", t - 5000, 1));
        REQUIRE(store.upsert("agent-b", "new-host", "windows", t, 2));
        auto rows = store.query_stale_within(std::chrono::hours(1));
        const auto* b = find(rows, "agent-b");
        REQUIRE(b != nullptr);
        CHECK(b->hostname == "new-host");
        CHECK(b->os == "windows");
        CHECK(b->agent_ts == 2);
        // Exactly one row for the agent (PK conflict updated in place).
        int count = 0;
        for (const auto& e : rows)
            if (e.agent_id == "agent-b")
                ++count;
        CHECK(count == 1);
    }

    SECTION("query_stale_within excludes rows older than the window") {
        REQUIRE(store.upsert("recent", "h1", "linux", t - 1000, 0));     // 1s ago
        REQUIRE(store.upsert("ancient", "h2", "linux", t - 86'400'000, 0)); // ~1 day ago
        auto rows = store.query_stale_within(std::chrono::seconds(60));
        CHECK(find(rows, "recent") != nullptr);
        CHECK(find(rows, "ancient") == nullptr);
    }

    SECTION("empty agent_id is rejected, no row written") {
        CHECK_FALSE(store.upsert("", "h", "linux", t, 0));
        auto rows = store.query_stale_within(std::chrono::hours(1));
        CHECK(find(rows, "") == nullptr);
    }

    // Round-3 v2 columns (Devices-page merge, item 1): agent_version/arch.
    SECTION("v2 round-trip: agent_version and arch persist") {
        REQUIRE(store.upsert("agent-v2", "host-v2", "windows", t, 0, "1.4.2", "x86_64"));
        auto rows = store.query_stale_within(std::chrono::hours(1));
        const auto* v = find(rows, "agent-v2");
        REQUIRE(v != nullptr);
        CHECK(v->agent_version == "1.4.2");
        CHECK(v->arch == "x86_64");
    }

    SECTION("v2 blank-preserve: a blank agent_version/arch does not clobber a known value") {
        REQUIRE(store.upsert("agent-v2b", "host-v2b", "linux", t - 1000, 0, "2.0.0", "arm64"));
        // A later heartbeat that raced the session lookup supplies blanks —
        // hostname/os still update unconditionally, but the last-known
        // version/arch must survive (see upsert()'s CASE WHEN doc comment).
        REQUIRE(store.upsert("agent-v2b", "host-v2b-renamed", "linux", t, 0, "", ""));
        auto rows = store.query_stale_within(std::chrono::hours(1));
        const auto* v = find(rows, "agent-v2b");
        REQUIRE(v != nullptr);
        CHECK(v->hostname == "host-v2b-renamed"); // unconditional field still updates
        CHECK(v->agent_version == "2.0.0");       // preserved, not blanked
        CHECK(v->arch == "arm64");                // preserved, not blanked
    }

    SECTION("v2 pre-migration rows read back as empty version/arch") {
        // No explicit pre-v1-only fixture is practical here (the template
        // always migrates through the latest version) — this asserts the
        // DEFAULT '' on a row that never supplied them, which is the same
        // observable shape a genuinely pre-v2 row would have after the
        // ADD COLUMN migration runs.
        REQUIRE(store.upsert("agent-noversion", "h", "linux", t, 0));
        auto rows = store.query_stale_within(std::chrono::hours(1));
        const auto* v = find(rows, "agent-noversion");
        REQUIRE(v != nullptr);
        CHECK(v->agent_version.empty());
        CHECK(v->arch.empty());
    }
}

// HA WS-5 (ADR-2002 §7a): cross-replica presence — query_live_ids's identity
// projection and remove_if_session's session-guarded delete.
TEST_CASE("OfflineEndpointStore HA WS-5 presence", "[pg][offline]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    const auto t = now_ms();

    SECTION("query_live_ids returns identity fields for a recent row") {
        REQUIRE(store.upsert("agent-p1", "host-p1", "linux", t, 0, "1.0.0", "x86_64",
                             "sess-1"));
        auto rows = store.query_live_ids(std::chrono::hours(1));
        const auto* p = find_presence(rows, "agent-p1");
        REQUIRE(p != nullptr);
        CHECK(p->hostname == "host-p1");
        CHECK(p->os == "linux");
        CHECK(p->agent_version == "1.0.0");
        CHECK(p->arch == "x86_64");
    }

    SECTION("query_live_ids's TTL is the DATABASE clock, not last_heartbeat_ms") {
        // A row whose last_heartbeat_ms is old (client-supplied, potentially
        // skewed) but whose last_seen_at was JUST authored by upsert() (PG
        // now()) is live — last_seen_at is the sole liveness authority,
        // exactly the #3715 precedent (never the replica's own clock, and
        // here not even the client-supplied last_heartbeat_ms).
        REQUIRE(store.upsert("agent-freshseen", "h", "linux", t - 86'400'000, 0, "", "", ""));
        auto rows = store.query_live_ids(std::chrono::seconds(60));
        CHECK(find_presence(rows, "agent-freshseen") != nullptr);
    }

    SECTION("query_live_ids excludes a row outside the TTL window") {
        // A ttl of 0 means "nothing is live" (last_seen_at is authored at
        // upsert time, strictly before the read's now()).
        REQUIRE(store.upsert("agent-stale", "h", "linux", t, 0, "", "", "sess-x"));
        auto rows = store.query_live_ids(std::chrono::seconds(0));
        CHECK(find_presence(rows, "agent-stale") == nullptr);
    }

    SECTION("remove_if_session no-ops on a session mismatch") {
        REQUIRE(store.upsert("agent-guard", "h", "linux", t, 0, "", "", "sess-real"));
        CHECK_FALSE(store.remove_if_session("agent-guard", "sess-stale"));
        auto rows = store.query_live_ids(std::chrono::hours(1));
        CHECK(find_presence(rows, "agent-guard") != nullptr); // row survives
    }

    SECTION("remove_if_session deletes on a session match") {
        REQUIRE(store.upsert("agent-guard2", "h", "linux", t, 0, "", "", "sess-real2"));
        CHECK(store.remove_if_session("agent-guard2", "sess-real2"));
        auto rows = store.query_live_ids(std::chrono::hours(1));
        CHECK(find_presence(rows, "agent-guard2") == nullptr);
    }

    SECTION("remove_if_session rejects an empty session_id — never a bare agent_id delete") {
        REQUIRE(store.upsert("agent-guard3", "h", "linux", t, 0, "", "", "sess-real3"));
        CHECK_FALSE(store.remove_if_session("agent-guard3", ""));
        auto rows = store.query_live_ids(std::chrono::hours(1));
        CHECK(find_presence(rows, "agent-guard3") != nullptr);
    }

    SECTION("a blank session_id on upsert never matches a later remove_if_session") {
        // The blank-session upsert path (a heartbeat that raced session
        // lookup — see upsert()'s doc comment): the row's session_id column
        // is blanked, and remove_if_session always requires a NON-empty
        // caller-supplied value, so it can never match — the row simply
        // waits out the TTL instead, which is always safe.
        REQUIRE(store.upsert("agent-raced", "h", "linux", t, 0, "", "", ""));
        CHECK_FALSE(store.remove_if_session("agent-raced", ""));
        auto rows = store.query_live_ids(std::chrono::hours(1));
        CHECK(find_presence(rows, "agent-raced") != nullptr);
    }
}

// gov fjarvis B1: a reachable database whose schema migration FAILS must leave
// the store !is_open() — which the server wires to startup_failed_ (fail
// closed, not serve-degraded). Force the failure by pre-seeding a table in the
// store's schema with no schema_meta row: the migration runner's schema-drift
// guard refuses (version 0 but tables exist), so run() returns false.
TEST_CASE("OfflineEndpointStore reports !is_open on a migration failure", "[pg][offline]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);

    // Pre-seed: create the endpoint_state schema + a conflicting table, but no
    // public.schema_meta row for the store — the drift guard will refuse.
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA endpoint_state")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE endpoint_state.endpoints (bogus int)")};
        REQUIRE(t.ok());
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    CHECK_FALSE(store.is_open()); // → server.cpp sets startup_failed_ = true
}
