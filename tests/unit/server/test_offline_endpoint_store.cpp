// OfflineEndpointStore tests (#1320 PR 3): upsert idempotency, RETURNING
// mutate-and-return, the stale-within window query, and the typed
// failure contract (StoreUnavailable / DbError, never an empty success).
// Born-on-Postgres store, schema `endpoint_state`.

#include <catch2/catch_test_macros.hpp>

#include "offline_endpoint_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <stdexcept>
#include <string>

using yuzu::server::OfflineEndpoint;
using yuzu::server::OfflineEndpointStore;
using yuzu::server::PresenceIdentity;
using yuzu::server::PresenceReadError;
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

// #4981 PR-1 (Finding B1): query_live_ids now returns std::expected — this
// unwraps the healthy-path result for the pre-existing tests below, which all
// exercise a live/reachable store and only ever cared about the row set.
std::vector<PresenceIdentity> live_ids_ok(OfflineEndpointStore& s, std::chrono::seconds ttl) {
    auto r = s.query_live_ids(ttl);
    REQUIRE(r.has_value());
    return *r;
}

// #5531: query_stale_within is typed too; unwraps the healthy-path result.
std::vector<OfflineEndpoint> stale_ok(OfflineEndpointStore& s, std::chrono::seconds window) {
    auto r = s.query_stale_within(window);
    REQUIRE(r.has_value());
    return *r;
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
        auto rows = stale_ok(store, std::chrono::hours(1));
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
        auto rows = stale_ok(store, std::chrono::hours(1));
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
        auto rows = stale_ok(store, std::chrono::seconds(60));
        CHECK(find(rows, "recent") != nullptr);
        CHECK(find(rows, "ancient") == nullptr);
    }

    SECTION("empty agent_id is rejected, no row written") {
        CHECK_FALSE(store.upsert("", "h", "linux", t, 0));
        auto rows = stale_ok(store, std::chrono::hours(1));
        CHECK(find(rows, "") == nullptr);
    }

    // Round-3 v2 columns (Devices-page merge, item 1): agent_version/arch.
    SECTION("v2 round-trip: agent_version and arch persist") {
        REQUIRE(store.upsert("agent-v2", "host-v2", "windows", t, 0, "1.4.2", "x86_64"));
        auto rows = stale_ok(store, std::chrono::hours(1));
        const auto* v = find(rows, "agent-v2");
        REQUIRE(v != nullptr);
        CHECK(v->agent_version == "1.4.2");
        CHECK(v->arch == "x86_64");
    }

    SECTION("v2 blank-preserve: a blank agent_version/arch does not clobber a known value") {
        REQUIRE(store.upsert("agent-v2b", "host-v2b", "linux", t - 1000, 0, "2.0.0", "arm64"));
        // A later heartbeat that raced the session lookup supplies blanks —
        // a NON-blank hostname still overwrites, but the last-known
        // version/arch/os must survive (see upsert()'s CASE WHEN doc comment).
        REQUIRE(store.upsert("agent-v2b", "host-v2b-renamed", "", t, 0, "", ""));
        auto rows = stale_ok(store, std::chrono::hours(1));
        const auto* v = find(rows, "agent-v2b");
        REQUIRE(v != nullptr);
        CHECK(v->hostname == "host-v2b-renamed"); // non-blank hostname still overwrites
        CHECK(v->agent_version == "2.0.0");       // preserved, not blanked
        CHECK(v->arch == "arm64");                // preserved, not blanked
        CHECK(v->os == "linux");                  // #5294: preserved, not blanked
        // A non-blank os still wins (a genuine OS change).
        REQUIRE(store.upsert("agent-v2b", "host-v2b-renamed", "windows", t, 0, "", ""));
        rows = stale_ok(store, std::chrono::hours(1));
        v = find(rows, "agent-v2b");
        REQUIRE(v != nullptr);
        CHECK(v->os == "windows");
    }

    // HA WS-5: a replica without the local AgentSession ingests heartbeats whose
    // hostname/os are blank; that must never wipe what the owning replica wrote.
    SECTION("WS-5 blank-preserve: a blank hostname or os never clobbers a known one") {
        REQUIRE(store.upsert("agent-ws5-bp", "known-host", "linux", t - 1000, 0, "3.0.0", "arm64"));
        REQUIRE(store.upsert("agent-ws5-bp", "", "", t, 7, "", ""));
        auto rows = stale_ok(store, std::chrono::hours(1));
        const auto* v = find(rows, "agent-ws5-bp");
        REQUIRE(v != nullptr);
        CHECK(v->hostname == "known-host");   // preserved, not blanked
        CHECK(v->os == "linux");              // preserved, not blanked
        CHECK(v->agent_version == "3.0.0");
        CHECK(v->arch == "arm64");
        CHECK(v->agent_ts == 7);              // non-identity columns still advance
        CHECK(v->last_heartbeat_ms == t);

        // Blank hostname alone (os supplied) -> hostname preserved, os overwritten.
        REQUIRE(store.upsert("agent-ws5-bp", "", "windows", t, 8, "", ""));
        rows = stale_ok(store, std::chrono::hours(1));
        v = find(rows, "agent-ws5-bp");
        REQUIRE(v != nullptr);
        CHECK(v->hostname == "known-host");
        CHECK(v->os == "windows");

        // Non-blank hostname still overwrites.
        REQUIRE(store.upsert("agent-ws5-bp", "renamed-host", "", t, 9, "", ""));
        rows = stale_ok(store, std::chrono::hours(1));
        v = find(rows, "agent-ws5-bp");
        REQUIRE(v != nullptr);
        CHECK(v->hostname == "renamed-host");
        CHECK(v->os == "windows");
    }

    SECTION("WS-5 blank hostname on a FIRST insert stores empty (nothing to preserve)") {
        REQUIRE(store.upsert("agent-ws5-first", "", "", t, 0));
        auto rows = stale_ok(store, std::chrono::hours(1));
        const auto* v = find(rows, "agent-ws5-first");
        REQUIRE(v != nullptr);
        CHECK(v->hostname.empty());
        CHECK(v->os.empty());
    }

    SECTION("v2 pre-migration rows read back as empty version/arch") {
        // No explicit pre-v1-only fixture is practical here (the template
        // always migrates through the latest version) — this asserts the
        // DEFAULT '' on a row that never supplied them, which is the same
        // observable shape a genuinely pre-v2 row would have after the
        // ADD COLUMN migration runs.
        REQUIRE(store.upsert("agent-noversion", "h", "linux", t, 0));
        auto rows = stale_ok(store, std::chrono::hours(1));
        const auto* v = find(rows, "agent-noversion");
        REQUIRE(v != nullptr);
        CHECK(v->agent_version.empty());
        CHECK(v->arch.empty());
    }
}

// HA WS-5 (ADR-2002 §7a): cross-replica presence — query_live_ids's identity
// projection and remove_if_session's session-guarded presence clear (#5678).
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
        auto rows = live_ids_ok(store, std::chrono::hours(1));
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
        REQUIRE(store.upsert("agent-freshseen", "h", "linux", t - 86'400'000, 0, "", "", "sess-fresh"));
        auto rows = live_ids_ok(store, std::chrono::seconds(60));
        CHECK(find_presence(rows, "agent-freshseen") != nullptr);
    }

    SECTION("query_live_ids excludes a row outside the TTL window") {
        // A ttl of 0 means "nothing is live" (last_seen_at is authored at
        // upsert time, strictly before the read's now()).
        REQUIRE(store.upsert("agent-stale", "h", "linux", t, 0, "", "", "sess-x"));
        auto rows = live_ids_ok(store, std::chrono::seconds(0));
        CHECK(find_presence(rows, "agent-stale") == nullptr);
    }

    SECTION("remove_if_session no-ops on a session mismatch") {
        REQUIRE(store.upsert("agent-guard", "h", "linux", t, 0, "", "", "sess-real"));
        CHECK_FALSE(store.remove_if_session("agent-guard", "sess-stale"));
        auto rows = live_ids_ok(store, std::chrono::hours(1));
        CHECK(find_presence(rows, "agent-guard") != nullptr); // still present
        auto roster = stale_ok(store, std::chrono::hours(1));
        const auto* r = find(roster, "agent-guard");
        REQUIRE(r != nullptr);
        CHECK(r->last_heartbeat_ms == t); // row unchanged
    }

    SECTION("remove_if_session clears presence but keeps the roster row (#5678)") {
        REQUIRE(store.upsert("agent-guard2", "host-g2", "linux", t, 0, "1.0.0", "x86_64",
                             "sess-real2"));
        CHECK(store.remove_if_session("agent-guard2", "sess-real2"));
        auto rows = live_ids_ok(store, std::chrono::hours(1));
        CHECK(find_presence(rows, "agent-guard2") == nullptr);
        auto roster = stale_ok(store, std::chrono::hours(1));
        const auto* r = find(roster, "agent-guard2");
        REQUIRE(r != nullptr);
        CHECK(r->hostname == "host-g2");
        CHECK(r->agent_version == "1.0.0");
        CHECK(r->arch == "x86_64");
        CHECK(r->last_heartbeat_ms == t); // the real last heartbeat survives
    }

    SECTION("a blank-session heartbeat does not drop a LIVE agent from presence") {
        REQUIRE(store.upsert("agent-live", "h1", "linux", t - 1000, 0, "1.0.0", "x86_64",
                             "sess-1"));
        REQUIRE(store.upsert("agent-live", "h2", "linux", t, 0, "", "", ""));
        auto rows = live_ids_ok(store, std::chrono::hours(1));
        CHECK(find_presence(rows, "agent-live") != nullptr); // blank preserved sess-1
        auto roster = stale_ok(store, std::chrono::hours(1));
        const auto* r = find(roster, "agent-live");
        REQUIRE(r != nullptr);
        CHECK(r->hostname == "h2");
        CHECK(r->last_heartbeat_ms == t);
    }

    SECTION("a departed agent becomes present again on its next session-carrying heartbeat") {
        REQUIRE(store.upsert("agent-back", "h", "linux", t, 0, "", "", "sess-1"));
        REQUIRE(store.remove_if_session("agent-back", "sess-1"));
        CHECK(find_presence(live_ids_ok(store, std::chrono::hours(1)), "agent-back") == nullptr);
        REQUIRE(store.upsert("agent-back", "h", "linux", t, 0, "", "", "sess-2"));
        CHECK(find_presence(live_ids_ok(store, std::chrono::hours(1)), "agent-back") != nullptr);
        // A later blank-session heartbeat preserves sess-2.
        REQUIRE(store.upsert("agent-back", "h", "linux", t, 0, "", "", ""));
        CHECK(find_presence(live_ids_ok(store, std::chrono::hours(1)), "agent-back") != nullptr);
    }

    SECTION("remove_if_session rejects an empty session_id — never a bare agent_id delete") {
        REQUIRE(store.upsert("agent-guard3", "h", "linux", t, 0, "", "", "sess-real3"));
        CHECK_FALSE(store.remove_if_session("agent-guard3", ""));
        auto rows = live_ids_ok(store, std::chrono::hours(1));
        CHECK(find_presence(rows, "agent-guard3") != nullptr);
    }

    SECTION("blank-session upsert on a NEW row is not present (fail-closed) but is on the roster") {
        // A heartbeat that raced session lookup for an agent with no stored
        // session: the row exists for the roster, but presence requires a
        // non-blank session_id, so the agent is NOT present until a
        // session-carrying heartbeat. remove_if_session still refuses "".
        REQUIRE(store.upsert("agent-raced", "h", "linux", t, 0, "", "", ""));
        CHECK_FALSE(store.remove_if_session("agent-raced", ""));
        auto rows = live_ids_ok(store, std::chrono::hours(1));
        CHECK(find_presence(rows, "agent-raced") == nullptr);
        auto roster = stale_ok(store, std::chrono::hours(1));
        CHECK(find(roster, "agent-raced") != nullptr);
    }
}

// Raw SQL on the store's table, for fixtures the public API cannot express:
// last_seen_at is PG-authored on every upsert, so ageing a row means rewriting it.
static void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    REQUIRE(r.ok());
}

TEST_CASE("OfflineEndpointStore run_retention_prune deletes only rows past roster+margin",
          "[pg][offline][retention-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    const auto t = now_ms();
    REQUIRE(store.upsert("prune-a", "h", "linux", t, 0, "", "", "s"));
    REQUIRE(store.upsert("prune-b", "h", "linux", t, 0, "", "", "s"));
    REQUIRE(store.upsert("prune-c", "h", "linux", t, 0, "", "", "s"));
    // The prune keys on the PG-authored last_seen_at, so age the rows there.
    exec_sql(db.dsn(), "UPDATE endpoint_state.endpoints SET last_seen_at = now() - interval "
                       "'40 days' WHERE agent_id = 'prune-a'"); // past 37 d
    exec_sql(db.dsn(), "UPDATE endpoint_state.endpoints SET last_seen_at = now() - interval "
                       "'31 days' WHERE agent_id = 'prune-b'"); // in margin
    exec_sql(db.dsn(), "UPDATE endpoint_state.endpoints SET last_seen_at = now() - interval "
                       "'10 days' WHERE agent_id = 'prune-c'");

    const auto window = std::chrono::hours(24 * 30);
    // Part-6 Decline: the first pass on a store with data and no persisted
    // anchor records the anchor + settled marker and deletes nothing.
    CHECK(store.run_retention_prune(window) == 0);
    CHECK(store.run_retention_prune(window) == 1);
    auto rows = stale_ok(store, std::chrono::hours(24 * 60));
    CHECK(find(rows, "prune-a") == nullptr);
    CHECK(find(rows, "prune-b") != nullptr);
    CHECK(find(rows, "prune-c") != nullptr);
}

// The prune clock is PG's last_seen_at, never the replica-authored
// last_heartbeat_ms the roster reads (gov GV-2): a lagging replica clock cannot
// expire a live row, and a future-stamped one cannot make a dead row immortal.
TEST_CASE("OfflineEndpointStore run_retention_prune keys on last_seen_at, not last_heartbeat_ms",
          "[pg][offline][retention-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    constexpr std::int64_t kDayMs = 24LL * 3600 * 1000;
    const auto t = now_ms();
    // A: live agent whose replica clock lags 60 d; last_seen_at is fresh -> survives.
    REQUIRE(store.upsert("ch-a", "h", "linux", t - 60 * kDayMs, 0, "", "", "s"));
    // B: departed 2 d ago -> survives.
    REQUIRE(store.upsert("ch-b", "h", "linux", t, 0, "", "", "s"));
    // C: unseen 40 d -> deleted.
    REQUIRE(store.upsert("ch-c", "h", "linux", t, 0, "", "", "s"));
    // D: replica clock 90 d AHEAD, unseen 40 d -> deleted (not immortal).
    REQUIRE(store.upsert("ch-d", "h", "linux", t + 90 * kDayMs, 0, "", "", "s"));
    exec_sql(db.dsn(), "UPDATE endpoint_state.endpoints SET last_seen_at = now() - interval "
                       "'2 days' WHERE agent_id = 'ch-b'");
    exec_sql(db.dsn(), "UPDATE endpoint_state.endpoints SET last_seen_at = now() - interval "
                       "'40 days' WHERE agent_id IN ('ch-c', 'ch-d')");

    const auto window = std::chrono::hours(24 * 30);
    CHECK(store.run_retention_prune(window) == 0); // bootstrap decline settles the anchor
    CHECK(store.run_retention_prune(window) == 2);
    auto rows = stale_ok(store, std::chrono::hours(24 * 120));
    CHECK(find(rows, "ch-a") != nullptr);
    CHECK(find(rows, "ch-b") != nullptr);
    CHECK(find(rows, "ch-c") == nullptr);
    CHECK(find(rows, "ch-d") == nullptr);
}

// The server's drain loop re-arms only while a pass returns exactly the cap, so
// the store must return kPruneCapPerPass when more expired rows remain (GV-17).
TEST_CASE("OfflineEndpointStore run_retention_prune returns the cap while more rows remain",
          "[pg][offline][retention-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    // One fresh survivor (else the would-wipe decline fires) + cap+1 expired rows.
    REQUIRE(store.upsert("cap-live", "h", "linux", now_ms(), 0, "", "", "s"));
    exec_sql(db.dsn(),
             "INSERT INTO endpoint_state.endpoints (agent_id, last_heartbeat_ms, last_seen_at) "
             "SELECT 'cap-' || g, 0, now() - interval '40 days' FROM generate_series(1, " +
                 std::to_string(OfflineEndpointStore::kPruneCapPerPass + 1) + ") g");

    const auto window = std::chrono::hours(24 * 30);
    CHECK(store.run_retention_prune(window) == 0); // bootstrap decline
    CHECK(store.run_retention_prune(window) == OfflineEndpointStore::kPruneCapPerPass);
    CHECK(store.run_retention_prune(window) == 1);
    CHECK(store.run_retention_prune(window) == 0);
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
    CHECK(store.run_retention_prune(std::chrono::hours(24 * 30)) == -1);

    // #4981 PR-1 (Finding B1): a store that never opened reports
    // PresenceReadError::StoreUnavailable on query_live_ids, never a silent
    // empty vector — the SAME "cannot answer" surface a live-but-degraded
    // read produces below.
    auto r = store.query_live_ids(std::chrono::hours(1));
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == PresenceReadError::StoreUnavailable);

    // #5531: same for the roster read.
    auto stale = store.query_stale_within(std::chrono::hours(1));
    REQUIRE_FALSE(stale.has_value());
    CHECK(stale.error() == PresenceReadError::StoreUnavailable);
}

// #4981 PR-1 (Finding B1): query_live_ids's typed failure surface. Genuine
// backend failure (DbError, deterministic lock-timeout fault injection — the
// established pattern in this repo, see test_result_set_store.cpp) and the
// new row-cap truncation case (Truncated). #5531: query_stale_within (the
// roster read) shares the same held lock — a failed read is never an empty
// vector and is counted under op=query_stale_within.
TEST_CASE("OfflineEndpointStore query_live_ids and query_stale_within report DbError on a "
          "genuine query failure - not a silent empty vector",
          "[pg][offline]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);

    PgPool short_lock_pool{{.conninfo = db.dsn(), .size = 2, .lock_timeout_ms = 100}};
    REQUIRE(short_lock_pool.valid());
    OfflineEndpointStore degraded_store{short_lock_pool};
    REQUIRE(degraded_store.is_open());
    yuzu::MetricsRegistry metrics;
    degraded_store.set_metrics(&metrics);

    yuzu::server::pg::PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(yuzu::server::pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);
    REQUIRE(yuzu::server::pg::exec_params(
                locker.get(), "LOCK TABLE endpoint_state.endpoints IN ACCESS EXCLUSIVE MODE",
                std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    auto degraded = degraded_store.query_live_ids(std::chrono::hours(1));
    REQUIRE_FALSE(degraded.has_value());
    CHECK(degraded.error() == PresenceReadError::DbError);

    auto degraded_stale = degraded_store.query_stale_within(std::chrono::hours(1));
    REQUIRE_FALSE(degraded_stale.has_value());
    CHECK(degraded_stale.error() == PresenceReadError::DbError);

    // Release the lock immediately: it also stalls heartbeat upserts.
    REQUIRE(yuzu::server::pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    CHECK(metrics
              .counter("yuzu_server_agent_presence_store_failed_total",
                       {{"op", "query_stale_within"}, {"reason", "db_error"}})
              .value() == 1);
    CHECK(metrics
              .counter("yuzu_server_agent_presence_store_failed_total",
                       {{"op", "query_stale_within"}, {"reason", "store_unavailable"}})
              .value() == 0);

    auto recovered = degraded_store.query_live_ids(std::chrono::hours(1));
    REQUIRE(recovered.has_value());
    auto recovered_stale = degraded_store.query_stale_within(std::chrono::hours(1));
    REQUIRE(recovered_stale.has_value());
}

// #5531. Kills: the no-lease arm of query_stale_within answering an empty
// success (or skipping the store_unavailable count) when the pool cannot
// lease a connection in time — the issue's motivating failure. Costs one
// bounded kQueryAcquireTimeout wait, hence [slow].
TEST_CASE("OfflineEndpointStore query_stale_within reports StoreUnavailable and counts it when "
          "the pool is exhausted",
          "[pg][offline][slow]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    auto held = pool.acquire(); // exhaust the single-connection pool
    REQUIRE(static_cast<bool>(held));

    auto r = store.query_stale_within(std::chrono::hours(1));
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == PresenceReadError::StoreUnavailable);
    CHECK(metrics
              .counter("yuzu_server_agent_presence_store_failed_total",
                       {{"op", "query_stale_within"}, {"reason", "store_unavailable"}})
              .value() == 1);
}

TEST_CASE("OfflineEndpointStore query_live_ids reports Truncated past kQueryRowCap, "
          "succeeds normally exactly at the cap",
          "[pg][offline][slow]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);

    SECTION("exactly kQueryRowCap rows: succeeds, no Truncated") {
        std::string sql =
            "INSERT INTO endpoint_state.endpoints (agent_id, hostname, os, last_heartbeat_ms, "
            "session_id) "
            "SELECT 'cap-'||g, 'h', 'linux', 0, 's' FROM generate_series(1, " +
            std::to_string(OfflineEndpointStore::kQueryRowCap) + ") g";
        PgResult ins{PQexec(conn.get(), sql.c_str())};
        REQUIRE(ins.ok());

        auto r = store.query_live_ids(std::chrono::hours(1));
        REQUIRE(r.has_value());
        CHECK(r->size() == static_cast<std::size_t>(OfflineEndpointStore::kQueryRowCap));
        CHECK(metrics
                  .counter("yuzu_server_agent_presence_store_failed_total",
                           {{"op", "query_live_ids"}, {"reason", "truncated"}})
                  .value() == 0);
    }

    SECTION("kQueryRowCap + 1 rows: Truncated, never a silently-partial vector") {
        std::string sql =
            "INSERT INTO endpoint_state.endpoints (agent_id, hostname, os, last_heartbeat_ms, "
            "session_id) "
            "SELECT 'cap-'||g, 'h', 'linux', 0, 's' FROM generate_series(1, " +
            std::to_string(OfflineEndpointStore::kQueryRowCap + 1) + ") g";
        PgResult ins{PQexec(conn.get(), sql.c_str())};
        REQUIRE(ins.ok());

        auto r = store.query_live_ids(std::chrono::hours(1));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == PresenceReadError::Truncated);
        CHECK(metrics
                  .counter("yuzu_server_agent_presence_store_failed_total",
                           {{"op", "query_live_ids"}, {"reason", "truncated"}})
                  .value() == 1);
    }
}
