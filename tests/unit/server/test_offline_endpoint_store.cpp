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

#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

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
    return r->rows;
}

} // namespace

using yuzu::server::FleetPlatform;
using yuzu::server::fleet_platform_of;
using yuzu::server::partition_fleet_state;
using yuzu::server::fleet_estate_reading;
using yuzu::server::reconcile_fleet_estate;

TEST_CASE("fleet_platform_of puts every spelling in exactly one bucket", "[offline][fleet]") {
    for (const char* os : {"windows", "Windows", "WIN", "win"})
        CHECK(fleet_platform_of(os) == FleetPlatform::Windows);
    for (const char* os : {"linux", "Linux", "lin"})
        CHECK(fleet_platform_of(os) == FleetPlatform::Linux);
    for (const char* os : {"darwin", "Darwin", "macos", "MacOS", "mac"})
        CHECK(fleet_platform_of(os) == FleetPlatform::MacOs);
    for (const char* os : {"freebsd", "?", "", "unknown", "windows server", "linuxish"})
        CHECK(fleet_platform_of(os) == FleetPlatform::Other);
}

TEST_CASE("partition_fleet_state: segments always sum to the clamped total", "[offline][fleet]") {
    auto sum = [](const yuzu::server::FleetStatePartition& p) {
        return p.online + p.not_seen + p.offline;
    };
    SECTION("plain") {
        auto p = partition_fleet_state(100, 60, 30);
        CHECK(p.online == 60);
        CHECK(p.not_seen == 30);
        CHECK(p.offline == 10);
    }
    SECTION("online-and-stale overlap: stale is capped at what online leaves") {
        // 10 rows, 8 online, 6 heartbeat-stale: at least 4 stale rows are
        // online, so not_seen cannot exceed the 2 non-online rows.
        auto p = partition_fleet_state(10, 8, 6);
        CHECK(p.online == 8);
        CHECK(p.not_seen == 2);
        CHECK(p.offline == 0);
        CHECK(sum(p) == 10);
    }
    SECTION("online above total clamps; nothing negative") {
        auto p = partition_fleet_state(5, 9, 3);
        CHECK(p.online == 5);
        CHECK(p.not_seen == 0);
        CHECK(p.offline == 0);
    }
    SECTION("negative and zero inputs") {
        auto p = partition_fleet_state(-4, -1, -2);
        CHECK(sum(p) == 0);
        auto q = partition_fleet_state(7, -1, -2);
        CHECK(q.online == 0);
        CHECK(q.not_seen == 0);
        CHECK(q.offline == 7);
    }
}

TEST_CASE("reconcile_fleet_estate: a connected agent is never reported as an empty fleet",
          "[offline][fleet]") {
    SECTION("registry knows an agent the store has no row for: total widens, flagged lower bound") {
        // The failed-presence-upsert shape from the PR #5859 review: SQL total 0, registry 1.
        const auto r = reconcile_fleet_estate(0, 1, 0);
        CHECK(r.total == 1);
        CHECK(r.online == 1);
        CHECK(r.not_seen == 0);
        CHECK(r.offline == 0);
        CHECK(r.lower_bound);
    }
    SECTION("online above a non-empty total widens too, and the parts still sum") {
        const auto r = reconcile_fleet_estate(5, 9, 3);
        CHECK(r.total == 9);
        CHECK(r.online == 9);
        CHECK(r.online + r.not_seen + r.offline == r.total);
        CHECK(r.lower_bound);
    }
    SECTION("an honest store is passed through unflagged") {
        const auto r = reconcile_fleet_estate(100, 60, 30);
        CHECK(r.total == 100);
        CHECK(r.online == 60);
        CHECK(r.not_seen == 30);
        CHECK(r.offline == 10);
        CHECK_FALSE(r.lower_bound);
        const auto z = reconcile_fleet_estate(0, 0, 0);
        CHECK(z.total == 0);
        CHECK_FALSE(z.lower_bound);
    }
    SECTION("negative inputs never produce a negative figure") {
        const auto r = reconcile_fleet_estate(-4, -1, -2);
        CHECK(r.total == 0);
        CHECK(r.online == 0);
        CHECK_FALSE(r.lower_bound);
    }
}

TEST_CASE("fleet_estate_reading: the Dashboard's production input never reads a live fleet as "
          "empty",
          "[offline][fleet]") {
    yuzu::server::FleetStateCounts c;
    SECTION("registry ahead of an empty store: widened and flagged (the PR #5859 blocker)") {
        c.total = 0;
        c.live = 0;
        c.stale = 0;
        const auto r = fleet_estate_reading(c, std::size_t{1});
        CHECK(r.total == 1);
        CHECK(r.online == 1);
        CHECK(r.lower_bound);
    }
    SECTION("registry unavailable: the SQL durable-live count stands in") {
        c.total = 10;
        c.live = 7;
        c.stale = 2;
        const auto r = fleet_estate_reading(c, std::nullopt);
        CHECK(r.total == 10);
        CHECK(r.online == 7);
        CHECK_FALSE(r.lower_bound);
    }
    SECTION("registry ahead of the store's live count but still under total: flagged too") {
        c.total = 10; // 4 offline rows; 2 connected agents have no row
        c.live = 6;
        c.stale = 0;
        const auto r = fleet_estate_reading(c, std::size_t{8});
        CHECK(r.total == 10);
        CHECK(r.online == 8);
        CHECK(r.lower_bound); // total and the offline split understate
    }
    SECTION("registry agrees with the store: passed through unflagged") {
        c.total = 10;
        c.live = 7;
        c.stale = 2;
        const auto r = fleet_estate_reading(c, std::size_t{7});
        CHECK(r.online == 7);
        CHECK(r.online + r.not_seen + r.offline == r.total);
        CHECK_FALSE(r.lower_bound);
    }
}

TEST_CASE("OfflineEndpointStore fleet_state_counts tallies in SQL by window, stale and platform",
          "[pg][offline][fleet]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    constexpr std::int64_t kNow = 1'800'000'000'000;
    constexpr std::int64_t kHour = 3'600'000;
    constexpr std::int64_t kDay = 24 * kHour;
    const std::chrono::seconds window{30 * 24 * 3600};
    const std::chrono::milliseconds stale_after{2 * kDay};

    // fresh: win x2 (spellings), linux, darwin, freebsd (Other)
    REQUIRE(store.upsert("w1", "h", "windows", kNow - kHour, 0));
    REQUIRE(store.upsert("w2", "h", "WIN", kNow - kHour, 0));
    REQUIRE(store.upsert("l1", "h", "linux", kNow - kHour, 0));
    REQUIRE(store.upsert("m1", "h", "darwin", kNow - kHour, 0));
    REQUIRE(store.upsert("o1", "h", "freebsd", kNow - kHour, 0));
    // stale (older than 2 d, inside the 30 d window)
    REQUIRE(store.upsert("l2", "h", "Linux", kNow - 3 * kDay, 0));
    REQUIRE(store.upsert("b1", "h", "", kNow - 5 * kDay, 0));
    // outside the window: must not be counted at all
    REQUIRE(store.upsert("gone", "h", "linux", kNow - 40 * kDay, 0));

    auto c = store.fleet_state_counts(kNow, window, stale_after, std::chrono::seconds{90});
    REQUIRE(c.has_value());
    CHECK(c->total == 7);
    CHECK(c->stale == 2);
    CHECK(c->windows == 2);
    CHECK(c->linux_os == 2);
    CHECK(c->macos == 1);
    CHECK(c->other == 2);
    CHECK(c->windows + c->linux_os + c->macos + c->other == c->total);
}

TEST_CASE("OfflineEndpointStore fleet_state_counts live count matches query_live_ids, uncapped",
          "[pg][offline][fleet]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    constexpr std::int64_t kNow = 1'800'000'000'000;
    const std::chrono::seconds window{3600};
    const std::chrono::milliseconds stale_after{1000};
    REQUIRE(store.upsert("a", "h", "linux", kNow, 0, "", "", "s-a"));
    REQUIRE(store.upsert("b", "h", "linux", kNow, 0, "", "", "s-b"));
    REQUIRE(store.upsert("c", "h", "linux", kNow, 0, "", "", "s-c"));
    REQUIRE(store.upsert("nosess", "h", "linux", kNow, 0)); // blank session: not live
    REQUIRE(store.remove_if_session("c", "s-c"));           // departed: not live

    auto c = store.fleet_state_counts(kNow, window, stale_after, std::chrono::seconds{3600});
    REQUIRE(c.has_value());
    CHECK(c->total == 4);
    CHECK(c->live == 2);
    auto ids = store.query_live_ids(std::chrono::seconds{3600});
    REQUIRE(ids.has_value());
    CHECK(static_cast<std::int64_t>(ids->size()) == c->live);

    // A TTL no row can satisfy (last_seen_at is now(), strictly before the read).
    auto none = store.fleet_state_counts(kNow, window, stale_after, std::chrono::seconds{0});
    REQUIRE(none.has_value());
    CHECK(none->live == 0);
}

TEST_CASE("OfflineEndpointStore fleet_state_counts stays exact past kQueryRowCap",
          "[pg][offline][fleet]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    constexpr std::int64_t kNow = 1'800'000'000'000;
    const int rows = OfflineEndpointStore::kQueryRowCap + 1;
    {
        auto lease = pool.acquire();
        REQUIRE(static_cast<bool>(lease));
        PgResult r{PQexec(lease.get(),
                          ("INSERT INTO endpoint_state.endpoints "
                           "(agent_id, hostname, os, last_heartbeat_ms, agent_ts, session_id) "
                           "SELECT 'cap-' || g, 'h', 'linux', " +
                           std::to_string(kNow) + ", 0, 's-' || g FROM generate_series(1, " +
                           std::to_string(rows) + ") g")
                              .c_str())};
        REQUIRE(r.ok());
    }
    // query_live_ids refuses past the cap; the SQL tally does not.
    auto ids = store.query_live_ids(std::chrono::hours(1));
    REQUIRE_FALSE(ids.has_value());
    CHECK(ids.error() == PresenceReadError::Truncated);

    auto c = store.fleet_state_counts(kNow, std::chrono::hours(1), std::chrono::milliseconds{1000},
                                      std::chrono::hours(1));
    REQUIRE(c.has_value());
    CHECK(c->total == rows);
    CHECK(c->live == rows);
    CHECK(c->linux_os == rows);
}

TEST_CASE("OfflineEndpointStore fleet_state_counts is StoreUnavailable on a store that never opened",
          "[offline][fleet]") {
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    OfflineEndpointStore store{pool};
    REQUIRE_FALSE(store.is_open());
    auto r = store.fleet_state_counts(1'800'000'000'000, std::chrono::hours(1),
                                      std::chrono::milliseconds{1000}, std::chrono::seconds{90});
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == PresenceReadError::StoreUnavailable);
}

TEST_CASE("OfflineEndpointStore fleet_state_counts is an error, never a zero struct, when the "
          "store cannot answer",
          "[pg][offline][fleet]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    PgPool short_lock_pool{{.conninfo = db.dsn(), .size = 2, .lock_timeout_ms = 100}};
    REQUIRE(short_lock_pool.valid());
    OfflineEndpointStore store{short_lock_pool};
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    yuzu::server::pg::PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(yuzu::server::pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);
    REQUIRE(yuzu::server::pg::exec_params(
                locker.get(), "LOCK TABLE endpoint_state.endpoints IN ACCESS EXCLUSIVE MODE",
                std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    auto r = store.fleet_state_counts(1'800'000'000'000, std::chrono::hours(1),
                                      std::chrono::milliseconds{1000}, std::chrono::seconds{90});
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == PresenceReadError::DbError);

    REQUIRE(yuzu::server::pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);
    CHECK(metrics
              .counter("yuzu_server_agent_presence_store_failed_total",
                       {{"op", "fleet_state_counts"}, {"reason", "db_error"}})
              .value() == 1);
}

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

// ── #5712: the roster read reports a cap hit as a typed PARTIAL; find_within is exact ──────────

namespace {

// `rows` endpoints `cap-1` .. `cap-N`, heartbeats now-1ms .. now-Nms, so `cap-1` is the newest and
// the ordering at the cut is fully determined (no ties for the tiebreak-free ORDER BY to resolve).
void seed_roster(PgConn& conn, int rows) {
    const std::string sql =
        "INSERT INTO endpoint_state.endpoints (agent_id, hostname, os, last_heartbeat_ms, agent_ts) "
        "SELECT 'cap-' || g, 'h', 'linux', " + std::to_string(now_ms()) +
        " - g, 0 FROM generate_series(1, " + std::to_string(rows) + ") g";
    PgResult ins{PQexec(conn.get(), sql.c_str())};
    REQUIRE(ins.ok());
}

} // namespace

// Kills: a cap hit read as the complete roster (the #5712 silent truncation); a cap hit returned as
// `unexpected(Truncated)` (the #5371 refusal trap — a display read that never clears); an exactly-cap
// fleet flagged partial; the extra row leaking into the served set; the oldest row surviving the cut;
// a flag that latches once set; and no counter for the partial.
TEST_CASE("OfflineEndpointStore query_stale_within serves a typed partial past kQueryRowCap, "
          "complete exactly at the cap",
          "[pg][offline][slow][roster_truncated]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    yuzu::MetricsRegistry metrics; // declared before the store: it outlives it, as in ServerImpl
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());
    store.set_metrics(&metrics);

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    const auto cap = static_cast<std::size_t>(OfflineEndpointStore::kQueryRowCap);
    auto truncated_count = [&] {
        return metrics.counter("yuzu_server_agent_presence_roster_truncated_total").value();
    };

    SECTION("exactly kQueryRowCap rows: complete, not truncated") {
        seed_roster(conn, OfflineEndpointStore::kQueryRowCap);
        auto r = store.query_stale_within(std::chrono::hours(1));
        REQUIRE(r.has_value());
        CHECK(r->rows.size() == cap);
        CHECK_FALSE(r->truncated);
        CHECK(truncated_count() == 0);
    }

    SECTION("kQueryRowCap + 1 rows: a SUCCESS carrying the newest cap rows, flagged truncated") {
        seed_roster(conn, OfflineEndpointStore::kQueryRowCap + 1);
        auto r = store.query_stale_within(std::chrono::hours(1));
        REQUIRE(r.has_value()); // never unexpected(Truncated): a partial is served, not refused
        CHECK(r->truncated);
        REQUIRE(r->rows.size() == cap); // the extra detection row is dropped, not served
        CHECK(r->rows.front().agent_id == "cap-1"); // newest first
        CHECK(find(r->rows, "cap-" + std::to_string(OfflineEndpointStore::kQueryRowCap)) != nullptr);
        CHECK(find(r->rows, "cap-" + std::to_string(OfflineEndpointStore::kQueryRowCap + 1)) == nullptr);
        CHECK(truncated_count() == 1);
        // It is NOT a failure: the failure counter family stays untouched by a partial.
        CHECK(metrics
                  .counter("yuzu_server_agent_presence_store_failed_total",
                           {{"op", "query_stale_within"}, {"reason", "truncated"}})
                  .value() == 0);

        // Self-clearing: the flag is derived per read, so the fleet dropping back to the cap clears it.
        PgResult del{PQexec(conn.get(),
                            ("DELETE FROM endpoint_state.endpoints WHERE agent_id = 'cap-" +
                             std::to_string(OfflineEndpointStore::kQueryRowCap + 1) + "'")
                                .c_str())};
        REQUIRE(del.ok());
        auto again = store.query_stale_within(std::chrono::hours(1));
        REQUIRE(again.has_value());
        CHECK_FALSE(again->truncated);
        CHECK(again->rows.size() == cap);
        CHECK(truncated_count() == 1); // no second increment for a complete read
    }
}

// The AC3 harm itself (#5531 reached through the cap): an enrolled offline device OLDER than the
// newest cap is absent from the capped roster, so the old identity scan read it as "not found".
// Kills: find_within degrading to a roster scan (would miss it too), an empty answer for an in-window
// row, and any disagreement with query_stale_within about which rows are inside the window.
TEST_CASE("OfflineEndpointStore find_within is exact for a device beyond kQueryRowCap",
          "[pg][offline][slow][roster_truncated]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    seed_roster(conn, OfflineEndpointStore::kQueryRowCap + 5);

    const std::string beyond = "cap-" + std::to_string(OfflineEndpointStore::kQueryRowCap + 5);
    auto roster = store.query_stale_within(std::chrono::hours(1));
    REQUIRE(roster.has_value());
    CHECK(roster->truncated);
    CHECK(find(roster->rows, beyond) == nullptr); // the roster scan cannot see it ...

    auto hit = store.find_within(beyond, std::chrono::hours(1));
    REQUIRE(hit.has_value());
    REQUIRE(hit->has_value()); // ... the point read can
    CHECK((*hit)->agent_id == beyond);
    CHECK((*hit)->hostname == "h");
    CHECK((*hit)->os == "linux");
}

TEST_CASE("OfflineEndpointStore find_within: hit, confirmed absence, and the roster's own window",
          "[pg][offline][roster_truncated]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    const std::int64_t kNow = now_ms();
    constexpr std::int64_t kMinute = 60'000;
    REQUIRE(store.upsert("fw-in", "host-in", "linux", kNow - 10 * kMinute, 77, "1.2.3", "x86_64"));
    REQUIRE(store.upsert("fw-out", "host-out", "linux", kNow - 120 * kMinute, 0));

    // A row inside the window: every mapped column survives the shared row reader.
    auto in = store.find_within("fw-in", std::chrono::hours(1));
    REQUIRE(in.has_value());
    REQUIRE(in->has_value());
    CHECK((*in)->hostname == "host-in");
    CHECK((*in)->os == "linux");
    CHECK((*in)->last_heartbeat_ms == kNow - 10 * kMinute);
    CHECK((*in)->agent_ts == 77);
    CHECK((*in)->agent_version == "1.2.3");
    CHECK((*in)->arch == "x86_64");

    // A row outside the window, and one that never existed: both are a CONFIRMED absence (an engaged
    // read with an empty optional), never an error.
    auto out = store.find_within("fw-out", std::chrono::hours(1));
    REQUIRE(out.has_value());
    CHECK_FALSE(out->has_value());
    auto none = store.find_within("fw-never", std::chrono::hours(1));
    REQUIRE(none.has_value());
    CHECK_FALSE(none->has_value());

    // The point read and the roster scan must agree on membership, row for row.
    const auto roster = stale_ok(store, std::chrono::hours(1));
    CHECK(find(roster, "fw-in") != nullptr);
    CHECK(find(roster, "fw-out") == nullptr);
    // Widening the window brings the old row into BOTH reads.
    auto wide = store.find_within("fw-out", std::chrono::hours(3));
    REQUIRE(wide.has_value());
    CHECK(wide->has_value());
    CHECK(find(stale_ok(store, std::chrono::hours(3)), "fw-out") != nullptr);
}

TEST_CASE("OfflineEndpointStore find_within is StoreUnavailable on a store that never opened",
          "[offline][roster_truncated]") {
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    OfflineEndpointStore store{pool};
    REQUIRE_FALSE(store.is_open());
    auto r = store.find_within("any", std::chrono::hours(1));
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == PresenceReadError::StoreUnavailable);
}

// Kills: a failed point read answered as "absent" (the false "not found" this whole change exists to
// remove, reached through a DB fault instead of the cap); the failures going uncounted.
TEST_CASE("OfflineEndpointStore find_within reports DbError and StoreUnavailable, counted under "
          "op=find_within, never an absence",
          "[pg][offline][slow][roster_truncated]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);

    SECTION("DbError on a genuine query failure") {
        yuzu::MetricsRegistry metrics;
        PgPool short_lock_pool{{.conninfo = db.dsn(), .size = 2, .lock_timeout_ms = 100}};
        REQUIRE(short_lock_pool.valid());
        OfflineEndpointStore store{short_lock_pool};
        REQUIRE(store.is_open());
        store.set_metrics(&metrics);

        yuzu::server::pg::PgConn locker{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
        REQUIRE(yuzu::server::pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);
        REQUIRE(yuzu::server::pg::exec_params(
                    locker.get(), "LOCK TABLE endpoint_state.endpoints IN ACCESS EXCLUSIVE MODE",
                    std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);

        auto r = store.find_within("a1", std::chrono::hours(1));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == PresenceReadError::DbError);
        REQUIRE(yuzu::server::pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);
        CHECK(metrics
                  .counter("yuzu_server_agent_presence_store_failed_total",
                           {{"op", "find_within"}, {"reason", "db_error"}})
                  .value() == 1);
    }

    SECTION("StoreUnavailable when the pool is exhausted") {
        yuzu::MetricsRegistry metrics;
        PgPool pool{{.conninfo = db.dsn(), .size = 1}};
        REQUIRE(pool.valid());
        OfflineEndpointStore store{pool};
        REQUIRE(store.is_open());
        store.set_metrics(&metrics);

        auto held = pool.acquire();
        REQUIRE(static_cast<bool>(held));
        auto r = store.find_within("a1", std::chrono::hours(1));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == PresenceReadError::StoreUnavailable);
        CHECK(metrics
                  .counter("yuzu_server_agent_presence_store_failed_total",
                           {{"op", "find_within"}, {"reason", "store_unavailable"}})
                  .value() == 1);
    }
}

// The new counter exists from the moment metrics are attached, so a Prometheus scrape sees the
// series at 0 before the first cap hit (rate() over a never-created series reads as absent).
TEST_CASE("OfflineEndpointStore pre-seeds the roster-truncated counter at zero",
          "[pg][offline][roster_truncated]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    yuzu::MetricsRegistry metrics;
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    store.set_metrics(&metrics);
    CHECK(metrics.serialize().find("yuzu_server_agent_presence_roster_truncated_total 0") !=
          std::string::npos);
}

// The point read's two failure series exist at 0 once metrics are attached, so the first failure
// is an increase() from 0 and not a series born at 1. Kills: dropping the pre-seed in set_metrics.
TEST_CASE("OfflineEndpointStore pre-seeds the find_within failure series at zero",
          "[offline][roster_truncated]") {
    yuzu::MetricsRegistry metrics;
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 1}};
    OfflineEndpointStore store{pool};
    store.set_metrics(&metrics);
    const auto text = metrics.serialize();
    for (const char* reason : {"store_unavailable", "db_error"}) {
        const std::string series =
            std::string("yuzu_server_agent_presence_store_failed_total{op=\"find_within\",reason=\"") +
            reason + "\"} 0";
        INFO(series);
        CHECK(text.find(series) != std::string::npos);
    }
}

// A malformed agent_id (a NUL byte, ill-formed UTF-8) can never be a stored key, so find_within
// answers a CONFIRMED absence for it without a store read: no failure counter, no warn, no "store
// unavailable" for an input that can never succeed. The roster scan this replaces answered absent too.
// Kills: the id reaching Postgres (SQLSTATE 22021 / the NUL guard) and surfacing as a DbError that
// marks the identity read degraded and bumps `op=find_within,reason=db_error` for a fuzzer's input.
TEST_CASE("OfflineEndpointStore find_within answers a malformed agent_id as a confirmed absence",
          "[offline][roster_truncated]") {
    const std::vector<std::string> malformed = {
        std::string("\xFF"),                 // stray continuation / invalid lead byte
        std::string("a\xC3"),                // truncated two-byte sequence
        std::string("\xC0\xAF"),             // overlong encoding of '/'
        std::string("\xED\xA0\x80"),         // a UTF-16 surrogate
        std::string("a\0b", 3),              // an embedded NUL
    };
    SECTION("on a store that never opened: still an absence, not StoreUnavailable") {
        PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
        OfflineEndpointStore store{pool};
        REQUIRE_FALSE(store.is_open());
        for (const auto& id : malformed) {
            auto r = store.find_within(id, std::chrono::hours(1));
            REQUIRE(r.has_value());
            CHECK_FALSE(r->has_value());
        }
        // A well-formed id on the same store is still a store failure (the pre-check is narrow).
        auto ok = store.find_within("fine-id", std::chrono::hours(1));
        REQUIRE_FALSE(ok.has_value());
        CHECK(ok.error() == PresenceReadError::StoreUnavailable);
    }
    SECTION("a valid multibyte id is NOT malformed and reaches the store") {
        PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
        OfflineEndpointStore store{pool};
        auto r = store.find_within("h\xC3\xA9llo-\xE2\x82\xAC", std::chrono::hours(1)); // "héllo-€"
        REQUIRE_FALSE(r.has_value()); // store not open => StoreUnavailable, proving it was not short-circuited
        CHECK(r.error() == PresenceReadError::StoreUnavailable);
    }
}

TEST_CASE("OfflineEndpointStore find_within: a malformed id on an open store counts no failure",
          "[pg][offline][roster_truncated]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    yuzu::MetricsRegistry metrics;
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());
    store.set_metrics(&metrics);
    REQUIRE(store.upsert("real", "h", "linux", now_ms(), 0));

    for (const std::string& id : {std::string("\xFF"), std::string("a\0b", 3), std::string("\xC0\xAF")}) {
        auto r = store.find_within(id, std::chrono::hours(1));
        REQUIRE(r.has_value());
        CHECK_FALSE(r->has_value());
    }
    for (const char* reason : {"db_error", "store_unavailable"})
        CHECK(metrics
                  .counter("yuzu_server_agent_presence_store_failed_total",
                           {{"op", "find_within"}, {"reason", reason}})
                  .value() == 0);
    // The store is unharmed: a valid id right after still resolves.
    auto hit = store.find_within("real", std::chrono::hours(1));
    REQUIRE(hit.has_value());
    CHECK(hit->has_value());
}

// Ties at the cut. The roster orders by last_heartbeat_ms only (the sole index), so rows sharing the
// cutoff millisecond are cut arbitrarily: WHICH of them survive may differ between reads, but the
// flag, the served count, uniqueness, newest-first order and every row ABOVE the tie group may not.
// 99,950 distinct newer rows + 100 rows on one older millisecond: the cap cuts through the tie group.
// Kills: a duplicate row served across the cut, a short or long page, a flag that depends on the
// tie, and a non-monotone order.
TEST_CASE("OfflineEndpointStore query_stale_within: a tie group straddling the cut keeps flag, count, "
          "uniqueness and order stable",
          "[pg][offline][slow][roster_truncated]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());
    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);

    const int cap = OfflineEndpointStore::kQueryRowCap;
    const int distinct = cap - 50;
    const std::int64_t t0 = now_ms();
    const std::string hi =
        "INSERT INTO endpoint_state.endpoints (agent_id, hostname, os, last_heartbeat_ms, agent_ts) "
        "SELECT 'hi-' || g, 'h', 'linux', " + std::to_string(t0) + " - 1000 - g, 0 FROM generate_series(1, " +
        std::to_string(distinct) + ") g";
    const std::string tie =
        "INSERT INTO endpoint_state.endpoints (agent_id, hostname, os, last_heartbeat_ms, agent_ts) "
        "SELECT 'tie-' || g, 'h', 'linux', " + std::to_string(t0) + " - 200000, 0 FROM generate_series(1, 100) g";
    PgResult a{PQexec(conn.get(), hi.c_str())};
    REQUIRE(a.ok());
    PgResult b{PQexec(conn.get(), tie.c_str())};
    REQUIRE(b.ok());

    std::vector<std::string> above_first;
    for (int pass = 0; pass < 3; ++pass) {
        auto r = store.query_stale_within(std::chrono::hours(1));
        REQUIRE(r.has_value());
        CHECK(r->truncated);
        REQUIRE(r->rows.size() == static_cast<std::size_t>(cap));

        std::set<std::string> seen;
        std::int64_t prev = std::numeric_limits<std::int64_t>::max();
        std::size_t ties = 0;
        std::vector<std::string> above;
        for (const auto& e : r->rows) {
            CHECK(seen.insert(e.agent_id).second); // no duplicate across the cut
            CHECK(e.last_heartbeat_ms <= prev);    // newest first, monotone non-increasing
            prev = e.last_heartbeat_ms;
            if (e.agent_id.rfind("tie-", 0) == 0)
                ++ties;
            else
                above.push_back(e.agent_id);
        }
        CHECK(ties == 50);                                          // exactly the room left under the cap
        CHECK(above.size() == static_cast<std::size_t>(distinct)); // every row above the tie group survives
        if (pass == 0)
            above_first = above;
        else
            CHECK(above == above_first); // only the tie group may rotate between reads
    }
    // The point read is exact for EVERY tie row, whether or not the roster served it.
    for (int g = 1; g <= 100; ++g) {
        auto hit = store.find_within("tie-" + std::to_string(g), std::chrono::hours(1));
        REQUIRE(hit.has_value());
        CHECK(hit->has_value());
    }
}

// The counter is bumped from every HTTP worker that renders an over-cap roster. Two readers, a few
// reads each, against one seeded over-cap table: every read is truncated and the counter equals the
// number of reads (a lost increment, or a latched flag, breaks the equality). Sized small on purpose:
// each read materialises 100,001 rows and the CI runners share one box (#1871).
TEST_CASE("OfflineEndpointStore query_stale_within: concurrent truncated reads each count once",
          "[pg][offline][slow][roster_truncated]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    yuzu::MetricsRegistry metrics;
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());
    store.set_metrics(&metrics);
    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    seed_roster(conn, OfflineEndpointStore::kQueryRowCap + 1);

    constexpr int kThreads = 2;
    constexpr int kReadsEach = 2;
    std::atomic<int> truncated_seen{0};
    std::atomic<int> failed{0};
    std::vector<std::thread> readers;
    readers.reserve(kThreads);
    // Joins on every exit path (std::jthread is not available on Apple Clang's libc++): a throw
    // after the first thread starts must not reach ~thread() on a joinable thread (std::terminate).
    struct JoinAll {
        std::vector<std::thread>& threads;
        ~JoinAll() {
            for (auto& th : threads)
                if (th.joinable())
                    th.join();
        }
    } join_all{readers};
    for (int t = 0; t < kThreads; ++t)
        readers.emplace_back([&] {
            for (int i = 0; i < kReadsEach; ++i) {
                auto r = store.query_stale_within(std::chrono::hours(1));
                if (!r.has_value())
                    ++failed;
                else if (r->truncated && r->rows.size() == static_cast<std::size_t>(OfflineEndpointStore::kQueryRowCap))
                    ++truncated_seen;
            }
        });
    for (auto& th : readers)
        th.join();

    CHECK(failed.load() == 0);
    CHECK(truncated_seen.load() == kThreads * kReadsEach);
    CHECK(metrics.counter("yuzu_server_agent_presence_roster_truncated_total").value() ==
          static_cast<double>(kThreads * kReadsEach));
}

// HA WS-5 #5685 follow-up (plugin-capability visibility, migration v5: `endpoint_plugins`).
TEST_CASE("OfflineEndpointStore plugin lists (session-keyed and served only for the current "
          "session and quoted and capped and cascaded and truncation-typed)",
          "[pg][offline][ha][plugin_visibility]") {
    YUZU_REQUIRE_PG_DB_TPL(db, offline_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());
    const auto ttl = std::chrono::hours(1);
    const auto without = [&](std::string_view plugin) {
        auto r = store.query_live_ids_without_plugin(ttl, plugin);
        REQUIRE(r.has_value());
        return *r;
    };
    using Ids = std::vector<std::string>;

    // has-echo, lacks-echo, never-published (unknown), lacks-echo-but-departed.
    REQUIRE(store.upsert("yuzu_test_pv_has", "h", "linux", 1, 0, "1", "x", "s1"));
    REQUIRE(store.publish_plugins("yuzu_test_pv_has", "s1", {"echo", "os_info"}));
    REQUIRE(store.upsert("yuzu_test_pv_lacks", "h", "linux", 1, 0, "1", "x", "s2"));
    REQUIRE(store.publish_plugins("yuzu_test_pv_lacks", "s2", {"os_info"}));
    REQUIRE(store.upsert("yuzu_test_pv_unknown", "h", "linux", 1, 0, "1", "x", "s3"));
    REQUIRE(store.upsert("yuzu_test_pv_gone", "h", "linux", 1, 0, "1", "x", "s4"));
    REQUIRE(store.publish_plugins("yuzu_test_pv_gone", "s4", {"os_info"}));
    REQUIRE(store.remove_if_session("yuzu_test_pv_gone", "s4")); // graceful disconnect
    CHECK(without("echo") == Ids{"yuzu_test_pv_lacks"}); // unknown and departed excluded

    SECTION("a heartbeat that passes no session or list leaves the published list alone") {
        REQUIRE(store.upsert("yuzu_test_pv_lacks", "", "", 2, 0, "", "", ""));
        CHECK(without("echo") == Ids{"yuzu_test_pv_lacks"});
    }

    SECTION("a NEW session with no published list reads as unknown, then republishes") {
        // The list belongs to the session that reported it: once the row moves to s2b the old
        // list is not served (fail open), whatever the old list said.
        REQUIRE(store.upsert("yuzu_test_pv_lacks", "", "", 3, 0, "", "", "s2b"));
        CHECK(without("echo").empty());
        REQUIRE(store.publish_plugins("yuzu_test_pv_lacks", "s2b", {"echo"}));
        CHECK(without("echo").empty()); // the new list HAS echo
        CHECK(without("os_info") == Ids{"yuzu_test_pv_lacks"});
    }

    SECTION("a row older than the ttl is excluded") {
        exec_sql(db.dsn(), "UPDATE endpoint_state.endpoints SET last_seen_at = now() - interval "
                           "'2 hours' WHERE agent_id = 'yuzu_test_pv_lacks'");
        CHECK(without("echo").empty());
    }

    SECTION("names are stored as plain text: quotes, braces and NULL are never array syntax") {
        REQUIRE(store.upsert("yuzu_test_pv_inject", "h", "linux", 1, 0, "1", "x", "s5"));
        REQUIRE(store.publish_plugins("yuzu_test_pv_inject", "s5",
                                      {"echo\",\"x", "a}b", "NULL", "os_info"}));
        const auto lacking_echo = without("echo");
        CHECK(std::ranges::find(lacking_echo, "yuzu_test_pv_inject") != lacking_echo.end());
        // "NULL" is an element like any other, so a plugin of that name is present, not absent.
        const auto lacking_null = without("NULL");
        CHECK(std::ranges::find(lacking_null, "yuzu_test_pv_inject") == lacking_null.end());
    }

    SECTION("an empty list, or one of only unusable names, publishes nothing") {
        CHECK_FALSE(store.publish_plugins("yuzu_test_pv_lacks", "s2", {}));
        CHECK_FALSE(store.publish_plugins("yuzu_test_pv_lacks", "s2", {"", std::string(65, 'x')}));
        CHECK_FALSE(store.publish_plugins("yuzu_test_pv_lacks", "", {"echo"}));
        CHECK(without("echo") == Ids{"yuzu_test_pv_lacks"}); // unchanged
    }

    SECTION("a list is capped at kMaxPublishedPlugins names") {
        std::vector<std::string> many;
        for (std::size_t n = 0; n < OfflineEndpointStore::kMaxPublishedPlugins + 40; ++n)
            many.push_back("p" + std::to_string(n));
        REQUIRE(store.upsert("yuzu_test_pv_many", "h", "linux", 1, 0, "1", "x", "s6"));
        REQUIRE(store.publish_plugins("yuzu_test_pv_many", "s6", many));
        const auto kept = without("p0");     // inside the cap: present
        const auto dropped = without("p299"); // past it: dropped, so it reads as absent
        CHECK(std::ranges::find(kept, "yuzu_test_pv_many") == kept.end());
        CHECK(std::ranges::find(dropped, "yuzu_test_pv_many") != dropped.end());
    }

    SECTION("deleting the endpoint (decommission, retention) cascades to its list") {
        REQUIRE(store.delete_agent("yuzu_test_pv_lacks"));
        REQUIRE(store.upsert("yuzu_test_pv_lacks", "h", "linux", 1, 0, "1", "x", "s2"));
        CHECK(without("echo").empty()); // same session id, but the old list is gone: unknown
    }

    SECTION("a result past kQueryRowCap is Truncated, never a partial set") {
        exec_sql(db.dsn(),
                 "INSERT INTO endpoint_state.endpoints (agent_id, last_heartbeat_ms, session_id) "
                 "SELECT 'cap-' || g, 1, 's-' || g FROM generate_series(1, " +
                     std::to_string(OfflineEndpointStore::kQueryRowCap + 1) + ") g");
        exec_sql(db.dsn(), "INSERT INTO endpoint_state.endpoint_plugins "
                           "SELECT agent_id, session_id, ARRAY['os_info'] "
                           "FROM endpoint_state.endpoints WHERE agent_id LIKE 'cap-%'");
        auto r = store.query_live_ids_without_plugin(ttl, "echo");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == PresenceReadError::Truncated);
    }
}
