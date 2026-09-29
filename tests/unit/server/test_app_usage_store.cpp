// AppUsageStore tests (wave 7 PR7.2): the born-on-Postgres per-executable
// last-used store — migration-at-construction, the raw-blob hash-skip
// trichotomy primitives (stored/touched/need-full), atomic full-replace, the
// staleness read, the decommission delete_agent (two-table, one txn, the
// hash-skip repopulation trap), and the authoritative-read posture
// (nullopt/kDegraded on a degrade, never a silent empty).

#include <catch2/catch_test_macros.hpp>

#include "app_usage_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::AgentLastUsedRow;
using yuzu::server::AppUsageReadError;
using yuzu::server::AppUsageStore;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;

namespace {

AgentLastUsedRow row(const std::string& exe_key, std::int64_t first_seen, std::int64_t last_seen,
                     std::int64_t run_count = 1, std::int64_t total_seconds = 60) {
    AgentLastUsedRow r;
    r.exe_key = exe_key;
    r.first_seen = first_seen;
    r.last_seen = last_seen;
    r.run_count_30d = run_count;
    r.total_seconds_30d = total_seconds;
    r.collected_at = last_seen;
    return r;
}

// ── Shared pre-migrated fixture (behaviour-preserving DB-provisioning swap) ──
// One migrated clone + one persistent pool for the whole FILE, TRUNCATE-reset
// between tests instead of a fresh CREATE DATABASE + new pool per test — the
// same substrate swap already applied in test_software_licensing_store.cpp.
// Behaviour-preserving: identical store calls + CHECKs; only the DB
// provisioning/isolation substrate changes. At testRunEnded the pool is drained
// and the clone dropped (keep_until_run_end), leaving static destruction inert.
// CARVE-OUT: the migration-at-construction test needs a genuinely fresh
// database (a clone would find schema_meta already current and skip
// migration, proving nothing) — it keeps its own per-test database
// (YUZU_REQUIRE_PG_DB).
yuzu::test::PgTestTemplate ausg_tpl{"ausgstore", [](const std::string& dsn) {
                                        PgPool pool{{.conninfo = dsn, .size = 1}};
                                        AppUsageStore store{pool};
                                        // Throw, don't return: a silently-unmigrated template
                                        // would make every clone fall back to in-test migration —
                                        // correct but slow, defeating the point.
                                        if (!store.is_open())
                                            throw std::runtime_error(
                                                "ausgstore template: store failed to migrate");
                                    }};

struct AusgShared {
    yuzu::test::PostgresTestDb db{ausg_tpl};
    std::optional<PgPool> pool;
    AusgShared() {
        REQUIRE(db.available());
        pool.emplace(PgPool::Options{.conninfo = db.dsn(), .size = 4});
        REQUIRE(pool->valid());
        db.keep_until_run_end([this]() noexcept { pool.reset(); });
    }
};
AusgShared& ausg_shared() {
    static AusgShared s;
    return s;
}

// Restore the shared DB to its fresh-clone state: TRUNCATE both data tables.
// public.schema_meta is deliberately untouched, so the per-test store ctor
// finds the schema current and skips migration (a cheap SELECT, no new
// backend).
void ausg_reset() {
    auto lease = ausg_shared().pool->acquire();
    REQUIRE(lease);
    auto trunc =
        pg::exec_params(lease.get(),
                        "TRUNCATE app_usage_store.usage_state, "
                        "app_usage_store.agent_last_used RESTART IDENTITY CASCADE",
                        std::vector<std::string>{});
    REQUIRE(trunc.status() == PGRES_COMMAND_OK);
}

// Preamble for a convertible test: same skip contract as YUZU_REQUIRE_PG_DB,
// then TRUNCATE-reset the shared DB and bind `pool` (reference to the
// persistent pool) + `store` (fresh; the ctor's migration check is a no-op on
// the already-migrated clone). `pool` is [[maybe_unused]] — most tests only
// touch `store`.
#define AUSG_SHARED(store, pool)                                                                   \
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {                                               \
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");                            \
    }                                                                                               \
    ausg_reset();                                                                                  \
    [[maybe_unused]] PgPool& pool = *ausg_shared().pool;                                           \
    AppUsageStore store{pool};                                                                     \
    REQUIRE(store.is_open())

} // namespace

TEST_CASE("AppUsageStore: opens and migrates on a fresh database", "[app_usage_store][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    AppUsageStore store{pool};
    CHECK(store.is_open());
}

TEST_CASE("AppUsageStore: stored_hash on a cold cache is a value holding nullopt",
          "[app_usage_store][pg]") {
    AUSG_SHARED(store, pool);
    auto result = store.stored_hash("never-seen-agent");
    REQUIRE(result.has_value());  // not degraded
    CHECK_FALSE(result->has_value()); // cold cache
}

TEST_CASE("AppUsageStore: replace_agent_last_used round-trips rows and the raw hash",
          "[app_usage_store][pg]") {
    AUSG_SHARED(store, pool);

    const std::string agent = "agent-1";
    std::vector<AgentLastUsedRow> rows = {row("chrome.exe", 1699000000, 1700000500, 12, 43200),
                                          row("word.exe", 1698000000, 1700000600, 3, 900)};
    REQUIRE(store.replace_agent_last_used(agent, rows, "hash-v1", 1700000900));

    auto stored = store.stored_hash(agent);
    REQUIRE(stored.has_value());
    REQUIRE(stored->has_value());
    CHECK(**stored == "hash-v1");

    auto got = store.get_agent_last_used(agent);
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 2);
    // exe_key-sorted.
    CHECK((*got)[0].exe_key == "chrome.exe");
    CHECK((*got)[0].run_count_30d == 12);
    CHECK((*got)[0].total_seconds_30d == 43200);
    CHECK((*got)[1].exe_key == "word.exe");

    auto collected = store.collected_at(agent);
    REQUIRE(collected.has_value());
    REQUIRE(collected->has_value());
    CHECK(**collected == 1700000900);
}

TEST_CASE("AppUsageStore: a second replace supersedes the first (old rows gone)",
          "[app_usage_store][pg]") {
    AUSG_SHARED(store, pool);

    const std::string agent = "agent-2";
    REQUIRE(store.replace_agent_last_used(
        agent, {row("chrome.exe", 1699000000, 1700000500)}, "hash-v1", 1700000500));
    REQUIRE(store.replace_agent_last_used(agent, {row("word.exe", 1698000000, 1700000600)},
                                          "hash-v2", 1700000600));

    auto got = store.get_agent_last_used(agent);
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 1);
    CHECK((*got)[0].exe_key == "word.exe");

    auto stored = store.stored_hash(agent);
    REQUIRE(stored.has_value());
    REQUIRE(stored->has_value());
    CHECK(**stored == "hash-v2");

    auto collected = store.collected_at(agent);
    REQUIRE(collected.has_value());
    REQUIRE(collected->has_value());
    CHECK(**collected == 1700000600); // the second replace's value wins
}

TEST_CASE("AppUsageStore: an empty rows replace is a legitimate replace-to-empty, and "
          "collected_at survives it (#C2)",
          "[app_usage_store][pg]") {
    AUSG_SHARED(store, pool);

    const std::string agent = "agent-3";
    REQUIRE(store.replace_agent_last_used(
        agent, {row("chrome.exe", 1699000000, 1700000500)}, "hash-v1", 1699000900));
    // The empty-snapshot replace's OWN collected_at — distinct from the prior
    // value above — must still land on usage_state even though there is no
    // agent_last_used row to carry it.
    REQUIRE(store.replace_agent_last_used(agent, {}, "hash-empty", 1699009999));

    auto got = store.get_agent_last_used(agent);
    REQUIRE(got.has_value());
    CHECK(got->empty());
    auto stored = store.stored_hash(agent);
    REQUIRE(stored.has_value());
    REQUIRE(stored->has_value());
    CHECK(**stored == "hash-empty");

    // The pinned regression: collected_at must be the empty replace's real
    // batch time (1699009999), NEVER 0 — 0 would be indistinguishable from
    // "never collected" and silently defeat the freshness signal for a
    // legitimate empty snapshot.
    auto collected = store.collected_at(agent);
    REQUIRE(collected.has_value());
    REQUIRE(collected->has_value());
    CHECK(**collected == 1699009999);
}

TEST_CASE("AppUsageStore: collected_at on a cold cache is a value holding nullopt",
          "[app_usage_store][pg]") {
    AUSG_SHARED(store, pool);
    auto result = store.collected_at("never-seen-agent");
    REQUIRE(result.has_value()); // not degraded
    CHECK_FALSE(result->has_value()); // cold cache
}

TEST_CASE("AppUsageStore: collected_at with an empty agent_id is an empty value, not a degrade",
          "[app_usage_store][pg]") {
    AUSG_SHARED(store, pool);
    auto result = store.collected_at("");
    REQUIRE(result.has_value());
    CHECK_FALSE(result->has_value());
}

TEST_CASE("AppUsageStore: touch bumps freshness without altering child rows or collected_at",
          "[app_usage_store][pg]") {
    AUSG_SHARED(store, pool);

    const std::string agent = "agent-4";
    REQUIRE(store.replace_agent_last_used(
        agent, {row("chrome.exe", 1699000000, 1700000500)}, "hash-v1", 1700000500));
    CHECK(store.touch(agent));

    auto stored = store.stored_hash(agent);
    REQUIRE(stored.has_value());
    REQUIRE(stored->has_value());
    CHECK(**stored == "hash-v1"); // touch never changes the hash
    auto got = store.get_agent_last_used(agent);
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 1);
    auto collected = store.collected_at(agent);
    REQUIRE(collected.has_value());
    REQUIRE(collected->has_value());
    CHECK(**collected == 1700000500); // touch never changes collected_at either
}

TEST_CASE("AppUsageStore: touch on a cold cache (no state row) fails",
          "[app_usage_store][pg]") {
    AUSG_SHARED(store, pool);
    CHECK_FALSE(store.touch("never-seen-agent"));
}

TEST_CASE("AppUsageStore: get_agent_last_used with an empty agent_id is an empty value, "
          "not a degrade",
          "[app_usage_store][pg]") {
    AUSG_SHARED(store, pool);
    auto got = store.get_agent_last_used("");
    REQUIRE(got.has_value());
    CHECK(got->empty());
}

// ── get_agent_usage_snapshot: the combined-transaction read (review finding) ─

TEST_CASE("AppUsageStore: get_agent_usage_snapshot returns rows + collected_at together, "
          "matching the two individual accessors",
          "[app_usage_store][pg]") {
    AUSG_SHARED(store, pool);
    const std::string agent = "agent-snap-1";
    REQUIRE(store.replace_agent_last_used(
        agent, {row("chrome.exe", 1699000000, 1700000500)}, "hash-snap-1", 1700000500));

    auto snap = store.get_agent_usage_snapshot(agent);
    REQUIRE(snap.has_value());
    REQUIRE(snap->rows.size() == 1);
    CHECK(snap->rows[0].exe_key == "chrome.exe");
    CHECK(snap->collected_at == 1700000500);

    // Cross-checked against the two individual accessors this method
    // replaces for callers that need both — same data, one transaction.
    auto rows = store.get_agent_last_used(agent);
    auto collected = store.collected_at(agent);
    REQUIRE(rows.has_value());
    REQUIRE(collected.has_value());
    REQUIRE(collected->has_value());
    CHECK(rows->size() == snap->rows.size());
    CHECK(**collected == snap->collected_at);
}

TEST_CASE("AppUsageStore: get_agent_usage_snapshot on a cold cache is empty rows + "
          "collected_at 0, not a degrade",
          "[app_usage_store][pg]") {
    AUSG_SHARED(store, pool);
    auto snap = store.get_agent_usage_snapshot("never-seen-agent-snap");
    REQUIRE(snap.has_value()); // not degraded — genuinely never collected
    CHECK(snap->rows.empty());
    CHECK(snap->collected_at == 0);
}

TEST_CASE("AppUsageStore: get_agent_usage_snapshot with an empty agent_id is an empty "
          "value, not a degrade",
          "[app_usage_store][pg]") {
    AUSG_SHARED(store, pool);
    auto snap = store.get_agent_usage_snapshot("");
    REQUIRE(snap.has_value());
    CHECK(snap->rows.empty());
    CHECK(snap->collected_at == 0);
}

TEST_CASE("AppUsageStore: get_agent_usage_snapshot on an empty-snapshot replace still "
          "carries the real collected_at, never 0 (#C2)",
          "[app_usage_store][pg]") {
    AUSG_SHARED(store, pool);
    const std::string agent = "agent-snap-empty";
    // A legitimate replace-to-empty (the store's own header banner: "the
    // retained-window projection can genuinely shrink to nothing") — the
    // pinned #C2 regression, now exercised through the combined accessor too.
    REQUIRE(store.replace_agent_last_used(agent, {}, "hash-snap-empty", 1699009999));

    auto snap = store.get_agent_usage_snapshot(agent);
    REQUIRE(snap.has_value());
    CHECK(snap->rows.empty());
    CHECK(snap->collected_at == 1699009999);
}

// ── delete_agent: the two-table decommission, and the hash-skip repopulation
//    trap it must never reopen (PLAN-01 ruling (b)) ─────────────────────────

TEST_CASE("AppUsageStore: delete_agent guards an empty id and reports commit status",
          "[app_usage_store][pg]") {
    AUSG_SHARED(store, pool);
    REQUIRE(store.replace_agent_last_used(
        "agent-5", {row("chrome.exe", 1699000000, 1700000500)}, "hash-v1", 1700000500));

    // Empty id: guarded — never a `WHERE agent_id = ''` — reports false, and
    // the real row is untouched.
    CHECK_FALSE(store.delete_agent(""));
    auto got = store.get_agent_last_used("agent-5");
    REQUIRE(got.has_value());
    CHECK_FALSE(got->empty());
}

TEST_CASE("AppUsageStore: delete_agent erases usage_state AND agent_last_used in one "
          "commit — pinned: post-delete stored_hash==nullopt and get_agent_last_used=={} "
          "(not nullopt)",
          "[app_usage_store][pg]") {
    AUSG_SHARED(store, pool);

    const std::string agent = "agent-6";
    REQUIRE(store.replace_agent_last_used(
        agent, {row("chrome.exe", 1699000000, 1700000500), row("word.exe", 1698000000, 1700000600)},
        "hash-v1", 1700000600));

    REQUIRE(store.delete_agent(agent));

    // The hash-skip repopulation trap (this package's spec): a delete that
    // cleared agent_last_used but left usage_state would make the still-
    // "enrolled" agent's next sync hash-only "touched", and the projection
    // would NEVER repopulate. Pin both halves of the erasure.
    auto stored = store.stored_hash(agent);
    REQUIRE(stored.has_value()); // not degraded
    CHECK_FALSE(stored->has_value()); // cold cache again — usage_state row is gone

    auto got = store.get_agent_last_used(agent);
    REQUIRE(got.has_value()); // AUTHORITATIVE: not a degrade
    CHECK(got->empty());      // empty VALUE (genuine zero rows), not nullopt

    // A real full resend after the delete must be accepted as a fresh cold
    // start (not "touched" against a resurrected hash).
    REQUIRE(store.replace_agent_last_used(
        agent, {row("chrome.exe", 1699000000, 1700000500)}, "hash-v2", 1700000501));
    auto got2 = store.get_agent_last_used(agent);
    REQUIRE(got2.has_value());
    REQUIRE(got2->size() == 1);
}

TEST_CASE("AppUsageStore: delete_agent on an agent with no rows still commits",
          "[app_usage_store][pg]") {
    AUSG_SHARED(store, pool);
    CHECK(store.delete_agent("agent-never-existed"));
}

TEST_CASE("AppUsageStore: count_stale_agents counts by last_seen threshold",
          "[app_usage_store][pg]") {
    AUSG_SHARED(store, pool);
    REQUIRE(store.replace_agent_last_used(
        "agent-stale-1", {row("chrome.exe", 1699000000, 1700000500)}, "h1", 1700000500));

    // Everything is fresh (last_seen == now()) relative to a threshold far in
    // the past, so the stale count is 0; relative to a threshold far in the
    // future, the freshly-written row counts as stale.
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    auto stale_past = store.count_stale_agents(now - 3600);
    REQUIRE(stale_past.has_value());
    CHECK(*stale_past == 0);

    auto stale_future = store.count_stale_agents(now + 3600);
    REQUIRE(stale_future.has_value());
    CHECK(*stale_future >= 1);
}

TEST_CASE("AppUsageStore: a store on an unreachable pool is closed and reads degrade",
          "[app_usage_store]") {
    PgPool pool{{.conninfo = "host=127.0.0.1 port=1 dbname=nope connect_timeout=1", .size = 1}};
    AppUsageStore store{pool};
    REQUIRE_FALSE(store.is_open());
    CHECK_FALSE(store.stored_hash("agent").has_value());
    CHECK_FALSE(store.touch("agent"));
    CHECK_FALSE(store.replace_agent_last_used("agent", {}, "h", 0));
    CHECK_FALSE(store.get_agent_last_used("agent").has_value());
    CHECK_FALSE(store.collected_at("agent").has_value());
    CHECK_FALSE(store.delete_agent("agent"));
    CHECK_FALSE(store.count_stale_agents(0).has_value());
}
