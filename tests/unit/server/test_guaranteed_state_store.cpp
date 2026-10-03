/**
 * test_guaranteed_state_store.cpp — Unit tests for GuaranteedStateStore
 *
 * Covers:
 *   - schema migration applies cleanly against a fresh in-memory DB
 *   - rule CRUD round-trip (create / get / list / update / delete)
 *   - event insert + query with filtering
 *   - UNIQUE(name) and PRIMARY KEY rejection surface as kConflictPrefix errors
 *   - unknown-rule update/delete return a non-conflict error
 *   - signature BLOB round-trip (incl. empty vs non-empty)
 *   - query_events tie-break ordering with distinct timestamps
 *   - query_events limit clamped to kMaxEventsLimit
 *   - bad-path constructor returns sentinels from every method
 *   - migration idempotency: re-open existing on-disk DB
 *   - #452 §2 created_by / updated_by round-trip
 *   - #452 §5 TTL reaper deletes expired events on demand
 *   - #452 §7 batch insert_events transactional semantics
 *
 * No legacy-SQLite backfill test coverage: the dedicated [backfill] TEST_CASE
 * suite (5 cases, ADR-0038's 5-table shape) was removed (2026-08-25) as part
 * of a fresh-start-by-default policy change (ADR-0009 amendment) — no
 * production fleet has ever run a pre-Postgres build.
 * GuaranteedStateStore::migrate_from_sqlite() itself was retired
 * (chore/retire-migrate-from-sqlite-batch-b, #3623). The unrelated "legacy
 * slice-1 crash keys" test (PR #1311 JSON field-naming compat, nothing to do
 * with the SQLite backfill) is kept.
 */

#include "guaranteed_state_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "store_errors.hpp"
#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <limits>
#include <map>
#include <random>
#include <thread>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every test
// below constructs its own GuaranteedStateStore against a clone of this schema
// (ADR-0038 migration). Shared key "guardianstate" — SAME spelling as every
// other GuaranteedStateStore test file's template.
yuzu::test::PgTestTemplate guardianstate_tpl{"guardianstate", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    GuaranteedStateStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("guardianstate template: store failed to migrate");
}};

GuaranteedStateRuleRow make_rule(std::string rule_id, std::string name) {
    GuaranteedStateRuleRow r;
    r.rule_id = std::move(rule_id);
    r.name = std::move(name);
    r.yaml_source = "apiVersion: yuzu.io/v1alpha1\nkind: GuaranteedStateRule\n";
    r.version = 1;
    r.enabled = true;
    r.enforcement_mode = "enforce";
    r.severity = "high";
    r.os_target = "windows";
    r.scope_expr = "tag:workstations";
    r.signature = {0xDE, 0xAD, 0xBE, 0xEF};
    r.created_at = "2026-04-19T12:00:00Z";
    r.updated_at = "2026-04-19T12:00:00Z";
    r.created_by = "alice";
    r.updated_by = "alice";
    return r;
}

GuaranteedStateEventRow make_event(std::string event_id, std::string rule_id,
                                   std::string agent_id, std::string severity = "high",
                                   std::string timestamp = "2026-04-19T12:00:00Z") {
    GuaranteedStateEventRow e;
    e.event_id = std::move(event_id);
    e.rule_id = std::move(rule_id);
    e.agent_id = std::move(agent_id);
    e.event_type = "drift.remediated";
    e.severity = std::move(severity);
    e.guard_type = "registry";
    e.guard_category = "event";
    e.detected_value = "0";
    e.expected_value = "1";
    e.remediation_action = "registry-write";
    e.remediation_success = true;
    e.detection_latency_us = 500;
    e.remediation_latency_us = 1200;
    e.timestamp = std::move(timestamp);
    return e;
}

// RAII guard for a per-test temp database file. Constructed FIRST so the
// destructor fires even if downstream construction throws (prior governance
// memory qe-B1 — partial-construction leaks when RAII wraps come later).
// Use the shared fixture (unique_temp_path + -wal/-shm cleanup) rather than a
// local random_device variant — matches the CLAUDE.md test-helper mandate and
// avoids the flake-#473 salt pitfalls (qa-S4 / #1209).
using yuzu::test::TempDbFile;

// Run a raw SQL statement against the test database on a second connection —
// lets a test simulate a sibling replica / an aged ttl / a poisoned gc_meta
// row that the public API deliberately cannot produce. Mirrors
// test_result_set_store.cpp's exec_sql.
void exec_sql(const std::string& dsn, const std::string& sql) {
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}

// Scalar SELECT on a second connection — column 0, row 0, as text; "" when
// the result set is genuinely empty. Mirrors test_result_set_store.cpp's
// query_scalar.
std::string query_scalar(const std::string& dsn, const std::string& sql) {
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
    if (PQntuples(r.get()) == 0)
        return "";
    return PQgetvalue(r.get(), 0, 0);
}

// PostgreSQL's own clock, for tests that need to reason about what the FIXED
// reap_expired() actually compares against — mirrors test_audit_store.cpp's
// pg_now(). A fixed epoch constant would drift from "what the guard compares
// against" the same way test_audit_store.cpp's own history warns about.
int64_t pg_now(const std::string& dsn) {
    return std::stoll(query_scalar(dsn, "SELECT EXTRACT(EPOCH FROM now())::bigint"));
}

// Pass `reap_expired()` over an EMPTY table BEFORE seeding, so the #2579
// missing-anchor trigger's bootstrap decline is consumed on nothing — mirrors
// test_audit_store.cpp's `anchor_guard`. Needed because the trigger makes "no
// stored reading, and rows already expired" a decline in its own right;
// almost every reap test here is about something else (the cap, the dedup
// rule, one specific detector) and would otherwise spend its first pass
// absorbing a bootstrap decline it never meant to exercise.
//
// Exact rather than approximate: with nothing expired, `classify()`
// short-circuits to `None` on `!has_expired` before it ever tests
// `no_anchor`, so no counter moves and no anomaly is recorded — but the pass
// still reaches a verdict and settles `bootstrap_settled` (see
// `guaranteed_state_store.cpp`'s `reap_expired`), which is the effect this
// helper exists for. Call it immediately after construction, before seeding.
//
// The `last_anomaly_facts` check is load-bearing, not decorative (governance
// UP-consistency finding): the reaped-count checks above hold identically on
// ANY decline path, since nothing is ever deleted on a decline — they cannot
// tell a genuinely clean `None` short-circuit apart from a wrong-reason
// decline (`Wipe`/`BadState`) a future `classify()`-path regression might
// cause on an empty table. Only the ABSENCE of a recorded anomaly fact set
// discriminates the two.
void anchor_guard(GuaranteedStateStore& store, const std::string& dsn) {
    store.reap_expired();
    REQUIRE(store.events_reaped_total() == 0);
    REQUIRE(store.observations_reaped_total() == 0);
    REQUIRE(query_scalar(dsn, "SELECT COUNT(*) FROM guaranteed_state_store.gc_meta WHERE key = "
                              "'last_anomaly_facts'") == "0");
}

} // namespace

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("GuaranteedStateStore: opens in-memory and runs migrations",
          "[pg][guaranteed_state_store][db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    CHECK(store.rule_count() == 0);
    CHECK(store.event_count() == 0);
}

// ── M6 / #1209: monotonic policy generation ─────────────────────────────────

TEST_CASE("GuaranteedStateStore: policy_generation bumps monotonically on mutations",
          "[pg][guaranteed_state_store][generation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    CHECK(store.current_policy_generation() == 0);  // seeded at 0

    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    CHECK(store.current_policy_generation() == 1);  // create bumped

    auto r = make_rule("r1", "guard-one");
    r.enabled = false;
    REQUIRE(store.update_rule(r));
    CHECK(store.current_policy_generation() == 2);  // update bumped

    REQUIRE(store.delete_rule("r1"));
    CHECK(store.current_policy_generation() == 3);  // delete bumped

    // A failed mutation (unknown rule) must NOT advance the generation —
    // otherwise a reconcile would chase a phantom version.
    CHECK_FALSE(store.update_rule(make_rule("nope", "missing")));
    CHECK(store.current_policy_generation() == 3);
}

TEST_CASE("GuaranteedStateStore: policy_generation persists across reopen",
          "[pg][guaranteed_state_store][generation]") {
    // Postgres redesign (ADR-0038): "reopen the same SQLite file" has no direct
    // analogue — the persisted state lives in the shared database, not a
    // process-local handle. The equivalent behaviour is a SECOND store
    // constructed against the SAME dsn (a fresh PgPool, a fresh
    // GuaranteedStateStore instance, same underlying schema) — the generation
    // counter must be visible to it exactly as an agent talking to a
    // server restarted (or load-balanced to a second replica) would see it.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    {
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        GuaranteedStateStore store(pool);
        REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
        CHECK(store.current_policy_generation() == 1);
    }
    // Second store, same dsn: the counter is persisted in Postgres, not reset
    // — an agent that applied generation 1 before a server restart must not
    // look stale afterwards.
    PgPool pool2{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore reopened(pool2);
    CHECK(reopened.current_policy_generation() == 1);
}

// ── Rule CRUD ──────────────────────────────────────────────────────────────

TEST_CASE("GuaranteedStateStore: rule round-trip", "[pg][guaranteed_state_store][rules]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto rule = make_rule("rule-1", "block-smb-445");

    REQUIRE(store.create_rule(rule));
    REQUIRE(store.rule_count() == 1);

    // get_rule is three-state (ADR-0038): REQUIRE the outer expected (not
    // degraded), then the inner optional (genuinely found).
    auto fetched = store.get_rule("rule-1");
    REQUIRE(fetched.has_value());
    REQUIRE(fetched->has_value());
    CHECK((*fetched)->name == "block-smb-445");
    CHECK((*fetched)->enforcement_mode == "enforce");
    CHECK((*fetched)->os_target == "windows");
    CHECK((*fetched)->signature == rule.signature);
    CHECK((*fetched)->scope_expr == "tag:workstations");
    CHECK((*fetched)->created_by == "alice");
    CHECK((*fetched)->updated_by == "alice");
}

TEST_CASE("GuaranteedStateStore: list returns all rules ordered by name",
          "[pg][guaranteed_state_store][rules]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.create_rule(make_rule("r-2", "bravo")));
    REQUIRE(store.create_rule(make_rule("r-1", "alpha")));
    REQUIRE(store.create_rule(make_rule("r-3", "charlie")));

    // list_rules is type-distinguishable (ADR-0038 catastrophic-read set).
    auto rules = store.list_rules();
    REQUIRE(rules.has_value());
    REQUIRE(rules->size() == 3);
    CHECK((*rules)[0].name == "alpha");
    CHECK((*rules)[1].name == "bravo");
    CHECK((*rules)[2].name == "charlie");
}

TEST_CASE("GuaranteedStateStore: update mutates row", "[pg][guaranteed_state_store][rules]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto rule = make_rule("rule-1", "name-v1");
    REQUIRE(store.create_rule(rule));

    rule.name = "name-v2";
    rule.version = 2;
    rule.enforcement_mode = "audit";
    rule.updated_at = "2026-04-19T13:00:00Z";
    rule.updated_by = "bob";
    REQUIRE(store.update_rule(rule));

    auto fetched = store.get_rule("rule-1");
    REQUIRE(fetched.has_value());
    REQUIRE(fetched->has_value());
    CHECK((*fetched)->name == "name-v2");
    CHECK((*fetched)->version == 2);
    CHECK((*fetched)->enforcement_mode == "audit");
    // created_by stays immutable; updated_by records the new principal.
    CHECK((*fetched)->created_by == "alice");
    CHECK((*fetched)->updated_by == "bob");
}

TEST_CASE("GuaranteedStateStore: update of unknown rule returns error",
          "[pg][guaranteed_state_store][rules]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto rule = make_rule("does-not-exist", "ghost");
    auto r = store.update_rule(rule);
    REQUIRE_FALSE(r.has_value());
    CHECK_FALSE(is_conflict_error(r.error()));
    CHECK(r.error().find("not found") != std::string::npos);
}

TEST_CASE("GuaranteedStateStore: delete removes row", "[pg][guaranteed_state_store][rules]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.create_rule(make_rule("rule-1", "to-remove")));
    REQUIRE(store.delete_rule("rule-1"));
    // Three-state (ADR-0038): the outer expected still has_value() (the read
    // succeeded) — genuinely-deleted is the INNER optional being empty.
    auto after_delete = store.get_rule("rule-1");
    REQUIRE(after_delete.has_value());
    CHECK_FALSE(after_delete->has_value());
    auto second = store.delete_rule("rule-1");
    REQUIRE_FALSE(second.has_value());
    CHECK(second.error().find("not found") != std::string::npos);
}

TEST_CASE("GuaranteedStateStore: duplicate name rejected with kConflictPrefix",
          "[pg][guaranteed_state_store][rules][conflict]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.create_rule(make_rule("rule-1", "same-name")));
    auto dup = store.create_rule(make_rule("rule-2", "same-name"));
    REQUIRE_FALSE(dup.has_value());
    CHECK(is_conflict_error(dup.error()));
    // Human-readable detail names the offending field so the 409 response
    // body can be shown verbatim to operators after strip_conflict_prefix.
    CHECK(dup.error().find("same-name") != std::string::npos);
    CHECK(std::string(strip_conflict_prefix(dup.error())).find("name") != std::string::npos);
}

TEST_CASE("GuaranteedStateStore: duplicate rule_id rejected with kConflictPrefix",
          "[pg][guaranteed_state_store][rules][conflict]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.create_rule(make_rule("same-id", "name-one")));
    auto dup = store.create_rule(make_rule("same-id", "name-two"));
    REQUIRE_FALSE(dup.has_value());
    CHECK(is_conflict_error(dup.error()));
    // PRIMARY KEY collision — detail calls out rule_id, not name.
    CHECK(dup.error().find("rule_id") != std::string::npos);
    CHECK(dup.error().find("same-id") != std::string::npos);
}

TEST_CASE("GuaranteedStateStore: update into an existing name is a conflict",
          "[pg][guaranteed_state_store][rules][conflict]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.create_rule(make_rule("a", "alpha")));
    REQUIRE(store.create_rule(make_rule("b", "bravo")));

    // Rename b → alpha must collide with a, returning a conflict error.
    auto rule = make_rule("b", "alpha");
    auto r = store.update_rule(rule);
    REQUIRE_FALSE(r.has_value());
    CHECK(is_conflict_error(r.error()));
}

// ── Events ─────────────────────────────────────────────────────────────────

TEST_CASE("GuaranteedStateStore: event insert + query", "[pg][guaranteed_state_store][events]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.insert_event(make_event("evt-1", "rule-1", "agent-A")));
    REQUIRE(store.insert_event(make_event("evt-2", "rule-1", "agent-B", "medium")));
    REQUIRE(store.insert_event(make_event("evt-3", "rule-2", "agent-A")));

    CHECK(store.event_count() == 3);
    CHECK(store.events_written_total() == 3);

    auto all = store.query_events();
    CHECK(all.size() == 3);

    GuaranteedStateEventQuery q;
    q.rule_id = "rule-1";
    auto by_rule = store.query_events(q);
    CHECK(by_rule.size() == 2);

    GuaranteedStateEventQuery q2;
    q2.agent_id = "agent-A";
    auto by_agent = store.query_events(q2);
    CHECK(by_agent.size() == 2);

    GuaranteedStateEventQuery q3;
    q3.severity = "medium";
    auto by_sev = store.query_events(q3);
    REQUIRE(by_sev.size() == 1);
    CHECK(by_sev[0].event_id == "evt-2");
}

TEST_CASE("GuaranteedStateStore: mismatched-payload event_id collision is dropped + counted (#1414)",
          "[pg][guaranteed_state_store][events]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.insert_event(make_event("evt-dup", "rule-1", "agent-A")));
    CHECK(store.events_written_total() == 1);
    CHECK(store.events_dropped_total() == 0);

    // Forged-id pre-claim / seq-reset: the SAME event_id from a DIFFERENT agent (a
    // MISMATCHED immutable field) is a genuine collision, not a redelivery — the
    // event must NOT be written, the failure surfaces as an error, and the loud
    // CC7.3 drop counter advances (#1414). A matching-fields redelivery is the quiet
    // redelivered path — covered by the tri-state test below.
    auto r = store.insert_event(make_event("evt-dup", "rule-1", "agent-B"));
    REQUIRE_FALSE(r);
    CHECK(store.event_count() == 1);
    CHECK(store.events_written_total() == 1);
    CHECK(store.events_dropped_total() == 1);
    CHECK(store.events_redelivered_total() == 0);
}

TEST_CASE("GuaranteedStateStore: matching-fields redelivery is quiet + counted apart (item-7)",
          "[pg][guaranteed_state_store][events][redelivery]") {
    // The durable agent lifecycle journal re-sends on every reconnect, so a
    // matching-fields event_id redelivery is EXPECTED + idempotent: NOT re-written,
    // reported as Redelivered (so ingest skips the DEX observers), counted on the
    // quiet redelivered metric. A SAME event_id with a DIFFERENT immutable field is a
    // loud Conflict; a server-enriched severity change is EXCLUDED from the match.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto e = make_event("evt-r", "rule-1", "agent-A");
    const std::int64_t before_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count();
    const auto inserted = store.insert_event_classified(e);
    const std::int64_t after_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                       std::chrono::system_clock::now().time_since_epoch())
                                       .count();
    CHECK(inserted.outcome == EventInsertOutcome::Inserted);
    // #4606 criterion-10 T_server: a fresh Inserted result carries a real, recent
    // wall-clock commit instant (benchmark-diagnostic field, not a precision
    // assertion) — bounded between the timestamps taken immediately either side
    // of the call, with generous slack for scheduler jitter.
    CHECK(inserted.committed_wall_ns > 0);
    CHECK(inserted.committed_wall_ns >= before_ns);
    CHECK(inserted.committed_wall_ns <= after_ns + std::chrono::nanoseconds(std::chrono::seconds(5)).count());

    // Exact redelivery: identical row, same event_id.
    const auto redelivered = store.insert_event_classified(e);
    CHECK(redelivered.outcome == EventInsertOutcome::Redelivered);
    // committed_wall_ns is populated for Inserted only — 0 for every other outcome.
    CHECK(redelivered.committed_wall_ns == 0);
    CHECK(store.event_count() == 1);
    CHECK(store.events_written_total() == 1);
    CHECK(store.events_redelivered_total() == 1);
    CHECK(store.events_dropped_total() == 0);
    // The back-compat wrapper treats a redelivery as benign success.
    CHECK(store.insert_event(e).has_value());
    CHECK(store.events_redelivered_total() == 2);

    // Same event_id, DIFFERENT immutable field -> genuine collision, stays loud.
    auto forged = e;
    forged.detected_value = "TAMPERED";
    CHECK(store.insert_event_classified(forged).outcome == EventInsertOutcome::Conflict);
    CHECK(store.events_dropped_total() == 1);
    CHECK(store.events_redelivered_total() == 2); // unchanged
    CHECK(store.event_count() == 1);              // not written

    // Severity is server-enriched -> excluded from the match: a severity-only change
    // is still a redelivery, not a collision.
    auto sev = make_event("evt-r", "rule-1", "agent-A", "critical");
    CHECK(store.insert_event_classified(sev).outcome == EventInsertOutcome::Redelivered);
    CHECK(store.events_dropped_total() == 1); // no new drop
}

TEST_CASE("GuaranteedStateStore: an embedded-NUL event field is rejected as malformed (item-7)",
          "[pg][guaranteed_state_store][events][redelivery]") {
    // A NUL would be silently truncated by SQLite's -1 text binds and corrupt both the
    // event_id PK dedup and the redelivery compare — reject it as Error (malformed),
    // never store-truncate it, and never count it as a collision. Guardian fields are
    // structured text / JSON and never legitimately carry a NUL.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto e = make_event("evt-nul", "rule-1", "agent-A");
    e.detected_value = std::string("a\0b", 3); // embedded NUL
    CHECK(store.insert_event_classified(e).outcome == EventInsertOutcome::Error);
    CHECK(store.event_count() == 0);
    CHECK(store.events_dropped_total() == 0);       // malformed, NOT a collision
    CHECK(store.events_redelivered_total() == 0);
    CHECK_FALSE(store.insert_event(e).has_value()); // wrapper maps Error -> unexpected

    // A NUL in event_id (would truncate the PK) is likewise rejected.
    auto e2 = make_event(std::string("evt\0x", 5), "rule-1", "agent-A");
    CHECK(store.insert_event_classified(e2).outcome == EventInsertOutcome::Error);
    CHECK(store.event_count() == 0);
}

TEST_CASE("GuaranteedStateStore: every compared field triggers a Conflict when it differs (item-7)",
          "[pg][guaranteed_state_store][events][redelivery]") {
    // A same-event_id re-insert that differs in ANY ONE immutable compared field must be
    // a loud Conflict, not a quiet Redelivered — this pins the whole compare column set so
    // a column-index off-by-one in stored_event_matches_locked is caught (qa-S2). severity
    // is EXCLUDED (server-enriched) and is asserted to stay a Redelivery.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto base = make_event("evt-f", "rule-1", "agent-A");
    base.detail_json = R"({"k":"v"})";
    REQUIRE(store.insert_event_classified(base).outcome == EventInsertOutcome::Inserted);

    uint64_t dropped = 0;
    auto expect_conflict = [&](auto mutate) {
        auto e = base;
        mutate(e); // one field differs; event_id stays "evt-f" so it conflicts on the PK
        CHECK(store.insert_event_classified(e).outcome == EventInsertOutcome::Conflict);
        CHECK(store.events_dropped_total() == ++dropped);
        CHECK(store.event_count() == 1); // never written
    };

    expect_conflict([](GuaranteedStateEventRow& e) { e.rule_id = "rule-2"; });
    expect_conflict([](GuaranteedStateEventRow& e) { e.agent_id = "agent-Z"; });
    expect_conflict([](GuaranteedStateEventRow& e) { e.event_type = "drift.detected"; });
    expect_conflict([](GuaranteedStateEventRow& e) { e.guard_type = "etw"; });
    expect_conflict([](GuaranteedStateEventRow& e) { e.guard_category = "condition"; });
    expect_conflict([](GuaranteedStateEventRow& e) { e.detected_value = "1"; });
    expect_conflict([](GuaranteedStateEventRow& e) { e.expected_value = "0"; });
    expect_conflict([](GuaranteedStateEventRow& e) { e.remediation_action = "other"; });
    expect_conflict([](GuaranteedStateEventRow& e) { e.remediation_success = false; });
    expect_conflict([](GuaranteedStateEventRow& e) { e.detection_latency_us = 999; });
    expect_conflict([](GuaranteedStateEventRow& e) { e.remediation_latency_us = 999; });
    expect_conflict([](GuaranteedStateEventRow& e) { e.timestamp = "2026-04-19T13:00:00Z"; });
    expect_conflict([](GuaranteedStateEventRow& e) { e.detail_json = R"({"k":"w"})"; });

    // Control: severity is server-enriched -> excluded -> a severity-only change stays a
    // Redelivery and does not bump the drop counter.
    auto sev = base;
    sev.severity = (base.severity == "high") ? "low" : "high";
    CHECK(store.insert_event_classified(sev).outcome == EventInsertOutcome::Redelivered);
    CHECK(store.events_dropped_total() == dropped); // unchanged
}

TEST_CASE("GuaranteedStateStore: ruleless crash observation skips the compliance census",
          "[pg][guaranteed_state_store][events][crash]") {
    // Guardian DEX slice 1: a fleet-wide process crash is RULELESS — sentinel
    // rule_id "__observation__" + event_type "process.crashed". It must insert
    // (rule_id is NOT NULL — the sentinel satisfies it), keep its agent-set
    // severity verbatim, and NOT create a per-(agent,rule) compliance census row
    // (process.crashed is not a compliance state). A normal drift event in the
    // same store still updates the census — proving the skip is crash-specific.
    // Pins the ruleless path the agent crash recorder relies on.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    // A normal rule-bound drift (drift.remediated) -> updates the census.
    REQUIRE(store.insert_event(make_event("evt-drift", "rule-1", "agent-A")));

    // A ruleless crash observation.
    GuaranteedStateEventRow crash;
    crash.event_id = "__observation__-1718000000000-0";
    crash.rule_id = "__observation__";
    crash.agent_id = "agent-A";
    crash.event_type = "process.crashed";
    crash.severity = "info";
    crash.guard_type = "process";
    crash.guard_category = ""; // ruleless-ness + event_type IS the discriminator
    crash.detected_value = "notepad.exe pid=1234 code=0xC0000005 ACCESS_VIOLATION module=ntdll.dll";
    crash.timestamp = "2026-06-08T12:00:00Z";
    REQUIRE(store.insert_event(crash));

    // The crash is stored and keeps its severity verbatim (no rule to enrich from).
    GuaranteedStateEventQuery q;
    q.rule_id = "__observation__";
    auto crashes = store.query_events(q);
    REQUIRE(crashes.size() == 1);
    CHECK(crashes[0].event_type == "process.crashed");
    CHECK(crashes[0].severity == "info");
    CHECK(crashes[0].guard_category.empty());

    // The census has the drift's (agent,rule) row but NONE for the sentinel.
    // agent_rule_statuses is type-distinguishable (ADR-0038); REQUIRE the
    // outer expected then assert on the container.
    auto census_all = store.agent_rule_statuses();
    REQUIRE(census_all.has_value());
    CHECK(census_all->size() == 1);
    auto census_sentinel = store.agent_rule_statuses("__observation__");
    REQUIRE(census_sentinel.has_value());
    CHECK(census_sentinel->empty());
}

TEST_CASE("GuaranteedStateStore: a reserved sentinel rule_id never updates the census",
          "[pg][guaranteed_state_store][events][crash][security]") {
    // Security hardening (Gate-2 LOW → enforced): the "__observation__" sentinel is
    // reserved for ruleless observations and has no live rule. A (mis)behaving agent
    // could pair it with a COMPLIANCE event_type (drift.detected) to mint a phantom
    // per-(agent,rule) census row keyed to the reserved id. The store must skip the
    // census for ANY reserved __…__ rule_id regardless of event_type — not just for
    // process.crashed.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    GuaranteedStateEventRow abuse;
    abuse.event_id = "__observation__-abuse-1";
    abuse.rule_id = "__observation__";
    abuse.agent_id = "agent-A";
    abuse.event_type = "drift.detected"; // a compliance verdict paired with the sentinel
    abuse.severity = "info";
    abuse.timestamp = "2026-06-09T12:00:00Z";
    REQUIRE(store.insert_event(abuse));

    // The event is still stored (rule_id is NOT NULL — the sentinel satisfies it)…
    GuaranteedStateEventQuery q;
    q.rule_id = "__observation__";
    REQUIRE(store.query_events(q).size() == 1);
    // …but it creates NO census row for the reserved id.
    auto census_all = store.agent_rule_statuses();
    REQUIRE(census_all.has_value());
    CHECK(census_all->empty());
    auto census_sentinel = store.agent_rule_statuses("__observation__");
    REQUIRE(census_sentinel.has_value());
    CHECK(census_sentinel->empty());

    // Regression guard: the skip is EXACT-match, NOT a "__"-prefix. A legitimately
    // authored guard whose name slugifies to a "__"-prefixed rule_id (e.g. "__foo-<hex>")
    // is a REAL rule-bound id and MUST keep its compliance census.
    GuaranteedStateEventRow real;
    real.event_id = "evt-real-1";
    real.rule_id = "__foo-abc123"; // not the exact sentinel
    real.agent_id = "agent-A";
    real.event_type = "drift.detected";
    real.severity = "high";
    real.timestamp = "2026-06-09T12:01:00Z";
    REQUIRE(store.insert_event(real));
    auto census_real = store.agent_rule_statuses("__foo-abc123");
    REQUIRE(census_real.has_value());
    CHECK(census_real->size() == 1);
}

TEST_CASE("GuaranteedStateStore: observation projects uniform detail_json keys",
          "[pg][guaranteed_state_store][events][crash][dex]") {
    // A ruleless observation projects its UNIFORM detail_json facts
    // (subject/reason/symbolic/component/metric) into the guardian_observations
    // read model — generically, for every signal type. A plain drift event must
    // NOT project — the projection is observations-only.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.insert_event(make_event("evt-drift", "rule-1", "agent-A")));
    CHECK(store.query_observations().empty()); // drift does not project

    GuaranteedStateEventRow crash;
    crash.event_id = "__observation__-proj-1";
    crash.rule_id = "__observation__";
    crash.agent_id = "agent-A";
    crash.event_type = "process.crashed";
    crash.severity = "info";
    crash.detected_value = "notepad.exe pid=1234 code=0xC0000005 ACCESS_VIOLATION module=ntdll.dll";
    crash.detail_json =
        R"({"subject":"notepad.exe","pid":1234,"kind":"exception",)"
        R"("reason":"0xC0000005","symbolic":"ACCESS_VIOLATION",)"
        R"("component":"ntdll.dll","version":"11.0.26100.1","platform":"windows"})";
    crash.timestamp = "2026-06-08T12:00:00Z";
    REQUIRE(store.insert_event(crash));

    auto obs = store.query_observations();
    REQUIRE(obs.size() == 1); // the crash projected; the drift did not
    CHECK(obs[0].event_id == "__observation__-proj-1");
    CHECK(obs[0].agent_id == "agent-A");
    CHECK(obs[0].observed_at == "2026-06-08T12:00:00Z");
    CHECK(obs[0].obs_type == "process.crashed");
    CHECK(obs[0].subject == "notepad.exe");
    CHECK(obs[0].reason == "0xC0000005");
    CHECK(obs[0].symbolic == "ACCESS_VIOLATION");
    CHECK(obs[0].component == "ntdll.dll");
    CHECK(obs[0].version == "11.0.26100.1"); // slice 2b: per-version stability projects
    CHECK(obs[0].platform == "windows");
}

// ── #4665: log-injection neutralisation on the rule_id/event_id error paths ─
//
// guaranteed_state_store.cpp wraps every rule_id/event_id it hands to
// spdlog:: on these best-effort warn/error paths with yuzu::log_id_token (a
// hostile value cannot forge a log line or smuggle extra key=value tokens
// onto it). Each case below forces a GENUINE SQL-level failure via a
// second-connection exec_sql, rather than faking the log call, so it
// exercises the real production code path. agent_id is deliberately left
// unwrapped everywhere in this file (issue #489, a separate fleet-wide
// outcome) and is not asserted on here.
//
// Each assertion below checks the id= FIELD carries the neutralised form,
// not that the raw hostile string is globally absent from the captured
// text: the trailing {} in both log lines is PQerrorMessage()/pr.error()
// (deliberately unwrapped, same reasoning as `why` in
// guardian_push_builder.cpp) and Postgres's own constraint-violation DETAIL
// text ("Failing row contains (...)" / "Key (...)=(...) already exists")
// echoes the raw offending value back through THAT channel -- confirmed
// empirically while writing this test. That is a separate, out-of-scope
// exposure through the SQL diagnostic text itself (not an id/key field, and
// not something log_id_token/log_key_token is meant to touch); see the PR
// report for a note on it.

TEST_CASE("GuaranteedStateStore: a hostile rule_id is neutralised on a failed "
          "compliance-census upsert",
          "[pg][guaranteed_state_store][events][log_hygiene]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);

    // A CHECK constraint the public API can never violate on its own — added
    // directly so upsert_rule_status's INSERT...ON CONFLICT genuinely fails,
    // exercising the real "status upsert failed" warn path rather than
    // mocking the log call.
    exec_sql(db.dsn(),
             "ALTER TABLE guaranteed_state_store.guardian_agent_rule_status "
             "ADD CONSTRAINT chk_test_no_newline_rule_id "
             "CHECK (rule_id NOT LIKE '%' || chr(10) || '%')");

    const std::string hostile_rule_id = "rule\ninjected-line";
    yuzu::test::LogCapture cap(spdlog::level::warn);
    // drift.remediated -> "compliant" state, so the census upsert fires.
    REQUIRE(store.insert_event(make_event("evt-census-1", hostile_rule_id, "agent-A")));
    cap.stop();

    const std::string logs = cap.text();
    CHECK(logs.find("status upsert failed") != std::string::npos);
    // log_id_token(rule_id) is inserted correctly at the rule_id= field: the
    // embedded newline is folded to '_' rather than splitting the log line
    // or leaking a second, forged rule_id= token.
    CHECK(logs.find("rule_id=rule_injected-line") != std::string::npos);
    CHECK(logs.find("rule_id=rule\ninjected-line") == std::string::npos);
}

TEST_CASE("GuaranteedStateStore: a hostile event_id is neutralised on a failed "
          "observation projection",
          "[pg][guaranteed_state_store][events][crash][dex][log_hygiene]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);

    const std::string hostile_event_id = "obs-collide\ninjected-line";
    // Pre-seed a colliding PK directly in the read-model table -- the public
    // API can never produce two rows sharing an event_id, so this is the only
    // way to force project_observation's INSERT to genuinely fail rather than
    // faking the log call.
    exec_sql(db.dsn(), "INSERT INTO guaranteed_state_store.guardian_observations "
                       "(event_id, agent_id, observed_at, obs_type) VALUES ('" +
                           hostile_event_id +
                           "', 'agent-B', '2026-06-08T12:00:00Z', 'process.crashed')");

    GuaranteedStateEventRow crash;
    crash.event_id = hostile_event_id;
    crash.rule_id = "__observation__";
    crash.agent_id = "agent-B";
    crash.event_type = "process.crashed";
    crash.severity = "info";
    crash.detail_json = R"({"subject":"notepad.exe"})";
    crash.timestamp = "2026-06-08T12:00:00Z";

    yuzu::test::LogCapture cap(spdlog::level::err);
    REQUIRE(store.insert_event(crash)); // event itself is kept even though projection fails
    cap.stop();

    const std::string logs = cap.text();
    CHECK(logs.find("observation projection failed") != std::string::npos);
    // log_id_token(row.event_id) is inserted correctly at the event_id=
    // field, same reasoning as the rule_id case above.
    CHECK(logs.find("event_id=obs-collide_injected-line") != std::string::npos);
    CHECK(logs.find("event_id=obs-collide\ninjected-line") == std::string::npos);
}

TEST_CASE("GuaranteedStateStore: dex_device_top_apps splits crashes/hangs by version",
          "[pg][guaranteed_state_store][events][crash][dex]") {
    // Slice 2b: the per-device app-reliability query groups by (subject, version)
    // so "did THIS build crash more" is answerable. A missing version buckets
    // under "". Crashes on a DIFFERENT device must not leak into the count.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto crash = [&](const char* id, const char* agent, const char* subject, const char* version,
                     const char* type, const char* ts) {
        GuaranteedStateEventRow e;
        e.event_id = id;
        e.rule_id = "__observation__";
        e.agent_id = agent;
        e.event_type = type;
        e.severity = "info";
        nlohmann::json j{{"subject", subject}, {"platform", "windows"}};
        if (version[0])
            j["version"] = version;
        e.detail_json = j.dump();
        e.timestamp = ts;
        REQUIRE(store.insert_event(e));
    };
    // chrome on agent-A: 2 crashes on v125, 1 crash + 1 hang on v124.
    crash("o1", "agent-A", "chrome.exe", "125.0.6422.61", "process.crashed", "2026-06-08T10:00:00Z");
    crash("o2", "agent-A", "chrome.exe", "125.0.6422.61", "process.crashed", "2026-06-08T11:00:00Z");
    crash("o3", "agent-A", "chrome.exe", "124.0.6367.91", "process.crashed", "2026-06-08T09:00:00Z");
    crash("o4", "agent-A", "chrome.exe", "124.0.6367.91", "process.hung",    "2026-06-08T09:30:00Z");
    // an unknown-version crash (packaged app) buckets under "".
    crash("o5", "agent-A", "Teams.exe", "", "process.crashed", "2026-06-08T08:00:00Z");
    // a crash on ANOTHER device must not appear in agent-A's per-device query.
    crash("o6", "agent-B", "chrome.exe", "125.0.6422.61", "process.crashed", "2026-06-08T10:30:00Z");

    auto rows = store.dex_device_top_apps("agent-A", "2026-06-01T00:00:00Z", 50);
    // 3 (subject,version) buckets: chrome 125, chrome 124, Teams "".
    REQUIRE(rows.size() == 3);
    // Ranked by (crashes+hangs) desc → chrome 125 (2) and chrome 124 (2) lead.
    auto find = [&](const std::string& s, const std::string& v) {
        return std::find_if(rows.begin(), rows.end(),
                            [&](const auto& r) { return r.subject == s && r.version == v; });
    };
    auto v125 = find("chrome.exe", "125.0.6422.61");
    REQUIRE(v125 != rows.end());
    CHECK(v125->crashes == 2);   // agent-B's crash excluded
    CHECK(v125->hangs == 0);
    auto v124 = find("chrome.exe", "124.0.6367.91");
    REQUIRE(v124 != rows.end());
    CHECK(v124->crashes == 1);
    CHECK(v124->hangs == 1);
    auto teams = find("Teams.exe", "");
    REQUIRE(teams != rows.end()); // unknown version is its own honest bucket
    CHECK(teams->crashes == 1);
}

TEST_CASE("GuaranteedStateStore: dex_device_top_apps honors time-fence, ranking and limit",
          "[pg][guaranteed_state_store][events][crash][dex]") {
    // quality SHOULD-2: the prior test shares one timestamp band, so the
    // `observed_at >= ?` fence, the ORDER BY rank, and the LIMIT cap were all
    // unexercised — a regression dropping any of the three would pass. Pin them.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    int n = 0;
    auto crash = [&](const char* subject, const char* ts) {
        GuaranteedStateEventRow e;
        e.event_id = "o" + std::to_string(++n);
        e.rule_id = "__observation__";
        e.agent_id = "agent-A";
        e.event_type = "process.crashed";
        e.severity = "info";
        e.detail_json = nlohmann::json{{"subject", subject}, {"version", "1.0.0.0"}}.dump();
        e.timestamp = ts;
        REQUIRE(store.insert_event(e));
    };
    // hot.exe: 3 crashes in-window; cold.exe: 1 in-window. Plus one hot.exe crash
    // BEFORE the cutoff that must be fenced out.
    crash("hot.exe", "2026-06-10T10:00:00Z");
    crash("hot.exe", "2026-06-10T11:00:00Z");
    crash("hot.exe", "2026-06-10T12:00:00Z");
    crash("cold.exe", "2026-06-10T10:00:00Z");
    crash("hot.exe", "2026-05-01T10:00:00Z"); // pre-cutoff — must NOT count

    auto rows = store.dex_device_top_apps("agent-A", "2026-06-01T00:00:00Z", 50);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].subject == "hot.exe"); // ranking: highest (crashes+hangs) first
    CHECK(rows[0].crashes == 3);         // time-fence: the May crash excluded (else 4)
    CHECK(rows[1].subject == "cold.exe");

    // LIMIT cap: top-1 returns only the hottest bucket.
    auto capped = store.dex_device_top_apps("agent-A", "2026-06-01T00:00:00Z", 1);
    REQUIRE(capped.size() == 1);
    CHECK(capped[0].subject == "hot.exe");
}

TEST_CASE("GuaranteedStateStore: projection RE-CANONICALIZES the agent version (UP-4)",
          "[pg][guaranteed_state_store][events][crash][dex][security]") {
    // UP-4: the server must never trust the agent's version string. Re-running
    // canon_version at the projection boundary guarantees guardian_observations
    // .version is always a clean 4-group quad or "" — closing the latent
    // stored-XSS surface and the arity join, regardless of agent behaviour.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto project_version = [&](const char* id, const std::string& sent) -> std::string {
        GuaranteedStateEventRow e;
        e.event_id = id;
        e.rule_id = "__observation__";
        e.agent_id = "agent-A";
        e.event_type = "process.crashed";
        e.severity = "info";
        e.detail_json = nlohmann::json{{"subject", "a.exe"}, {"version", sent}}.dump();
        e.timestamp = "2026-06-08T12:00:00Z";
        REQUIRE(store.insert_event(e));
        for (const auto& o : store.query_observations())
            if (o.event_id == id)
                return o.version;
        return "<not-found>";
    };
    CHECK(project_version("rc1", "1.2") == "1.2.0.0");              // short -> padded (arity)
    CHECK(project_version("rc2", "01.02.03.04") == "1.2.3.4");      // leading zeros normalized
    CHECK(project_version("rc3", "<script>alert(1)</script>").empty()); // hostile -> "" (no XSS)
    CHECK(project_version("rc4", std::string(5000, '9')).empty());  // garbage length -> ""
    CHECK(project_version("rc5", "6.15.101.7085") == "6.15.101.7085"); // clean quad unchanged
}

TEST_CASE("GuaranteedStateStore: legacy slice-1 crash keys still project (fallback)",
          "[pg][guaranteed_state_store][events][crash][dex]") {
    // PR #1311 transition compat: an agent still emitting the slice-1 crash keys
    // (process/exception_code/faulting_module) must keep projecting — the
    // projection falls back to them when the uniform keys are absent.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    GuaranteedStateEventRow crash;
    crash.event_id = "__observation__-legacy-1";
    crash.rule_id = "__observation__";
    crash.agent_id = "agent-L";
    crash.event_type = "process.crashed";
    crash.severity = "info";
    crash.detail_json =
        R"({"process":"old-agent.exe","exception_code":"0xC0000374",)"
        R"("symbolic":"HEAP_CORRUPTION","faulting_module":"heap.dll","platform":"windows"})";
    crash.timestamp = "2026-06-08T12:00:00Z";
    REQUIRE(store.insert_event(crash));

    auto obs = store.query_observations();
    REQUIRE(obs.size() == 1);
    CHECK(obs[0].subject == "old-agent.exe");   // process → subject
    CHECK(obs[0].reason == "0xC0000374");       // exception_code → reason
    CHECK(obs[0].component == "heap.dll");      // faulting_module → component
}

TEST_CASE("GuaranteedStateStore: metric projects for numeric payloads, rejects garbage",
          "[pg][guaranteed_state_store][events][dex]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto boot = [&](const std::string& id, const std::string& json) {
        GuaranteedStateEventRow e;
        e.event_id = id;
        e.rule_id = "__observation__";
        e.agent_id = "agent-A";
        e.event_type = "os.boot";
        e.severity = "info";
        e.detail_json = json;
        e.timestamp = "2026-06-09T08:00:00Z";
        REQUIRE(store.insert_event(e));
    };
    boot("b1", R"({"subject":"boot","metric":43210.0,"platform":"windows"})");
    boot("b2", R"({"subject":"boot","metric":-99,"platform":"windows"})");   // negative → 0
    auto obs = store.query_observations();
    REQUIRE(obs.size() == 2);
    // newest-first ties broken by event_id DESC → b2 first
    CHECK(obs[0].metric == 0.0);
    CHECK(obs[1].metric == 43210.0);
}

TEST_CASE("GuaranteedStateStore: redelivered crash event_id does not double-count the projection",
          "[pg][guaranteed_state_store][events][crash][dex]") {
    // The event journal is at-least-once. The projection INSERT lives inside the
    // event INSERT's transaction, so a duplicate event_id fails the event PK and
    // rolls back BOTH — the projection inherits the dedup and never double-counts.
    // A plain round-trip test would miss this (the catch the advisor flagged).
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    GuaranteedStateEventRow crash;
    crash.event_id = "__observation__-dup-1";
    crash.rule_id = "__observation__";
    crash.agent_id = "agent-A";
    crash.event_type = "process.crashed";
    crash.severity = "info";
    crash.detail_json = R"({"process":"svc.exe","exception_code":"0xC0000409","platform":"windows"})";
    crash.timestamp = "2026-06-08T12:00:00Z";

    REQUIRE(store.insert_event(crash));
    // Matching-fields redelivery (item-7 PR-Sv): an idempotent success — NOT
    // re-inserted or re-projected (event_id PK dedup), counted on the quiet
    // redelivered metric, never the loud CC7.3 drop metric.
    auto dup = store.insert_event(crash); // same event_id redelivered
    REQUIRE(dup.has_value());
    CHECK(store.events_redelivered_total() == 1);
    CHECK(store.events_dropped_total() == 0);

    // Exactly one event row AND one projection row — no double-count.
    GuaranteedStateEventQuery q;
    q.rule_id = "__observation__";
    CHECK(store.query_events(q).size() == 1);
    CHECK(store.query_observations().size() == 1);
}

TEST_CASE("GuaranteedStateStore: malformed crash detail_json still records the observation",
          "[pg][guaranteed_state_store][events][crash][dex]") {
    // detail_json is parsed defensively: a malformed blob must NOT drop the crash
    // (the event itself is still valuable). The observation lands with empty crash
    // fields rather than failing the insert.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    GuaranteedStateEventRow crash;
    crash.event_id = "__observation__-bad-json-1";
    crash.rule_id = "__observation__";
    crash.agent_id = "agent-A";
    crash.event_type = "process.crashed";
    crash.severity = "info";
    crash.detail_json = "{not valid json";
    crash.timestamp = "2026-06-08T12:00:00Z";
    REQUIRE(store.insert_event(crash)); // does not fail

    auto obs = store.query_observations();
    REQUIRE(obs.size() == 1);
    CHECK(obs[0].obs_type == "process.crashed");
    CHECK(obs[0].subject.empty()); // degraded, not dropped
}

TEST_CASE("GuaranteedStateStore: DEX crash aggregations", "[pg][guaranteed_state_store][crash][dex]") {
    // Slice 2: crash-scoped GROUP BY over the projection. Known dataset with
    // verifiable counts, blast radius (distinct devices), tie-break, by-OS, by-day,
    // and the since-cutoff.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto crash = [&](const std::string& id, const std::string& agent, const std::string& proc,
                     const std::string& mod, const std::string& plat, const std::string& ts) {
        GuaranteedStateEventRow c;
        c.event_id = id;
        c.rule_id = "__observation__";
        c.agent_id = agent;
        c.event_type = "process.crashed";
        c.severity = "info";
        c.detail_json = "{\"subject\":\"" + proc + "\",\"reason\":\"0xC0000005\","
                        "\"symbolic\":\"ACCESS_VIOLATION\",\"component\":\"" + mod +
                        "\",\"platform\":\"" + plat + "\"}";
        c.timestamp = ts;
        REQUIRE(store.insert_event(c));
    };
    crash("e1", "agent-A", "chrome.exe", "ntdll.dll", "windows", "2026-06-08T10:00:00Z");
    crash("e2", "agent-A", "chrome.exe", "ntdll.dll", "windows", "2026-06-08T11:00:00Z");
    crash("e3", "agent-B", "chrome.exe", "chrome.dll", "windows", "2026-06-09T10:00:00Z");
    crash("e4", "agent-B", "Teams.exe", "ntdll.dll", "windows", "2026-06-09T11:00:00Z");
    crash("e5", "agent-C", "AcmeCRM.exe", "AcmeCRM.dll", "linux", "2026-06-09T12:00:00Z");

    auto sum = store.dex_crash_summary();
    CHECK(sum.total_crashes == 5);
    CHECK(sum.distinct_devices == 3);
    CHECK(sum.distinct_apps == 3);

    auto apps = store.dex_top_apps();
    REQUIRE(apps.size() == 3);
    CHECK(apps[0].subject == "chrome.exe");
    CHECK(apps[0].crashes == 3);
    CHECK(apps[0].hangs == 0); // crash-only dataset
    CHECK(apps[0].distinct_devices == 2); // blast radius: agent-A + agent-B
    CHECK(apps[0].last_seen == "2026-06-09T10:00:00Z");

    auto mods = store.dex_top_modules();
    REQUIRE(mods.size() == 3);
    CHECK(mods[0].component == "ntdll.dll");
    CHECK(mods[0].crashes == 3);
    CHECK(mods[0].distinct_apps == 2); // chrome.exe + Teams.exe

    auto devs = store.dex_top_devices();
    REQUIRE(devs.size() == 3);
    CHECK(devs[0].agent_id == "agent-A"); // ties at 2 broken by agent_id ASC
    CHECK(devs[0].crashes == 2);
    CHECK(devs[1].agent_id == "agent-B");
    CHECK(devs[2].agent_id == "agent-C");
    CHECK(devs[2].crashes == 1);

    auto os = store.dex_crashes_by_os();
    REQUIRE(os.size() == 2);
    CHECK(os[0].platform == "windows");
    CHECK(os[0].crashes == 4);
    CHECK(os[0].distinct_devices == 2);
    CHECK(os[1].platform == "linux");
    CHECK(os[1].crashes == 1);

    auto days = store.dex_crashes_by_day();
    REQUIRE(days.size() == 2);
    CHECK(days[0].day == "2026-06-08");
    CHECK(days[0].crashes == 2);
    CHECK(days[1].day == "2026-06-09");
    CHECK(days[1].crashes == 3);

    // since-cutoff: only 06-09 onward → e3,e4,e5
    auto recent = store.dex_crash_summary("2026-06-09T00:00:00Z");
    CHECK(recent.total_crashes == 3);
    CHECK(recent.distinct_devices == 2); // agent-B + agent-C
}

TEST_CASE("GuaranteedStateStore: generic per-obs_type drill-down + OS scope",
          "[pg][guaranteed_state_store][dex][signals]") {
    // The catalogue View-3 read-model: subjects / OS-split / devices / trend for
    // ANY obs_type (not crash-scoped), plus per-OS coverage scope.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto obs = [&](const std::string& id, const std::string& agent, const std::string& type,
                   const std::string& subject, const std::string& plat, const std::string& ts) {
        GuaranteedStateEventRow r;
        r.event_id = id;
        r.rule_id = "__observation__";
        r.agent_id = agent;
        r.event_type = type;
        r.severity = "info";
        r.detail_json = "{\"subject\":\"" + subject + "\",\"platform\":\"" + plat + "\"}";
        r.timestamp = ts;
        REQUIRE(store.insert_event(r));
    };
    obs("w1", "agent-A", "network.wifi_drop", "CorpNet", "windows", "2026-06-08T10:00:00Z");
    obs("w2", "agent-A", "network.wifi_drop", "CorpNet", "windows", "2026-06-08T11:00:00Z");
    obs("w3", "agent-B", "network.wifi_drop", "Guest", "windows", "2026-06-09T10:00:00Z");
    obs("w4", "mac-1", "network.wifi_drop", "Wi-Fi", "macos", "2026-06-09T11:00:00Z");
    obs("c1", "mac-1", "process.crashed", "Safari", "macos", "2026-06-09T12:00:00Z");

    auto subj = store.dex_signal_subjects("network.wifi_drop");
    REQUIRE(subj.size() == 3);
    CHECK(subj[0].subject == "CorpNet");
    CHECK(subj[0].count == 2);
    CHECK(subj[0].distinct_devices == 1);

    auto os = store.dex_signal_by_os("network.wifi_drop");
    REQUIRE(os.size() == 2);
    CHECK(os[0].platform == "windows");
    CHECK(os[0].crashes == 3); // generic event count
    CHECK(os[1].platform == "macos");
    CHECK(os[1].crashes == 1);

    auto devs = store.dex_signal_devices("network.wifi_drop");
    REQUIRE(devs.size() == 3);
    CHECK(devs[0].agent_id == "agent-A");
    CHECK(devs[0].crashes == 2);

    auto days = store.dex_signal_by_day("network.wifi_drop");
    REQUIRE(days.size() == 2);
    CHECK(days[0].day == "2026-06-08");
    CHECK(days[0].crashes == 2);

    // Per-OS scope: windows collects 1 type (3 events); macOS collects 2 types
    // (2 events). Ordered by total events desc.
    auto scope = store.dex_os_signal_scope();
    REQUIRE(scope.size() == 2);
    CHECK(scope[0].platform == "windows");
    CHECK(scope[0].distinct_types == 1);
    CHECK(scope[0].total_events == 3);
    CHECK(scope[1].platform == "macos");
    CHECK(scope[1].distinct_types == 2);
    CHECK(scope[1].total_events == 2);

    // day × obs_type matrix (the Trends source): grouped by (day, obs_type).
    auto mat = store.dex_signal_day_matrix();
    REQUIRE(mat.size() == 3);
    CHECK(mat[0].day == "2026-06-08");
    CHECK(mat[0].obs_type == "network.wifi_drop");
    CHECK(mat[0].count == 2);
    CHECK(mat[2].day == "2026-06-09");
    CHECK(mat[2].obs_type == "process.crashed");
    CHECK(mat[2].count == 1);
}

TEST_CASE("GuaranteedStateStore: DEX crash + signal aggregations are OS-scopable (C-DEX-1)",
          "[pg][guaranteed_state_store][dex][signals][crash]") {
    // process.crashed now arrives from BOTH Windows and macOS agents. The
    // crash-free headline is Windows-denominated, and the Catalogue drilldown
    // honours a single-OS lens, so both must be scopable by platform — the
    // default (empty platform) stays all-OS.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto obs = [&](const std::string& id, const std::string& agent, const std::string& type,
                   const std::string& subject, const std::string& plat, const std::string& ts) {
        GuaranteedStateEventRow r;
        r.event_id = id;
        r.rule_id = "__observation__";
        r.agent_id = agent;
        r.event_type = type;
        r.severity = "info";
        r.detail_json = "{\"subject\":\"" + subject + "\",\"platform\":\"" + plat + "\"}";
        r.timestamp = ts;
        REQUIRE(store.insert_event(r));
    };
    obs("c1", "win-1", "process.crashed", "chrome.exe", "windows", "2026-06-08T10:00:00Z");
    obs("c2", "win-1", "process.crashed", "chrome.exe", "windows", "2026-06-09T10:00:00Z");
    obs("c3", "win-2", "process.crashed", "outlook.exe", "windows", "2026-06-09T11:00:00Z");
    obs("c4", "mac-1", "process.crashed", "Safari", "macos", "2026-06-09T12:00:00Z");

    SECTION("dex_crash_summary scopes by platform; empty = all-OS") {
        auto all = store.dex_crash_summary();
        CHECK(all.total_crashes == 4);
        CHECK(all.distinct_devices == 3);

        auto win = store.dex_crash_summary("", "windows");
        CHECK(win.total_crashes == 3);
        CHECK(win.distinct_devices == 2); // win-1, win-2 — NOT mac-1

        auto mac = store.dex_crash_summary("", "macos");
        CHECK(mac.total_crashes == 1);
        CHECK(mac.distinct_devices == 1);
    }

    SECTION("subjects/devices/by_day OS-scope the drilldown; by_os stays cross-OS") {
        // subjects: the Windows lens sees chrome.exe + outlook.exe, never Safari.
        auto subj_win = store.dex_signal_subjects("process.crashed", "", 15, "windows");
        REQUIRE(subj_win.size() == 2);
        bool win_has_safari = false;
        for (const auto& s : subj_win)
            if (s.subject == "Safari")
                win_has_safari = true;
        CHECK_FALSE(win_has_safari);

        auto subj_mac = store.dex_signal_subjects("process.crashed", "", 15, "macos");
        REQUIRE(subj_mac.size() == 1);
        CHECK(subj_mac[0].subject == "Safari");

        // devices: the Windows lens is win-1/win-2 only.
        auto dev_win = store.dex_signal_devices("process.crashed", "", 15, "windows");
        REQUIRE(dev_win.size() == 2);
        for (const auto& d : dev_win)
            CHECK(d.agent_id != "mac-1");

        // by_day: the Windows lens excludes the macOS-only crash on 06-09.
        int64_t all_0609 = 0, win_0609 = 0;
        for (const auto& d : store.dex_signal_by_day("process.crashed"))
            if (d.day == "2026-06-09")
                all_0609 = d.crashes;
        for (const auto& d : store.dex_signal_by_day("process.crashed", "", "windows"))
            if (d.day == "2026-06-09")
                win_0609 = d.crashes;
        CHECK(all_0609 == 3); // c2(win) + c3(win) + c4(mac)
        CHECK(win_0609 == 2); // c2 + c3 only

        // by_os is deliberately NOT platform-scoped — it IS the cross-OS split.
        auto os = store.dex_signal_by_os("process.crashed");
        REQUIRE(os.size() == 2); // both windows and macos rows present
    }
}

TEST_CASE("GuaranteedStateStore: DEX drill-down aggregations", "[pg][guaranteed_state_store][crash][dex]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto crash = [&](const std::string& id, const std::string& agent, const std::string& proc,
                     const std::string& mod, const std::string& plat, const std::string& ts) {
        GuaranteedStateEventRow c;
        c.event_id = id;
        c.rule_id = "__observation__";
        c.agent_id = agent;
        c.event_type = "process.crashed";
        c.severity = "info";
        c.detail_json = "{\"subject\":\"" + proc + "\",\"reason\":\"0xC0000005\","
                        "\"symbolic\":\"ACCESS_VIOLATION\",\"component\":\"" + mod +
                        "\",\"platform\":\"" + plat + "\"}";
        c.timestamp = ts;
        REQUIRE(store.insert_event(c));
    };
    crash("e1", "agent-A", "chrome.exe", "ntdll.dll", "windows", "2026-06-08T10:00:00Z");
    crash("e2", "agent-A", "chrome.exe", "ntdll.dll", "windows", "2026-06-08T11:00:00Z");
    crash("e3", "agent-B", "chrome.exe", "chrome.dll", "windows", "2026-06-09T10:00:00Z");
    crash("e4", "agent-B", "Teams.exe", "ntdll.dll", "windows", "2026-06-09T11:00:00Z");

    // Per-app (chrome.exe): 3 crashes across 2 devices.
    auto as = store.dex_app_summary("chrome.exe");
    CHECK(as.crashes == 3);
    CHECK(as.hangs == 0);
    CHECK(as.distinct_devices == 2);
    CHECK(as.first_seen == "2026-06-08T10:00:00Z");
    CHECK(as.last_seen == "2026-06-09T10:00:00Z");

    auto am = store.dex_app_modules("chrome.exe");
    REQUIRE(am.size() == 2);
    CHECK(am[0].component == "ntdll.dll"); // 2 beats chrome.dll's 1
    CHECK(am[0].crashes == 2);

    auto ae = store.dex_app_exceptions("chrome.exe");
    REQUIRE(ae.size() == 1);
    CHECK(ae[0].reason == "0xC0000005");
    CHECK(ae[0].symbolic == "ACCESS_VIOLATION");
    CHECK(ae[0].crashes == 3);

    auto ad = store.dex_app_devices("chrome.exe");
    REQUIRE(ad.size() == 2);
    CHECK(ad[0].agent_id == "agent-A"); // 2 beats agent-B's 1
    CHECK(ad[0].crashes == 2);

    // Per-device (agent-A): 2 crashes, 1 distinct app; history newest-first.
    auto ds = store.dex_device_summary("agent-A");
    CHECK(ds.crashes == 2);
    CHECK(ds.signals == 2);
    CHECK(ds.distinct_apps == 1);

    auto dh = store.dex_device_history("agent-A");
    REQUIRE(dh.size() == 2);
    CHECK(dh[0].event_id == "e2"); // newest first (11:00 before 10:00)
    CHECK(dh[0].subject == "chrome.exe");
    CHECK(dh[1].event_id == "e1");
}

TEST_CASE("GuaranteedStateStore: multi-signal summary, hang-aware apps, boot stats",
          "[pg][guaranteed_state_store][dex][signals]") {
    // The multi-signal read model: mixed signal types land in ONE projection;
    // dex_signal_summary rolls up per type; dex_top_apps pivots crash+hang; the
    // boot aggregations read the metric column; the device history is unified.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto sig = [&](const std::string& id, const std::string& agent, const std::string& type,
                   const std::string& json, const std::string& ts) {
        GuaranteedStateEventRow e;
        e.event_id = id;
        e.rule_id = "__observation__";
        e.agent_id = agent;
        e.event_type = type;
        e.severity = "info";
        e.detail_json = json;
        e.timestamp = ts;
        REQUIRE(store.insert_event(e));
    };
    sig("s1", "agent-A", "process.crashed",
        R"({"subject":"chrome.exe","reason":"0xC0000005","symbolic":"ACCESS_VIOLATION","component":"ntdll.dll","platform":"windows"})",
        "2026-06-09T10:00:00Z");
    sig("s2", "agent-A", "process.hung",
        R"({"subject":"chrome.exe","symbolic":"NOT_RESPONDING","platform":"windows"})",
        "2026-06-09T10:05:00Z");
    sig("s3", "agent-B", "process.hung",
        R"({"subject":"chrome.exe","symbolic":"NOT_RESPONDING","platform":"windows"})",
        "2026-06-09T10:06:00Z");
    sig("s4", "agent-A", "service.crashed",
        R"({"subject":"Spooler","reason":"7031","symbolic":"SERVICE_CRASHED","platform":"windows"})",
        "2026-06-09T11:00:00Z");
    sig("s5", "agent-A", "os.boot",
        R"({"subject":"boot","metric":43210.0,"platform":"windows"})", "2026-06-09T08:00:00Z");
    sig("s6", "agent-B", "os.boot",
        R"({"subject":"boot","metric":91000.0,"platform":"windows"})", "2026-06-09T08:05:00Z");

    // Whole-catalogue rollup: 4 types, ordered by count.
    auto summary = store.dex_signal_summary();
    REQUIRE(summary.size() == 4);
    CHECK(summary[0].count == 2); // hung / boot tie at 2, obs_type ASC → os.boot first
    CHECK(summary[0].obs_type == "os.boot");
    CHECK(summary[1].obs_type == "process.hung");
    CHECK(summary[1].distinct_devices == 2);

    // Hang-aware app table: chrome has 1 crash + 2 hangs across 2 devices.
    auto apps = store.dex_top_apps();
    REQUIRE(apps.size() == 1); // only crash/hang subjects (Spooler/boot are other types)
    CHECK(apps[0].subject == "chrome.exe");
    CHECK(apps[0].crashes == 1);
    CHECK(apps[0].hangs == 2);
    CHECK(apps[0].distinct_devices == 2);

    // Crash summary stays crash-scoped: 1 crash, 1 device.
    auto cs = store.dex_crash_summary();
    CHECK(cs.total_crashes == 1);
    CHECK(cs.distinct_devices == 1);

    // Boot stats from the metric column.
    auto boot = store.dex_boot_stats();
    CHECK(boot.boots == 2);
    CHECK(boot.avg_ms == 67105.0); // (43210 + 91000) / 2
    CHECK(boot.max_ms == 91000.0);
    CHECK(boot.distinct_devices == 2);
    auto slow = store.dex_slowest_boots();
    REQUIRE(slow.size() == 2);
    CHECK(slow[0].agent_id == "agent-B"); // slowest average first
    CHECK(slow[0].max_ms == 91000.0);

    // Per-app summary spans crash + hang, fleet-wide.
    auto as = store.dex_app_summary("chrome.exe");
    CHECK(as.crashes == 1);  // s1
    CHECK(as.hangs == 2);    // s2 + s3
    CHECK(as.distinct_devices == 2);

    // Per-device summary + unified history for agent-A: crash + hang + service + boot.
    auto ds = store.dex_device_summary("agent-A");
    CHECK(ds.crashes == 1);
    CHECK(ds.hangs == 1);
    CHECK(ds.signals == 4);
    CHECK(ds.distinct_apps == 1); // only crash/hang subjects count as apps

    auto dh = store.dex_device_history("agent-A");
    REQUIRE(dh.size() == 4);
    CHECK(dh[0].obs_type == "service.crashed"); // newest first
    CHECK(dh[3].obs_type == "os.boot");
    CHECK(dh[3].metric == 43210.0);
}

TEST_CASE("GuaranteedStateStore: dex_signal_summary(platform) scopes to one OS; "
          "empty stays all-OS (#1746)",
          "[pg][guaranteed_state_store][dex][signals]") {
    // The Catalogue's single-OS filter needs its own signal rollup, not the
    // all-fleet composite read under a Linux/macOS heading. `platform` is an
    // ADDITIVE filter on top of the existing GROUP BY obs_type — proven here on
    // both a type shared across all three platforms (process.crashed) and a type
    // exclusive to one (network.wifi_drop, macOS-only).
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto sig = [&](const std::string& id, const std::string& agent, const std::string& type,
                   const std::string& plat, const std::string& ts) {
        GuaranteedStateEventRow e;
        e.event_id = id;
        e.rule_id = "__observation__";
        e.agent_id = agent;
        e.event_type = type;
        e.severity = "info";
        e.detail_json = "{\"subject\":\"x\",\"platform\":\"" + plat + "\"}";
        e.timestamp = ts;
        REQUIRE(store.insert_event(e));
    };
    sig("w1", "agent-A", "process.crashed", "windows", "2026-06-09T10:00:00Z");
    sig("w2", "agent-B", "process.crashed", "windows", "2026-06-09T10:05:00Z");
    sig("l1", "agent-C", "process.crashed", "linux", "2026-06-09T10:10:00Z");
    sig("m1", "agent-D", "process.crashed", "macos", "2026-06-09T10:15:00Z");
    sig("m2", "agent-D", "network.wifi_drop", "macos", "2026-06-09T10:20:00Z");
    // Non-canonical agent token: canonicalized at projection write (the per-OS
    // lens filters on exact platform match, so "Darwin" must land in "macos"
    // rather than silently vanishing from every single-OS lens).
    sig("m3", "agent-E", "network.wifi_drop", "Darwin", "2026-06-09T10:25:00Z");
    // QE-c: three more canonicalization edge cases on top of "Darwin" above.
    // "WINDOWS" (all-caps) lowercases to "windows" then starts_with("win") — an
    // ordinary canonicalization, landing in the windows lens like w1/w2.
    sig("w3", "agent-F", "process.crashed", "WINDOWS", "2026-06-09T10:30:00Z");
    // "Linux " (trailing space) lowercases to "linux " — starts_with("lin") still
    // matches on the PREFIX, and the canonicalization is a full literal
    // reassignment (not a trim), so the trailing space is discarded and this
    // still lands in the linux lens like l1.
    sig("l2", "agent-G", "process.crashed", "Linux ", "2026-06-09T10:35:00Z");
    // "" (no platform key/empty value): none of the canonicalization branches
    // match, so it stays "". It can never equal "windows"/"linux"/"macos" in the
    // scoped query's exact-match filter, so it is EXCLUDED from every single-OS
    // lens — but it has no platform filter at all in the unscoped ("all") query,
    // so it still counts there.
    sig("e1", "agent-H", "process.crashed", "", "2026-06-09T10:40:00Z");

    // Scoped to macOS: only macOS's own rows — its slice of process.crashed AND
    // its exclusive network.wifi_drop (including the "Darwin"-token agent). The
    // new WINDOWS/"Linux "/"" rows above are all non-macOS, so this is unchanged.
    // Windows/Linux crashes never leak in.
    auto mac = store.dex_signal_summary("", "macos");
    REQUIRE(mac.size() == 2);
    CHECK(mac[0].obs_type == "network.wifi_drop"); // count 2 > crashed's 1
    CHECK(mac[0].count == 2);
    CHECK(mac[0].distinct_devices == 2);
    CHECK(mac[1].obs_type == "process.crashed");
    CHECK(mac[1].count == 1);
    CHECK(mac[1].distinct_devices == 1);

    // Scoped to windows: w1/w2 plus the canonicalized "WINDOWS" row (w3) = 3
    // crashes, 3 devices; the macOS-only wifi_drop and the empty-platform row
    // are both absent.
    auto win = store.dex_signal_summary("", "windows");
    REQUIRE(win.size() == 1);
    CHECK(win[0].obs_type == "process.crashed");
    CHECK(win[0].count == 3);
    CHECK(win[0].distinct_devices == 3);

    // Scoped to linux: l1 plus the canonicalized "Linux " row (l2) = 2 crashes,
    // 2 devices; the empty-platform row is absent (never matches an exact
    // single-OS filter).
    auto lin = store.dex_signal_summary("", "linux");
    REQUIRE(lin.size() == 1);
    CHECK(lin[0].obs_type == "process.crashed");
    CHECK(lin[0].count == 2);
    CHECK(lin[0].distinct_devices == 2);

    // Unscoped (platform="", the default parameter): the full all-OS rollup now
    // also picks up the WINDOWS/"Linux "/"" rows — process.crashed climbs from 4
    // to 7 rows / 7 distinct agents (the empty-platform row counts here even
    // though it's excluded from every single-OS lens above); network.wifi_drop
    // is macOS-only (2 rows incl. the canonicalized "Darwin" agent), unchanged.
    auto all = store.dex_signal_summary();
    REQUIRE(all.size() == 2);
    CHECK(all[0].obs_type == "process.crashed"); // count=7 beats wifi_drop's count=2
    CHECK(all[0].count == 7);
    CHECK(all[0].distinct_devices == 7);
    CHECK(all[1].obs_type == "network.wifi_drop");
    CHECK(all[1].count == 2);
}

TEST_CASE("GuaranteedStateStore: event query honours limit/offset",
          "[pg][guaranteed_state_store][events]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    for (int i = 0; i < 10; ++i) {
        auto e = make_event("evt-" + std::to_string(i), "rule-1", "agent-A");
        REQUIRE(store.insert_event(e));
    }

    GuaranteedStateEventQuery q;
    q.limit = 3;
    auto page1 = store.query_events(q);
    CHECK(page1.size() == 3);

    q.offset = 3;
    auto page2 = store.query_events(q);
    CHECK(page2.size() == 3);
}

TEST_CASE("GuaranteedStateStore: event round-trip preserves all fields",
          "[pg][guaranteed_state_store][events]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto in = make_event("evt-1", "rule-1", "agent-X");
    in.detail_json = R"({"process":"notepad.exe","pid":1234})"; // route a' structured companion
    REQUIRE(store.insert_event(in));

    auto out = store.query_events();
    REQUIRE(out.size() == 1);
    CHECK(out[0].detail_json == in.detail_json); // persisted + read back through the new column
    CHECK(out[0].event_id == in.event_id);
    CHECK(out[0].rule_id == in.rule_id);
    CHECK(out[0].agent_id == in.agent_id);
    CHECK(out[0].event_type == in.event_type);
    CHECK(out[0].severity == in.severity);
    CHECK(out[0].guard_type == in.guard_type);
    CHECK(out[0].guard_category == in.guard_category);
    CHECK(out[0].detected_value == in.detected_value);
    CHECK(out[0].expected_value == in.expected_value);
    CHECK(out[0].remediation_action == in.remediation_action);
    CHECK(out[0].remediation_success == in.remediation_success);
    CHECK(out[0].detection_latency_us == in.detection_latency_us);
    CHECK(out[0].remediation_latency_us == in.remediation_latency_us);
    CHECK(out[0].timestamp == in.timestamp);
}

TEST_CASE("GuaranteedStateStore: duplicate event_id rejected with kConflictPrefix",
          "[pg][guaranteed_state_store][events][conflict]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.insert_event(make_event("evt-same", "rule-1", "agent-A")));
    auto dup = store.insert_event(make_event("evt-same", "rule-1", "agent-B"));
    REQUIRE_FALSE(dup.has_value());
    CHECK(is_conflict_error(dup.error()));
    CHECK(dup.error().find("evt-same") != std::string::npos);
}

// ── Regression tests carried forward from PR 1 governance ──────────────────

TEST_CASE("GuaranteedStateStore: empty signature round-trip stays empty",
          "[pg][guaranteed_state_store][rules]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto r = make_rule("r-empty", "sig-empty");
    r.signature.clear();
    REQUIRE(store.create_rule(r));

    auto fetched = store.get_rule("r-empty");
    REQUIRE(fetched.has_value());
    REQUIRE(fetched->has_value());
    CHECK((*fetched)->signature.empty());

    auto listed = store.list_rules();
    REQUIRE(listed.has_value());
    REQUIRE(listed->size() == 1);
    CHECK((*listed)[0].signature.empty());
}

TEST_CASE("GuaranteedStateStore: event query tie-breaks by event_id on equal timestamp",
          "[pg][guaranteed_state_store][events]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.insert_event(
        make_event("older", "rule-1", "agent-A", "high", "2026-04-19T12:00:00Z")));
    REQUIRE(store.insert_event(
        make_event("newer", "rule-1", "agent-A", "high", "2026-04-19T13:00:00Z")));

    auto out = store.query_events();
    REQUIRE(out.size() == 2);
    CHECK(out[0].event_id == "newer");
    CHECK(out[1].event_id == "older");

    YUZU_REQUIRE_PG_DB_TPL(db2, guardianstate_tpl);

    PgPool pool2{{.conninfo = db2.dsn(), .size = 4}};

    GuaranteedStateStore tie_store(pool2);
    const std::string same_ts = "2026-04-19T12:00:00Z";
    REQUIRE(tie_store.insert_event(make_event("evt-A", "r", "a", "high", same_ts)));
    REQUIRE(tie_store.insert_event(make_event("evt-Z", "r", "a", "high", same_ts)));
    REQUIRE(tie_store.insert_event(make_event("evt-M", "r", "a", "high", same_ts)));

    auto tied = tie_store.query_events();
    REQUIRE(tied.size() == 3);
    CHECK(tied[0].event_id == "evt-Z");
    CHECK(tied[1].event_id == "evt-M");
    CHECK(tied[2].event_id == "evt-A");
}

TEST_CASE("GuaranteedStateStore: query_events limit is clamped and semantically consistent",
          "[pg][guaranteed_state_store][events]") {
    static_assert(kMaxEventsLimit == 10'000,
                  "kMaxEventsLimit changed — update REST layer cap + docs");

    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);

    PgPool pool{{.conninfo = db.dsn(), .size = 4}};

    GuaranteedStateStore store(pool);
    for (int i = 0; i < 5; ++i) {
        REQUIRE(store.insert_event(make_event("evt-" + std::to_string(i), "r", "a")));
    }

    GuaranteedStateEventQuery upper;
    upper.limit = 2'000'000'000;
    CHECK(store.query_events(upper).size() == 5);

    GuaranteedStateEventQuery zero;
    zero.limit = 0;
    CHECK(store.query_events(zero).empty());

    GuaranteedStateEventQuery neg;
    neg.limit = -42;
    CHECK(store.query_events(neg).empty());
}

TEST_CASE("GuaranteedStateStore: bad path yields closed store with sentinel returns",
          "[guaranteed_state_store][db]") {
    // Postgres redesign (ADR-0038): "bad file path" has no analogue — the
    // equivalent closed-store condition is an unreachable/invalid DSN, which
    // PgPool detects at construction (valid() == false, every acquire fails).
    // No live rig needed for this one (deliberately NOT gated behind
    // YUZU_REQUIRE_PG_DB_TPL) — an unroutable address fails fast everywhere.
    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    // metrics is declared BEFORE bad so it outlives the store: bad only holds
    // a borrowed MetricsRegistry* (set_metrics), and C++ destroys locals in
    // reverse declaration order — declaring metrics first means bad's
    // destructor runs while metrics is still alive, never after.
    yuzu::MetricsRegistry metrics;
    GuaranteedStateStore bad(bad_pool);
    CHECK_FALSE(bad.is_open());
    bad.set_metrics(&metrics);

    CHECK_FALSE(bad.create_rule(make_rule("x", "x")));
    CHECK_FALSE(bad.update_rule(make_rule("x", "x")));
    CHECK_FALSE(bad.delete_rule("x"));
    // get_rule is three-state (ADR-0038): a closed store degrades (unexpected),
    // never a bare "not found" — CHECK_FALSE(...has_value()) on the OUTER
    // expected is the correct closed-store assertion here.
    CHECK_FALSE(bad.get_rule("x").has_value());
    // list_rules is type-distinguishable: closed store -> std::unexpected, not
    // a silent empty vector (the catastrophic-read posture this ADR exists
    // for) — assert on the outer expected, not .empty().
    CHECK_FALSE(bad.list_rules().has_value());
    CHECK_FALSE(bad.insert_event(make_event("e", "r", "a")));
    CHECK(bad.query_events().empty()); // DEX/analytics read: plain empty-on-degrade
    CHECK(bad.rule_count() == 0);
    CHECK(bad.event_count() == 0);
    // Batch insert on a closed store is also a graceful error.
    auto batch = bad.insert_events({make_event("e", "r", "a")});
    CHECK_FALSE(batch.has_value());
    // errored_rule_count (ADR-0017 INV-3, #2298 item 6d) is std::expected like
    // get_rule/list_rules above -> closed store is std::unexpected, never a
    // silent 0 (that posture is exactly what this method exists to avoid on
    // the confined read path), for BOTH the unscoped and an engaged non-empty
    // scoped form. The ONE deliberate exception: an engaged but EMPTY scope
    // (INV-2, "a real grant with zero visible agents is a legitimate 0, not a
    // denial") short-circuits to success(0) before the open-check even runs
    // -- pinned explicitly here (found by cpp-expert review: an earlier
    // version of this comment claimed "never a silent 0" unqualified, which
    // this third case disproves) so the fast path stays a documented
    // exception, not an accidental gap in this test's own coverage.
    CHECK_FALSE(bad.errored_rule_count(std::nullopt).has_value());
    CHECK_FALSE(bad.errored_rule_count(std::vector<std::string>{"WS-1"}).has_value());
    auto empty_scope = bad.errored_rule_count(std::vector<std::string>{});
    REQUIRE(empty_scope.has_value());
    CHECK(*empty_scope == 0);

    // #4856: the AUTHORITATIVE rule/status reads must ALSO bump the shared
    // yuzu_server_guardian_read_degrade_total counter, distinguished by
    // source="guardian_rules" from the DEX/observation family's
    // source="guardian_state" (query_events above) — previously these seven
    // reads surfaced a typed error WITHOUT bumping anything, so a sustained
    // read degrade on the catastrophic-read set was invisible on /metrics.
    CHECK_FALSE(bad.agent_rule_statuses("").has_value());
    CHECK_FALSE(bad.agent_rule_statuses_for_agent("agent-a").has_value());
    CHECK_FALSE(bad.rule_names().has_value());
    CHECK_FALSE(bad.rule_names_for(std::vector<std::string>{"r1"}).has_value());
    // rule_names_for's own empty-input short-circuit (success, not degrade —
    // mirrored by errored_rule_count's empty-scope case above) must NOT
    // increment either.
    auto empty_names = bad.rule_names_for(std::vector<std::string>{});
    REQUIRE(empty_names.has_value());
    CHECK(empty_names->empty());
    // 8 authoritative-read degrades total: get_rule, list_rules,
    // agent_rule_statuses, agent_rule_statuses_for_agent, rule_names,
    // rule_names_for, and errored_rule_count's two non-empty-scope calls
    // above — the metric label itself, not just the typed-error return, is
    // what a regression here would silently drop.
    CHECK(metrics
              .counter("yuzu_server_guardian_read_degrade_total",
                       {{"reason", "store_not_open"}, {"source", "guardian_rules"}})
              .value() == 8.0);
    // The DEX/observation family's own store_not_open degrade (query_events
    // above) stays on the ORIGINAL source — proof the two families are
    // counted separately rather than merged into one undifferentiated total.
    CHECK(metrics
              .counter("yuzu_server_guardian_read_degrade_total",
                       {{"reason", "store_not_open"}, {"source", "guardian_state"}})
              .value() == 1.0);
    // #4855: dex_device_signal_summary_checked is the type-distinguishable
    // twin — a closed store degrades to std::nullopt, never a silent empty
    // vector indistinguishable from "no signals" (that indistinguishability
    // is exactly what fabricated the healthy score-100 bug this twin fixes).
    CHECK_FALSE(bad.dex_device_signal_summary_checked("a1").has_value());
    // The plain form stays #2659-style empty-on-degrade (unchanged, byte-
    // identical to every other DEX/analytics read on a closed store).
    CHECK(bad.dex_device_signal_summary("a1").empty());
}

// #4855: dex_device_signal_summary_checked must distinguish a genuine
// QUERY-LEVEL failure (not just store-not-open above) from "no signals" —
// dropping the underlying table mid-test (guardian_agent_rule_status's own
// degrade tests use the identical DROP-TABLE-on-a-second-connection
// technique) forces exactly that failure mode while the store itself stays
// open (every OTHER table is intact).
TEST_CASE("GuaranteedStateStore: dex_device_signal_summary_checked distinguishes a query-level "
          "degrade from genuinely no signals",
          "[pg][guaranteed_state_store][dex][degraded]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());

    // Baseline: a real (empty) result is Some(empty), not None — the ONLY
    // thing this twin exists to distinguish is the degrade case below.
    {
        auto ok = store.dex_device_signal_summary_checked("no-such-agent");
        REQUIRE(ok.has_value());
        CHECK(ok->empty());
    }

    {
        pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE guaranteed_state_store.guardian_observations")};
        REQUIRE(d.ok());
    }

    auto degraded = store.dex_device_signal_summary_checked("no-such-agent");
    CHECK_FALSE(degraded.has_value());
    // The plain form still collapses the SAME degrade to empty (#2659
    // posture, unchanged) — the two forms must read the identical failure
    // differently ONLY at the type level, not the underlying query.
    CHECK(store.dex_device_signal_summary("no-such-agent").empty());
}

TEST_CASE("GuaranteedStateStore: migration is idempotent across re-open",
          "[pg][guaranteed_state_store][db]") {
    // Postgres redesign (ADR-0038): "re-open the same file" -> a second store
    // against the SAME dsn (see the policy_generation-persists-across-reopen
    // test above for the same pattern). Exercises PgMigrationRunner's
    // idempotency (the second construction's migration pass is a no-op
    // against the already-applied schema_meta version).
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);

    {
        PgPool pool1{{.conninfo = db.dsn(), .size = 4}};
        GuaranteedStateStore s1(pool1);
        REQUIRE(s1.is_open());
        REQUIRE(s1.create_rule(make_rule("rule-1", "survives-reopen")));
        REQUIRE(s1.insert_event(make_event("evt-1", "rule-1", "agent-A")));
        REQUIRE(s1.rule_count() == 1);
        REQUIRE(s1.event_count() == 1);
    }

    {
        PgPool pool2{{.conninfo = db.dsn(), .size = 4}};
        GuaranteedStateStore s2(pool2);
        REQUIRE(s2.is_open());
        CHECK(s2.rule_count() == 1);
        CHECK(s2.event_count() == 1);

        auto r = s2.get_rule("rule-1");
        REQUIRE(r.has_value());
        REQUIRE(r->has_value());
        CHECK((*r)->name == "survives-reopen");

        REQUIRE(s2.insert_event(make_event("evt-2", "rule-1", "agent-B")));
        CHECK(s2.event_count() == 2);
    }
}

// ── #452 §7 — batch insert_events ────────────────────────────────────────

TEST_CASE("GuaranteedStateStore: batch insert writes all rows transactionally",
          "[pg][guaranteed_state_store][events][batch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    std::vector<GuaranteedStateEventRow> batch;
    for (int i = 0; i < 50; ++i) {
        batch.push_back(make_event("evt-" + std::to_string(i), "rule-1", "agent-A"));
    }

    auto n = store.insert_events(batch);
    REQUIRE(n.has_value());
    CHECK(*n == 50);
    CHECK(store.event_count() == 50);
    CHECK(store.events_written_total() == 50);
}

TEST_CASE("GuaranteedStateStore: batch insert with duplicate rolls back whole batch",
          "[pg][guaranteed_state_store][events][batch][conflict]") {
    // Confirm the transactional contract: any failing row invalidates the
    // whole batch, so REST handlers never have to reason about partial
    // commits. First write a row that will collide with the batch.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.insert_event(make_event("evt-collision", "rule-1", "agent-A")));
    CHECK(store.event_count() == 1);

    std::vector<GuaranteedStateEventRow> batch = {
        make_event("evt-new-1", "rule-1", "agent-A"),
        make_event("evt-new-2", "rule-1", "agent-A"),
        make_event("evt-collision", "rule-1", "agent-B"),  // conflict
        make_event("evt-new-3", "rule-1", "agent-A"),
    };

    auto r = store.insert_events(batch);
    REQUIRE_FALSE(r.has_value());
    CHECK(is_conflict_error(r.error()));
    // None of the batch's new IDs should have landed.
    CHECK(store.event_count() == 1);
    CHECK(store.events_written_total() == 1);

    // Regression guard for the B1 transaction-safety fix: a rolled-back batch must
    // NOT leave the connection wedged in an open transaction. A subsequent batch
    // (which issues its own BEGIN) must succeed — before the SqliteTxn RAII owner,
    // a failure/exception between BEGIN and COMMIT could strand the transaction and
    // make the next BEGIN fail (and a still-open stmt make sqlite3_close BUSY-leak).
    auto after = store.insert_events({make_event("evt-after-rollback", "rule-1", "agent-A")});
    REQUIRE(after.has_value());
    CHECK(store.event_count() == 2);
}

TEST_CASE("GuaranteedStateStore: batch insert of empty vector is a no-op",
          "[pg][guaranteed_state_store][events][batch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto r = store.insert_events({});
    REQUIRE(r.has_value());
    CHECK(*r == 0);
    CHECK(store.event_count() == 0);
}

TEST_CASE("GuaranteedStateStore: insert_events batch projects only observations",
          "[pg][guaranteed_state_store][events][dex]") {
    // Governance qa-B1: the batch path also projects ruleless observations into
    // guardian_observations. A mixed batch (drift + observations) must project
    // exactly the observation rows — and a projection failure must NOT roll back
    // the batch (degrade-don't-destroy, UP-1).
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    std::vector<GuaranteedStateEventRow> batch;
    auto obs = [](const std::string& id, const std::string& proc) {
        GuaranteedStateEventRow e;
        e.event_id = id;
        e.rule_id = "__observation__";
        e.agent_id = "agent-A";
        e.event_type = "process.crashed";
        e.severity = "info";
        e.detail_json = R"({"subject":")" + proc + R"(","reason":"0xC0000005","platform":"windows"})";
        e.timestamp = "2026-06-09T10:00:00Z";
        return e;
    };
    batch.push_back(make_event("d1", "rule-1", "agent-A")); // drift — must NOT project
    batch.push_back(obs("o1", "chrome.exe"));
    batch.push_back(obs("o2", "Teams.exe"));
    auto n = store.insert_events(batch);
    REQUIRE(n.has_value());
    CHECK(*n == 3);
    auto rows = store.query_observations();
    REQUIRE(rows.size() == 2); // only the two observations projected
    CHECK(rows[0].subject != rows[1].subject);
    for (const auto& r : rows)
        CHECK((r.subject == "chrome.exe" || r.subject == "Teams.exe"));
}

TEST_CASE("GuaranteedStateStore: batch ingest never pollutes the census with the sentinel",
          "[pg][guaranteed_state_store][events][dex][security]") {
    // Adversarial-review F1: the batch insert_events path (the preferred gRPC
    // GuaranteedStatePush ingest) must apply the SAME sentinel guard as the
    // single-row path — a batch carrying rule_id="__observation__" with a
    // census-mapping event_type (drift.detected) must NOT mint a phantom
    // (agent, __observation__) census row (§24). Enforce server-side, never trust
    // the agent to pair the sentinel with a non-census event_type.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    std::vector<GuaranteedStateEventRow> batch;
    // A real rule's drift (SHOULD create a census row) + a hostile sentinel row
    // with a census-mapping event_type (must NOT) in the same batch.
    batch.push_back(make_event("real-1", "rule-real", "agent-A")); // event_type drift.detected
    GuaranteedStateEventRow abuse;
    abuse.event_id = "abuse-1";
    abuse.rule_id = "__observation__";
    abuse.agent_id = "agent-A";
    abuse.event_type = "drift.detected"; // maps to a census state — the attack
    abuse.severity = "high";
    abuse.timestamp = "2026-06-09T10:00:00Z";
    batch.push_back(abuse);
    auto n = store.insert_events(batch);
    REQUIRE(n.has_value());
    CHECK(*n == 2); // both events recorded (the sentinel event itself is valid)
    // The real rule got its census row…
    auto census_real = store.agent_rule_statuses("rule-real");
    REQUIRE(census_real.has_value());
    CHECK(census_real->size() == 1);
    // …but the sentinel minted NONE (this is the F1 regression assertion).
    auto census_sentinel = store.agent_rule_statuses("__observation__");
    REQUIRE(census_sentinel.has_value());
    CHECK(census_sentinel->empty());
}

TEST_CASE("GuaranteedStateStore: projected fields are length-clamped (server-side)",
          "[pg][guaranteed_state_store][dex][security]") {
    // Governance sec-M1: the server must not trust an enrolled agent to clip —
    // an oversized subject is clamped (256 B) so it cannot bloat the projection
    // or the dashboard. UTF-8-safe so the clamp never tears a codepoint.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    const std::string huge(5000, 'A');
    GuaranteedStateEventRow c;
    c.event_id = "big-1";
    c.rule_id = "__observation__";
    c.agent_id = "agent-A";
    c.event_type = "process.crashed";
    c.severity = "info";
    c.detail_json = R"({"subject":")" + huge + R"(","reason":"0xC0000005","platform":"windows"})";
    c.timestamp = "2026-06-09T10:00:00Z";
    REQUIRE(store.insert_event(c));
    auto obs = store.query_observations();
    REQUIRE(obs.size() == 1);
    CHECK(obs[0].subject.size() <= 256);
}

TEST_CASE("GuaranteedStateStore: reap_expired reaps observations in lockstep with events",
          "[pg][guaranteed_state_store][dex][retention]") {
    // Governance qa-B2, ported to reap_expired()'s #2496 gc_sweep shape
    // (ADR-0038): a stale observation (projected via insert_event, so it
    // carries the parent event's ttl) is reaped in the SAME guarded pass as
    // its parent event; a fresh one survives. Ages both rows via a second
    // connection (the real projection sets both ttl_expires_at columns
    // identically at insert; this simulates wall-clock passing, not a
    // production code path) then calls the real reap_expired().
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool, /*retention_days=*/30);
    anchor_guard(store, db.dsn()); // consume the #2579 bootstrap decline before seeding
    auto obs = [&](const std::string& id) {
        GuaranteedStateEventRow e;
        e.event_id = id;
        e.rule_id = "__observation__";
        e.agent_id = "agent-A";
        e.event_type = "process.crashed";
        e.severity = "info";
        e.detail_json = R"({"subject":"chrome.exe","reason":"0xC0000005","platform":"windows"})";
        e.timestamp = "2026-06-09T10:00:00Z";
        REQUIRE(store.insert_event(e));
    };
    obs("fresh");
    obs("stale");
    REQUIRE(store.query_observations().size() == 2);

    {
        pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        // Age BOTH the event and its observation projection — the lockstep
        // invariant means reap_expired()'s probe/decline decision reads the
        // EVENTS table, so only the event's ttl actually gates the sweep; the
        // observation row is aged too for parity with how the real projection
        // always writes them equal.
        auto r1 = pg::exec_params(
            conn.get(),
            "UPDATE guaranteed_state_store.guaranteed_state_events SET ttl_expires_at = 1 "
            "WHERE event_id = 'stale'",
            std::vector<std::string>{});
        REQUIRE(r1.status() == PGRES_COMMAND_OK);
        auto r2 = pg::exec_params(
            conn.get(),
            "UPDATE guaranteed_state_store.guardian_observations SET ttl_expires_at = 1 "
            "WHERE event_id = 'stale'",
            std::vector<std::string>{});
        REQUIRE(r2.status() == PGRES_COMMAND_OK);
    }

    store.reap_expired();
    CHECK(store.events_reaped_total() == 1);
    CHECK(store.observations_reaped_total() == 1);
    auto survivors = store.query_observations();
    REQUIRE(survivors.size() == 1);
    CHECK(survivors[0].event_id == "fresh");
}

// ── #452 §5 — retention reaper ────────────────────────────────────────────

TEST_CASE("GuaranteedStateStore: retention_days=0 disables TTL",
          "[pg][guaranteed_state_store][retention]") {
    // Sentinel contract: non-positive retention parks ttl_expires_at at 0
    // so the reaper's partial index and WHERE predicate skip every row.
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool, /*retention_days=*/0);
    for (int i = 0; i < 5; ++i) {
        REQUIRE(store.insert_event(make_event("evt-" + std::to_string(i), "r", "a")));
    }
    // Explicit reap pass (ADR-0038: reap_expired() replaces the old background
    // cleanup thread's start_cleanup()/stop_cleanup()): nothing eligible
    // (ttl_expires_at parked at 0), event_count stays put.
    store.reap_expired();
    CHECK(store.event_count() == 5);
    CHECK(store.events_reaped_total() == 0);
}

// Quality-engineer gap (governance): the test above can't discriminate a
// broken `retention_window_secs` guard, because every row IT seeds gets
// ttl_expires_at=0 via compute_ttl_epoch()'s OWN, separate, unmodified
// `retention_days_ <= 0` sentinel — excluded from the reap probe's
// `ttl_expires_at > 0` predicate regardless of the horizon value, so
// `retention_window_secs`'s identically-shaped guard is never exercised.
// This test seeds rows with POSITIVE ttl_expires_at directly via SQL
// (bypassing compute_ttl_epoch entirely) under a NEGATIVE retention_days_ —
// legitimate input: the guard's own `<= 0` shape treats 0 and negative
// identically, so a negative value pins the same branch a future caller
// could reach. If the horizon guard were ever removed
// (`retention_window_secs = retention_days_ * 86400` unconditionally),
// -5 * 86400 would push `datable_horizon` into the PAST, wrongly excluding
// "future-live" from `datable` and turning a clean partial-expiry drain into
// a false `would_wipe` decline.
TEST_CASE("GuaranteedStateStore: negative retention_days computes the same "
          "zero-window reap horizon as zero",
          "[pg][guaranteed_state_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool, /*retention_days=*/-5);
    anchor_guard(store, db.dsn());

    REQUIRE(store.insert_event(make_event("old-expired", "r", "a")));
    REQUIRE(store.insert_event(make_event("future-live", "r", "a")));
    exec_sql(db.dsn(),
            "UPDATE guaranteed_state_store.guaranteed_state_events SET ttl_expires_at = "
            "(EXTRACT(EPOCH FROM clock_timestamp())::bigint - 500000) WHERE event_id = "
            "'old-expired'"); // ~5.8 days past — deeply expired regardless of horizon
    exec_sql(db.dsn(),
            "UPDATE guaranteed_state_store.guaranteed_state_events SET ttl_expires_at = "
            "(EXTRACT(EPOCH FROM clock_timestamp())::bigint + 100) WHERE event_id = "
            "'future-live'"); // barely in the future — inside a correct (0d+2d slack) horizon,
                              // outside a broken (negative-window) one

    store.reap_expired();
    CHECK(store.events_reaped_total() == 1); // clean partial-expiry drain, not a would_wipe decline
    CHECK(store.event_count() == 1);
    CHECK(query_scalar(db.dsn(), "SELECT event_id FROM guaranteed_state_store."
                                 "guaranteed_state_events") == "future-live");
}

TEST_CASE("GuaranteedStateStore: reap_expired deletes rows past ttl_expires_at, keeps fresh ones",
          "[pg][guaranteed_state_store][retention]") {
    // Ported to reap_expired()'s #2496 gc_sweep shape (ADR-0038) — a real PG
    // database so a second connection can poke ttl_expires_at directly and
    // exercise the same DELETE the guarded pass issues, without relying on a
    // wall-clock sleep or a background thread (reap_expired() is synchronous
    // now — no start_cleanup()/stop_cleanup() to drain).
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool, /*retention_days=*/30);
    anchor_guard(store, db.dsn()); // consume the #2579 bootstrap decline before seeding

    for (int i = 0; i < 3; ++i)
        REQUIRE(store.insert_event(make_event("fresh-" + std::to_string(i), "r", "a")));
    for (int i = 0; i < 3; ++i)
        REQUIRE(store.insert_event(make_event("stale-" + std::to_string(i), "r", "a")));
    CHECK(store.event_count() == 6);

    // Age only the "stale-*" rows via a second connection — mirrors the
    // sqlite3-second-handle trick the original test used, ported to libpq.
    {
        pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto r = pg::exec_params(
            conn.get(),
            "UPDATE guaranteed_state_store.guaranteed_state_events SET ttl_expires_at = 1 "
            "WHERE event_id LIKE 'stale-%'",
            std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    // expiring(3) < datable(6): not would_wipe — a clean pass drains immediately.
    store.reap_expired();
    CHECK(store.events_reaped_total() == 3);
    CHECK(store.event_count() == 3); // only the three "fresh" survivors
    auto out = store.query_events();
    for (const auto& e : out)
        CHECK(e.event_id.starts_with("fresh-"));
}

// reap_expired would_wipe decline-once (#2496 shape, mirrors ResultSetStore's
// gc_sweep test of the same name): when EVERY datable row is expired, part 1's
// would_wipe classifier trips — the pass reports the anomaly, records it in
// gc_meta, and declines to delete anything. An identical next pass (same fact
// set) is a suppressed repeat: the report is skipped, but the (capped) drain
// proceeds — a legitimately all-expired table still ages out, one pass later.
TEST_CASE("GuaranteedStateStore: reap_expired declines once on an all-expired "
          "(would_wipe) table, then drains",
          "[pg][guaranteed_state_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);
    // Anchored first: without this, pass 1's fact set carries no_anchor=true
    // (#2579 — a decline in its own right, would_wipe outranks it so the
    // decline reason is unaffected) but SETTLES the bootstrap marker, so pass
    // 2's fact set differs from pass 1's in that one field alone and is no
    // longer a suppressed repeat — it declines a second time instead of
    // draining. Anchoring first keeps this test's decline-once contract intact.
    anchor_guard(store, db.dsn());

    for (int i = 0; i < 3; ++i)
        REQUIRE(store.insert_event(make_event("wipe-" + std::to_string(i), "r", "a")));

    // Every row in the table is aged into the past — no live row survives, so
    // expiring == datable (would_wipe: expiring >= datable).
    {
        pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto r = pg::exec_params(
            conn.get(),
            "UPDATE guaranteed_state_store.guaranteed_state_events SET ttl_expires_at = 1",
            std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    auto gc_meta_anomaly_count = [&]() -> std::string {
        pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto r = pg::exec_params(
            conn.get(),
            "SELECT COUNT(*) FROM guaranteed_state_store.gc_meta WHERE key = "
            "'last_anomaly_facts'",
            std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        return std::string(PQgetvalue(r.get(), 0, 0));
    };

    // First pass: declines (would_wipe) — nothing reaped, the anomaly recorded.
    store.reap_expired();
    CHECK(store.events_reaped_total() == 0);
    CHECK(store.event_count() == 3); // still present — the decline held
    CHECK(gc_meta_anomaly_count() == "1");
    // The metric label itself, not just the functional decline (governance
    // gap): a regression mapping Wipe to declined_no_anchor would pass every
    // check above while silently firing the WRONG alert.
    CHECK(metrics.counter("yuzu_server_guardian_reap_passes_total", {{"result", "declined"}})
              .value() == 1.0);
    CHECK(metrics.counter("yuzu_server_guardian_reap_passes_total",
                          {{"result", "declined_no_anchor"}})
              .value() == 0.0);

    // Second pass: suppressed repeat (same fact set) — drains, capped.
    store.reap_expired();
    CHECK(store.events_reaped_total() == 3);
    CHECK(store.event_count() == 0);
    // The anomaly-dedup row is NOT cleared by a suppressed-repeat drain — it
    // is cleared only by a genuinely clean pass (asserted next), same as
    // ResultSetStore's gc_sweep test.
    CHECK(gc_meta_anomaly_count() == "1");

    REQUIRE(store.insert_event(make_event("fresh", "r", "a")));
    store.reap_expired(); // clean pass: nothing expired
    CHECK(store.events_reaped_total() == 3); // unchanged — nothing new reaped
    CHECK(gc_meta_anomaly_count() == "0");   // consumed/cleared
}

// fjarvis's PR #2663 review, "still open": no test seeded an honest OLD
// last_pass_now and advanced real elapsed time past kReapBigStepSecs to prove
// the Step anomaly actually fires — the would_wipe test above covers a
// DIFFERENT detector, and a regression that broke big_step construction (e.g.
// #2663's own pg_now switch getting the comparison backwards) would go
// uncaught. Seeds gc_meta directly (bootstrap already settled, a stale
// last_pass_now 2 days back — comfortably past the 1-day kReapBigStepSecs)
// rather than via anchor_guard(), which would always stamp a FRESH reading.
TEST_CASE("GuaranteedStateStore: reap_expired declines once on a big forward clock step, "
          "then drains",
          "[pg][guaranteed_state_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    const int64_t real_now = pg_now(db.dsn());
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    exec_sql(db.dsn(),
             "INSERT INTO guaranteed_state_store.gc_meta (key, value) VALUES "
             "('bootstrap_settled', '1'), ('last_pass_now', '" +
                 std::to_string(real_now - 2 * 86400) + "')");

    REQUIRE(store.insert_event(make_event("expired", "r", "a")));
    REQUIRE(store.insert_event(make_event("survivor", "r", "a"))); // keeps this out of would_wipe
    exec_sql(db.dsn(), "UPDATE guaranteed_state_store.guaranteed_state_events SET "
                       "ttl_expires_at = 1 WHERE event_id = 'expired'");

    // First pass: has_expired (partial — "survivor" keeps would_wipe false),
    // big_step (2 days > kReapBigStepSecs's 1 day) — declines, nothing reaped.
    store.reap_expired();
    CHECK(store.events_reaped_total() == 0);
    CHECK(store.event_count() == 2); // both still present — the decline held
    CHECK(query_scalar(db.dsn(), "SELECT value FROM guaranteed_state_store.gc_meta WHERE key = "
                                 "'last_anomaly_facts'") == "e-s--");
    CHECK(metrics.counter("yuzu_server_guardian_reap_passes_total", {{"result", "declined"}})
              .value() == 1.0);

    // Second pass: re-anchored by the first pass's own (unconditional) stamp,
    // so the delta collapses to ~0 — no longer a big step. Drains, capped.
    store.reap_expired();
    CHECK(store.events_reaped_total() == 1);
    CHECK(store.event_count() == 1); // only "survivor" remains
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM guaranteed_state_store.gc_meta WHERE key "
                                 "= 'last_anomaly_facts'") == "0"); // consumed/cleared
}

// #2579's missing-anchor trigger, ported: the disclosed shape, end to end. A
// fresh PG deploy — no `gc_meta` row exists yet — whose host clock is
// forward-skewed at the very first guarded pass. Some rows are already
// expired (written before the skew), one is still inside the window (written
// after it), so `0 < expiring < datable`: neither `would_wipe` nor `big_step`
// (no prior reading to compare against) trips. Before this fix, every
// detector was false, so the pass classified `Anomaly::None` and deleted with
// no decline, no anomaly record, and no counter — this is the review's own
// falsifier for the #2663 blocking finding. Deliberately NOT anchored first:
// the absence of a stored reading IS the input under test.
TEST_CASE("GuaranteedStateStore #2579: no stored reading + partial expiry declines, once",
          "[pg][guaranteed_state_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    REQUIRE(store.insert_event(make_event("anchor-expired", "r", "a")));
    REQUIRE(store.insert_event(make_event("anchor-live", "r", "a"))); // 30d-ahead ttl, survives
    // Only one of the two rows is aged into the past — expiring (1) < datable
    // (2), so would_wipe does NOT trip. That is the shape #2579 closes: before
    // it, nothing else would have declined either.
    exec_sql(db.dsn(), "UPDATE guaranteed_state_store.guaranteed_state_events SET "
                       "ttl_expires_at = 1 WHERE event_id = 'anchor-expired'");
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM guaranteed_state_store.gc_meta WHERE key "
                                 "= 'last_pass_now'") == "0"); // fresh deploy: no anchor yet

    // First pass: declines (NoAnchor) — nothing reaped, the anomaly recorded,
    // the bootstrap marker settled (so the trigger cannot be spent twice).
    store.reap_expired();
    CHECK(store.events_reaped_total() == 0);
    CHECK(store.event_count() == 2); // both rows still present — the decline held
    CHECK(query_scalar(db.dsn(), "SELECT value FROM guaranteed_state_store.gc_meta WHERE key = "
                                 "'last_anomaly_facts'") == "e---b");
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM guaranteed_state_store.gc_meta WHERE key "
                                 "= 'bootstrap_settled'") == "1");
    // The operator-facing metric label, not just the functional decline: a
    // regression mapping NoAnchor back to generic "declined" would still pass
    // every check above while silently breaking the documented alert
    // (increase(...{result="declined_no_anchor"}[24h]) > 1, metrics.md).
    CHECK(metrics.counter("yuzu_server_guardian_reap_passes_total",
                          {{"result", "declined_no_anchor"}})
              .value() == 1.0);
    CHECK(metrics.counter("yuzu_server_guardian_reap_passes_total", {{"result", "declined"}})
              .value() == 0.0);

    // Second pass: re-anchored (bootstrap_settled from pass 1), so this is a
    // genuinely CLEAN pass (Anomaly::None) — drains the one expired row,
    // capped as always, and clears the dedup row.
    store.reap_expired();
    CHECK(store.events_reaped_total() == 1);
    CHECK(store.event_count() == 1); // only "anchor-live" survives
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM guaranteed_state_store.gc_meta WHERE key "
                                 "= 'last_anomaly_facts'") == "0"); // consumed/cleared
    CHECK(metrics.counter("yuzu_server_guardian_reap_passes_total", {{"result", "swept"}})
              .value() == 1.0);

    // Once, not forever: a third pass against an already-settled bootstrap
    // marker does not decline again — nothing left to reap, clean no-op.
    store.reap_expired();
    CHECK(store.events_reaped_total() == 1); // unchanged
    // The bootstrap decline never recurs, no matter how many passes follow.
    CHECK(metrics.counter("yuzu_server_guardian_reap_passes_total",
                          {{"result", "declined_no_anchor"}})
              .value() == 1.0);
}

// Adversarial-review blocker (#2663, found independently by both reviewers):
// a FIXED "implausibly ahead" horizon cannot exceed every accepted
// `guardian_event_retention_days` configuration (no maximum is enforced at
// any ingress), so a long-retention deployment's own honest, live TTLs get
// excluded from `datable` and a partial-expiry pass misclassifies as a false
// `would_wipe` decline. This falsifier uses a 500-day retention — comfortably
// past the old fixed 400-day bound, comfortably short of anything else this
// test needs to worry about — with one genuinely expired row and one live
// row carrying that config's own honest ~500-day TTL. Anchored first so the
// #2579 no_anchor trigger (a different, already-covered decline path) can't
// also explain a decline here.
TEST_CASE("GuaranteedStateStore: reap_expired's datable horizon covers a long retention window",
          "[pg][guaranteed_state_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool, /*retention_days=*/500);
    REQUIRE(store.is_open());
    anchor_guard(store, db.dsn());

    REQUIRE(store.insert_event(make_event("long-expired", "r", "a")));
    REQUIRE(store.insert_event(make_event("long-live", "r", "a"))); // ~500d-ahead ttl
    exec_sql(db.dsn(), "UPDATE guaranteed_state_store.guaranteed_state_events SET "
                       "ttl_expires_at = 1 WHERE event_id = 'long-expired'");

    // expiring(1) < datable(2): a clean partial-expiry pass, PROVIDED the
    // probe horizon actually covers "long-live"'s ~500-day TTL. A fixed
    // 400-day horizon would exclude it from datable, making expiring(1) >=
    // datable(0..1) and falsely declining would_wipe instead.
    store.reap_expired();
    CHECK(store.events_reaped_total() == 1);
    CHECK(store.event_count() == 1); // only "long-live" survives — drained, not declined
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM guaranteed_state_store.gc_meta WHERE key "
                                 "= 'last_anomaly_facts'") == "0"); // no anomaly recorded
}

// The upper-bound clock sanitiser (#2663 review should-fix): the PRE-TXN
// plausibility check still reads reap_expired()'s own process clock (the
// actual retention DECISION reads PostgreSQL's own clock since the #2663
// fjarvis-review fix, same as AuditStore's cleanup_once(now)), so exercising
// the kMaxPlausibleNow branch needs the now_fn test seam — the ctor's third
// parameter, unset in every other test here and never wired from production
// (see the ctor doc comment).
TEST_CASE("GuaranteedStateStore: reap_expired declines an implausibly large clock reading",
          "[pg][guaranteed_state_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    // Comfortably past kMaxPlausibleNow (INT64_MAX / 4) without itself risking
    // overflow in the test's own arithmetic.
    const int64_t implausible_now = std::numeric_limits<int64_t>::max() / 2;
    GuaranteedStateStore store(pool, /*retention_days=*/30,
                               [implausible_now] { return implausible_now; });
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    REQUIRE(store.insert_event(make_event("evt", "r", "a")));
    exec_sql(db.dsn(), "UPDATE guaranteed_state_store.guaranteed_state_events SET "
                       "ttl_expires_at = 1 WHERE event_id = 'evt'");

    store.reap_expired();
    CHECK(store.events_reaped_total() == 0);
    CHECK(store.event_count() == 1); // declined before it ever reached the probe
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM guaranteed_state_store.gc_meta WHERE key "
                                 "= 'last_pass_now'") == "0"); // never reached the stamp
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM guaranteed_state_store.gc_meta WHERE key "
                                 "= 'bootstrap_settled'") == "0"); // rolled back, trigger stays armed
    CHECK(metrics.counter("yuzu_server_guardian_reap_passes_total", {{"result", "failed"}})
              .value() == 1.0);
}

// fjarvis's PR #2663 review (2026-08-07): reap_expired() decided against its
// own PROCESS clock (now_fn_/now_epoch()), not Postgres's. Two replicas whose
// process clocks disagree write the SAME shared gc_meta.last_pass_now row, and
// the probe itself compares ttl_expires_at against each replica's OWN `now` —
// so a replica running merely an hour fast (well under kReapBigStepSecs, 1
// day) reads a row that is still LIVE by every other clock as already
// expired. classify()'s existing detectors do not catch this: `has_expired`
// alone with no other trigger derives `Anomaly::None` — an ordinary clean
// sweep, zero anomaly recorded. This is the "one additional untraced failure
// mode (a consistently-fast replica could delete early with zero anomaly
// flagged)" the earlier governance run's `arch-M1` adjudication NAMED and then
// left unproven, capping it at MEDIUM/E6 on the (disproven) premise that
// multi-replica is not a supported deployment shape — the schema comment at
// gc_meta's own CREATE TABLE and ADR-0038's "Considered and rejected" section
// both say otherwise. Mirrors AuditStore's `#2360/1d`
// ("a skewed process clock cannot change the verdict") regression exactly.
TEST_CASE("GuaranteedStateStore #2663 fjarvis H1: a fast replica cannot sweep a row that is "
          "still live by Postgres's own clock",
          "[pg][guaranteed_state_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    const int64_t real_now = pg_now(db.dsn());
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore replica_a(pool, /*retention_days=*/30);
    REQUIRE(replica_a.is_open());
    anchor_guard(replica_a, db.dsn());

    REQUIRE(replica_a.insert_event(make_event("still-live", "r", "a")));
    // 30 minutes in the FUTURE by the real clock.
    exec_sql(db.dsn(), "UPDATE guaranteed_state_store.guaranteed_state_events SET ttl_expires_at "
                       "= " + std::to_string(real_now + 1800) + " WHERE event_id = 'still-live'");
    // A second row, further out, so this is a PARTIAL expiry (0 < expiring <
    // datable) under replica B's clock, not a would_wipe — a single-row table
    // makes expiring==datable trivially, which the existing Wipe detector
    // already declines and would mask the defect this test is isolating.
    REQUIRE(replica_a.insert_event(make_event("far-live", "r", "a")));
    exec_sql(db.dsn(), "UPDATE guaranteed_state_store.guaranteed_state_events SET ttl_expires_at "
                       "= " + std::to_string(real_now + 5000) + " WHERE event_id = 'far-live'");

    // Replica B's process clock is an hour FAST — comfortably under
    // kReapBigStepSecs (1 day), so big_step never fires either.
    GuaranteedStateStore replica_b(pool, /*retention_days=*/30,
                                   [real_now] { return real_now + 3600; });
    REQUIRE(replica_b.is_open());
    yuzu::MetricsRegistry metrics;
    replica_b.set_metrics(&metrics);
    replica_b.reap_expired();

    // FIXED: replica B's own clock cannot move the verdict — "still-live" is
    // still live by PostgreSQL's own clock, so both rows survive and the pass
    // is a clean no-op, not a silent sweep.
    CHECK(replica_a.event_count() == 2);
    CHECK(metrics.counter("yuzu_server_guardian_reap_passes_total", {{"result", "swept"}})
              .value() == 0.0);

    // The shared ANCHOR itself must reflect PG's clock, not replica B's own
    // skewed reading (quality-engineer, Gate 8: gc_meta is "the transmission
    // medium" per the fix's own comment — a hypothetical partial revert of
    // only the stamp line would still pass the checks above while poisoning
    // this row for the next replica's prev-comparison). Tolerance is wide
    // (60s) purely for test-execution latency, nowhere near replica B's
    // 3600s skew.
    const int64_t stamped =
        std::stoll(query_scalar(db.dsn(), "SELECT value FROM guaranteed_state_store.gc_meta "
                                          "WHERE key = 'last_pass_now'"));
    CHECK(std::abs(stamped - pg_now(db.dsn())) < 60);
}

TEST_CASE("GuaranteedStateStore: reap_expired is a no-op on a closed store",
          "[guaranteed_state_store][retention]") {
    // ADR-0038: reap_expired() replaces the old background-thread start_cleanup()/
    // stop_cleanup(); it must be safe to call directly on a closed store (guarded
    // by is_open() at its own top, same as every other method) — an unroutable
    // DSN closed-store condition, same as the bad-path test above.
    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    GuaranteedStateStore bad(bad_pool);
    REQUIRE_FALSE(bad.is_open());
    bad.reap_expired();
    SUCCEED();
}

// gc_sweep cap (mirrors ResultSetStore's "GC sweep caps a large expired batch
// at kGcSweepCapPerPass"): bulk-insert kReapCapPerPass(10000)+1 expired,
// DISTINCT-ttl events (+ their observation projections, for lockstep parity)
// directly via SQL — looping insert_event() 10001 times would make this test
// the slow part of the whole suite. A `cap-live` (unexpired) row seeded
// alongside keeps datable (10002) strictly greater than expiring (10001) so
// part 1's would_wipe classifier (expiring >= datable) does NOT trip — that
// shape is covered separately below. Anchored first (`anchor_guard`) so the
// #2579 missing-anchor trigger doesn't decline this pass instead — with the
// bootstrap marker already settled and no prior gc_meta reading to trip
// big_step, this pass classifies clean (Anomaly::None) and the unconditional
// per-pass cap is the only thing bounding the delete on EACH of the two
// lockstep DELETEs — exactly what this test pins. Contract note:
// reap_expired() returns void — the cap is observed via the cumulative
// events_reaped_total()/observations_reaped_total() counters, not a return
// value (unlike ResultSetStore::gc_sweep(), which returns the per-call count
// directly).
TEST_CASE("GuaranteedStateStore: reap_expired caps a large expired batch at kReapCapPerPass",
          "[pg][guaranteed_state_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());
    anchor_guard(store, db.dsn()); // consume the #2579 bootstrap decline before seeding

    {
        pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        // 10001 events, each with its OWN ttl_expires_at (1..10001, all
        // strictly in the past) — distinct ttls so the cap boundary, not a
        // tie, decides which rows land in the first pass's LIMIT.
        auto ev = pg::exec_params(
            conn.get(),
            "INSERT INTO guaranteed_state_store.guaranteed_state_events "
            "(event_id, rule_id, agent_id, event_type, severity, timestamp, ttl_expires_at) "
            "SELECT 'cap-evt-' || lpad(g::text, 6, '0'), 'r', 'a', 'drift.remediated', 'high', "
            "'2026-04-19T12:00:00Z', g "
            "FROM generate_series(1, 10001) AS g",
            std::vector<std::string>{});
        REQUIRE(ev.status() == PGRES_COMMAND_OK);
        auto obs = pg::exec_params(
            conn.get(),
            "INSERT INTO guaranteed_state_store.guardian_observations "
            "(event_id, agent_id, observed_at, obs_type, ttl_expires_at) "
            "SELECT 'cap-evt-' || lpad(g::text, 6, '0'), 'a', '2026-04-19T12:00:00Z', "
            "'process.crashed', g "
            "FROM generate_series(1, 10001) AS g",
            std::vector<std::string>{});
        REQUIRE(obs.status() == PGRES_COMMAND_OK);
    }
    REQUIRE(store.insert_event(make_event("cap-live", "r", "a"))); // 30d-ahead ttl, avoids would_wipe

    store.reap_expired();
    CHECK(store.events_reaped_total() == 10000);        // capped exactly at kReapCapPerPass
    CHECK(store.observations_reaped_total() == 10000);   // lockstep: same cap, same outcome

    store.reap_expired();
    CHECK(store.events_reaped_total() == 10001);          // second pass drains the single remainder
    CHECK(store.observations_reaped_total() == 10001);

    CHECK(store.event_count() == 1); // only "cap-live" survives
}

// gc_sweep advisory-lock skip (mirrors ResultSetStore's "GC sweep skips
// quietly when a sibling holds the advisory lock"): a sibling replica
// already sweeping holds the fleet-wide try-advisory-xact-lock, so this pass
// must skip quietly and never even reach the gc_meta read/stamp (which run
// only after the try-lock succeeds), never mind the delete.
TEST_CASE("GuaranteedStateStore: reap_expired skips quietly when a sibling holds the advisory "
          "lock",
          "[pg][guaranteed_state_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());

    REQUIRE(store.insert_event(make_event("locked-evt", "r", "a")));
    exec_sql(db.dsn(), "UPDATE guaranteed_state_store.guaranteed_state_events SET "
                       "ttl_expires_at = 1 WHERE event_id = 'locked-evt'");
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM guaranteed_state_store.gc_meta WHERE key "
                                 "= 'last_pass_now'") == "0");

    pg::PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    {
        pg::PgResult begin{PQexec(locker.get(), "BEGIN")};
        REQUIRE(begin.status() == PGRES_COMMAND_OK);
        pg::PgResult lock{PQexec(
            locker.get(),
            "SELECT pg_advisory_xact_lock(hashtextextended('guaranteed_state_store:reap', 0))")};
        REQUIRE(lock.status() == PGRES_TUPLES_OK);
    }

    store.reap_expired();
    CHECK(store.events_reaped_total() == 0);
    CHECK(store.event_count() == 1); // nothing deleted — the sibling held the lock
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM guaranteed_state_store.gc_meta WHERE key "
                                 "= 'last_pass_now'") == "0"); // never reached the stamp

    pg::PgResult rollback{PQexec(locker.get(), "ROLLBACK")};
    REQUIRE(rollback.status() == PGRES_COMMAND_OK);
}

// gc_sweep clock anomaly / prev_unusable (mirrors ResultSetStore's "GC sweep
// declines once on a clock reading ahead of now"). CONTRACT SURPRISE vs. a
// naive "same facts -> suppressed repeat" expectation: reap_expired() stamps
// a FRESH, honest last_pass_now on EVERY pass (including a declining one)
// BEFORE it even evaluates the anomaly (see the .cpp: the meta stamp runs
// ahead of the probe/classify block) — so the poisoned reading is self-healed
// by the very first call. Pass 2 reads pass 1's (now-valid) stamp,
// prev_unusable comes back false, and the second pass is a genuinely CLEAN
// pass (Anomaly::None), not a suppressed repeat of BadState — it still
// drains, just via a different path than the would_wipe test above.
TEST_CASE("GuaranteedStateStore: reap_expired declines once on a clock reading ahead of now",
          "[pg][guaranteed_state_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());

    REQUIRE(store.insert_event(make_event("clock-a", "r", "a")));
    REQUIRE(store.insert_event(make_event("clock-b", "r", "a")));
    REQUIRE(store.insert_event(make_event("clock-live", "r", "a"))); // avoids would_wipe
    exec_sql(db.dsn(), "UPDATE guaranteed_state_store.guaranteed_state_events SET "
                       "ttl_expires_at = 1 WHERE event_id IN ('clock-a', 'clock-b')");
    // Poison gc_meta with a wildly-future last_pass_now — no C++-side wall
    // clock read needed, computed server-side from clock_timestamp().
    exec_sql(db.dsn(),
            "INSERT INTO guaranteed_state_store.gc_meta (key, value) VALUES ('last_pass_now', "
            "(EXTRACT(EPOCH FROM clock_timestamp())::bigint + 999999)::text) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value");

    store.reap_expired();
    CHECK(store.events_reaped_total() == 0); // declined: prev_unusable (BadState)
    CHECK(store.event_count() == 3);
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM guaranteed_state_store.gc_meta WHERE key "
                                 "= 'last_anomaly_facts'") == "1");

    // Self-healed: the stamp reap_expired() just wrote is an honest reading,
    // so this pass is clean, drains both expired rows, and clears the dedup
    // row.
    store.reap_expired();
    CHECK(store.events_reaped_total() == 2);
    CHECK(store.event_count() == 1);
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM guaranteed_state_store.gc_meta WHERE key "
                                 "= 'last_anomaly_facts'") == "0"); // consumed/cleared
}

// UP-1 tiebreaker: events and observations are reaped via TWO independently-
// executed, independently-capped DELETEs, each ordered by (ttl_expires_at,
// event_id) — a cohort sharing ONE tied ttl_expires_at second is exactly the
// case where two separate ORDER BY/LIMIT statements could disagree on which
// rows fall inside the limit unless the tiebreak column (event_id) makes the
// order identical between the two tables. Forcing the cap boundary itself to
// land INSIDE a tied group would need >kReapCapPerPass (10000) tied rows,
// which the cap constant does not expose as injectable — this instead pins
// the ordering GUARANTEE on a sub-cap tied cohort (the whole cohort drains in
// one pass): every reaped event's observation is gone, and the untied,
// unexpired survivor's observation is untouched.
TEST_CASE("GuaranteedStateStore: reap_expired reaps a tied-ttl cohort of events and their "
          "observations as one set (UP-1 tiebreaker)",
          "[pg][guaranteed_state_store][dex][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());
    anchor_guard(store, db.dsn()); // consume the #2579 bootstrap decline before seeding

    {
        pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto ev = pg::exec_params(
            conn.get(),
            "INSERT INTO guaranteed_state_store.guaranteed_state_events "
            "(event_id, rule_id, agent_id, event_type, severity, timestamp, ttl_expires_at) "
            "SELECT 'tied-evt-' || lpad(g::text, 4, '0'), 'r', 'a', 'drift.remediated', 'high', "
            "'2026-04-19T12:00:00Z', 1 " // ALL 25 rows share ttl_expires_at = 1 (tied second)
            "FROM generate_series(1, 25) AS g",
            std::vector<std::string>{});
        REQUIRE(ev.status() == PGRES_COMMAND_OK);
        auto obs = pg::exec_params(
            conn.get(),
            "INSERT INTO guaranteed_state_store.guardian_observations "
            "(event_id, agent_id, observed_at, obs_type, ttl_expires_at) "
            "SELECT 'tied-evt-' || lpad(g::text, 4, '0'), 'a', '2026-04-19T12:00:00Z', "
            "'process.crashed', 1 "
            "FROM generate_series(1, 25) AS g",
            std::vector<std::string>{});
        REQUIRE(obs.status() == PGRES_COMMAND_OK);
        // Untied, unexpired survivor pair — a distinct future ttl so it
        // never competes with the tied cohort's ORDER BY position.
        auto ev_live = pg::exec_params(
            conn.get(),
            "INSERT INTO guaranteed_state_store.guaranteed_state_events "
            "(event_id, rule_id, agent_id, event_type, severity, timestamp, ttl_expires_at) "
            "VALUES ('tied-survivor', 'r', 'a', 'drift.remediated', 'high', "
            "'2026-04-19T12:00:00Z', (EXTRACT(EPOCH FROM clock_timestamp())::bigint + 100000))",
            std::vector<std::string>{});
        REQUIRE(ev_live.status() == PGRES_COMMAND_OK);
        auto obs_live = pg::exec_params(
            conn.get(),
            "INSERT INTO guaranteed_state_store.guardian_observations "
            "(event_id, agent_id, observed_at, obs_type, ttl_expires_at) "
            "VALUES ('tied-survivor', 'a', '2026-04-19T12:00:00Z', 'process.crashed', "
            "(EXTRACT(EPOCH FROM clock_timestamp())::bigint + 100000))",
            std::vector<std::string>{});
        REQUIRE(obs_live.status() == PGRES_COMMAND_OK);
    }

    store.reap_expired();
    CHECK(store.events_reaped_total() == 25);
    CHECK(store.observations_reaped_total() == 25);
    CHECK(store.event_count() == 1); // only "tied-survivor" left

    auto survivors = store.query_observations();
    REQUIRE(survivors.size() == 1);
    CHECK(survivors[0].event_id == "tied-survivor");
}

TEST_CASE("GuaranteedStateStore: overview aggregations", "[pg][guaranteed_state_store][overview]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store{pool, /*retention_days=*/30};
    REQUIRE(store.is_open());

    auto ev = [&](std::string id, std::string rule, std::string agent, std::string type,
                  std::string ts) {
        auto e = make_event(std::move(id), std::move(rule), std::move(agent), "high", std::move(ts));
        e.event_type = std::move(type);
        return e;
    };
    // Insertion order == rowid order, so the LAST event per (agent,rule) is "latest".
    REQUIRE(store.insert_event(ev("e1", "r1", "a1", "drift.detected", "2026-06-04T10:00:00Z")).has_value());
    REQUIRE(store.insert_event(ev("e2", "r1", "a1", "drift.remediated", "2026-06-04T10:01:00Z")).has_value());
    REQUIRE(store.insert_event(ev("e3", "r1", "a2", "drift.detected", "2026-06-04T10:02:00Z")).has_value());
    REQUIRE(store.insert_event(ev("e4", "r2", "a1", "remediation.failed", "2026-06-04T10:03:00Z")).has_value());

    SECTION("rule_activity: per-rule window counts") {
        std::map<std::string, GuardianRuleActivity> m;
        for (auto& a : store.rule_activity("")) m[a.rule_id] = a;
        REQUIRE(m.count("r1"));
        CHECK(m["r1"].detected == 2);
        CHECK(m["r1"].remediated == 1);
        CHECK(m["r1"].failed == 0);
        CHECK(m["r1"].distinct_agents == 2);
        CHECK(m["r1"].last_activity == "2026-06-04T10:02:00Z");
        CHECK(m["r2"].failed == 1);
        CHECK(m["r2"].distinct_agents == 1);
    }
    SECTION("daily_remediations: per-day fixed/failed") {
        auto days = store.daily_remediations("");
        REQUIRE(days.size() == 1);
        CHECK(days[0].day == "2026-06-04");
        CHECK(days[0].remediated == 1);
        CHECK(days[0].failed == 1);
    }
    SECTION("since cutoff excludes earlier events") {
        std::map<std::string, GuardianRuleActivity> m;
        for (auto& a : store.rule_activity("2026-06-04T10:02:30Z")) m[a.rule_id] = a;
        CHECK(m.count("r1") == 0);  // all r1 events precede the cutoff
        CHECK(m["r2"].failed == 1);
    }
}

TEST_CASE("GuaranteedStateStore: per-(agent,rule) compliance census (Slice B)",
          "[pg][guaranteed_state_store][census]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store{pool, /*retention_days=*/30};
    REQUIRE(store.is_open());

    auto ev = [&](std::string id, std::string rule, std::string agent, std::string type,
                  std::string ts) {
        auto e = make_event(std::move(id), std::move(rule), std::move(agent), "high", std::move(ts));
        e.event_type = std::move(type);
        return e;
    };
    // agent_rule_statuses is now type-distinguishable (ADR-0038 catastrophic-
    // read set) — REQUIRE the outer expected here; a degrade is a genuine
    // test-infra failure, not a scenario under test.
    auto census = [&] {
        std::map<std::pair<std::string, std::string>, std::string> m;
        auto rows = store.agent_rule_statuses();
        REQUIRE(rows.has_value());
        for (auto& s : *rows)
            m[{s.agent_id, s.rule_id}] = s.state;
        return m;
    };

    // (a1,r1): compliant → drift → remediated  ⇒ final "compliant".
    REQUIRE(store.insert_event(ev("c1", "r1", "a1", "guard.compliant", "2026-06-04T10:00:00Z")));
    REQUIRE(store.insert_event(ev("c2", "r1", "a1", "drift.detected", "2026-06-04T10:01:00Z")));
    REQUIRE(store.insert_event(ev("c3", "r1", "a1", "drift.remediated", "2026-06-04T10:02:00Z")));
    // (a2,r1): drift only ⇒ "drifted".
    REQUIRE(store.insert_event(ev("c4", "r1", "a2", "drift.detected", "2026-06-04T10:00:30Z")));
    // (a1,r2): unhealthy ⇒ "errored".
    REQUIRE(store.insert_event(ev("c5", "r2", "a1", "guard.unhealthy", "2026-06-04T10:00:00Z")));
    // guard.armed carries no verdict ⇒ no census row.
    REQUIRE(store.insert_event(ev("c6", "r3", "a9", "guard.armed", "2026-06-04T10:00:00Z")));

    {
        auto m = census();
        CHECK(m[{"a1", "r1"}] == "compliant");
        CHECK(m[{"a2", "r1"}] == "drifted");
        CHECK(m[{"a1", "r2"}] == "errored");
        CHECK(m.count({"a9", "r3"}) == 0); // guard.armed left no census row
    }

    SECTION("a late-arriving OLDER event does not regress a newer state") {
        // a1/r1 is compliant as of 10:02; replay an older 10:01 drift — must be ignored.
        REQUIRE(store.insert_event(ev("c7", "r1", "a1", "drift.detected", "2026-06-04T10:01:00Z")));
        CHECK(census()[{"a1", "r1"}] == "compliant");
    }
    SECTION("a newer event updates the state") {
        REQUIRE(store.insert_event(ev("c8", "r1", "a1", "drift.detected", "2026-06-04T10:05:00Z")));
        CHECK(census()[{"a1", "r1"}] == "drifted");
    }
    SECTION("batch ingest maintains the census transactionally") {
        std::vector<GuaranteedStateEventRow> batch = {
            ev("b1", "r5", "a5", "guard.compliant", "2026-06-04T11:00:00Z"),
            ev("b2", "r5", "a5", "drift.detected", "2026-06-04T11:01:00Z"),
        };
        REQUIRE(store.insert_events(batch));
        CHECK(census()[{"a5", "r5"}] == "drifted"); // latest in the batch wins
    }
    SECTION("rule-filtered status returns only that guard's per-device rows (Slice C drill-down)") {
        auto r1 = store.agent_rule_statuses("r1");
        REQUIRE(r1.has_value());
        CHECK(r1->size() == 2); // a1 + a2
        for (const auto& s : *r1)
            CHECK(s.rule_id == "r1");
        auto r2 = store.agent_rule_statuses("r2");
        REQUIRE(r2.has_value());
        CHECK(r2->size() == 1); // a1 only
        auto nope = store.agent_rule_statuses("nope");
        REQUIRE(nope.has_value());
        CHECK(nope->empty()); // unknown rule
        auto all = store.agent_rule_statuses();
        REQUIRE(all.has_value());
        CHECK(all->size() == 3); // unfiltered = whole fleet
    }
    SECTION("deleting a rule drops its status rows (no orphan census inflation)") {
        GuaranteedStateRuleRow r;
        r.rule_id = "r1";
        r.name = "rule-one";
        r.yaml_source = "x";
        r.enforcement_mode = "audit";
        r.severity = "high";
        r.created_at = "2026-06-04T09:00:00Z";
        r.updated_at = r.created_at;
        REQUIRE(store.create_rule(r)); // r1 already has a1/a2 status rows from above
        REQUIRE(census().count({"a1", "r1"}) == 1);

        REQUIRE(store.delete_rule("r1"));
        auto m = census();
        CHECK(m.count({"a1", "r1"}) == 0); // gone with the rule
        CHECK(m.count({"a2", "r1"}) == 0);
        CHECK(m.count({"a1", "r2"}) == 1); // an unrelated rule's status is untouched
    }
}

TEST_CASE("GuaranteedStateStore::errored_rule_count — ADR-0017 INV-3 SQL-level confinement",
          "[pg][guaranteed_state_store][adr0017]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardianstate_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store{pool, /*retention_days=*/30};
    REQUIRE(store.is_open());

    auto make_rule = [](const std::string& rule_id) {
        GuaranteedStateRuleRow r;
        r.rule_id = rule_id;
        r.name = rule_id + "-name";
        r.yaml_source = "x";
        r.enforcement_mode = "audit";
        r.severity = "high";
        r.created_at = "2026-06-04T09:00:00Z";
        r.updated_at = r.created_at;
        return r;
    };
    REQUIRE(store.create_rule(make_rule("r1")));
    REQUIRE(store.create_rule(make_rule("r2")));

    auto ev = [&](std::string id, std::string rule, std::string agent, std::string type) {
        auto e = make_event(std::move(id), std::move(rule), std::move(agent), "high",
                            "2026-06-04T10:00:00Z");
        e.event_type = std::move(type);
        return e;
    };
    // r1 errored on a1 AND a2 (counted once — DISTINCT rule_id); r2 errored on a1 only.
    REQUIRE(store.insert_event(ev("e1", "r1", "a1", "guard.unhealthy")));
    REQUIRE(store.insert_event(ev("e2", "r1", "a2", "guard.unhealthy")));
    REQUIRE(store.insert_event(ev("e3", "r2", "a1", "guard.unhealthy")));
    // r-orphan has a census row but was never created as a rule — the SQL JOIN
    // against guaranteed_state_rules must exclude it (mirrors the C++
    // rule_names.count() intersection the route used to do post-fetch).
    REQUIRE(store.insert_event(ev("e4", "r-orphan", "a1", "guard.unhealthy")));
    // r1 also compliant on a3 — must not contribute.
    REQUIRE(store.insert_event(ev("e5", "r1", "a3", "guard.compliant")));

    SECTION("nullopt scope: unfiltered fleet-wide count") {
        auto n = store.errored_rule_count(std::nullopt);
        REQUIRE(n.has_value());
        CHECK(*n == 2); // r1 (once) + r2; r-orphan excluded by the catalogue JOIN
    }

    SECTION("engaged scope: agent_id = ANY($1::text[]) applied before the aggregate") {
        auto n = store.errored_rule_count(std::vector<std::string>{"a1"});
        REQUIRE(n.has_value());
        CHECK(*n == 2); // a1 alone reports both r1 and r2 as errored

        auto n2 = store.errored_rule_count(std::vector<std::string>{"a2"});
        REQUIRE(n2.has_value());
        CHECK(*n2 == 1); // a2 only reports r1
    }

    SECTION("engaged-empty scope: zero without issuing a query (INV-2)") {
        auto n = store.errored_rule_count(std::vector<std::string>{});
        REQUIRE(n.has_value());
        CHECK(*n == 0);
    }

    SECTION("a scope naming an agent with no errored rows counts nothing") {
        auto n = store.errored_rule_count(std::vector<std::string>{"a3"});
        REQUIRE(n.has_value());
        CHECK(*n == 0); // a3's only row is compliant, not errored
    }
}
