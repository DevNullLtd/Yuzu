/**
 * test_audit_store.cpp — Unit tests for AuditStore (PostgreSQL, ADR-0040)
 *
 * Covers: logging (fail-hard), querying + filters + action-prefix scoping +
 * random-sample, degrade-distinguishable reads, and the retention clock guard
 * (#2360) ported to a single-sweeper advisory lease with durable dedup.
 *
 * The dedicated [backfill] TEST_CASE suite is gone entirely as of
 * 2026-09-04 — `AuditStore::migrate_from_sqlite()` itself was the last
 * `migrate_from_sqlite()` on the ladder to retire (#3623,
 * `chore/retire-migrate-from-sqlite-auditstore`, ADR-0009's hard-cutover
 * Update withdrew the permanent exception ADR-0040's own amendment had
 * carved out for this store). Every store's backfill test suite is gone
 * with it; store-behaviour tests use a pre-migrated template clone.
 *
 * PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails when it is set
 * but broken.
 */

#include "audit_store.hpp"
#include <yuzu/audit_retention_rules.hpp>

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <cstdint>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Pre-migrated template: every store-behaviour test clones this schema.
yuzu::test::PgTestTemplate auditstore_tpl{"auditstore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    AuditStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("auditstore template: store failed to migrate");
}};

void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}

std::string query_scalar(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
    if (PQntuples(r.get()) == 0)
        return "";
    return PQgetvalue(r.get(), 0, 0);
}

AuditEvent mk(const std::string& principal, const std::string& action,
              const std::string& result = "success") {
    AuditEvent e;
    e.principal = principal;
    e.principal_role = "admin";
    e.action = action;
    e.result = result;
    return e;
}

// ── Retention-guard fixtures ────────────────────────────────────────────────
constexpr int kGuardRetentionDays = 1;
constexpr std::int64_t kWindow = static_cast<std::int64_t>(kGuardRetentionDays) * 86400;

// PostgreSQL's OWN clock, queried directly — the retention DECISION (Gate 4
// unhappy-path UP-2 / Sol) now reads `now()` inside the advisory-lock
// transaction rather than trusting the CALLER's clock, so a fixed historical
// constant (the old `kNow = 1'700'000'000`, ~Nov 2023) no longer has any
// relationship to what the guard actually compares against — a "survivor"
// row seeded at `kNow + kWindow` is, by 2026, already YEARS in the past
// relative to the real clock the decision uses, and every test built on that
// assumption either passed for the wrong reason or failed outright. Every
// clock-guard test below computes its own `now` from this helper and builds
// all relative math off it.
std::int64_t pg_now(const std::string& dsn) {
    return std::stoll(query_scalar(dsn, "SELECT EXTRACT(EPOCH FROM now())::bigint"));
}

// For the two tests below that deliberately never open a live connection
// (an unreachable PgPool) — there is no `dsn` to read `pg_now` from, and
// `cleanup_once` returns before the value would matter anyway (`!open_`
// short-circuits ahead of every clock use). Any plausible reading works;
// named so it reads as deliberate rather than a stray literal.
constexpr std::int64_t kArbitraryPlausibleTime = 1'700'000'000;

// Seed `count` rows all carrying the same ttl_expires_at (and timestamp), via a
// second connection, so a test can place rows at a chosen distance from the
// `now` it passes to cleanup_once().
void seed_rows_with_ttl(const std::string& dsn, std::int64_t ttl, int count) {
    exec_sql(dsn, "INSERT INTO audit_store.audit_events (timestamp, principal, principal_role, "
                  "action, result, ttl_expires_at) SELECT " +
                      std::to_string(ttl) + ", 'admin', 'admin', 'auth.login', 'success', " +
                      std::to_string(ttl) + " FROM generate_series(1, " + std::to_string(count) +
                      ")");
}

/// Put a store in the state of one that has already completed a pass, so the
/// bootstrap trigger (#2579) does not fire.
///
/// Needed because #2579 makes "no stored reading, and rows already expired" a
/// decline in its own right. Almost every guard test here is about something
/// else -- the cap, the dedup rule, one specific trigger -- and each would
/// otherwise spend its first pass absorbing a bootstrap decline it never meant
/// to exercise. This states the precondition those tests always assumed
/// implicitly; the ones that ARE about the bootstrap do not call it.
///
/// A pass over an EMPTY table is the whole mechanism, and it is exact rather
/// than approximate: `cleanup_once` anchors the reading and settles the marker
/// before it probes, and with nothing expired the rule short-circuits to `None`,
/// so no counter moves, nothing is deleted and no anomaly is recorded. Call it
/// BEFORE seeding.
///
/// `now` is REQUIRED, not defaulted. Since #2360/1d the retention DECISION
/// reads PostgreSQL's own clock, not this argument — `cleanup_once`'s `now`
/// only gates the pre-txn implausibility check and stamps the liveness gauge
/// (`last_pass_unixtime_`), so its value has no bearing on which anomaly, if
/// any, gets classified. It stays required rather than defaulted so a call
/// site cannot assume otherwise; pass any plausible reading, e.g. `pg_now(dsn)`
/// or an offset from one.
void anchor_guard(AuditStore& store, std::int64_t last_pass_now) {
    REQUIRE(store.cleanup_once(last_pass_now) == 0);
    REQUIRE(store.clock_anomaly_skips_count() == 0);
    REQUIRE(store.bootstrap_declines_count() == 0);
}

std::int64_t row_count(const std::string& dsn) {
    return std::stoll(query_scalar(dsn, "SELECT COUNT(*) FROM audit_store.audit_events"));
}

} // namespace

// ── Migration ────────────────────────────────────────────────────────────────

TEST_CASE("AuditStore migration v2 deletes the backfill marker rows and forbids their "
          "re-insertion, leaving the clock-guard's durable state untouched (#3623)",
          "[pg][audit_store][migration]") {
    YUZU_REQUIRE_PG_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);

        PgResult meta{PQexec(conn.get(),
                             "CREATE TABLE public.schema_meta ("
                             "  store       TEXT PRIMARY KEY,"
                             "  version     INTEGER NOT NULL,"
                             "  upgraded_at BIGINT NOT NULL)")};
        REQUIRE(meta.ok());
        PgResult schema{PQexec(conn.get(), "CREATE SCHEMA audit_store")};
        REQUIRE(schema.ok());

        // v1 DDL, copied from migrations() in audit_store.cpp — schema-qualified, unlike the
        // source (a raw PQexec connection has no search_path set the way PgMigrationRunner's
        // migration transaction does; mirrors the QuarantineStore v1→v2 test precedent).
        PgResult v1{PQexec(conn.get(),
                           "CREATE TABLE audit_store.audit_events ("
                           "  id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
                           "  timestamp       BIGINT  NOT NULL,"
                           "  principal       TEXT    NOT NULL,"
                           "  principal_role  TEXT    NOT NULL,"
                           "  action          TEXT    NOT NULL,"
                           "  target_type     TEXT    NOT NULL DEFAULT '',"
                           "  target_id       TEXT    NOT NULL DEFAULT '',"
                           "  detail          TEXT    NOT NULL DEFAULT '',"
                           "  source_ip       TEXT    NOT NULL DEFAULT '',"
                           "  user_agent      TEXT    NOT NULL DEFAULT '',"
                           "  session_id      TEXT    NOT NULL DEFAULT '',"
                           "  result          TEXT    NOT NULL,"
                           "  ttl_expires_at  BIGINT  NOT NULL DEFAULT 0,"
                           "  principal_class TEXT    NOT NULL DEFAULT '');"
                           "CREATE TABLE audit_store.audit_retention_meta ("
                           "  key   TEXT PRIMARY KEY,"
                           "  value TEXT NOT NULL"
                           ")")};
        REQUIRE(v1.ok());
        PgResult stamp{PQexec(conn.get(),
                              "INSERT INTO public.schema_meta (store, version, upgraded_at) "
                              "VALUES ('audit_store', 1, extract(epoch FROM now())::bigint)")};
        REQUIRE(stamp.ok());

        // All four keys genuinely present BEFORE v2's DELETE runs — the two retired backfill
        // markers, and the two the clock guard depends on surviving this migration.
        PgResult seed{PQexec(
            conn.get(),
            "INSERT INTO audit_store.audit_retention_meta (key, value) VALUES "
            "('backfill_complete', '1700000000'), "
            "('backfill_source_fingerprint', '5:15:5000:1000:1004'), "
            "('last_pass_now', '1700000500'), "
            "('last_anomaly_facts', '-----')")};
        REQUIRE(seed.ok());
    }

    // The real construction path: PgMigrationRunner::run reads version 1 from schema_meta and
    // applies v2's DELETE against the meta table seeded above.
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AuditStore store{pool};
    REQUIRE(store.is_open());

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult ver{PQexec(conn.get(), "SELECT version FROM public.schema_meta WHERE store = "
                                    "'audit_store'")};
    REQUIRE(ver.ok());
    REQUIRE(PQntuples(ver.get()) == 1);
    CHECK(std::string(PQgetvalue(ver.get(), 0, 0)) == "2");

    // The two backfill-only markers are GONE.
    PgResult markers{PQexec(conn.get(),
                            "SELECT key FROM audit_store.audit_retention_meta WHERE key IN "
                            "('backfill_complete', 'backfill_source_fingerprint')")};
    REQUIRE(markers.ok());
    CHECK(PQntuples(markers.get()) == 0);

    // The clock guard's own durable rows are BYTE-IDENTICAL, not merely present.
    PgResult surviving{PQexec(
        conn.get(), "SELECT key, value FROM audit_store.audit_retention_meta ORDER BY key")};
    REQUIRE(surviving.ok());
    REQUIRE(PQntuples(surviving.get()) == 2);
    CHECK(std::string(PQgetvalue(surviving.get(), 0, 0)) == "last_anomaly_facts");
    CHECK(std::string(PQgetvalue(surviving.get(), 0, 1)) == "-----");
    CHECK(std::string(PQgetvalue(surviving.get(), 1, 0)) == "last_pass_now");
    CHECK(std::string(PQgetvalue(surviving.get(), 1, 1)) == "1700000500");

    // Gate 4 unhappy-path UP-1 (round 4): a plain DELETE alone leaves a window where an old
    // binary can re-stamp `backfill_complete` while `audit_events` is still empty, after which
    // nothing ever deletes it again. v2 also adds a CHECK constraint forbidding either marker
    // key outright, so this must survive independent of table content: re-inserting EITHER
    // key, even into an otherwise-empty table, is rejected at the constraint (23514
    // check_violation), never silently accepted.
    PgResult constraint{PQexec(
        conn.get(),
        "SELECT 1 FROM pg_constraint WHERE conname = "
        "'audit_retention_meta_no_retired_backfill_markers' AND connamespace = "
        "'audit_store'::regnamespace")};
    REQUIRE(constraint.ok());
    CHECK(PQntuples(constraint.get()) == 1);

    for (const char* key : {"backfill_complete", "backfill_source_fingerprint"}) {
        const std::string sql = std::string("INSERT INTO audit_store.audit_retention_meta "
                                             "(key, value) VALUES ('") +
                                 key + "', 'x')";
        PgResult rejected{PQexec(conn.get(), sql.c_str())};
        CHECK_FALSE(rejected.ok());
        const char* sqlstate =
            rejected ? PQresultErrorField(rejected.get(), PG_DIAG_SQLSTATE) : nullptr;
        REQUIRE(sqlstate != nullptr);
        CHECK(std::string(sqlstate) == "23514"); // check_violation
    }

    // The constraint is scoped to these two keys only — an ordinary key/value row is
    // unaffected, matching the clock guard's own untouched rows above.
    PgResult ordinary{
        PQexec(conn.get(), "INSERT INTO audit_store.audit_retention_meta (key, value) "
                            "VALUES ('some_other_key', 'ok')")};
    CHECK(ordinary.ok());
}

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("AuditStore: open against a fresh template clone", "[pg][audit_store][db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    // #2854: no durable anchor exists yet on a freshly-migrated database — `0`
    // is the correct seed, not an anomaly.
    CHECK(store.last_pass_unixtime() == 0);
}

TEST_CASE("AuditStore: bad-path constructor (unroutable DSN) is closed and fails hard/degrades",
          "[audit_store]") {
    PgPool bad{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    AuditStore store(bad);
    REQUIRE_FALSE(store.is_open());
    // Write fails hard (false); reads degrade to nullopt — never a false-empty.
    CHECK_FALSE(store.log(mk("admin", "auth.login")));
    CHECK(store.emit_failed_count() == 1);
    CHECK_FALSE(store.query().has_value());
    CHECK_FALSE(store.total_count().has_value());
    // #2854: the lease-acquire failure returns before the liveness seed ever
    // runs, same as it returns before schema migration ever runs — a store
    // that never opened stays at the `0` default, not the anomaly sentinel.
    CHECK(store.last_pass_unixtime() == 0);
}

// ── Logging + queries ───────────────────────────────────────────────────────

TEST_CASE("AuditStore: log and retrieve", "[pg][audit_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());

    AuditEvent e = mk("admin", "auth.login");
    e.source_ip = "192.168.1.1";
    CHECK(store.log(e));

    auto results = store.query();
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].principal == "admin");
    CHECK((*results)[0].action == "auth.login");
    CHECK((*results)[0].result == "success");
    CHECK((*results)[0].source_ip == "192.168.1.1");
}

TEST_CASE("AuditStore: filter by principal / action / target", "[pg][audit_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);

    for (const auto& u : {"admin", "admin", "viewer"})
        CHECK(store.log(mk(u, "auth.login")));
    AuditEvent tgt = mk("admin", "agent.approve");
    tgt.target_type = "agent";
    tgt.target_id = "agent-001";
    CHECK(store.log(tgt));

    AuditQuery byp;
    byp.principal = "admin";
    auto rp = store.query(byp);
    REQUIRE(rp.has_value());
    CHECK(rp->size() == 3); // 2 logins + 1 approve

    AuditQuery bya;
    bya.action = "agent.approve";
    auto ra = store.query(bya);
    REQUIRE(ra.has_value());
    REQUIRE(ra->size() == 1);

    AuditQuery byt;
    byt.target_type = "agent";
    byt.target_id = "agent-001";
    auto rt = store.query(byt);
    REQUIRE(rt.has_value());
    REQUIRE(rt->size() == 1);
}

TEST_CASE("AuditStore: timestamp ordering, limit/offset, total_count", "[pg][audit_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);

    for (int i = 0; i < 10; ++i) {
        AuditEvent e = mk("admin", "test");
        e.timestamp = 100 + i * 10;
        CHECK(store.log(e));
    }
    auto all = store.query();
    REQUIRE(all.has_value());
    REQUIRE(all->size() == 10);
    CHECK((*all)[0].timestamp >= (*all)[1].timestamp); // newest first

    AuditQuery q;
    q.limit = 3;
    auto p1 = store.query(q);
    REQUIRE(p1.has_value());
    REQUIRE(p1->size() == 3);
    q.offset = 3;
    auto p2 = store.query(q);
    REQUIRE(p2.has_value());
    REQUIRE(p2->size() == 3);
    CHECK((*p1)[0].timestamp != (*p2)[0].timestamp);

    auto total = store.total_count();
    REQUIRE(total.has_value());
    CHECK(*total == 10);
}

TEST_CASE("AuditStore: all fields stored; principal_class round-trips and defaults honest-empty",
          "[pg][audit_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);

    AuditEvent e = mk("admin", "setting.update");
    e.target_type = "setting";
    e.target_id = "tls_enabled";
    e.detail = "changed to true";
    e.source_ip = "10.0.0.1";
    e.user_agent = "Mozilla/5.0";
    e.session_id = "sess-abc";
    e.principal_class = "human";
    CHECK(store.log(e));
    // A server-internal writer that leaves principal_class unset → honest-empty.
    CHECK(store.log(mk("system", "cert.reload")));

    AuditQuery q;
    q.action = "setting.update";
    auto r = store.query(q);
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 1);
    CHECK((*r)[0].target_id == "tls_enabled");
    CHECK((*r)[0].detail == "changed to true");
    CHECK((*r)[0].user_agent == "Mozilla/5.0");
    CHECK((*r)[0].session_id == "sess-abc");
    CHECK((*r)[0].principal_class == "human");

    AuditQuery q2;
    q2.action = "cert.reload";
    auto r2 = store.query(q2);
    REQUIRE(r2.has_value());
    REQUIRE(r2->size() == 1);
    CHECK((*r2)[0].principal_class.empty());
}

TEST_CASE("AuditStore: time range filter", "[pg][audit_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    for (int64_t ts : {100, 200, 300, 400, 500}) {
        AuditEvent e = mk("admin", "test");
        e.timestamp = ts;
        CHECK(store.log(e));
    }
    AuditQuery q;
    q.since = 200;
    q.until = 400;
    auto r = store.query(q);
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 3);
}

TEST_CASE("AuditStore: non-UTF-8 / embedded-NUL free text is defanged, the write still lands",
          "[pg][audit_store]") {
    // FAIL-HARD write must never be taken down by a hostile/mis-encoded byte —
    // sanitize_pg_text scrubs it to U+FFFD so a real audit event still surfaces.
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    AuditEvent e = mk("admin", "auth.login");
    e.detail = std::string("bad\xff\xfe") + '\0' + "tail"; // invalid UTF-8 + embedded NUL
    e.source_ip = std::string("1.2.3.4\xc0");
    CHECK(store.log(e));
    auto r = store.query();
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 1);
    // The whole value survived (nothing truncated at the NUL) and no raw NUL
    // remains.
    CHECK((*r)[0].detail.find("tail") != std::string::npos);
    CHECK((*r)[0].detail.find('\0') == std::string::npos);
}

// ── #4: action-prefix scoping + random-sample ────────────────────────────────

TEST_CASE("AuditStore::sanitized_detail is idempotent and leaves an empty detail alone",
          "[audit_store][secret]") {
    // Rows written after the writer fix already hold the placeholder; applying the
    // read-time rule again must not double-wrap or invent content.
    CHECK(AuditStore::sanitized_detail("RuntimeConfig", "oidc_client_secret",
                                       "value=<redacted>") == "value=<redacted>");
    CHECK(AuditStore::sanitized_detail("RuntimeConfig", "oidc_client_secret", "").empty());
    CHECK(AuditStore::sanitized_detail("RuntimeConfig", "oidc_issuer", "value=https://idp") ==
          "value=https://idp");
    // No leading `value=`: we cannot tell which part is the credential, so the whole
    // detail goes. Fail safe, not fail open.
    CHECK(AuditStore::sanitized_detail("RuntimeConfig", "oidc_client_secret", "raw-leak") ==
          "<redacted>");
    // The credential written BEFORE a value= token -- the case the old prefix-
    // preserving rule leaked verbatim.
    CHECK(AuditStore::sanitized_detail("RuntimeConfig", "oidc_client_secret", "s3cr3t value=x") ==
          "<redacted>");
}

TEST_CASE("AuditStore: a pre-existing config.update secret detail is redacted on READ",
          "[pg][audit_store][secret]") {
    // Defence in depth behind the backfill-time redaction: a row that reaches the
    // table by any other route (a restore, a hand-written import) must still not
    // disclose the credential through the six readers. The port dropped this
    // entirely at one point, which is why it is pinned here.
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    exec_sql(db.dsn(),
             "INSERT INTO audit_store.audit_events (timestamp, principal, principal_role, action, "
             "target_type, target_id, detail, result, ttl_expires_at) VALUES "
             "(1000,'admin','admin','config.update','RuntimeConfig','oidc_client_secret',"
             "'value=hunter2-the-real-secret','success',0)");

    auto r = store.query();
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 1);
    CHECK((*r)[0].detail == "value=<redacted>");
    CHECK((*r)[0].detail.find("hunter2") == std::string::npos);
}

TEST_CASE("AuditStore: action_prefixes scopes to the auth surface",
          "[pg][audit_store][auth-sample]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    for (const auto& a : {"auth.login", "auth.login_failed", "mfa.step_up.passed",
                          "session.revoke_all", "instruction.execute", "ca.cert.issued"})
        CHECK(store.log(mk("admin", a)));

    AuditQuery q;
    q.action_prefixes = {"auth.", "mfa.", "session."};
    auto r = store.query(q);
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 4);
    for (const auto& e : *r) {
        const bool scoped = e.action.rfind("auth.", 0) == 0 || e.action.rfind("mfa.", 0) == 0 ||
                            e.action.rfind("session.", 0) == 0;
        CHECK(scoped);
    }
}

TEST_CASE("AuditStore: wildcard-bearing / all-empty prefixes fail closed (M-2)",
          "[pg][audit_store][auth-sample]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    CHECK(store.log(mk("admin", "auth.login")));
    CHECK(store.log(mk("admin", "instruction.execute")));

    // A smuggled LIKE wildcard must NOT widen to all actions — dropped → empty.
    AuditQuery q;
    q.action_prefixes = {"%"};
    auto r = store.query(q);
    REQUIRE(r.has_value());
    CHECK(r->empty());

    // Valid prefix alongside a wildcard one: only the valid prefix applies.
    AuditQuery q2;
    q2.action_prefixes = {"auth.", "ins%"};
    auto r2 = store.query(q2);
    REQUIRE(r2.has_value());
    REQUIRE(r2->size() == 1);
    CHECK((*r2)[0].action == "auth.login");

    // Degenerate all-empty filter must not widen.
    AuditQuery q3;
    q3.action_prefixes = {"", ""};
    auto r3 = store.query(q3);
    REQUIRE(r3.has_value());
    CHECK(r3->empty());
}

TEST_CASE("AuditStore: random_sample over the scan cap is recency-capped + bounded by limit",
          "[pg][audit_store][auth-sample][slow]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    const int n = static_cast<int>(kAuditSampleScanCap) + 250;
    // Bulk-seed in-window auth events with ascending timestamps.
    exec_sql(db.dsn(), "INSERT INTO audit_store.audit_events (timestamp, principal, principal_role, "
                       "action, result, ttl_expires_at) SELECT 1000 + g, 'admin','admin',"
                       "'auth.login','success',0 FROM generate_series(1," +
                           std::to_string(n) + ") g");

    AuditQuery q;
    q.action_prefixes = {"auth."};
    q.random_sample = true;
    q.limit = 25;
    std::size_t pool_size = 0;
    auto r = store.query(q, &pool_size);
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 25);                // bounded by limit
    CHECK(pool_size == kAuditSampleScanCap); // pool hit the cap (recency-biased)
    for (const auto& e : *r)
        CHECK(e.timestamp >=
              static_cast<int64_t>(1000 + n - static_cast<int>(kAuditSampleScanCap)));

    // A limit ABOVE the cap must not lift the cap. The pool is the bound the
    // header promises and the REST layer reports as `recency_capped`; a caller
    // asking for more evidence than the cap gets the capped pool, not a bigger
    // scan. (The fetch used to be max(limit, cap), so this returned 10250.)
    AuditQuery over;
    over.action_prefixes = {"auth."};
    over.random_sample = true;
    over.limit = 12000;
    std::size_t over_pool = 0;
    auto ro = store.query(over, &over_pool);
    REQUIRE(ro.has_value());
    CHECK(over_pool == kAuditSampleScanCap);
    CHECK(ro->size() <= kAuditSampleScanCap);
}

TEST_CASE("AuditStore #2854: an ordinary restart seeds the liveness gauge from the "
          "existing anchor",
          "[pg][audit_store][retention][clock-guard]") {
    // The case the constructor-only seed DOES correctly handle: a database
    // that already has an anchor from a previous pass, restarted as a new
    // process. No backfill involved.
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    exec_sql(db.dsn(), "INSERT INTO audit_store.audit_retention_meta (key, value) VALUES "
                       "('last_pass_now', '1700000000')");
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    CHECK(store.last_pass_unixtime() == 1700000000);
}

// Per docs/observability-conventions.md: a bounded-label counter is
// pre-seeded to 0 at boot so an `absent()`-based alert stays meaningful on a
// healthy server before any degrade has ever fired.
TEST_CASE("AuditStore: wiring metrics pre-seeds the read-degrade label set",
          "[pg][audit_store][metrics]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    const std::string seeded = metrics.serialize();
    for (const char* reason : {"store_not_open", "pool_acquire_timeout", "query_error"})
        CHECK(seeded.find(std::string("yuzu_server_audit_read_degrade_total{reason=\"") + reason +
                          "\"} 0") != std::string::npos);
}

// Gate 3 cpp-expert, who measured both halves on PG 18: `result` and
// `principal_class` were bound verbatim as "enum-controlled". An embedded NUL
// stored `"suc"` — a silently truncated audit RESULT — and invalid UTF-8 failed
// the INSERT outright, losing the event on a fail-hard write path. Every caller
// in the tree passes a literal today; this pins the store so that stays a
// property of the store rather than of every caller remembering.
TEST_CASE("AuditStore: a NUL or invalid UTF-8 in result does not truncate or lose the row",
          "[pg][audit_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());

    AuditEvent e = mk("admin", "auth.login");
    e.result = std::string("suc\0cess", 8); // embedded NUL
    e.principal_class = "\xff\xfe";         // invalid UTF-8
    REQUIRE(store.log(e));                   // the event is NOT lost

    auto rows = store.query();
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    // Scrubbed, not truncated: the tail after the NUL survives.
    CHECK(rows->at(0).result != "suc");
    CHECK(rows->at(0).result.find("cess") != std::string::npos);
}

// Gate 2 security / Gate 3 cpp-expert: a negative limit reached PostgreSQL as
// `LIMIT -1`, which errors — and this store reports a query error as a DEGRADE,
// which is the series `YuzuAuditReadDegraded` pages on. So any read-privileged
// client could fire the evidence-availability alert at will and send the on-call
// after a database fault that does not exist. The parsers reject it as a 400;
// the store clamps as defence in depth. Both halves matter: the assertion that
// the DEGRADE COUNTER DID NOT MOVE is the one that pins the security property,
// and it is only meaningful because set_metrics pre-seeds the series to 0.
TEST_CASE("AuditStore: a negative limit clamps rather than reporting a degrade",
          "[pg][audit_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);
    REQUIRE(store.log(mk("admin", "auth.login")));

    AuditQuery q;
    q.limit = -1;
    auto rows = store.query(q);
    REQUIRE(rows.has_value()); // a degrade would be nullopt -> 503
    CHECK(rows->empty());
    CHECK(metrics.serialize().find(
              "yuzu_server_audit_read_degrade_total{reason=\"query_error\"} 0") !=
          std::string::npos);

    // A negative offset is already inert at this seam (the OFFSET clause is
    // emitted only when offset > 0) — pin that so it stays inert.
    AuditQuery q2;
    q2.offset = -5;
    auto rows2 = store.query(q2);
    REQUIRE(rows2.has_value());
    CHECK(rows2->size() == 1);
    CHECK(metrics.serialize().find(
              "yuzu_server_audit_read_degrade_total{reason=\"query_error\"} 0") !=
          std::string::npos);
}

// Gate 3 quality-engineer, on a fix of mine: it reverted the retention probe to
// the counting form PERF-1 replaced and the ENTIRE suite stayed green — the only
// evidence the fix worked was a hand-run EXPLAIN in a commit message, so a
// future revert would ship silently. This pins the two properties that make the
// probe index-eligible. It asserts SHAPE, not a query plan: the planner is
// cost-based and at this table size a sequential scan is legitimately cheaper,
// so a plan assertion here would pin an accident rather than the contract.
TEST_CASE("AuditStore: the retention probe stays index-eligible, and the survivor "
          "half stays ORDER BY/LIMIT-shaped (1f)",
          "[audit_store][retention]") {
    const std::string sql{kAuditRetentionProbeSql};
    // Never a counting aggregate: a count with no statement-level WHERE must
    // visit the ttl_expires_at = 0 majority, which sits outside the partial
    // index, so it degenerates to a full scan of the evidence table every pass.
    CHECK(sql.find("count(") == std::string::npos);
    CHECK(sql.find("COUNT(") == std::string::npos);
    CHECK(sql.find("FILTER") == std::string::npos);
    // The two halves are deliberately NOT the same shape (1f): the expired
    // half stays a bare EXISTS (fine — during a backlog almost every row
    // matches, so it finds one within the first few rows regardless of scan
    // strategy). Exactly one EXISTS(, not two.
    std::size_t exists_at = 0, exists_count = 0;
    while ((exists_at = sql.find("EXISTS(", exists_at)) != std::string::npos) {
        ++exists_count;
        exists_at += 1;
    }
    CHECK(exists_count == 1);
    // The survivor half is ORDER BY <indexed column> LIMIT 1 ... IS NOT NULL:
    // a plan-independent signal that survives a bad selectivity estimate on a
    // wide, sparsely-matched range (a Seq Scan would need a full sort before
    // it could apply the LIMIT, so the pre-ordered index path wins
    // regardless of the estimate).
    CHECK(sql.find("ORDER BY ttl_expires_at LIMIT 1") != std::string::npos);
    CHECK(sql.find(") IS NOT NULL") != std::string::npos);
    // Both halves must still carry the partial index's own predicate, or the
    // index is not eligible at all.
    std::size_t at = 0, predicates = 0;
    while ((at = sql.find("ttl_expires_at > 0", at)) != std::string::npos) {
        ++predicates;
        at += 1;
    }
    CHECK(predicates == 2);
}

// Gate 3 performance: at one capped pass per hour the 25k cap stops being a
// per-pass bound and becomes a permanent drain ceiling, below the rate the
// store's own write path sustains. A pass that hits the cap AND leaves a real
// backlog must therefore re-arm in seconds; anything else keeps the interval.
TEST_CASE("AuditStore: a binding cap re-arms in seconds, everything else waits the interval",
          "[audit_store][retention]") {
    CHECK(audit_next_wait_s(/*cap_bound_with_backlog=*/true, 60) == kAuditBacklogRearmSec);
    CHECK(audit_next_wait_s(/*cap_bound_with_backlog=*/true, 1) == kAuditBacklogRearmSec);
    // No backlog: the configured cadence, untouched.
    CHECK(audit_next_wait_s(/*cap_bound_with_backlog=*/false, 60) == 3600);
    CHECK(audit_next_wait_s(/*cap_bound_with_backlog=*/false, 1) == 60);
    // The re-arm is a floor on responsiveness, not on load: it must stay well
    // above the measured per-pass cost and well below the default interval.
    STATIC_REQUIRE(kAuditBacklogRearmSec > 0);
    STATIC_REQUIRE(kAuditBacklogRearmSec < 60);
}

// Gate 3 quality-engineer: the retention thread's lifecycle had no test at all.
// This pins start -> stop -> stop-again -> destroy. It deliberately does NOT
// call start_cleanup() twice: that is a KNOWN defect in the non-jthread arm
// (move-assigning over a joinable std::thread is std::terminate), and a test
// that crashes the suite is not a regression net. Tracked separately.
TEST_CASE("AuditStore: the cleanup thread stops idempotently and joins on destroy",
          "[pg][audit_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    {
        // A 1-minute interval: the first pass never fires inside the test, so
        // this exercises teardown, not the pass itself.
        AuditStore store(pool, kGuardRetentionDays, 1);
        REQUIRE(store.is_open());
        store.start_cleanup();
        store.stop_cleanup();
        store.stop_cleanup(); // idempotent
    }                         // ~AuditStore joins an already-stopped thread
    SUCCEED("cleanup thread torn down without hang or terminate");
}

// Dead-CMOS-then-NTP, driven through the real reap flow (Gate 3 QE SHOULD — the
// catastrophic-protection claim for the dropped is_event exemption was only
// proven at the pure classify() level). A corrupt durable last_pass_now
// (prev_unusable) stacked under a would_wipe condition (every row expired) must
// DECLINE, never drain the evidence chain on the corrupt pass.
TEST_CASE("AuditStore #2360: a corrupt clock reading under a would-wipe declines, never drains",
          "[pg][audit_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    const std::int64_t now = pg_now(db.dsn());
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, /*cleanup_interval_min=*/0);
    REQUIRE(store.is_open());
    seed_rows_with_ttl(db.dsn(), now - 100, 10); // every row expired → would_wipe
    // Poison the durable clock reading with a non-numeric value → prev_unusable.
    exec_sql(db.dsn(), "INSERT INTO audit_store.audit_retention_meta (key, value) VALUES "
                       "('last_pass_now', 'not-a-number') ON CONFLICT (key) DO UPDATE SET value = "
                       "EXCLUDED.value");

    CHECK(store.cleanup_once(now) == 0);           // declines (BadState/prev_unusable)
    CHECK(row_count(db.dsn()) == 10);              // nothing deleted on the corrupt pass
    CHECK(store.clock_anomaly_skips_count() == 1); // reported
    CHECK(store.rows_deleted_count() == 0);
    // The pass re-anchored an honest reading, so a durable anomaly fact set was
    // recorded rather than the evidence being wiped.
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE key = "
                                 "'last_anomaly_facts'") == "1");
}

// ── #2360: retention clock guard (single-sweeper advisory lease) ─────────────

TEST_CASE("AuditStore #2360: a first pass that would wipe every datable row declines once, "
          "then drains",
          "[pg][audit_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    const std::int64_t now = pg_now(db.dsn());
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, /*cleanup_interval_min=*/0);
    REQUIRE(store.is_open());
    anchor_guard(store, now - 3600); // #2579 precondition: this test is not about the bootstrap
    seed_rows_with_ttl(db.dsn(), now - 100, 10); // every row already expired

    CHECK(store.cleanup_once(now) == 0); // declines (would_wipe)
    CHECK(row_count(db.dsn()) == 10);
    CHECK(store.clock_anomaly_skips_count() == 1);
    CHECK(store.cleanup_failed_count() == 0);
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE key = "
                                 "'last_anomaly_facts'") == "1");

    // Identical next pass: suppressed repeat → drains, capped.
    CHECK(store.cleanup_once(now + 1) == 10);
    CHECK(row_count(db.dsn()) == 0);
    CHECK(store.clock_anomaly_skips_count() == 1); // not counted twice
    CHECK(store.rows_deleted_count() == 10);

    // A clean pass clears the durable anomaly fact set.
    CHECK(store.cleanup_once(now + 2) == 0);
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE key = "
                                 "'last_anomaly_facts'") == "0");
}

TEST_CASE("AuditStore #2360: a datable survivor means no wipe, so the pass deletes immediately",
          "[pg][audit_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    const std::int64_t now = pg_now(db.dsn());
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, 0);
    anchor_guard(store, now - 3600); // #2579 precondition: this test is not about the bootstrap
    seed_rows_with_ttl(db.dsn(), now - 100, 10);    // expired
    seed_rows_with_ttl(db.dsn(), now + kWindow, 1); // healthy survivor

    CHECK(store.cleanup_once(now) == 10);
    CHECK(row_count(db.dsn()) == 1);
    CHECK(store.clock_anomaly_skips_count() == 0);
}

TEST_CASE("AuditStore #2579: no stored reading + rows already expired declines, once",
          "[pg][audit_store][retention][clock-guard]") {
    // The disclosed shape, end to end. A host whose clock was ALREADY skewed
    // forward before its first guarded pass: rows written before the skew look
    // expired, rows written after it are still inside the window, so the
    // would-expire-everything test does not fire and -- before this trigger --
    // nothing else did either. The pass deleted, with no decline, no counter and
    // no warning.
    //
    // Deliberately NOT anchored: the absence of a stored reading IS the input.
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    const std::int64_t now = pg_now(db.dsn());
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, 0);
    REQUIRE(store.is_open());
    seed_rows_with_ttl(db.dsn(), now - 100, 10);    // expired: written before the skew
    seed_rows_with_ttl(db.dsn(), now + kWindow, 2); // datable survivors: written after it

    REQUIRE(store.cleanup_once(now) == 0); // was 10 before #2579
    CHECK(row_count(db.dsn()) == 12);
    CHECK(store.bootstrap_declines_count() == 1);
    // The signal separation is the contract, not an implementation detail: this
    // decline must not fire the alert that means "the clock moved".
    CHECK(store.clock_anomaly_skips_count() == 0);

    // Once, not forever. The declining pass settled the marker, so the next pass
    // has a comparison point and proceeds -- paced by the cap as always.
    CHECK(store.cleanup_once(now + 1) == 10);
    CHECK(row_count(db.dsn()) == 2);
    CHECK(store.bootstrap_declines_count() == 1); // and NOT counted twice
}

TEST_CASE("AuditStore #2579: a probe-failed pass does not spend the bootstrap trigger",
          "[pg][audit_store][retention][clock-guard]") {
    // `cleanup_once` re-anchors BEFORE it probes, so a pass whose probes then
    // fail has consumed the anchor without ever reaching a verdict. Deriving the
    // trigger from the stored reading would let ONE transient probe failure
    // disarm it permanently: pass 2 sees a reading, calls itself anchored, and
    // deletes with every detector false -- the exact defect #2579 closes,
    // reinstated. The marker is therefore settled at the VERDICT, and every
    // early return before it rolls the whole transaction back.
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    const std::int64_t now = pg_now(db.dsn());
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, 0);
    REQUIRE(store.is_open());
    seed_rows_with_ttl(db.dsn(), now - 100, 10);
    seed_rows_with_ttl(db.dsn(), now + kWindow, 2);

    // Pass 1 cannot probe -- and DOES re-anchor on its way past.
    exec_sql(db.dsn(), "ALTER TABLE audit_store.audit_events RENAME TO audit_events_hidden");
    CHECK(store.cleanup_once(now) == 0);
    CHECK(store.cleanup_failed_count() == 1);
    CHECK(store.bootstrap_declines_count() == 0); // no verdict was reached
    exec_sql(db.dsn(), "ALTER TABLE audit_store.audit_events_hidden RENAME TO audit_events");

    // Pass 2 must STILL decline. Without the verdict-point settle it deleted all 10.
    CHECK(store.cleanup_once(now + 1) == 0);
    CHECK(store.bootstrap_declines_count() == 1);
    CHECK(row_count(db.dsn()) == 12);

    // ...and having now reached a verdict, it is spent: pass 3 drains.
    CHECK(store.cleanup_once(now + 2) == 10);
    CHECK(row_count(db.dsn()) == 2);
}

TEST_CASE("AuditStore #2579: consecutive probe failures do not erode the trigger",
          "[pg][audit_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    const std::int64_t now = pg_now(db.dsn());
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, 0);
    REQUIRE(store.is_open());
    seed_rows_with_ttl(db.dsn(), now - 100, 10);
    seed_rows_with_ttl(db.dsn(), now + kWindow, 2);

    exec_sql(db.dsn(), "ALTER TABLE audit_store.audit_events RENAME TO audit_events_hidden");
    for (int i = 0; i < 3; ++i)
        CHECK(store.cleanup_once(now + i) == 0);
    CHECK(store.cleanup_failed_count() == 3);
    CHECK(store.bootstrap_declines_count() == 0); // no verdict on any of them
    exec_sql(db.dsn(), "ALTER TABLE audit_store.audit_events_hidden RENAME TO audit_events");

    // Still armed after three failures.
    CHECK(store.cleanup_once(now + 10) == 0);
    CHECK(store.bootstrap_declines_count() == 1);
    CHECK(row_count(db.dsn()) == 12);
}

TEST_CASE("AuditStore #2579: nothing expired means no bootstrap decline",
          "[pg][audit_store][retention][clock-guard]") {
    // The cost control. A fresh install has no stored reading either, and if the
    // trigger fired on that it would declare an anomaly on every server's first
    // boot -- which is why `no_anchor` is tested AFTER `has_expired`.
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    const std::int64_t now = pg_now(db.dsn());
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, 0);
    REQUIRE(store.is_open());
    seed_rows_with_ttl(db.dsn(), now + kWindow, 3); // nothing expired

    CHECK(store.cleanup_once(now) == 0);
    CHECK(store.bootstrap_declines_count() == 0);
    CHECK(store.clock_anomaly_skips_count() == 0);
    CHECK(row_count(db.dsn()) == 3);
}

TEST_CASE("AuditStore #2360: one forward-skew far-future row cannot disarm the guard",
          "[pg][audit_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    const std::int64_t now = pg_now(db.dsn());
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, 0);
    seed_rows_with_ttl(db.dsn(), now - 100, 10);
    seed_rows_with_ttl(db.dsn(), now + kWindow + kAuditTtlFutureSlackSec + 1000, 1); // implausible

    CHECK(store.cleanup_once(now) == 0); // still declines — far-future row is not a survivor
    CHECK(row_count(db.dsn()) == 11);
    CHECK(store.clock_anomaly_skips_count() == 1);
}

TEST_CASE("AuditStore #2360: the per-pass cap paces a large expiry and reports a backlog",
          "[pg][audit_store][retention][clock-guard][slow]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    const std::int64_t now = pg_now(db.dsn());
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, 0);
    anchor_guard(store, now - 3600); // #2579 precondition: this test is not about the bootstrap
    constexpr int kSurplus = 7;
    seed_rows_with_ttl(db.dsn(), now - 100, static_cast<int>(kMaxAuditDeletesPerPass) + kSurplus);
    seed_rows_with_ttl(db.dsn(), now + kWindow, 1); // survivor → not a would_wipe

    CHECK(store.cleanup_once(now) == kMaxAuditDeletesPerPass);
    CHECK(store.cap_reached_count() == 1);
    CHECK(store.rows_deleted_count() == kMaxAuditDeletesPerPass);
    CHECK(store.clock_anomaly_skips_count() == 0); // an over-cap backlog is NOT an anomaly

    // The pass that clears the backlog does NOT count as cap-reached.
    CHECK(store.cleanup_once(now + 1) == kSurplus);
    CHECK(store.cap_reached_count() == 1);
    CHECK(row_count(db.dsn()) == 1);
}

TEST_CASE("AuditStore #2360: the clock-step guard survives a restart via durable meta",
          "[pg][audit_store][retention][clock-guard]") {
    // The elapsed-time step is the only detector that survives a write landing
    // after the jump. Held in memory it would compare against nothing on the
    // first pass of a new process; the durable last_pass_now closes that.
    //
    // The decision clock is PostgreSQL's own `now()` (#2360/1d), which a fast
    // unit test cannot make jump. What a genuine jump (or a long outage) WOULD
    // leave behind is reachable, though: a `last_pass_now` row far older than
    // the current real reading. `cleanup_once` reads that row back verbatim
    // (audit_store.cpp's meta read, above the stamp), so hand-writing it here
    // reproduces the post-jump state exactly rather than approximating it.
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    const std::int64_t now = pg_now(db.dsn());
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    {
        AuditStore first(pool, kGuardRetentionDays, 0);
        REQUIRE(first.is_open());
        anchor_guard(first, now - 3600); // #2579 precondition: this test is about the durable STEP
        seed_rows_with_ttl(db.dsn(), now - 100, 5);
        seed_rows_with_ttl(db.dsn(), now + kWindow, 1); // survivor: no would_wipe
        REQUIRE(first.cleanup_once(now) == 5);
        REQUIRE(first.clock_anomaly_skips_count() == 0);
    }
    // Simulate what a restart after a large clock jump (or a long outage) would
    // find durably stored: a `last_pass_now` far older than the current real
    // reading. Direct SQL, not a store method — no product path writes this
    // row to an arbitrary value, only the guard itself.
    exec_sql(db.dsn(), "UPDATE audit_store.audit_retention_meta SET value = '" +
                            std::to_string(now - kAuditMinBigStepSec - 10) +
                            "' WHERE key = 'last_pass_now'");

    // A fresh store (new process) over the same DB. From the OUTCOME alone —
    // some expired rows, one survivor — nothing looks wrong; only the durable
    // step catches it.
    AuditStore second(pool, kGuardRetentionDays, 0);
    REQUIRE(second.is_open());
    seed_rows_with_ttl(db.dsn(), now - 100, 5);          // already expired
    seed_rows_with_ttl(db.dsn(), now + kWindow + 10, 1); // survivor
    CHECK(second.cleanup_once(now) == 0);
    CHECK(second.clock_anomaly_skips_count() == 1);
}

TEST_CASE("AuditStore #2854: a negative anchor is seeded unclamped, not laundered to 0",
          "[pg][audit_store][retention][clock-guard]") {
    // The anti-clamp pin. A negative `last_pass_now` is the legitimate
    // dead-CMOS case the clock guard exists for (`cleanup_once` writes it
    // straight from PostgreSQL's own `now()`, unclamped, when THAT server's
    // clock is behind 1970). A `> 0` filter anywhere on the seed path would
    // silently re-merge this with `0` ("no pass has ever run"), handing a
    // permanent grace to exactly the machine the guard exists to catch.
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    exec_sql(db.dsn(), "INSERT INTO audit_store.audit_retention_meta (key, value) VALUES "
                       "('last_pass_now', '-100')");
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    CHECK(store.last_pass_unixtime() == -100);
}

TEST_CASE("AuditStore #2854: a non-integer anchor seeds the anomaly sentinel, never 0",
          "[pg][audit_store][retention][clock-guard]") {
    // Corrupt/hand-edited durable state is an anomaly, not a clean slate —
    // laundering it into `0` would silently hand it the liveness family's
    // "never ran" grace instead of surfacing it.
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    exec_sql(db.dsn(), "INSERT INTO audit_store.audit_retention_meta (key, value) VALUES "
                       "('last_pass_now', 'not-a-number')");
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    const auto seeded = store.last_pass_unixtime();
    CHECK(seeded != 0);
    CHECK(seeded == std::numeric_limits<std::int64_t>::min());
}

TEST_CASE("AuditStore #2854: an implausibly large anchor seeds the anomaly sentinel, never 0",
          "[pg][audit_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    const auto huge = std::numeric_limits<std::int64_t>::max(); // past kMaxPlausibleNow (max/4)
    exec_sql(db.dsn(), "INSERT INTO audit_store.audit_retention_meta (key, value) VALUES "
                       "('last_pass_now', '" + std::to_string(huge) + "')");
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    const auto seeded = store.last_pass_unixtime();
    CHECK(seeded != 0);
    CHECK(seeded == std::numeric_limits<std::int64_t>::min());
}

TEST_CASE("AuditStore #2854: a live retention pass overwrites the seeded anchor with the "
          "caller's clock",
          "[pg][audit_store][retention][clock-guard]") {
    // The two-clock contract: the SEED reads PostgreSQL's clock (via the
    // durable anchor); every SUBSEQUENT pass overwrites the gauge with the
    // CALLER's clock (`cleanup_once`), which drives no decision.
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    exec_sql(db.dsn(), "INSERT INTO audit_store.audit_retention_meta (key, value) VALUES "
                       "('last_pass_now', '1700000000')");
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, 0);
    REQUIRE(store.is_open());
    CHECK(store.last_pass_unixtime() == 1700000000); // seeded from the durable anchor

    const std::int64_t caller_now = pg_now(db.dsn()) + 5; // deliberately not the seeded value
    store.cleanup_once(caller_now);
    CHECK(store.last_pass_unixtime() == caller_now); // overwritten by the CALLER's clock
}

TEST_CASE("AuditStore #2360: a closed store counts a failed pass, not silence",
          "[audit_store][retention][clock-guard]") {
    PgPool bad{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    AuditStore store(bad, kGuardRetentionDays, 0);
    REQUIRE_FALSE(store.is_open());
    CHECK(store.cleanup_once(kArbitraryPlausibleTime) == 0);
    CHECK(store.cleanup_failed_count() == 1);
    CHECK(store.clock_anomaly_skips_count() == 0);
    CHECK(store.retention_passes_count() == 1); // liveness still moves
}

TEST_CASE("AuditStore #2360: an implausible caller clock is refused before any arithmetic",
          "[audit_store][retention][clock-guard]") {
    PgPool bad{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    AuditStore store(bad, kGuardRetentionDays, 0);
    const std::int64_t huge = std::numeric_limits<std::int64_t>::max() / 2;
    CHECK(store.cleanup_once(huge) == 0);
    CHECK(store.cleanup_failed_count() == 1);
    CHECK(store.retention_passes_count() == 1);
    CHECK(store.last_pass_unixtime() == 0); // a refused reading is NOT stamped
}

TEST_CASE("AuditStore #2360: a sibling holding the advisory lease skips the pass quietly",
          "[pg][audit_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    const std::int64_t now = pg_now(db.dsn());
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, 0);
    // #2579 precondition, and here it is load-bearing rather than cosmetic:
    // without it this pass declines for the MISSING ANCHOR, every assertion below
    // passes for the wrong reason, and the test stays green through an advisory
    // lock that does not work at all. Verified by deleting the lock acquisition —
    // with this line the no-lock case fails as it must; without it it passes.
    anchor_guard(store, now - 3600);
    seed_rows_with_ttl(db.dsn(), now - 100, 5);
    seed_rows_with_ttl(db.dsn(), now + kWindow, 1); // a survivor: a lone pass WOULD delete

    // Hold the fleet-wide reap lease on a separate connection's open txn.
    PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    PgResult begin{PQexec(locker.get(), "BEGIN")};
    REQUIRE(begin.ok());
    PgResult lk{PQexec(locker.get(),
                       "SELECT pg_advisory_xact_lock(hashtextextended('audit_store:reap', 0))")};
    REQUIRE(lk.ok());

    CHECK(store.cleanup_once(now) == 0);      // skipped — lease held elsewhere
    CHECK(row_count(db.dsn()) == 6);          // nothing deleted
    CHECK(store.cleanup_failed_count() == 0); // a skip is NOT a failure
    CHECK(store.clock_anomaly_skips_count() == 0);

    PgResult rollback{PQexec(locker.get(), "ROLLBACK")};
    REQUIRE(rollback.ok());
}

TEST_CASE("AuditStore #2360/1d: a skewed process clock cannot change the verdict",
          "[pg][audit_store][retention][clock-guard]") {
    // Gate 4 unhappy-path UP-2 / Sol: before this fix, the DECISION read the
    // CALLER's clock, so two replicas whose process clocks disagreed could
    // derive different datable_horizon/would_wipe verdicts from the SAME
    // underlying rows — each could anchor a reading the other then treated as
    // an anomaly, alternating forever. Since #2360/1d every decision reads
    // PostgreSQL's OWN clock inside the advisory-lock transaction, so the
    // CALLER's `now` — however skewed — cannot move the verdict. Two replicas
    // reading wildly different process clocks against the same rows still
    // agree, because neither's reading is what gets compared.
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    const std::int64_t now = pg_now(db.dsn());
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore replica_a(pool, kGuardRetentionDays, 0);
    AuditStore replica_b(pool, kGuardRetentionDays, 0);
    REQUIRE(replica_a.is_open());
    REQUIRE(replica_b.is_open());
    anchor_guard(replica_a, now - 3600); // #2579 precondition: this test is about clock skew
    seed_rows_with_ttl(db.dsn(), now - 100, 5);      // expired by the REAL clock
    seed_rows_with_ttl(db.dsn(), now + kWindow, 1);  // a survivor by the REAL clock

    // Replica A's process clock reads a month BEHIND real time; replica B's
    // reads a month AHEAD. Under a caller-clock-driven decision, A would see
    // nothing expired yet (its own `now` sits before every ttl) and B would
    // see everything past `datable_horizon` (excluded as implausibly future),
    // so the two would disagree about whether the pass should delete at all.
    const std::int64_t behind = now - 30 * 86400;
    const std::int64_t ahead = now + 30 * 86400;

    CHECK(replica_a.cleanup_once(behind) == 5); // still governed by PG's real clock
    CHECK(replica_a.clock_anomaly_skips_count() == 0);
    CHECK(row_count(db.dsn()) == 1); // the survivor remains

    CHECK(replica_b.cleanup_once(ahead) == 0); // real clock agrees: nothing left to expire
    CHECK(replica_b.clock_anomaly_skips_count() == 0);
    CHECK(replica_b.cleanup_failed_count() == 0);
    CHECK(row_count(db.dsn()) == 1); // unchanged — no mutual decline, no double-delete
}

TEST_CASE("AuditStore #2360: classify pins the anomaly precedence with no database",
          "[audit_store][retention][clock-guard]") {
    using namespace yuzu::server::audit_retention;
    CHECK(classify({.has_expired = true, .would_wipe = true, .big_step = false,
                    .prev_unusable = false}) == Anomaly::Wipe);
    CHECK(classify({.has_expired = true, .would_wipe = true, .big_step = true,
                    .prev_unusable = false}) == Anomaly::Step); // Step outranks Wipe
    CHECK(classify({.has_expired = true, .would_wipe = true, .big_step = true,
                    .prev_unusable = true}) == Anomaly::BadState); // BadState outranks all
    CHECK(classify({.has_expired = false, .would_wipe = false, .big_step = false,
                    .prev_unusable = false}) == Anomaly::None);
}
