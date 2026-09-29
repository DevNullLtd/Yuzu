/**
 * test_response_store.cpp — Unit tests for ResponseStore
 *
 * Covers: CRUD, query filters, TTL, count, multi-agent, ordering, facets,
 * #1634 aggregate scope, and the ADR-0039 retention reap (`reap_expired()`).
 * Migrated Postgres store (ADR-0006/0008/0039, schema `response_store`).
 * PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails when it is set
 * but broken.
 */

#include "response_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every test
// below constructs its own ResponseStore against a clone of this schema.
yuzu::test::PgTestTemplate responsestore_tpl{"responsestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResponseStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("responsestore template: store failed to migrate");
}};

// Run a raw SQL statement against the test database on a second connection —
// lets a test simulate TTL expiry / poison gc_meta directly.
void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}

// Scalar SELECT on a second connection — column 0, row 0, as text; "" when
// the result set is genuinely empty.
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

// PostgreSQL's own clock, for tests that need a plausible reading to poison
// or compare against — mirrors test_audit_store.cpp's own `pg_now`.
std::int64_t pg_now(const std::string& dsn) {
    return std::stoll(query_scalar(dsn, "SELECT EXTRACT(EPOCH FROM now())::bigint"));
}

// #2691 (transplanted from #2663/#2579): a `reap_expired()` pass over an
// EMPTY table settles the durable `bootstrap_settled` marker with nothing
// expired, so `classify()` short-circuits to `Anomaly::None` regardless of
// `no_anchor` and no counter moves. Call BEFORE seeding any expired data so
// a test about something else keeps its original decline-once-not-applicable,
// drains-immediately contract instead of picking up an extra missing-anchor
// decline on its first real pass.
void anchor_guard(ResponseStore& store) {
    store.reap_expired();
    REQUIRE(store.responses_reaped_total() == 0);
}

} // namespace

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("ResponseStore: open against a fresh template clone", "[pg][response_store][db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
}

TEST_CASE("ResponseStore: bad-path constructor (unroutable DSN) is closed",
          "[response_store]") {
    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    ResponseStore store(bad_pool);
    REQUIRE_FALSE(store.is_open());
    // Reads degrade to nullopt; ingest/reap are silent no-ops.
    CHECK_FALSE(store.query("cmd-x").has_value());
    CHECK(store.total_count() == 0);
    store.store(StoredResponse{}); // must not throw/crash
    store.reap_expired();          // must not throw/crash
}

TEST_CASE("ResponseStore: store and retrieve", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());

    StoredResponse resp;
    resp.instruction_id = "cmd-abc123";
    resp.agent_id = "agent-1";
    resp.status = 1; // SUCCESS
    resp.output = "hostname|WORKSTATION-01";
    store.store(resp);

    auto results = store.get_by_instruction("cmd-abc123");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].instruction_id == "cmd-abc123");
    CHECK((*results)[0].agent_id == "agent-1");
    CHECK((*results)[0].status == 1);
    CHECK((*results)[0].output == "hostname|WORKSTATION-01");
}

// #2691 (Gate 4 unhappy-path UP-5): pg::exec_params binds instruction_id/
// execution_id/plugin unsanitized, as a NUL-terminated C string
// (paramLengths=nullptr) — an embedded NUL byte (valid UTF-8) would
// otherwise silently truncate the bound value at the store layer instead of
// failing the INSERT, letting a forged short instruction_id collide with a
// real one. store() must drop the whole row (counted, never truncate) when
// any of those three fields contains an embedded NUL.
TEST_CASE("ResponseStore: an embedded NUL in instruction_id is dropped, not silently truncated",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    StoredResponse resp;
    resp.instruction_id = std::string("victim-instruction") + '\0' + "attacker-payload";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.output = "forged";
    store.store(resp);

    // Must NOT appear under the truncated-to prefix "victim-instruction" —
    // that would be exactly the forgery-via-truncation UP-5 describes.
    auto results = store.get_by_instruction("victim-instruction");
    REQUIRE(results.has_value());
    CHECK(results->empty());
}

TEST_CASE("ResponseStore: an embedded NUL in execution_id or plugin is also dropped",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    StoredResponse r1;
    r1.instruction_id = "cmd-exec-nul";
    r1.agent_id = "agent-1";
    r1.status = 1;
    r1.execution_id = std::string("real-exec") + '\0' + "junk";
    store.store(r1);

    StoredResponse r2;
    r2.instruction_id = "cmd-plugin-nul";
    r2.agent_id = "agent-1";
    r2.status = 1;
    r2.plugin = std::string("real-plugin") + '\0' + "junk";
    store.store(r2);

    auto results1 = store.get_by_instruction("cmd-exec-nul");
    REQUIRE(results1.has_value());
    CHECK(results1->empty());

    auto results2 = store.get_by_instruction("cmd-plugin-nul");
    REQUIRE(results2.has_value());
    CHECK(results2->empty());
}

// #2691 (Gate 8 security-guardian): agent_id shares the identical hazard —
// Register() validates length/non-emptiness but not embedded-NUL, so a
// maliciously-enrolled device's responses could otherwise land, truncated,
// under a shorter real device's agent_id.
TEST_CASE("ResponseStore: an embedded NUL in agent_id is also dropped, not silently truncated",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    StoredResponse resp;
    resp.instruction_id = "cmd-agent-nul";
    resp.agent_id = std::string("victim-agent") + '\0' + "attacker-payload";
    resp.status = 1;
    resp.output = "forged";
    store.store(resp);

    ResponseQuery q;
    q.agent_id = "victim-agent";
    auto results = store.query("cmd-agent-nul", q);
    REQUIRE(results.has_value());
    CHECK(results->empty());
}

TEST_CASE("ResponseStore: multiple responses same instruction", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    for (int i = 0; i < 5; ++i) {
        StoredResponse resp;
        resp.instruction_id = "cmd-multi";
        resp.agent_id = "agent-" + std::to_string(i);
        resp.status = 1;
        resp.output = "data-" + std::to_string(i);
        store.store(resp);
    }

    auto results = store.get_by_instruction("cmd-multi");
    REQUIRE(results.has_value());
    CHECK(results->size() == 5);
}

TEST_CASE("ResponseStore: query with agent_id filter", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    for (const auto& aid : {"agent-a", "agent-b", "agent-a"}) {
        StoredResponse resp;
        resp.instruction_id = "cmd-filter";
        resp.agent_id = aid;
        resp.status = 1;
        resp.output = "ok";
        store.store(resp);
    }

    ResponseQuery q;
    q.agent_id = "agent-a";
    auto results = store.query("cmd-filter", q);
    REQUIRE(results.has_value());
    CHECK(results->size() == 2);
}

TEST_CASE("ResponseStore: query with status filter", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    StoredResponse r1;
    r1.instruction_id = "cmd-status";
    r1.agent_id = "agent-1";
    r1.status = 1; // SUCCESS
    r1.output = "ok";
    store.store(r1);

    StoredResponse r2;
    r2.instruction_id = "cmd-status";
    r2.agent_id = "agent-1";
    r2.status = 2; // FAILURE
    r2.output = "fail";
    store.store(r2);

    ResponseQuery q;
    q.status = 2;
    auto results = store.query("cmd-status", q);
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].output == "fail");
}

TEST_CASE("ResponseStore: query with limit and offset", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    for (int i = 0; i < 10; ++i) {
        StoredResponse resp;
        resp.instruction_id = "cmd-page";
        resp.agent_id = "agent-1";
        resp.status = 1;
        resp.output = "row-" + std::to_string(i);
        store.store(resp);
    }

    ResponseQuery q;
    q.limit = 3;
    q.offset = 0;
    auto page1 = store.query("cmd-page", q);
    REQUIRE(page1.has_value());
    CHECK(page1->size() == 3);

    q.offset = 3;
    auto page2 = store.query("cmd-page", q);
    REQUIRE(page2.has_value());
    CHECK(page2->size() == 3);
}

// #2691 (Doomgoose finding #2): a negative limit bound raw into `LIMIT $N`
// is not a benign empty query — Postgres rejects a negative LIMIT outright,
// so before the fix this failed the statement and read as store degradation
// (nullopt) rather than falling back to the struct's default page size.
TEST_CASE("ResponseStore: a negative limit is sanitized, not a degrade",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    StoredResponse resp;
    resp.instruction_id = "cmd-negfix";
    resp.agent_id = "agent-1";
    resp.status = 1;
    store.store(resp);

    ResponseQuery q;
    q.limit = -1;
    auto out = store.query("cmd-negfix", q);
    REQUIRE(out.has_value()); // NOT a degrade
    CHECK(out->size() == 1);

    auto out2 = store.query_by_execution("nonexistent-exec", q);
    REQUIRE(out2.has_value()); // engaged-empty (unknown execution_id), not a degrade
}

TEST_CASE("ResponseStore: empty query returns an engaged-empty vector, not a degrade",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    auto results = store.get_by_instruction("nonexistent");
    REQUIRE(results.has_value());
    CHECK(results->empty());
}

TEST_CASE("ResponseStore: total_count", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.total_count() == 0);

    StoredResponse resp;
    resp.instruction_id = "cmd-count";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.output = "ok";
    store.store(resp);

    REQUIRE(store.total_count() == 1);
}

TEST_CASE("ResponseStore: error_detail stored", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    StoredResponse resp;
    resp.instruction_id = "cmd-err";
    resp.agent_id = "agent-1";
    resp.status = 2;
    resp.output = "";
    resp.error_detail = "plugin not found";
    store.store(resp);

    auto results = store.get_by_instruction("cmd-err");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].error_detail == "plugin not found");
}

TEST_CASE("ResponseStore: large output stored", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    StoredResponse resp;
    resp.instruction_id = "cmd-large";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.output = std::string(100000, 'X');
    store.store(resp);

    auto results = store.get_by_instruction("cmd-large");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].output.size() == 100000);
}

// ADR-0039 addendum: `output`/`error_detail` are untrusted agent-supplied
// bytes; Postgres TEXT requires valid server-encoding (unlike SQLite's
// permissive TEXT affinity), so store() sanitizes to U+FFFD before the
// insert (sanitize_utf8_strict, utf8_sanitize.hpp) — the row still LANDS
// (never a fail-soft drop from a self-inflicted encoding rejection),
// preserving the #1593 guarantee (test_rest_bundle.cpp's REST-level pin).
TEST_CASE("ResponseStore: invalid-UTF-8 output is sanitized to U+FFFD, not dropped",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    StoredResponse resp;
    resp.instruction_id = "cmd-badutf8";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.output = std::string(1, '\xff') + "binary";
    resp.error_detail = std::string(1, '\xfe') + "err";
    store.store(resp);

    auto results = store.get_by_instruction("cmd-badutf8");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1); // present, not silently dropped
    CHECK((*results)[0].output == "\xEF\xBF\xBD" "binary");
    CHECK((*results)[0].error_detail == "\xEF\xBF\xBD" "err");
}

// Facets are derived from `sanitized_output` (response_store.cpp:324), NOT the
// raw bytes — so an invalid-UTF-8 facet value must land as its U+FFFD-defanged
// form, never a raw byte the facet INSERT would reject (SQLSTATE 22021) and
// silently ROLLBACK-TO-SAVEPOINT away. The plain-output UTF-8 test above leaves
// `plugin` empty and so skips the whole facet block; this one exercises the
// post-sanitize-derivation invariant with a real schema.
TEST_CASE("ResponseStore: facets are derived post-sanitize (invalid-UTF-8 value defanged)",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    // vuln_scan schema: severity|category|title|detail. Put an invalid byte in
    // the category field (col_idx 1) — the facet value must come back defanged.
    StoredResponse resp;
    resp.instruction_id = "cmd-facet-badutf8";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.plugin = "vuln_scan";
    resp.output = std::string("high|") + '\xff' + "category|title|detail";
    store.store(resp);

    auto facets = store.facet_values("cmd-facet-badutf8", /*col_idx=*/1);
    REQUIRE(facets.has_value());
    REQUIRE(facets->size() == 1); // derived, not dropped
    CHECK((*facets)[0].value == "\xEF\xBF\xBD" "category");
    // No raw invalid byte survived into the persisted facet value.
    CHECK((*facets)[0].value.find('\xff') == std::string::npos);
}

// finalize_terminal_status binds the agent-supplied error message; like store()
// it must U+FFFD-defang it (Gate 2 security MEDIUM). An unsanitized non-UTF-8
// byte would fail the UPDATE (SQLSTATE 22021), leaving the RUNNING row never
// finalized and no fallback frame — the #1593 "real result must surface" gap
// reopened on the finalize path.
TEST_CASE("ResponseStore: finalize_terminal_status sanitizes error_detail (invalid UTF-8)",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    // A RUNNING row (status 0) awaiting its terminal frame.
    StoredResponse running;
    running.instruction_id = "cmd-finalize-badutf8";
    running.agent_id = "agent-1";
    running.execution_id = "exec-1";
    running.status = 0;
    running.output = "partial output";
    store.store(running);

    // Terminal frame carries a non-UTF-8 error message.
    const std::string bad_err = std::string(1, '\xff') + "boom";
    auto fr = store.finalize_terminal_status("cmd-finalize-badutf8", "agent-1", /*status=*/2,
                                             bad_err, "exec-1", /*plugin_result_status=*/0);
    CHECK(fr == ResponseStore::FinalizeResult::Updated); // row finalized, not lost to 22021

    auto results = store.get_by_instruction("cmd-finalize-badutf8");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].status == 2);
    CHECK((*results)[0].error_detail == "\xEF\xBF\xBD" "boom");
    CHECK((*results)[0].error_detail.find('\xff') == std::string::npos);
}

TEST_CASE("ResponseStore: timestamp ordering", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    for (int64_t ts : {100, 300, 200}) {
        StoredResponse resp;
        resp.instruction_id = "cmd-order";
        resp.agent_id = "agent-1";
        resp.timestamp = ts;
        resp.status = 1;
        resp.output = std::to_string(ts);
        store.store(resp);
    }

    auto results = store.get_by_instruction("cmd-order");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 3);
    // DESC ordering
    CHECK((*results)[0].timestamp >= (*results)[1].timestamp);
    CHECK((*results)[1].timestamp >= (*results)[2].timestamp);
}

TEST_CASE("ResponseStore: query with time range", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    for (int64_t ts : {100, 200, 300, 400, 500}) {
        StoredResponse resp;
        resp.instruction_id = "cmd-range";
        resp.agent_id = "agent-1";
        resp.timestamp = ts;
        resp.status = 1;
        resp.output = "t" + std::to_string(ts);
        store.store(resp);
    }

    ResponseQuery q;
    q.since = 200;
    q.until = 400;
    auto results = store.query("cmd-range", q);
    REQUIRE(results.has_value());
    CHECK(results->size() == 3);
}

TEST_CASE("ResponseStore: multiple instructions", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    for (const auto& id : {"cmd-1", "cmd-2", "cmd-3"}) {
        StoredResponse resp;
        resp.instruction_id = id;
        resp.agent_id = "agent-1";
        resp.status = 1;
        resp.output = "ok";
        store.store(resp);
    }

    CHECK(store.get_by_instruction("cmd-1")->size() == 1);
    CHECK(store.get_by_instruction("cmd-2")->size() == 1);
    CHECK(store.get_by_instruction("cmd-99")->size() == 0);
    CHECK(store.total_count() == 3);
}

TEST_CASE("ResponseStore: ttl_expires_at set from retention", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/30);

    StoredResponse resp;
    resp.instruction_id = "cmd-ttl";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.output = "ok";
    store.store(resp);

    auto results = store.get_by_instruction("cmd-ttl");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].ttl_expires_at > 0);
}

TEST_CASE("ResponseStore: custom ttl_expires_at preserved", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    StoredResponse resp;
    resp.instruction_id = "cmd-custom-ttl";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.output = "ok";
    resp.ttl_expires_at = 999999;
    store.store(resp);

    auto results = store.get_by_instruction("cmd-custom-ttl");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].ttl_expires_at == 999999);
}

// ============================================================================
// PR 2 — execution_id column + query_by_execution exact correlation.
// ============================================================================

TEST_CASE("ResponseStore PR2: execution_id default empty for legacy writers",
          "[pg][response_store][execution_id]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    StoredResponse r;
    r.instruction_id = "cmd-legacy-1";
    r.agent_id = "agent-1";
    r.status = 1;
    r.output = "ok";
    // Caller did NOT set execution_id — legacy / out-of-band path.
    store.store(r);

    auto rows = store.get_by_instruction("cmd-legacy-1");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].execution_id.empty());
}

TEST_CASE("ResponseStore PR2: execution_id round-trip when stamped at write",
          "[pg][response_store][execution_id]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    StoredResponse r;
    r.instruction_id = "cmd-pr2-1";
    r.agent_id = "agent-1";
    r.status = 1;
    r.output = "ok";
    r.execution_id = "exec-aaaa-bbbb-cccc-dddd-eeee";
    store.store(r);

    auto rows = store.get_by_instruction("cmd-pr2-1");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].execution_id == "exec-aaaa-bbbb-cccc-dddd-eeee");
}

TEST_CASE("ResponseStore PR2: query_by_execution returns only matching exec",
          "[pg][response_store][execution_id]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    // Two executions of the same definition (same command_id namespace).
    StoredResponse a;
    a.instruction_id = "cmd-shared";
    a.agent_id = "agent-1";
    a.status = 1;
    a.output = "from-exec-A";
    a.execution_id = "exec-A";
    store.store(a);

    StoredResponse b;
    b.instruction_id = "cmd-shared";
    b.agent_id = "agent-1";
    b.status = 1;
    b.output = "from-exec-B";
    b.execution_id = "exec-B";
    store.store(b);

    auto from_a = store.query_by_execution("exec-A");
    REQUIRE(from_a.has_value());
    REQUIRE(from_a->size() == 1);
    CHECK((*from_a)[0].output == "from-exec-A");

    auto from_b = store.query_by_execution("exec-B");
    REQUIRE(from_b.has_value());
    REQUIRE(from_b->size() == 1);
    CHECK((*from_b)[0].output == "from-exec-B");
}

TEST_CASE("ResponseStore PR2: query_by_execution rejects empty sentinel (engaged-empty, not "
          "a degrade)",
          "[pg][response_store][execution_id]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    StoredResponse r;
    r.instruction_id = "cmd-leg";
    r.agent_id = "agent-1";
    r.status = 1;
    r.output = "legacy";
    // execution_id stays empty.
    store.store(r);

    auto rows = store.query_by_execution("");
    REQUIRE(rows.has_value());
    CHECK(rows->empty());
}

TEST_CASE("ResponseStore PR2: query_by_execution honours agent_id + since/until + status "
          "filters",
          "[pg][response_store][execution_id]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    auto seed = [&](const std::string& exec, const std::string& agent, int64_t ts, int status,
                    const std::string& out) {
        StoredResponse r;
        r.instruction_id = "cmd-x";
        r.agent_id = agent;
        r.status = status;
        r.output = out;
        r.timestamp = ts;
        r.execution_id = exec;
        store.store(r);
    };
    seed("exec-1", "agent-A", 100, 1, "A-100");
    seed("exec-1", "agent-A", 200, 1, "A-200");
    seed("exec-1", "agent-B", 150, 2, "B-150-fail");
    seed("exec-2", "agent-A", 175, 1, "exec2-A-175");

    SECTION("agent_id filter") {
        ResponseQuery q;
        q.agent_id = "agent-B";
        auto rows = store.query_by_execution("exec-1", q);
        REQUIRE(rows.has_value());
        REQUIRE(rows->size() == 1);
        CHECK((*rows)[0].output == "B-150-fail");
    }
    SECTION("since/until window") {
        ResponseQuery q;
        q.since = 110;
        q.until = 180;
        auto rows = store.query_by_execution("exec-1", q);
        REQUIRE(rows.has_value());
        REQUIRE(rows->size() == 1);
        CHECK((*rows)[0].output == "B-150-fail");
    }
    SECTION("status filter") {
        ResponseQuery q;
        q.status = 2;
        auto rows = store.query_by_execution("exec-1", q);
        REQUIRE(rows.has_value());
        REQUIRE(rows->size() == 1);
        CHECK((*rows)[0].status == 2);
    }
    SECTION("scope of exec-2 doesn't bleed into exec-1") {
        auto rows = store.query_by_execution("exec-1");
        REQUIRE(rows.has_value());
        REQUIRE(rows->size() == 3);
        for (const auto& r : *rows)
            CHECK(r.output != "exec2-A-175");
    }
}

// ── #1634 management-group scope on aggregate (filter-BEFORE-aggregate) ───────

namespace {
StoredResponse mk_agg_resp(const std::string& instr, const std::string& agent, int status) {
    StoredResponse r;
    r.instruction_id = instr;
    r.agent_id = agent;
    r.status = status;
    r.output = "out";
    return r;
}
} // namespace

TEST_CASE("ResponseStore: distinct_agent_ids returns sorted distinct agents",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    store.store(mk_agg_resp("instr-1", "agent-c", 0));
    store.store(mk_agg_resp("instr-1", "agent-a", 0));
    store.store(mk_agg_resp("instr-1", "agent-a", 1)); // duplicate agent
    store.store(mk_agg_resp("instr-1", "agent-b", 0));
    store.store(mk_agg_resp("instr-2", "agent-z", 0)); // other instruction

    auto ids = store.distinct_agent_ids("instr-1");
    REQUIRE(ids.has_value());
    REQUIRE(ids->size() == 3);
    CHECK((*ids)[0] == "agent-a");
    CHECK((*ids)[1] == "agent-b");
    CHECK((*ids)[2] == "agent-c");
    // Genuinely-empty (instruction has no rows) is an ENGAGED empty vector, NOT
    // nullopt — nullopt is reserved for a store-read error so the caller can fail
    // closed on error without conflating it with "no agents" (#1634 UP-2).
    auto none = store.distinct_agent_ids("nope");
    REQUIRE(none.has_value());
    CHECK(none->empty());
}

TEST_CASE("ResponseStore: aggregate scope excludes out-of-scope rows from totals (#1634)",
          "[pg][response_store][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    // Two agents reported SUCCESS (status 0), one reported FAILURE (status 1).
    store.store(mk_agg_resp("instr-1", "agent-1", 0)); // in scope
    store.store(mk_agg_resp("instr-1", "agent-2", 0)); // OUT of scope
    store.store(mk_agg_resp("instr-1", "agent-3", 1)); // OUT of scope

    AggregationQuery aq;
    aq.group_by = "status";
    aq.op = AggregateOp::Count;

    auto count_for = [](const std::vector<AggregationResult>& rs, const std::string& status) {
        for (const auto& r : rs)
            if (r.group_value == status)
                return r.count;
        return std::int64_t{0};
    };

    SECTION("nullopt scope = legacy-open: all rows counted") {
        auto rs = store.aggregate("instr-1", aq, {}, std::nullopt);
        REQUIRE(rs.has_value());
        CHECK(count_for(*rs, "0") == 2);
        CHECK(count_for(*rs, "1") == 1);
    }

    SECTION("subset scope: only in-scope agents fold into the totals") {
        auto rs = store.aggregate("instr-1", aq, {}, AggregateScope{{"agent-1"}});
        REQUIRE(rs.has_value());
        // agent-1 is the only in-scope agent → status 0 count is 1, not 2.
        CHECK(count_for(*rs, "0") == 1);
        // agent-3's FAILURE belongs to an out-of-scope agent → excluded entirely.
        CHECK(count_for(*rs, "1") == 0);
    }

    SECTION("empty scope set = visible to no one: zero rows, never silently unfiltered") {
        auto rs = store.aggregate("instr-1", aq, {}, AggregateScope{std::vector<std::string>{}});
        REQUIRE(rs.has_value());
        CHECK(rs->empty());
    }
}

// #1634 (governance Gate 3 quality-engineer finding, adversarial-review blocker fix):
// query()/query_by_execution() must push the visible-agent set into SQL BEFORE
// LIMIT, not post-filter the raw result — ADR-0017 INV-3. The two prior scope
// tests on GET /api/v1/executions/{id}/visualization used only 2 total rows,
// well under the route's unrelated 10000-row cap, so they passed UNCHANGED
// against the pre-fix code that filtered AFTER a raw LIMIT-bounded query — a
// false-green regression test, confirmed by building the pre-fix commit and
// running them against it. This test discriminates the two implementations
// directly at the store seam: the out-of-scope row is NEWER (query orders
// `timestamp DESC`), so a raw `LIMIT 1` lands on it alone. A post-fetch filter
// then drops that one row and returns EMPTY, even though a visible row exists
// one position back. Pushing scope into the WHERE clause excludes the hidden
// row from the scan entirely, so `LIMIT 1` lands on the visible row instead.
TEST_CASE("ResponseStore: query pushes scope into SQL before LIMIT, not post-fetch (#1634)",
          "[pg][response_store][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());

    auto out_of_scope = mk_agg_resp("instr-cap", "agent-hidden", 0);
    out_of_scope.timestamp = 200; // newer -> sorts first in the raw scan
    auto in_scope = mk_agg_resp("instr-cap", "agent-visible", 0);
    in_scope.timestamp = 100; // older -> a raw LIMIT 1 would miss it entirely
    store.store(out_of_scope);
    store.store(in_scope);

    ResponseQuery q;
    q.limit = 1;
    auto rows = store.query("instr-cap", q, AggregateScope{{"agent-visible"}});
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].agent_id == "agent-visible");
}

TEST_CASE("ResponseStore: query_by_execution pushes scope into SQL before LIMIT (#1634)",
          "[pg][response_store][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());

    auto out_of_scope = mk_agg_resp("instr-x", "agent-hidden", 0);
    out_of_scope.execution_id = "exec-cap";
    out_of_scope.timestamp = 200;
    auto in_scope = mk_agg_resp("instr-x", "agent-visible", 0);
    in_scope.execution_id = "exec-cap";
    in_scope.timestamp = 100;
    store.store(out_of_scope);
    store.store(in_scope);

    ResponseQuery q;
    q.limit = 1;
    auto rows = store.query_by_execution("exec-cap", q, AggregateScope{{"agent-visible"}});
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].agent_id == "agent-visible");
}

TEST_CASE("ResponseStore: aggregate scope applies to SUM, not just COUNT (#1634)",
          "[pg][response_store][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    store.store(mk_agg_resp("instr-1", "agent-1", 2)); // in scope, status=2
    store.store(mk_agg_resp("instr-1", "agent-2", 3)); // OUT of scope, status=3

    AggregationQuery aq;
    aq.group_by = "agent_id";
    aq.op = AggregateOp::Sum;
    aq.op_column = "status";

    auto rs = store.aggregate("instr-1", aq, {}, AggregateScope{{"agent-1"}});
    REQUIRE(rs.has_value());
    REQUIRE(rs->size() == 1);
    CHECK((*rs)[0].group_value == "agent-1");
    CHECK((*rs)[0].aggregate_value == 2.0);
}

TEST_CASE("ResponseStore: aggregate scope AND filter.agent_id compose — out-of-scope explicit "
          "agent yields zero (#1634)",
          "[pg][response_store][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    store.store(mk_agg_resp("instr-1", "agent-1", 0)); // in scope
    store.store(mk_agg_resp("instr-1", "agent-2", 0)); // OUT of scope

    AggregationQuery aq;
    aq.group_by = "status";
    aq.op = AggregateOp::Count;

    ResponseQuery filter;
    filter.agent_id = "agent-2";
    auto rs = store.aggregate("instr-1", aq, filter, AggregateScope{{"agent-1"}});
    REQUIRE(rs.has_value());
    CHECK(rs->empty());

    ResponseQuery filter_ok;
    filter_ok.agent_id = "agent-1";
    auto rs_ok = store.aggregate("instr-1", aq, filter_ok, AggregateScope{{"agent-1"}});
    REQUIRE(rs_ok.has_value());
    int64_t total = 0;
    for (const auto& r : *rs_ok)
        total += r.count;
    CHECK(total == 1);
}

TEST_CASE("ResponseStore: query/aggregate scope applies past 10000 agents, no silent "
          "truncation (#1634 sre finding)",
          "[pg][response_store][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    store.store(mk_agg_resp("instr-bigscope", "agent-real", 0));

    // append_scope_clause previously bound one placeholder per agent behind
    // a 10,000-agent cap: query()/query_by_execution() silently dropped rows
    // past it, and aggregate() silently under-counted with no indicator at
    // all (I3 wrong-result-presented-as-correct). Put the one real agent
    // LAST, past where the old cap would have excluded it.
    std::vector<std::string> big_scope(10001, "no-such-agent");
    big_scope[10000] = "agent-real";

    ResponseQuery q;
    auto rows = store.query("instr-bigscope", q, AggregateScope{big_scope});
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].agent_id == "agent-real");

    AggregationQuery aq;
    aq.group_by = "agent_id";
    aq.op = AggregateOp::Count;
    auto rs = store.aggregate("instr-bigscope", aq, {}, AggregateScope{big_scope});
    REQUIRE(rs.has_value());
    REQUIRE(rs->size() == 1);
    CHECK((*rs)[0].group_value == "agent-real");
    CHECK((*rs)[0].count == 1);
}

TEST_CASE("ResponseStore: scope agent id containing a double-quote is escaped, not "
          "corrupted (#1634 sre follow-up)",
          "[pg][response_store][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    const std::string tricky_agent = R"(agent-"quoted",comma)";
    store.store(mk_agg_resp("instr-escape", tricky_agent, 0));
    store.store(mk_agg_resp("instr-escape", "agent-other", 0)); // OUT of scope

    ResponseQuery q;
    auto rows = store.query("instr-escape", q, AggregateScope{{tricky_agent}});
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].agent_id == tricky_agent);
}

TEST_CASE("ResponseStore: distinct_agent_ids / aggregate return nullopt on a closed store "
          "(#1634 UP-2)",
          "[response_store][scope]") {
    // Unroutable DSN → is_open() false. distinct_agent_ids MUST return nullopt
    // (store-read error), NOT an engaged-empty vector — so the aggregate caller
    // fails CLOSED instead of reading "couldn't read" as "no agents to drop" →
    // unrestricted (the UP-2 fail-open this contract closes).
    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    ResponseStore store(bad_pool);
    REQUIRE_FALSE(store.is_open());
    auto ids = store.distinct_agent_ids("instr-1");
    CHECK_FALSE(ids.has_value());
    AggregationQuery aq;
    aq.group_by = "status";
    aq.op = AggregateOp::Count;
    CHECK_FALSE(store.aggregate("instr-1", aq).has_value());
}

// ── Facets ─────────────────────────────────────────────────────────────────

TEST_CASE("ResponseStore: facet cascade — deleting the parent response removes its facets",
          "[pg][response_store][facets]") {
    // response_facets.response_id REFERENCES responses(id) ON DELETE CASCADE
    // (ADR-0039: replaces the SQLite cleanup thread's manual orphan sweep) —
    // pinned here directly against the schema, independent of store()'s
    // ability to populate facets from a real plugin schema.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());

    StoredResponse r;
    r.instruction_id = "cmd-facet";
    r.agent_id = "agent-1";
    r.status = 1;
    r.output = "ok";
    store.store(r);
    auto rows = store.get_by_instruction("cmd-facet");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    const int64_t response_id = (*rows)[0].id;

    exec_sql(db.dsn(), "INSERT INTO response_store.response_facets (response_id, "
                       "instruction_id, agent_id, col_idx, value, line_count) VALUES (" +
                           std::to_string(response_id) + ", 'cmd-facet', 'agent-1', 0, 'v', 1)");
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM response_store.response_facets WHERE "
                                 "response_id = " +
                                     std::to_string(response_id)) == "1");

    exec_sql(db.dsn(),
            "DELETE FROM response_store.responses WHERE id = " + std::to_string(response_id));
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM response_store.response_facets WHERE "
                                 "response_id = " +
                                     std::to_string(response_id)) == "0");
}

// ── Retention reap (`reap_expired()`, #2496 gc_sweep shape, ADR-0039) ────────

TEST_CASE("ResponseStore: retention_days=0 disables TTL", "[pg][response_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/0);
    anchor_guard(store);
    for (int i = 0; i < 5; ++i)
        store.store(mk_agg_resp("cmd-noreap", "agent-" + std::to_string(i), 1));
    store.reap_expired();
    CHECK(store.total_count() == 5);
    CHECK(store.responses_reaped_total() == 0);
}

TEST_CASE("ResponseStore: reap_expired deletes rows past ttl_expires_at, keeps fresh ones",
          "[pg][response_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/30);
    anchor_guard(store);

    for (int i = 0; i < 3; ++i)
        store.store(mk_agg_resp("fresh-" + std::to_string(i), "agent-a", 1));
    for (int i = 0; i < 3; ++i)
        store.store(mk_agg_resp("stale-" + std::to_string(i), "agent-a", 1));
    CHECK(store.total_count() == 6);

    exec_sql(db.dsn(), "UPDATE response_store.responses SET ttl_expires_at = 1 WHERE "
                       "instruction_id LIKE 'stale-%'");

    // expiring(3) < datable(6): not would_wipe — a clean pass drains immediately.
    store.reap_expired();
    CHECK(store.responses_reaped_total() == 3);
    CHECK(store.total_count() == 3);
    for (int i = 0; i < 3; ++i) {
        auto out = store.get_by_instruction("fresh-" + std::to_string(i));
        REQUIRE(out.has_value());
        CHECK(out->size() == 1);
    }
    for (int i = 0; i < 3; ++i) {
        auto out = store.get_by_instruction("stale-" + std::to_string(i));
        REQUIRE(out.has_value());
        CHECK(out->empty());
    }
}

// reap_expired would_wipe decline-once (mirrors GuaranteedStateStore/ResultSetStore's
// gc_sweep test of the same name): when EVERY datable row is expired, part 1's
// would_wipe classifier trips — the pass reports the anomaly, records it in
// gc_meta, and declines to delete anything. An identical next pass (same fact
// set) is a suppressed repeat: the report is skipped, but the (capped) drain
// proceeds.
TEST_CASE("ResponseStore: reap_expired declines once on an all-expired (would_wipe) table, "
          "then drains",
          "[pg][response_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());
    anchor_guard(store);

    for (int i = 0; i < 3; ++i)
        store.store(mk_agg_resp("wipe-" + std::to_string(i), "agent-a", 1));

    exec_sql(db.dsn(), "UPDATE response_store.responses SET ttl_expires_at = 1");

    auto gc_meta_anomaly_count = [&]() -> std::string {
        return query_scalar(db.dsn(), "SELECT COUNT(*) FROM response_store.gc_meta WHERE key = "
                                      "'last_anomaly_facts'");
    };

    // First pass: declines (would_wipe) — nothing reaped, the anomaly recorded.
    store.reap_expired();
    CHECK(store.responses_reaped_total() == 0);
    CHECK(store.total_count() == 3); // still present — the decline held
    CHECK(gc_meta_anomaly_count() == "1");

    // Second pass: suppressed repeat (same fact set) — drains, capped.
    store.reap_expired();
    CHECK(store.responses_reaped_total() == 3);
    CHECK(store.total_count() == 0);
    CHECK(gc_meta_anomaly_count() == "1"); // not cleared by a suppressed-repeat drain

    store.store(mk_agg_resp("fresh", "agent-a", 1));
    store.reap_expired(); // clean pass: nothing expired
    CHECK(store.responses_reaped_total() == 3); // unchanged — nothing new reaped
    CHECK(gc_meta_anomaly_count() == "0");      // consumed/cleared
}

// #2691 (transplanted from #2663/#2579): the missing-anchor falsifier.
// Deliberately NOT anchor_guard'd — a fresh store with no prior gc_meta
// reading. Partial expiry (0 < expiring < datable, via the second, further-out
// row) means neither `would_wipe` nor `big_step` trips, so before this fix
// the pass would classify clean (Anomaly::None) and delete immediately with
// no anomaly recorded — exactly the gap #2579 exists to close.
TEST_CASE("ResponseStore: reap_expired declines once on a missing anchor with partial expiry, "
          "then drains",
          "[pg][response_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    store.store(mk_agg_resp("noanchor-expired", "agent-a", 1));
    exec_sql(db.dsn(), "UPDATE response_store.responses SET ttl_expires_at = 1 WHERE "
                       "instruction_id = 'noanchor-expired'");
    // A second, further-out row so expiring(1) < datable(2) — a single-row
    // table would make expiring==datable trivially, which the would_wipe
    // detector already declines and would mask the missing-anchor defect
    // this test isolates.
    store.store(mk_agg_resp("noanchor-survivor", "agent-a", 1));

    const auto reaped = [&](const char* result) {
        return metrics.counter("yuzu_server_response_reap_passes_total", {{"result", result}})
            .value();
    };

    // First pass: no prior gc_meta reading exists on this fresh database —
    // declines (NoAnchor), zero deletes, and anchors the reading.
    store.reap_expired();
    CHECK(store.responses_reaped_total() == 0);
    CHECK(store.total_count() == 2); // both rows survive — the decline held
    CHECK(reaped("declined_no_anchor") == 1.0);
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM response_store.gc_meta WHERE key = "
                                 "'last_anomaly_facts'") == "1");

    // Second pass: now anchored (bootstrap_settled from pass 1) — drains the
    // genuinely expired row, the survivor stays.
    store.reap_expired();
    CHECK(store.responses_reaped_total() == 1);
    CHECK(store.total_count() == 1);
    CHECK(reaped("swept") == 1.0);
}

// #2691 fjarvis H1 (transplanted from #2663): a fast replica cannot sweep a
// row that is still live by Postgres's own clock. Verified the SAME bug
// class this store shares with GuaranteedStateStore/AuditStore before the
// #2663 clock-guard shape was transplanted here — mirrors that test exactly.
TEST_CASE("ResponseStore #2691: a fast replica cannot sweep a row that is still live by "
          "Postgres's own clock",
          "[pg][response_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    const int64_t real_now = pg_now(db.dsn());
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore replica_a(pool, /*retention_days=*/30);
    REQUIRE(replica_a.is_open());
    anchor_guard(replica_a);

    replica_a.store(mk_agg_resp("still-live", "agent-a", 1));
    // 30 minutes in the FUTURE by the real clock.
    exec_sql(db.dsn(), "UPDATE response_store.responses SET ttl_expires_at = " +
                           std::to_string(real_now + 1800) +
                           " WHERE instruction_id = 'still-live'");
    // A second row, further out, so this is a PARTIAL expiry (0 < expiring <
    // datable) under replica B's clock, not a would_wipe — a single-row table
    // makes expiring==datable trivially, which the existing Wipe detector
    // already declines and would mask the defect this test is isolating.
    replica_a.store(mk_agg_resp("far-live", "agent-a", 1));
    exec_sql(db.dsn(), "UPDATE response_store.responses SET ttl_expires_at = " +
                           std::to_string(real_now + 5000) +
                           " WHERE instruction_id = 'far-live'");

    // Replica B's process clock is an hour FAST — comfortably under
    // kReapBigStepSecs (1 day), so big_step never fires either.
    ResponseStore replica_b(pool, /*retention_days=*/30, [real_now] { return real_now + 3600; });
    REQUIRE(replica_b.is_open());
    yuzu::MetricsRegistry metrics;
    replica_b.set_metrics(&metrics);
    replica_b.reap_expired();

    // FIXED: replica B's own clock cannot move the verdict — "still-live" is
    // still live by PostgreSQL's own clock, so both rows survive and the
    // pass is a clean no-op, not a silent sweep.
    CHECK(replica_a.total_count() == 2);
    CHECK(metrics.counter("yuzu_server_response_reap_passes_total", {{"result", "swept"}})
              .value() == 0.0);

    // The shared ANCHOR itself must reflect PG's clock, not replica B's own
    // skewed reading — gc_meta is the transmission medium, not the fix; a
    // hypothetical partial revert of only the stamp line would still pass
    // the checks above while poisoning this row for the next replica's
    // prev-comparison. Tolerance is wide (60s) purely for test-execution
    // latency, nowhere near replica B's 3600s skew.
    const int64_t stamped = std::stoll(query_scalar(
        db.dsn(), "SELECT value FROM response_store.gc_meta WHERE key = 'last_pass_now'"));
    CHECK(std::abs(stamped - pg_now(db.dsn())) < 60);
}

TEST_CASE("ResponseStore: reap_expired is a no-op on a closed store",
          "[response_store][retention]") {
    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    ResponseStore bad(bad_pool);
    REQUIRE_FALSE(bad.is_open());
    bad.reap_expired();
    SUCCEED();
}

// gc_sweep cap: bulk-insert kReapCapPerPass(10000)+1 expired, DISTINCT-ttl
// responses directly via SQL — looping store() 10001 times would make this
// test the slow part of the whole suite. A `cap-live` (unexpired) row seeded
// alongside keeps datable strictly greater than expiring so part 1's
// would_wipe classifier does NOT trip.
TEST_CASE("ResponseStore: reap_expired caps a large expired batch at kReapCapPerPass",
          "[pg][response_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());
    anchor_guard(store);

    exec_sql(db.dsn(),
            "INSERT INTO response_store.responses (instruction_id, agent_id, timestamp, "
            "status, output, ttl_expires_at) SELECT 'cap-cmd-' || g, 'agent-a', 1700000000, 1, "
            "'', g FROM generate_series(1, 10001) AS g");
    store.store(mk_agg_resp("cap-live", "agent-a", 1)); // 30d-ahead ttl, avoids would_wipe

    store.reap_expired();
    CHECK(store.responses_reaped_total() == 10000); // capped exactly at kReapCapPerPass

    store.reap_expired();
    CHECK(store.responses_reaped_total() == 10001); // second pass drains the remainder

    CHECK(store.total_count() == 1); // only "cap-live" survives
}

// #2691 (Doomgoose finding #6): the parent-row delete is chunked
// (kReapDeleteChunkRows=500) so the ON DELETE CASCADE fan-out per statement
// is bounded — 1200 expired rows, each carrying its own facet, crosses that
// chunk boundary twice within a single pass (well under kReapCapPerPass).
// Every row AND every facet must still be gone, and the pass reports
// "swept" (not "capped") since the total is under the per-pass ceiling —
// pins that chunk-boundary crossing introduces no off-by-one or partial
// deletion.
TEST_CASE("ResponseStore: reap_expired deletes correctly across a chunk boundary",
          "[pg][response_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());
    anchor_guard(store);
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    constexpr int kRows = 1200; // > 2x kReapDeleteChunkRows (500)
    for (int i = 0; i < kRows; ++i) {
        StoredResponse r;
        r.instruction_id = "chunk-" + std::to_string(i);
        r.agent_id = "agent-a";
        r.status = 1;
        r.plugin = "vuln_scan";
        r.output = "high|cat-" + std::to_string(i) + "|title|detail";
        store.store(r);
    }
    exec_sql(db.dsn(), "UPDATE response_store.responses SET ttl_expires_at = 1 WHERE "
                       "instruction_id LIKE 'chunk-%'");
    store.store(mk_agg_resp("chunk-live", "agent-a", 1)); // avoids would_wipe

    store.reap_expired();
    CHECK(store.responses_reaped_total() == kRows);
    CHECK(store.total_count() == 1); // only "chunk-live" survives

    const auto reaped = [&](const char* result) {
        return metrics.counter("yuzu_server_response_reap_passes_total", {{"result", result}})
            .value();
    };
    CHECK(reaped("swept") == 1.0);
    CHECK(reaped("capped") == 0.0);

    // No orphaned facets — every reaped row's facet went with it via CASCADE.
    // mk_agg_resp (the surviving "chunk-live" row) sets no `plugin`, so it
    // produces zero facets of its own — the table should be fully empty.
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM response_store.response_facets") == "0");
}

// #2691 (Gate 5 chaos-injector): the reap's facet pre-drain runs in
// kReapFacetDeleteBatchRows(5000)-row batches BEFORE the parent-row delete,
// so a single chunk's cascade is never left to an unbounded implicit FK
// CASCADE. This seeds enough facets in ONE reap chunk (500 responses x 12
// facets = 6000, raw-SQL — bypassing plugin/output parsing so the count is
// exact) to force the facet drain loop to run more than one batch within a
// single chunk, and confirms it still fully drains both facets and parents.
TEST_CASE("ResponseStore: reap_expired facet pre-drain spans more than one batch within a chunk",
          "[pg][response_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());
    anchor_guard(store);
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    constexpr int kRows = 500; // == kReapDeleteChunkRows, one chunk
    constexpr int kFacetsPerRow = 12; // 500 * 12 = 6000 > kReapFacetDeleteBatchRows (5000)
    for (int i = 0; i < kRows; ++i) {
        StoredResponse r;
        r.instruction_id = "facetchunk-" + std::to_string(i);
        r.agent_id = "agent-a";
        r.status = 1;
        store.store(r);
    }
    exec_sql(db.dsn(), "UPDATE response_store.responses SET ttl_expires_at = 1 WHERE "
                       "instruction_id LIKE 'facetchunk-%'");
    // Raw-SQL facet seed, exact count, independent of plugin output parsing.
    exec_sql(db.dsn(),
             "INSERT INTO response_store.response_facets (response_id, instruction_id, "
             "agent_id, col_idx, value, line_count) "
             "SELECT r.id, r.instruction_id, r.agent_id, g, 'v' || g, 1 "
             "FROM response_store.responses r, generate_series(0, " +
                 std::to_string(kFacetsPerRow - 1) +
                 ") g "
                 "WHERE r.instruction_id LIKE 'facetchunk-%'");
    REQUIRE(query_scalar(db.dsn(), "SELECT COUNT(*) FROM response_store.response_facets") ==
            std::to_string(kRows * kFacetsPerRow));
    store.store(mk_agg_resp("facetchunk-live", "agent-a", 1)); // avoids would_wipe

    store.reap_expired();
    CHECK(store.responses_reaped_total() == kRows);
    CHECK(store.total_count() == 1); // only "facetchunk-live" survives

    // #2691 (Gate 8 architect): the assertions above pass identically
    // whether the explicit pre-drain loop ran OR was a silent no-op that let
    // the parent DELETE's ON DELETE CASCADE clean up the (small, 6000-row)
    // facet set instead — a false-green at this scale, since CASCADE alone
    // is more than capable of 6000 rows. This assertion is what actually
    // discriminates: facets_predrained_total() only increments inside the
    // explicit drain loop itself, so it stays 0 if that loop is broken or
    // removed, even though the CASCADE fallback would still leave the table
    // empty and every assertion above still green.
    CHECK(store.facets_predrained_total() == kRows * kFacetsPerRow);

    const auto reaped = [&](const char* result) {
        return metrics.counter("yuzu_server_response_reap_passes_total", {{"result", result}})
            .value();
    };
    CHECK(reaped("swept") == 1.0);
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM response_store.response_facets") == "0");
}

// gc_sweep advisory-lock skip: a sibling replica already sweeping holds the
// fleet-wide try-advisory-xact-lock, so this pass must skip quietly and never
// even reach the gc_meta read/stamp, never mind the delete.
TEST_CASE("ResponseStore: reap_expired skips quietly when a sibling holds the advisory lock",
          "[pg][response_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());

    store.store(mk_agg_resp("locked-cmd", "agent-a", 1));
    exec_sql(db.dsn(), "UPDATE response_store.responses SET ttl_expires_at = 1 WHERE "
                       "instruction_id = 'locked-cmd'");
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM response_store.gc_meta WHERE key = "
                                 "'last_pass_now'") == "0");

    PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    {
        PgResult begin{PQexec(locker.get(), "BEGIN")};
        REQUIRE(begin.status() == PGRES_COMMAND_OK);
        PgResult lock{PQexec(
            locker.get(), "SELECT pg_advisory_xact_lock(hashtextextended('response_store:reap', "
                          "0))")};
        REQUIRE(lock.status() == PGRES_TUPLES_OK);
    }

    store.reap_expired();
    CHECK(store.responses_reaped_total() == 0);
    CHECK(store.total_count() == 1); // nothing deleted — the sibling held the lock
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM response_store.gc_meta WHERE key = "
                                 "'last_pass_now'") == "0"); // never reached the stamp

    PgResult rollback{PQexec(locker.get(), "ROLLBACK")};
    REQUIRE(rollback.status() == PGRES_COMMAND_OK);
}

// gc_sweep clock anomaly / prev_unusable: reap_expired() stamps a FRESH,
// honest last_pass_now on EVERY pass (including a declining one) BEFORE it
// evaluates the anomaly — so a poisoned reading self-heals on the very next
// pass.
TEST_CASE("ResponseStore: reap_expired declines once on a clock reading ahead of now",
          "[pg][response_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());
    anchor_guard(store);

    store.store(mk_agg_resp("clock-a", "agent-a", 1));
    store.store(mk_agg_resp("clock-b", "agent-a", 1));
    store.store(mk_agg_resp("clock-live", "agent-a", 1)); // avoids would_wipe
    exec_sql(db.dsn(), "UPDATE response_store.responses SET ttl_expires_at = 1 WHERE "
                       "instruction_id IN ('clock-a', 'clock-b')");
    exec_sql(db.dsn(),
            "INSERT INTO response_store.gc_meta (key, value) VALUES ('last_pass_now', "
            "(EXTRACT(EPOCH FROM clock_timestamp())::bigint + 999999)::text) ON CONFLICT (key) "
            "DO UPDATE SET value = EXCLUDED.value");

    store.reap_expired();
    CHECK(store.responses_reaped_total() == 0); // declined: prev_unusable (BadState)
    CHECK(store.total_count() == 3);
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM response_store.gc_meta WHERE key = "
                                 "'last_anomaly_facts'") == "1");

    // Self-healed: the stamp reap_expired() just wrote is an honest reading.
    store.reap_expired();
    CHECK(store.responses_reaped_total() == 2);
    CHECK(store.total_count() == 1);
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM response_store.gc_meta WHERE key = "
                                 "'last_anomaly_facts'") == "0"); // consumed/cleared
}

// The implausibly-ahead bound must be DERIVED from retention_days (2× horizon,
// floored), NOT a fixed constant (consistency-auditor Gate 4). With a fixed
// ~120d bound, an operator who raised response_retention_days above ~120 would
// push every LIVE row's honest ttl_expires_at past the bound → excluded from
// `datable` → would_wipe trips → perpetual decline → the table never reaps. At
// retention=200d a fresh row (ttl ≈ now+200d) must stay datable and a genuinely
// expired row must still drain on the first pass.
TEST_CASE("ResponseStore: reap bound scales with a >120d retention (no false would_wipe)",
          "[pg][response_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/200); // > the old fixed ~120d bound
    REQUIRE(store.is_open());
    anchor_guard(store);

    store.store(mk_agg_resp("ret200-live", "agent-a", 1)); // ttl ≈ now + 200d
    store.store(mk_agg_resp("ret200-old", "agent-a", 1));
    exec_sql(db.dsn(), "UPDATE response_store.responses SET ttl_expires_at = 1 WHERE "
                       "instruction_id = 'ret200-old'");

    store.reap_expired();
    // The live row is datable (bound is 2×200d), so would_wipe does NOT trip and
    // the expired row drains — with a fixed 120d bound the live row would fall
    // out of `datable`, trip would_wipe, and this pass would decline (0 reaped).
    CHECK(store.responses_reaped_total() == 1);
    CHECK(store.total_count() == 1); // only the live row survives
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM response_store.gc_meta WHERE key = "
                                 "'last_anomaly_facts'") == "0"); // no anomaly recorded
}

// A capped pass (per-pass cap hit, backlog remains) must record
// result="capped", not "swept", so on-call can distinguish a healthy drain from
// one being outrun (Gate 4 R2 / sre). A fully-draining pass records "swept".
TEST_CASE("ResponseStore: reap records result=capped when the per-pass cap is hit",
          "[pg][response_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);
    anchor_guard(store);

    exec_sql(db.dsn(),
            "INSERT INTO response_store.responses (instruction_id, agent_id, timestamp, "
            "status, output, ttl_expires_at) SELECT 'capm-' || g, 'agent-a', 1700000000, 1, "
            "'', g FROM generate_series(1, 10001) AS g");
    store.store(mk_agg_resp("capm-live", "agent-a", 1)); // avoids would_wipe

    const auto reaped = [&](const char* result) {
        return metrics.counter("yuzu_server_response_reap_passes_total", {{"result", result}})
            .value();
    };

    store.reap_expired(); // deletes 10000, backlog of 1 remains → capped
    CHECK(reaped("capped") == 1.0);
    CHECK(reaped("swept") == 0.0);

    store.reap_expired(); // drains the last row → swept
    CHECK(reaped("swept") == 1.0);
    CHECK(reaped("capped") == 1.0); // unchanged
}

// Exact boundary: a pass that deletes EXACTLY the cap but leaves NO backlog is
// "swept", not "capped" — hitting the cap doesn't prove a backlog, and a false
// "capped" would page on-call for a drain that actually completed (chaos Gate 5,
// the post-delete backlog probe).
TEST_CASE("ResponseStore: reap that hits the cap with an empty backlog records swept",
          "[pg][response_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);
    anchor_guard(store);

    // EXACTLY kReapCapPerPass expired rows, nothing else expired.
    exec_sql(db.dsn(),
            "INSERT INTO response_store.responses (instruction_id, agent_id, timestamp, "
            "status, output, ttl_expires_at) SELECT 'exact-' || g, 'agent-a', 1700000000, 1, "
            "'', g FROM generate_series(1, 10000) AS g");
    store.store(mk_agg_resp("exact-live", "agent-a", 1)); // avoids would_wipe

    const auto reaped = [&](const char* result) {
        return metrics.counter("yuzu_server_response_reap_passes_total", {{"result", result}})
            .value();
    };

    store.reap_expired(); // deletes exactly 10000, 0 expired remain → swept
    CHECK(store.responses_reaped_total() == 10000);
    CHECK(reaped("swept") == 1.0);
    CHECK(reaped("capped") == 0.0); // NOT a false backlog page
    CHECK(store.total_count() == 1); // only the live row
}

// R3: an embedded NUL is valid ASCII to sanitize_utf8_strict, but PG TEXT can't
// store it and libpq's text-bind C-string-truncates at the first NUL — silently
// dropping everything after it. sanitize_pg_text must U+FFFD-defang the NUL so
// the WHOLE value survives (the #1593 must-surface guarantee) and facets stay
// byte-consistent with the stored output.
TEST_CASE("ResponseStore: embedded NUL is defanged, output past it is not truncated",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    StoredResponse resp;
    resp.instruction_id = "cmd-nul";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.output = std::string("before") + '\0' + "after";      // embedded NUL
    resp.error_detail = std::string("e") + '\0' + "x";
    store.store(resp);

    auto results = store.get_by_instruction("cmd-nul");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    // "after" survived — NOT truncated at the NUL — with the NUL as U+FFFD.
    CHECK((*results)[0].output == "before\xEF\xBF\xBD" "after");
    CHECK((*results)[0].error_detail == "e\xEF\xBF\xBD" "x");
    CHECK((*results)[0].output.find('\0') == std::string::npos);
}

// #2691 (Doomgoose finding #8): sanitize_pg_text was rewritten from an
// in-place find+replace loop to a single reserve-and-append pass — pin the
// boundary cases a rewritten loop is most likely to get wrong: a leading
// NUL, a trailing NUL, and adjacent NULs with nothing between them.
TEST_CASE("ResponseStore: sanitize_pg_text handles leading/trailing/adjacent NULs",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    StoredResponse resp;
    resp.instruction_id = "cmd-nul-edges";
    resp.agent_id = "agent-1";
    resp.status = 1;
    // leading NUL, then adjacent NULs, then a trailing NUL.
    resp.output = std::string("\0mid\0\0end\0", 10);
    store.store(resp);

    auto results = store.get_by_instruction("cmd-nul-edges");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].output ==
          "\xEF\xBF\xBD" "mid" "\xEF\xBF\xBD" "\xEF\xBF\xBD" "end" "\xEF\xBF\xBD");
    CHECK((*results)[0].output.find('\0') == std::string::npos);
}

// #2691 (Doomgoose finding #4): output/error_detail past the per-response
// ingest cap (matches the agent's own per-dispatch cap) are truncated with a
// marker, not stored raw — this store shares the PG pool the auth/RBAC
// substrate leases from, so an unbounded ingest volume must not be able to
// pressure it.
TEST_CASE("ResponseStore: output past the ingest cap is truncated with a marker",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    constexpr std::size_t kOverCap = 2ull * 1024 * 1024 + 100; // kMaxIngestBytes + 100
    StoredResponse resp;
    resp.instruction_id = "cmd-overcap";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.output = std::string(kOverCap, 'x');
    store.store(resp);

    auto results = store.get_by_instruction("cmd-overcap");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].output.size() < kOverCap); // genuinely truncated
    CHECK((*results)[0].output.find("truncated by server ingest cap") != std::string::npos);

    // Well under the cap: stored byte-for-byte, no truncation.
    StoredResponse small;
    small.instruction_id = "cmd-undercap";
    small.agent_id = "agent-1";
    small.status = 1;
    small.output = std::string(1000, 'y');
    store.store(small);
    auto small_results = store.get_by_instruction("cmd-undercap");
    REQUIRE(small_results.has_value());
    REQUIRE(small_results->size() == 1);
    CHECK((*small_results)[0].output.size() == 1000);
    CHECK((*small_results)[0].output.find("truncated") == std::string::npos);
}

// #2691 (Doomgoose finding #4): facet cardinality is bounded independently
// of output byte size — a highly-repetitive tabular output can carry many
// distinct values without approaching the byte cap.
TEST_CASE("ResponseStore: facet cardinality is capped independently of output size",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    // vuln_scan schema: severity|category|title|detail. 6001 distinct
    // category values in col_idx 1 — well under kMaxIngestBytes (a few
    // hundred KB), comfortably over kMaxFacetsPerResponse (5000).
    std::string output;
    constexpr int kDistinctValues = 6001;
    for (int i = 0; i < kDistinctValues; ++i)
        output += "high|category-" + std::to_string(i) + "|title|detail\n";

    StoredResponse resp;
    resp.instruction_id = "cmd-facetcap";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.plugin = "vuln_scan";
    resp.output = output;
    store.store(resp);

    auto results = store.get_by_instruction("cmd-facetcap");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    // The full (untruncated) output still persists on the response row —
    // only the FACET projection is capped, matching the cap's stated scope.
    CHECK((*results)[0].output.size() == output.size());

    const auto facet_count = query_scalar(
        db.dsn(), "SELECT COUNT(*) FROM response_store.response_facets WHERE instruction_id = "
                  "'cmd-facetcap'");
    CHECK(std::stoll(facet_count) == 5000); // kMaxFacetsPerResponse, not 6001
}

// R1: a wide tabular output (>64 distinct facet values) must still persist ALL
// its facets. The batched single-savepoint INSERT replaced the per-facet
// savepoint loop (which suboverflowed the ingest txn's subxids on the shared
// pool); this pins that the batch itself is correct — every distinct value lands
// and the response row is present.
TEST_CASE("ResponseStore: wide facet set (>64 distinct values) all persist via batch insert",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    // vuln_scan schema: severity|category|title|detail. 200 distinct category
    // values in col_idx 1 — well past the 64-subxid suboverflow threshold.
    std::string out;
    for (int i = 0; i < 200; ++i)
        out += "high|category-" + std::to_string(i) + "|title|detail\n";
    StoredResponse resp;
    resp.instruction_id = "cmd-wide";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.plugin = "vuln_scan";
    resp.output = out;
    store.store(resp);

    auto facets = store.facet_values("cmd-wide", /*col_idx=*/1);
    REQUIRE(facets.has_value());
    CHECK(facets->size() == 200); // every distinct category landed
    // The response row itself is present.
    auto results = store.get_by_instruction("cmd-wide");
    REQUIRE(results.has_value());
    CHECK(results->size() == 1);
}

// #2691 (Doomgoose finding #7): facet_agent_count/facet_line_count were a
// plain int64_t degrading silently to 0 on a store/pool/query failure — the
// SAME observable value as a genuine zero-match answer. The group-creation
// dashboard flow this feeds must be able to tell "0 agents match" from
// "the count could not be determined".
TEST_CASE("ResponseStore: facet_agent_count and facet_line_count distinguish degrade from zero",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    StoredResponse resp;
    resp.instruction_id = "cmd-facetcount";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.plugin = "vuln_scan";
    resp.output = "high|cat-a|title|detail\nhigh|cat-a|title2|detail2\n";
    store.store(resp);

    FacetFilter match{/*col_idx=*/1, "cat-a"};
    auto count = store.facet_agent_count("cmd-facetcount", {match});
    REQUIRE(count.has_value());
    CHECK(*count == 1); // one distinct agent

    auto lines = store.facet_line_count("cmd-facetcount", {match});
    REQUIRE(lines.has_value());
    CHECK(*lines == 2); // two matching lines

    // A genuinely non-matching filter is a real 0, not a degrade.
    FacetFilter no_match{/*col_idx=*/1, "cat-nonexistent"};
    auto zero_count = store.facet_agent_count("cmd-facetcount", {no_match});
    REQUIRE(zero_count.has_value());
    CHECK(*zero_count == 0);

    // Empty filters: genuine 0 (no scoped count to report), not a degrade —
    // matches BOTH functions' documented "no filter -> no scoped count" rule.
    auto empty_filter_count = store.facet_agent_count("cmd-facetcount", {});
    REQUIRE(empty_filter_count.has_value());
    CHECK(*empty_filter_count == 0);

    // A genuinely closed/degraded store returns nullopt, not 0 — the actual
    // defect this finding fixes.
    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    ResponseStore bad_store(bad_pool);
    REQUIRE_FALSE(bad_store.is_open());
    CHECK_FALSE(bad_store.facet_agent_count("cmd-facetcount", {match}).has_value());
    CHECK_FALSE(bad_store.facet_line_count("cmd-facetcount", {match}).has_value());
}

// ── CC-07 typed plugin result status (PR1.1 finding F11) ───────────────────
//
// The typed status is written at response_store.cpp's insert bind and again by
// finalize_terminal_status, but nothing asserted it survives the round trip:
// every existing test leaves it at its 0/UNDECLARED default, so binding a
// literal 0 at either site would have kept the suite green while silently
// discarding every plugin-reported status. These pin both write paths against
// the read path (`COALESCE(plugin_result_status, 0)` in query/get_by_instruction).
//
// Values mirror YuzuResultStatus in sdk/include/yuzu/plugin.h — 3 =
// PERMISSION_DENIED, 4 = CONSTRAINED — deliberately not 1, so a bind that
// accidentally reused `status` (also an int, also on this row) is caught too.

TEST_CASE("ResponseStore: plugin_result_status round-trips through store/read (CC-07)",
          "[pg][response_store][cc07]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());

    StoredResponse resp;
    resp.instruction_id = "cmd-cc07";
    resp.agent_id = "agent-1";
    resp.status = 1; // SUCCESS — distinct from the typed status below
    resp.plugin_result_status = 3;
    resp.output = "firewall|blocked";
    store.store(resp);

    auto results = store.get_by_instruction("cmd-cc07");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].status == 1);
    CHECK((*results)[0].plugin_result_status == 3);

    // A response whose plugin never reported one stays honestly undeclared
    // rather than inheriting the neighbouring row's value.
    StoredResponse silent;
    silent.instruction_id = "cmd-cc07";
    silent.agent_id = "agent-2";
    silent.status = 1;
    silent.output = "no typed status";
    store.store(silent);

    auto both = store.get_by_instruction("cmd-cc07");
    REQUIRE(both.has_value());
    REQUIRE(both->size() == 2);
    int declared = 0, undeclared = 0;
    for (const auto& r : *both) {
        if (r.agent_id == "agent-1") {
            CHECK(r.plugin_result_status == 3);
            ++declared;
        } else {
            CHECK(r.plugin_result_status == 0);
            ++undeclared;
        }
    }
    CHECK(declared == 1);
    CHECK(undeclared == 1);
}

TEST_CASE("ResponseStore: finalize_terminal_status writes the typed status onto the RUNNING row "
          "(CC-07)",
          "[pg][response_store][cc07]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());

    // The normal shape for a command that streamed output: a RUNNING row
    // (status 0, no typed status yet) followed by an empty-output terminal
    // frame that carries the real one.
    StoredResponse running;
    running.instruction_id = "cmd-final";
    running.agent_id = "agent-1";
    running.status = 0; // RUNNING
    running.execution_id = "exec-1";
    running.output = "streamed line";
    store.store(running);

    auto before = store.get_by_instruction("cmd-final");
    REQUIRE(before.has_value());
    REQUIRE(before->size() == 1);
    REQUIRE((*before)[0].plugin_result_status == 0);

    auto res = store.finalize_terminal_status("cmd-final", "agent-1", /*terminal_status=*/2,
                                              "denied by policy", "exec-1",
                                              /*plugin_result_status=*/4);
    REQUIRE(res == ResponseStore::FinalizeResult::Updated);

    auto after = store.get_by_instruction("cmd-final");
    REQUIRE(after.has_value());
    REQUIRE(after->size() == 1);
    CHECK((*after)[0].status == 2);
    CHECK((*after)[0].error_detail == "denied by policy");
    CHECK((*after)[0].plugin_result_status == 4);
}

// ── Scoped facet queries: agent_scope on facet_values/facet_agent_count ────
//
// ADR-0017 INV-3 / #1712: the dashboard's visible-agent set must confine the
// facet aggregate IN SQL, never as a C++ post-filter over an unscoped
// result. #2691: an engaged-but-empty scope is success-empty, distinct from
// a genuine store degrade.

TEST_CASE("ResponseStore: scoped facet_values/facet_agent_count return only the scoped "
          "agent's values and counts (partial scope)",
          "[pg][response_store][facet_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());

    // agent-A and agent-B share the "net" category with DIFFERENT line
    // counts — a mutant that drops the SQL agent_id filter but still groups
    // by value would return the right value with the wrong SUM (2 vs
    // 2+3=5). Each agent also has a category the other doesn't ("disk" /
    // "mem"), so a mutant that ignores scope entirely also fails on the
    // returned value set, not just the counts.
    StoredResponse a;
    a.instruction_id = "cmd-facet-scope-partial";
    a.agent_id = "agent-A";
    a.status = 1;
    a.plugin = "vuln_scan";
    a.output = "high|net|t1|d1\nhigh|net|t2|d2\nhigh|disk|t3|d3";
    store.store(a);

    StoredResponse b;
    b.instruction_id = "cmd-facet-scope-partial";
    b.agent_id = "agent-B";
    b.status = 1;
    b.plugin = "vuln_scan";
    b.output = "high|net|t4|d4\nhigh|net|t5|d5\nhigh|net|t6|d6\nhigh|mem|t7|d7";
    store.store(b);

    std::vector<std::string> scope_a{"agent-A"};
    auto values = store.facet_values("cmd-facet-scope-partial", /*col_idx=*/1, scope_a);
    REQUIRE(values.has_value());
    REQUIRE(values->size() == 2); // "mem" (agent-B only) must not appear
    // ORDER BY SUM(line_count) DESC: "net" (2) before "disk" (1).
    CHECK((*values)[0].value == "net");
    CHECK((*values)[0].line_count == 2); // agent-A's 2 lines only, not 2+3=5
    CHECK((*values)[1].value == "disk");
    CHECK((*values)[1].line_count == 1);

    FacetFilter net_filter{/*col_idx=*/1, "net"};
    auto count = store.facet_agent_count("cmd-facet-scope-partial", {net_filter}, scope_a);
    REQUIRE(count.has_value());
    CHECK(*count == 1); // agent-B also matches "net" but is out of scope
}

TEST_CASE("ResponseStore: an engaged-empty agent_scope short-circuits to success-empty "
          "before any query, distinct from a genuine degrade (#2691)",
          "[pg][response_store][facet_scope]") {
    // Unroutable DSN, same idiom as the "bad-path constructor" case above:
    // the store never opens, so reaching the pool/query would always
    // produce the same nullopt-degrade. An engaged-but-empty scope must
    // short-circuit BEFORE that check — proving it precedes any query, not
    // just that it happens to also return an empty-looking result.
    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    ResponseStore store(bad_pool);
    REQUIRE_FALSE(store.is_open());

    // facet_values: unscoped (nullopt, the default) still degrades...
    CHECK_FALSE(store.facet_values("cmd-x", /*col_idx=*/0).has_value());
    // ...but an engaged empty scope is success-empty, not degrade.
    auto scoped_values = store.facet_values("cmd-x", /*col_idx=*/0, std::vector<std::string>{});
    REQUIRE(scoped_values.has_value());
    CHECK(scoped_values->empty());

    // facet_agent_count: a non-empty filters vector defeats the unrelated
    // "no filter -> 0" short-circuit, isolating the scope short-circuit.
    FacetFilter any_filter{/*col_idx=*/0, "anything"};
    CHECK_FALSE(store.facet_agent_count("cmd-x", {any_filter}).has_value());
    auto scoped_count =
        store.facet_agent_count("cmd-x", {any_filter}, std::vector<std::string>{});
    REQUIRE(scoped_count.has_value());
    CHECK(*scoped_count == 0);
}

TEST_CASE("ResponseStore: std::nullopt agent_scope on facet_values/facet_agent_count matches "
          "the legacy unscoped call",
          "[pg][response_store][facet_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());

    StoredResponse a;
    a.instruction_id = "cmd-facet-scope-nullopt";
    a.agent_id = "agent-A";
    a.status = 1;
    a.plugin = "vuln_scan";
    a.output = "high|net|t1|d1\nhigh|disk|t2|d2";
    store.store(a);

    StoredResponse b;
    b.instruction_id = "cmd-facet-scope-nullopt";
    b.agent_id = "agent-B";
    b.status = 1;
    b.plugin = "vuln_scan";
    b.output = "high|net|t3|d3\nhigh|mem|t4|d4";
    store.store(b);

    auto legacy_values = store.facet_values("cmd-facet-scope-nullopt", /*col_idx=*/1);
    auto explicit_nullopt_values =
        store.facet_values("cmd-facet-scope-nullopt", /*col_idx=*/1, std::nullopt);
    REQUIRE(legacy_values.has_value());
    REQUIRE(explicit_nullopt_values.has_value());
    REQUIRE(legacy_values->size() == explicit_nullopt_values->size());
    for (std::size_t i = 0; i < legacy_values->size(); ++i) {
        CHECK((*legacy_values)[i].value == (*explicit_nullopt_values)[i].value);
        CHECK((*legacy_values)[i].line_count == (*explicit_nullopt_values)[i].line_count);
    }
    // Both agents' values present, "net" summed across both (1+1=2).
    REQUIRE(legacy_values->size() == 3);
    bool found_net = false;
    for (const auto& fv : *legacy_values) {
        if (fv.value == "net") {
            CHECK(fv.line_count == 2);
            found_net = true;
        }
    }
    CHECK(found_net);

    FacetFilter net_filter{/*col_idx=*/1, "net"};
    auto legacy_count = store.facet_agent_count("cmd-facet-scope-nullopt", {net_filter});
    auto explicit_nullopt_count =
        store.facet_agent_count("cmd-facet-scope-nullopt", {net_filter}, std::nullopt);
    REQUIRE(legacy_count.has_value());
    REQUIRE(explicit_nullopt_count.has_value());
    CHECK(*legacy_count == *explicit_nullopt_count);
    CHECK(*legacy_count == 2); // both agents match "net"
}

TEST_CASE("ResponseStore: scoped facet_values/facet_agent_count apply the WHOLE scope, no "
          "10000-element truncation",
          "[pg][response_store][facet_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());

    StoredResponse resp;
    resp.instruction_id = "cmd-facet-scope-cap";
    resp.agent_id = "agent-cap";
    resp.status = 1;
    resp.plugin = "vuln_scan";
    resp.output = "high|net|t1|d1\nhigh|net|t2|d2";
    store.store(resp);

    // append_scope_clause (response_store.cpp) previously bound one
    // placeholder per agent behind a 10,000-agent cap, silently dropping
    // rows/under-counting aggregates past it (#1634 sre finding). Now a
    // single ANY($n::text[]) bind applies the WHOLE scope regardless of
    // size — put the one agent that actually has facet rows LAST, past
    // where the old cap would have cut it off.
    std::vector<std::string> big_scope(10001, "no-such-agent");
    big_scope[10000] = "agent-cap";

    auto values = store.facet_values("cmd-facet-scope-cap", /*col_idx=*/1, big_scope);
    REQUIRE(values.has_value());
    REQUIRE(values->size() == 1);
    CHECK((*values)[0].value == "net");
    CHECK((*values)[0].line_count == 2);

    FacetFilter net_filter{/*col_idx=*/1, "net"};
    auto count = store.facet_agent_count("cmd-facet-scope-cap", {net_filter}, big_scope);
    REQUIRE(count.has_value());
    CHECK(*count == 1);
}
