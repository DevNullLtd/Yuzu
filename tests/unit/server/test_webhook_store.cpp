/**
 * test_webhook_store.cpp -- Unit tests for the Postgres-backed WebhookStore
 * (ADR-0057).
 *
 * Non-PG tests: pure-function coverage (hmac_sha256 against RFC 4231
 * vectors) that needs no database.
 *
 * [pg] tests: CRUD, cascade delete, and the ADR-0010 secrets seam
 * (has_secret invariant, tamper -> skip-not-unsigned-fire, no-secret ->
 * unsigned fire preserved).
 *
 * No legacy-SQLite backfill test coverage: `WebhookStore::migrate_from_sqlite()`/
 * `migrate_from_sqlite_impl()` themselves were retired
 * (chore/retire-migrate-from-sqlite-batch-a, #3623, ADR-0057 Update, 2026-09-03) -- no
 * production fleet has ever run a pre-Postgres build, so the mandatory backfill never had
 * real legacy data to protect. The two WAL/SHM sidecar 0600-enforcement regression tests
 * that used to live here (reinstated 2026-08-25 for real PR #3563 findings) moved to
 * `test_legacy_sqlite_probe.cpp` against the new `harden_legacy_file_0600()` helper those
 * findings' hardening logic was generalized into -- move-aside no longer applies (nothing
 * is migrated, so a `.migrated-<epoch>` rename would misdescribe what happened), so the
 * move-aside-failure regression test (the second of the original pair) has no remaining
 * subject and was not carried forward. `server.cpp` now calls `harden_legacy_file_0600()`
 * then `warn_if_legacy_rows()` at boot instead.
 */

#include "webhook_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "test_webhook_store_pg_helper.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;
using yuzu::test::WebhookStorePg;

// ── hmac_sha256 — pure function, no database needed ────────────────────────
// RFC 4231 test case 2: key="Jefe", data="what do ya want for nothing?"

TEST_CASE("WebhookStore::hmac_sha256 matches RFC 4231 test vector 2", "[webhook_store]") {
    const auto sig = WebhookStore::hmac_sha256("Jefe", "what do ya want for nothing?");
    CHECK(sig == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

TEST_CASE("WebhookStore::hmac_sha256 is deterministic and key-sensitive", "[webhook_store]") {
    const auto a = WebhookStore::hmac_sha256("secret-a", "payload");
    const auto b = WebhookStore::hmac_sha256("secret-a", "payload");
    const auto c = WebhookStore::hmac_sha256("secret-b", "payload");
    CHECK(a == b);
    CHECK(a != c);
    CHECK(a.size() == 64); // 32 bytes, hex-encoded
}

// ── [pg] fixture ─────────────────────────────────────────────────────────
//
// WebhookStorePg (skip-if-no-PG, self-contained ephemeral DB + FileKeyProvider
// + SecretCodec + WebhookStore) lives in test_webhook_store_pg_helper.hpp —
// shared with test_agent_service_impl.cpp's EventSinkScope so both files
// derive the FileKeyProvider/SecretCodec/WebhookStore wiring exactly once
// (docs/postgres-store-playbook.md's test-file-drift note).

namespace {

/// Polls get_deliveries() until at least `min_count` rows are present or
/// `timeout` elapses — deliveries land asynchronously on the worker pool.
std::vector<WebhookDelivery> wait_for_deliveries(WebhookStore& store, std::int64_t webhook_id,
                                                 std::size_t min_count,
                                                 std::chrono::milliseconds timeout =
                                                     std::chrono::seconds(5)) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        auto d = store.get_deliveries(webhook_id, 50);
        if (d.size() >= min_count || std::chrono::steady_clock::now() >= deadline)
            return d;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

} // namespace

// ── CRUD ─────────────────────────────────────────────────────────────────

TEST_CASE("WebhookStore[pg]: create and list webhook", "[webhook_store][pg]") {
    WebhookStorePg store;

    auto id = store->create_webhook("https://example.com/hook", "agent.registered", "secret123");
    REQUIRE(id.has_value());
    CHECK(*id > 0);

    auto hooks = store->list();
    REQUIRE(hooks.has_value());
    REQUIRE(hooks->size() == 1);
    CHECK((*hooks)[0].url == "https://example.com/hook");
    CHECK((*hooks)[0].event_types == "agent.registered");
    CHECK((*hooks)[0].has_secret == true); // list() never exposes the secret itself
    CHECK((*hooks)[0].enabled == true);
    CHECK((*hooks)[0].id == *id);
}

TEST_CASE("WebhookStore[pg]: migration lands at v2 and drops sqlite_backfill_source (#3623)",
          "[webhook_store][pg][migration]") {
    // Deliberately NOT WebhookStorePg / webhook_store_pg_template -- both are backed by the
    // process-wide PgTestTemplate (built once, cloned per fixture), so in a full suite run this
    // store may already be at v2 by the time this test's clone is taken, making the version
    // check a no-op read of someone else's already-completed migration rather than a genuine
    // from-scratch v1->v2 run. YUZU_REQUIRE_PG_MIGRATION_DB is a private, unshared database, so
    // the WebhookStore construction below always drives a real migration.
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    yuzu::test::TempDir keys;
    yuzu::server::FileKeyProvider provider(keys.path);
    yuzu::server::pg::SecretCodec codec(provider);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    WebhookStore store{pool, codec};
    REQUIRE(store.is_open());

    yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    REQUIRE(codec.init(conn.get()).has_value());

    yuzu::server::pg::PgResult ver{PQexec(
        conn.get(), "SELECT version FROM public.schema_meta WHERE store = 'webhook_store'")};
    REQUIRE(ver.ok());
    REQUIRE(PQntuples(ver.get()) == 1);
    CHECK(std::string(PQgetvalue(ver.get(), 0, 0)) == "2");
    yuzu::server::pg::PgResult tbl{
        PQexec(conn.get(), "SELECT COUNT(*) FROM information_schema.tables WHERE "
                           "table_schema = 'webhook_store' AND table_name = "
                           "'sqlite_backfill_source'")};
    REQUIRE(tbl.ok());
    CHECK(std::string(PQgetvalue(tbl.get(), 0, 0)) == "0");
}

TEST_CASE("WebhookStore[pg]: create without a secret sets has_secret=false",
         "[webhook_store][pg]") {
    WebhookStorePg store;

    auto id = store->create_webhook("https://example.com/hook", "*", /*secret=*/"");
    REQUIRE(id.has_value());

    auto hooks = store->list();
    REQUIRE(hooks.has_value());
    REQUIRE(hooks->size() == 1);
    CHECK((*hooks)[0].has_secret == false);
}

TEST_CASE("WebhookStore[pg]: multiple webhooks", "[webhook_store][pg]") {
    WebhookStorePg store;

    REQUIRE(store->create_webhook("https://a.com/hook", "agent.registered", "s1").has_value());
    REQUIRE(store->create_webhook("https://b.com/hook", "execution.completed", "s2").has_value());
    REQUIRE(store->create_webhook("http://c.com/hook", "agent.heartbeat", "s3").has_value());

    auto hooks = store->list();
    REQUIRE(hooks.has_value());
    CHECK(hooks->size() == 3);
}

TEST_CASE("WebhookStore[pg]: delete webhook cascades its deliveries", "[webhook_store][pg]") {
    WebhookStorePg store;

    auto id = store->create_webhook("http://127.0.0.1:1/h", "agent.registered", "secret");
    REQUIRE(id.has_value());

    store->fire_event("agent.registered", R"({"k":"v"})");
    auto before = wait_for_deliveries(*store, *id, 1);
    REQUIRE(before.size() == 1);

    auto deleted = store->delete_webhook(*id);
    REQUIRE(deleted.has_value());
    CHECK(*deleted == true);

    auto hooks = store->list();
    REQUIRE(hooks.has_value());
    CHECK(hooks->empty());
    // ON DELETE CASCADE — the delivery log for the deleted webhook is gone too.
    CHECK(store->get_deliveries(*id).empty());
}

TEST_CASE("WebhookStore[pg]: delete nonexistent webhook returns false, not an error",
         "[webhook_store][pg]") {
    WebhookStorePg store;

    auto deleted = store->delete_webhook(99999);
    REQUIRE(deleted.has_value());
    CHECK(*deleted == false);
}

TEST_CASE("WebhookStore[pg]: rejects invalid URL scheme with a typed error",
         "[webhook_store][pg][security]") {
    WebhookStorePg store;

    auto r1 = store->create_webhook("ftp://example.com/hook", "agent.registered", "secret");
    REQUIRE_FALSE(r1.has_value());
    CHECK(r1.error() == WebhookWriteError::invalid_url);

    auto r2 = store->create_webhook("javascript:alert(1)", "agent.registered", "secret");
    REQUIRE_FALSE(r2.has_value());
    CHECK(r2.error() == WebhookWriteError::invalid_url);

    auto r3 = store->create_webhook("", "agent.registered", "secret");
    REQUIRE_FALSE(r3.has_value());
    CHECK(r3.error() == WebhookWriteError::invalid_url);

    auto r4 = store->create_webhook("https://example.com/hook", "agent.registered", "secret");
    REQUIRE(r4.has_value());
}

TEST_CASE("WebhookStore[pg]: empty store returns empty list, not degraded",
         "[webhook_store][pg]") {
    WebhookStorePg store;
    auto hooks = store->list();
    REQUIRE(hooks.has_value());
    CHECK(hooks->empty());
}

TEST_CASE("WebhookStore[pg]: get_deliveries on empty webhook returns empty",
         "[webhook_store][pg]") {
    WebhookStorePg store;
    auto id = store->create_webhook("https://example.com/hook", "agent.registered", "secret");
    REQUIRE(id.has_value());
    CHECK(store->get_deliveries(*id).empty());
}

// ── ADR-0010 secrets seam ────────────────────────────────────────────────

TEST_CASE("WebhookStore[pg]: delivery with no secret configured fires unsigned (not skipped)",
         "[webhook_store][pg][security]") {
    WebhookStorePg store;
    auto id = store->create_webhook("http://127.0.0.1:1/h", "agent.registered", /*secret=*/"");
    REQUIRE(id.has_value());

    store->fire_event("agent.registered", R"({"k":"v"})");
    auto deliveries = wait_for_deliveries(*store, *id, 1);
    REQUIRE(deliveries.size() == 1);
    // Port 1 always refuses — the connection attempt itself was made
    // (unsigned), proving the has_secret=false path never routes through
    // the decrypt-skip branch.
    CHECK(deliveries[0].error == "connection_failed");
}

TEST_CASE("WebhookStore[pg]: fire_event never dispatches to a disabled webhook",
         "[webhook_store][pg]") {
    // gov Gate 3 quality-engineer (PR #3563 full-PR review): fire_event's
    // routing predicate (event_matches + enabled) was never exercised
    // end-to-end by any prior round — every delivery test fired an event
    // whose type exactly matched the sole enabled webhook. This proves the
    // enabled=false exclusion specifically.
    WebhookStorePg store;
    auto disabled_id = store->create_webhook("http://127.0.0.1:1/disabled", "agent.registered",
                                             /*secret=*/"", /*enabled=*/false);
    REQUIRE(disabled_id.has_value());
    auto control_id =
        store->create_webhook("http://127.0.0.1:1/control", "agent.registered", /*secret=*/"");
    REQUIRE(control_id.has_value());

    store->fire_event("agent.registered", R"({"k":"v"})");
    // Synchronize on the ENABLED control webhook's delivery completing —
    // both dispatch through the same worker pool, so once the control is
    // done the disabled one (if it had erroneously fired) would be too.
    auto control_deliveries = wait_for_deliveries(*store, *control_id, 1);
    REQUIRE(control_deliveries.size() == 1);

    auto disabled_deliveries = store->get_deliveries(*disabled_id, 50);
    CHECK(disabled_deliveries.empty());
}

TEST_CASE("WebhookStore[pg]: fire_event never dispatches on an event-type mismatch",
         "[webhook_store][pg]") {
    // Same rationale as the disabled-webhook test above — proves the
    // event_matches() half of the routing predicate.
    WebhookStorePg store;
    auto mismatched_id = store->create_webhook("http://127.0.0.1:1/mismatched",
                                               "policy.violation", /*secret=*/"");
    REQUIRE(mismatched_id.has_value());
    auto control_id =
        store->create_webhook("http://127.0.0.1:1/control", "agent.registered", /*secret=*/"");
    REQUIRE(control_id.has_value());

    store->fire_event("agent.registered", R"({"k":"v"})");
    auto control_deliveries = wait_for_deliveries(*store, *control_id, 1);
    REQUIRE(control_deliveries.size() == 1);

    auto mismatched_deliveries = store->get_deliveries(*mismatched_id, 50);
    CHECK(mismatched_deliveries.empty());
}

TEST_CASE("WebhookStore[pg]: a tampered secret blob is skipped, never fired unsigned",
         "[webhook_store][pg][security]") {
    WebhookStorePg store;
    auto id = store->create_webhook("http://127.0.0.1:1/h", "agent.registered", "real-secret");
    REQUIRE(id.has_value());

    // Corrupt the stored ciphertext via a second connection — flips the LSB
    // of the last byte (squarely inside the ciphertext region, well past
    // the fixed 93-byte header), so decrypt() must fail its GCM tag check.
    {
        auto lease = store.pool().acquire();
        REQUIRE(lease);
        auto res = yuzu::server::pg::exec_params(
            lease.get(),
            "UPDATE webhook_store.webhooks SET secret = set_byte(secret, "
            "octet_length(secret)-1, get_byte(secret, octet_length(secret)-1) # 1) "
            "WHERE id = $1::bigint",
            std::vector<std::string>{std::to_string(*id)});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    store->fire_event("agent.registered", R"({"k":"v"})");
    auto deliveries = wait_for_deliveries(*store, *id, 1);
    REQUIRE(deliveries.size() == 1);
    // NEVER "connection_failed" here — a decrypt failure must skip the
    // delivery entirely (headline rule, ADR-0057/ADR-0010), not fall
    // through to an unsigned (or any) network attempt.
    CHECK(deliveries[0].error == "secret_unavailable");
    CHECK(deliveries[0].status_code == 0);

    // gov Gate 3 quality-engineer: the delivery-outcome assertions above
    // prove ONLY that some decrypt failure occurred — they can't
    // distinguish this tamper from e.g. a malformed_blob false-pass. Assert
    // the codec's own internal counter to prove tag_mismatch specifically
    // was hit, confirming the byte flip landed inside the GCM tag/
    // ciphertext region (kCiphertextOffset=93, well past the 11-byte
    // plaintext here) rather than some other failure class.
    bool saw_tag_mismatch = false;
    for (const auto& [key, count] : store.codec().decrypt_failure_counts()) {
        const auto& [codec_store, cls] = key;
        if (codec_store == "webhook_store" &&
            cls == yuzu::server::pg::SecretCodec::FailureClass::tag_mismatch && count > 0)
            saw_tag_mismatch = true;
    }
    CHECK(saw_tag_mismatch);
}

TEST_CASE("WebhookStore[pg]: NULL secret with has_secret=true is a hard decrypt error",
         "[webhook_store][pg][security]") {
    WebhookStorePg store;
    auto id = store->create_webhook("http://127.0.0.1:1/h", "agent.registered", "real-secret");
    REQUIRE(id.has_value());

    // ADR-0010 §Decision-1 anti-downgrade: a row whose has_secret=true but
    // whose blob is NULL must be a hard error, never silently read as
    // "no auth". The CHECK constraint forbids writing this state through
    // the store's own API — simulate an out-of-band corruption (a hand
    // edit, a botched migration) that produced it anyway, bypassing the
    // constraint via a direct constraint-violating attempt, and confirm
    // Postgres itself refuses it (defence-in-depth is real, not just
    // asserted in a comment).
    auto lease = store.pool().acquire();
    REQUIRE(lease);
    auto res = yuzu::server::pg::exec_params(
        lease.get(), "UPDATE webhook_store.webhooks SET secret = NULL WHERE id = $1::bigint",
        std::vector<std::string>{std::to_string(*id)});
    CHECK(res.status() == PGRES_FATAL_ERROR); // CHECK constraint violation
}

TEST_CASE("WebhookStore[pg]: a non-NULL secret with has_secret=false is also a CHECK violation",
         "[webhook_store][pg][security]") {
    // gov Gate 3 quality-engineer: the CHECK constraint
    // (webhook_store.cpp's migration DDL) is a symmetric XNOR —
    // (has_secret AND secret IS NOT NULL) OR (NOT has_secret AND secret IS
    // NULL) — and the sibling test above only exercised one arm. Prove the
    // other: has_secret=false with a non-NULL secret is refused too, not
    // just silently ignored.
    WebhookStorePg store;
    auto id = store->create_webhook("http://127.0.0.1:1/h", "agent.registered", /*secret=*/"");
    REQUIRE(id.has_value());

    auto lease = store.pool().acquire();
    REQUIRE(lease);
    auto res = yuzu::server::pg::exec_params(
        lease.get(),
        "UPDATE webhook_store.webhooks SET secret = decode('00','hex') WHERE id = $1::bigint",
        std::vector<std::string>{std::to_string(*id)});
    CHECK(res.status() == PGRES_FATAL_ERROR); // CHECK constraint violation
}

