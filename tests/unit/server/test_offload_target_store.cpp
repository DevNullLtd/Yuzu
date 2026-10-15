/**
 * test_offload_target_store.cpp -- Unit tests for OffloadTargetStore
 * (Phase 8.3, #255; Postgres migration ADR-0059).
 *
 * Covers: open, create, list, get, get_by_name, delete, URL/name/batch
 * validation, delivery records, credential redaction, base64 encoding,
 * auth-type roundtrip, and the ADR-0010 secrets seam (envelope round-trip,
 * decrypt-failure fail-closed, the has_credential/auth_credential CHECK
 * constraint). No legacy-SQLite backfill exists for this store — ADR-0009's
 * 2026-08-25 fresh-start-by-default amendment (no production fleet has ever
 * run a pre-Postgres build of any Yuzu store), same posture as ResponseStore.
 *
 * PG-gated ([pg] tag): skips when YUZU_TEST_POSTGRES_DSN is unset, fails
 * when it is set but broken (docs/postgres-store-playbook.md §7).
 *
 * Network delivery (HTTP POST) is exercised against unreachable
 * loopback/reserved ports; the unit suite keeps the focus on store
 * invariants that the REST surface and the dispatch path rely on.
 */

#include "offload_target_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "test_offload_target_store_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <chrono>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;
using yuzu::test::OffloadTargetStorePg;

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: opens and migrates", "[offload_store][pg]") {
    OffloadTargetStorePg store;
    REQUIRE(store->is_open());
}

// ── Create and list ────────────────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: create and list target", "[offload_store][pg]") {
    OffloadTargetStorePg store;

    auto result = store->create_target("siem-primary", "https://siem.example.com/ingest",
                                       OffloadAuthType::Bearer, "token-abc",
                                       "execution.completed", /*batch_size=*/1);
    REQUIRE(result.has_value());
    auto id = *result;
    CHECK(id > 0);

    auto targets = store->list();
    REQUIRE(targets.has_value());
    REQUIRE(targets->size() == 1);
    CHECK((*targets)[0].id == id);
    CHECK((*targets)[0].name == "siem-primary");
    CHECK((*targets)[0].url == "https://siem.example.com/ingest");
    CHECK((*targets)[0].auth_type == OffloadAuthType::Bearer);
    CHECK((*targets)[0].has_credential); // configured, but no plaintext exposed
    CHECK((*targets)[0].event_types == "execution.completed");
    CHECK((*targets)[0].batch_size == 1);
    CHECK((*targets)[0].enabled);
}

TEST_CASE("OffloadTargetStore[pg]: multiple targets", "[offload_store][pg]") {
    OffloadTargetStorePg store;
    REQUIRE(store->create_target("a", "https://a.example.com/h", OffloadAuthType::None, "",
                                 "*")
                .has_value());
    REQUIRE(store->create_target("b", "http://b.example.com/h", OffloadAuthType::Basic,
                                 "user:pass", "agent.registered")
                .has_value());
    REQUIRE(store->create_target("c", "https://c.example.com/h", OffloadAuthType::Hmac,
                                 "shared-secret", "execution.completed", 5)
                .has_value());

    auto targets = store->list();
    REQUIRE(targets.has_value());
    REQUIRE(targets->size() == 3);
}

// ── get / get_by_name ──────────────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: get by id and name", "[offload_store][pg]") {
    OffloadTargetStorePg store;
    auto result = store->create_target("named-target", "https://x.example.com/h",
                                       OffloadAuthType::None, "", "*");
    REQUIRE(result.has_value());
    auto id = *result;

    bool ok = true;
    auto by_id = store->get(id, &ok);
    REQUIRE(by_id.has_value());
    CHECK(ok);
    CHECK(by_id->name == "named-target");
    CHECK_FALSE(by_id->has_credential);

    auto by_name = store->get_by_name("named-target");
    REQUIRE(by_name.has_value());
    CHECK(by_name->id == id);

    ok = true;
    CHECK_FALSE(store->get(99999, &ok).has_value());
    CHECK(ok); // genuinely not found, not a degraded read
    CHECK_FALSE(store->get_by_name("nonexistent").has_value());
}

// ── Delete ─────────────────────────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: delete target", "[offload_store][pg]") {
    OffloadTargetStorePg store;
    auto result = store->create_target("doomed", "https://x.example.com/h",
                                       OffloadAuthType::None, "", "*");
    REQUIRE(result.has_value());
    auto id = *result;
    auto listed = store->list();
    REQUIRE(listed.has_value());
    CHECK(listed->size() == 1);

    auto deleted = store->delete_target(id);
    REQUIRE(deleted.has_value());
    CHECK(*deleted);
    listed = store->list();
    REQUIRE(listed.has_value());
    CHECK(listed->empty());

    // Idempotent on missing — a business fact (false), not an error.
    deleted = store->delete_target(id);
    REQUIRE(deleted.has_value());
    CHECK_FALSE(*deleted);
}

// ── URL scheme validation ──────────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: rejects invalid URL scheme", "[offload_store][pg][security]") {
    OffloadTargetStorePg store;

    auto ftp = store->create_target("ftp", "ftp://evil.example.com/h", OffloadAuthType::None, "",
                                    "*");
    REQUIRE_FALSE(ftp.has_value());
    CHECK(ftp.error() == OffloadWriteError::invalid_input);
    CHECK_FALSE(
        store->create_target("js", "javascript:alert(1)", OffloadAuthType::None, "", "*")
            .has_value());
    CHECK_FALSE(store->create_target("blank", "", OffloadAuthType::None, "", "*").has_value());

    CHECK(store->create_target("ok-https", "https://ok.example.com/h", OffloadAuthType::None, "",
                               "*")
              .has_value());
    CHECK(store->create_target("ok-http", "http://ok.example.com/h", OffloadAuthType::None, "",
                               "*")
              .has_value());
}

// ── Empty-name rejected ────────────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: rejects empty name", "[offload_store][pg]") {
    OffloadTargetStorePg store;
    auto result = store->create_target("", "https://x.example.com/h", OffloadAuthType::None, "",
                                       "*");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == OffloadWriteError::invalid_input);
}

// ── Duplicate name rejected (UNIQUE constraint) ────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: rejects duplicate name", "[offload_store][pg]") {
    OffloadTargetStorePg store;
    REQUIRE(
        store->create_target("dup", "https://a.example.com/h", OffloadAuthType::None, "", "*")
            .has_value());
    auto second =
        store->create_target("dup", "https://b.example.com/h", OffloadAuthType::None, "", "*");
    REQUIRE_FALSE(second.has_value());
    CHECK(second.error() == OffloadWriteError::invalid_input);
}

TEST_CASE("OffloadTargetStore[pg]: a PK collision from an out-of-sync identity sequence is "
          "db_error, never mistaken for a duplicate name",
          "[offload_store][pg]") {
    OffloadTargetStorePg store;

    // Force the sequence out of sync with a second connection: consume the
    // sequence's next value, then pre-insert a row at the value the store's
    // OWN next nextval() call will therefore return next. This reproduces an
    // operator manually resetting the sequence, or restoring a dump with
    // stale sequence state — never a legitimate name collision.
    int64_t collide_id = -1;
    {
        pg::PgConn conn{PQconnectdb(store.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult seqres = pg::exec_params(
            conn.get(),
            "SELECT nextval(pg_get_serial_sequence('offload_target_store.offload_targets','id'))",
            std::vector<std::string>{});
        REQUIRE(seqres.status() == PGRES_TUPLES_OK);
        collide_id = std::stoll(PQgetvalue(seqres.get(), 0, 0)) + 1;
        pg::PgResult insres = pg::exec_params(
            conn.get(),
            "INSERT INTO offload_target_store.offload_targets "
            "(id, name, url, auth_type, auth_credential, has_credential, event_types, "
            " batch_size, enabled, created_at) OVERRIDING SYSTEM VALUE VALUES "
            "($1::bigint, 'pre-existing', 'https://x.example.com/h', 'none', NULL, false, "
            " '*', 1, true, 0)",
            std::vector<std::string>{std::to_string(collide_id)});
        REQUIRE(insres.status() == PGRES_COMMAND_OK);
    }

    auto result = store->create_target("desynced", "https://y.example.com/h",
                                       OffloadAuthType::None, "", "*");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == OffloadWriteError::db_error); // NOT invalid_input
}

// ── batch_size validation ──────────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: rejects batch_size < 1", "[offload_store][pg]") {
    OffloadTargetStorePg store;
    CHECK_FALSE(store->create_target("zero", "https://x.example.com/h", OffloadAuthType::None,
                                     "", "*", /*batch_size=*/0)
                    .has_value());
    CHECK_FALSE(store->create_target("neg", "https://x.example.com/h", OffloadAuthType::None, "",
                                     "*", /*batch_size=*/-1)
                    .has_value());

    CHECK(store->create_target("ok", "https://x.example.com/h", OffloadAuthType::None, "", "*",
                               /*batch_size=*/1)
              .has_value());
}

// ── Empty deliveries ───────────────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: get_deliveries on empty target returns empty",
          "[offload_store][pg]") {
    OffloadTargetStorePg store;
    auto result =
        store->create_target("t", "https://x.example.com/h", OffloadAuthType::None, "", "*");
    REQUIRE(result.has_value());
    CHECK(store->get_deliveries(*result).empty());
}

// ── Auth-type roundtrip (pure function — no store needed) ──────────────────

TEST_CASE("OffloadTargetStore: auth-type string roundtrip", "[offload_store]") {
    CHECK(offload_auth_type_to_string(OffloadAuthType::None) == "none");
    CHECK(offload_auth_type_to_string(OffloadAuthType::Bearer) == "bearer");
    CHECK(offload_auth_type_to_string(OffloadAuthType::Basic) == "basic");
    CHECK(offload_auth_type_to_string(OffloadAuthType::Hmac) == "hmac");

    CHECK(offload_auth_type_from_string("none") == OffloadAuthType::None);
    CHECK(offload_auth_type_from_string("bearer") == OffloadAuthType::Bearer);
    CHECK(offload_auth_type_from_string("basic") == OffloadAuthType::Basic);
    CHECK(offload_auth_type_from_string("hmac") == OffloadAuthType::Hmac);

    // Unknown / empty default to None — keeps the surface robust to wire
    // additions without crashing.
    CHECK(offload_auth_type_from_string("") == OffloadAuthType::None);
    CHECK(offload_auth_type_from_string("unknown") == OffloadAuthType::None);
}

// ── Base64 vectors (RFC 4648) — pure function ───────────────────────────────

TEST_CASE("OffloadTargetStore: base64 RFC 4648 vectors", "[offload_store]") {
    CHECK(OffloadTargetStore::base64_encode("") == "");
    CHECK(OffloadTargetStore::base64_encode("f") == "Zg==");
    CHECK(OffloadTargetStore::base64_encode("fo") == "Zm8=");
    CHECK(OffloadTargetStore::base64_encode("foo") == "Zm9v");
    CHECK(OffloadTargetStore::base64_encode("foob") == "Zm9vYg==");
    CHECK(OffloadTargetStore::base64_encode("fooba") == "Zm9vYmE=");
    CHECK(OffloadTargetStore::base64_encode("foobar") == "Zm9vYmFy");
    // Basic-auth shape — "user:pass" — exercised by the live header path.
    CHECK(OffloadTargetStore::base64_encode("user:pass") == "dXNlcjpwYXNz");
}

// ── HMAC-SHA256 known vector — pure function ────────────────────────────────

TEST_CASE("OffloadTargetStore: hmac_sha256 known vector", "[offload_store]") {
    // RFC 4231 test case 2: key="Jefe", data="what do ya want for nothing?".
    auto sig = OffloadTargetStore::hmac_sha256("Jefe", "what do ya want for nothing?");
    REQUIRE(sig.has_value());
    CHECK(*sig == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

// ── fire_event matching: target_filter scoping ─────────────────────────────
//
// We can't test the network delivery in a unit test cleanly, but we CAN
// test that fire_event with a non-matching target_filter does NOT enqueue
// any deliveries by observing get_deliveries remains empty after the
// synchronous matching decision. With no network endpoint to hit, fire_event
// with batch_size=1 would otherwise produce a connection_failed delivery
// record — which is the signal that the dispatch loop ran. Filtered-out
// targets must produce nothing.

TEST_CASE("OffloadTargetStore[pg]: target_filter excludes non-matching names",
          "[offload_store][pg][filter]") {
    OffloadTargetStorePg store;
    auto id_a =
        store->create_target("alpha", "http://127.0.0.1:1/h", OffloadAuthType::None, "", "*");
    auto id_b =
        store->create_target("beta", "http://127.0.0.1:1/h", OffloadAuthType::None, "", "*");
    REQUIRE(id_a.has_value());
    REQUIRE(id_b.has_value());

    // Filter to a name that doesn't exist — neither target should fire.
    // The filter decision runs synchronously inside fire_event before any
    // delivery is queued, so the absence assertion is deterministic without
    // a sleep (qe-S2).
    store->fire_event("execution.completed", R"({"k":"v"})", {"gamma"});
    CHECK(store->get_deliveries(*id_a).empty());
    CHECK(store->get_deliveries(*id_b).empty());
}

// ── fire_event respects event_types filter ─────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: event_types filter excludes non-matching events",
          "[offload_store][pg][filter]") {
    OffloadTargetStorePg store;
    // Subscribed only to "agent.registered"
    auto result = store->create_target("only-reg", "http://127.0.0.1:1/h", OffloadAuthType::None,
                                       "", "agent.registered");
    REQUIRE(result.has_value());

    // Different event — filter is checked before dispatch (qe-S2).
    store->fire_event("execution.completed", R"({"k":"v"})");
    CHECK(store->get_deliveries(*result).empty());
}

// ── Disabled target is skipped ─────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: disabled target receives no events",
          "[offload_store][pg][filter]") {
    OffloadTargetStorePg store;
    auto result = store->create_target("dormant", "http://127.0.0.1:1/h", OffloadAuthType::None,
                                       "", "*", /*batch_size=*/1, /*enabled=*/false);
    REQUIRE(result.has_value());

    // `WHERE enabled` filters disabled rows out of the scan synchronously
    // (the load-bearing partial index), so no dispatch runs and no sleep is
    // required (qe-S2).
    store->fire_event("execution.completed", R"({"k":"v"})");
    CHECK(store->get_deliveries(*result).empty());
}

// ── Batch accumulator: events buffer until threshold (qe-S3) ───────────────

TEST_CASE("OffloadTargetStore[pg]: batch_size > 1 accumulates without dispatch",
          "[offload_store][pg][batch]") {
    OffloadTargetStorePg store;
    auto result = store->create_target("batched", "http://127.0.0.1:1/h", OffloadAuthType::None,
                                       "", "*", /*batch_size=*/3);
    REQUIRE(result.has_value());
    auto id = *result;

    // Fire two events — buffer holds them, no dispatch yet.
    store->fire_event("execution.completed", R"({"k":1})");
    store->fire_event("execution.completed", R"({"k":2})");
    CHECK(store->get_deliveries(id).empty());

    // Flush via the public flush_all() API rather than a third event so the
    // assertion is deterministic without a sleep on a worker-pool thread.
    store->flush_all();

    // Flush dispatch is async; poll up to 5s for the row to land.
    constexpr auto kPollDeadline = std::chrono::seconds(5);
    auto start = std::chrono::steady_clock::now();
    std::vector<OffloadDelivery> deliveries;
    while (std::chrono::steady_clock::now() - start < kPollDeadline) {
        deliveries = store->get_deliveries(id);
        if (!deliveries.empty())
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    REQUIRE(deliveries.size() == 1);
    CHECK(deliveries[0].event_count == 2);
    // Body shape: {"events":[…]}
    CHECK(deliveries[0].payload.find("\"events\"") != std::string::npos);
}

// ── Depth guard: a poisoned batched event is preserved as raw text, sibling
//    valid event in the same batch is unaffected (#2437-class fix) ─────────

TEST_CASE("OffloadTargetStore[pg]: batched event past the depth guard is preserved as raw "
          "text, sibling event in the same batch unaffected",
          "[offload_store][pg][batch][security]") {
    OffloadTargetStorePg store;
    auto result = store->create_target("poison-batch", "http://127.0.0.1:1/h",
                                       OffloadAuthType::None, "", "*", /*batch_size=*/2);
    REQUIRE(result.has_value());
    auto id = *result;

    // 35 levels of nesting, well past kMcpMaxJsonDepth (32) but nowhere
    // near the ~100,000-level depth that actually crashes the process
    // (json_exceeds_depth's own doc comment, mcp_jsonrpc.hpp: measured, not
    // assumed; never reproduce the real attack depth in a test). Valid
    // JSON on its own: 35 nested arrays, innermost empty.
    const std::string poisoned = std::string(35, '[') + std::string(35, ']');

    // Poisoned event fired first so its position in the resulting "events"
    // array is deterministic. Second event reaches batch_size=2 and
    // triggers a synchronous build_batch_body() call inside fire_event()
    // itself, before the async HTTP dispatch is submitted.
    store->fire_event("execution.completed", poisoned);
    store->fire_event("execution.completed", R"({"k":2})");

    // Delivery recording still runs on the worker pool; poll for the row.
    constexpr auto kPollDeadline = std::chrono::seconds(5);
    auto start = std::chrono::steady_clock::now();
    std::vector<OffloadDelivery> deliveries;
    while (std::chrono::steady_clock::now() - start < kPollDeadline) {
        deliveries = store->get_deliveries(id);
        if (!deliveries.empty())
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    REQUIRE(deliveries.size() == 1);
    CHECK(deliveries[0].event_count == 2); // neither event dropped

    nlohmann::json body;
    REQUIRE_NOTHROW(body = nlohmann::json::parse(deliveries[0].payload));
    REQUIRE(body.contains("events"));
    REQUIRE(body["events"].is_array());
    REQUIRE(body["events"].size() == 2);

    // Poisoned event: preserved as a raw STRING leaf (never parsed into a
    // nested structure); proves the guard fired BEFORE
    // nlohmann::json::parse ever ran on it. Without the guard, 35 levels
    // parses cleanly and this would come back as a nested JSON array
    // instead, which is exactly the discriminator the red/green proof uses.
    REQUIRE(body["events"][0].is_string());
    CHECK(body["events"][0].get<std::string>() == poisoned);

    // Sibling valid event in the same batch: unaffected, parsed normally.
    REQUIRE(body["events"][1].is_object());
    CHECK(body["events"][1].value("k", 0) == 2);
}

// ── Control-byte rejection in name and url (round-3 residual finding) ─────

TEST_CASE("OffloadTargetStore[pg]: rejects name with control bytes",
          "[offload_store][pg][security]") {
    OffloadTargetStorePg store;
    // Audit-row line-splitting via newline in name — DELETE handler
    // emits `name=<n> url=<u>` to the audit `detail` field.
    CHECK_FALSE(store->create_target("evil\nfake.event", "https://x.example.com/h",
                                     OffloadAuthType::None, "", "*")
                    .has_value());
    CHECK_FALSE(store->create_target(std::string("nul\0byte", 8), "https://x.example.com/h",
                                     OffloadAuthType::None, "", "*")
                    .has_value());
    CHECK(store->create_target("ok-name", "https://x.example.com/h", OffloadAuthType::None, "",
                               "*")
              .has_value());
}

TEST_CASE("OffloadTargetStore[pg]: rejects url with control bytes",
          "[offload_store][pg][security]") {
    OffloadTargetStorePg store;
    CHECK_FALSE(store->create_target("a", "https://x.example.com/h\r\nX-Evil: 1",
                                     OffloadAuthType::None, "", "*")
                    .has_value());
    CHECK_FALSE(store->create_target("b", "https://x.example.com/h\nfoo", OffloadAuthType::None,
                                     "", "*")
                    .has_value());
    CHECK(store->create_target("c", "https://x.example.com/h", OffloadAuthType::None, "", "*")
              .has_value());
}

TEST_CASE("OffloadTargetStore[pg]: rejects event_types with control bytes",
          "[offload_store][pg][security]") {
    OffloadTargetStorePg store;
    CHECK_FALSE(store->create_target("a", "https://x.example.com/h", OffloadAuthType::None, "",
                                     "exec\r\nX-Evil: 1")
                    .has_value());
    CHECK(store->create_target("b", "https://x.example.com/h", OffloadAuthType::None, "", "*")
              .has_value());
}

// ── CRLF / control-byte rejection in auth_credential (sec-H1) ──────────────

TEST_CASE("OffloadTargetStore[pg]: rejects auth_credential with control bytes",
          "[offload_store][pg][security]") {
    OffloadTargetStorePg store;

    CHECK_FALSE(store->create_target("crlf-bearer", "https://x.example.com/h",
                                     OffloadAuthType::Bearer, "tok\r\nX-Evil: 1", "*")
                    .has_value());
    CHECK_FALSE(store->create_target("lf-only", "https://x.example.com/h", OffloadAuthType::Bearer,
                                     "tok\nfoo", "*")
                    .has_value());
    CHECK_FALSE(store->create_target("cr-only", "https://x.example.com/h", OffloadAuthType::Bearer,
                                     "tok\rfoo", "*")
                    .has_value());
    CHECK_FALSE(store->create_target("nul", "https://x.example.com/h", OffloadAuthType::Bearer,
                                     std::string("tok\0foo", 7), "*")
                    .has_value());
    // The same guard fires for Basic and HMAC as defence-in-depth even
    // though those auth types don't emit the credential verbatim.
    CHECK_FALSE(store->create_target("crlf-basic", "https://x.example.com/h",
                                     OffloadAuthType::Basic, "user\r\n:pass", "*")
                    .has_value());
    CHECK_FALSE(store->create_target("crlf-hmac", "https://x.example.com/h", OffloadAuthType::Hmac,
                                     "secret\nfoo", "*")
                    .has_value());

    CHECK(store->create_target("ok-bearer", "https://x.example.com/h", OffloadAuthType::Bearer,
                               "abcXYZ012!@#$%^&*()", "*")
              .has_value());
}

// ── Dispatch-time scheme guard (sec-M2) ────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: dispatch fires against a live target",
          "[offload_store][pg][security]") {
    OffloadTargetStorePg store;
    auto result =
        store->create_target("legit", "http://127.0.0.1:1/h", OffloadAuthType::None, "", "*");
    REQUIRE(result.has_value());
    auto id = *result;

    store->fire_event("execution.completed", R"({"k":"v"})");
    std::vector<OffloadDelivery> deliveries;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (std::chrono::steady_clock::now() < deadline) {
        deliveries = store->get_deliveries(id);
        if (!deliveries.empty())
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    REQUIRE(deliveries.size() == 1);
    // Port 1 is reserved — the connection fails, proving the dispatch path
    // ran and reached the HTTP client.
    CHECK(deliveries[0].error == "connection_failed");
}

// ── ADR-0010 secrets seam ────────────────────────────────────────────────

TEST_CASE("OffloadTargetStore[pg]: delivery with no credential configured fires unsigned "
          "(not skipped)",
          "[offload_store][pg][security]") {
    OffloadTargetStorePg store;
    auto result = store->create_target("no-cred", "http://127.0.0.1:1/h", OffloadAuthType::Bearer,
                                       /*auth_credential=*/"", "*");
    REQUIRE(result.has_value());
    auto id = *result;

    store->fire_event("execution.completed", R"({"k":"v"})");
    std::vector<OffloadDelivery> deliveries;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (std::chrono::steady_clock::now() < deadline) {
        deliveries = store->get_deliveries(id);
        if (!deliveries.empty())
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    REQUIRE(deliveries.size() == 1);
    // connection_failed (not credential_unavailable) proves the connection
    // attempt was actually made — the has_credential=false path never
    // routes through the decrypt-skip branch.
    CHECK(deliveries[0].error == "connection_failed");
}

TEST_CASE("OffloadTargetStore[pg]: a tampered credential blob is skipped, never fired unsigned",
          "[offload_store][pg][security]") {
    OffloadTargetStorePg store;
    auto result = store->create_target("tampered", "http://127.0.0.1:1/h", OffloadAuthType::Hmac,
                                       "shared-secret", "*");
    REQUIRE(result.has_value());
    auto id = *result;

    // Flip one bit of the stored ciphertext directly via a second PG
    // connection — chosen to land inside the ciphertext (past the 93-byte
    // blob header), so this is a tamper detection (GCM tag mismatch), not a
    // parse failure.
    {
        pg::PgConn conn{PQconnectdb(store.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult res = pg::exec_params(
            conn.get(),
            "UPDATE offload_target_store.offload_targets SET auth_credential = "
            "set_byte(auth_credential, octet_length(auth_credential)-1, "
            "get_byte(auth_credential, octet_length(auth_credential)-1) # 1) WHERE id = $1",
            std::vector<std::string>{std::to_string(id)});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    store->fire_event("execution.completed", R"({"k":"v"})");
    std::vector<OffloadDelivery> deliveries;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (std::chrono::steady_clock::now() < deadline) {
        deliveries = store->get_deliveries(id);
        if (!deliveries.empty())
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    REQUIRE(deliveries.size() == 1);
    CHECK(deliveries[0].status_code == 0);
    CHECK(deliveries[0].error == "credential_unavailable"); // never "connection_failed"

    // Rule out a different failure class coincidentally passing.
    bool saw_tag_mismatch = false;
    for (const auto& [key, count] : store.codec().decrypt_failure_counts()) {
        const auto& [decrypt_store, cls] = key;
        if (decrypt_store == "offload_target_store" &&
            cls == pg::SecretCodec::FailureClass::tag_mismatch && count > 0)
            saw_tag_mismatch = true;
    }
    CHECK(saw_tag_mismatch);
}

TEST_CASE("OffloadTargetStore[pg]: a stored auth_type that doesn't round-trip is refused "
          "dispatch, never fired with the credential unauthenticated",
          "[offload_store][pg][security]") {
    OffloadTargetStorePg store;
    auto result = store->create_target("desynced-auth", "http://127.0.0.1:1/h",
                                       OffloadAuthType::Bearer, "shared-secret", "*");
    REQUIRE(result.has_value());
    auto id = *result;

    // Simulate a tampered/legacy row via a second connection: a stored
    // auth_type string outside {none,bearer,basic,hmac}. The lenient
    // from-string parser folds this to None on read, so without the
    // defence-in-depth check this would dispatch the configured credential
    // completely unauthenticated instead of being refused.
    {
        pg::PgConn conn{PQconnectdb(store.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        pg::PgResult res = pg::exec_params(
            conn.get(),
            "UPDATE offload_target_store.offload_targets SET auth_type = 'oauth2' WHERE id = $1",
            std::vector<std::string>{std::to_string(id)});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    store->fire_event("execution.completed", R"({"k":"v"})");
    std::vector<OffloadDelivery> deliveries;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (std::chrono::steady_clock::now() < deadline) {
        deliveries = store->get_deliveries(id);
        if (!deliveries.empty())
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    REQUIRE(deliveries.size() == 1);
    CHECK(deliveries[0].status_code == 0);
    CHECK(deliveries[0].error == "invalid_auth_type"); // never dispatched unauthenticated
}

TEST_CASE("OffloadTargetStore[pg]: NULL auth_credential with has_credential=true is a hard "
          "CHECK violation",
          "[offload_store][pg][security]") {
    OffloadTargetStorePg store;
    auto result = store->create_target("checked", "https://x.example.com/h",
                                       OffloadAuthType::Bearer, "tok", "*");
    REQUIRE(result.has_value());

    pg::PgConn conn{PQconnectdb(store.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult res = pg::exec_params(
        conn.get(),
        "UPDATE offload_target_store.offload_targets SET auth_credential = NULL WHERE id = $1",
        std::vector<std::string>{std::to_string(*result)});
    // The CHECK constraint refuses this at the database level — the
    // anti-downgrade invariant is structural, not just app-level.
    CHECK(res.status() == PGRES_FATAL_ERROR);
}

TEST_CASE("OffloadTargetStore[pg]: a non-NULL auth_credential with has_credential=false is "
          "also a CHECK violation",
          "[offload_store][pg][security]") {
    OffloadTargetStorePg store;
    auto result =
        store->create_target("unchecked", "https://x.example.com/h", OffloadAuthType::None, "",
                             "*");
    REQUIRE(result.has_value());

    pg::PgConn conn{PQconnectdb(store.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult res = pg::exec_params(
        conn.get(),
        "UPDATE offload_target_store.offload_targets SET auth_credential = "
        "decode('00','hex') WHERE id = $1",
        std::vector<std::string>{std::to_string(*result)});
    CHECK(res.status() == PGRES_FATAL_ERROR);
}
