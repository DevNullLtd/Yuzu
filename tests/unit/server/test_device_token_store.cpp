/**
 * test_device_token_store.cpp — `DeviceTokenStore` (device authorization tokens, capability
 * 18.8, ADR-0052).
 *
 * **This store is deliberately DORMANT on `dev`** — nothing in `server.cpp` constructs a
 * `DeviceTokenStore` (see device_token_store.hpp's file header). These tests exercise the
 * store's public API directly, exactly as `test_rest_api_t2.cpp`'s/`test_rest_api_tokens.cpp`'s
 * device-token cases and a future re-wiring do.
 *
 * Covers:
 *  - fail-closed construction, both the migration-drift case (a live but unmigratable database)
 *    and the unreachable-pool case (mirrors test_license_store.cpp's two fail-closed cases).
 *  - create_token validation (empty principal_id) and CSPRNG-shaped errors.
 *  - create/validate round-trip, token shape, CSPRNG uniqueness (256 consecutive tokens).
 *  - validate_token's full rejection ordering: not_found -> revoked -> expired ->
 *    unbound_legacy -> binding_mismatch, and the #1053 rich-rejection context per variant.
 *  - list_tokens (typed reads — ADR-0036), revoke_token, revoke_by_principal (#823).
 *
 * No legacy-SQLite backfill test coverage: the dedicated [backfill] TEST_CASE suite
 * (2026-08-25) was removed as part of a fresh-start-by-default policy change (ADR-0009
 * amendment) — no production fleet has ever run a pre-Postgres build.
 * DeviceTokenStore::migrate_from_sqlite() itself was retired
 * (chore/retire-migrate-from-sqlite-batch-b, #3623) — this store had zero production
 * callers to begin with, so there was no live database to protect either way.
 *
 * Migrated-to-Postgres store (ADR-0012 §1, authoritative/fail-hard). PG-gated: skips when
 * YUZU_TEST_POSTGRES_DSN is unset, fails when set but broken (test_helpers.hpp skip-vs-fail
 * contract). Store-behaviour cases use the pre-migrated PgTestTemplate variant
 * (docs/postgres-store-playbook.md step 7); the two fail-closed cases use YUZU_REQUIRE_PG_DB / no
 * gate at all, per the plain-migration-test carve-out documented on that macro.
 */

#include "device_token_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::DeviceAuthToken;
using yuzu::server::DeviceTokenStore;
using yuzu::server::DeviceTokenValidateError;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Shares the "devicetokenstore" key with test_rest_api_t2.cpp's and test_rest_api_tokens.cpp's
// own templates (identical setup, replay-verified per docs/postgres-store-playbook.md step 7).
yuzu::test::PgTestTemplate device_token_store_tpl{
    "devicetokenstore", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        DeviceTokenStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("device_token_store template: store failed to migrate");
    }};

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

// ── Construction fail-closed ────────────────────────────────────────────────

TEST_CASE("DeviceTokenStore reports !is_open on a migration failure", "[device_token][pg]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA device_token_store")};
        REQUIRE(s.ok());
        PgResult t{
            PQexec(conn.get(), "CREATE TABLE device_token_store.device_auth_tokens (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    DeviceTokenStore store{pool};
    CHECK_FALSE(store.is_open());
}

TEST_CASE(
    "DeviceTokenStore reports !is_open on an unreachable pool, and every method fails closed",
    "[device_token]") {
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    DeviceTokenStore store{pool};
    CHECK_FALSE(store.is_open());

    auto create_res = store.create_token("n", "admin", "d", "", 0);
    CHECK_FALSE(create_res.has_value());
    CHECK(create_res.error().starts_with(yuzu::server::kDeviceTokenDbErrorPrefix));

    // A closed store collapses to invalid_input, same as an empty raw token — preserved
    // unchanged from the pre-migration store's contract (device_token_store.hpp: "Empty /
    // malformed raw token, or store closed").
    auto validate_res = store.validate_token("ydt_whatever", "d");
    CHECK_FALSE(validate_res.has_value());
    CHECK(validate_res.error().error == DeviceTokenValidateError::invalid_input);

    auto list_res = store.list_tokens();
    CHECK_FALSE(list_res.has_value());
    CHECK(list_res.error().starts_with(yuzu::server::kDeviceTokenDbErrorPrefix));

    auto revoke_res = store.revoke_token("x");
    CHECK_FALSE(revoke_res.has_value());
    CHECK(revoke_res.error().starts_with(yuzu::server::kDeviceTokenDbErrorPrefix));

    auto revoke_by_res = store.revoke_by_principal("alice");
    CHECK_FALSE(revoke_by_res.has_value());
    CHECK(revoke_by_res.error().starts_with(yuzu::server::kDeviceTokenDbErrorPrefix));

    auto revoke_by_device_res = store.revoke_by_device("endpoint-99");
    CHECK_FALSE(revoke_by_device_res.has_value());
    CHECK(revoke_by_device_res.error().starts_with(yuzu::server::kDeviceTokenDbErrorPrefix));
}

// ── Create and Validate ──────────────────────────────────────────────────────

TEST_CASE("create_token rejects an empty principal_id", "[device_token][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_token("n", "", "d", "", 0);
    REQUIRE_FALSE(r.has_value());
    CHECK_FALSE(r.error().starts_with(yuzu::server::kDeviceTokenDbErrorPrefix));
}

// #3351: store-level length bound, matching the REST route's own 256-char clamp (rest_api_v1.cpp)
// on name/device_id/definition_id, and the store's only bound at all on principal_id (which the
// route never clamps — it comes from session->username). REST itself can never reach this
// rejection (its own clamp fires first for the three clamped fields, and usernames are bounded
// to 64 by auth_db.cpp) — this is defence-in-depth for a future non-REST caller.
TEST_CASE("DeviceTokenStore: create_token rejects each free-text field exceeding 256 bytes, "
          "accepts exactly 256",
          "[device_token][3351][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    const std::string ok256(256, 'a');
    const std::string over257(257, 'a');

    SECTION("name exceeds 256") {
        auto res = store.create_token(over257, "admin", "device-A", "", 0);
        REQUIRE_FALSE(res.has_value());
        CHECK(res.error().find("invalid_input_length") != std::string::npos);
        CHECK(res.error().find("name") != std::string::npos);
        auto tokens = store.list_tokens();
        REQUIRE(tokens.has_value());
        CHECK(tokens->empty());
    }
    SECTION("principal_id exceeds 256") {
        auto res = store.create_token("n", over257, "device-A", "", 0);
        REQUIRE_FALSE(res.has_value());
        CHECK(res.error().find("invalid_input_length") != std::string::npos);
        CHECK(res.error().find("principal_id") != std::string::npos);
        auto tokens = store.list_tokens();
        REQUIRE(tokens.has_value());
        CHECK(tokens->empty());
    }
    SECTION("device_id exceeds 256") {
        auto res = store.create_token("n", "admin", over257, "", 0);
        REQUIRE_FALSE(res.has_value());
        CHECK(res.error().find("invalid_input_length") != std::string::npos);
        CHECK(res.error().find("device_id") != std::string::npos);
        auto tokens = store.list_tokens();
        REQUIRE(tokens.has_value());
        CHECK(tokens->empty());
    }
    SECTION("definition_id exceeds 256") {
        auto res = store.create_token("n", "admin", "device-A", over257, 0);
        REQUIRE_FALSE(res.has_value());
        CHECK(res.error().find("invalid_input_length") != std::string::npos);
        CHECK(res.error().find("definition_id") != std::string::npos);
        auto tokens = store.list_tokens();
        REQUIRE(tokens.has_value());
        CHECK(tokens->empty());
    }
    SECTION("exactly 256 bytes on every field is accepted") {
        auto res = store.create_token(ok256, ok256, ok256, ok256, 0);
        REQUIRE(res.has_value());
        auto tokens = store.list_tokens();
        REQUIRE(tokens.has_value());
        REQUIRE(tokens->size() == 1);
        CHECK((*tokens)[0].name.size() == 256);
        CHECK((*tokens)[0].principal_id.size() == 256);
        CHECK((*tokens)[0].device_id.size() == 256);
        CHECK((*tokens)[0].definition_id.size() == 256);
    }
}

// #3351: proves the linear rewrite still defangs correctly (embedded NULs -> U+FFFD) and that the
// length bound is measured on RAW bytes BEFORE sanitize can grow the string — 256 raw NULs (which
// would expand to 768 bytes of U+FFFD) must be accepted, not rejected as "over 256".
TEST_CASE("DeviceTokenStore: create_token's NUL-embedded name is stored as U+FFFD, measured "
          "pre-sanitize against the length bound",
          "[device_token][3351][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    const std::string nul_dense(256, '\0');
    auto created = store.create_token(nul_dense, "admin", "device-A", "", 0);
    REQUIRE(created.has_value());

    auto tokens = store.list_tokens();
    REQUIRE(tokens.has_value());
    REQUIRE(tokens->size() == 1);
    const std::string expected_scrubbed = [] {
        std::string out;
        for (int i = 0; i < 256; ++i)
            out += "\xEF\xBF\xBD";
        return out;
    }();
    CHECK((*tokens)[0].name == expected_scrubbed);
}

TEST_CASE("DeviceTokenStore: create and validate round-trip", "[device_token][crud][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.create_token("Test Token", "admin", "device-RT", "", 0);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "device-RT");
    REQUIRE(validated.has_value());
    CHECK(validated->name == "Test Token");
    CHECK(validated->principal_id == "admin");
    CHECK(validated->created_at > 0);
    CHECK(!validated->revoked);
}

TEST_CASE("DeviceTokenStore: token starts with ydt_ prefix", "[device_token][format][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.create_token("Prefixed Token", "admin", "", "", 0);
    REQUIRE(result.has_value());
    CHECK(result->starts_with("ydt_"));
    CHECK(result->size() == 68); // "ydt_" (4) + 64 hex chars
}

TEST_CASE("DeviceTokenStore: invalid token rejected", "[device_token][auth][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto validated = store.validate_token("ydt_this_is_not_a_valid_token_abcdef0123456789", "");
    REQUIRE(!validated.has_value());
    CHECK(validated.error().error == DeviceTokenValidateError::not_found);
    CHECK(validated.error().token_id.empty());
    CHECK(validated.error().bound_device_id.empty());
    CHECK(validated.error().bound_principal_id.empty());
}

TEST_CASE("DeviceTokenStore: empty token rejected", "[device_token][auth][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto validated = store.validate_token("", "");
    REQUIRE(!validated.has_value());
    CHECK(validated.error().error == DeviceTokenValidateError::invalid_input);
    CHECK(validated.error().token_id.empty());
}

TEST_CASE("DeviceTokenStore: expired token rejected", "[device_token][auth][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.create_token("Expired Token", "admin", "device-X", "", 1);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "device-X");
    REQUIRE(!validated.has_value());
    CHECK(validated.error().error == DeviceTokenValidateError::expired);
    CHECK(!validated.error().token_id.empty());
    CHECK(validated.error().bound_device_id == "device-X");
    CHECK(validated.error().bound_principal_id == "admin");
}

TEST_CASE("DeviceTokenStore: revoked token rejected", "[device_token][auth][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("Revocable", "admin", "device-R", "", 0);
    REQUIRE(raw.has_value());

    auto valid1 = store.validate_token(*raw, "device-R");
    REQUIRE(valid1.has_value());

    auto revoked = store.revoke_token(valid1->token_id);
    CHECK(revoked.has_value());

    auto valid2 = store.validate_token(*raw, "device-R");
    REQUIRE(!valid2.has_value());
    CHECK(valid2.error().error == DeviceTokenValidateError::revoked);
    CHECK(valid2.error().bound_device_id == "device-R");
    CHECK(valid2.error().bound_principal_id == "admin");
}

// ── List ──────────────────────────────────────────────────────────────────────

TEST_CASE("DeviceTokenStore: list tokens", "[device_token][crud][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create_token("Token A", "alice", "", "", 0).has_value());
    REQUIRE(store.create_token("Token B", "alice", "", "", 0).has_value());
    REQUIRE(store.create_token("Token C", "bob", "", "", 0).has_value());

    auto all = store.list_tokens();
    REQUIRE(all.has_value());
    CHECK(all->size() == 3);
}

TEST_CASE("DeviceTokenStore: list tokens with principal_id filter", "[device_token][crud][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create_token("Token A", "alice", "", "", 0).has_value());
    REQUIRE(store.create_token("Token B", "alice", "", "", 0).has_value());
    REQUIRE(store.create_token("Token C", "bob", "", "", 0).has_value());

    auto alice_tokens = store.list_tokens("alice");
    REQUIRE(alice_tokens.has_value());
    CHECK(alice_tokens->size() == 2);
    for (const auto& t : *alice_tokens)
        CHECK(t.principal_id == "alice");

    auto bob_tokens = store.list_tokens("bob");
    REQUIRE(bob_tokens.has_value());
    CHECK(bob_tokens->size() == 1);
    CHECK((*bob_tokens)[0].principal_id == "bob");
}

// ── Revoke edge cases ─────────────────────────────────────────────────────────

TEST_CASE("DeviceTokenStore: revoke non-existent is not_found", "[device_token][crud][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto revoked = store.revoke_token("nonexistent-token-id");
    REQUIRE_FALSE(revoked.has_value());
    CHECK(revoked.error().starts_with("not_found:"));
}

// ── W1.5 / #823 — revoke_by_principal ────────────────────────────────────────

TEST_CASE("DeviceTokenStore: revoke_by_principal revokes every still-valid token for the "
          "principal",
          "[device_token][823][crud][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto a1 = store.create_token("alice-1", "alice", "device-A1", "", 0);
    auto a2 = store.create_token("alice-2", "alice", "device-A2", "", 0);
    auto b1 = store.create_token("bob-1", "bob", "device-B1", "", 0);
    REQUIRE(a1.has_value());
    REQUIRE(a2.has_value());
    REQUIRE(b1.has_value());

    REQUIRE(store.validate_token(*a1, "device-A1").has_value());
    REQUIRE(store.validate_token(*a2, "device-A2").has_value());
    REQUIRE(store.validate_token(*b1, "device-B1").has_value());

    auto revoked = store.revoke_by_principal("alice");
    REQUIRE(revoked.has_value());
    CHECK(*revoked == 2);

    auto v1 = store.validate_token(*a1, "device-A1");
    REQUIRE(!v1.has_value());
    CHECK(v1.error().error == DeviceTokenValidateError::revoked);

    auto v2 = store.validate_token(*a2, "device-A2");
    REQUIRE(!v2.has_value());
    CHECK(v2.error().error == DeviceTokenValidateError::revoked);

    auto v3 = store.validate_token(*b1, "device-B1");
    REQUIRE(v3.has_value());
}

TEST_CASE("DeviceTokenStore: revoke_by_principal is idempotent and skips already-revoked rows",
          "[device_token][823][crud][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto t = store.create_token("only", "alice", "device-A", "", 0);
    REQUIRE(t.has_value());

    auto first = store.revoke_by_principal("alice");
    REQUIRE(first.has_value());
    CHECK(*first == 1);
    auto second = store.revoke_by_principal("alice");
    REQUIRE(second.has_value());
    CHECK(*second == 0);

    auto nobody = store.revoke_by_principal("nobody");
    REQUIRE(nobody.has_value());
    CHECK(*nobody == 0);

    // Empty principal is rejected at the wrapper — must not match historical rows that happen to
    // have an empty principal_id.
    auto empty = store.revoke_by_principal("");
    REQUIRE(empty.has_value());
    CHECK(*empty == 0);
}

// ── #3401 — revoke_by_device (the actual #823 sweep; discriminates from revoke_by_principal) ──

TEST_CASE("DeviceTokenStore: revoke_by_device revokes every still-valid token for the device, "
          "across different operators, and leaves other devices' tokens alone",
          "[device_token][823][3401][crud][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    // Two tokens for the SAME device, minted by DIFFERENT operators — the shape a
    // principal-keyed sweep can never revoke together, and the shape revoke_by_device must.
    auto a1 = store.create_token("alice-tok", "alice", "endpoint-99", "", 0);
    auto a2 = store.create_token("bob-tok", "bob", "endpoint-99", "", 0);
    // A token for a DIFFERENT device, same operator as one of the above — must survive.
    auto other = store.create_token("alice-other", "alice", "endpoint-7", "", 0);
    REQUIRE(a1.has_value());
    REQUIRE(a2.has_value());
    REQUIRE(other.has_value());

    REQUIRE(store.validate_token(*a1, "endpoint-99").has_value());
    REQUIRE(store.validate_token(*a2, "endpoint-99").has_value());
    REQUIRE(store.validate_token(*other, "endpoint-7").has_value());

    auto revoked = store.revoke_by_device("endpoint-99");
    REQUIRE(revoked.has_value());
    CHECK(*revoked == 2);

    auto v1 = store.validate_token(*a1, "endpoint-99");
    REQUIRE(!v1.has_value());
    CHECK(v1.error().error == DeviceTokenValidateError::revoked);
    CHECK(v1.error().bound_principal_id == "alice");

    auto v2 = store.validate_token(*a2, "endpoint-99");
    REQUIRE(!v2.has_value());
    CHECK(v2.error().error == DeviceTokenValidateError::revoked);
    CHECK(v2.error().bound_principal_id == "bob");

    // Untouched: same operator (alice) as a revoked token, but a different device.
    auto v3 = store.validate_token(*other, "endpoint-7");
    REQUIRE(v3.has_value());

    // The pre-#3401 bug, pinned as a regression check: sweeping by principal_id (an agent_id in
    // production) must NOT touch these rows — they were minted with principal_id="alice"/"bob",
    // never "endpoint-99".
    auto by_principal = store.revoke_by_principal("endpoint-99");
    REQUIRE(by_principal.has_value());
    CHECK(*by_principal == 0);
}

TEST_CASE("DeviceTokenStore: revoke_by_device is idempotent, skips already-revoked rows, and "
          "empty device_id is a no-op that never sweeps unbound tokens",
          "[device_token][823][3401][crud][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto t = store.create_token("only", "alice", "endpoint-99", "", 0);
    REQUIRE(t.has_value());
    // An intentionally unbound token (empty device_id) — must never be swept by an empty input.
    auto unbound = store.create_token("unbound", "alice", "", "", 0);
    REQUIRE(unbound.has_value());

    auto first = store.revoke_by_device("endpoint-99");
    REQUIRE(first.has_value());
    CHECK(*first == 1);
    auto second = store.revoke_by_device("endpoint-99");
    REQUIRE(second.has_value());
    CHECK(*second == 0);

    auto nobody = store.revoke_by_device("no-such-device");
    REQUIRE(nobody.has_value());
    CHECK(*nobody == 0);

    auto empty = store.revoke_by_device("");
    REQUIRE(empty.has_value());
    CHECK(*empty == 0);

    // The unbound token must have survived every call above, including the empty-string sweep.
    auto list = store.list_tokens();
    REQUIRE(list.has_value());
    bool unbound_still_present = false;
    for (const auto& tok : *list) {
        if (tok.name == "unbound") {
            unbound_still_present = true;
            CHECK_FALSE(tok.revoked);
        }
    }
    CHECK(unbound_still_present);
}

// ── Validate updates last_used_at ────────────────────────────────────────────

TEST_CASE("DeviceTokenStore: validate updates last_used_at", "[device_token][auth][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("Usage Token", "admin", "device-U", "", 0);
    REQUIRE(raw.has_value());

    auto before = store.list_tokens();
    REQUIRE(before.has_value());
    REQUIRE(before->size() == 1);
    CHECK((*before)[0].last_used_at == 0);

    auto validated = store.validate_token(*raw, "device-U");
    REQUIRE(validated.has_value());

    auto after = store.list_tokens();
    REQUIRE(after.has_value());
    REQUIRE(after->size() == 1);
    CHECK((*after)[0].last_used_at > 0);
}

// ── Scope fields ──────────────────────────────────────────────────────────────

TEST_CASE("DeviceTokenStore: device scope stored correctly", "[device_token][scope][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.create_token("Scoped Token", "admin", "device-42", "", 0);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "device-42");
    REQUIRE(validated.has_value());
    CHECK(validated->device_id == "device-42");
    CHECK(validated->definition_id.empty());
}

TEST_CASE("DeviceTokenStore: definition scope stored correctly", "[device_token][scope][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.create_token("Def Scoped Token", "admin", "device-D", "get-os-info", 0);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "device-D");
    REQUIRE(validated.has_value());
    CHECK(validated->device_id == "device-D");
    CHECK(validated->definition_id == "get-os-info");
}

TEST_CASE("DeviceTokenStore: both scopes stored correctly", "[device_token][scope][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto result =
        store.create_token("Dual Scoped Token", "admin", "device-99", "restart-service", 0);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "device-99");
    REQUIRE(validated.has_value());
    CHECK(validated->device_id == "device-99");
    CHECK(validated->definition_id == "restart-service");
}

// ── Expiration edge cases ────────────────────────────────────────────────────

TEST_CASE("DeviceTokenStore: non-expiring token (expires_at=0) is valid",
          "[device_token][auth][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.create_token("Perpetual Token", "admin", "device-P", "", 0);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "device-P");
    REQUIRE(validated.has_value());
    CHECK(validated->expires_at == 0);
}

TEST_CASE("DeviceTokenStore: future expiry token is valid", "[device_token][auth][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto future = now_epoch() + 86400 * 365; // 1 year from now
    auto result = store.create_token("Future Token", "admin", "device-F", "", future);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "device-F");
    REQUIRE(validated.has_value());
    CHECK(validated->expires_at == future);
}

// ── Binding enforcement (#824) — token presenter MUST equal token subject ──────

TEST_CASE("DeviceTokenStore: device-bound token accepted from matching presenter",
          "[device_token][binding][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("Bound", "admin", "device-A", "", 0);
    REQUIRE(raw.has_value());

    auto ok = store.validate_token(*raw, "device-A");
    REQUIRE(ok.has_value());
    CHECK(ok->device_id == "device-A");
}

TEST_CASE("DeviceTokenStore: device-bound token rejected from different presenter",
          "[device_token][binding][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("Bound", "admin", "device-A", "", 0);
    REQUIRE(raw.has_value());

    auto bad = store.validate_token(*raw, "device-B");
    REQUIRE(!bad.has_value());
    CHECK(bad.error().error == DeviceTokenValidateError::binding_mismatch);
    CHECK(bad.error().bound_device_id == "device-A");
    CHECK(bad.error().bound_principal_id == "admin");
    CHECK(!bad.error().token_id.empty());
}

TEST_CASE("DeviceTokenStore: device-bound token rejected when presenter empty",
          "[device_token][binding][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("Bound", "admin", "device-A", "", 0);
    REQUIRE(raw.has_value());

    auto bad = store.validate_token(*raw, "");
    REQUIRE(!bad.has_value());
    CHECK(bad.error().error == DeviceTokenValidateError::binding_mismatch);
    CHECK(bad.error().bound_device_id == "device-A");
    CHECK(bad.error().bound_principal_id == "admin");
}

TEST_CASE(
    "DeviceTokenStore: validate_token rejects unbound legacy token with unbound_legacy variant",
    "[device_token][binding][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("LegacyAny", "admin", "", "", 0);
    REQUIRE(raw.has_value());

    auto e = store.validate_token(*raw, "");
    REQUIRE(!e.has_value());
    CHECK(e.error().error == DeviceTokenValidateError::unbound_legacy);
    CHECK(e.error().bound_device_id.empty());
    CHECK(e.error().bound_principal_id == "admin");
    CHECK(!e.error().token_id.empty());

    auto a = store.validate_token(*raw, "device-A");
    REQUIRE(!a.has_value());
    CHECK(a.error().error == DeviceTokenValidateError::unbound_legacy);

    auto b = store.validate_token(*raw, "device-B");
    REQUIRE(!b.has_value());
    CHECK(b.error().error == DeviceTokenValidateError::unbound_legacy);
}

TEST_CASE("DeviceTokenStore: validate_token unbound_legacy precedes binding_mismatch and follows "
          "expired",
          "[device_token][binding][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto expired_raw = store.create_token("ExpiredLegacy", "admin", "", "", 1);
    REQUIRE(expired_raw.has_value());
    auto exp = store.validate_token(*expired_raw, "anything");
    REQUIRE(!exp.has_value());
    CHECK(exp.error().error == DeviceTokenValidateError::expired);

    auto legacy_raw = store.create_token("Legacy", "admin", "", "", 0);
    REQUIRE(legacy_raw.has_value());
    auto leg = store.validate_token(*legacy_raw, "device-X");
    REQUIRE(!leg.has_value());
    CHECK(leg.error().error == DeviceTokenValidateError::unbound_legacy);
}

TEST_CASE("DeviceTokenStore: binding_mismatch precedes neither expired nor revoked",
          "[device_token][binding][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("ExpiredBound", "admin", "device-A", "", 1);
    REQUIRE(raw.has_value());

    auto exp_ok = store.validate_token(*raw, "device-A");
    REQUIRE(!exp_ok.has_value());
    CHECK(exp_ok.error().error == DeviceTokenValidateError::expired);
    auto exp_bad = store.validate_token(*raw, "device-B");
    REQUIRE(!exp_bad.has_value());
    CHECK(exp_bad.error().error == DeviceTokenValidateError::expired);
}

// ── CSPRNG contract (#801) ────────────────────────────────────────────────────

TEST_CASE("DeviceTokenStore: consecutive tokens differ", "[device_token][csprng][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto a = store.create_token("A", "admin", "", "", 0);
    auto b = store.create_token("B", "admin", "", "", 0);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    CHECK(*a != *b);
}

TEST_CASE("DeviceTokenStore: 256 consecutive tokens are all unique", "[device_token][csprng][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    std::set<std::string> seen;
    for (int i = 0; i < 256; ++i) {
        auto r = store.create_token("bulk", "admin", "", "", 0);
        REQUIRE(r.has_value());
        CHECK(seen.insert(*r).second);
    }
    CHECK(seen.size() == 256);
}

TEST_CASE("DeviceTokenStore: token shape — 'ydt_' + 64 lowercase hex chars",
          "[device_token][csprng][format][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_token("Shape", "admin", "", "", 0);
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 68);
    CHECK(r->starts_with("ydt_"));
    for (std::size_t i = 4; i < r->size(); ++i) {
        char c = (*r)[i];
        CHECK(((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
    }
}
