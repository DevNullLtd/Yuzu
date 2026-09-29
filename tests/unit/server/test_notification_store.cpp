/**
 * test_notification_store.cpp -- Unit tests for NotificationStore
 * (Postgres-backed, ADR-0006 Wave 2 migration, schema `notification_store`).
 *
 * Covers: lifecycle, create/list_unread/list_all/mark_read/dismiss/
 * count_unread.
 *
 * No legacy-SQLite backfill test coverage: the dedicated migrate_from_sqlite
 * TEST_CASE suite was removed as part of a fresh-start-by-default policy
 * change (ADR-0009 amendment) -- no production fleet has ever run a
 * pre-Postgres build. NotificationStore::migrate_from_sqlite() itself was
 * retired (chore/retire-migrate-from-sqlite-batch-b, #3623).
 */

#include "notification_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
namespace pg = yuzu::server::pg;
using yuzu::server::pg::PgPool;

namespace {

// Pre-migrated template (docs/postgres-store-playbook.md step 7). Every
// store-behaviour case clones this instead of re-migrating per test.
yuzu::test::PgTestTemplate notif_tpl{"notifstore", [](const std::string& dsn) {
                                         PgPool pool{{.conninfo = dsn, .size = 1}};
                                         NotificationStore store{pool};
                                         if (!store.is_open())
                                             throw std::runtime_error(
                                                 "notification template: store failed to migrate");
                                     }};

} // namespace

// Fixture: a fresh cloned PG database, a pool, and an open NotificationStore.
// Expands to statements (includes the SKIP-if-no-DSN guard), so it must lead
// a block. The db/pool must outlive `store_var`; declaring all three here
// keeps that order.
#define NOTIFICATION_STORE(store_var)                                                             \
    YUZU_REQUIRE_PG_DB_TPL(notif_db_fx_, notif_tpl);                                               \
    PgPool notif_pool_fx_{{.conninfo = notif_db_fx_.dsn(), .size = 4}};                            \
    REQUIRE(notif_pool_fx_.valid());                                                               \
    NotificationStore store_var{notif_pool_fx_};                                                   \
    REQUIRE(store_var.is_open())

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("NotificationStore: migrates and opens", "[notification_store][pg]") {
    NOTIFICATION_STORE(store);
    CHECK(store.list_all().empty());
}

// ── Create and retrieve ────────────────────────────────────────────────────

TEST_CASE("NotificationStore: create and list_unread", "[notification_store][pg]") {
    NOTIFICATION_STORE(store);

    auto id = store.create("info", "Agent connected", "Agent abc123 registered successfully");
    REQUIRE(id > 0);

    auto unread = store.list_unread();
    REQUIRE(unread.size() == 1);
    CHECK(unread[0].id == id);
    CHECK(unread[0].level == "info");
    CHECK(unread[0].title == "Agent connected");
    CHECK(unread[0].message == "Agent abc123 registered successfully");
    CHECK(unread[0].read == false);
    CHECK(unread[0].dismissed == false);
    CHECK(unread[0].timestamp > 0);
}

// ── Multiple notifications ─────────────────────────────────────────────────

TEST_CASE("NotificationStore: multiple creates and list_all", "[notification_store][pg]") {
    NOTIFICATION_STORE(store);

    store.create("info", "First", "First message");
    store.create("warn", "Second", "Second message");
    store.create("error", "Third", "Third message");

    auto all = store.list_all();
    REQUIRE(all.size() == 3);
    // Newest first (ORDER BY ts_ms DESC, id DESC — inserted in this order,
    // same-millisecond ties broken by id).
    CHECK(all[0].title == "Third");
    CHECK(all[2].title == "First");
}

// ── Mark read ──────────────────────────────────────────────────────────────

TEST_CASE("NotificationStore: mark_read removes from unread", "[notification_store][pg]") {
    NOTIFICATION_STORE(store);

    auto id = store.create("info", "Test", "Test notification");
    REQUIRE(store.count_unread() == 1);

    CHECK(store.mark_read(id));

    auto unread = store.list_unread();
    CHECK(unread.empty());
    CHECK(store.count_unread() == 0);

    // Should still appear in list_all.
    auto all = store.list_all();
    REQUIRE(all.size() == 1);
    CHECK(all[0].read == true);
}

// ── Dismiss ────────────────────────────────────────────────────────────────

TEST_CASE("NotificationStore: dismiss removes from unread", "[notification_store][pg]") {
    NOTIFICATION_STORE(store);

    auto id = store.create("warn", "Alert", "Something happened");
    REQUIRE(store.count_unread() == 1);

    CHECK(store.dismiss(id));

    CHECK(store.count_unread() == 0);
    auto unread = store.list_unread();
    CHECK(unread.empty());
}

// Regression test for the fixed audit-integrity defect (adversarial-review,
// fjarvis): mark_read/dismiss must report whether the write actually
// affected a row, not just that the statement executed — an UPDATE against
// a nonexistent id returns PGRES_COMMAND_OK either way, and the REST layer
// relies on this return value to avoid asserting a "success" audit row for
// a mutation that never landed.
TEST_CASE("NotificationStore: mark_read and dismiss report false for a nonexistent id",
          "[notification_store][pg]") {
    NOTIFICATION_STORE(store);

    auto id = store.create("info", "Real notification", "exists");
    REQUIRE(id > 0);
    const int64_t bogus_id = id + 999999;

    CHECK_FALSE(store.mark_read(bogus_id));
    CHECK_FALSE(store.dismiss(bogus_id));

    // The real row is untouched by either no-op call.
    CHECK(store.count_unread() == 1);
    auto all = store.list_all();
    REQUIRE(all.size() == 1);
    CHECK(all[0].read == false);
    CHECK(all[0].dismissed == false);
}

// ── Count unread ───────────────────────────────────────────────────────────

TEST_CASE("NotificationStore: count_unread tracks correctly", "[notification_store][pg]") {
    NOTIFICATION_STORE(store);

    CHECK(store.count_unread() == 0);

    auto id1 = store.create("info", "A", "msg");
    auto id2 = store.create("info", "B", "msg");
    store.create("error", "C", "msg");

    CHECK(store.count_unread() == 3);

    CHECK(store.mark_read(id1));
    CHECK(store.count_unread() == 2);

    CHECK(store.dismiss(id2));
    CHECK(store.count_unread() == 1);
}

// ── Empty store ────────────────────────────────────────────────────────────

TEST_CASE("NotificationStore: empty store returns empty lists", "[notification_store][pg]") {
    NOTIFICATION_STORE(store);

    CHECK(store.list_unread().empty());
    CHECK(store.list_all().empty());
    CHECK(store.count_unread() == 0);
}
