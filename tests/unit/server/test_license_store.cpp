/**
 * test_license_store.cpp — `LicenseStore` (product license activation/entitlement,
 * capability 22.3, ADR-0048).
 *
 * **This store is deliberately DORMANT on `dev`** — nothing in `server.cpp` constructs a
 * `LicenseStore` (see license_store.hpp's file header). These tests exercise the store's public
 * API directly, exactly as `test_rest_api_t2.cpp`'s license-flow cases and a future re-wiring do.
 *
 * Covers:
 *  - fail-closed construction, both the migration-drift case (a live but unmigratable database)
 *    and the unreachable-pool case (mirrors test_deployment_store.cpp's two fail-closed cases).
 *  - activate_license validation (empty key, empty organization) and the atomic
 *    ON CONFLICT (license_key_hash) duplicate-key detection.
 *  - list_licenses / get_active_license: typed reads — a genuine DB error is distinguishable
 *    from "no licenses" (ADR-0036 program policy); get_active_license's `nullopt`-inside-
 *    `expected` double layer specifically.
 *  - remove_license: not-found vs success, atomic license+alerts delete.
 *  - validate(): expiry/seat-limit/warning alert generation, status transitions, one-transaction
 *    atomicity.
 *  - get_status / list_alerts / acknowledge_alert / has_feature / seat_count / days_remaining.
 *
 * Migrated-to-Postgres store (ADR-0012 §1, authoritative/fail-hard). PG-gated: skips when
 * YUZU_TEST_POSTGRES_DSN is unset, fails when set but broken (test_helpers.hpp skip-vs-fail
 * contract). Store-behaviour cases use the pre-migrated PgTestTemplate variant
 * (docs/postgres-store-playbook.md step 7); the two fail-closed cases use YUZU_REQUIRE_PG_DB / no
 * gate at all, per the plain-migration-test carve-out documented on that macro.
 *
 * migrate_from_sqlite backfill-contract coverage was retired 2026-08-25 (fresh-start-by-default,
 * ADR-0009 amendment); the method itself was retired 2026-09-02
 * (chore/retire-migrate-from-sqlite-batch-b, #3623) — this store had zero production callers to
 * begin with, so there was no live database to protect either way.
 */

#include "license_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <cstdint>
#include <future>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::License;
using yuzu::server::LicenseAlert;
using yuzu::server::LicenseStore;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
using yuzu::server::pg::PgTxn;

namespace {

yuzu::test::PgTestTemplate license_store_tpl{
    "licensestore", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        LicenseStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("license_store template: store failed to migrate");
    }};

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

License make_license(const std::string& org = "Acme Corp", int64_t seats = 100,
                     int64_t expires_at = 0, const std::string& edition = "enterprise",
                     const std::string& features =
                         R"(["admin_read","remote_execute","policy_engine"])") {
    License lic;
    lic.organization = org;
    lic.seat_count = seats;
    lic.expires_at = expires_at;
    lic.edition = edition;
    lic.features_json = features;
    return lic;
}

} // namespace

// ── Construction fail-closed ────────────────────────────────────────────────

TEST_CASE("LicenseStore reports !is_open on a migration failure", "[license_store][pg]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA license_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE license_store.licenses (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    LicenseStore store{pool};
    CHECK_FALSE(store.is_open());
}

TEST_CASE("LicenseStore reports !is_open on an unreachable pool, and every method fails closed",
          "[license_store]") {
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    LicenseStore store{pool};
    CHECK_FALSE(store.is_open());

    auto activate_res = store.activate_license(make_license(), "KEY-1");
    CHECK_FALSE(activate_res.has_value());
    CHECK(activate_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto list_res = store.list_licenses();
    CHECK_FALSE(list_res.has_value());
    CHECK(list_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto active_res = store.get_active_license();
    CHECK_FALSE(active_res.has_value());
    CHECK(active_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto remove_res = store.remove_license("x");
    CHECK_FALSE(remove_res.has_value());
    CHECK(remove_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto validate_res = store.validate(10);
    CHECK_FALSE(validate_res.has_value());
    CHECK(validate_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto status_res = store.get_status();
    CHECK_FALSE(status_res.has_value());
    CHECK(status_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto alerts_res = store.list_alerts();
    CHECK_FALSE(alerts_res.has_value());
    CHECK(alerts_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto ack_res = store.acknowledge_alert(1);
    CHECK_FALSE(ack_res.has_value());
    CHECK(ack_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto feat_res = store.has_feature("x");
    CHECK_FALSE(feat_res.has_value());
    CHECK(feat_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto seats_res = store.seat_count();
    CHECK_FALSE(seats_res.has_value());
    CHECK(seats_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto days_res = store.days_remaining();
    CHECK_FALSE(days_res.has_value());
    CHECK(days_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));
}

// ── activate_license / get_active_license round-trip ────────────────────────

TEST_CASE("activate_license validates key/organization before writing", "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    SECTION("empty key is rejected") {
        auto r = store.activate_license(make_license(), "");
        REQUIRE_FALSE(r.has_value());
    }
    SECTION("empty organization is rejected") {
        License lic;
        lic.organization = "";
        lic.seat_count = 50;
        auto r = store.activate_license(lic, "VALID-KEY-123");
        REQUIRE_FALSE(r.has_value());
    }
    SECTION("a valid activation round-trips through get_active_license") {
        auto future = now_epoch() + 86400 * 365;
        auto lic = make_license("Acme Corp", 100, future, "enterprise");
        auto result = store.activate_license(lic, "LICENSE-KEY-ABC123");
        REQUIRE(result.has_value());
        CHECK_FALSE(result->empty());

        auto active = store.get_active_license();
        REQUIRE(active.has_value());
        REQUIRE(active->has_value());
        CHECK((*active)->id == *result);
        CHECK((*active)->organization == "Acme Corp");
        CHECK((*active)->seat_count == 100);
        CHECK((*active)->edition == "enterprise");
        CHECK((*active)->status == "active");
        CHECK((*active)->expires_at == future);
    }
}

TEST_CASE("activate_license detects a duplicate key atomically", "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto lic = make_license();
    auto first = store.activate_license(lic, "SAME-KEY-ABC");
    REQUIRE(first.has_value());

    auto second = store.activate_license(lic, "SAME-KEY-ABC");
    CHECK_FALSE(second.has_value());
    CHECK(second.error() == "license key already activated");
    // A genuine business-rule rejection, never the db_error prefix (would misclassify as 503).
    CHECK_FALSE(second.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));
}

TEST_CASE("get_active_license: nullopt-inside-expected distinguishes 'none active' from a "
          "store failure",
          "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto active = store.get_active_license();
    REQUIRE(active.has_value()); // a genuine successful read of zero rows
    CHECK_FALSE(active->has_value());
}

// ── list_licenses / remove_license ───────────────────────────────────────────

TEST_CASE("list_licenses returns every license, empty when none exist", "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto empty = store.list_licenses();
    REQUIRE(empty.has_value());
    CHECK(empty->empty());

    REQUIRE(store.activate_license(make_license("Org A"), "KEY-A").has_value());
    REQUIRE(store.activate_license(make_license("Org B"), "KEY-B").has_value());

    auto list = store.list_licenses();
    REQUIRE(list.has_value());
    CHECK(list->size() == 2);
}

TEST_CASE("remove_license deletes the license and its alerts atomically, and reports "
          "not_found for an unknown id",
          "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    SECTION("removing an unknown id is not_found") {
        auto r = store.remove_license("nonexistent-id");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().starts_with("not_found:"));
    }
    SECTION("removing a real license clears it and its alerts") {
        auto past = now_epoch() - 86400;
        auto id = store.activate_license(make_license("Cleanup Org", 50, past), "KEY-CLEANUP");
        REQUIRE(id.has_value());
        REQUIRE(store.validate(10).has_value()); // generates an "expired" alert

        auto alerts_before = store.list_alerts();
        REQUIRE(alerts_before.has_value());
        CHECK_FALSE(alerts_before->empty());

        auto removed = store.remove_license(*id);
        CHECK(removed.has_value());

        auto list = store.list_licenses();
        REQUIRE(list.has_value());
        CHECK(list->empty());

        auto alerts_after = store.list_alerts();
        REQUIRE(alerts_after.has_value());
        CHECK(alerts_after->empty());

        auto active = store.get_active_license();
        REQUIRE(active.has_value());
        CHECK_FALSE(active->has_value());
    }
}

// ── validate() / get_status ───────────────────────────────────────────────

TEST_CASE("get_status reports the most recent license's status, or unlicensed",
          "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto none = store.get_status();
    REQUIRE(none.has_value());
    CHECK(*none == "unlicensed");

    auto future = now_epoch() + 86400 * 365;
    REQUIRE(store.activate_license(make_license("Acme", 100, future), "KEY-ACTIVE").has_value());

    auto active = store.get_status();
    REQUIRE(active.has_value());
    CHECK(*active == "active");
}

TEST_CASE("validate detects an expired license, updates status, and emits an alert",
          "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto past = now_epoch() - 86400;
    REQUIRE(
        store.activate_license(make_license("Expired Org", 50, past), "KEY-EXPIRED").has_value());

    REQUIRE(store.validate(10).has_value());

    auto status = store.get_status();
    REQUIRE(status.has_value());
    CHECK(*status == "expired");

    auto alerts = store.list_alerts();
    REQUIRE(alerts.has_value());
    CHECK_FALSE(alerts->empty());
    bool found_expired_alert = false;
    for (const auto& a : *alerts) {
        if (a.alert_type == "expired")
            found_expired_alert = true;
    }
    CHECK(found_expired_alert);
}

TEST_CASE("validate detects a seat-limit-exceeded license", "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto future = now_epoch() + 86400 * 365;
    REQUIRE(
        store.activate_license(make_license("Small Org", 10, future), "KEY-SEATS").has_value());

    REQUIRE(store.validate(15).has_value()); // 15 agents exceed the 10-seat limit

    auto status = store.get_status();
    REQUIRE(status.has_value());
    CHECK(*status == "exceeded");

    auto alerts = store.list_alerts();
    REQUIRE(alerts.has_value());
    bool found_exceeded = false;
    for (const auto& a : *alerts) {
        if (a.alert_type == "exceeded")
            found_exceeded = true;
    }
    CHECK(found_exceeded);
}

TEST_CASE("validate generates a near-expiry warning without changing status",
          "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto near_expiry = now_epoch() + 86400 * 15; // within the 30-day warning window
    REQUIRE(store.activate_license(make_license("Warning Org", 100, near_expiry), "KEY-NEAREXPIRY")
               .has_value());

    REQUIRE(store.validate(5).has_value());

    auto status = store.get_status();
    REQUIRE(status.has_value());
    CHECK(*status == "active");

    auto alerts = store.list_alerts();
    REQUIRE(alerts.has_value());
    bool found_warning = false;
    for (const auto& a : *alerts) {
        if (a.alert_type == "expiry_warning")
            found_warning = true;
    }
    CHECK(found_warning);
}

TEST_CASE("validate: calling twice in quick succession dedups the alert within 24h",
          "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto past = now_epoch() - 86400;
    REQUIRE(store.activate_license(make_license("Dedup Org", 50, past), "KEY-DEDUP").has_value());

    REQUIRE(store.validate(10).has_value());
    REQUIRE(store.validate(10).has_value());

    auto alerts = store.list_alerts();
    REQUIRE(alerts.has_value());
    int expired_count = 0;
    for (const auto& a : *alerts) {
        if (a.alert_type == "expired")
            ++expired_count;
    }
    CHECK(expired_count == 1);
}

TEST_CASE("validate: SELECT ... FOR UPDATE serializes overlapping status transitions "
          "(gov Gate 4 unhappy-path UP-1 regression)",
          "[license_store][pg][concurrency]") {
    // Defect this catches: without a row lock on the initial SELECT, two overlapping
    // validate() transactions (e.g. two server replicas sharing this Postgres) each read the
    // pre-transition status under their own snapshot and the later COMMIT silently clobbers
    // the earlier one's write with no error. Reproducing the exact lost-update byte-for-byte
    // needs precise interleaving this store has no clock-injection seam to control, so this
    // proves the mechanism directly instead: hold a manual row lock open on a second raw
    // connection, confirm a concurrent validate() call blocks for as long as the lock is
    // held, then confirm it completes correctly once released — the observable behaviour
    // FOR UPDATE is responsible for.
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto future = now_epoch() + 86400 * 365;
    REQUIRE(store.activate_license(make_license("Lock Org", 10, future), "KEY-LOCK").has_value());
    // Establish the row as 'active' before contending for its lock.
    REQUIRE(store.validate(5).has_value());
    REQUIRE(*store.get_status() == "active");

    // Hold a manual FOR UPDATE lock on the license row from a second raw connection.
    PgPool::Lease locker = pool.acquire();
    REQUIRE(locker);
    PgResult begin{PQexec(locker.get(), "BEGIN")};
    REQUIRE(begin.ok());
    // PgTxn (defense-in-depth per gov Gate 8 cpp-safety SHOULD): rolls back on any exception
    // anywhere below, rather than relying solely on PgPool::release()'s own fallback rollback
    // for a not-PQTRANS_IDLE connection.
    PgTxn locker_txn{locker.get()};
    PgResult lock{PQexec(locker.get(), "SELECT id FROM license_store.licenses "
                                       "WHERE status = 'active' FOR UPDATE")};
    REQUIRE(lock.ok());

    std::promise<std::expected<void, std::string>> result_promise;
    auto result_future = result_promise.get_future();
    std::thread validator([&] {
        result_promise.set_value(store.validate(15)); // 15 exceeds the 10-seat limit
    });
    // Gov Gate 8 cpp-safety (BLOCKING, policy floor): a bare std::thread left joinable when a
    // REQUIRE between here and the explicit join() throws (Catch2 unwinds via exception) calls
    // std::terminate() in ~thread(), crashing the whole test binary instead of failing red.
    // Not std::jthread — that exact substitution broke Apple Clang's libc++ once already in
    // this codebase (CLAUDE.md Gate 8 history) — a plain RAII join-guard is portable.
    struct JoinGuard {
        std::thread& t;
        ~JoinGuard() {
            if (t.joinable())
                t.join();
        }
    } join_guard{validator};

    // The concurrent validate() must still be blocked on the row lock — it must NOT have
    // raced ahead and read/written the row while the manual lock is held.
    CHECK(result_future.wait_for(std::chrono::milliseconds(300)) != std::future_status::ready);

    REQUIRE(locker_txn.commit());

    REQUIRE(result_future.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    REQUIRE(result_future.get().has_value());

    auto status = store.get_status();
    REQUIRE(status.has_value());
    CHECK(*status == "exceeded");
}

// ── Alerts ────────────────────────────────────────────────────────────────

TEST_CASE("acknowledge_alert flips the flag and is excluded from the unacknowledged filter",
          "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto past = now_epoch() - 86400;
    REQUIRE(store.activate_license(make_license("Ack Org", 50, past), "KEY-ACK").has_value());
    REQUIRE(store.validate(10).has_value());

    auto alerts = store.list_alerts();
    REQUIRE(alerts.has_value());
    REQUIRE_FALSE(alerts->empty());
    auto alert_id = (*alerts)[0].id;
    CHECK_FALSE((*alerts)[0].acknowledged);

    auto acked = store.acknowledge_alert(alert_id);
    CHECK(acked.has_value());

    auto unacked = store.list_alerts(true);
    REQUIRE(unacked.has_value());
    for (const auto& a : *unacked)
        CHECK(a.id != alert_id);

    auto all = store.list_alerts(false);
    REQUIRE(all.has_value());
    bool found = false;
    for (const auto& a : *all) {
        if (a.id == alert_id) {
            CHECK(a.acknowledged);
            found = true;
        }
    }
    CHECK(found);
}

TEST_CASE("acknowledge_alert on an unknown id is not_found", "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.acknowledge_alert(99999);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().starts_with("not_found:"));
}

// ── Feature / seat / expiry checks ──────────────────────────────────────────

TEST_CASE("has_feature matches exactly, never a substring or superstring",
          "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto future = now_epoch() + 86400 * 365;
    REQUIRE(store.activate_license(
                       make_license("Acme", 100, future, "enterprise", R"(["admin_read"])"),
                       "KEY-PARTIAL")
               .has_value());

    auto admin = store.has_feature("admin");
    REQUIRE(admin.has_value());
    CHECK_FALSE(*admin);
    auto admin_rw = store.has_feature("admin_read_write");
    REQUIRE(admin_rw.has_value());
    CHECK_FALSE(*admin_rw);
    auto admin_read = store.has_feature("admin_read");
    REQUIRE(admin_read.has_value());
    CHECK(*admin_read);
}

TEST_CASE("has_feature: empty feature and no license both report false, not an error",
          "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto empty_feature = store.has_feature("");
    REQUIRE(empty_feature.has_value());
    CHECK_FALSE(*empty_feature);

    auto no_license = store.has_feature("some_feature");
    REQUIRE(no_license.has_value());
    CHECK_FALSE(*no_license);
}

TEST_CASE("seat_count and days_remaining", "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    SECTION("seat_count with no license is 0") {
        auto s = store.seat_count();
        REQUIRE(s.has_value());
        CHECK(*s == 0);
    }
    SECTION("seat_count reflects the active license") {
        auto future = now_epoch() + 86400 * 365;
        REQUIRE(
            store.activate_license(make_license("Acme", 250, future), "KEY-SEATS250").has_value());
        auto s = store.seat_count();
        REQUIRE(s.has_value());
        CHECK(*s == 250);
    }
    SECTION("days_remaining for a fixed-term license") {
        auto expires = now_epoch() + 86400 * 90; // exactly 90 days
        REQUIRE(store.activate_license(make_license("Acme", 100, expires), "KEY-90DAYS")
                   .has_value());
        auto d = store.days_remaining();
        REQUIRE(d.has_value());
        CHECK(*d >= 89); // 1-day tolerance for timing edge cases
        CHECK(*d <= 90);
    }
    SECTION("days_remaining for a perpetual license is 0") {
        REQUIRE(store.activate_license(make_license("Acme", 100, 0), "KEY-PERPETUAL")
                   .has_value());
        auto d = store.days_remaining();
        REQUIRE(d.has_value());
        CHECK(*d == 0);
    }
    SECTION("days_remaining with no license is 0") {
        auto d = store.days_remaining();
        REQUIRE(d.has_value());
        CHECK(*d == 0);
    }
}
