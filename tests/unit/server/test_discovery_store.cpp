/**
 * test_discovery_store.cpp — `DiscoveryStore` (network-discovered devices,
 * Issue 7.18). Migrated Postgres store (ADR-0006/0009, schema
 * `discovery_store`).
 *
 * Covers:
 *  - upsert ON CONFLICT semantics: mac_address/last_seen/subnet always
 *    refresh; hostname refreshes only when the new value is non-empty;
 *    discovered_at/discovered_by/managed/agent_id are untouched by a re-scan.
 *  - list_devices: all devices and subnet-filtered, newest-last-seen-first.
 *  - get_device: found, genuinely-absent (nullopt value, not an error), and
 *    empty ip_address (precondition miss, not a store failure).
 *  - mark_managed: success and not_found: prefix on an unknown ip_address.
 *  - clear_results: all rows and subnet-scoped.
 *  - fail-closed construction (migration-drift case).
 *
 * No legacy-SQLite backfill test coverage: the dedicated [backfill] TEST_CASE
 * suite (2026-08-25) was removed as part of a fresh-start-by-default policy
 * change (ADR-0009 amendment) — no production fleet has ever run a
 * pre-Postgres build. DiscoveryStore::migrate_from_sqlite() itself was
 * retired (chore/retire-migrate-from-sqlite-batch-b, #3623).
 *
 * Migrated Postgres store (ADR-0044, authoritative/fail-hard per ADR-0012
 * §1). PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails when set
 * but broken (test_helpers.hpp skip-vs-fail contract). Store-behaviour cases
 * use the pre-migrated PgTestTemplate variant
 * (docs/postgres-store-playbook.md step 7); the fail-closed construction
 * case uses plain YUZU_REQUIRE_PG_DB, per the plain-migration-test carve-out
 * documented on that macro.
 */

#include "discovery_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "utf8_sanitize.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::DiscoveredDevice;
using yuzu::server::DiscoveryStore;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

yuzu::test::PgTestTemplate discovery_tpl{"discoverystore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    DiscoveryStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("discovery_store template: store failed to migrate");
}};

DiscoveredDevice make_device(const std::string& ip, const std::string& subnet = "10.0.0.0/24") {
    DiscoveredDevice d;
    d.ip_address = ip;
    d.mac_address = "aa:bb:cc:dd:ee:ff";
    d.hostname = "host-" + ip;
    d.discovered_by = "agent-scanner";
    d.subnet = subnet;
    return d;
}

const DiscoveredDevice* find(const std::vector<DiscoveredDevice>& v, const std::string& ip) {
    for (const auto& d : v)
        if (d.ip_address == ip)
            return &d;
    return nullptr;
}

} // namespace

// ── Construction fail-closed ────────────────────────────────────────────────

TEST_CASE("DiscoveryStore: construction fails closed on migration drift", "[pg][discovery]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);

    // Pre-seed: create the discovery_store schema + a conflicting table, but
    // no public.schema_meta row — the drift guard refuses (version 0 but
    // tables exist).
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA discovery_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE discovery_store.discovered_devices (bogus int)")};
        REQUIRE(t.ok());
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    DiscoveryStore store{pool};
    CHECK_FALSE(store.is_open()); // → server.cpp sets startup_failed_ = true
}

// ── CRUD ─────────────────────────────────────────────────────────────────────

TEST_CASE("DiscoveryStore: upsert and list/get", "[pg][discovery][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, discovery_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DiscoveryStore store{pool};
    REQUIRE(store.is_open());

    SECTION("upsert then list finds the device") {
        auto d = make_device("10.0.0.5");
        REQUIRE(store.upsert_device(d));

        auto rows = store.list_devices();
        REQUIRE(rows.has_value());
        const auto* found = find(*rows, "10.0.0.5");
        REQUIRE(found != nullptr);
        CHECK(found->mac_address == "aa:bb:cc:dd:ee:ff");
        CHECK(found->hostname == "host-10.0.0.5");
        CHECK(found->subnet == "10.0.0.0/24");
        CHECK(found->managed == false);
        CHECK(found->discovered_at > 0);
        CHECK(found->last_seen > 0);
    }

    SECTION("an explicit discovered_at in the past does not also skew last_seen") {
        // Regression: discovered_at and last_seen must bind as SEPARATE
        // parameters. A caller-supplied discovered_at far in the past must
        // not leak into last_seen (which is always "now" on every call,
        // independent of discovered_at).
        auto d = make_device("10.0.0.8");
        d.discovered_at = 1000; // a fixed, clearly-in-the-past epoch second
        REQUIRE(store.upsert_device(d));

        auto got = store.get_device("10.0.0.8");
        REQUIRE(got.has_value());
        REQUIRE(got->has_value());
        CHECK((*got)->discovered_at == 1000);
        CHECK((*got)->last_seen > 1000); // last_seen tracks "now", not discovered_at
    }

    SECTION("a fresh insert honors caller-supplied managed/agent_id") {
        // Regression: managed/agent_id must be part of the INSERT column
        // list — the "untouched by a re-scan" ON CONFLICT guarantee applies
        // only to an ALREADY-EXISTING row, never to a device's first insert.
        auto d = make_device("10.0.0.9");
        d.managed = true;
        d.agent_id = "agent-preexisting";
        REQUIRE(store.upsert_device(d));

        auto got = store.get_device("10.0.0.9");
        REQUIRE(got.has_value());
        REQUIRE(got->has_value());
        CHECK((*got)->managed == true);
        CHECK((*got)->agent_id == "agent-preexisting");
    }

    SECTION("upsert on same ip_address overwrites mac/last_seen/subnet, preserves discovered_at") {
        auto first = make_device("10.0.0.6");
        REQUIRE(store.upsert_device(first));
        auto after_first = store.get_device("10.0.0.6");
        REQUIRE(after_first.has_value());
        REQUIRE(after_first->has_value());
        const auto discovered_at_1 = (*after_first)->discovered_at;

        auto second = make_device("10.0.0.6", "10.0.1.0/24");
        second.mac_address = "11:22:33:44:55:66";
        REQUIRE(store.upsert_device(second));

        auto rows = store.list_devices();
        REQUIRE(rows.has_value());
        const auto* found = find(*rows, "10.0.0.6");
        REQUIRE(found != nullptr);
        CHECK(found->mac_address == "11:22:33:44:55:66");
        CHECK(found->subnet == "10.0.1.0/24");
        // Exactly one row (PK conflict updated in place, not a new row).
        int count = 0;
        for (const auto& r : *rows)
            if (r.ip_address == "10.0.0.6")
                ++count;
        CHECK(count == 1);
        // discovered_at is first-seen, untouched by the re-scan.
        CHECK(found->discovered_at == discovered_at_1);
    }

    SECTION("upsert with empty hostname does not blank out a previously known one") {
        auto first = make_device("10.0.0.7");
        first.hostname = "known-host";
        REQUIRE(store.upsert_device(first));

        auto second = make_device("10.0.0.7");
        second.hostname = ""; // scan could not resolve a hostname this time
        REQUIRE(store.upsert_device(second));

        auto got = store.get_device("10.0.0.7");
        REQUIRE(got.has_value());
        REQUIRE(got->has_value());
        CHECK((*got)->hostname == "known-host");
    }

    SECTION("upsert with empty ip_address is rejected") {
        DiscoveredDevice d;
        d.ip_address = "";
        auto r = store.upsert_device(d);
        CHECK_FALSE(r.has_value());
    }

    SECTION("list_devices filters by subnet") {
        REQUIRE(store.upsert_device(make_device("10.0.2.1", "10.0.2.0/24")));
        REQUIRE(store.upsert_device(make_device("10.0.3.1", "10.0.3.0/24")));

        auto filtered = store.list_devices("10.0.2.0/24");
        REQUIRE(filtered.has_value());
        CHECK(find(*filtered, "10.0.2.1") != nullptr);
        CHECK(find(*filtered, "10.0.3.1") == nullptr);
    }

    SECTION("get_device on a genuinely absent ip_address returns a value holding nullopt") {
        auto got = store.get_device("192.168.99.99");
        REQUIRE(got.has_value()); // the READ succeeded
        CHECK_FALSE(got->has_value()); // ...it just found nothing
    }

    SECTION("get_device with empty ip_address returns nullopt without a store round-trip") {
        auto got = store.get_device("");
        REQUIRE(got.has_value());
        CHECK_FALSE(got->has_value());
    }
}

TEST_CASE("DiscoveryStore: mark_managed", "[pg][discovery][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, discovery_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DiscoveryStore store{pool};
    REQUIRE(store.is_open());

    SECTION("marks an existing device managed") {
        REQUIRE(store.upsert_device(make_device("10.0.4.1")));
        REQUIRE(store.mark_managed("10.0.4.1", "agent-123"));

        auto got = store.get_device("10.0.4.1");
        REQUIRE(got.has_value());
        REQUIRE(got->has_value());
        CHECK((*got)->managed == true);
        CHECK((*got)->agent_id == "agent-123");
    }

    SECTION("unknown ip_address reports not_found") {
        auto r = store.mark_managed("10.0.4.99", "agent-x");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().starts_with("not_found:"));
    }

    SECTION("a re-scan after mark_managed does not clear managed/agent_id") {
        REQUIRE(store.upsert_device(make_device("10.0.4.2")));
        REQUIRE(store.mark_managed("10.0.4.2", "agent-456"));
        REQUIRE(store.upsert_device(make_device("10.0.4.2")));

        auto got = store.get_device("10.0.4.2");
        REQUIRE(got.has_value());
        REQUIRE(got->has_value());
        CHECK((*got)->managed == true);
        CHECK((*got)->agent_id == "agent-456");
    }
}

TEST_CASE("DiscoveryStore: clear_results", "[pg][discovery][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, discovery_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DiscoveryStore store{pool};
    REQUIRE(store.is_open());

    SECTION("clears one subnet only") {
        REQUIRE(store.upsert_device(make_device("10.0.5.1", "10.0.5.0/24")));
        REQUIRE(store.upsert_device(make_device("10.0.6.1", "10.0.6.0/24")));
        REQUIRE(store.clear_results("10.0.5.0/24"));

        auto rows = store.list_devices();
        REQUIRE(rows.has_value());
        CHECK(find(*rows, "10.0.5.1") == nullptr);
        CHECK(find(*rows, "10.0.6.1") != nullptr);
    }

    SECTION("clears everything when no subnet given") {
        REQUIRE(store.upsert_device(make_device("10.0.7.1")));
        REQUIRE(store.upsert_device(make_device("10.0.7.2")));
        REQUIRE(store.clear_results());

        auto rows = store.list_devices();
        REQUIRE(rows.has_value());
        CHECK(find(*rows, "10.0.7.1") == nullptr);
        CHECK(find(*rows, "10.0.7.2") == nullptr);
    }
}
