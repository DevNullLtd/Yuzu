/**
 * test_software_collection_settings_store.cpp - SoftwareCollectionSettingsStore (born-on-Postgres,
 * schema `software_collection_settings_store`): migration, conditional writes (create-only,
 * version-guarded replace, never last-writer-wins), the timezone existence check, the count-bounded
 * history, the read rule (a corrupt row vs a missing known key read as the fleet default), the list
 * cap and the failure channel (a held pool is Unavailable, never "no document").
 */

#include "software_collection_settings_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <chrono>
#include <stdexcept>
#include <string>

using namespace yuzu::server;
namespace cs = yuzu::server::collection_settings;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
using Kind = SoftwareCollectionSettingsStore::Error::Kind;

namespace {

yuzu::test::PgTestTemplate settings_tpl{"collectionsettings", [](const std::string& dsn) {
                                            PgPool pool{{.conninfo = dsn, .size = 1}};
                                            SoftwareCollectionSettingsStore store{pool};
                                            if (!store.is_open())
                                                throw std::runtime_error(
                                                    "collection settings template: store failed "
                                                    "to migrate");
                                        }};

const std::string kRoot{cs::kRootGroupId};
const std::string kGroupA = "aaaa11112222";

cs::CollectionSettings make(int interval = 86400, int priority = 0, std::string tz = "") {
    cs::CollectionSettings s = cs::kFleetDefault;
    s.interval_s = interval;
    s.window = std::nullopt;
    s.timezone = std::move(tz);
    s.priority = priority;
    return s;
}

// Direct SQL against the clone for the shapes the store API cannot produce.
void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQerrorMessage(conn.get()));
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

std::string scalar(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(r.get()) == 1);
    return PQgetvalue(r.get(), 0, 0);
}

const std::string kInsertRow =
    "INSERT INTO software_collection_settings_store.settings (group_id, interval_s, plugins_json, "
    "version, updated_at) VALUES ('aaaa11112222', 86400, '%s', 'v', 1)";

std::string insert_with_plugins(const std::string& plugins) {
    std::string sql = kInsertRow;
    sql.replace(sql.find("%s"), 2, plugins);
    return sql;
}

} // namespace

#define SETTINGS_STORE(store_var)                                                                  \
    YUZU_REQUIRE_PG_DB_TPL(settings_db_fx_, settings_tpl);                                         \
    PgPool settings_pool_fx_{{.conninfo = settings_db_fx_.dsn(), .size = 2}};                      \
    REQUIRE(settings_pool_fx_.valid());                                                            \
    SoftwareCollectionSettingsStore store_var{settings_pool_fx_};                                  \
    REQUIRE(store_var.is_open())

TEST_CASE("SoftwareCollectionSettingsStore: migration creates both tables and is a no-op twice",
          "[pg][store][collection_settings][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    SoftwareCollectionSettingsStore store{pool};
    REQUIRE(store.is_open());
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM information_schema.tables WHERE table_schema = "
                           "'software_collection_settings_store'") == "2");
    CHECK(scalar(db.dsn(), "SELECT version FROM public.schema_meta WHERE store = "
                           "'software_collection_settings_store'") == "1");
    SoftwareCollectionSettingsStore again{pool};
    CHECK(again.is_open());
}

TEST_CASE("SoftwareCollectionSettingsStore: an unknown group reads as nullopt, not an error",
          "[pg][store][collection_settings]") {
    SETTINGS_STORE(store);
    const auto got = store.get(kGroupA);
    REQUIRE(got.has_value());
    CHECK_FALSE(got->has_value());
}

TEST_CASE("SoftwareCollectionSettingsStore: create stores the document with its version and DB time",
          "[pg][store][collection_settings]") {
    SETTINGS_STORE(store);
    const auto s = make(7200, 3);
    const auto put = store.put(kGroupA, s, std::nullopt, "alice");
    REQUIRE(put.has_value());
    CHECK_FALSE(put->previous.has_value());
    CHECK(put->stored.version == *cs::document_version(s));
    CHECK(put->stored.updated_by == "alice");
    CHECK(put->stored.updated_at > 1'700'000'000);
    const auto got = store.get(kGroupA);
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->settings == s);
    CHECK((*got)->version == put->stored.version);
}

TEST_CASE("SoftwareCollectionSettingsStore: create when a row exists is a Conflict carrying it",
          "[pg][store][collection_settings]") {
    SETTINGS_STORE(store);
    const auto first = store.put(kGroupA, make(7200), std::nullopt, "alice");
    REQUIRE(first.has_value());
    const auto second = store.put(kGroupA, make(10800), std::nullopt, "bob");
    REQUIRE_FALSE(second.has_value());
    CHECK(second.error().kind == Kind::Conflict);
    REQUIRE(second.error().current.has_value());
    CHECK(second.error().current->version == first->stored.version);
    // The winner is untouched and only its own history row exists.
    CHECK(store.get(kGroupA)->value().settings.interval_s == 7200);
    CHECK(store.list_history(kGroupA, 10)->size() == 1);
}

TEST_CASE("SoftwareCollectionSettingsStore: replace needs the stored version",
          "[pg][store][collection_settings]") {
    SETTINGS_STORE(store);
    SECTION("a version for a row that does not exist is a Conflict with no current") {
        const auto r = store.put(kGroupA, make(), std::string(64, 'a'), "alice");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == Kind::Conflict);
        CHECK_FALSE(r.error().current.has_value());
    }
    SECTION("a stale version is a Conflict and the row is unchanged") {
        const auto first = store.put(kGroupA, make(7200), std::nullopt, "alice");
        REQUIRE(first.has_value());
        const auto r = store.put(kGroupA, make(10800), std::string(64, 'b'), "bob");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == Kind::Conflict);
        REQUIRE(r.error().current.has_value());
        CHECK(r.error().current->version == first->stored.version);
        CHECK(store.get(kGroupA)->value().settings.interval_s == 7200);
    }
    SECTION("the right version replaces and returns the previous row") {
        const auto first = store.put(kGroupA, make(7200), std::nullopt, "alice");
        REQUIRE(first.has_value());
        const auto r = store.put(kGroupA, make(10800), first->stored.version, "bob");
        REQUIRE(r.has_value());
        REQUIRE(r->previous.has_value());
        CHECK(r->previous->version == first->stored.version);
        CHECK(r->stored.settings.interval_s == 10800);
        CHECK(r->stored.version != first->stored.version);
        // The old version is stale.
        const auto again = store.put(kGroupA, make(14400), first->stored.version, "bob");
        REQUIRE_FALSE(again.has_value());
        CHECK(again.error().kind == Kind::Conflict);
    }
}

TEST_CASE("SoftwareCollectionSettingsStore: a priority-only change changes the version",
          "[pg][store][collection_settings]") {
    SETTINGS_STORE(store);
    const auto first = store.put(kGroupA, make(7200, 1), std::nullopt, "alice");
    REQUIRE(first.has_value());
    const auto r = store.put(kGroupA, make(7200, 2), first->stored.version, "alice");
    REQUIRE(r.has_value());
    CHECK(r->stored.version != first->stored.version);
    // A second writer holding the old version loses.
    const auto loser = store.put(kGroupA, make(7200, 9), first->stored.version, "bob");
    REQUIRE_FALSE(loser.has_value());
    CHECK(loser.error().kind == Kind::Conflict);
}

TEST_CASE("SoftwareCollectionSettingsStore: invalid documents are refused without running SQL",
          "[pg][store][collection_settings]") {
    SETTINGS_STORE(store);
    SECTION("the root group takes no priority") {
        const auto r = store.put(kRoot, make(86400, 1), std::nullopt, "alice");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == Kind::InvalidInput);
        CHECK_FALSE(store.get(kRoot)->has_value());
        CHECK(store.put(kRoot, make(86400, 0), std::nullopt, "alice").has_value());
    }
    SECTION("an out-of-range interval") {
        const auto r = store.put(kGroupA, make(60), std::nullopt, "alice");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == Kind::InvalidInput);
    }
    SECTION("a group id that is not lowercase hex") {
        const auto r = store.put("NOT-HEX", make(), std::nullopt, "alice");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == Kind::InvalidInput);
    }
    SECTION("a malformed expected version") {
        const auto r = store.put(kGroupA, make(), std::string("short"), "alice");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == Kind::InvalidInput);
    }
}

TEST_CASE("SoftwareCollectionSettingsStore: the timezone must exist in the database",
          "[pg][store][collection_settings]") {
    SETTINGS_STORE(store);
    SECTION("a real zone is accepted") {
        CHECK(store.put(kGroupA, make(86400, 0, "Europe/London"), std::nullopt, "alice")
                  .has_value());
    }
    SECTION("a well-formed unknown zone is refused and leaves no row or history") {
        const auto r = store.put(kGroupA, make(86400, 0, "Mars/Olympus"), std::nullopt, "alice");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == Kind::InvalidTimezone);
        CHECK_FALSE(store.get(kGroupA)->has_value());
        CHECK(store.list_history(kGroupA, 10)->empty());
    }
}

TEST_CASE("SoftwareCollectionSettingsStore: history keeps one row per save, bounded to the newest 200",
          "[pg][store][collection_settings]") {
    SETTINGS_STORE(store);
    auto put = store.put(kGroupA, make(3600), std::nullopt, "alice");
    REQUIRE(put.has_value());
    {
        const auto h = store.list_history(kGroupA, 10);
        REQUIRE(h.has_value());
        REQUIRE(h->size() == 1);
        CHECK_FALSE((*h)[0].before_json.has_value());
        CHECK((*h)[0].actor == "alice");
        CHECK((*h)[0].at > 1'700'000'000);
    }
    // 204 more saves: 205 in all. Each interval is distinct so every save is a real change.
    for (int i = 1; i <= 204; ++i) {
        put = store.put(kGroupA, make(3600 + i), put->stored.version, "alice");
        REQUIRE(put.has_value());
    }
    CHECK(scalar(settings_db_fx_.dsn(), "SELECT count(*) FROM "
                                        "software_collection_settings_store.settings_history") ==
          "200");
    const auto h = store.list_history(kGroupA, 500);
    REQUIRE(h.has_value());
    REQUIRE(h->size() == 200);
    // Newest first: the final document, and a prior document on every kept row.
    CHECK((*h)[0].after_json.find("\"interval_s\":" + std::to_string(3600 + 204)) !=
          std::string::npos);
    CHECK((*h)[0].before_json.has_value());
    // The five oldest saves were trimmed.
    CHECK((*h)[199].after_json.find("\"interval_s\":" + std::to_string(3600 + 5)) !=
          std::string::npos);
}

TEST_CASE("SoftwareCollectionSettingsStore: a corrupt row is Corrupt, never a default document",
          "[pg][store][collection_settings]") {
    SETTINGS_STORE(store);
    SECTION("unparseable plugins_json") {
        exec_sql(settings_db_fx_.dsn(), insert_with_plugins("{not json"));
    }
    SECTION("an unknown plugin key") {
        exec_sql(settings_db_fx_.dsn(), insert_with_plugins("{\"evidence\":true}"));
    }
    SECTION("a non-boolean value") {
        exec_sql(settings_db_fx_.dsn(), insert_with_plugins("{\"runtimes\":\"yes\"}"));
    }
    SECTION("a scalar the validator refuses") {
        exec_sql(settings_db_fx_.dsn(),
                 "INSERT INTO software_collection_settings_store.settings (group_id, interval_s, "
                 "window_start_min, window_end_min, plugins_json, version, updated_at) VALUES "
                 "('aaaa11112222', 90000, 60, 300, '{}', 'v', 1)"); // window on a 25 h interval
    }
    const auto got = store.get(kGroupA);
    REQUIRE_FALSE(got.has_value());
    CHECK(got.error().kind == Kind::Corrupt);
    const auto list = store.list_all();
    REQUIRE_FALSE(list.has_value());
    CHECK(list.error().kind == Kind::Corrupt);
    // A write over the corrupt row is Corrupt on both paths, never a Conflict whose missing
    // `current` would read as "no document exists".
    const auto create = store.put(kGroupA, make(), std::nullopt, "alice");
    REQUIRE_FALSE(create.has_value());
    CHECK(create.error().kind == Kind::Corrupt);
    const auto replace = store.put(kGroupA, make(), std::string(64, 'a'), "alice");
    REQUIRE_FALSE(replace.has_value());
    CHECK(replace.error().kind == Kind::Corrupt);
}

TEST_CASE("SoftwareCollectionSettingsStore: a missing known plugin key reads as the fleet default",
          "[pg][store][collection_settings]") {
    SETTINGS_STORE(store);
    // Written by a build with fewer keys: only runtimes is present, and it is off.
    exec_sql(settings_db_fx_.dsn(), insert_with_plugins("{\"runtimes\":false}"));
    const auto got = store.get(kGroupA);
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    const auto& d = **got;
    CHECK_FALSE(d.settings.plugins.at("runtimes"));
    for (const auto p : cs::kCollectionPlugins) {
        if (p != "runtimes")
            CHECK(d.settings.plugins.at(std::string{p}));
    }
    CHECK(d.version == "v"); // returned as stored, not re-hashed
}

TEST_CASE("SoftwareCollectionSettingsStore: list_all returns every row and refuses past the cap",
          "[pg][store][collection_settings]") {
    SETTINGS_STORE(store);
    REQUIRE(store.put("bbbb00000002", make(7200), std::nullopt, "a").has_value());
    REQUIRE(store.put("bbbb00000001", make(10800), std::nullopt, "a").has_value());
    const auto list = store.list_all();
    REQUIRE(list.has_value());
    REQUIRE(list->size() == 2);
    CHECK((*list)[0].group_id == "bbbb00000001"); // ordered by group id
    // Fill to one past the cap with valid rows.
    exec_sql(settings_db_fx_.dsn(),
             "INSERT INTO software_collection_settings_store.settings (group_id, interval_s, "
             "plugins_json, version, updated_at) SELECT 'cccc' || lpad(g::text, 8, '0'), 86400, "
             "'{}', 'v', 1 FROM generate_series(1, " +
                 std::to_string(SoftwareCollectionSettingsStore::kListRowCap - 2) + ") g");
    const auto full = store.list_all();
    REQUIRE(full.has_value()); // exactly at the cap
    CHECK(full->size() == static_cast<std::size_t>(SoftwareCollectionSettingsStore::kListRowCap));
    exec_sql(settings_db_fx_.dsn(),
             "INSERT INTO software_collection_settings_store.settings (group_id, interval_s, "
             "plugins_json, version, updated_at) VALUES ('dddd00000001', 86400, '{}', 'v', 1)");
    const auto over = store.list_all();
    REQUIRE_FALSE(over.has_value());
    CHECK(over.error().kind == Kind::TooMany);
}

TEST_CASE("SoftwareCollectionSettingsStore: a held pool is Unavailable, never no document",
          "[pg][store][collection_settings]") {
    SETTINGS_STORE(store);
    store.set_acquire_timeout_for_test(std::chrono::milliseconds{50});
    auto lease1 = settings_pool_fx_.acquire();
    auto lease2 = settings_pool_fx_.acquire();
    REQUIRE(lease1);
    REQUIRE(lease2);
    const auto got = store.get(kGroupA);
    REQUIRE_FALSE(got.has_value());
    CHECK(got.error().kind == Kind::Unavailable);
    const auto put = store.put(kGroupA, make(), std::nullopt, "alice");
    REQUIRE_FALSE(put.has_value());
    CHECK(put.error().kind == Kind::Unavailable);
    const auto list = store.list_all();
    REQUIRE_FALSE(list.has_value());
    CHECK(list.error().kind == Kind::Unavailable);
}
