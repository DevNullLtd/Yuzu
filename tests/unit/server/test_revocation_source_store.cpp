/**
 * test_revocation_source_store.cpp -- Unit tests for RevocationSourceStore (born-on-Postgres,
 * ADR-0070 R1, schema `revocation_source_store`).
 *
 * Covers: the migration (the WHOLE design schema, including the tables only the fetcher writes),
 * create/get/list round trips, one source per CA, the 64-source ceiling, a full replace (equal
 * body = no version bump; a dropped URL and a dropped key delete their held rows), a changed CA
 * subject, remove (cascade, the high-water mark SURVIVES), the anti-rollback reset, the
 * crl_past_next_update count, concurrent registrations of one CA, and the closed-store /
 * held-pool failure channel (a degrade is never an empty list).
 */

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "revocation_source_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <atomic>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

yuzu::test::PgTestTemplate rs_tpl{"revocationsource", [](const std::string& dsn) {
                                      PgPool pool{{.conninfo = dsn, .size = 1}};
                                      RevocationSourceStore store{pool};
                                      if (!store.is_open())
                                          throw std::runtime_error(
                                              "revocation source template: store failed to migrate");
                                  }};

std::string hex64(char c) { return std::string(64, c); }

NewRevocationSource make_source(const std::string& name, char ca_digit,
                                std::vector<char> key_digits = {'a'},
                                std::vector<std::string> urls = {"http://crl.example.com/a.crl"}) {
    NewRevocationSource n;
    n.name = name;
    n.ca_subject_name_sha256 = hex64(ca_digit);
    for (const char d : key_digits) {
        RevocationSourceKey k;
        k.cert_sha256 = hex64(d);
        k.cert_der = std::string("\x30\x03\x02\x01\x01", 5);
        k.ski = std::string(40, d);
        k.spki_sha256 = hex64(d == 'a' ? '1' : d == 'b' ? '2' : '3');
        n.keys.push_back(std::move(k));
    }
    for (const auto& u : urls)
        n.urls.push_back({u, "crl.example.com", {"public"}});
    return n;
}

} // namespace

#define RS_STORE(store_var)                                                                        \
    YUZU_REQUIRE_PG_DB_TPL(rs_db_fx_, rs_tpl);                                                     \
    PgPool rs_pool_fx_{{.conninfo = rs_db_fx_.dsn(), .size = 4}};                                  \
    REQUIRE(rs_pool_fx_.valid());                                                                  \
    RevocationSourceStore store_var{rs_pool_fx_};                                                  \
    REQUIRE(store_var.is_open())

// Run raw SQL on its own connection (a fixture write the store has no method for yet: the
// fetcher PR owns those writes).
#define RS_EXEC(db_fx, sql)                                                                        \
    do {                                                                                           \
        PgConn c_{PQconnectdb((db_fx).dsn().c_str())};                                             \
        REQUIRE(PQstatus(c_.get()) == CONNECTION_OK);                                              \
        PgResult r_{PQexec(c_.get(), (sql))};                                                      \
        INFO(PQresultErrorMessage(r_.get()));                                                      \
        REQUIRE((r_.status() == PGRES_COMMAND_OK || r_.status() == PGRES_TUPLES_OK));              \
    } while (0)

using RKind = RevocationSourceStoreError::Kind;

TEST_CASE("RevocationSourceStore: migration creates the whole design schema",
          "[revocation_source_store][pg][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    RevocationSourceStore store{pool};
    REQUIRE(store.is_open());
    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), "SELECT table_name FROM information_schema.tables WHERE "
                                  "table_schema = 'revocation_source_store' ORDER BY table_name")};
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    std::set<std::string> tables;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        tables.insert(PQgetvalue(r.get(), i, 0));
    // The tables only the fetcher (2b-1b) writes exist from this PR on: no second migration.
    CHECK(tables == std::set<std::string>{"crl", "crl_entry", "fetch_status",
                                          "rollback_high_water", "source", "source_ca_key",
                                          "source_url"});
    // Never touches ca_store (ADR-0070 D6).
    PgResult ca{PQexec(conn.get(), "SELECT count(*) FROM information_schema.tables WHERE "
                                   "table_schema = 'ca_store'")};
    REQUIRE(ca.status() == PGRES_TUPLES_OK);
    CHECK(std::string(PQgetvalue(ca.get(), 0, 0)) == "0");
    RevocationSourceStore again{pool};
    CHECK(again.is_open());
}

TEST_CASE("RevocationSourceStore: create then get and list round-trip a source",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    auto n = make_source("Corp CA", '1', {'a', 'b'}, {"http://crl.example.com/a.crl", "https://pki.corp/b.crl"});
    n.urls[1].confirmed_address_classes = {"private", "public"};
    const auto id = store.create(n, "alice");
    REQUIRE(id.has_value());

    const auto got = store.get(*id);
    REQUIRE(got.has_value());
    CHECK(got->id == *id);
    CHECK(got->name == "Corp CA");
    CHECK(got->ca_subject_name_sha256 == hex64('1'));
    CHECK(got->config_version == 1);
    CHECK(got->created_by == "alice");
    CHECK(got->created_at > 0);
    CHECK(got->updated_at >= got->created_at);
    CHECK(got->held_crl_count == 0);
    REQUIRE(got->keys.size() == 2);
    CHECK(got->keys[0].cert_sha256 == hex64('a'));
    CHECK(got->keys[0].ski == std::string(40, 'a'));
    CHECK(got->keys[0].spki_sha256 == hex64('1'));
    CHECK(got->keys[0].cert_der.empty()); // the DER is never read back by a route
    REQUIRE(got->urls.size() == 2);
    CHECK(got->urls[0].url == "http://crl.example.com/a.crl");
    CHECK(got->urls[0].confirmed_address_classes == std::vector<std::string>{"public"});
    CHECK(got->urls[1].confirmed_address_classes == std::vector<std::string>{"private", "public"});
    // Fetch status is present as "never fetched" until the fetcher writes it.
    CHECK_FALSE(got->urls[0].fetch.present);
    CHECK_FALSE(got->urls[0].fetch.last_attempt_at.has_value());
    CHECK(got->urls[0].fetch.consecutive_failures == 0);

    const auto all = store.list();
    REQUIRE(all.has_value());
    REQUIRE(all->size() == 1);
    CHECK(all->front().id == *id);
    CHECK(all->front().keys.size() == 2);
    CHECK(all->front().urls.size() == 2);
}

TEST_CASE("RevocationSourceStore: an unknown id is not found, an empty store lists empty",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto none = store.list();
    REQUIRE(none.has_value());
    CHECK(none->empty());
    const auto got = store.get(12345);
    REQUIRE_FALSE(got.has_value());
    CHECK(got.error().kind == RKind::kNotFound);
    CHECK(store.remove(12345).error().kind == RKind::kNotFound);
    CHECK(store.replace(12345, make_source("x", '1')).error().kind == RKind::kNotFound);
    CHECK(store.reset_high_water(12345, "").error().kind == RKind::kNotFound);
}

TEST_CASE("RevocationSourceStore: one source per CA, the conflict names the existing id",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto first = store.create(make_source("Corp CA", '1'), "alice");
    REQUIRE(first.has_value());
    const auto again = store.create(make_source("Another label", '1'), "bob");
    REQUIRE_FALSE(again.has_value());
    CHECK(again.error().kind == RKind::kConflict);
    CHECK(again.error().existing_id == *first);
    // A different CA is fine.
    CHECK(store.create(make_source("Other CA", '2'), "bob").has_value());
    CHECK(store.list()->size() == 2);
}

TEST_CASE("RevocationSourceStore: at most 64 sources", "[revocation_source_store][pg]") {
    RS_STORE(store);
    for (int i = 0; i < 64; ++i) {
        std::string h = std::to_string(1000 + i);
        h.append(64 - h.size(), 'f');
        auto n = make_source("ca" + std::to_string(i), '1');
        n.ca_subject_name_sha256 = h;
        REQUIRE(store.create(n, "alice").has_value());
    }
    auto over = make_source("one too many", '1');
    over.ca_subject_name_sha256 = hex64('e');
    const auto r = store.create(over, "alice");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == RKind::kLimitReached);
    CHECK(store.list()->size() == 64);
}

TEST_CASE("RevocationSourceStore: the store re-checks what it must to stay consistent",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    auto bad_name = make_source("", '1');
    CHECK(store.create(bad_name, "alice").error().kind == RKind::kInvalidInput);
    auto long_name = make_source(std::string(129, 'n'), '1');
    CHECK(store.create(long_name, "alice").error().kind == RKind::kInvalidInput);
    auto nul_name = make_source(std::string("a\0b", 3), '1');
    CHECK(store.create(nul_name, "alice").error().kind == RKind::kInvalidInput);
    auto bad_utf8 = make_source("\xff\xfe", '1');
    CHECK(store.create(bad_utf8, "alice").error().kind == RKind::kInvalidInput);
    auto no_keys = make_source("x", '1');
    no_keys.keys.clear();
    CHECK(store.create(no_keys, "alice").error().kind == RKind::kInvalidInput);
    auto no_urls = make_source("x", '1');
    no_urls.urls.clear();
    CHECK(store.create(no_urls, "alice").error().kind == RKind::kInvalidInput);
    auto nine_urls = make_source("x", '1');
    for (int i = 0; i < 9; ++i)
        nine_urls.urls.push_back({"http://h" + std::to_string(i) + ".example.com/", "h", {"public"}});
    CHECK(store.create(nine_urls, "alice").error().kind == RKind::kInvalidInput);
    auto dup_url = make_source("x", '1', {'a'}, {"http://a/", "http://a/"});
    CHECK(store.create(dup_url, "alice").error().kind == RKind::kInvalidInput);
    CHECK(store.create(make_source("x", '1'), "").error().kind == RKind::kInvalidInput);
    // Nothing was written by any refusal.
    CHECK(store.list()->empty());
}

TEST_CASE("RevocationSourceStore: a full replace; an equal body changes nothing",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = store.create(make_source("Corp CA", '1', {'a'}, {"http://crl.example.com/a.crl"}),
                                 "alice");
    REQUIRE(id.has_value());

    // Equal body: no write, no version bump, changed=false.
    const auto same = store.replace(*id, make_source("Corp CA", '1', {'a'}, {"http://crl.example.com/a.crl"}));
    REQUIRE(same.has_value());
    CHECK_FALSE(same->changed);
    CHECK(same->source.config_version == 1);

    // A renamed, re-keyed, re-URLed source bumps the version exactly once.
    const auto changed = store.replace(
        *id, make_source("Corp CA (renewed)", '1', {'a', 'b'},
                         {"http://crl.example.com/a.crl", "http://crl2.example.com/b.crl"}));
    REQUIRE(changed.has_value());
    CHECK(changed->changed);
    CHECK(changed->dropped_urls == 0);
    CHECK(changed->dropped_keys == 0);
    CHECK(changed->source.config_version == 2);
    CHECK(changed->source.name == "Corp CA (renewed)");
    CHECK(changed->source.keys.size() == 2);
    CHECK(changed->source.urls.size() == 2);
    // The creator and creation time are not rewritten by a replace.
    CHECK(changed->source.created_by == "alice");
}

TEST_CASE("RevocationSourceStore: a replace that drops a URL or a key deletes its held rows",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    // Key 'a' has SPKI 1.., key 'b' has SPKI 2... Two URLs.
    const auto id = store.create(
        make_source("Corp CA", '1', {'a', 'b'},
                    {"http://crl.example.com/a.crl", "http://crl2.example.com/b.crl"}),
        "alice");
    REQUIRE(id.has_value());
    const auto src = store.get(*id);
    REQUIRE(src.has_value());
    const auto url_a = src->urls[0].id;
    const auto url_b = src->urls[1].id;

    // What the fetcher will write (not yet written by this PR's code): a fetch_status row for
    // each URL, and one held CRL per URL, each verified under a different key.
    const std::string sid = std::to_string(*id);
    RS_EXEC(rs_db_fx_, ("INSERT INTO revocation_source_store.fetch_status (url_id, last_attempt_at) "
                        "VALUES (" + std::to_string(url_a) + ", now()), (" + std::to_string(url_b) +
                        ", now())").c_str());
    RS_EXEC(rs_db_fx_, ("INSERT INTO revocation_source_store.crl (source_id, scope_key, url_id, "
                        "this_update, verified_key_sha256, der_sha256, entry_count) VALUES (" +
                        sid + ", '*', " + std::to_string(url_a) + ", now(), '" + hex64('1') + "', '" +
                        hex64('c') + "', 1)").c_str());
    RS_EXEC(rs_db_fx_, ("INSERT INTO revocation_source_store.crl (source_id, scope_key, url_id, "
                        "this_update, verified_key_sha256, der_sha256, entry_count) VALUES (" +
                        sid + ", 'idp:1', " + std::to_string(url_b) + ", now(), '" + hex64('2') +
                        "', '" + hex64('d') + "', 1)").c_str());
    RS_EXEC(rs_db_fx_, "INSERT INTO revocation_source_store.crl_entry (crl_id, serial, revocation_date) "
                       "SELECT id, '01', now() FROM revocation_source_store.crl");
    CHECK(store.get(*id)->held_crl_count == 2);

    // Drop URL b and key 'b': URL b's fetch_status and CRL go (cascade), and so does any CRL that
    // verified only under key b (here the same row). CRL a (key 'a') survives.
    const auto r = store.replace(*id, make_source("Corp CA", '1', {'a'}, {"http://crl.example.com/a.crl"}));
    REQUIRE(r.has_value());
    CHECK(r->changed);
    CHECK(r->dropped_urls == 1);
    CHECK(r->dropped_keys == 1);
    CHECK(r->source.held_crl_count == 1);
    REQUIRE(r->source.urls.size() == 1);
    CHECK(r->source.urls[0].id == url_a);
    CHECK(r->source.urls[0].fetch.present); // URL a's status is kept
    PgConn conn{PQconnectdb(rs_db_fx_.dsn().c_str())};
    PgResult left{PQexec(conn.get(), "SELECT (SELECT count(*) FROM revocation_source_store.fetch_status), "
                                     "(SELECT count(*) FROM revocation_source_store.crl_entry)")};
    REQUIRE(left.status() == PGRES_TUPLES_OK);
    CHECK(std::string(PQgetvalue(left.get(), 0, 0)) == "1");
    CHECK(std::string(PQgetvalue(left.get(), 0, 1)) == "1");

    // Dropping only key 'a' now (keeping a different cert over the same SPKI would keep the CRL;
    // here a new key 'c' replaces it): the CRL that verified under SPKI 1.. is deleted.
    const auto r2 = store.replace(*id, make_source("Corp CA", '1', {'c'}, {"http://crl.example.com/a.crl"}));
    REQUIRE(r2.has_value());
    CHECK(r2->dropped_keys == 1);
    CHECK(r2->crls_deleted == 1);
    CHECK(r2->source.held_crl_count == 0);
}

TEST_CASE("RevocationSourceStore: a replace naming a different CA subject is refused",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = store.create(make_source("Corp CA", '1'), "alice");
    REQUIRE(id.has_value());
    const auto r = store.replace(*id, make_source("Corp CA", '2'));
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == RKind::kSubjectChanged);
    CHECK(store.get(*id)->config_version == 1);
}

TEST_CASE("RevocationSourceStore: remove cascades, the high-water mark survives",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = store.create(make_source("Corp CA", '1'), "alice");
    REQUIRE(id.has_value());
    // A mark exists for the CA (as the fetcher or a reset would leave it).
    REQUIRE(store.reset_high_water(*id, "").has_value());
    REQUIRE(store.remove(*id).has_value());
    CHECK(store.get(*id).error().kind == RKind::kNotFound);
    CHECK(store.remove(*id).error().kind == RKind::kNotFound); // a repeat is a 404, not an error

    PgConn conn{PQconnectdb(rs_db_fx_.dsn().c_str())};
    PgResult r{PQexec(conn.get(), ("SELECT count(*) FROM revocation_source_store.rollback_high_water "
                                   "WHERE ca_subject_name_sha256 = '" + hex64('1') + "'").c_str())};
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    CHECK(std::string(PQgetvalue(r.get(), 0, 0)) == "1");
    PgResult gone{PQexec(conn.get(), "SELECT (SELECT count(*) FROM revocation_source_store.source_url), "
                                     "(SELECT count(*) FROM revocation_source_store.source_ca_key)")};
    REQUIRE(gone.status() == PGRES_TUPLES_OK);
    CHECK(std::string(PQgetvalue(gone.get(), 0, 0)) == "0");
    CHECK(std::string(PQgetvalue(gone.get(), 0, 1)) == "0");

    // Re-registering the CA is allowed and the mark is still there (the fetcher reads it).
    CHECK(store.create(make_source("Corp CA again", '1'), "alice").has_value());
}

TEST_CASE("RevocationSourceStore: reset_high_water sets a floor and discards held CRLs",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = store.create(make_source("Corp CA", '1'), "alice");
    REQUIRE(id.has_value());
    const auto src = store.get(*id);
    RS_EXEC(rs_db_fx_, ("INSERT INTO revocation_source_store.crl (source_id, scope_key, url_id, "
                        "this_update, verified_key_sha256, der_sha256, entry_count) VALUES (" +
                        std::to_string(*id) + ", '*', " + std::to_string(src->urls[0].id) +
                        ", now(), '" + hex64('1') + "', '" + hex64('c') + "', 0)").c_str());
    RS_EXEC(rs_db_fx_, ("INSERT INTO revocation_source_store.rollback_high_water (ca_subject_name_sha256, "
                        "scope_key, crl_number, this_update) VALUES ('" + hex64('1') +
                        "', 'idp:7', 41, now())").c_str());
    CHECK(store.get(*id)->held_crl_count == 1);

    // Reset to a supplied past time: echoed to the second, every scope row gets it.
    const auto r = store.reset_high_water(*id, "2020-01-02T03:04:05Z");
    REQUIRE(r.has_value());
    CHECK(r->reset_at == 1577934245);
    CHECK(r->crls_deleted == 1);
    CHECK(store.get(*id)->held_crl_count == 0);
    PgConn conn{PQconnectdb(rs_db_fx_.dsn().c_str())};
    PgResult marks{PQexec(conn.get(), "SELECT scope_key, EXTRACT(EPOCH FROM reset_at)::bigint, "
                                      "crl_number FROM revocation_source_store.rollback_high_water "
                                      "ORDER BY scope_key")};
    REQUIRE(marks.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(marks.get()) == 2);
    CHECK(std::string(PQgetvalue(marks.get(), 0, 0)) == "*");
    CHECK(std::string(PQgetvalue(marks.get(), 0, 1)) == "1577934245");
    CHECK(PQgetisnull(marks.get(), 0, 2)); // a row that only records the reset has no number
    CHECK(std::string(PQgetvalue(marks.get(), 1, 0)) == "idp:7");
    CHECK(std::string(PQgetvalue(marks.get(), 1, 1)) == "1577934245");
    CHECK(PQgetisnull(marks.get(), 1, 2)); // a rebuilt CA restarts its numbering: the number is cleared
    // A reset is a configuration change.
    CHECK(store.get(*id)->config_version == 2);
    CHECK(store.get(*id)->reset_at == 1577934245); // visible on the source read

    // NOT idempotent: a second reset (default now) sets a NEW, later floor.
    const auto r2 = store.reset_high_water(*id, "");
    REQUIRE(r2.has_value());
    CHECK(r2->reset_at > r->reset_at);
}

TEST_CASE("RevocationSourceStore: reset_at later than the server clock, or unparseable, is refused",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = store.create(make_source("Corp CA", '1'), "alice");
    REQUIRE(id.has_value());
    const auto future = store.reset_high_water(*id, "2999-01-01T00:00:00Z");
    REQUIRE_FALSE(future.has_value());
    CHECK(future.error().kind == RKind::kBadResetTime);
    const auto bad = store.reset_high_water(*id, "not a time");
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error().kind == RKind::kInvalidInput);
    // Neither wrote a mark.
    PgConn conn{PQconnectdb(rs_db_fx_.dsn().c_str())};
    PgResult r{PQexec(conn.get(), "SELECT count(*) FROM revocation_source_store.rollback_high_water")};
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    CHECK(std::string(PQgetvalue(r.get(), 0, 0)) == "0");
}

TEST_CASE("RevocationSourceStore: crl_past_next_update counts sources, not CRLs",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = store.create(make_source("Corp CA", '1'), "alice");
    REQUIRE(id.has_value());
    CHECK(store.crl_past_next_update_count().value() == 0);
    const auto src = store.get(*id);
    for (const char* scope : {"*", "idp:1"})
        RS_EXEC(rs_db_fx_, (std::string("INSERT INTO revocation_source_store.crl (source_id, scope_key, "
                                        "url_id, this_update, next_update, verified_key_sha256, "
                                        "der_sha256, entry_count) VALUES (") +
                            std::to_string(*id) + ", '" + scope + "', " +
                            std::to_string(src->urls[0].id) + ", now() - interval '2 days', "
                            "now() - interval '1 day', '" + hex64('1') + "', '" + hex64('c') +
                            scope + "', 0)").c_str());
    CHECK(store.crl_past_next_update_count().value() == 1);
}

TEST_CASE("RevocationSourceStore: two registrations of one CA race to exactly one winner",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    std::atomic<int> won{0}, conflicted{0};
    std::vector<std::thread> ts;
    for (int i = 0; i < 4; ++i)
        ts.emplace_back([&, i] {
            const auto r = store.create(make_source("racer" + std::to_string(i), '1'), "alice");
            if (r.has_value())
                ++won;
            else if (r.error().kind == RKind::kConflict)
                ++conflicted;
        });
    for (auto& t : ts)
        t.join();
    CHECK(won.load() == 1);
    CHECK(conflicted.load() == 3);
    CHECK(store.list()->size() == 1);
}

TEST_CASE("RevocationSourceStore: a held pool is a typed degrade, never an empty list",
          "[revocation_source_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, rs_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    RevocationSourceStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.create(make_source("Corp CA", '1'), "alice").has_value());
    store.set_acquire_timeout_for_test(std::chrono::milliseconds(50));
    auto l1 = pool.acquire();
    auto l2 = pool.acquire();
    REQUIRE(l1);
    REQUIRE(l2);
    const auto listed = store.list();
    REQUIRE_FALSE(listed.has_value());
    CHECK(listed.error().kind == RKind::kPoolAcquireTimeout);
    CHECK(store.get(1).error().kind == RKind::kPoolAcquireTimeout);
    CHECK(store.crl_past_next_update_count().error().kind == RKind::kPoolAcquireTimeout);
    CHECK(store.create(make_source("x", '2'), "alice").error().kind == RKind::kPoolAcquireTimeout);
    CHECK(store.remove(1).error().kind == RKind::kPoolAcquireTimeout);
}

TEST_CASE("RevocationSourceStore: replace honours expected_config_version under the row lock",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = store.create(make_source("Corp CA", '1'), "alice");
    REQUIRE(id.has_value());
    auto stale = make_source("Renamed", '1');
    stale.expected_config_version = 5;
    const auto r = store.replace(*id, stale);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == RKind::kVersionConflict);
    CHECK(r.error().existing_id == 1); // carries the stored version
    CHECK(store.get(*id)->name == "Corp CA");
    auto fresh = make_source("Renamed", '1');
    fresh.expected_config_version = 1;
    const auto ok = store.replace(*id, fresh);
    REQUIRE(ok.has_value());
    CHECK(ok->source.config_version == 2);
    // A body that already IS the stored configuration is a retry of the caller's own committed
    // change: a no-op success even though the version it names is stale.
    auto noop = make_source("Renamed", '1');
    noop.expected_config_version = 1;
    const auto retry = store.replace(*id, noop);
    REQUIRE(retry.has_value());
    CHECK_FALSE(retry->changed);
    CHECK(retry->source.config_version == 2);
    // A body that would CHANGE it from a stale version is the conflict.
    auto stale2 = make_source("Renamed again", '1');
    stale2.expected_config_version = 1;
    CHECK(store.replace(*id, stale2).error().kind == RKind::kVersionConflict);
}

TEST_CASE("RevocationSourceStore: a reset records the pin and keeps the floor permanently",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = store.create(make_source("Corp CA", '1'), "alice");
    REQUIRE(id.has_value());
    const std::string pin(64, 'b');
    const auto r = store.reset_high_water(*id, "2020-01-02T03:04:05Z", pin);
    REQUIRE(r.has_value());
    CHECK(r->pinned);
    auto src = store.get(*id);
    REQUIRE(src.has_value());
    CHECK(src->pinned_crl_sha256 == pin);
    // A later reset WITHOUT a pin clears the old pin (the new window has none) and moves the floor.
    const auto r2 = store.reset_high_water(*id, "2021-01-02T03:04:05Z");
    REQUIRE(r2.has_value());
    CHECK_FALSE(r2->pinned);
    src = store.get(*id);
    CHECK_FALSE(src->pinned_crl_sha256.has_value());
    CHECK(src->reset_at == 1609556645);
    CHECK(src->config_version == 3);
    CHECK(store.reset_high_water(*id, "", "not-hex").error().kind == RKind::kInvalidInput);
}

TEST_CASE("RevocationSourceStore: crl_entry.serial is pinned to the canonical byte form",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = store.create(make_source("Corp CA", '1'), "alice");
    REQUIRE(id.has_value());
    const auto src = store.get(*id);
    RS_EXEC(rs_db_fx_, ("INSERT INTO revocation_source_store.crl (source_id, scope_key, url_id, "
                        "this_update, verified_key_sha256, der_sha256, entry_count) VALUES (" +
                        std::to_string(*id) + ", '*', " + std::to_string(src->urls[0].id) +
                        ", now(), '" + hex64('1') + "', '" + hex64('c') + "', 0)").c_str());
    const auto try_serial = [&](const std::string& serial) {
        PgConn c{PQconnectdb(rs_db_fx_.dsn().c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        PgResult r{PQexec(c.get(), ("INSERT INTO revocation_source_store.crl_entry (crl_id, serial, "
                                    "revocation_date) SELECT id, '" + serial + "', now() FROM "
                                    "revocation_source_store.crl").c_str())};
        return r.status() == PGRES_COMMAND_OK;
    };
    CHECK(try_serial("0A1B"));   // whole bytes, upper case
    CHECK(try_serial("00"));     // zero itself
    CHECK(try_serial("FF"));
    CHECK_FALSE(try_serial("0a1b")); // lower case: a second spelling of the same serial
    CHECK_FALSE(try_serial("A1B"));  // odd length: not whole bytes
    CHECK_FALSE(try_serial("000A")); // a leading 00 byte: a padded spelling
    CHECK_FALSE(try_serial(""));
    CHECK_FALSE(try_serial("0G"));
}
