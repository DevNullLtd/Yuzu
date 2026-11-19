/**
 * test_revocation_source_store.cpp -- Unit tests for RevocationSourceStore (born-on-Postgres,
 * ADR-0070 R1, schema `revocation_source_store`).
 *
 * Covers: the migration (every table the fetcher (2b-1b) uses, including those only it writes;
 * `cert_signature_check` is 2b-2's and is not created),
 * create/get/list round trips, one source per CA, the 64-source ceiling, a full replace (equal
 * body = no version bump; a dropped URL and a dropped key delete their held rows), a changed CA
 * subject, remove (cascade, the high-water mark SURVIVES), the anti-rollback reset, the
 * crl_past_next_update count, concurrent registrations of one CA, and the closed-store /
 * held-pool failure channel (a degrade is never an empty list). Migration v2 (the #6590 rulings,
 * 2026-11-18): the one encoded scope key and its CHECKs, the generated `crl.is_delta`, the
 * delete-then-insert replacement under UNIQUE (source_id, scope_key, is_delta), the v1 -> v2
 * upgrade of held rows, the canonical-URL pass at open (rewrite keeping the URL id and fetch
 * status; a collapse refuses the open), and the reset's surviving-key list and version check.
 */

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/pg_migration_runner.hpp"
#include "revocation_source_store.hpp"
#include "revocation_url_canonical.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <atomic>
#include <expected>
#include <optional>
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
    // The store keeps only canonical URLs (the service canonicalises; a fixture does the same).
    for (const auto& u : urls) {
        const auto c = yuzu::server::revocation_source::canonical_crl_url(u);
        n.urls.push_back({c ? c->url : u, c ? c->host : std::string("crl.example.com"), {"public"}});
    }
    return n;
}

/// A reset that keeps every key the source holds now, read at its current config_version (an
/// unknown id gets a well-formed request, so the store's own kNotFound answers).
HighWaterResetRequest reset_req(RevocationSourceStore& store, std::int64_t id, std::string at = {},
                                std::string pin = {}) {
    HighWaterResetRequest r;
    r.reset_at_rfc3339 = std::move(at);
    r.pin_crl_sha256 = std::move(pin);
    if (const auto s = store.get(id)) {
        r.expected_config_version = s->config_version;
        for (const auto& k : s->keys)
            r.keep_key_sha256.push_back(k.cert_sha256);
    } else {
        r.expected_config_version = 1;
        r.keep_key_sha256 = {hex64('a')};
    }
    return r;
}

/// An encoded scope key (#6590): `full` or `idp:<64 hex>`, then `:base` or `:delta`.
std::string scope(char idp_digit, bool delta = false) {
    return (idp_digit == 0 ? std::string("full") : "idp:" + hex64(idp_digit)) +
           (delta ? ":delta" : ":base");
}

/// The caller's precondition on a changing replace (the store refuses a body without it).
NewRevocationSource at_version(NewRevocationSource n, std::int64_t version) {
    n.expected_config_version = version;
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

namespace {
// `create` returns the stored record; most cases only need its id.
std::expected<std::int64_t, RevocationSourceStoreError>
create_id(RevocationSourceStore& store, const NewRevocationSource& src, const std::string& who) {
    auto r = store.create(src, who);
    if (!r)
        return std::unexpected(r.error());
    return r->id;
}
} // namespace

TEST_CASE("RevocationSourceStore: migration creates the tables the fetcher uses",
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
    // The tables only the fetcher (2b-1b) writes exist already; 2b-2's cert_signature_check does not.
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
    const auto created = store.create(n, "alice");
    REQUIRE(created.has_value());
    const auto id = std::optional<std::int64_t>(created->id);
    CHECK(created->name == "Corp CA");
    CHECK(created->config_version == 1);
    CHECK(created->urls.size() == 2);
    CHECK(created->keys.size() == 2);

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
    CHECK(store.reset_high_water(12345, reset_req(store, 12345)).error().kind == RKind::kNotFound);
}

TEST_CASE("RevocationSourceStore: one source per CA, the conflict names the existing id",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto first = create_id(store, make_source("Corp CA", '1'), "alice");
    REQUIRE(first.has_value());
    const auto again = create_id(store, make_source("Another label", '1'), "bob");
    REQUIRE_FALSE(again.has_value());
    CHECK(again.error().kind == RKind::kConflict);
    CHECK(again.error().existing_id == *first);
    // A different CA is fine.
    CHECK(create_id(store, make_source("Other CA", '2'), "bob").has_value());
    CHECK(store.list()->size() == 2);
}

TEST_CASE("RevocationSourceStore: a failed read-back inside create commits nothing",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    store.set_read_fault_for_test([](std::string_view op) -> std::optional<RKind> {
        if (op == "create.reread")
            return RKind::kQueryError;
        return std::nullopt;
    });
    const auto failed = create_id(store, make_source("Corp CA", '1'), "alice");
    REQUIRE_FALSE(failed.has_value());
    CHECK(failed.error().kind == RKind::kQueryError);
    store.set_read_fault_for_test(nullptr);
    // Rolled back: nothing is listed, and a retry is a fresh registration, not a conflict.
    CHECK(store.list()->empty());
    const auto retry = create_id(store, make_source("Corp CA", '1'), "alice");
    REQUIRE(retry.has_value());
    CHECK(store.list()->size() == 1);
}

TEST_CASE("RevocationSourceStore: at most 64 sources", "[revocation_source_store][pg]") {
    RS_STORE(store);
    for (int i = 0; i < 64; ++i) {
        std::string h = std::to_string(1000 + i);
        h.append(64 - h.size(), 'f');
        auto n = make_source("ca" + std::to_string(i), '1');
        n.ca_subject_name_sha256 = h;
        REQUIRE(create_id(store, n, "alice").has_value());
    }
    auto over = make_source("one too many", '1');
    over.ca_subject_name_sha256 = hex64('e');
    const auto r = create_id(store, over, "alice");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == RKind::kLimitReached);
    CHECK(store.list()->size() == 64);
}

TEST_CASE("RevocationSourceStore: the store re-checks what it must to stay consistent",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    auto bad_name = make_source("", '1');
    CHECK(create_id(store, bad_name, "alice").error().kind == RKind::kInvalidInput);
    auto long_name = make_source(std::string(129, 'n'), '1');
    CHECK(create_id(store, long_name, "alice").error().kind == RKind::kInvalidInput);
    auto nul_name = make_source(std::string("a\0b", 3), '1');
    CHECK(create_id(store, nul_name, "alice").error().kind == RKind::kInvalidInput);
    auto bad_utf8 = make_source("\xff\xfe", '1');
    CHECK(create_id(store, bad_utf8, "alice").error().kind == RKind::kInvalidInput);
    auto no_keys = make_source("x", '1');
    no_keys.keys.clear();
    CHECK(create_id(store, no_keys, "alice").error().kind == RKind::kInvalidInput);
    auto no_urls = make_source("x", '1');
    no_urls.urls.clear();
    CHECK(create_id(store, no_urls, "alice").error().kind == RKind::kInvalidInput);
    auto nine_urls = make_source("x", '1');
    for (int i = 0; i < 9; ++i)
        nine_urls.urls.push_back({"http://h" + std::to_string(i) + ".example.com/", "h", {"public"}});
    CHECK(create_id(store, nine_urls, "alice").error().kind == RKind::kInvalidInput);
    auto dup_url = make_source("x", '1', {'a'}, {"http://a/", "http://a/"});
    CHECK(create_id(store, dup_url, "alice").error().kind == RKind::kInvalidInput);
    CHECK(create_id(store, make_source("x", '1'), "").error().kind == RKind::kInvalidInput);
    // Only the canonical form is ever stored (#6590): another spelling, or a host that is not
    // the canonical URL's, is refused even though the service would never send one.
    auto not_canonical = make_source("x", '1');
    not_canonical.urls[0].url = "HTTP://crl.example.com:80/a.crl";
    CHECK(create_id(store, not_canonical, "alice").error().kind == RKind::kInvalidInput);
    auto no_path = make_source("x", '1');
    no_path.urls[0].url = "http://crl.example.com";
    CHECK(create_id(store, no_path, "alice").error().kind == RKind::kInvalidInput);
    auto wrong_host = make_source("x", '1');
    wrong_host.urls[0].host = "other.example.com";
    CHECK(create_id(store, wrong_host, "alice").error().kind == RKind::kInvalidInput);
    // Nothing was written by any refusal.
    CHECK(store.list()->empty());
}

TEST_CASE("RevocationSourceStore: a full replace; an equal body changes nothing",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = create_id(store, make_source("Corp CA", '1', {'a'}, {"http://crl.example.com/a.crl"}),
                                 "alice");
    REQUIRE(id.has_value());

    // Equal body: no write, no version bump, changed=false.
    const auto same = store.replace(*id, make_source("Corp CA", '1', {'a'}, {"http://crl.example.com/a.crl"}));
    REQUIRE(same.has_value());
    CHECK_FALSE(same->changed);
    CHECK(same->source.config_version == 1);

    // A renamed, re-keyed, re-URLed source bumps the version exactly once.
    const auto changed = store.replace(
        *id, at_version(make_source("Corp CA (renewed)", '1', {'a', 'b'},
                                    {"http://crl.example.com/a.crl", "http://crl2.example.com/b.crl"}),
                        1));
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
    const auto id = create_id(store,
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
                        sid + ", '" + scope(0) + "', " + std::to_string(url_a) + ", now(), '" + hex64('1') + "', '" +
                        hex64('c') + "', 1)").c_str());
    RS_EXEC(rs_db_fx_, ("INSERT INTO revocation_source_store.crl (source_id, scope_key, url_id, "
                        "this_update, verified_key_sha256, der_sha256, entry_count) VALUES (" +
                        sid + ", '" + scope('1') + "', " + std::to_string(url_b) + ", now(), '" + hex64('2') +
                        "', '" + hex64('d') + "', 1)").c_str());
    RS_EXEC(rs_db_fx_, "INSERT INTO revocation_source_store.crl_entry (crl_id, serial, revocation_date) "
                       "SELECT id, '01', now() FROM revocation_source_store.crl");
    CHECK(store.get(*id)->held_crl_count == 2);

    // Drop URL b and key 'b': URL b's fetch_status and CRL go (cascade), and so does any CRL that
    // verified only under key b (here the same row). CRL a (key 'a') survives.
    const auto r = store.replace(
        *id, at_version(make_source("Corp CA", '1', {'a'}, {"http://crl.example.com/a.crl"}), 1));
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
    const auto r2 = store.replace(
        *id, at_version(make_source("Corp CA", '1', {'c'}, {"http://crl.example.com/a.crl"}), 2));
    REQUIRE(r2.has_value());
    CHECK(r2->dropped_keys == 1);
    CHECK(r2->crls_deleted == 1);
    CHECK(r2->source.held_crl_count == 0);
}

TEST_CASE("RevocationSourceStore: a changing replace that names no version is refused",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = create_id(store, make_source("Corp CA", '1'), "alice");
    REQUIRE(id.has_value());
    const auto r = store.replace(*id, make_source("Renamed", '1')); // no expected_config_version
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == RKind::kVersionConflict);
    CHECK(r.error().existing_id == 1); // carries the stored version
    CHECK(store.get(*id)->name == "Corp CA");
    // An equal body needs no version: it writes nothing.
    const auto same = store.replace(*id, make_source("Corp CA", '1'));
    REQUIRE(same.has_value());
    CHECK_FALSE(same->changed);
}

TEST_CASE("RevocationSourceStore: a replace naming a different CA subject is refused",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = create_id(store, make_source("Corp CA", '1'), "alice");
    REQUIRE(id.has_value());
    const auto r = store.replace(*id, make_source("Corp CA", '2'));
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == RKind::kSubjectChanged);
    CHECK(store.get(*id)->config_version == 1);
}

TEST_CASE("RevocationSourceStore: remove cascades, the high-water mark survives",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = create_id(store, make_source("Corp CA", '1'), "alice");
    REQUIRE(id.has_value());
    // A mark exists for the CA (as the fetcher or a reset would leave it).
    REQUIRE(store.reset_high_water(*id, reset_req(store, *id)).has_value());
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
    CHECK(create_id(store, make_source("Corp CA again", '1'), "alice").has_value());
}

TEST_CASE("RevocationSourceStore: reset_high_water sets a floor and discards held CRLs",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = create_id(store, make_source("Corp CA", '1'), "alice");
    REQUIRE(id.has_value());
    const auto src = store.get(*id);
    RS_EXEC(rs_db_fx_, ("INSERT INTO revocation_source_store.crl (source_id, scope_key, url_id, "
                        "this_update, verified_key_sha256, der_sha256, entry_count) VALUES (" +
                        std::to_string(*id) + ", '" + scope(0) + "', " + std::to_string(src->urls[0].id) +
                        ", now(), '" + hex64('1') + "', '" + hex64('c') + "', 0)").c_str());
    RS_EXEC(rs_db_fx_, ("INSERT INTO revocation_source_store.rollback_high_water (ca_subject_name_sha256, "
                        "scope_key, crl_number, this_update) VALUES ('" + hex64('1') +
                        "', '" + scope('7') + "', 41, now())").c_str());
    CHECK(store.get(*id)->held_crl_count == 1);

    // Reset to a supplied past time: echoed to the second, every scope row gets it.
    const auto r = store.reset_high_water(*id, reset_req(store, *id, "2020-01-02T03:04:05Z"));
    REQUIRE(r.has_value());
    CHECK(r->reset_at == 1577934245);
    CHECK(r->config_version == 2);
    CHECK(r->dropped_keys == 0); // every key was named as surviving
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
    CHECK(std::string(PQgetvalue(marks.get(), 1, 0)) == scope('7'));
    CHECK(std::string(PQgetvalue(marks.get(), 1, 1)) == "1577934245");
    CHECK(PQgetisnull(marks.get(), 1, 2)); // a rebuilt CA restarts its numbering: the number is cleared
    // A reset is a configuration change.
    CHECK(store.get(*id)->config_version == 2);
    CHECK(store.get(*id)->reset_at == 1577934245); // visible on the source read

    // NOT idempotent: a second reset (default now) sets a NEW, later floor.
    const auto r2 = store.reset_high_water(*id, reset_req(store, *id));
    REQUIRE(r2.has_value());
    CHECK(r2->reset_at > r->reset_at);
}

TEST_CASE("RevocationSourceStore: reset_at later than the server clock, or unparseable, is refused",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = create_id(store, make_source("Corp CA", '1'), "alice");
    REQUIRE(id.has_value());
    const auto future = store.reset_high_water(*id, reset_req(store, *id, "2999-01-01T00:00:00Z"));
    REQUIRE_FALSE(future.has_value());
    CHECK(future.error().kind == RKind::kBadResetTime);
    const auto bad = store.reset_high_water(*id, reset_req(store, *id, "not a time"));
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error().kind == RKind::kInvalidInput);
    // Neither wrote a mark.
    PgConn conn{PQconnectdb(rs_db_fx_.dsn().c_str())};
    PgResult r{PQexec(conn.get(), "SELECT count(*) FROM revocation_source_store.rollback_high_water")};
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    CHECK(std::string(PQgetvalue(r.get(), 0, 0)) == "0");
}

TEST_CASE("RevocationSourceStore: crl_past_next_update counts CRL scopes past nextUpdate",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = create_id(store, make_source("Corp CA", '1'), "alice");
    REQUIRE(id.has_value());
    CHECK(store.crl_past_next_update_count().value() == 0);
    const auto src = store.get(*id);
    // One held CRL row per call: scope, nextUpdate SQL expression, base or delta.
    // is_delta is GENERATED from the scope key's suffix (v2), so the fixture never writes it.
    const auto hold = [&](char idp, const char* next_update, bool delta) {
        const std::string key = scope(idp, delta);
        RS_EXEC(rs_db_fx_, (std::string("INSERT INTO revocation_source_store.crl (source_id, scope_key, "
                                        "url_id, this_update, next_update, "
                                        "verified_key_sha256, der_sha256, entry_count) VALUES (") +
                            std::to_string(*id) + ", '" + key + "', " +
                            std::to_string(src->urls[0].id) + ", now() - interval '2 days', " +
                            next_update + ", '" + hex64('1') + "', '" + key + "', 0)").c_str());
    };
    // Two stale scopes of ONE source count twice: the count is over scopes, not sources.
    hold(0, "now() - interval '1 day'", false);
    hold('1', "now() - interval '1 day'", false);
    CHECK(store.crl_past_next_update_count().value() == 2);
    // A fresh scope and a scope with no nextUpdate add nothing.
    hold('2', "now() + interval '1 day'", false);
    hold('3', "NULL", false);
    CHECK(store.crl_past_next_update_count().value() == 2);
    // A stale DELTA is its own scope (design: one per (CA, IDP, base or delta)), so it counts, even
    // when that scope's base CRL is fresh.
    hold('2', "now() - interval '1 day'", true);
    CHECK(store.crl_past_next_update_count().value() == 3);
}

TEST_CASE("RevocationSourceStore: two registrations of one CA race to exactly one winner",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    std::atomic<int> won{0}, conflicted{0};
    std::vector<std::thread> ts;
    for (int i = 0; i < 4; ++i)
        ts.emplace_back([&, i] {
            const auto r = create_id(store, make_source("racer" + std::to_string(i), '1'), "alice");
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
    REQUIRE(create_id(store, make_source("Corp CA", '1'), "alice").has_value());
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
    CHECK(create_id(store, make_source("x", '2'), "alice").error().kind == RKind::kPoolAcquireTimeout);
    CHECK(store.remove(1).error().kind == RKind::kPoolAcquireTimeout);
}

TEST_CASE("RevocationSourceStore: replace honours expected_config_version under the row lock",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = create_id(store, make_source("Corp CA", '1'), "alice");
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
    const auto id = create_id(store, make_source("Corp CA", '1'), "alice");
    REQUIRE(id.has_value());
    const std::string pin(64, 'b');
    const auto r = store.reset_high_water(*id, reset_req(store, *id, "2020-01-02T03:04:05Z", pin));
    REQUIRE(r.has_value());
    CHECK(r->pinned);
    auto src = store.get(*id);
    REQUIRE(src.has_value());
    CHECK(src->pinned_crl_sha256 == pin);
    // A later reset WITHOUT a pin clears the old pin (the new window has none) and moves the floor.
    const auto r2 = store.reset_high_water(*id, reset_req(store, *id, "2021-01-02T03:04:05Z"));
    REQUIRE(r2.has_value());
    CHECK_FALSE(r2->pinned);
    src = store.get(*id);
    CHECK_FALSE(src->pinned_crl_sha256.has_value());
    CHECK(src->reset_at == 1609556645);
    CHECK(src->config_version == 3);
    CHECK(store.reset_high_water(*id, reset_req(store, *id, "", "not-hex")).error().kind ==
          RKind::kInvalidInput);
}

TEST_CASE("RevocationSourceStore: crl_entry.serial is pinned to the canonical byte form",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = create_id(store, make_source("Corp CA", '1'), "alice");
    REQUIRE(id.has_value());
    const auto src = store.get(*id);
    RS_EXEC(rs_db_fx_, ("INSERT INTO revocation_source_store.crl (source_id, scope_key, url_id, "
                        "this_update, verified_key_sha256, der_sha256, entry_count) VALUES (" +
                        std::to_string(*id) + ", '" + scope(0) + "', " + std::to_string(src->urls[0].id) +
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

namespace {
// Run one statement on its own connection; the SQLSTATE it ended with ("00000" on success), so a
// refusal is tied to its cause (23514 is a CHECK, 23505 a UNIQUE, 428C9 a generated column).
std::string rs_state(const std::string& dsn, const std::string& sql) {
    PgConn c{PQconnectdb(dsn.c_str())};
    if (PQstatus(c.get()) != CONNECTION_OK)
        return "no-connection";
    PgResult r{PQexec(c.get(), sql.c_str())};
    if (r.status() == PGRES_COMMAND_OK || r.status() == PGRES_TUPLES_OK)
        return "00000";
    const char* st = PQresultErrorField(r.get(), PG_DIAG_SQLSTATE);
    return st ? st : "unknown";
}
bool rs_try(const std::string& dsn, const std::string& sql) { return rs_state(dsn, sql) == "00000"; }
constexpr const char* kCheckViolation = "23514";
} // namespace

TEST_CASE("RevocationSourceStore v2: one encoded scope key, pinned by a CHECK on both tables",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = create_id(store, make_source("Corp CA", '1'), "alice");
    REQUIRE(id.has_value());
    const auto src = store.get(*id);
    REQUIRE(src.has_value());
    const std::string sid = std::to_string(*id);
    const std::string uid = std::to_string(src->urls[0].id);
    const auto crl_sql = [&](const std::string& key, char der) {
        return "INSERT INTO revocation_source_store.crl (source_id, scope_key, url_id, this_update, "
               "verified_key_sha256, der_sha256, entry_count) VALUES (" + sid + ", '" + key +
               "', " + uid + ", now(), '" + hex64('1') + "', '" + hex64(der) + "', 0)";
    };
    const auto crl = [&](const std::string& key, char der) {
        return rs_try(rs_db_fx_.dsn(), crl_sql(key, der));
    };
    // Refused by the scope-key CHECK and nothing else (each uses a fresh scope and digest).
    const auto crl_check = [&](const std::string& key, char der) {
        INFO(key);
        return rs_state(rs_db_fx_.dsn(), crl_sql(key, der)) == kCheckViolation;
    };
    CHECK(crl(scope(0), 'a'));
    CHECK(crl(scope('1', true), 'b'));
    CHECK(crl_check("*", 'c'));                           // the CA-level key is rollback_high_water's alone
    CHECK(crl_check("full", 'c'));                        // no base-or-delta suffix
    CHECK(crl_check("FULL:base", 'c'));                   // one spelling only
    CHECK(crl_check("idp:1:base", 'c'));                  // the IDP part is a 64-hex digest
    CHECK(crl_check("idp:" + hex64('A') + ":base", 'c')); // lowercase hex only
    CHECK(crl_check("full:base:x", 'c'));
    CHECK(crl_check("full:both", 'c'));

    // is_delta is generated from the suffix: it agrees with the key, and cannot be written.
    PgConn conn{PQconnectdb(rs_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult rows{PQexec(conn.get(), "SELECT scope_key, is_delta FROM revocation_source_store.crl "
                                     "ORDER BY scope_key")};
    REQUIRE(rows.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(rows.get()) == 2);
    CHECK(std::string(PQgetvalue(rows.get(), 0, 0)) == scope(0));
    CHECK(std::string(PQgetvalue(rows.get(), 0, 1)) == "f");
    CHECK(std::string(PQgetvalue(rows.get(), 1, 0)) == scope('1', true));
    CHECK(std::string(PQgetvalue(rows.get(), 1, 1)) == "t");
    CHECK(rs_state(rs_db_fx_.dsn(),
                       "INSERT INTO revocation_source_store.crl (source_id, scope_key, url_id, "
                       "this_update, is_delta, verified_key_sha256, der_sha256, entry_count) VALUES (" +
                           sid + ", '" + scope('2') + "', " + uid + ", now(), TRUE, '" + hex64('1') +
                           "', '" + hex64('e') + "', 0)") == "428C9");

    // One held CRL per scope: a second insert is refused, and the fetcher's replacement (delete
    // then insert inside one transaction) leaves exactly the new CRL.
    CHECK(rs_state(rs_db_fx_.dsn(), crl_sql(scope(0), 'f')) == "23505");
    CHECK(rs_try(rs_db_fx_.dsn(),
                 "BEGIN; DELETE FROM revocation_source_store.crl WHERE source_id = " + sid +
                     " AND scope_key = '" + scope(0) + "'; " + crl_sql(scope(0), 'f') + "; COMMIT"));
    PgResult held{PQexec(conn.get(), ("SELECT der_sha256 FROM revocation_source_store.crl WHERE "
                                      "scope_key = '" + scope(0) + "'").c_str())};
    REQUIRE(held.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(held.get()) == 1);
    CHECK(std::string(PQgetvalue(held.get(), 0, 0)) == hex64('f'));

    // rollback_high_water: the same encoding, plus '*' for the CA-level row.
    const auto mark_state = [&](const std::string& key) {
        INFO(key);
        return rs_state(rs_db_fx_.dsn(),
                        "INSERT INTO revocation_source_store.rollback_high_water "
                        "(ca_subject_name_sha256, scope_key) VALUES ('" + hex64('9') + "', '" + key +
                            "')");
    };
    const auto mark = [&](const std::string& key) { return mark_state(key) == "00000"; };
    CHECK(mark("*"));
    CHECK(mark(scope(0)));
    CHECK(mark(scope('2', true)));
    CHECK(mark_state("full") == kCheckViolation);
    CHECK(mark_state("idp:7") == kCheckViolation);
    CHECK(mark_state("**") == kCheckViolation);
}

TEST_CASE("RevocationSourceStore v2: a v1 database upgrades its held rows in place",
          "[revocation_source_store][pg][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    const auto& all = revocation_source_store_migrations();
    REQUIRE(all.size() == 2);
    std::string sid, uid;
    {
        PgConn c{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        REQUIRE(pg::PgMigrationRunner::run(c.get(), "revocation_source_store", {all.front()}));
        const auto one = [&](const std::string& sql) {
            PgResult r{PQexec(c.get(), sql.c_str())};
            INFO(PQresultErrorMessage(r.get()));
            REQUIRE((r.status() == PGRES_COMMAND_OK || r.status() == PGRES_TUPLES_OK));
            return PQntuples(r.get()) == 1 ? std::string(PQgetvalue(r.get(), 0, 0)) : std::string();
        };
        sid = one("INSERT INTO revocation_source_store.source (name, ca_subject_name_sha256, "
                  "created_by) VALUES ('Corp CA', '" + hex64('1') + "', 'alice') RETURNING id");
        one("INSERT INTO revocation_source_store.source_ca_key (source_id, cert_sha256, cert_der, "
            "spki_sha256) VALUES (" + sid + ", '" + hex64('a') + "', '\\x300302010101'::bytea, '" +
            hex64('1') + "')");
        // A v1 URL in a spelling v2 does not keep, with fetch state that must survive the rewrite.
        uid = one("INSERT INTO revocation_source_store.source_url (source_id, url, host, "
                  "confirmed_address_classes) VALUES (" + sid +
                  ", 'HTTP://CRL.Example.COM:0080', 'crl.example.com', 'public') RETURNING id");
        one("INSERT INTO revocation_source_store.fetch_status (url_id, last_attempt_at) VALUES (" +
            uid + ", now())");
        // v1 held CRLs: the scope without a suffix, base or delta in is_delta.
        one("INSERT INTO revocation_source_store.crl (source_id, scope_key, url_id, this_update, "
            "is_delta, verified_key_sha256, der_sha256, entry_count) VALUES (" + sid + ", 'full', " +
            uid + ", now(), FALSE, '" + hex64('1') + "', '" + hex64('c') + "', 0), (" + sid +
            ", 'idp:" + hex64('9') + "', " + uid + ", now(), TRUE, '" + hex64('1') + "', '" +
            hex64('d') + "', 0)");
        one("INSERT INTO revocation_source_store.rollback_high_water (ca_subject_name_sha256, "
            "scope_key, reset_at) VALUES ('" + hex64('1') + "', '*', now())");
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    RevocationSourceStore store{pool};
    REQUIRE(store.is_open());

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    PgResult rows{PQexec(conn.get(), "SELECT scope_key, is_delta FROM revocation_source_store.crl "
                                     "ORDER BY scope_key")};
    REQUIRE(rows.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(rows.get()) == 2);
    CHECK(std::string(PQgetvalue(rows.get(), 0, 0)) == "full:base");
    CHECK(std::string(PQgetvalue(rows.get(), 0, 1)) == "f");
    CHECK(std::string(PQgetvalue(rows.get(), 1, 0)) == "idp:" + hex64('9') + ":delta");
    CHECK(std::string(PQgetvalue(rows.get(), 1, 1)) == "t");

    // The URL is rewritten in place: the same id, so its fetch status and held CRLs are kept.
    const auto got = store.get(std::stoll(sid));
    REQUIRE(got.has_value());
    REQUIRE(got->urls.size() == 1);
    CHECK(got->urls[0].id == std::stoll(uid));
    CHECK(got->urls[0].url == "http://crl.example.com/");
    CHECK(got->urls[0].host == "crl.example.com");
    CHECK(got->urls[0].fetch.present);
    CHECK(got->held_crl_count == 2);
    CHECK(got->reset_at.has_value()); // the CA-level mark is untouched
}

TEST_CASE("RevocationSourceStore v2: a v1 scope key that cannot take the v2 form fails the open",
          "[revocation_source_store][pg][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    const auto& all = revocation_source_store_migrations();
    {
        PgConn c{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        REQUIRE(pg::PgMigrationRunner::run(c.get(), "revocation_source_store", {all.front()}));
        PgResult r{PQexec(c.get(), ("INSERT INTO revocation_source_store.rollback_high_water "
                                    "(ca_subject_name_sha256, scope_key, crl_number, this_update) "
                                    "VALUES ('" + hex64('1') + "', 'idp:7', 41, now())").c_str())};
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    RevocationSourceStore store{pool};
    // An anti-rollback mark is never silently dropped: the CHECK fails the migration, the store
    // stays closed (boot is fail-closed), and the mark is still there to be fixed by hand.
    CHECK_FALSE(store.is_open());
    PgConn conn{PQconnectdb(db.dsn().c_str())};
    PgResult left{PQexec(conn.get(), "SELECT crl_number FROM revocation_source_store.rollback_high_water "
                                     "WHERE scope_key = 'idp:7'")};
    REQUIRE(left.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(left.get()) == 1);
    CHECK(std::string(PQgetvalue(left.get(), 0, 0)) == "41");
}

TEST_CASE("RevocationSourceStore v2: a v1 held CRL whose scope cannot take the v2 form fails the open",
          "[revocation_source_store][pg][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    const auto& all = revocation_source_store_migrations();
    {
        PgConn c{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        REQUIRE(pg::PgMigrationRunner::run(c.get(), "revocation_source_store", {all.front()}));
        const auto one = [&](const std::string& sql) {
            PgResult r{PQexec(c.get(), sql.c_str())};
            INFO(PQresultErrorMessage(r.get()));
            REQUIRE((r.status() == PGRES_COMMAND_OK || r.status() == PGRES_TUPLES_OK));
            return PQntuples(r.get()) == 1 ? std::string(PQgetvalue(r.get(), 0, 0)) : std::string();
        };
        const auto sid = one("INSERT INTO revocation_source_store.source (name, "
                             "ca_subject_name_sha256, created_by) VALUES ('Corp CA', '" +
                             hex64('1') + "', 'alice') RETURNING id");
        const auto uid = one("INSERT INTO revocation_source_store.source_url (source_id, url, host, "
                             "confirmed_address_classes) VALUES (" + sid +
                             ", 'http://crl.example.com/', 'crl.example.com', 'public') RETURNING id");
        one("INSERT INTO revocation_source_store.crl (source_id, scope_key, url_id, this_update, "
            "is_delta, verified_key_sha256, der_sha256, entry_count) VALUES (" + sid +
            ", 'idp:7', " + uid + ", now(), TRUE, '" + hex64('1') + "', '" + hex64('c') + "', 0)");
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    RevocationSourceStore store{pool};
    CHECK_FALSE(store.is_open());
    // The migration rolled back whole: the v1 row is untouched, its column still writable.
    PgConn conn{PQconnectdb(db.dsn().c_str())};
    PgResult left{PQexec(conn.get(), "SELECT scope_key, is_delta FROM revocation_source_store.crl")};
    REQUIRE(left.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(left.get()) == 1);
    CHECK(std::string(PQgetvalue(left.get(), 0, 0)) == "idp:7");
    CHECK(std::string(PQgetvalue(left.get(), 0, 1)) == "t");
}

TEST_CASE("RevocationSourceStore: a stored URL that cannot be canonicalised keeps the store closed",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = create_id(store, make_source("Corp CA", '1'), "alice");
    REQUIRE(id.has_value());
    const auto uid = store.get(*id)->urls[0].id;
    RS_EXEC(rs_db_fx_, ("UPDATE revocation_source_store.source_url SET url = 'ftp://crl.example.com/' "
                        "WHERE id = " + std::to_string(uid)).c_str());
    CHECK_FALSE(store.canonicalise_stored_urls_for_test().has_value());
    RevocationSourceStore again{rs_pool_fx_};
    CHECK_FALSE(again.is_open());
    // Nothing was rewritten.
    PgConn conn{PQconnectdb(rs_db_fx_.dsn().c_str())};
    PgResult left{PQexec(conn.get(), ("SELECT url FROM revocation_source_store.source_url WHERE id = " +
                                      std::to_string(uid)).c_str())};
    REQUIRE(left.status() == PGRES_TUPLES_OK);
    CHECK(std::string(PQgetvalue(left.get(), 0, 0)) == "ftp://crl.example.com/");
}

TEST_CASE("RevocationSourceStore: a replace refuses a URL that is not canonical",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = create_id(store, make_source("Corp CA", '1'), "alice");
    REQUIRE(id.has_value());
    auto body = at_version(make_source("Corp CA", '1'), 1);
    body.urls[0].url = "HTTP://crl.example.com:80/a.crl";
    CHECK(store.replace(*id, body).error().kind == RKind::kInvalidInput);
    CHECK(store.get(*id)->config_version == 1);
}

TEST_CASE("RevocationSourceStore: the open-time pass rewrites a stored URL and refuses a collapse",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = create_id(store, make_source("Corp CA", '1', {'a'}, {"http://crl.example.com/a.crl"}),
                              "alice");
    REQUIRE(id.has_value());
    const auto uid = store.get(*id)->urls[0].id;
    // A spelling the canonical form does not keep, as a v1 row could hold, with fetch state.
    RS_EXEC(rs_db_fx_, ("UPDATE revocation_source_store.source_url SET url = "
                        "'HTTP://CRL.EXAMPLE.COM:80/a.crl' WHERE id = " + std::to_string(uid)).c_str());
    RS_EXEC(rs_db_fx_, ("INSERT INTO revocation_source_store.fetch_status (url_id, last_attempt_at) "
                        "VALUES (" + std::to_string(uid) + ", now())").c_str());
    CHECK(store.canonicalise_stored_urls_for_test() == std::optional<std::int64_t>(1));
    auto got = store.get(*id);
    REQUIRE(got.has_value());
    CHECK(got->urls[0].id == uid);
    CHECK(got->urls[0].url == "http://crl.example.com/a.crl");
    CHECK(got->urls[0].fetch.present);
    CHECK(store.canonicalise_stored_urls_for_test() == std::optional<std::int64_t>(0)); // idempotent

    // A second URL of the SAME source that is one URL in the canonical form: the pass refuses,
    // rewrites nothing, and a fresh open stays closed.
    RS_EXEC(rs_db_fx_, ("INSERT INTO revocation_source_store.source_url (source_id, url, host, "
                        "confirmed_address_classes) VALUES (" + std::to_string(*id) +
                        ", 'http://crl.example.com:00080/a.crl', 'crl.example.com', 'public')").c_str());
    CHECK_FALSE(store.canonicalise_stored_urls_for_test().has_value());
    RevocationSourceStore again{rs_pool_fx_};
    CHECK_FALSE(again.is_open());
    PgConn conn{PQconnectdb(rs_db_fx_.dsn().c_str())};
    PgResult left{PQexec(conn.get(), "SELECT count(*) FROM revocation_source_store.source_url WHERE "
                                     "url = 'http://crl.example.com:00080/a.crl'")};
    REQUIRE(left.status() == PGRES_TUPLES_OK);
    CHECK(std::string(PQgetvalue(left.get(), 0, 0)) == "1");

    // The same canonical URL under two DIFFERENT sources is no collapse.
    RS_EXEC(rs_db_fx_, "DELETE FROM revocation_source_store.source_url WHERE url = "
                       "'http://crl.example.com:00080/a.crl'");
    const auto other = create_id(store, make_source("Other CA", '2', {'a'}, {"http://crl.example.com/a.crl"}),
                                 "alice");
    REQUIRE(other.has_value());
    CHECK(store.canonicalise_stored_urls_for_test() == std::optional<std::int64_t>(0));
}

TEST_CASE("RevocationSourceStore: a reset keeps only the named keys, at the version it was read from",
          "[revocation_source_store][pg]") {
    RS_STORE(store);
    const auto id = create_id(store, make_source("Corp CA", '1', {'a', 'b', 'c'}), "alice");
    REQUIRE(id.has_value());
    const auto src = store.get(*id);
    RS_EXEC(rs_db_fx_, ("INSERT INTO revocation_source_store.crl (source_id, scope_key, url_id, "
                        "this_update, verified_key_sha256, der_sha256, entry_count) VALUES (" +
                        std::to_string(*id) + ", '" + scope(0) + "', " + std::to_string(src->urls[0].id) +
                        ", now(), '" + hex64('2') + "', '" + hex64('c') + "', 0)").c_str());

    HighWaterResetRequest r;
    r.keep_key_sha256 = {hex64('b')};
    // A stale read: refused under the row lock, carrying the stored version.
    r.expected_config_version = 5;
    auto e = store.reset_high_water(*id, r);
    REQUIRE_FALSE(e.has_value());
    CHECK(e.error().kind == RKind::kVersionConflict);
    CHECK(e.error().existing_id == 1);
    // A surviving key the source does not hold: refused, naming the entry's index.
    r.expected_config_version = 1;
    // (index 2, so it cannot be mistaken for the stored version 1)
    r.keep_key_sha256 = {hex64('b'), hex64('c'), hex64('d')};
    e = store.reset_high_water(*id, r);
    REQUIRE_FALSE(e.has_value());
    CHECK(e.error().kind == RKind::kUnknownKey);
    CHECK(e.error().existing_id == 2);
    // The list is required, distinct, lowercase hex; the version must be a real one.
    r.keep_key_sha256 = {};
    CHECK(store.reset_high_water(*id, r).error().kind == RKind::kInvalidInput);
    r.keep_key_sha256 = {hex64('b'), hex64('b')};
    CHECK(store.reset_high_water(*id, r).error().kind == RKind::kInvalidInput);
    r.keep_key_sha256 = {hex64('B')};
    CHECK(store.reset_high_water(*id, r).error().kind == RKind::kInvalidInput);
    r.keep_key_sha256 = {hex64('b')};
    r.expected_config_version = 0;
    CHECK(store.reset_high_water(*id, r).error().kind == RKind::kInvalidInput);
    // No refusal changed anything.
    auto now = store.get(*id);
    REQUIRE(now.has_value());
    CHECK(now->keys.size() == 3);
    CHECK(now->config_version == 1);
    CHECK(now->held_crl_count == 1);
    CHECK_FALSE(now->reset_at.has_value());

    // Keep 'b' only: 'a' and 'c' are removed with every held CRL (even one 'b' verified) in the
    // reset's transaction, and the version moves.
    r.expected_config_version = 1;
    const auto ok = store.reset_high_water(*id, r);
    REQUIRE(ok.has_value());
    CHECK(ok->dropped_keys == 2);
    CHECK(ok->crls_deleted == 1);
    CHECK(ok->config_version == 2);
    now = store.get(*id);
    REQUIRE(now.has_value());
    REQUIRE(now->keys.size() == 1);
    CHECK(now->keys[0].cert_sha256 == hex64('b'));
    CHECK(now->held_crl_count == 0);
    CHECK(now->config_version == 2);
    CHECK(now->reset_at == ok->reset_at);
    // A retry from the same read (an outcome-unknown reset retried) is a conflict, not a second
    // reset.
    e = store.reset_high_water(*id, r);
    REQUIRE_FALSE(e.has_value());
    CHECK(e.error().kind == RKind::kVersionConflict);
    CHECK(e.error().existing_id == 2);
}
