// RuntimeConfigStore tests (ADR-0060) — general store behaviour. Redaction
// specifically is covered in test_runtime_config_secret_redaction.cpp; this
// file covers CRUD, updated_by/updated_at semantics, the SecretCodec
// envelope round-trip, the becomes-secret-later transitional-row transform,
// the empty-secret rule at the storage layer, degrade-distinguishable reads
// (ADR-0036), and the detect-and-warn obligation
// (docs/postgres-store-playbook.md's Backfill bullet) — there was no
// general store test file before this PR. No backfill coverage:
// ADR-0009's fresh-start-by-default amendment means this store never
// copies a legacy SQLite file.

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "key_provider.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "runtime_config_store.hpp"
#include "sqlite_raii.hpp"

#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"
#include "test_runtime_config_helpers.hpp"

#include <libpq-fe.h>
#include <sqlite3.h>

using yuzu::server::FileKeyProvider;
using yuzu::server::RuntimeConfigEntry;
using yuzu::server::RuntimeConfigStore;
using yuzu::server::kRuntimeConfigDbErrorPrefix;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
using yuzu::server::pg::SecretCodec;

// ── Degraded-store contract — NO Postgres required ─────────────────────────
//
// An invalid conninfo fails PgPool's own parse step (documented: "valid() is
// false and every acquire returns an empty lease"), so this never attempts a
// network connection and runs identically with or without
// YUZU_TEST_ENABLE_PG.

TEST_CASE("a store that failed to open reports every read/write as unexpected, never as empty",
          "[runtime_config][degrade]") {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgPool pool{{.conninfo = "this is not a valid conninfo :::", .size = 1}};
    REQUIRE_FALSE(pool.valid());

    RuntimeConfigStore store{pool, codec};
    REQUIRE_FALSE(store.is_open());

    auto all = store.get_all();
    REQUIRE_FALSE(all.has_value());
    CHECK(all.error().starts_with(kRuntimeConfigDbErrorPrefix));

    auto one = store.get("log_level");
    REQUIRE_FALSE(one.has_value());
    CHECK(one.error().starts_with(kRuntimeConfigDbErrorPrefix));

    auto secret = store.read_secret("oidc_client_secret");
    REQUIRE_FALSE(secret.has_value());
    CHECK(secret.error().starts_with(kRuntimeConfigDbErrorPrefix));

    auto set_result = store.set("log_level", "debug", "tester");
    REQUIRE_FALSE(set_result.has_value());
    CHECK(set_result.error().starts_with(kRuntimeConfigDbErrorPrefix));

    // The non-typed convenience getter collapses a degraded read to "" (the
    // same as "not set") -- documented, not a bug; see the header.
    CHECK(store.get_value("log_level").empty());

    CHECK_FALSE(store.remove("log_level"));
}

// ── Detect-and-warn (docs/postgres-store-playbook.md's Backfill bullet) — pure
//    SQLite + filesystem, NO Postgres required ─────────────────────────────

TEST_CASE("warn_if_legacy_data_present is silent when the legacy file does not exist",
          "[runtime_config][detect-and-warn]") {
    auto path = yuzu::test::unique_temp_path("yuzu_test_rtcfg_nofile_");
    REQUIRE_FALSE(std::filesystem::exists(path));

    yuzu::test::LogCapture cap;
    RuntimeConfigStore::warn_if_legacy_data_present(path);
    cap.stop();
    CHECK(cap.text().find("legacy") == std::string::npos);
}

TEST_CASE("warn_if_legacy_data_present is silent when the legacy table is empty",
          "[runtime_config][detect-and-warn]") {
    yuzu::test::TempDbFile legacy{"yuzu_test_rtcfg_empty_"};
    {
        yuzu::server::SqliteDb raw;
        REQUIRE(sqlite3_open(legacy.path.string().c_str(), raw.addr()) == SQLITE_OK);
        yuzu::server::SqliteErrMsg err;
        REQUIRE(sqlite3_exec(raw.get(),
                             "CREATE TABLE runtime_config (key TEXT PRIMARY KEY, value TEXT "
                             "NOT NULL, updated_by TEXT NOT NULL DEFAULT '', updated_at "
                             "INTEGER NOT NULL);",
                             nullptr, nullptr, err.addr()) == SQLITE_OK);
    }

    yuzu::test::LogCapture cap;
    RuntimeConfigStore::warn_if_legacy_data_present(legacy.path);
    cap.stop();
    CHECK(cap.text().find("legacy") == std::string::npos);
}

TEST_CASE("warn_if_legacy_data_present is silent when the file has no runtime_config table",
          "[runtime_config][detect-and-warn]") {
    yuzu::test::TempDbFile legacy{"yuzu_test_rtcfg_notable_"};
    {
        yuzu::server::SqliteDb raw;
        REQUIRE(sqlite3_open(legacy.path.string().c_str(), raw.addr()) == SQLITE_OK);
        yuzu::server::SqliteErrMsg err;
        REQUIRE(sqlite3_exec(raw.get(), "CREATE TABLE unrelated (x INTEGER);", nullptr, nullptr,
                             err.addr()) == SQLITE_OK);
    }

    yuzu::test::LogCapture cap;
    RuntimeConfigStore::warn_if_legacy_data_present(legacy.path);
    cap.stop();
    CHECK(cap.text().find("legacy") == std::string::npos);
}

TEST_CASE("warn_if_legacy_data_present warns with a row count when real overrides exist",
          "[runtime_config][detect-and-warn]") {
    yuzu::test::TempDbFile legacy{"yuzu_test_rtcfg_realdata_"};
    {
        yuzu::server::SqliteDb raw;
        REQUIRE(sqlite3_open(legacy.path.string().c_str(), raw.addr()) == SQLITE_OK);
        yuzu::server::SqliteErrMsg err;
        REQUIRE(sqlite3_exec(raw.get(),
                             "CREATE TABLE runtime_config (key TEXT PRIMARY KEY, value TEXT "
                             "NOT NULL, updated_by TEXT NOT NULL DEFAULT '', updated_at "
                             "INTEGER NOT NULL); "
                             "INSERT INTO runtime_config VALUES "
                             "('log_level','debug','admin',1700000000),"
                             "('oidc_client_secret','s3cr3t','admin',1700000001);",
                             nullptr, nullptr, err.addr()) == SQLITE_OK);
    }

    yuzu::test::LogCapture cap;
    RuntimeConfigStore::warn_if_legacy_data_present(legacy.path);
    cap.stop();
    const std::string text = cap.text();
    // NOT text.find("2") -- spdlog's default pattern stamps every line with the
    // current year ("2026"), which made this assertion pass regardless of the
    // actual row count (governance quality-engineer finding). Assert the real
    // count substring instead.
    CHECK(text.find("holds 2 override(s)") != std::string::npos);
    CHECK(text.find(legacy.path.string()) != std::string::npos);
    // The secret's plaintext value must never appear in the warning.
    CHECK(text.find("s3cr3t") == std::string::npos);
}

TEST_CASE("warn_if_legacy_data_present warns defensively when the legacy file is corrupt",
          "[runtime_config][detect-and-warn]") {
    yuzu::test::TempDbFile legacy{"yuzu_test_rtcfg_corrupt_"};
    {
        std::ofstream f(legacy.path, std::ios::binary);
        REQUIRE(f.is_open());
        f << "this is not a valid sqlite database file";
    }

    yuzu::test::LogCapture cap;
    RuntimeConfigStore::warn_if_legacy_data_present(legacy.path);
    cap.stop();
    CHECK(cap.text().find("legacy") != std::string::npos);
}

#ifndef _WIN32
TEST_CASE("warn_if_legacy_data_present restricts the legacy file AND its WAL/SHM sidecars to "
          "0600",
          "[runtime_config][detect-and-warn]") {
    // External adversarial-review finding: WebhookStore::migrate_from_sqlite_impl
    // (retired #3623 -- its 0600+sidecar logic lives on as the shared
    // legacy_sqlite_probe::harden_legacy_file_0600, test_legacy_sqlite_probe.cpp's
    // analogous tests) forced 0600 on a legacy plaintext-secret-bearing file AND
    // its -wal/-shm sidecars before ever reading it; this store's detect-and-warn
    // path opened the legacy file read-only without ever doing either, leaving a
    // real deployment's -wal sidecar (the pre-migration store ran
    // journal_mode=WAL unconditionally) at whatever mode it already had -- exactly
    // as sensitive as the main file it belongs to.
    yuzu::test::TempDbFile legacy{"yuzu_test_rtcfg_wal_"};
    {
        yuzu::server::SqliteDb raw;
        REQUIRE(sqlite3_open(legacy.path.string().c_str(), raw.addr()) == SQLITE_OK);
        yuzu::server::SqliteErrMsg err;
        REQUIRE(sqlite3_exec(raw.get(),
                             "CREATE TABLE runtime_config (key TEXT PRIMARY KEY, value TEXT "
                             "NOT NULL, updated_by TEXT NOT NULL DEFAULT '', updated_at "
                             "INTEGER NOT NULL);",
                             nullptr, nullptr, err.addr()) == SQLITE_OK);
    }
    // Simulate an unclean-shutdown leftover: dummy sidecars, group/world-readable,
    // sitting beside the legacy db. Content is irrelevant -- the fix only needs
    // to see them exist at the expected path.
    std::vector<std::filesystem::path> sidecars;
    for (const char* suffix : {"-wal", "-shm"}) {
        auto side = legacy.path;
        side += suffix;
        std::ofstream(side) << "dummy-sidecar-content";
        std::filesystem::permissions(side,
                                     std::filesystem::perms::owner_read |
                                         std::filesystem::perms::owner_write |
                                         std::filesystem::perms::group_read |
                                         std::filesystem::perms::others_read,
                                     std::filesystem::perm_options::replace);
        sidecars.push_back(side);
    }
    std::filesystem::permissions(legacy.path,
                                 std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write |
                                     std::filesystem::perms::group_read |
                                     std::filesystem::perms::others_read,
                                 std::filesystem::perm_options::replace);

    RuntimeConfigStore::warn_if_legacy_data_present(legacy.path);

    const auto owner_only =
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write;
    std::error_code st_ec;
    const auto main_perms = std::filesystem::status(legacy.path, st_ec).permissions();
    REQUIRE_FALSE(st_ec);
    CHECK((main_perms & std::filesystem::perms::mask) == owner_only);
    for (const auto& side : sidecars) {
        std::error_code side_ec;
        const auto perms = std::filesystem::status(side, side_ec).permissions();
        REQUIRE_FALSE(side_ec);
        CHECK((perms & std::filesystem::perms::mask) == owner_only);
    }
}
#endif

// No test exists for the sqlite3_step()-failure branch (distinct from the
// prepare()-failure branch the corrupt-file test above covers) beyond the one
// bounded attempt below (cpp-safety + advisor, Gate 8), which came back
// negative rather than green: a second connection holding BEGIN EXCLUSIVE on
// the legacy file, then a fresh RuntimeConfigStore::warn_if_legacy_data_present()
// call against it, landed in the PREPARE-fails branch, not the step-fails one --
// a brand-new SqliteDb has a cold schema cache, so its FIRST prepare() (reading
// sqlite_master) needs the same lock the later step() would have needed, and
// bites first. No externally-triggerable repro for the step-fails branch
// specifically was found in one attempt, and per governance's false-green
// floor a test that can't discriminate which branch it hit is not coverage of
// the branch it was meant to prove -- so none is shipped here.
// disposition: accepted-with-rationale (cpp-safety, Gate 8) -- the branch
// itself is retained on defensive-coverage grounds (see the code comment at
// its call site), not because it has been independently demonstrated
// reachable via an external lock the way the branch above has.

// ── Migration / fresh-database (plain YUZU_REQUIRE_PG_DB, per the playbook's
//    §7 rule — these exercise migration itself) ────────────────────────────

TEST_CASE("RuntimeConfigStore opens on a fresh Postgres and migrates once",
          "[pg][runtime_config][store]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    RuntimeConfigStore store{pool, codec};
    CHECK(store.is_open());
    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    REQUIRE(codec.init(conn.get()).has_value());

    // Re-opening a second store against the SAME already-migrated database
    // is idempotent (the migration runner records the applied version and
    // does not re-run DDL) — a second store/codec pair opens cleanly too.
    yuzu::test::TempDir keys2{"yuzu_test_keys2_"};
    FileKeyProvider provider2(keys2.path);
    SecretCodec codec2(provider2);
    RuntimeConfigStore store2{pool, codec2};
    CHECK(store2.is_open());
}

// ── Store-behaviour tests: pre-migrated template (§7) ───────────────────────
//
// No backfill section: ADR-0009's 2026-08-25 fresh-start-by-default amendment
// means this store never reads a legacy SQLite file (see the header doc).

namespace {

/// Fully-wired store for a test case: fresh keys dir, fresh codec, fresh
/// pool, `codec.init()` run in the correct order. Callers keep this alive
/// for the whole test case.
struct Wired {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider{keys.path};
    SecretCodec codec{provider};
    PgPool pool;
    RuntimeConfigStore store;

    explicit Wired(const std::string& dsn)
        : pool{{.conninfo = dsn, .size = 4}}, store{pool, codec} {
        REQUIRE(store.is_open());
        PgConn conn{PQconnectdb(dsn.c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto r = codec.init(conn.get());
        REQUIRE(r.has_value());
    }
};

std::size_t count_rows(const std::string& dsn, const char* table) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), (std::string("SELECT count(*) FROM ") + table).c_str())};
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    return static_cast<std::size_t>(std::strtoll(PQgetvalue(r.get(), 0, 0), nullptr, 10));
}

// Polls `pg_locks` on `conn` until at least one advisory-lock waiter is queued
// (not granted), or `deadline` elapses. Used by the advisory-lock regression
// tests below so the proof that a caller blocked doesn't depend on scheduling
// luck within a fixed sleep window (quality-engineer, Gate 8): the fixed hold
// only starts counting once the waiter is genuinely observed queued.
//
// Filtered to `current_database()` (quality-engineer, Gate 8, citing the
// identical #2530 G7-B3 hazard in test_kek_op_lock_holder.cpp): `pg_locks` is
// a CLUSTER-WIDE view, and the 4 server test shards share one Postgres
// container (one database per shard) -- an unfiltered query here could
// observe a SIBLING SHARD's unrelated advisory-lock waiter and return `true`
// before THIS test's own spawned thread has actually queued, silently
// reintroducing the scheduling-luck gamble this helper exists to remove.
bool wait_for_advisory_waiter(PGconn* conn, std::chrono::milliseconds deadline) {
    const auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < deadline) {
        PgResult r{PQexec(conn, "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                                "AND NOT granted AND database = (SELECT oid FROM pg_database "
                                "WHERE datname = current_database())")};
        if (r.status() == PGRES_TUPLES_OK && PQntuples(r.get()) > 0 &&
            std::strtoll(PQgetvalue(r.get(), 0, 0), nullptr, 10) > 0)
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

} // namespace

namespace {

yuzu::test::PgTestTemplate rtcfg_store_tpl{"rtcfgstore", [](const std::string& dsn) {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgPool pool{{.conninfo = dsn, .size = 1}};
    RuntimeConfigStore store{pool, codec};
    if (!store.is_open())
        throw std::runtime_error("rtcfgstore template: store failed to migrate");
    PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        throw std::runtime_error("rtcfgstore template: connect failed");
    if (!codec.init(conn.get()).has_value())
        throw std::runtime_error("rtcfgstore template: codec init failed");
    PgResult reset{PQexec(conn.get(), "DELETE FROM secrets.kek_meta")};
    if (!reset.ok())
        throw std::runtime_error("rtcfgstore template: kek_meta reset failed");
}};

} // namespace

TEST_CASE("RuntimeConfigStore: CRUD round-trips for a non-secret key",
          "[pg][runtime_config][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, rtcfg_store_tpl);
    Wired w{db.dsn()};

    CHECK_FALSE(w.store.get("log_level").value().has_value()); // unset -> nullopt, not an error
    CHECK(w.store.get_value("log_level").empty());

    REQUIRE(w.store.set("log_level", "debug", "alice").has_value());
    CHECK(w.store.get_value("log_level") == "debug");
    auto e = w.store.get("log_level");
    REQUIRE(e.has_value());
    REQUIRE(e->has_value());
    CHECK((*e)->value == "debug");
    CHECK((*e)->updated_by == "alice");
    CHECK((*e)->updated_at > 0);

    auto all = w.store.get_all();
    REQUIRE(all.has_value());
    bool found = false;
    for (const auto& entry : *all)
        if (entry.key == "log_level")
            found = true;
    CHECK(found);

    CHECK(w.store.remove("log_level"));
    CHECK(w.store.get_value("log_level").empty());
    CHECK_FALSE(w.store.remove("log_level")); // already gone
}

TEST_CASE("RuntimeConfigStore: updated_by/updated_at change on overwrite",
          "[pg][runtime_config][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, rtcfg_store_tpl);
    Wired w{db.dsn()};

    REQUIRE(w.store.set("oidc_issuer", "https://a.example", "alice").has_value());
    auto first = w.store.get("oidc_issuer");
    REQUIRE(first.has_value());
    REQUIRE(first->has_value());
    CHECK((*first)->updated_by == "alice");

    REQUIRE(w.store.set("oidc_issuer", "https://b.example", "bob").has_value());
    auto second = w.store.get("oidc_issuer");
    REQUIRE(second.has_value());
    REQUIRE(second->has_value());
    CHECK((*second)->value == "https://b.example");
    CHECK((*second)->updated_by == "bob");
    CHECK((*second)->updated_at >= (*first)->updated_at);
}

TEST_CASE("RuntimeConfigStore: set() refuses an unknown key", "[pg][runtime_config][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, rtcfg_store_tpl);
    Wired w{db.dsn()};
    auto result = w.store.set("not_a_real_key", "x", "alice");
    REQUIRE_FALSE(result.has_value());
    CHECK_FALSE(result.error().starts_with(kRuntimeConfigDbErrorPrefix)); // 400, not 503
}

TEST_CASE("RuntimeConfigStore: set() validates typed keys", "[pg][runtime_config][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, rtcfg_store_tpl);
    Wired w{db.dsn()};
    CHECK_FALSE(w.store.set("heartbeat_timeout", "not-a-number", "alice").has_value());
    CHECK_FALSE(w.store.set("heartbeat_timeout", "-5", "alice").has_value());
    CHECK(w.store.set("heartbeat_timeout", "60", "alice").has_value());

    CHECK_FALSE(w.store.set("auto_approve_enabled", "maybe", "alice").has_value());
    CHECK(w.store.set("auto_approve_enabled", "true", "alice").has_value());

    CHECK_FALSE(w.store.set("log_level", "loud", "alice").has_value());
    CHECK(w.store.set("log_level", "warn", "alice").has_value());
}

TEST_CASE("RuntimeConfigStore: a secret value round-trips through the SecretCodec envelope",
          "[pg][runtime_config][store][secret]") {
    YUZU_REQUIRE_PG_DB_TPL(db, rtcfg_store_tpl);
    Wired w{db.dsn()};

    REQUIRE(w.store.set("oidc_client_secret", "s3cr3t", "alice").has_value());

    // The plain table never sees the credential.
    CHECK(count_rows(db.dsn(), "runtime_config_store.runtime_config_secrets") == 1);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto r = yuzu::server::pg::exec_params(
            conn.get(), "SELECT value FROM runtime_config_store.runtime_config WHERE key = $1",
            std::vector<std::string>{"oidc_client_secret"});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        // Either no plain-table row at all, or one whose value is empty --
        // never the plaintext credential.
        for (int i = 0; i < PQntuples(r.get()); ++i)
            CHECK(std::string(PQgetvalue(r.get(), i, 0)).empty());
    }

    CHECK(decrypt_for_test(w.store, "oidc_client_secret") == "s3cr3t");

    // A second write re-encrypts under a fresh DEK and fully replaces the row.
    REQUIRE(w.store.set("oidc_client_secret", "rotated", "bob").has_value());
    CHECK(decrypt_for_test(w.store, "oidc_client_secret") == "rotated");
    CHECK(count_rows(db.dsn(), "runtime_config_store.runtime_config_secrets") == 1);
}

TEST_CASE("RuntimeConfigStore: a secret containing an embedded NUL/invalid-UTF-8 byte round-trips "
          "byte-for-byte, never sanitized before encrypting",
          "[pg][runtime_config][store][secret]") {
    // External adversarial-review finding: set()'s secret-key non-empty path
    // encrypted sanitize_pg_text(value) instead of the raw value -- sealed_value
    // is BYTEA, so there was no storage reason to touch the secret's bytes at
    // all, and doing so silently replaced an embedded NUL (with U+FFFD's 3-byte
    // encoding) or an invalid-UTF-8 sequence before it was ever sealed. A
    // rotated credential containing such a byte would have reported success
    // while silently storing the wrong value. WebhookStore/PluginConfigStore
    // (this store's own cited precedent) both encrypt raw -- prove this store
    // now does too, with a value sanitize_pg_text() would visibly alter.
    YUZU_REQUIRE_PG_DB_TPL(db, rtcfg_store_tpl);
    Wired w{db.dsn()};

    // sanitize_pg_text() is file-local to runtime_config_store.cpp (not
    // reachable from this test), but its documented behavior (scrub invalid
    // UTF-8 to U+FFFD, then replace any embedded NUL) means both bytes below
    // are exactly the ones it would visibly alter if applied.
    const std::string secret_with_nul("a\0b\xFF" "c", 5); // embedded NUL + invalid UTF-8 byte
    REQUIRE(w.store.set("oidc_client_secret", secret_with_nul, "alice").has_value());
    CHECK(decrypt_for_test(w.store, "oidc_client_secret") == secret_with_nul);
}

TEST_CASE("RuntimeConfigStore: an empty secret clears ciphertext but keeps attribution",
          "[pg][runtime_config][store][secret]") {
    YUZU_REQUIRE_PG_DB_TPL(db, rtcfg_store_tpl);
    Wired w{db.dsn()};

    REQUIRE(w.store.set("oidc_client_secret", "real", "alice").has_value());
    CHECK(count_rows(db.dsn(), "runtime_config_store.runtime_config_secrets") == 1);

    REQUIRE(w.store.set("oidc_client_secret", "", "bob").has_value());
    CHECK(count_rows(db.dsn(), "runtime_config_store.runtime_config_secrets") == 0);
    CHECK(decrypt_for_test(w.store, "oidc_client_secret").empty());

    auto e = w.store.get("oidc_client_secret");
    REQUIRE(e.has_value());
    REQUIRE(e->has_value());
    CHECK((*e)->value.empty());
    CHECK((*e)->updated_by == "bob"); // the CLEAR is attributed, not silently forgotten
}

TEST_CASE("RuntimeConfigStore: a stale legacy-plaintext row for a secret key is used as a "
          "fallback, then cleaned up on the next write",
          "[pg][runtime_config][store][secret]") {
    // Simulates the becomes-secret-later transitional state: a plaintext row
    // sitting in runtime_config for a key that IS classified secret today,
    // with no runtime_config_secrets row yet (as if it were written by an
    // older release, before the key was classified secret).
    YUZU_REQUIRE_PG_DB_TPL(db, rtcfg_store_tpl);
    Wired w{db.dsn()};

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto ins = yuzu::server::pg::exec_params(
            conn.get(),
            "INSERT INTO runtime_config_store.runtime_config (key, value, updated_by, "
            "updated_at) VALUES ($1, $2, $3, $4::bigint)",
            std::vector<std::string>{"oidc_client_secret", "legacy-plaintext", "seed",
                                     "1700000000"});
        REQUIRE(ins.status() == PGRES_COMMAND_OK);
    }

    // Fallback: the real value is readable even though it's still plaintext.
    CHECK(decrypt_for_test(w.store, "oidc_client_secret") == "legacy-plaintext");
    // Redaction still applies -- is_secret_key() decides, not storage location.
    CHECK(w.store.get_value("oidc_client_secret") == RuntimeConfigStore::redacted_placeholder());

    // The next write envelopes it and cleans up the stale plaintext row.
    REQUIRE(w.store.set("oidc_client_secret", "fresh-encrypted", "operator").has_value());
    CHECK(decrypt_for_test(w.store, "oidc_client_secret") == "fresh-encrypted");
    CHECK(count_rows(db.dsn(), "runtime_config_store.runtime_config_secrets") == 1);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto r = yuzu::server::pg::exec_params(
            conn.get(), "SELECT count(*) FROM runtime_config_store.runtime_config WHERE key = $1",
            std::vector<std::string>{"oidc_client_secret"});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        CHECK(std::string(PQgetvalue(r.get(), 0, 0)) == "0");
    }
}

TEST_CASE("RuntimeConfigStore: remove() deletes from both tables",
          "[pg][runtime_config][store][secret]") {
    YUZU_REQUIRE_PG_DB_TPL(db, rtcfg_store_tpl);
    Wired w{db.dsn()};

    REQUIRE(w.store.set("oidc_client_secret", "real", "alice").has_value());
    REQUIRE(w.store.set("log_level", "debug", "alice").has_value());

    CHECK(w.store.remove("oidc_client_secret"));
    CHECK(count_rows(db.dsn(), "runtime_config_store.runtime_config_secrets") == 0);
    CHECK(decrypt_for_test(w.store, "oidc_client_secret").empty());

    CHECK(w.store.remove("log_level"));
    CHECK(w.store.get_value("log_level").empty());
}

TEST_CASE("set() on a secret key blocks on a held advisory lock for the SAME key "
          "(genuine serialization proof, not thread-timing luck)",
          "[pg][runtime_config][store][secret][concurrency]") {
    // Regression test for the concurrent clear-vs-set race (governance Gate 4/5
    // chaos-confirmed BLOCKING finding): two concurrent set() calls on the SAME
    // secret key, one clearing it and one setting a real value, could interleave
    // across their independent transactions so the clearing caller was told
    // `applied:true` while the concurrently-set secret silently survived. The
    // fix is a transaction-scoped pg_advisory_xact_lock keyed by the secret key.
    // Same technique as BaselineStore's row-lock TOCTOU test: hold the identical
    // lock from a second connection so set() is made to genuinely BLOCK, rather
    // than hoping two threads happen to race.
    YUZU_REQUIRE_PG_DB_TPL(db, rtcfg_store_tpl);
    Wired w{db.dsn()};

    PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    {
        PgResult r{PQexec(locker.get(), "BEGIN")};
        REQUIRE(r.ok());
    }
    {
        // Identical hash input to set()'s own kSecretKeyLockSql -- same key, same lock ID.
        PgResult r{PQexec(
            locker.get(),
            "SELECT pg_advisory_xact_lock(hashtextextended("
            "'runtime_config_store:secret:' || 'oidc_client_secret', 0))")};
        REQUIRE(r.ok());
    }

    bool set_ok = false;
    std::string set_error;
    std::chrono::steady_clock::duration call_duration{};
    std::thread t([&] {
        const auto call_start = std::chrono::steady_clock::now();
        auto r = w.store.set("oidc_client_secret", "new-value", "tester");
        call_duration = std::chrono::steady_clock::now() - call_start;
        set_ok = r.has_value();
        if (!r)
            set_error = r.error();
    });
    // Wait until the thread is genuinely queued on the lock (not a fixed sleep
    // gambling that scheduling was fast enough to reach it) before starting the
    // deliberate hold below. Captured as a bool, NOT asserted yet -- a REQUIRE
    // here, before `t` is joined, would unwind past a still-blocked-on-the-lock
    // std::thread on the exact regression this test exists to catch (the lock
    // silently not taken, so the wait times out) and call std::terminate on
    // that still-joinable thread, aborting the whole shard instead of
    // producing one clean red test (governance Gate 3 finding, cpp-safety +
    // cpp-expert + quality-engineer independently).
    const bool queued = wait_for_advisory_waiter(locker.get(), std::chrono::seconds(5));
    // This hold is what the timed assertion below measures -- it only starts
    // once the waiter above is confirmed queued, so it is not gambling on
    // scheduling luck the way a bare pre-spawn sleep would. Held even if
    // `queued` came back false: `t` is still running set() and still needs
    // the ROLLBACK below to release it before it can be joined.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    // Join BEFORE any assertion that could throw -- a REQUIRE between spawning
    // `t` and joining it would unwind past a still-joinable std::thread on
    // failure and call std::terminate, aborting the whole shard.
    PgResult rollback_result{PQexec(locker.get(), "ROLLBACK")};
    const bool rollback_ok = rollback_result.ok();
    t.join();
    // Registered before the assertions below (not after) so it actually
    // decorates whichever one fails -- Catch2's INFO only attaches to
    // assertions that run after it in the same scope.
    INFO(set_error);
    REQUIRE(rollback_ok);
    REQUIRE(queued);

    // Self-verifying against a future regression that drops the lock silently:
    // if set() did not actually block on it, this would return almost
    // immediately, well under the 200ms this test controls.
    CHECK(call_duration >= std::chrono::milliseconds(150));

    REQUIRE(set_ok);
    CHECK(decrypt_for_test(w.store, "oidc_client_secret") == "new-value");
}

TEST_CASE("remove() on a secret key blocks on a held advisory lock for the SAME key "
          "(genuine serialization proof, not thread-timing luck)",
          "[pg][runtime_config][store][secret][concurrency]") {
    // Regression test for the Gate 8 finding (architect + security-guardian,
    // independently converged): remove() deletes from both tables with no lock
    // at all, so a concurrent remove()-vs-set() race on the same secret key was
    // unserialized the same way the original set()-vs-set() race was. remove()
    // now takes the identical per-key advisory lock, unconditionally, before
    // either DELETE -- verify it genuinely blocks rather than assuming the
    // three-line fix works because it compiles.
    YUZU_REQUIRE_PG_DB_TPL(db, rtcfg_store_tpl);
    Wired w{db.dsn()};
    REQUIRE(w.store.set("oidc_client_secret", "real-secret", "alice").has_value());

    PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    {
        PgResult r{PQexec(locker.get(), "BEGIN")};
        REQUIRE(r.ok());
    }
    {
        PgResult r{PQexec(
            locker.get(),
            "SELECT pg_advisory_xact_lock(hashtextextended("
            "'runtime_config_store:secret:' || 'oidc_client_secret', 0))")};
        REQUIRE(r.ok());
    }

    bool remove_ok = false;
    std::chrono::steady_clock::duration call_duration{};
    std::thread t([&] {
        const auto call_start = std::chrono::steady_clock::now();
        remove_ok = w.store.remove("oidc_client_secret");
        call_duration = std::chrono::steady_clock::now() - call_start;
    });
    // See the set()-side test above for why this is captured, not asserted,
    // before `t` is joined.
    const bool queued = wait_for_advisory_waiter(locker.get(), std::chrono::seconds(5));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    PgResult rollback_result{PQexec(locker.get(), "ROLLBACK")};
    const bool rollback_ok = rollback_result.ok();
    t.join();
    REQUIRE(rollback_ok);
    REQUIRE(queued);

    CHECK(call_duration >= std::chrono::milliseconds(150));
    REQUIRE(remove_ok);
    CHECK(count_rows(db.dsn(), "runtime_config_store.runtime_config_secrets") == 0);
}

TEST_CASE("read_secret() surfaces a genuine decrypt failure as unexpected, never as nullopt",
          "[pg][runtime_config][store][secret]") {
    // Regression coverage for a gap quality-engineer found in governance Gate 3: the
    // crypto_error branch (decrypt_sealed_value() failing) had zero test coverage --
    // every existing test only exercised the found-and-decryptable or not-found paths.
    // Corrupt the stored ciphertext directly so decrypt() genuinely fails, rather than
    // asserting the branch exists without ever executing it.
    YUZU_REQUIRE_PG_DB_TPL(db, rtcfg_store_tpl);
    Wired w{db.dsn()};
    REQUIRE(w.store.set("oidc_client_secret", "real-secret", "alice").has_value());

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult corrupt{PQexec(
        conn.get(),
        "UPDATE runtime_config_store.runtime_config_secrets "
        "SET sealed_value = '\\xdeadbeef'::bytea WHERE key = 'oidc_client_secret'")};
    REQUIRE(corrupt.ok());

    auto secret = w.store.read_secret("oidc_client_secret");
    REQUIRE_FALSE(secret.has_value());
    CHECK(secret.error().starts_with(kRuntimeConfigDbErrorPrefix));
}
