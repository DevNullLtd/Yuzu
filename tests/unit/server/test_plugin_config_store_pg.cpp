// test_plugin_config_store_pg.cpp — PluginConfigStore behaviour tests
// (PR1.5b). Born-on-Postgres, schema `plugin_config_store`. PG-gated: skips
// when YUZU_TEST_POSTGRES_DSN is unset, fails when it is set but broken
// (docs/postgres-store-playbook.md §7 skip-vs-fail contract).
//
// Construction order mirrors AuthDB's production wiring exactly (ADR-0010
// register-before-init, per-store SecretCodec instance): construct
// FileKeyProvider -> construct SecretCodec (ctor only) -> construct
// PluginConfigStore (registers its secret column) -> secret_codec.init().

#include <catch2/catch_test_macros.hpp>

#include "agent_registry.hpp"
#include "capability_decls/core_dispatch_capabilities.hpp"
#include "command_capability.hpp"
#include "dispatch_caller.hpp"
#include "key_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "plugin_config_parsers.hpp"
#include "plugin_config_store.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>

using yuzu::server::FileKeyProvider;
using yuzu::server::PluginConfigStore;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
using yuzu::server::pg::SecretCodec;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): pre-applies
// BOTH the `plugin_config_store` schema migration and the `secrets` schema
// migration (via a throwaway codec init), then resets `secrets.kek_meta` to
// the empty first-boot state — each test still mints its own KEK against its
// own fresh keys TempDir, exactly as on a plain empty database. Mirrors
// test_secret_codec.cpp's `secrets_tpl` pattern exactly; no key material
// reaches the shared template (the throwaway KEK's TempDir is destroyed at
// scope exit and kek_meta is emptied before the template is ever cloned).
yuzu::test::PgTestTemplate plugincfg_tpl{"plugincfg", [](const std::string& dsn) {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgPool pool{{.conninfo = dsn, .size = 1}};
    PluginConfigStore store{pool, codec};
    if (!store.is_open())
        throw std::runtime_error("plugincfg template: store failed to migrate");
    PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        throw std::runtime_error("plugincfg template: connect failed");
    if (!codec.init(conn.get()).has_value())
        throw std::runtime_error("plugincfg template: codec init failed to migrate");
    PgResult reset{PQexec(conn.get(), "DELETE FROM secrets.kek_meta")};
    if (!reset.ok())
        throw std::runtime_error("plugincfg template: kek_meta reset failed");
}};

// Runs one statement directly against `dsn`, bypassing the store's public
// API entirely — for bulk fixture seeding where looping through
// `set_config` (a lease acquire + a round trip per call) would be
// thousands of individual round trips. Mirrors test_audit_store.cpp's
// `exec_sql` + `generate_series` bulk-seed idiom exactly.
void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}

/// Fully-wired store for a test case: fresh keys dir, fresh codec, fresh
/// pool, `codec.init()` run in the correct order. Callers keep this alive
/// for the whole test case (it owns the pool and provider the store borrows).
struct Wired {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider{keys.path};
    SecretCodec codec{provider};
    PgPool pool;
    PluginConfigStore store;

    explicit Wired(const std::string& dsn)
        : pool{{.conninfo = dsn, .size = 4}}, store{pool, codec} {
        REQUIRE(store.is_open());
        PgConn conn{PQconnectdb(dsn.c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto r = codec.init(conn.get());
        INFO((r ? std::string{} : r.error().message));
        REQUIRE(r.has_value());
    }
};

// Swaps a capturing sink onto the default logger for one test and restores
// it in the destructor (including on a throwing REQUIRE) — mirrors
// test_audit_store.cpp's `LogCapture`. Catch2 runs cases serially in one
// process, so no other test logs concurrently.
class LogCapture {
public:
    LogCapture() : saved_(spdlog::default_logger()) {
        sink_ = std::make_shared<spdlog::sinks::ostream_sink_mt>(stream_);
        auto logger = std::make_shared<spdlog::logger>("plugin_config_capture", sink_);
        logger->set_level(spdlog::level::trace);
        logger->set_pattern("%v");
        spdlog::set_default_logger(logger);
    }
    ~LogCapture() { spdlog::set_default_logger(saved_); }

    LogCapture(const LogCapture&) = delete;
    LogCapture& operator=(const LogCapture&) = delete;

    [[nodiscard]] bool says(std::string_view needle) const {
        return stream_.str().find(needle) != std::string::npos;
    }

private:
    std::ostringstream stream_;
    std::shared_ptr<spdlog::sinks::ostream_sink_mt> sink_;
    std::shared_ptr<spdlog::logger> saved_;
};

} // namespace

// ── Migration / fresh-database (plain YUZU_REQUIRE_PG_DB per the playbook's
//    §7 rule — this exercises migration itself, so it must NOT use the
//    pre-migrated template) ───────────────────────────────────────────────

TEST_CASE("PluginConfigStore opens on a fresh Postgres and migrates once",
          "[pg][store][plugin_config]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    Wired w{db.dsn()};
    CHECK(w.store.is_open());

    // Re-opening a second store against the SAME already-migrated database
    // is idempotent (the migration runner records the applied version and
    // does not re-run DDL) — a second store/codec pair opens cleanly too.
    yuzu::test::TempDir keys2{"yuzu_test_keys2_"};
    FileKeyProvider provider2(keys2.path);
    SecretCodec codec2(provider2);
    PluginConfigStore store2{w.pool, codec2};
    CHECK(store2.is_open());
}

// ── Store-behaviour tests: pre-migrated template (§7) ───────────────────

TEST_CASE("Config CRUD round-trips through set/get/list/delete", "[pg][store][plugin_config]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};

    auto set1 = w.store.set_config("email", "smtp.host", "mail.example.com", "alice");
    REQUIRE(set1.has_value());
    CHECK(set1->plugin == "email");
    CHECK(set1->key == "smtp.host");
    CHECK(set1->value == "mail.example.com");
    CHECK(set1->updated_by == "alice");

    auto get1 = w.store.get_config("email", "smtp.host");
    REQUIRE(get1.has_value());
    CHECK(get1->value == "mail.example.com");

    // Overwrite — same (plugin, key), new value, RETURNING reflects it.
    auto set2 = w.store.set_config("email", "smtp.host", "mail2.example.com", "bob");
    REQUIRE(set2.has_value());
    CHECK(set2->value == "mail2.example.com");
    CHECK(set2->updated_by == "bob");

    w.store.set_config("email", "smtp.port", "587", "alice");
    w.store.set_config("firewall", "mode", "strict", "alice");

    auto listed_email = w.store.list_config("email");
    REQUIRE(listed_email.has_value());
    CHECK(listed_email->size() == 2);

    auto listed_all = w.store.list_config("");
    REQUIRE(listed_all.has_value());
    CHECK(listed_all->size() == 3);

    auto del = w.store.delete_config("email", "smtp.port");
    CHECK(del.has_value());
    auto after = w.store.get_config("email", "smtp.port");
    REQUIRE_FALSE(after.has_value());
    CHECK(after.error() == PluginConfigStore::Error::NotFound);

    // Deleting an already-absent key is NotFound, not a write failure.
    auto redel = w.store.delete_config("email", "smtp.port");
    REQUIRE_FALSE(redel.has_value());
    CHECK(redel.error() == PluginConfigStore::Error::NotFound);
}

TEST_CASE("get_config on a missing key is a typed NotFound, not an empty value",
          "[pg][store][plugin_config]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    auto missing = w.store.get_config("nosuch", "key");
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error() == PluginConfigStore::Error::NotFound);
}

TEST_CASE("set_config rejects an invalid plugin/key/value as InvalidInput",
          "[pg][store][plugin_config]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    auto bad_plugin = w.store.set_config("Email", "host", "x", "alice");
    REQUIRE_FALSE(bad_plugin.has_value());
    CHECK(bad_plugin.error() == PluginConfigStore::Error::InvalidInput);

    const std::string oversized(9000, 'x');
    auto bad_value = w.store.set_config("email", "host", oversized, "alice");
    REQUIRE_FALSE(bad_value.has_value());
    CHECK(bad_value.error() == PluginConfigStore::Error::InvalidInput);
}

// ── Secret write-only contract ───────────────────────────────────────────

TEST_CASE("A secret's plaintext never appears in the returned struct or the stored row bytes",
          "[pg][store][plugin_config][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};

    const std::string plaintext = "sk_live_super_secret_do_not_leak_12345";
    auto set = w.store.set_secret("email", "smtp.password", plaintext, "alice");
    REQUIRE(set.has_value());

    // SecretMeta has no value field at all — this is a structural guarantee,
    // not a runtime check, but pin the fields it DOES carry are the metadata
    // ones and nothing that looks like the plaintext leaked into them.
    CHECK(set->plugin == "email");
    CHECK(set->key == "smtp.password");
    CHECK(set->updated_by == "alice");
    CHECK(set->plugin.find(plaintext) == std::string::npos);
    CHECK(set->key.find(plaintext) == std::string::npos);
    CHECK(set->updated_by.find(plaintext) == std::string::npos);

    // The stored bytes are genuinely sealed — not the plaintext, not a
    // trivial encoding of it (e.g. base64), fetched straight off the wire in
    // binary format so no textual escaping could hide a substring match.
    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult res{PQexecParams(conn.get(),
                              "SELECT sealed_value FROM plugin_config_store.secrets "
                              "WHERE plugin = 'email' AND key = 'smtp.password'",
                              0, nullptr, nullptr, nullptr, nullptr, /*resultFormat=*/1)};
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(res.get()) == 1);
    const auto* raw = reinterpret_cast<const std::uint8_t*>(PQgetvalue(res.get(), 0, 0));
    const int len = PQgetlength(res.get(), 0, 0);
    const std::string stored(reinterpret_cast<const char*>(raw), static_cast<std::size_t>(len));
    CHECK(stored.find(plaintext) == std::string::npos);
    CHECK(stored != plaintext);
    CHECK_FALSE(stored.empty()); // not the DEFAULT ''::bytea placeholder either
}

TEST_CASE("A secret's plaintext never appears in a log line emitted around set_secret",
          "[pg][store][plugin_config][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};

    const std::string sentinel = "LOG-LEAK-SENTINEL-do-not-print-me-98765";
    LogCapture log;
    auto set = w.store.set_secret("email", "smtp.password", sentinel, "alice");
    REQUIRE(set.has_value());
    CHECK_FALSE(log.says(sentinel));
}

TEST_CASE("delete_secret removes the row; a second delete is NotFound",
          "[pg][store][plugin_config][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    REQUIRE(w.store.set_secret("email", "api_key", "sk_abc123", "alice").has_value());
    auto del = w.store.delete_secret("email", "api_key");
    CHECK(del.has_value());
    auto redel = w.store.delete_secret("email", "api_key");
    REQUIRE_FALSE(redel.has_value());
    CHECK(redel.error() == PluginConfigStore::Error::NotFound);
}

TEST_CASE("A set secret decrypts under the deterministic scope_key AAD — the row genuinely "
          "round-trips, both fresh and on overwrite",
          "[pg][store][plugin_config][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};

    auto decrypt_stored = [&](const std::string& plugin, const std::string& key) {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult res{PQexecParams(conn.get(),
                                  "SELECT sealed_value FROM plugin_config_store.secrets "
                                  "WHERE plugin = $1 AND key = $2",
                                  2,
                                  nullptr,
                                  std::array<const char*, 2>{plugin.c_str(), key.c_str()}.data(),
                                  nullptr, nullptr, /*resultFormat=*/1)};
        REQUIRE(res.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(res.get()) == 1);
        const auto* raw = reinterpret_cast<const std::uint8_t*>(PQgetvalue(res.get(), 0, 0));
        const auto len = static_cast<std::size_t>(PQgetlength(res.get(), 0, 0));
        auto pk = yuzu::server::plugin_config::parse_plugin_key(plugin, key);
        REQUIRE(pk.has_value());
        const std::string scope_key = yuzu::server::plugin_config::canonical_plugin_key(*pk);
        auto dec = w.codec.decrypt(
            SecretCodec::SecretId{"plugin_config_store", "secrets", "sealed_value", scope_key},
            std::span<const std::uint8_t>{raw, len});
        REQUIRE(dec.has_value());
        return std::string(reinterpret_cast<const char*>(dec->data()), dec->size());
    };

    REQUIRE(w.store.set_secret("email", "smtp.password", "first-value", "alice").has_value());
    CHECK(decrypt_stored("email", "smtp.password") == "first-value");

    // Overwrite: a fresh DEK, same scope_key AAD, still decrypts.
    REQUIRE(w.store.set_secret("email", "smtp.password", "second-value", "bob").has_value());
    CHECK(decrypt_stored("email", "smtp.password") == "second-value");
}

TEST_CASE("set_secret rejects an empty or oversized plaintext as InvalidInput",
          "[pg][store][plugin_config][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    auto empty = w.store.set_secret("email", "api_key", "", "alice");
    REQUIRE_FALSE(empty.has_value());
    CHECK(empty.error() == PluginConfigStore::Error::InvalidInput);

    const std::string oversized(70 * 1024, 'x');
    auto huge = w.store.set_secret("email", "api_key", oversized, "alice");
    REQUIRE_FALSE(huge.has_value());
    CHECK(huge.error() == PluginConfigStore::Error::InvalidInput);
}

// ── Kill switch ───────────────────────────────────────────────────────────

TEST_CASE("Kill switch: no row at either level defaults to allowed",
          "[pg][store][plugin_config][killswitch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    CHECK(w.store.action_allowed("firewall", "block"));
    CHECK(w.store.action_allowed("firewall", ""));

    auto entry = w.store.get_kill_switch("firewall", "block");
    REQUIRE(entry.has_value());
    CHECK(entry->enabled);
    CHECK(entry->reason.empty());
}

TEST_CASE("Kill switch: a plugin-level flip disables every action under it",
          "[pg][store][plugin_config][killswitch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    auto set = w.store.set_kill_switch("firewall", "", false, "incident 42", "alice");
    REQUIRE(set.has_value());
    CHECK_FALSE(set->enabled);

    CHECK_FALSE(w.store.action_allowed("firewall", "block"));
    CHECK_FALSE(w.store.action_allowed("firewall", "allow"));
    CHECK_FALSE(w.store.action_allowed("firewall", ""));
    // A different plugin is unaffected.
    CHECK(w.store.action_allowed("email", "send"));
}

TEST_CASE("Kill switch: an action-level row overrides an inherited plugin-level state",
          "[pg][store][plugin_config][killswitch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    REQUIRE(w.store.set_kill_switch("firewall", "", false, "lockdown", "alice").has_value());
    // Re-enable just one action under the plugin-level kill.
    REQUIRE(w.store.set_kill_switch("firewall", "audit", true, "audit still needed", "alice")
                .has_value());

    CHECK_FALSE(w.store.action_allowed("firewall", "block")); // still inherits plugin-level
    CHECK(w.store.action_allowed("firewall", "audit"));       // action-level override wins

    auto entry = w.store.get_kill_switch("firewall", "audit");
    REQUIRE(entry.has_value());
    CHECK(entry->enabled);
    CHECK(entry->action == "audit");
}

TEST_CASE("Wave 7: seed_kill_switch_default_off seeds a disabled plugin-level row",
          "[pg][store][plugin_config][killswitch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    REQUIRE(w.store.seed_kill_switch_default_off(
        "execution_artifacts", "default-off: forensics class (Wave 7); enable per PUT "
                               "/api/v1/plugin-config/execution_artifacts/kill-switch"));

    CHECK_FALSE(w.store.action_allowed("execution_artifacts", "shimcache"));
    auto entry = w.store.get_kill_switch("execution_artifacts", "");
    REQUIRE(entry.has_value());
    CHECK_FALSE(entry->enabled);
    CHECK(entry->set_by == "system");
}

TEST_CASE("Wave 7: seed_kill_switch_default_off is ON CONFLICT DO NOTHING — an operator's "
          "own enable survives a re-seed",
          "[pg][store][plugin_config][killswitch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    REQUIRE(w.store.seed_kill_switch_default_off("execution_artifacts", "default-off seed"));
    CHECK_FALSE(w.store.action_allowed("execution_artifacts", "shimcache"));

    // Operator explicitly re-enables it.
    REQUIRE(w.store
                .set_kill_switch("execution_artifacts", "", true, "operator re-enable", "bob")
                .has_value());
    CHECK(w.store.action_allowed("execution_artifacts", "shimcache"));

    // A later re-seed (e.g. next boot) must NOT clobber the operator's own
    // decision — ON CONFLICT (scope_key) DO NOTHING.
    REQUIRE(w.store.seed_kill_switch_default_off("execution_artifacts", "default-off seed"));
    CHECK(w.store.action_allowed("execution_artifacts", "shimcache"));
}

// The two tests above prove seed_kill_switch_default_off itself behaves —
// but nothing here proves ServerImpl's real boot sequence (server.cpp)
// actually CALLS it, or that a seed failure actually fails the boot closed.
// A full ServerImpl construction is impractical at the unit level (it needs
// a live Postgres pool, gRPC service wiring, and dozens of other
// subsystems — squarely integration-test territory), so this mirrors the
// established `[source_tripwire]` pattern used elsewhere in this suite
// (see test_response_execution_scope_authz.cpp's route_block tests): scan
// the real server.cpp source for the exact call-site shape rather than
// executing it.
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif

TEST_CASE("Wave 7: ServerImpl's boot sequence actually calls "
          "seed_kill_switch_default_off(\"execution_artifacts\", ...) and fails the boot "
          "closed on a seed error — source tripwire against server.cpp, since a full "
          "ServerImpl construction is not practical at the unit level",
          "[server][killswitch][source_tripwire]") {
    std::ifstream input(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(input.is_open());
    const std::string source{std::istreambuf_iterator<char>(input),
                             std::istreambuf_iterator<char>()};

    const auto marker = source.find("seed_kill_switch_default_off(\n");
    REQUIRE(marker != std::string::npos);
    // Bound the block to the call's own enclosing braces so the assertions
    // below can't accidentally match some unrelated later call site.
    const auto block_end = source.find("\n        }\n", marker);
    REQUIRE(block_end != std::string::npos);
    const auto block = source.substr(marker, block_end - marker);

    CHECK(block.find("\"execution_artifacts\"") != std::string::npos);

    // The call is gated on the store existing and the boot not already
    // having failed — never unconditional.
    const auto guard_start = source.rfind("if (plugin_config_store_ && !startup_failed_)",
                                          marker);
    REQUIRE(guard_start != std::string::npos);
    CHECK(guard_start < marker);

    // A seed failure sets startup_failed_ = true — the same fail-closed
    // shape every other boot-time Postgres store initialisation in this
    // function uses (e.g. plugin_config_store_ itself, a few hundred lines
    // above). No `default:`/silent-continue escape.
    CHECK(block.find("startup_failed_ = true;") != std::string::npos);
    CHECK(block.find("Refusing to start") != std::string::npos);
}

TEST_CASE("Wave 10: ServerImpl's boot sequence actually calls "
          "seed_kill_switch_default_off(\"browser_inventory\", ...) and fails the boot "
          "closed on a seed error — source tripwire against server.cpp, since a full "
          "ServerImpl construction is not practical at the unit level",
          "[server][killswitch][source_tripwire]") {
    std::ifstream input(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(input.is_open());
    const std::string source{std::istreambuf_iterator<char>(input),
                             std::istreambuf_iterator<char>()};

    // browser_inventory's seed call is the SECOND
    // `seed_kill_switch_default_off(` call site in server.cpp (the first is
    // execution_artifacts', asserted above) — find the first occurrence and
    // resume the search past it so this case can't accidentally match that
    // earlier block.
    const auto first_marker = source.find("seed_kill_switch_default_off(\n");
    REQUIRE(first_marker != std::string::npos);
    const auto marker =
        source.find("seed_kill_switch_default_off(\n", first_marker + 1);
    REQUIRE(marker != std::string::npos);
    // Bound the block to the call's own enclosing braces so the assertions
    // below can't accidentally match some unrelated later call site.
    const auto block_end = source.find("\n        }\n", marker);
    REQUIRE(block_end != std::string::npos);
    const auto block = source.substr(marker, block_end - marker);

    CHECK(block.find("\"browser_inventory\"") != std::string::npos);

    // The call is gated on the store existing and the boot not already
    // having failed — never unconditional.
    const auto guard_start = source.rfind("if (plugin_config_store_ && !startup_failed_)",
                                          marker);
    REQUIRE(guard_start != std::string::npos);
    CHECK(guard_start < marker);

    // A seed failure sets startup_failed_ = true — the same fail-closed
    // shape every other boot-time Postgres store initialisation in this
    // function uses.
    CHECK(block.find("startup_failed_ = true;") != std::string::npos);
    CHECK(block.find("Refusing to start") != std::string::npos);
}

TEST_CASE("Wave 8: ServerImpl's boot sequence actually calls "
          "seed_kill_switch_default_off(\"privacy_permissions\", ...) and fails the boot "
          "closed on a seed error — source tripwire against server.cpp, since a full "
          "ServerImpl construction is not practical at the unit level",
          "[server][killswitch][source_tripwire]") {
    std::ifstream input(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(input.is_open());
    const std::string source{std::istreambuf_iterator<char>(input),
                             std::istreambuf_iterator<char>()};

    const auto marker = source.find("seed_kill_switch_default_off(\n                    \"privacy_permissions\"");
    REQUIRE(marker != std::string::npos);
    const auto block_end = source.find("\n        }\n", marker);
    REQUIRE(block_end != std::string::npos);
    const auto block = source.substr(marker, block_end - marker);

    CHECK(block.find("\"privacy_permissions\"") != std::string::npos);

    // The call is gated on the store existing and the boot not already
    // having failed — never unconditional.
    const auto guard_start = source.rfind("if (plugin_config_store_ && !startup_failed_)",
                                          marker);
    REQUIRE(guard_start != std::string::npos);
    CHECK(guard_start < marker);
    // The guard must be this call's own, not an earlier seed's.
    CHECK(source.substr(guard_start, marker - guard_start).find("seed_kill_switch_default_off") ==
          std::string::npos);

    CHECK(block.find("startup_failed_ = true;") != std::string::npos);
    CHECK(block.find("Refusing to start") != std::string::npos);
}

TEST_CASE("set_kill_switch rejects an invalid reason as InvalidInput",
          "[pg][store][plugin_config][killswitch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    const std::string bad_reason = "bad\r\nheader-injection";
    auto res = w.store.set_kill_switch("firewall", "", false, bad_reason, "alice");
    REQUIRE_FALSE(res.has_value());
    CHECK(res.error() == PluginConfigStore::Error::InvalidInput);
}

// ── #3265 regression: __guard__.push_rules must be kill-switch-addressable,
//    and must default to allowed when no switch was ever set ─────────────

TEST_CASE("#3265: __guard__.push_rules (a reserved-namespace, system_reserved dispatch "
          "capability) defaults to allowed with no kill-switch row ever set",
          "[pg][store][plugin_config][killswitch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    // This IS the exact shape of the live #3265 defect: on a fresh store, no
    // kill switch has ever been touched for __guard__, yet
    // is_valid_identifier("__guard__") used to fail parse_kill_switch_scope
    // unconditionally, collapsing action_allowed to false regardless of any
    // actual switch state.
    CHECK(w.store.action_allowed("__guard__", "push_rules"));
    CHECK(w.store.action_allowed("__guard__", "")); // whole-plugin form too
}

TEST_CASE("#3265: an explicitly-set kill switch on __guard__/push_rules still blocks the "
          "dispatch — the reserved-namespace grammar fix must not make the switch INERT",
          "[pg][store][plugin_config][killswitch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};

    REQUIRE(w.store.set_kill_switch("__guard__", "push_rules", false, "incident", "alice")
                .has_value());
    CHECK_FALSE(w.store.action_allowed("__guard__", "push_rules"));

    // Re-enabling restores delivery.
    REQUIRE(
        w.store.set_kill_switch("__guard__", "push_rules", true, "resolved", "alice").has_value());
    CHECK(w.store.action_allowed("__guard__", "push_rules"));
}

// ── #3265: the REAL finalize_classified_command composition, not a stubbed
//    push_fn_ (TestRouteSink-style stubs bypass this chokepoint entirely,
//    which is why the original regression shipped undetected) ────────────

TEST_CASE("#3265: __guard__.push_rules survives the real classify+finalize dispatch "
          "chokepoint composed over an open PluginConfigStore, with no switch set",
          "[pg][store][plugin_config][killswitch][dispatch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};

    yuzu::server::CommandCapabilityRegistry registry{
        std::span<const yuzu::server::CommandCapability>(
            yuzu::server::capdecls::core_dispatch_capabilities())};
    const yuzu::server::DispatchCaller system_caller{.system = true};

    auto classified = yuzu::server::detail::classify_and_authorize_dispatch(
        registry, system_caller, "__guard__", "push_rules",
        [](std::string_view, std::string_view, yuzu::server::authz::Operation) { return false; });
    REQUIRE(classified.has_value());

    std::function<bool(std::string_view, std::string_view)> action_allowed =
        [&w](std::string_view p, std::string_view a) { return w.store.action_allowed(p, a); };

    auto finalized = yuzu::server::detail::finalize_classified_command(
        *classified, action_allowed, "__guard__", "push_rules", "cmd-1");
    REQUIRE(finalized.has_value());
    CHECK(finalized->wire().plugin() == "__guard__");
    CHECK(finalized->wire().action() == "push_rules");
}

TEST_CASE("#3265: the real chokepoint composition DOES still deny __guard__.push_rules once an "
          "operator explicitly sets the kill switch — proving the fix isn't a bypass",
          "[pg][store][plugin_config][killswitch][dispatch]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};
    REQUIRE(w.store.set_kill_switch("__guard__", "push_rules", false, "incident", "alice")
                .has_value());

    yuzu::server::CommandCapabilityRegistry registry{
        std::span<const yuzu::server::CommandCapability>(
            yuzu::server::capdecls::core_dispatch_capabilities())};
    const yuzu::server::DispatchCaller system_caller{.system = true};

    auto classified = yuzu::server::detail::classify_and_authorize_dispatch(
        registry, system_caller, "__guard__", "push_rules",
        [](std::string_view, std::string_view, yuzu::server::authz::Operation) { return true; });
    REQUIRE(classified.has_value());

    std::function<bool(std::string_view, std::string_view)> action_allowed =
        [&w](std::string_view p, std::string_view a) { return w.store.action_allowed(p, a); };

    auto finalized = yuzu::server::detail::finalize_classified_command(
        *classified, action_allowed, "__guard__", "push_rules", "cmd-2");
    REQUIRE_FALSE(finalized.has_value());
    CHECK(finalized.error().reason == yuzu::server::detail::DispatchDenialReason::KillSwitched);
}

// ── Fail-closed evaluation on a degraded store (no live Postgres needed —
//    a bad conninfo fails fast and deterministically) ────────────────────

TEST_CASE("A degraded/unopened store makes action_allowed return false, never true",
          "[server][config][killswitch]") {
    PgPool bad_pool{{.conninfo = "host=127.0.0.1 port=1 dbname=nonexistent",
                     .size = 1,
                     .connect_timeout_s = 1}};
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PluginConfigStore store{bad_pool, codec};
    REQUIRE_FALSE(store.is_open());

    // Fail-closed: unopened means every action reads as disabled, never
    // "allowed" — the whole point of action_allowed's collapse (ADR-0036).
    CHECK_FALSE(store.action_allowed("firewall", "block"));
    CHECK_FALSE(store.action_allowed("email", ""));
    // #3265 governance Gate 5 (chaos-injector): the reserved-namespace path
    // inherits the SAME fail-closed collapse under a degraded store — a
    // transient PG stall during a Guardian push must never read as allowed.
    CHECK_FALSE(store.action_allowed("__guard__", "push_rules"));

    // The display accessor surfaces the degradation as a typed error rather
    // than silently answering "enabled" — a caller that (incorrectly) tried
    // to use it for a go/no-go decision would at least see an error to
    // mishandle, not a confident wrong answer.
    auto entry = store.get_kill_switch("firewall", "block");
    REQUIRE_FALSE(entry.has_value());
    CHECK(entry.error() == PluginConfigStore::Error::Unavailable);
}

// ── list_config row cap + truncated out-param (Codex M8) ────────────────

TEST_CASE("list_config caps at kListRowCap rows and only flags truncated past the boundary",
          "[pg][store][plugin_config]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plugincfg_tpl);
    Wired w{db.dsn()};

    // Mirrors plugin_config_store.cpp's anonymous-namespace `kListRowCap`.
    // Not exposed via the header (deliberately internal/defensive, see the
    // .cpp's comment) — hardcoded here, so this MUST track that constant if
    // it ever changes.
    constexpr int kListRowCap = 5000;

    // Bulk-seed exactly kListRowCap rows for one plugin via a single
    // server-side INSERT ... SELECT FROM generate_series, straight through
    // the pool connection — looping kListRowCap times through set_config's
    // public API would be kListRowCap individual lease-acquire+round-trip
    // calls, which is the kind of unit-suite cost the repo's test-efficiency
    // discipline calls out explicitly. Mirrors test_audit_store.cpp's own
    // generate_series bulk-seed idiom.
    exec_sql(db.dsn(),
             "INSERT INTO plugin_config_store.configs (plugin, key, value, updated_by) "
             "SELECT 'bulkplugin', 'k' || lpad(g::text, 5, '0'), 'v', 'seed' "
             "FROM generate_series(1, " +
                 std::to_string(kListRowCap) + ") g");

    // Exact-cap boundary: kListRowCap rows exist, kListRowCap rows come
    // back, and truncated must NOT flip — this is the whole point of the
    // production code fetching one row past the cap (see
    // plugin_config_store.cpp's "Fetch one row PAST the cap" comment): a
    // full page must be distinguishable from a truncated one.
    bool truncated = true; // pre-set to a value list_config must overwrite
    auto at_cap = w.store.list_config("bulkplugin", &truncated);
    REQUIRE(at_cap.has_value());
    CHECK(at_cap->size() == static_cast<std::size_t>(kListRowCap));
    CHECK_FALSE(truncated);

    // One more row for the SAME plugin — now kListRowCap + 1 exist.
    exec_sql(db.dsn(), "INSERT INTO plugin_config_store.configs (plugin, key, value, updated_by) "
                       "VALUES ('bulkplugin', 'k05001', 'v', 'seed')");

    truncated = false; // pre-set to a value list_config must overwrite
    auto over_cap = w.store.list_config("bulkplugin", &truncated);
    REQUIRE(over_cap.has_value());
    CHECK(over_cap->size() == static_cast<std::size_t>(kListRowCap)); // still capped
    CHECK(truncated);                                                 // now flagged

    // A different plugin, well under the cap, is unaffected — the cap
    // applies per-query (the WHERE plugin = $1 scoping), not globally.
    exec_sql(db.dsn(),
             "INSERT INTO plugin_config_store.configs (plugin, key, value, updated_by) VALUES "
             "('otherplugin', 'a', 'v', 'seed'), "
             "('otherplugin', 'b', 'v', 'seed'), "
             "('otherplugin', 'c', 'v', 'seed')");
    bool other_truncated = true; // pre-set to a value list_config must overwrite
    auto other = w.store.list_config("otherplugin", &other_truncated);
    REQUIRE(other.has_value());
    CHECK(other->size() == 3);
    CHECK_FALSE(other_truncated);

    // A caller that omits `truncated` (the header's default nullptr) must
    // not crash, and still gets the same capped row count.
    auto no_ptr = w.store.list_config("bulkplugin", nullptr);
    REQUIRE(no_ptr.has_value());
    CHECK(no_ptr->size() == static_cast<std::size_t>(kListRowCap));
}
