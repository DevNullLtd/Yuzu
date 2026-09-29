/**
 * test_settings_routes_dex_alerts.cpp — route-level tests for the Settings →
 * DEX alerts handlers against a REAL RuntimeConfigStore.
 *
 * Why this file exists (governance G3 QE + UAT live-fire 2026-06-12): the
 * cohort-export POST shipped 500ing in production because
 * `dex_cohort_export_key` was missing from RuntimeConfigStore's allowlist —
 * the handler had been exercised only against fakes, so the store's key
 * gate never ran. These tests put the real store behind every assertion.
 *
 * Covers POST /api/settings/dex-alerts/cohort-export:
 *   - valid key → 200 + persisted + audited + live-apply fn fired
 *   - empty key → 200 + persisted "" (export disabled) + audited as disabled
 *   - invalid key → 400 + store unchanged + apply fn NOT fired
 *   - store closed → 503
 *   - non-admin → 403 + nothing persisted
 */

#include "settings_routes.hpp"

#include "key_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "runtime_config_store.hpp"
#include "test_route_sink.hpp"
#include "../test_helpers.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <libpq-fe.h>

#include <filesystem>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

// Pre-migrated template — see test_settings_routes_oidc.cpp's identical
// `oidc_settings_tpl` (mirrors test_plugin_config_store_pg.cpp's
// `plugincfg_tpl`) for the full rationale. A separate template key ("rtcfgdex")
// because PgTestTemplate replay-verifies a shared key's setup by structural
// fingerprint — an identical-looking lambda in a different TU is a different
// setup, not guaranteed to replay identically.
yuzu::test::PgTestTemplate dex_alerts_tpl{"rtcfgdex", [](const std::string& dsn) {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    pg::SecretCodec codec(provider);
    pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    RuntimeConfigStore store{pool, codec};
    if (!store.is_open())
        throw std::runtime_error("rtcfgdex template: store failed to migrate");
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        throw std::runtime_error("rtcfgdex template: connect failed");
    if (!codec.init(conn.get()).has_value())
        throw std::runtime_error("rtcfgdex template: codec init failed");
    pg::PgResult reset{PQexec(conn.get(), "DELETE FROM secrets.kek_meta")};
    if (!reset.ok())
        throw std::runtime_error("rtcfgdex template: kek_meta reset failed");
}};

struct TmpDirGuard {
    fs::path path;
    explicit TmpDirGuard(fs::path p) : path(std::move(p)) { fs::create_directories(path); }
    ~TmpDirGuard() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    TmpDirGuard(const TmpDirGuard&) = delete;
    TmpDirGuard& operator=(const TmpDirGuard&) = delete;
};

struct DexAlertsHarness {
    TmpDirGuard tmp;
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::optional<yuzu::test::TempDir> keys_dir;
    std::optional<FileKeyProvider> key_provider;
    std::optional<pg::SecretCodec> secret_codec;
    std::optional<pg::PgPool> pool;
    std::unique_ptr<RuntimeConfigStore> runtime_config;
    SettingsRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    bool is_admin{true};
    int apply_calls{0};
    std::vector<std::string> audited; // "action|target_id|detail"

    explicit DexAlertsHarness(const std::string& dsn, bool open_store = true)
        : tmp(yuzu::test::unique_temp_path("settings-dex-alerts-")) {
        if (open_store) {
            keys_dir.emplace("yuzu_test_keys_");
            key_provider.emplace(keys_dir->path);
            secret_codec.emplace(*key_provider);
            pool.emplace(pg::PgPool::Options{.conninfo = dsn, .size = 4});
            REQUIRE(pool->valid());
            runtime_config = std::make_unique<RuntimeConfigStore>(*pool, *secret_codec);
            REQUIRE(runtime_config->is_open());
            pg::PgConn conn{PQconnectdb(dsn.c_str())};
            REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
            auto init_res = secret_codec->init(conn.get());
            REQUIRE(init_res.has_value());
        }
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "admin";
            s.role = auth::Role::admin;
            return s;
        };
        auto admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            if (!is_admin) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& /*result*/, const std::string& /*ttype*/,
                               const std::string& tid, const std::string& detail) -> bool {
            audited.push_back(action + "|" + tid + "|" + detail);
            return true;
        };
        routes.set_dex_alert_apply_fn([this]() { ++apply_calls; });
        routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr,
                               auto_approve,
                               /*api_token_store=*/nullptr,
                               /*mgmt_group_store=*/nullptr,
                               /*tag_store=*/nullptr,
                               /*update_registry=*/nullptr, runtime_config.get(),
                               /*audit_store=*/nullptr,
                               /*gateway_enabled=*/false, []() -> std::size_t { return 0; },
                               []() -> std::string { return "[]"; }, oidc_mu, oidc_provider);
    }
};

} // namespace

TEST_CASE("cohort-export POST: valid key persists through the REAL store + applies + audits",
          "[pg][settings][dex][perf]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_alerts_tpl);
    DexAlertsHarness h(db.dsn());
    auto res = h.sink.Post("/api/settings/dex-alerts/cohort-export", "export_key=model",
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 200);
    // The REAL store accepted the key — this is the assertion that would have
    // caught the missing-allowlist 500 before UAT did.
    CHECK(h.runtime_config->get_value("dex_cohort_export_key") == "model");
    CHECK(h.apply_calls == 1);
    REQUIRE_FALSE(h.audited.empty());
    CHECK(h.audited.back() ==
          "settings.dex_alerts.cohort_export|dex_cohort_export_key|export_key=model");
    // Re-render carries the saved key back into the form.
    CHECK(res->body.find("value=\"model\"") != std::string::npos);
}

TEST_CASE("cohort-export POST: empty key disables (valid, auditable choice)",
          "[pg][settings][dex][perf]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_alerts_tpl);
    DexAlertsHarness h(db.dsn());
    REQUIRE(h.runtime_config->set("dex_cohort_export_key", "model", "seed").has_value());
    auto res = h.sink.Post("/api/settings/dex-alerts/cohort-export", "export_key=",
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.runtime_config->get_value("dex_cohort_export_key").empty());
    CHECK(h.apply_calls == 1);
    CHECK(h.audited.back().find("export disabled") != std::string::npos);
}

TEST_CASE("cohort-export POST: invalid key 400s, persists nothing, never applies",
          "[pg][settings][dex][perf]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_alerts_tpl);
    DexAlertsHarness h(db.dsn());
    REQUIRE(h.runtime_config->set("dex_cohort_export_key", "model", "seed").has_value());
    auto res = h.sink.Post("/api/settings/dex-alerts/cohort-export",
                           "export_key=not%20a%20valid%20key%21",
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.runtime_config->get_value("dex_cohort_export_key") == "model"); // unchanged
    CHECK(h.apply_calls == 0);
}

// No Postgres fixture: open_store=false never touches the store. Kept as its
// own TEST_CASE (not a [pg]-tagged SECTION) so a `~[pg]` filtered run still
// covers this branch.
TEST_CASE("cohort-export POST: store unavailable → 503", "[settings][dex][perf]") {
    DexAlertsHarness h("", /*open_store=*/false);
    auto res = h.sink.Post("/api/settings/dex-alerts/cohort-export", "export_key=model",
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("cohort-export POST: non-admin → 403, nothing persisted",
          "[pg][settings][dex][perf]") {
    YUZU_REQUIRE_PG_DB_TPL(db, dex_alerts_tpl);
    DexAlertsHarness h(db.dsn());
    h.is_admin = false;
    auto res = h.sink.Post("/api/settings/dex-alerts/cohort-export", "export_key=model",
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.runtime_config->get_value("dex_cohort_export_key").empty());
    CHECK(h.apply_calls == 0);
}
