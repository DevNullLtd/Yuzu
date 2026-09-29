/**
 * test_settings_routes_oidc.cpp - Settings -> OIDC persist honesty.
 *
 * Covers the CALLER half of the OIDC-secret redaction work. The sink half
 * (RuntimeConfigStore::set() refusing the redaction placeholder) lives in
 * test_runtime_config_secret_redaction.cpp.
 *
 * Why the caller needs its own cover: the handler discarded all six set() results and
 * reported "OIDC configuration saved" regardless, so a refused write left the live
 * provider and the store diverged behind a success toast, and a restart healed it
 * silently. Governance caught that twice - once as the discarded result, once as a
 * missing `else` on the store guard producing the same false success.
 *
 * Cases:
 *   1. the placeholder means UNCHANGED, never a new secret
 *   2. the placeholder with stray whitespace also means UNCHANGED
 *   3. a real secret persists and is reported saved
 *   4. a NULL store reports NOT SAVED (defensive; unreachable in the shipped server)
 *   5. a non-admin is refused and nothing persists
 *
 * KNOWN GAP: the production-reachable degraded state is a NON-NULL store whose
 * is_open() is false (unwritable db_dir, failed migration). Nothing covers it -- the
 * NULL case above is defensive only, since server.cpp constructs the store
 * unconditionally. Two reviewers asked for that case; it is not here yet.
 *
 * No OidcProvider mocking is needed: the handler populates authorization_endpoint in
 * both branches, so the provider ctor returns at its pre-configured-endpoints guard
 * without any network I/O.
 */

#include "settings_routes.hpp"

#include "key_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "runtime_config_store.hpp"
#include "test_route_sink.hpp"
#include "../test_helpers.hpp"
#include "test_runtime_config_helpers.hpp"
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

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): pre-applies
// BOTH the `runtime_config_store` schema migration and the `secrets` schema
// migration (via a throwaway codec init), then resets `secrets.kek_meta` to
// the empty first-boot state — mirrors test_plugin_config_store_pg.cpp's
// `plugincfg_tpl` exactly. Each test still mints its own KEK against its own
// fresh keys TempDir.
yuzu::test::PgTestTemplate oidc_settings_tpl{"rtcfgoidc", [](const std::string& dsn) {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    pg::SecretCodec codec(provider);
    pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    RuntimeConfigStore store{pool, codec};
    if (!store.is_open())
        throw std::runtime_error("rtcfgoidc template: store failed to migrate");
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        throw std::runtime_error("rtcfgoidc template: connect failed");
    if (!codec.init(conn.get()).has_value())
        throw std::runtime_error("rtcfgoidc template: codec init failed");
    pg::PgResult reset{PQexec(conn.get(), "DELETE FROM secrets.kek_meta")};
    if (!reset.ok())
        throw std::runtime_error("rtcfgoidc template: kek_meta reset failed");
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

struct OidcHarness {
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
    std::vector<std::string> audited; // "action|result|target_id|detail"

    explicit OidcHarness(const std::string& dsn, bool open_store = true)
        : tmp(yuzu::test::unique_temp_path("yuzu_test_settings_oidc_")) {
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
                               const std::string& result, const std::string& /*ttype*/,
                               const std::string& tid, const std::string& detail) -> bool {
            audited.push_back(action + "|" + result + "|" + tid + "|" + detail);
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

// ── Settings -> OIDC persist honesty ────────────────────────────────────────
//
// These cover the handler-level half of the redaction work. The store-level half
// (set() refusing the placeholder) is covered in
// test_runtime_config_secret_redaction.cpp; this file covers the caller, which is
// where the real regression was: the handler discarded all six set() results and
// reported "saved" regardless.

namespace {
std::string oidc_form(const std::string& secret, const std::string& issuer = "https://idp.example",
                      const std::string& client_id = "cid") {
    return "issuer=" + issuer + "&client_id=" + client_id + "&client_secret=" + secret +
           "&redirect_uri=&admin_group=&skip_tls_verify=false";
}
} // namespace

TEST_CASE("Settings OIDC: the redaction placeholder means UNCHANGED, never a new secret",
          "[pg][settings][oidc][secret]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_settings_tpl);
    OidcHarness h(db.dsn());
    REQUIRE(h.runtime_config->set("oidc_client_secret", "real-secret", "seed").has_value());

    auto res = h.sink.Post("/api/settings/oidc", oidc_form("<redacted>"),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 200);

    // The stored credential is untouched -- not overwritten with the placeholder,
    // and not blanked.
    CHECK(decrypt_for_test(*h.runtime_config, "oidc_client_secret") == "real-secret");
    // And no failure was reported, because submitting the placeholder is a no-op on
    // the secret rather than an error.
    CHECK(res->body.find("could NOT be saved") == std::string::npos);
}

TEST_CASE("Settings OIDC: a placeholder with stray whitespace is also treated as UNCHANGED",
          "[pg][settings][oidc][secret]") {
    // Exact-match let a pasted "<redacted>\n" through both this guard and the store's,
    // persisting it as the client secret and destroying the real one.
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_settings_tpl);
    OidcHarness h(db.dsn());
    REQUIRE(h.runtime_config->set("oidc_client_secret", "real-secret", "seed").has_value());

    auto res = h.sink.Post("/api/settings/oidc", oidc_form("  <redacted>  "),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(decrypt_for_test(*h.runtime_config, "oidc_client_secret") == "real-secret");
}

TEST_CASE("Settings OIDC: a real secret is persisted and reported saved",
          "[pg][settings][oidc][secret]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_settings_tpl);
    OidcHarness h(db.dsn());
    auto res = h.sink.Post("/api/settings/oidc", oidc_form("brand-new-secret"),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(decrypt_for_test(*h.runtime_config, "oidc_client_secret") == "brand-new-secret");
    CHECK(res->body.find("could NOT be saved") == std::string::npos);
}

TEST_CASE("Settings OIDC: a NULL store reports NOT SAVED instead of success",
          "[settings][oidc][secret]") {
    // NULL store only - see the KNOWN GAP in this file's header. The regression this
    // pins: the persist block was guarded on is_open() with no
    // else, so a degraded store skipped the failure branch and still rendered the
    // success toast -- the same false-success the guard exists to remove. No Postgres
    // needed: open_store=false never touches the store at all.
    OidcHarness h{"", /*open_store=*/false};

    auto res = h.sink.Post("/api/settings/oidc", oidc_form("brand-new-secret"),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->body.find("could NOT be saved") != std::string::npos);
    // ...and it is audited as a failure, not a success.
    REQUIRE_FALSE(h.audited.empty());
    CHECK(h.audited.back().find("oidc.configure") != std::string::npos);
    CHECK(h.audited.back().find("persist failed") != std::string::npos);
    CHECK(h.audited.back().find("oidc.configure|failure|") != std::string::npos);
}

TEST_CASE("Settings OIDC: a non-admin cannot set the client secret and nothing persists",
          "[pg][settings][oidc][secret]") {
    // The admin gate is the outermost control on this handler. Asserting it here keeps
    // the redaction work from being the only thing standing between a lower-privileged
    // operator and the OIDC credential.
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_settings_tpl);
    OidcHarness h(db.dsn());
    h.is_admin = false;
    REQUIRE(h.runtime_config->set("oidc_client_secret", "real-secret", "seed").has_value());

    auto res = h.sink.Post("/api/settings/oidc", oidc_form("attacker-supplied"),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(decrypt_for_test(*h.runtime_config, "oidc_client_secret") == "real-secret");
    CHECK(h.audited.empty());
}

TEST_CASE("Settings OIDC: a secret CONTAINING the placeholder is refused, not silently dropped",
          "[pg][settings][oidc][secret]") {
    // CH-4. The handler used the CONTAINS predicate to mean "leave unchanged", so a real
    // credential containing the token was discarded and the operator was told SAVED -
    // the same false-success this branch exists to remove, re-entering through the guard
    // added to remove it. Four reviewers found it independently. Only an EXACT
    // placeholder means unchanged now; containment reaches the sink and is reported.
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_settings_tpl);
    OidcHarness h(db.dsn());
    REQUIRE(h.runtime_config->set("oidc_client_secret", "real-secret", "seed").has_value());

    auto res = h.sink.Post("/api/settings/oidc", oidc_form("abc<redacted>def"),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    // The operator is TOLD, rather than getting a success toast.
    CHECK(res->body.find("could NOT be saved") != std::string::npos);
    CHECK(res->body.find("oidc_client_secret") != std::string::npos);
    // The stored credential is untouched either way - the sink refused the write.
    CHECK(decrypt_for_test(*h.runtime_config, "oidc_client_secret") == "real-secret");
    // ...and it is audited as a failure.
    REQUIRE_FALSE(h.audited.empty());
    CHECK(h.audited.back().find("persist failed") != std::string::npos);
    CHECK(h.audited.back().find("oidc.configure|failure|") != std::string::npos);
}

TEST_CASE("Settings OIDC: hot-reload preserves the configured link claim (ADR-2001 gap fix)",
          "[pg][settings][oidc][adr2001]") {
    // Before the fix, this handler built a fresh local oidc::OidcConfig that left
    // scim_link_claim at its struct default ("sub") regardless of what the operator
    // configured via --oidc-scim-link-claim -- silently reverting an Entra ("oid")
    // deployment's link claim the moment ANY OIDC setting was saved via the Settings
    // UI, until the next process restart re-read the flag.
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_settings_tpl);
    OidcHarness h(db.dsn());
    h.cfg.oidc_scim_link_claim = "oid";

    auto res = h.sink.Post("/api/settings/oidc", oidc_form("brand-new-secret"),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 200);
    REQUIRE(h.oidc_provider != nullptr);

    // Differential probe mirroring test_oidc_provider.cpp's "missing oid is rejected
    // when oid is the link claim": a claims set with a valid sub but an EMPTY oid is
    // rejected iff the reloaded provider's link claim is "oid" -- and would be wrongly
    // ACCEPTED under the bugged "sub" default this test pins against.
    oidc::IdTokenClaims claims;
    claims.iss = "https://idp.example";
    claims.aud = "cid";
    claims.sub = "user-123";
    claims.nonce = "n";
    claims.exp = 9999999999;
    // claims.oid left at its default-constructed empty string.

    auto result = h.oidc_provider->validate_claims(claims, "n");
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().find("oid") != std::string::npos);
}

TEST_CASE("Settings OIDC: an EXACT placeholder still means unchanged, and reports saved",
          "[pg][settings][oidc][secret]") {
    // The benign case the CONTAINS rule was over-serving: pasting the token back from the
    // startup log or an API response must remain a no-op, not an error.
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_settings_tpl);
    OidcHarness h(db.dsn());
    REQUIRE(h.runtime_config->set("oidc_client_secret", "real-secret", "seed").has_value());

    auto res = h.sink.Post("/api/settings/oidc", oidc_form("  <redacted>\n"),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->body.find("could NOT be saved") == std::string::npos);
    CHECK(decrypt_for_test(*h.runtime_config, "oidc_client_secret") == "real-secret");
}
