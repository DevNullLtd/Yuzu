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
 * No OidcProvider mocking is needed for the persist cases: the provider constructor does no
 * network I/O (endpoints are discovered lazily on the first login), so a save never contacts
 * the IdP. The discovery cases at the end use the loopback MockIdp.
 */

#include "settings_routes.hpp"

#include "key_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "runtime_config_store.hpp"
#include "test_oidc_mock_idp.hpp"
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
        // The mock IdPs listen on loopback, which the OIDC egress policy refuses by default; the
        // refusal cases set it back to false.
        cfg.oidc_allow_private_networks = true;
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
           "&redirect_uri=https://yuzu.example/auth/callback&admin_group=&skip_tls_verify=false";
}
} // namespace

// A blank Redirect URI is a configuration that cannot sign in (no discovery, /auth/oidc/start
// answers 500), so the route refuses it with a red 400 naming the field instead of a success toast.
TEST_CASE("Settings OIDC: a blank Redirect URI is refused with a 400 naming the field",
          "[settings][oidc]") {
    OidcHarness h{"", /*open_store=*/false};
    for (const char* blank : {"", "+", "%20%09"}) {
        CAPTURE(blank);
        auto res = h.sink.Post(
            "/api/settings/oidc",
            std::string("issuer=https://idp.example&client_id=cid&client_secret=s&redirect_uri=") +
                blank + "&admin_group=&skip_tls_verify=false",
            "application/x-www-form-urlencoded");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("feedback-error") != std::string::npos);
        CHECK(res->body.find("Redirect URI is required") != std::string::npos);
        CHECK(res->body.find("could NOT be saved") == std::string::npos);
        CHECK(h.oidc_provider == nullptr); // nothing was built or swapped in
        CHECK(h.audited.empty());          // and no configure event was claimed
    }
}

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

// ── Discovery wiring (#5692) ─────────────────────────────────────────────────

#ifndef YUZU_OIDC_MOCK_IDP_TSAN
namespace {
using yuzu::server::test::MockIdp;

std::string discovery_form(const MockIdp& idp, const std::string& issuer = {}) {
    return "issuer=" + (issuer.empty() ? idp.base() : issuer) +
           "&client_id=yuzu-test-client&client_secret=s"
           "&redirect_uri=http://localhost:8443/auth/callback&admin_group=&skip_tls_verify=false";
}
} // namespace

TEST_CASE("Settings OIDC: a saved issuer is discovered lazily - the first login reaches the IdP's "
          "own authorization endpoint",
          "[settings][oidc][oidc_discovery]") {
    // The hot-reload site used to derive `{issuer}/authorize` and pre-set it, so discovery never
    // ran. Now the save contacts nothing and the provider discovers on its first login.
    MockIdp idp;
    idp.with([](MockIdp& m) { m.discovery_issuer = m.base(); });
    OidcHarness h{"", /*open_store=*/false};
    auto res =
        h.sink.Post("/api/settings/oidc", discovery_form(idp), "application/x-www-form-urlencoded");
    REQUIRE(res);
    REQUIRE(h.oidc_provider != nullptr);
    CHECK(idp.discovery_calls.load() == 0); // saving does no network I/O
    const auto flow = h.oidc_provider->start_auth_flow();
    CHECK(flow.url.starts_with(idp.base() + "/authorize?"));
    CHECK(idp.discovery_calls.load() == 1);
}

TEST_CASE("Settings OIDC test connection: reports what a login will find",
          "[settings][oidc][oidc_discovery]") {
    MockIdp idp;
    OidcHarness h{"", /*open_store=*/false};
    const auto test = [&](const std::string& issuer = {}) {
        auto r = h.sink.Post("/api/settings/oidc/test",
                             "issuer=" + (issuer.empty() ? idp.base() : issuer),
                             "application/x-www-form-urlencoded");
        REQUIRE(r);
        return r->body;
    };

    SECTION("a healthy IdP: discovery and one signing key") {
        const auto body = test();
        CHECK(body.find("feedback-ok") != std::string::npos);
        CHECK(body.find("1 signing key<") != std::string::npos); // singular
        CHECK(idp.discovery_calls.load() == 1);
        CHECK(idp.jwks_calls.load() == 1);
        REQUIRE_FALSE(h.audited.empty());
        CHECK(h.audited.front().find("oidc.test|attempt|") == 0);
    }
    SECTION("several keys are counted in the plural") {
        idp.with([](MockIdp& m) { m.jwks_key_count = 3; });
        CHECK(test().find("3 signing keys<") != std::string::npos);
    }
    SECTION("a discovery failure is named") {
        idp.with([](MockIdp& m) { m.discovery_status = 500; });
        const auto body = test();
        CHECK(body.find("Discovery failed: HTTP 500") != std::string::npos);
        CHECK(idp.jwks_calls.load() == 0);
    }
    SECTION("a JWKS failure is named, after discovery succeeded") {
        idp.with([](MockIdp& m) { m.jwks_status = 500; });
        CHECK(test().find("the JWKS could not be fetched: HTTP 500") != std::string::npos);
    }
    SECTION("an empty key set is not a pass") {
        idp.with([](MockIdp& m) { m.jwks_key_count = 0; });
        const auto body = test();
        CHECK(body.find("feedback-error") != std::string::npos);
        CHECK(body.find("no usable signing keys") != std::string::npos);
    }
    SECTION(
        "a malformed discovery document or JWKS reaches the answer without Unicode line breaks") {
        // The JSON error text quotes the bytes it was reading: NEL, U+2028 and U+2029 must not
        // survive into the text an admin sees (or the log it is copied from).
        const std::string breaks = "\xC2\x85\xE2\x80\xA8\xE2\x80\xA9";
        const auto clean = [&](const std::string& body) {
            CHECK(body.find("feedback-error") != std::string::npos);
            CHECK(body.find("\xC2\x85") == std::string::npos);
            CHECK(body.find("\xE2\x80\xA8") == std::string::npos);
            CHECK(body.find("\xE2\x80\xA9") == std::string::npos);
        };
        idp.with([&](MockIdp& m) { m.discovery_body = "{\"issuer\":\"" + breaks; });
        auto body = test();
        CHECK(body.find("not valid JSON") != std::string::npos);
        clean(body);
        idp.with([&](MockIdp& m) {
            m.discovery_body.clear();
            m.jwks_body = "{\"keys\":[\"" + breaks;
        });
        body = test();
        CHECK(body.find("JWKS parse error") != std::string::npos);
        clean(body);
    }
    SECTION("IdP-controlled text in the answer is HTML-escaped") {
        idp.with([](MockIdp& m) { m.discovery_issuer = "<script>alert(1)</script>"; });
        const auto body = test();
        CHECK(body.find("<script>") == std::string::npos);
        CHECK(body.find("&lt;script&gt;") != std::string::npos);
    }
    SECTION("a blank issuer asks for one without any request") {
        auto r =
            h.sink.Post("/api/settings/oidc/test", "issuer=", "application/x-www-form-urlencoded");
        REQUIRE(r);
        CHECK(r->body.find("Enter an Issuer URL first") != std::string::npos);
        CHECK(idp.discovery_calls.load() == 0);
    }
    SECTION("a blank form issuer falls back to the saved one") {
        h.cfg.oidc_issuer = idp.base();
        auto r =
            h.sink.Post("/api/settings/oidc/test", "issuer=", "application/x-www-form-urlencoded");
        REQUIRE(r);
        CHECK(r->body.find("feedback-ok") != std::string::npos);
    }
}
TEST_CASE("Settings OIDC test connection: the egress policy refuses an internal typed issuer",
          "[settings][oidc][oidc_egress]") {
    MockIdp idp;
    OidcHarness h{"", /*open_store=*/false};
    h.cfg.oidc_allow_private_networks = false; // the shipped default
    const auto test = [&](const std::string& issuer) {
        auto r = h.sink.Post("/api/settings/oidc/test", "issuer=" + issuer,
                             "application/x-www-form-urlencoded");
        REQUIRE(r);
        return r->body;
    };

    SECTION("a loopback issuer: the fixed text, no address, and the IdP sees nothing") {
        const auto body = test(idp.base());
        CHECK(body.find("feedback-error") != std::string::npos);
        CHECK(body.find("address not permitted") != std::string::npos);
        CHECK(body.find("127.0.0.1") == std::string::npos);
        CHECK(idp.discovery_calls.load() == 0);
    }
    SECTION("the same issuer connects once the server operator allows private networks") {
        h.cfg.oidc_allow_private_networks = true;
        CHECK(test(idp.base()).find("feedback-ok") != std::string::npos);
        CHECK(idp.discovery_calls.load() == 1);
    }
    SECTION("a cloud-metadata issuer is refused even then") {
        h.cfg.oidc_allow_private_networks = true;
        const auto body = test("http://169.254.169.254");
        CHECK(body.find("feedback-error") != std::string::npos);
        CHECK(body.find("address not permitted") != std::string::npos);
        CHECK(body.find("169.254") == std::string::npos);
    }
    SECTION("a JWKS on a refused host is refused although the issuer was allowed") {
        h.cfg.oidc_allow_private_networks = true;
        idp.with([](MockIdp& m) {
            m.discovery_body = R"({"issuer":")" + m.base() + R"(","authorization_endpoint":")" +
                               m.base() + R"(/authorize","token_endpoint":")" + m.base() +
                               R"(/token","jwks_uri":"http://169.254.169.254/jwks"})";
        });
        const auto body = test(idp.base());
        CHECK(body.find("the JWKS could not be fetched") != std::string::npos);
        CHECK(body.find("address not permitted") != std::string::npos);
        CHECK(idp.jwks_calls.load() == 0);
    }
}

TEST_CASE("Settings OIDC: the egress switch is OS-level and no form field can change it",
          "[settings][oidc][oidc_egress][security]") {
    MockIdp idp;
    OidcHarness h{"", /*open_store=*/false};
    h.cfg.oidc_allow_private_networks = false;
    for (const char* field : {"oidc_allow_private_networks", "allow_private_networks",
                              "oidc-allow-private-networks", "oidc_allow_private"}) {
        CAPTURE(field);
        auto res = h.sink.Post("/api/settings/oidc", discovery_form(idp) + "&" + field + "=true",
                               "application/x-www-form-urlencoded");
        REQUIRE(res);
        REQUIRE(h.oidc_provider != nullptr);
        CHECK_FALSE(h.cfg.oidc_allow_private_networks);
        // The rebuilt provider still refuses the loopback IdP, and the IdP saw nothing.
        CHECK_THROWS_AS(h.oidc_provider->start_auth_flow(), std::runtime_error);
        CHECK(idp.discovery_calls.load() == 0);
    }
    // The Test Connection route does not read the field either.
    auto r = h.sink.Post("/api/settings/oidc/test",
                         "issuer=" + idp.base() + "&oidc_allow_private_networks=true",
                         "application/x-www-form-urlencoded");
    REQUIRE(r);
    CHECK(r->body.find("address not permitted") != std::string::npos);
    CHECK(idp.discovery_calls.load() == 0);
}
#endif // !YUZU_OIDC_MOCK_IDP_TSAN
