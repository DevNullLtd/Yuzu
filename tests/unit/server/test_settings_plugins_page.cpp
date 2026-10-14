/**
 * @file test_settings_plugins_page.cpp
 * @brief System > Plugins and updates: page template pins, the page gate, and the three
 *        read fragments' gates and degraded/denied answers. Pure cases need no Postgres:
 *        every one returns before a store is dereferenced (stores left null) or exercises
 *        the gate alone. The Ready paths over a real PluginConfigStore are [pg].
 */

#include "app_shell.hpp"
#include "key_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "plugin_config_store.hpp"
#include "rbac_store.hpp"
#include "settings_plugins_routes.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cctype>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>

extern const char* const kSettingsPluginsHtml;

using namespace yuzu::server;
using Catch::Matchers::ContainsSubstring;

namespace {

bool has(const std::string& h, const std::string& n) { return h.find(n) != std::string::npos; }

/// The templates wrap prose across source lines; collapse runs of whitespace so a phrase
/// assertion does not depend on where the line broke.
std::string squash(const std::string& s) {
    std::string out;
    bool space = false;
    for (unsigned char c : s) {
        if (std::isspace(c)) {
            space = true;
            continue;
        }
        if (space && !out.empty())
            out.push_back(' ');
        space = false;
        out.push_back(static_cast<char>(c));
    }
    return out;
}

std::size_t count_of(const std::string& h, std::string_view n) {
    std::size_t c = 0;
    for (auto p = h.find(n); p != std::string::npos; p = h.find(n, p + n.size()))
        ++c;
    return c;
}

} // namespace

// ── The page template ───────────────────────────────────────────────────────

TEST_CASE("plugins page: one shell block, Settings / Plugins and updates, own entry lit",
          "[plugins_page][plugins][ui]") {
    const std::string html = kSettingsPluginsHtml;
    CHECK(count_of(html, shell::kShellBegin) == 1);
    CHECK(count_of(html, shell::kShellEnd) == 1);
    CHECK(count_of(html, "fetch('/api/me')") == 1);
    CHECK_THAT(html, ContainsSubstring("<a href=\"/settings/plugins\" class=\"on\""));
    CHECK_THAT(html, ContainsSubstring("<span>Settings</span><span class=\"shell-sep\">/</span>"
                                       "<b>Plugins and updates</b>"));
}

TEST_CASE("plugins page: five sections keep the ids the hosted handlers target",
          "[plugins_page][plugins][ui]") {
    const std::string html = kSettingsPluginsHtml;
    // The hosted handlers hx-target these exact ids; renaming one breaks every write.
    for (const char* id : {"plugin-config-section", "kill-switch-section", "plugin-signing-section",
                           "product-packs-section", "updates-section"})
        CHECK_THAT(html, ContainsSubstring(std::string("id=\"") + id + "\""));
    for (const char* url :
         {"/fragments/settings/plugin-config", "/fragments/settings/kill-switch",
          "/fragments/settings/plugin-signing", "/fragments/settings/product-packs",
          "/fragments/settings/updates"})
        CHECK_THAT(html, ContainsSubstring(std::string("hx-get=\"") + url + "\""));
    // The signing section still reloads on the event the hosted handlers fire.
    CHECK_THAT(html, ContainsSubstring("load, refreshPluginSigning from:body"));
    // The invented "Agent plugin policy" panel (version 7, 24 allowed) is not drawn.
    CHECK_FALSE(has(html, "Agent plugin policy"));
    CHECK_FALSE(has(html, "Policy version"));
}

TEST_CASE("plugins page: no hx-on, no inline handler, no innerHTML of server text",
          "[plugins_page][plugins][ui][security]") {
    const std::string html = kSettingsPluginsHtml;
    CHECK_FALSE(has(html, "hx-on"));
    CHECK_FALSE(std::regex_search(html, std::regex(R"(\son[a-z]+\s*=\s*["'])")));
    CHECK_THAT(html, ContainsSubstring("\"allowEval\":false"));
    CHECK_FALSE(std::regex_search(html, std::regex(R"(\.innerHTML\s*=)")));
    CHECK_FALSE(has(html, "eval("));
    CHECK_FALSE(has(html, "new Function"));
    // Error bodies are parsed inertly (DOMParser), never via a detached element's innerHTML.
    CHECK_THAT(html, ContainsSubstring("new DOMParser()"));
    CHECK_THAT(html, ContainsSubstring("htmx:responseError"));
}

TEST_CASE("plugins page: toast host and listener are present", "[plugins_page][plugins][ui]") {
    const std::string html = kSettingsPluginsHtml;
    CHECK_THAT(html, ContainsSubstring("id=\"toast-container\""));
    CHECK_THAT(html, ContainsSubstring("function showToast("));
    CHECK_THAT(html, ContainsSubstring("addEventListener('showToast'"));
}

TEST_CASE("plugins page: wording does not repeat the artboard's false claims",
          "[plugins_page][plugins][ui]") {
    const std::string html = kSettingsPluginsHtml;
    CHECK_FALSE(has(html, "reject unsigned plugins on every agent"));
    CHECK_FALSE(has(html, "Stops this plugin on every agent immediately"));
    CHECK_THAT(squash(html), ContainsSubstring("Each agent enforces its own"));
    CHECK_THAT(squash(html),
               ContainsSubstring("Agents do not check revocation when loading plugins"));
    CHECK_THAT(html, ContainsSubstring("href=\"/settings/pki\""));
    CHECK_THAT(squash(html), ContainsSubstring("not how many have updated"));
}

TEST_CASE("plugins page: the computed confirms read the data-* the hosted rows carry",
          "[plugins_page][plugins][ui]") {
    const std::string html = kSettingsPluginsHtml;
    CHECK_THAT(html, ContainsSubstring("addEventListener('htmx:confirm'"));
    CHECK_THAT(html, ContainsSubstring("rolloutQuestion"));
    CHECK_THAT(html, ContainsSubstring("uploadQuestion"));
    // Same version rule as the server: one of .exe .bin .tar.gz .zip .msi is stripped.
    for (const char* sfx : {".tar.gz", ".exe", ".bin", ".zip", ".msi"})
        CHECK_THAT(html, ContainsSubstring(std::string("'") + sfx + "'"));
    // An invalid (blank) rollout is never confirmed: validation reports instead.
    CHECK_THAT(html, ContainsSubstring("reportValidity()"));
    // The posted text is read with stoi server-side: 1e2 would apply 1% under a "100%" prompt.
    CHECK_THAT(html, ContainsSubstring("/^[0-9]{1,3}$/.test(pct)"));
}

// ── Gates ───────────────────────────────────────────────────────────────────

namespace {

struct Harness {
    test::TestRouteSink sink;
    bool admin{true};
    bool session{true};
    int admin_calls{0};

    void wire(settings_plugins::Deps deps = {}) {
        deps.admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            ++admin_calls;
            if (!admin) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403}})", "application/json");
                return false;
            }
            return true;
        };
        deps.auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            if (!session)
                return std::nullopt;
            auth::Session s;
            s.username = "alice";
            s.role = auth::Role::admin;
            return s;
        };
        settings_plugins::register_settings_plugins_routes(sink, std::move(deps));
    }
};

} // namespace

TEST_CASE("plugins page route: admin gets the page, a refusal redirects home",
          "[plugins_page][plugins]") {
    Harness h;
    h.wire();
    auto ok = h.sink.Get("/settings/plugins");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK_THAT(ok->body, ContainsSubstring("Plugins and updates"));

    h.admin = false;
    auto no = h.sink.Get("/settings/plugins");
    REQUIRE(no);
    CHECK(no->status == 302);
    CHECK(no->get_header_value("Location") == "/");
}

TEST_CASE("plugin fragments: the legacy admin gate runs first on every fragment",
          "[plugins_page][plugins][security]") {
    Harness h;
    h.admin = false;
    h.wire();
    for (const char* path :
         {"/fragments/settings/plugin-config", "/fragments/settings/kill-switch",
          "/fragments/settings/product-packs"}) {
        INFO(path);
        auto r = h.sink.Get(path);
        REQUIRE(r);
        CHECK(r->status == 403);
        CHECK_FALSE(has(r->body, "<table"));
    }
}

TEST_CASE("plugin fragments: no session is a denied note at 200, not an endless Loading",
          "[plugins_page][plugins][security]") {
    Harness h;
    h.session = false;
    h.wire();
    struct Case {
        const char* path;
        const char* grant;
    };
    for (auto c : {Case{"/fragments/settings/plugin-config", "PluginConfig:Read"},
                   Case{"/fragments/settings/kill-switch", "PluginConfig:Read"},
                   Case{"/fragments/settings/product-packs", "ProductPack:Read"}}) {
        INFO(c.path);
        auto r = h.sink.Get(c.path);
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK_THAT(r->body, ContainsSubstring(c.grant));
        CHECK_THAT(r->body, ContainsSubstring("data-denied=\"1\""));
        CHECK(r->get_header_value("Cache-Control") == "no-store");
    }
}

TEST_CASE("plugin fragments: unset stores are degraded notes, never an empty list",
          "[plugins_page][plugins]") {
    Harness h;
    h.wire(); // every store null
    // plugin-config: with no RBAC store the ADR-0017 list gate cannot be decided.
    auto cfg = h.sink.Get("/fragments/settings/plugin-config");
    REQUIRE(cfg);
    CHECK(cfg->status == 200);
    CHECK_THAT(cfg->body, ContainsSubstring("not an empty list"));
    CHECK_FALSE(has(cfg->body, "No plugin settings stored."));

    auto ks = h.sink.Get("/fragments/settings/kill-switch?plugin=processes");
    REQUIRE(ks);
    CHECK(ks->status == 200);
    CHECK_THAT(ks->body, ContainsSubstring("not an empty list"));
    CHECK_FALSE(has(ks->body, ">Enabled</span>"));

    auto packs = h.sink.Get("/fragments/settings/product-packs");
    REQUIRE(packs);
    CHECK(packs->status == 200);
    CHECK_THAT(packs->body, ContainsSubstring("not an empty list"));
    CHECK_FALSE(has(packs->body, "No product packs installed."));
}

// ── [pg] Ready paths over a real PluginConfigStore ──────────────────────────
//
// Same pre-migrated templates test_plugin_config_routes.cpp uses (identical setup under
// the same key, so the registry's replay check holds).

namespace {

yuzu::test::PgTestTemplate plug_page_rbac_tpl{"pluginroutesrbac", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    RbacStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("pluginroutes rbac template: store failed to migrate");
}};

yuzu::test::PgTestTemplate plug_page_store_tpl{"pluginroutes", [](const std::string& dsn) {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider(keys.path);
    pg::SecretCodec codec(provider);
    pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    PluginConfigStore store{pool, codec};
    if (!store.is_open())
        throw std::runtime_error("pluginroutes template: store failed to migrate");
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        throw std::runtime_error("pluginroutes template: connect failed");
    if (!codec.init(conn.get()).has_value())
        throw std::runtime_error("pluginroutes template: codec init failed");
    pg::PgResult reset{PQexec(conn.get(), "DELETE FROM secrets.kek_meta")};
    if (!reset.ok())
        throw std::runtime_error("pluginroutes template: kek_meta reset failed");
}};

struct PgWired {
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    FileKeyProvider provider{keys.path};
    pg::SecretCodec codec{provider};
    pg::PgPool pool;
    PluginConfigStore store;

    explicit PgWired(const std::string& dsn)
        : pool{{.conninfo = dsn, .size = 4}}, store{pool, codec} {
        REQUIRE(store.is_open());
        pg::PgConn conn{PQconnectdb(dsn.c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        REQUIRE(codec.init(conn.get()).has_value());
    }
};

const char* kHelp = R"({"plugins":[{"name":"processes","actions":[{"name":"list"}]},)"
                    R"({"name":"quarantine","actions":[{"name":"status"}]}]})";

} // namespace

TEST_CASE("plugin-config fragment: lists stored rows escaped, and shows no secret",
          "[pg][plugins_page][plugins]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plug_page_store_tpl);
    YUZU_REQUIRE_PG_DB_TPL(rbac_db, plug_page_rbac_tpl);
    PgWired w{db.dsn()};
    yuzu::server::pg::PgPool rbac_pool{{.conninfo = rbac_db.dsn(), .size = 2}};
    RbacStore rbac{rbac_pool};
    REQUIRE(rbac.is_open());
    REQUIRE(w.store.set_config("email", "smtp.host", "mail.example.com", "alice"));
    REQUIRE(w.store.set_config("email", "note", "<img src=x onerror=1>", "alice"));
    REQUIRE(w.store.set_secret("email", "api_key", "sk_live_do_not_leak", "alice"));

    Harness h;
    settings_plugins::Deps deps;
    deps.config_store = &w.store;
    deps.rbac_store = &rbac;
    h.wire(std::move(deps));

    auto r = h.sink.Get("/fragments/settings/plugin-config");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK_THAT(r->body, ContainsSubstring("smtp.host"));
    CHECK_THAT(r->body, ContainsSubstring("mail.example.com"));
    CHECK_THAT(r->body, ContainsSubstring("&lt;img src=x onerror=1&gt;"));
    CHECK_FALSE(has(r->body, "<img"));
    // A secret has no read path, and the panel names no secret rows at all.
    CHECK_FALSE(has(r->body, "sk_live_do_not_leak"));
    CHECK_FALSE(has(r->body, "api_key"));
}

TEST_CASE("plugin-config fragment: RBAC on with no grant is a denied note at 200",
          "[pg][plugins_page][plugins][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plug_page_store_tpl);
    YUZU_REQUIRE_PG_DB_TPL(rbac_db, plug_page_rbac_tpl);
    PgWired w{db.dsn()};
    yuzu::server::pg::PgPool rbac_pool{{.conninfo = rbac_db.dsn(), .size = 2}};
    RbacStore rbac{rbac_pool};
    REQUIRE(rbac.is_open());
    REQUIRE(w.store.set_config("email", "smtp.host", "mail.example.com", "alice"));
    rbac.set_rbac_enabled(true); // enforcement on, no role granted to alice

    Harness h;
    settings_plugins::Deps deps;
    deps.config_store = &w.store;
    deps.rbac_store = &rbac;
    h.wire(std::move(deps));

    auto r = h.sink.Get("/fragments/settings/plugin-config");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK_THAT(r->body, ContainsSubstring("PluginConfig:Read"));
    CHECK_FALSE(has(r->body, "mail.example.com"));
    // The kill-switch lookup applies the same securable and shows the same note.
    auto ks = h.sink.Get("/fragments/settings/kill-switch?plugin=email");
    REQUIRE(ks);
    CHECK_THAT(ks->body, ContainsSubstring("PluginConfig:Read"));
}

TEST_CASE("kill-switch fragment: a per-OS switch is visible and named, names are checked",
          "[pg][plugins_page][plugins]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plug_page_store_tpl);
    PgWired w{db.dsn()};
    REQUIRE(w.store.set_kill_switch("processes", "", false, "maintenance window", "alice", "windows"));

    Harness h;
    settings_plugins::Deps deps;
    deps.config_store = &w.store;
    deps.help_json_fn = [] { return std::string(kHelp); };
    h.wire(std::move(deps));

    auto r = h.sink.Get("/fragments/settings/kill-switch?plugin=processes");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK_THAT(r->body, ContainsSubstring("<td>Windows</td>"));
    CHECK_THAT(r->body, ContainsSubstring(">Disabled</span>"));
    CHECK_THAT(r->body, ContainsSubstring("<code>processes@windows</code>"));
    CHECK_THAT(r->body, ContainsSubstring("maintenance window"));
    // The all-OS layer alone would have read Enabled; both are shown.
    CHECK_THAT(r->body, ContainsSubstring(">Enabled</span>"));
    CHECK_FALSE(has(r->body, "has not seen plugin"));
    // The datalist is the fleet-observed catalogue.
    CHECK_THAT(r->body, ContainsSubstring("<option value=\"quarantine\">"));

    // A misspelt plugin still looks up (no switch set) but is flagged: it would stop nothing.
    auto typo = h.sink.Get("/fragments/settings/kill-switch?plugin=procesess");
    REQUIRE(typo);
    CHECK_THAT(typo->body, ContainsSubstring("has not seen plugin 'procesess'"));
    CHECK_THAT(typo->body, ContainsSubstring("No switch set"));

    // A protective plugin carries the note.
    auto q = h.sink.Get("/fragments/settings/kill-switch?plugin=quarantine");
    REQUIRE(q);
    CHECK_THAT(q->body, ContainsSubstring("protective actions of this plugin are never refused"));

    // The grammar is checked before any read; the lookup never echoes it unescaped.
    auto bad = h.sink.Get("/fragments/settings/kill-switch?plugin=%3Cscript%3E");
    REQUIRE(bad);
    CHECK_THAT(bad->body, ContainsSubstring("is not valid"));
    CHECK_FALSE(has(bad->body, "<script>"));
}
