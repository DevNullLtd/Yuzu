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
#include "plugin_config_routes.hpp"
#include "plugin_config_store.hpp"
#include "product_pack_store.hpp"
#include "settings_plugins_routes.hpp"
#include "settings_routes.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <regex>
#include <set>
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
    CHECK_THAT(squash(html), ContainsSubstring("Internal CA section of"));
    // The shared sidebar now links the Certificates and secrets page, so the check is scoped to the
    // signing note itself: it must not send the operator to the PKI page to issue a certificate.
    const auto note_at = html.find("To issue a code-signing");
    REQUIRE(note_at != std::string::npos);
    const auto note_end = html.find("</p>", note_at);
    REQUIRE(note_end != std::string::npos);
    CHECK_FALSE(has(html.substr(note_at, note_end - note_at), "/settings/pki"));
    // The PKI page has no issue control: the sentence must name the API route, not send the
    // operator there to issue.
    CHECK_THAT(squash(html), ContainsSubstring("POST /api/v1/ca/issue-code-signing"));
    CHECK_THAT(squash(html), ContainsSubstring("issue_code_signing_cert"));
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
    bool admin{true};          // the loud page gate (GET /settings/plugins only)
    bool probe_admin_ok{true}; // the quiet fragment gate
    bool session{true};
    bool elevated{false};
    int admin_calls{0};
    int probe_admin_calls{0};
    std::set<std::string> denied_perms;   // "Type:Op" the permission probe refuses
    std::vector<std::string> perm_probes; // every "Type:Op" a fragment asked, in order
    int list_refusal{0};                  // 401/403/503: the list-read probe renders it, no admit
    bool list_scoped{false};              // the list-read probe admits with a management-group scope
    std::vector<std::string> list_probes; // every "Type:Op" the list-read probe was asked

    /// What `AuthRoutes::probe_global_list_read` / `require_global_list_read` decide for the cases a unit
    /// test can name, in the real gate's order: no session refuses, an active elevation is
    /// admitted unfiltered BEFORE any grant is consulted, then the configured refusals apply.
    ListReadGate list_gate(httplib::Response& res, const std::string& type,
                           const std::string& op) {
        list_probes.push_back(type + ":" + op);
        ListReadGate g;
        int status = list_refusal;
        if (!status && !session)
            status = 401;
        if (!status && !elevated && denied_perms.count(type + ":" + op) != 0)
            status = 403;
        if (status != 0) {
            res.status = status;
            return g;
        }
        g.admitted = true;
        if (list_scoped && !elevated)
            g.scope = std::vector<std::string>{"agent-1"};
        return g;
    }

    /// What the production permission probe does for the cases a unit test can name: no
    /// session fails; an active elevation is full admin (AuthRoutes::require_permission's
    /// own short-circuit); otherwise the configured refusals apply. The real gates, and the
    /// audit rows they write, are exercised in test_settings_plugins_authz.cpp.
    bool perm_allowed(const std::string& type, const std::string& op) const {
        if (!session)
            return false;
        if (elevated)
            return true;
        return denied_perms.count(type + ":" + op) == 0;
    }

    std::optional<auth::Session> make_session() const {
        if (!session)
            return std::nullopt;
        auth::Session s;
        s.username = "alice";
        s.role = auth::Role::admin;
        if (elevated) {
            // is_elevated adjudicates against the monotonic steady deadline derived here.
            const std::int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                            std::chrono::system_clock::now().time_since_epoch())
                                            .count();
            REQUIRE(auth::AuthManager::derive_session_deadlines(
                s, now_ms, now_ms + 8LL * 3600 * 1000, now_ms, /*mfa_verified_ms=*/0,
                /*elevated_until_ms=*/now_ms + 5 * 60'000, /*elevation_issued_ms=*/now_ms, now_ms));
        }
        return s;
    }

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
        deps.probe_admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            ++probe_admin_calls;
            if (!probe_admin_ok) {
                res.status = 403;
                return false;
            }
            return true;
        };
        deps.probe_perm_fn = [this](const httplib::Request&, const std::string& type,
                                    const std::string& op) {
            perm_probes.push_back(type + ":" + op);
            return perm_allowed(type, op);
        };
        deps.probe_list_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                         const std::string& type, const std::string& op) {
            return list_gate(res, type, op);
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

TEST_CASE("plugin fragments: the quiet admin probe runs first and a refusal is a 200 denied note",
          "[plugins_page][plugins][security]") {
    Harness h;
    h.probe_admin_ok = false; // e.g. the session lost admin between page delivery and fragment load
    h.wire();
    for (const char* path :
         {"/fragments/settings/plugin-config", "/fragments/settings/kill-switch",
          "/fragments/settings/product-packs"}) {
        INFO(path);
        auto r = h.sink.Get(path);
        REQUIRE(r);
        // htmx drops a 4xx body and would stay on "Loading...": the answer is a 200 note.
        CHECK(r->status == 200);
        CHECK_THAT(r->body, ContainsSubstring("data-denied=\"1\""));
        CHECK_FALSE(has(r->body, "<table"));
        CHECK(r->get_header_value("Cache-Control") == "no-store");
    }
    CHECK(h.probe_admin_calls == 3);
    // The loud gate (an auth.admin_required row per refusal) is never the fragments' gate,
    // and nothing is asked after the admin probe refused.
    CHECK(h.admin_calls == 0);
    CHECK(h.perm_probes.empty());
    CHECK(h.list_probes.empty());
}

TEST_CASE("plugin fragments: each asks the permission probe for exactly its twin's securable",
          "[plugins_page][plugins][security]") {
    Harness h;
    h.wire(); // every store null: the answers are degraded notes, the probes still ran
    (void)h.sink.Get("/fragments/settings/plugin-config");
    // The list is gated by the list-read probe ALONE (the REST and MCP twins' sole gate):
    // stacking a bare permission probe on it is the defect class require_list_read forbids.
    CHECK(h.list_probes == std::vector<std::string>{"PluginConfig:Read"});
    CHECK(h.perm_probes.empty());
    (void)h.sink.Get("/fragments/settings/product-packs");
    CHECK(h.perm_probes == std::vector<std::string>{"ProductPack:Read"});
    h.perm_probes.clear();
    // The kill-switch lookup asks PluginConfig:Read first; with the store unset it answers
    // degraded before the catalogue (Infrastructure:Read) is considered.
    (void)h.sink.Get("/fragments/settings/kill-switch?plugin=processes");
    CHECK(h.perm_probes == std::vector<std::string>{"PluginConfig:Read"});
    CHECK(h.admin_calls == 0);
}

TEST_CASE("plugin fragments: a refused permission probe is a denied note naming the grant",
          "[plugins_page][plugins][security]") {
    Harness h;
    h.denied_perms = {"PluginConfig:Read", "ProductPack:Read"};
    h.wire();
    struct Case {
        const char* path;
        const char* grant;
    };
    for (auto c : {Case{"/fragments/settings/plugin-config", "PluginConfig:Read"},
                   Case{"/fragments/settings/kill-switch?plugin=processes", "PluginConfig:Read"},
                   Case{"/fragments/settings/product-packs", "ProductPack:Read"}}) {
        INFO(c.path);
        auto r = h.sink.Get(c.path);
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK_THAT(r->body, ContainsSubstring(c.grant));
        CHECK_THAT(r->body, ContainsSubstring("data-denied=\"1\""));
    }
}

TEST_CASE("plugin fragments: unwired probes fail closed and never open",
          "[plugins_page][plugins][security]") {
    test::TestRouteSink sink;
    settings_plugins::Deps deps;
    deps.admin_fn = [](const httplib::Request&, httplib::Response&) { return true; };
    // The admin probe passes, so each fragment goes on to its own unwired inner gate
    // (probe_list_read_fn for the config list, probe_perm_fn for the other two): a guard that
    // skipped an unwired gate would admit and reach the (null) stores' degraded notes instead.
    deps.probe_admin_fn = [](const httplib::Request&, httplib::Response&) { return true; };
    settings_plugins::register_settings_plugins_routes(sink, std::move(deps)); // no inner probes
    for (const char* path :
         {"/fragments/settings/plugin-config", "/fragments/settings/kill-switch",
          "/fragments/settings/product-packs"}) {
        INFO(path);
        auto r = sink.Get(path);
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK_THAT(r->body, ContainsSubstring("data-denied=\"1\""));
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

namespace {

/// A source file with its comments removed (whole-line `//` and block comments), so a pin
/// matches live code only: a comment that mentions the call must not satisfy it.
std::string live_code(const std::filesystem::path& file) {
    std::ifstream f(file);
    std::string live;
    bool in_block = false;
    for (std::string line; std::getline(f, line);) {
        if (in_block) {
            const auto end = line.find("*/");
            if (end == std::string::npos)
                continue;
            line.erase(0, end + 2);
            in_block = false;
        }
        const auto first = line.find_first_not_of(" \t");
        if (first == std::string::npos || line.compare(first, 2, "//") == 0)
            continue;
        if (line.compare(first, 2, "/*") == 0 && line.find("*/") == std::string::npos) {
            in_block = true;
            continue;
        }
        live += line + "\n";
    }
    return live;
}

} // namespace

TEST_CASE("plugin fragments: server.cpp binds the quiet probes for the fragments and the loud gate for the page",
          "[plugins_page][plugins][security]") {
    // The cases above fake the gates; test_settings_plugins_authz.cpp drives the real ones.
    // This pins that the production binding is the one that file proves.
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    const std::string server = live_code(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE_FALSE(server.empty());
    const auto at = server.find("register_settings_plugins_routes(");
    REQUIRE(at != std::string::npos);
    const auto end = server.find("help_json_fn", at);
    REQUIRE(end != std::string::npos);
    const std::string blk = server.substr(at, end - at);
    CHECK_THAT(blk, ContainsSubstring("return require_admin(req, res);"));
    CHECK_THAT(blk, ContainsSubstring("return auth_routes_->probe_admin(req, res);"));
    CHECK_THAT(blk, ContainsSubstring("return auth_routes_->has_permission(req, type, op);"));
    CHECK_THAT(blk, ContainsSubstring("return auth_routes_->probe_global_list_read(req, res, type, op);"));

    // The REST twin is gated by the global-grant list gate (the fragment's loud twin); the MCP
    // twin uses the shared list_read_fn and audits a scoped admission itself.
    const auto twin_at = server.find("register_plugin_config_routes(");
    REQUIRE(twin_at != std::string::npos);
    const auto twin_end = server.find(".perm_fn", twin_at);
    REQUIRE(twin_end != std::string::npos);
    CHECK_THAT(server.substr(twin_at, twin_end - twin_at),
               ContainsSubstring("auth_routes_->require_global_list_read(req, res, type, op);"));
    CHECK_THAT(server, ContainsSubstring("mcp_server_->set_list_read_fn(list_read_fn);"));
}

TEST_CASE("plugin fragments: unset stores are degraded notes, never an empty list",
          "[plugins_page][plugins]") {
    Harness h;
    h.wire(); // every store null
    // plugin-config: the list gate admits, but there is no store to list.
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

// Identical setup and key to test_product_pack_store.cpp: the registry's replay check needs it.
yuzu::test::PgTestTemplate plug_page_packs_tpl{"productpackstore", [](const std::string& dsn) {
    pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    ProductPackStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("product_pack_store template: store failed to migrate");
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
    PgWired w{db.dsn()};
    REQUIRE(w.store.set_config("email", "smtp.host", "mail.example.com", "alice"));
    REQUIRE(w.store.set_config("email", "note", "<img src=x onerror=1>", "alice"));
    REQUIRE(w.store.set_secret("email", "api_key", "sk_live_do_not_leak", "alice"));

    Harness h;
    settings_plugins::Deps deps;
    deps.config_store = &w.store;
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

TEST_CASE("plugin-config fragment: the list-read probe's verdict is the panel state",
          "[plugins_page][plugins][security]") {
    struct Case {
        int refusal;
        bool scoped;
        const char* needle;
    };
    // 401/403 and a management-group-scoped admission are denied notes; a 503 (the
    // authorization store unavailable) is the degraded note, never a false "no access".
    for (auto c : {Case{403, false, "data-denied=\"1\""}, Case{401, false, "data-denied=\"1\""},
                   Case{0, true, "data-denied=\"1\""}, Case{503, false, "not an empty list"}}) {
        INFO("refusal " << c.refusal << " scoped " << c.scoped);
        Harness h; // stores unset: nothing past the gate may be reached on a refusal
        h.list_refusal = c.refusal;
        h.list_scoped = c.scoped;
        h.wire();
        auto r = h.sink.Get("/fragments/settings/plugin-config");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK_THAT(r->body, ContainsSubstring(c.needle));
        if (c.refusal != 503) {
            CHECK_THAT(r->body, ContainsSubstring("PluginConfig:Read"));
            CHECK_FALSE(has(r->body, "not an empty list"));
        }
        CHECK(h.list_probes == std::vector<std::string>{"PluginConfig:Read"});
    }
}

TEST_CASE("plugin-config fragment and the REST twin bound to one list gate serve the same "
          "answer for an elevated session with no underlying grant",
          "[pg][plugins_page][plugins][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plug_page_store_tpl);
    YUZU_REQUIRE_PG_DB_TPL(pack_db, plug_page_packs_tpl);
    PgWired w{db.dsn()};
    yuzu::server::pg::PgPool pack_pool{{.conninfo = pack_db.dsn(), .size = 2}};
    ProductPackStore packs{pack_pool};
    REQUIRE(packs.is_open());
    REQUIRE(w.store.set_config("email", "smtp.host", "mail.example.com", "alice"));

    Harness h;
    settings_plugins::Deps deps;
    deps.config_store = &w.store;
    deps.pack_store = &packs;
    h.wire(std::move(deps));
    // The REST twin on the same sink, gated by the same fake list gate: this pins the WIRING (one
    // gate, both surfaces). The real gate's elevation rule is proven in
    // test_settings_plugins_authz.cpp ("agree for an elevated session").
    plugin_config::Deps twin;
    twin.store = &w.store;
    twin.list_read_fn = [&h](const httplib::Request&, httplib::Response& res,
                             const std::string& type, const std::string& op) {
        return h.list_gate(res, type, op);
    };
    twin.auth_fn = [&h](const httplib::Request&,
                        httplib::Response&) -> std::optional<auth::Session> {
        return h.make_session();
    };
    twin.perm_fn = [&h](const httplib::Request&, httplib::Response& res, const std::string& type,
                        const std::string& op) {
        const bool ok = h.perm_allowed(type, op);
        if (!ok)
            res.status = 403;
        return ok;
    };
    plugin_config::register_plugin_config_routes(h.sink, std::move(twin));

    // Not elevated, no grant: the permission probe refuses (as the twin's perm_fn does).
    h.denied_perms = {"PluginConfig:Read", "ProductPack:Read"};
    CHECK(h.sink.Get("/api/v1/plugin-config")->status == 403);
    auto packs_denied = h.sink.Get("/fragments/settings/product-packs");
    REQUIRE(packs_denied);
    CHECK_THAT(packs_denied->body, ContainsSubstring("ProductPack:Read"));
    CHECK_FALSE(has(h.sink.Get("/fragments/settings/plugin-config")->body, "mail.example.com"));

    // Elevated: `require_list_read` admits an active elevation unfiltered (full admin for the
    // window, no underlying grant needed), and the REST list, the fragment and the MCP tool all
    // consult that one gate, so BOTH surfaces serve the list. Neither is wider than the other.
    h.elevated = true;
    const auto rest = h.sink.Get("/api/v1/plugin-config");
    REQUIRE(rest);
    CHECK(rest->status == 200);
    CHECK_THAT(rest->body, ContainsSubstring("mail.example.com"));
    const auto cfg = h.sink.Get("/fragments/settings/plugin-config");
    REQUIRE(cfg);
    CHECK_FALSE(has(cfg->body, "data-denied"));
    CHECK_THAT(cfg->body, ContainsSubstring("mail.example.com"));
    // Packs have no list gate beyond the permission, which the elevation satisfies.
    auto pk = h.sink.Get("/fragments/settings/product-packs");
    REQUIRE(pk);
    CHECK_FALSE(has(pk->body, "data-denied"));
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
    // PluginConfig:Read gates the lookup; Infrastructure:Read only decides whether the
    // fleet-observed catalogue is drawn.
    CHECK(h.perm_probes == std::vector<std::string>{"PluginConfig:Read", "Infrastructure:Read"});
    CHECK_THAT(r->body, ContainsSubstring("<td>Windows</td>"));
    CHECK_THAT(r->body, ContainsSubstring(">Disabled</span>"));
    CHECK_THAT(r->body, ContainsSubstring("<code>processes@windows</code>"));
    CHECK_THAT(r->body, ContainsSubstring("maintenance window"));
    // The all-OS layer alone would have read Enabled; both are shown.
    CHECK_THAT(r->body, ContainsSubstring(">Enabled</span>"));
    CHECK_FALSE(has(r->body, "has not seen plugin"));
    // All four layers are read, in order: all-OS, Windows, Linux, macOS. A missing layer would
    // hide a per-OS switch that withholds the command from that OS.
    {
        const auto all = r->body.find("<td>All operating systems</td>");
        const auto win = r->body.find("<td>Windows</td>");
        const auto lin = r->body.find("<td>Linux</td>");
        const auto mac = r->body.find("<td>macOS</td>");
        REQUIRE(all != std::string::npos);
        REQUIRE(win != std::string::npos);
        REQUIRE(lin != std::string::npos);
        REQUIRE(mac != std::string::npos);
        CHECK(all < win);
        CHECK(win < lin);
        CHECK(lin < mac);
    }
    // The datalist is the fleet-observed catalogue.
    CHECK_THAT(r->body, ContainsSubstring("<option value=\"quarantine\">"));

    // Without Infrastructure:Read the lookup still answers (it is PluginConfig:Read's), but the
    // fleet-observed catalogue is not drawn and the names are not checked against it.
    h.denied_perms = {"Infrastructure:Read"};
    auto no_infra = h.sink.Get("/fragments/settings/kill-switch?plugin=processes");
    REQUIRE(no_infra);
    CHECK_FALSE(has(no_infra->body, "data-denied"));
    CHECK_THAT(no_infra->body, ContainsSubstring(">Disabled</span>"));
    CHECK_FALSE(has(no_infra->body, "<option value=\"quarantine\">"));
    h.denied_perms.clear();

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

// ── Product packs: the ready path through the route (live ProductPackStore) ─────────────────

namespace {

std::string pack_yaml(const std::string& name) {
    return "apiVersion: yuzu.io/v1alpha1\nkind: ProductPack\nname: " + name +
           "\nversion: 1.0.0\ndescription: pack " + name +
           "\n---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nname: item-" + name +
           "\n";
}

} // namespace

TEST_CASE("product-packs fragment: live packs are mapped and the first-N banner is exact",
          "[pg][plugins_page][plugins]") {
    YUZU_REQUIRE_PG_DB_TPL(db, plug_page_packs_tpl);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ProductPackStore store{pool};
    REQUIRE(store.is_open());
    store.set_require_signed_packs(false);
    auto install_fn = [](const std::string&, const std::string& name)
        -> std::expected<std::string, std::string> { return "id-" + name; };
    REQUIRE(store.install(pack_yaml("alpha"), install_fn).has_value());

    Harness h;
    settings_plugins::Deps deps;
    deps.pack_store = &store;
    h.wire(std::move(deps));

    auto one = h.sink.Get("/fragments/settings/product-packs");
    REQUIRE(one);
    CHECK(one->status == 200);
    CHECK_THAT(one->body, ContainsSubstring("<b>alpha</b>"));
    CHECK_THAT(one->body, ContainsSubstring("<code>1.0.0</code>"));
    CHECK_THAT(one->body, ContainsSubstring("1 item"));
    CHECK_THAT(one->body, ContainsSubstring("Unsigned"));
    CHECK_THAT(one->body, ContainsSubstring("/api/v1/product-packs/"));
    CHECK_FALSE(has(one->body, "shown. Page through the rest"));

    // 101 packs: exactly one more than the 100 shown, so the banner appears.
    for (int i = 0; i < 100; ++i)
        REQUIRE(store.install(pack_yaml("bulk" + std::to_string(i)), install_fn).has_value());
    auto many = h.sink.Get("/fragments/settings/product-packs");
    REQUIRE(many);
    CHECK_THAT(many->body, ContainsSubstring("First 100 shown. Page through the rest"));
    CHECK(count_of(many->body, "<details>") == 100);
}

// ── Plugin signing panel: every state of the three edited behaviours ────────────────────────

namespace {

plugin_signing::TrustBundleStats bundle_of(int certs, std::size_t subjects) {
    plugin_signing::TrustBundleStats b;
    b.cert_count = certs;
    b.sha256_hex = std::string(64, 'a');
    for (std::size_t i = 0; i < subjects; ++i)
        b.subjects.push_back("CN=signer" + std::to_string(i));
    return b;
}

std::optional<std::expected<plugin_signing::TrustBundleStats, std::string>> some(
    plugin_signing::TrustBundleStats b) {
    return std::expected<plugin_signing::TrustBundleStats, std::string>(std::move(b));
}

/// The opening tag of the first <form> whose hx-post targets `path`.
std::string form_tag(const std::string& html, const std::string& path) {
    const auto at = html.find("hx-post=\"" + path + "\"");
    if (at == std::string::npos)
        return {};
    const auto open = html.rfind("<form", at);
    return html.substr(open, html.find('>', at) - open + 1);
}

} // namespace

TEST_CASE("plugin signing panel: a truncated subject list says first N of M",
          "[plugins_page][plugins][signing]") {
    auto capped = render_plugin_signing_panel(some(bundle_of(40, 16)), false, false);
    CHECK_THAT(capped, ContainsSubstring("Subjects (first 16 of 40)"));
    auto whole = render_plugin_signing_panel(some(bundle_of(3, 3)), false, false);
    CHECK_THAT(whole, ContainsSubstring("<label>Subjects</label>"));
    CHECK_FALSE(has(whole, "Subjects (first"));
}

TEST_CASE("plugin signing panel: replacing a bundle asks, a first upload does not",
          "[plugins_page][plugins][signing]") {
    auto none = render_plugin_signing_panel(std::nullopt, false, false);
    const auto first = form_tag(none, "/api/settings/plugin-signing/upload");
    REQUIRE_FALSE(first.empty());
    CHECK_FALSE(has(first, "hx-confirm"));
    CHECK_FALSE(has(none, "/api/settings/plugin-signing/require"));

    auto have = render_plugin_signing_panel(some(bundle_of(2, 2)), false, false);
    const auto replace = form_tag(have, "/api/settings/plugin-signing/upload");
    CHECK_THAT(replace, ContainsSubstring("hx-confirm=\"Replace the trust bundle (2 certificate(s), "
                                          "SHA-256 " + std::string(64, 'a') + ")?"));
}

TEST_CASE("plugin signing panel: the require save confirms only when it can turn the flag on",
          "[plugins_page][plugins][signing]") {
    auto off = render_plugin_signing_panel(some(bundle_of(2, 2)), false, false);
    const auto off_form = form_tag(off, "/api/settings/plugin-signing/require");
    REQUIRE_FALSE(off_form.empty());
    CHECK_THAT(off_form, ContainsSubstring("hx-confirm=\"Save this setting? If Require signed "
                                           "plugins is ticked:"));
    CHECK_FALSE(has(off, " checked"));

    auto on = render_plugin_signing_panel(some(bundle_of(2, 2)), true, false);
    const auto on_form = form_tag(on, "/api/settings/plugin-signing/require");
    REQUIRE_FALSE(on_form.empty());
    CHECK_FALSE(has(on_form, "hx-confirm"));
    CHECK_THAT(on, ContainsSubstring(" checked"));
    // Both states say where enforcement lives: the agent, not this server.
    for (const auto& html : {off, on})
        CHECK_THAT(squash(html), ContainsSubstring("Each agent enforces its own"));

    // An unreadable flag shows no write control at all.
    auto unknown = render_plugin_signing_panel(some(bundle_of(2, 2)), false, true);
    CHECK_FALSE(has(unknown, "/api/settings/plugin-signing/require"));
}

// ── Production wiring ───────────────────────────────────────────────────────

#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif

TEST_CASE("plugins page: the shipped server registers the page and its fragments",
          "[plugins_page][plugins]") {
    // The route tests above register the helper straight onto a TestRouteSink, so deleting
    // the production call would leave them green and ship a Settings nav entry that 404s.
    // Same source-scan precedent as test_body_cap_route_inventory.cpp.
    // Only live code counts: a comment that mentions the call must not satisfy the pin.
    const std::string live = live_code(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE_FALSE(live.empty());
    CHECK(has(live, "settings_plugins::register_settings_plugins_routes("));
    // And the helper itself serves exactly the page plus the three new fragments.
    std::ifstream r(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "settings_plugins_routes.cpp");
    REQUIRE(r);
    std::stringstream rs;
    rs << r.rdbuf();
    for (const char* path : {"/settings/plugins", "/fragments/settings/plugin-config",
                             "/fragments/settings/kill-switch", "/fragments/settings/product-packs"})
        CHECK(has(rs.str(), std::string("sink.Get(\"") + path + "\""));
}
