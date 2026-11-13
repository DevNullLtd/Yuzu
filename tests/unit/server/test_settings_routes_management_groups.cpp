/**
 * test_settings_routes_management_groups.cpp — regression test for the F1
 * stored-XSS finding: a management-group name is stored verbatim
 * (ManagementGroupStore::create_group only rejects an empty name) and was
 * concatenated unescaped into the Settings "management-groups" fragment —
 * both as element text and inside the `hx-confirm` attribute, and again in
 * the "Create group" form's parent <option> list — while a sibling render
 * path elsewhere in this same file already escapes group names correctly.
 * Fixed by routing every render of a group's name/id through html_escape().
 *
 * PG-gated (ManagementGroupStore is a migrated Postgres store, ADR-0042):
 * skips when YUZU_TEST_POSTGRES_DSN is unset, fails when it is set but
 * broken. See test_management_group_store.cpp for the store-level template.
 */

#include "settings_routes.hpp"

#include "management_group_store.hpp"
#include "pg/pg_pool.hpp"
#include "test_route_sink.hpp"
#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>

#include <libpq-fe.h>

#include <memory>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

// Pre-migrated template — see test_management_group_store.cpp's identical
// `mgmt_tpl` (a separate template key ("mgmtgroupstoreroutes") because
// PgTestTemplate replay-verifies a shared key's setup by structural
// fingerprint — an identical-looking lambda in a different TU is a
// different setup, not guaranteed to replay identically).
yuzu::test::PgTestTemplate mgmt_routes_tpl{"mgmtgroupstoreroutes", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ManagementGroupStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("mgmtgroupstoreroutes template: store failed to migrate");
}};

// One call the routes layer made to the bool-returning audit hook (the audit-first path).
struct AuditRow {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
    bool stored{true}; // false: the hook refused the write (a failure-injection switch)
};

struct MgmtGroupsHarness {
    PgPool pool;
    ManagementGroupStore mgmt_group_store;
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    SettingsRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    // Failure injection for the audit-first create (#7074), copied from the users harness
    // (test_settings_routes_users.cpp): every call to the bool-returning audit hook lands in
    // `calls`; the two switches make the `attempted` row or the outcome rows unstorable.
    std::vector<AuditRow> calls;
    bool attempt_audit_ok{true};
    bool outcome_audit_ok{true};
    // The session / the grant disappear once an `attempted` row has been STORED (the audit write
    // can wait on the pool, so authority is decided again after it). They write their own 401 /
    // 403 into the response, as the production callbacks do.
    bool session_gone_after_attempt{false};
    bool perm_revoked_after_attempt{false};

    /// Rows the hook actually stored, in order.
    std::vector<AuditRow> stored() const {
        std::vector<AuditRow> out;
        for (const auto& c : calls)
            if (c.stored)
                out.push_back(c);
        return out;
    }
    /// Every management_group.create row stored, of any result.
    std::vector<AuditRow> create_rows() const {
        std::vector<AuditRow> out;
        for (const auto& c : stored())
            if (c.action == "management_group.create")
                out.push_back(c);
        return out;
    }
    bool attempted_stored() const {
        for (const auto& c : calls)
            if (c.stored && c.result == "attempted")
                return true;
        return false;
    }

    explicit MgmtGroupsHarness(const std::string& dsn)
        : pool({.conninfo = dsn, .size = 4}), mgmt_group_store(pool) {
        REQUIRE(mgmt_group_store.is_open());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            if (session_gone_after_attempt && attempted_stored()) {
                res.status = 401;
                return std::nullopt;
            }
            auth::Session s;
            s.username = "admin";
            s.role = auth::Role::admin;
            return s;
        };
        auto admin_fn = [](const httplib::Request&, httplib::Response&) { return true; };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) {
            if (perm_revoked_after_attempt && attempted_stored()) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&, const std::string&) {
            return true;
        };
        auto audit_read_fn = [this](const httplib::Request&, const std::string& action,
                                    const std::string& result, const std::string& target_type,
                                    const std::string& target_id,
                                    const std::string& detail) -> bool {
            const bool attempted = result == "attempted";
            const bool ok = attempted ? attempt_audit_ok : outcome_audit_ok;
            calls.push_back({action, result, target_type, target_id, detail, ok});
            return ok;
        };
        routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr,
                               auto_approve,
                               /*api_token_store=*/nullptr, &mgmt_group_store,
                               /*tag_store=*/nullptr,
                               /*update_registry=*/nullptr, /*runtime_config_store=*/nullptr,
                               /*audit_store=*/nullptr,
                               /*gateway_enabled=*/false, []() -> std::size_t { return 0; },
                               []() -> std::string { return "[]"; }, oidc_mu, oidc_provider,
                               /*metrics_registry=*/nullptr, /*step_up_fn=*/{}, audit_read_fn);
    }

    /// POST the create form. A form body needs its content type spelled out (test_route_sink.hpp).
    auto create(const std::string& name, const std::string& parent_id = {}) {
        return sink.Post("/api/settings/management-groups",
                         "name=" + httplib::encode_uri_component(name) +
                             "&parent_id=" + parent_id + "&membership_type=static",
                         "application/x-www-form-urlencoded");
    }
    /// Names of every group in the store.
    std::vector<std::string> group_names() const {
        std::vector<std::string> out;
        for (const auto& g : mgmt_group_store.list_groups())
            out.push_back(g.name);
        return out;
    }
};

// Runs `sql` on the test database over its own connection (the harness pool is not reachable).
void exec_sql(const std::string& dsn, const char* sql) {
    std::unique_ptr<PGconn, decltype(&PQfinish)> conn{PQconnectdb(dsn.c_str()), &PQfinish};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    std::unique_ptr<PGresult, decltype(&PQclear)> r{PQexec(conn.get(), sql), &PQclear};
    REQUIRE(PQresultStatus(r.get()) == PGRES_COMMAND_OK);
}

} // namespace

TEST_CASE("management-groups fragment escapes a name containing markup",
          "[pg][settings][management-groups][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_routes_tpl);
    MgmtGroupsHarness h(db.dsn());
    ManagementGroup g;
    g.name = "<script>alert(1)</script>";
    g.membership_type = "static";
    auto created = h.mgmt_group_store.create_group(g);
    REQUIRE(created.has_value());

    auto res = h.sink.Get("/fragments/settings/management-groups");
    REQUIRE(res);
    CHECK(res->status == 200);
    // The raw payload must never reach the response body verbatim.
    CHECK(res->body.find("<script>alert(1)</script>") == std::string::npos);
    // It must appear in its escaped form as element text.
    CHECK(res->body.find("&lt;script&gt;alert(1)&lt;/script&gt;") != std::string::npos);
}

TEST_CASE("management-groups fragment escapes a name that breaks out of an HTML attribute",
          "[pg][settings][management-groups][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_routes_tpl);
    MgmtGroupsHarness h(db.dsn());
    ManagementGroup g;
    // A double-quote breaks out of the hx-confirm="..." attribute; the
    // payload after it would otherwise land as a new, attacker-controlled
    // attribute/tag in the button's opening tag.
    g.name = "x\" onmouseover=\"alert(1)";
    g.membership_type = "static";
    auto created = h.mgmt_group_store.create_group(g);
    REQUIRE(created.has_value());

    auto res = h.sink.Get("/fragments/settings/management-groups");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("onmouseover=\"alert(1)") == std::string::npos);
    // Pin the specific escaped payload, not just any "&quot;" in the
    // fragment — a bare substring check would trivially pass once any
    // other markup in the page emits one.
    CHECK(res->body.find("x&quot; onmouseover=&quot;alert(1)") != std::string::npos);
}

TEST_CASE("create-group form's parent <option> list escapes group names",
          "[pg][settings][management-groups][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_routes_tpl);
    MgmtGroupsHarness h(db.dsn());
    ManagementGroup g;
    g.name = "<b>evil</b>";
    g.membership_type = "static";
    auto created = h.mgmt_group_store.create_group(g);
    REQUIRE(created.has_value());

    auto res = h.sink.Get("/fragments/settings/management-groups");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("<option value=\"" + *created + "\"><b>evil</b></option>") ==
          std::string::npos);
    // Pin the escaped payload to this specific <option>, not just anywhere
    // in the fragment — the tree-row text (test above) also escapes the
    // same name, so a bare substring check wouldn't discriminate the two
    // render sites.
    CHECK(res->body.find("<option value=\"" + *created +
                          "\">&lt;b&gt;evil&lt;/b&gt;</option>") != std::string::npos);
}

// ---------------------------------------------------------------------------------------------
// #7074: Settings create is audit-first. Twins: POST /api/v1/management-groups (REST) and the MCP
// create_management_group tool; same verb, row strings, order and fixed failure tokens.
// ---------------------------------------------------------------------------------------------

namespace {
constexpr const char* kMarkupName = "<img src=x onerror=1>";
} // namespace

TEST_CASE("Settings group create: an unstorable attempted row refuses with 503, a toast, and "
          "creates nothing",
          "[pg][settings][management-groups][mgmt-audit-first]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_routes_tpl);
    MgmtGroupsHarness h(db.dsn());
    h.attempt_audit_ok = false;

    auto res = h.create("Audit Down");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    // htmx drops a 5xx body, so the operator's only view of the refusal is the toast.
    const auto toast = res->get_header_value("HX-Trigger");
    CHECK(toast.find("showToast") != std::string::npos);
    CHECK(toast.find("\"level\":\"error\"") != std::string::npos);
    CHECK(toast.find("Audit log unavailable: the group was not created") != std::string::npos);
    CHECK(res->body.find("audit log unavailable") != std::string::npos);

    CHECK(h.group_names().empty());
    // Exactly one attempt, the failing attempted row; no outcome row of any result.
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].action == "management_group.create");
    CHECK(h.calls[0].result == "attempted");
    CHECK_FALSE(h.calls[0].stored);
    CHECK(h.stored().empty());
}

TEST_CASE("Settings group create: refusals decided without a write burn no audit row and echo "
          "no raw markup",
          "[pg][settings][management-groups][mgmt-audit-first][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_routes_tpl);
    MgmtGroupsHarness h(db.dsn());

    SECTION("empty name") {
        auto res = h.create("");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->body.find("Name required") != std::string::npos);
    }
    SECTION("unknown parent (a parent id that would inject markup)") {
        auto res = h.create("Orphan", kMarkupName);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->body.find("<span class=\"feedback-error\">parent group not found</span>") !=
              std::string::npos);
        CHECK(res->body.find("<img") == std::string::npos);
    }
    SECTION("unknown parent, markup name") {
        auto res = h.create(kMarkupName, "does-not-exist");
        REQUIRE(res);
        CHECK(res->body.find("parent group not found") != std::string::npos);
        CHECK(res->body.find("<img") == std::string::npos);
    }
    SECTION("hierarchy depth overflow") {
        std::string prev_id;
        for (int i = 0; i < 6; ++i) {
            ManagementGroup g;
            g.name = "Chain " + std::to_string(i);
            g.membership_type = "static";
            g.parent_id = prev_id;
            auto r = h.mgmt_group_store.create_group(g);
            REQUIRE(r.has_value());
            prev_id = *r;
        }
        auto res = h.create(kMarkupName, prev_id);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->body.find("<span class=\"feedback-error\">maximum hierarchy depth (5) "
                             "exceeded</span>") != std::string::npos);
        CHECK(res->body.find("<img") == std::string::npos);
        CHECK(h.group_names().size() == 6);
    }
    // Nothing was written: no management_group.create row of any result, and no hook call at all.
    CHECK(h.calls.empty());
    CHECK(h.create_rows().empty());
}

TEST_CASE("Settings group create: a store that cannot answer the validation refuses with fixed "
          "text, a toast and no row",
          "[settings][management-groups][mgmt-audit-first][degrade]") {
    // No database: a construct-invalid pool makes the store report "database not open", a store
    // fault by mgmt_group_error_is_store_fault, which validate_new_group returns first.
    PgPool pool{{.conninfo = "yuzu_invalid_keyword=1", .size = 1}};
    ManagementGroupStore closed_store{pool};
    REQUIRE(!closed_store.is_open());

    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    SettingsRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    std::vector<AuditRow> calls;
    auto auth_fn = [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "admin";
        s.role = auth::Role::admin;
        return s;
    };
    auto admin_fn = [](const httplib::Request&, httplib::Response&) { return true; };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) {
        return true;
    };
    auto audit_read_fn = [&calls](const httplib::Request&, const std::string& a,
                                  const std::string& r, const std::string& tt,
                                  const std::string& ti, const std::string& d) -> bool {
        calls.push_back({a, r, tt, ti, d, true});
        return true;
    };
    routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr,
                           auto_approve,
                           /*api_token_store=*/nullptr, &closed_store, /*tag_store=*/nullptr,
                           /*update_registry=*/nullptr, /*runtime_config_store=*/nullptr,
                           /*audit_store=*/nullptr,
                           /*gateway_enabled=*/false, []() -> std::size_t { return 0; },
                           []() -> std::string { return "[]"; }, oidc_mu, oidc_provider,
                           /*metrics_registry=*/nullptr, /*step_up_fn=*/{}, audit_read_fn);

    auto res = sink.Post("/api/settings/management-groups",
                         "name=Closed&parent_id=&membership_type=static",
                         "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("<span class=\"feedback-error\">Management group store unavailable, "
                         "try again</span>") != std::string::npos);
    CHECK(res->body.find("database not open") == std::string::npos);
    const auto toast = res->get_header_value("HX-Trigger");
    CHECK(toast.find("\"level\":\"error\"") != std::string::npos);
    CHECK(toast.find("Management group store unavailable, try again") != std::string::npos);
    CHECK(calls.empty());
}

TEST_CASE("Settings group create: a duplicate name writes attempted then failure/name_conflict",
          "[pg][settings][management-groups][mgmt-audit-first][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_routes_tpl);
    MgmtGroupsHarness h(db.dsn());
    ManagementGroup first;
    first.name = kMarkupName;
    first.membership_type = "static";
    REQUIRE(h.mgmt_group_store.create_group(first).has_value());

    auto res = h.create(kMarkupName);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("<span class=\"feedback-error\">a group with that name already "
                         "exists</span>") != std::string::npos);
    CHECK(res->body.find("<img") == std::string::npos);
    CHECK(h.group_names().size() == 1);

    const auto rows = h.create_rows();
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].result == "attempted");
    CHECK(rows[0].target_type == "ManagementGroup");
    CHECK(rows[0].target_id.empty());
    CHECK(rows[0].detail == kMarkupName); // the raw name, the existing contract
    CHECK(rows[1].result == "failure");
    CHECK(rows[1].target_id.empty());
    CHECK(rows[1].detail == "name_conflict");
}

TEST_CASE("Settings group create: success writes attempted then success with the new id",
          "[pg][settings][management-groups][mgmt-audit-first]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_routes_tpl);
    MgmtGroupsHarness h(db.dsn());

    auto res = h.create(kMarkupName);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Sec-Audit-Failed").empty());
    CHECK(res->get_header_value("HX-Trigger").empty());
    // The refreshed section, with the name escaped.
    CHECK(res->body.find("&lt;img src=x onerror=1&gt;") != std::string::npos);
    CHECK(res->body.find("<img") == std::string::npos);

    const auto groups = h.mgmt_group_store.list_groups();
    REQUIRE(groups.size() == 1);
    CHECK(groups[0].name == kMarkupName);
    CHECK(groups[0].created_by == "admin");

    const auto rows = h.create_rows();
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].result == "attempted");
    CHECK(rows[0].target_id.empty());
    CHECK(rows[0].detail == kMarkupName);
    CHECK(rows[1].result == "success");
    CHECK(rows[1].target_type == "ManagementGroup");
    CHECK(rows[1].target_id == groups[0].id);
    CHECK(rows[1].detail == kMarkupName);
}

TEST_CASE("Settings group create: a lost outcome row keeps the success and shows a warning toast",
          "[pg][settings][management-groups][mgmt-audit-first]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_routes_tpl);
    MgmtGroupsHarness h(db.dsn());
    h.outcome_audit_ok = false;

    auto res = h.create("Outcome Lost");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    const auto toast = res->get_header_value("HX-Trigger");
    CHECK(toast.find("\"level\":\"warning\"") != std::string::npos);
    CHECK(toast.find("Group created, but its audit record could not be stored") !=
          std::string::npos);
    CHECK(res->body.find("Outcome Lost") != std::string::npos); // the refreshed section

    // Nothing rolled back; the attempted row stands as "started, outcome unknown".
    CHECK(h.group_names() == std::vector<std::string>{"Outcome Lost"});
    REQUIRE(h.calls.size() == 2);
    CHECK(h.calls[0].result == "attempted");
    CHECK(h.calls[0].stored);
    CHECK(h.calls[1].result == "success");
    CHECK_FALSE(h.calls[1].stored);
}

TEST_CASE("Settings group create: a store fault answers fixed text, writes failure/store_error "
          "and leaks no database text",
          "[pg][settings][management-groups][mgmt-audit-first][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_routes_tpl);
    MgmtGroupsHarness h(db.dsn());
    // With no parent, validate_new_group reads nothing, so the fault surfaces in the insert.
    exec_sql(db.dsn(), "DROP TABLE management_group_store.management_groups CASCADE");

    yuzu::test::LogCapture cap;
    auto res = h.create("Store Down");
    cap.stop();
    REQUIRE(res);
    CHECK(res->status == 200);
    // The cause is recorded in the server log (not on the page, the toast or the audit rows).
    CHECK(cap.text().find("management_group.create store fault: failed to create group") !=
          std::string::npos);
    CHECK(cap.text().find("does not exist") != std::string::npos);
    CHECK(res->body.find("<span class=\"feedback-error\">Management group store unavailable, "
                         "try again</span>") != std::string::npos);
    for (const char* leak : {"relation \"", "does not exist", "management_groups", "ERROR",
                             "failed to create group"})
        CHECK(res->body.find(leak) == std::string::npos);
    const auto toast = res->get_header_value("HX-Trigger");
    CHECK(toast.find("\"level\":\"error\"") != std::string::npos);
    for (const char* leak : {"relation \"", "does not exist", "management_groups", "ERROR"})
        CHECK(toast.find(leak) == std::string::npos);

    const auto rows = h.create_rows();
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].result == "attempted");
    CHECK(rows[1].result == "failure");
    CHECK(rows[1].target_id.empty());
    CHECK(rows[1].detail == "store_error");
}

TEST_CASE("Settings group create: a session or grant gone after the attempted row creates "
          "nothing and writes a revoked failure row",
          "[pg][settings][management-groups][mgmt-audit-first]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_routes_tpl);
    MgmtGroupsHarness h(db.dsn());

    SECTION("session gone") {
        h.session_gone_after_attempt = true;
        auto res = h.create("Session Gone");
        REQUIRE(res);
        CHECK(res->status == 401);
        const auto rows = h.create_rows();
        REQUIRE(rows.size() == 2);
        CHECK(rows[0].result == "attempted");
        CHECK(rows[1].result == "failure");
        CHECK(rows[1].target_id.empty());
        CHECK(rows[1].detail == "session_revoked");
    }
    SECTION("permission revoked") {
        h.perm_revoked_after_attempt = true;
        auto res = h.create("Grant Gone");
        REQUIRE(res);
        CHECK(res->status == 403);
        const auto rows = h.create_rows();
        REQUIRE(rows.size() == 2);
        CHECK(rows[0].result == "attempted");
        CHECK(rows[1].result == "failure");
        CHECK(rows[1].target_id.empty());
        CHECK(rows[1].detail == "permission_revoked");
    }
    CHECK(h.group_names().empty());
}

TEST_CASE("Settings group create: a missing group store refuses with the fixed text, a toast "
          "and no audit row",
          "[settings][management-groups][mgmt-audit-first]") {
    // No Postgres needed: the route is registered with a null group store.
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    yuzu::server::test::TestRouteSink sink;
    std::vector<AuditRow> calls;

    auto auth_fn = [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "admin";
        s.role = auth::Role::admin;
        return s;
    };
    auto admin_fn = [](const httplib::Request&, httplib::Response&) { return true; };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) {
        return true;
    };
    auto audit_read_fn = [&calls](const httplib::Request&, const std::string& action,
                                  const std::string& result, const std::string& target_type,
                                  const std::string& target_id,
                                  const std::string& detail) -> bool {
        calls.push_back({action, result, target_type, target_id, detail, true});
        return true;
    };
    SettingsRoutes routes;
    routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr, auto_approve,
                           /*api_token_store=*/nullptr, /*mgmt_group_store=*/nullptr,
                           /*tag_store=*/nullptr,
                           /*update_registry=*/nullptr, /*runtime_config_store=*/nullptr,
                           /*audit_store=*/nullptr,
                           /*gateway_enabled=*/false, []() -> std::size_t { return 0; },
                           []() -> std::string { return "[]"; }, oidc_mu, oidc_provider,
                           /*metrics_registry=*/nullptr, /*step_up_fn=*/{}, audit_read_fn);

    auto res = sink.Post("/api/settings/management-groups", "name=NoStore&membership_type=static",
                         "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("<span class=\"feedback-error\">Management group store unavailable, "
                         "try again</span>") != std::string::npos);
    const auto toast = res->get_header_value("HX-Trigger");
    CHECK(toast.find("showToast") != std::string::npos);
    CHECK(toast.find("\"level\":\"error\"") != std::string::npos);
    CHECK(calls.empty());
}

TEST_CASE("Settings group create: an over-long or unclean name or parent id is refused with fixed "
          "text, no row and no group",
          "[pg][settings][management-groups][mgmt-audit-first][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, mgmt_routes_tpl);
    MgmtGroupsHarness h(db.dsn());
    const std::string fixed_name_text =
        "group name must be at most 256 bytes and must not contain control characters or invalid "
        "UTF-8";

    // No multi-MiB case: httplib answers 413 to an urlencoded body over its own cap before the
    // handler runs (and the sink models that), so a larger form never reaches this route.
    SECTION("257 B, 300 B and 3 KB names; 256 B is accepted") {
        for (const std::size_t n : {std::size_t{257}, std::size_t{300}, std::size_t{3 * 1024}}) {
            auto res = h.create(std::string(n, 'n'));
            REQUIRE(res);
            CHECK(res->status == 200);
            CHECK(res->body ==
                  "<span class=\"feedback-error\">" + fixed_name_text + "</span>");
        }
        CHECK(h.calls.empty());
        CHECK(h.group_names().empty());

        auto ok = h.create(std::string(256, 'n'));
        REQUIRE(ok);
        CHECK(h.create_rows().size() == 2); // attempted + success
        CHECK(h.group_names().size() == 1);
    }
    SECTION("a 20-iteration retry loop of 3 KB names writes no row") {
        for (int i = 0; i < 20; ++i) {
            auto res = h.create(std::string(3 * 1024, 'r'));
            REQUIRE(res);
            CHECK(res->body.find(fixed_name_text) != std::string::npos);
        }
        CHECK(h.calls.empty());
        CHECK(h.group_names().empty());
    }
    SECTION("a newline, a NUL, a DEL and invalid UTF-8 in the name") {
        for (const auto& name :
             {std::string("line1\nline2"), std::string("nul\0byte", 8), std::string("del\x7f"),
              std::string("bad\xff\xfe utf8")}) {
            auto res = h.create(name);
            REQUIRE(res);
            CHECK(res->status == 200);
            CHECK(res->body.find(fixed_name_text) != std::string::npos);
        }
        CHECK(h.calls.empty());
        CHECK(h.group_names().empty());
    }
    SECTION("an over-long or unclean parent id names no group") {
        for (const auto& pid : {std::string(300, 'a'), std::string(3 * 1024, 'b'),
                                std::string("ab\ncd"), std::string("bad\xff")}) {
            auto res = h.sink.Post("/api/settings/management-groups",
                                   "name=Child&parent_id=" + httplib::encode_uri_component(pid) +
                                       "&membership_type=static",
                                   "application/x-www-form-urlencoded");
            REQUIRE(res);
            CHECK(res->status == 200);
            CHECK(res->body ==
                  "<span class=\"feedback-error\">parent group not found</span>");
        }
        CHECK(h.calls.empty());
        CHECK(h.group_names().empty());
    }
}
