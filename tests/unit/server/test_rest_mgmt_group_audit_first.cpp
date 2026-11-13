/**
 * test_rest_mgmt_group_audit_first.cpp — #7074: `POST /api/v1/management-groups` is audit-first
 * (ADR-0033 section 9, "no audit row, no mutation").
 *
 * The route stores an `attempted` row BEFORE it creates the group and refuses (503 +
 * `Sec-Audit-Failed`) when that row cannot be stored. A refusal that needs no write to decide
 * (permission, malformed body, `ManagementGroupStore::validate_new_group`) answers first and
 * burns no row. The session and the permission are decided again after the `attempted` row
 * (it can wait on the audit pool). A store fault on create answers 503 with a fixed message and
 * a `store_error` failure row; the store's database error text is never returned.
 *
 * PG-gated: ManagementGroupStore is a Postgres store (ADR-0042), so every case SKIPs when
 * YUZU_TEST_POSTGRES_DSN is unset and FAILs when it is set but broken.
 */

#include "management_group_store.hpp"
#include "rest_api_v1.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <cstddef>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

constexpr const char* kCreate = "management_group.create";

struct AuditFirstHarness {
    // Declared FIRST: the store borrows it via set_metrics(), so it must outlive the store.
    yuzu::MetricsRegistry metrics;
    yuzu::test::ManagementGroupStorePg mgmt_bundle; // SKIPs without a PG DSN
    RestApiV1 api;
    yuzu::server::test::TestRouteSink sink;

    struct AuditRow {
        std::string action;
        std::string result;
        std::string target_type;
        std::string target_id;
        std::string detail;
    };
    /// Rows the sink STORED, in order (a row the sink refused is not here).
    std::vector<AuditRow> audits;
    /// "action|result" pairs the sink refuses (returns false for), to model an unavailable store.
    std::set<std::string> fail_audit;
    /// Deny a (securable, operation) on the FIRST permission check only.
    std::function<bool(const std::string&, const std::string&)> perm_override{};
    /// After an `attempted` row for management_group.create is stored: the session is gone / the
    /// permission is revoked (the second auth_fn / perm_fn call answers that way).
    bool session_gone_after_attempted = false;
    bool perm_revoked_after_attempted = false;

    [[nodiscard]] std::size_t audit_count(const std::string& action,
                                          const std::string& result) const {
        std::size_t n = 0;
        for (const auto& a : audits)
            if (a.action == action && a.result == result)
                ++n;
        return n;
    }
    /// Every stored row for the create verb, whatever its result.
    [[nodiscard]] std::size_t create_rows() const {
        std::size_t n = 0;
        for (const auto& a : audits)
            if (a.action == kCreate)
                ++n;
        return n;
    }
    [[nodiscard]] bool attempted_stored() const { return audit_count(kCreate, "attempted") > 0; }

    [[nodiscard]] std::size_t group_count() const { return mgmt_bundle->list_groups().size(); }
    [[nodiscard]] bool group_exists(const std::string& name) const {
        for (const auto& g : mgmt_bundle->list_groups())
            if (g.name == name)
                return true;
        return false;
    }

    AuditFirstHarness() {
        mgmt_bundle->set_metrics(&metrics);

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            if (session_gone_after_attempted && attempted_stored())
                return std::nullopt; // writes no response of its own: the route covers the 401
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::user;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) -> bool {
            const bool denied = (perm_override && !perm_override(type, op)) ||
                                (perm_revoked_after_attempted && attempted_stored());
            if (denied) {
                res.status = 403;
                res.set_content(R"({"error":"forbidden"})", "application/json");
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            if (fail_audit.contains(action + "|" + result))
                return false;
            audits.push_back({action, result, target_type, target_id, detail});
            return true;
        };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/&*mgmt_bundle,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr,
                            /*service_group_fn=*/{},
                            /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/&metrics,
                            /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{},
                            /*step_up_fn=*/{},
                            /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{},
                            /*network_api=*/{},
                            /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr,
                            /*scoped_perm_fn=*/{},
                            /*software_inventory_store=*/nullptr,
                            /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr,
                            /*access_review_store=*/nullptr,
                            /*auth_db=*/nullptr,
                            /*directory_sync=*/nullptr);
    }

    auto create(const std::string& body) { return sink.Post("/api/v1/management-groups", body); }
};

std::string make_group(AuditFirstHarness& h, const std::string& name,
                       const std::string& parent = {}) {
    ManagementGroup g;
    g.name = name;
    g.parent_id = parent;
    g.membership_type = "static";
    g.created_by = "tester";
    auto id = h.mgmt_bundle->create_group(g);
    REQUIRE(id.has_value());
    return *id;
}

/// Drop one table (CASCADE) of the per-test management-group schema so the next write fails.
void drop_mgmt_table(AuditFirstHarness& h, const char* qualified_table) {
    yuzu::server::pg::PgConn conn{PQconnectdb(h.mgmt_bundle.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    yuzu::server::pg::PgResult d{
        PQexec(conn.get(), (std::string("DROP TABLE ") + qualified_table + " CASCADE").c_str())};
    REQUIRE(d.ok());
}

} // namespace

TEST_CASE("POST /management-groups: an unstorable attempted row refuses the create (503 + "
          "Sec-Audit-Failed) and nothing is created",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    h.fail_audit.insert(std::string(kCreate) + "|attempted");
    const auto before = h.group_count();

    auto res = h.create(R"({"name":"audit-down"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->has_header("Sec-Audit-Failed"));
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["retry_after_ms"].is_number());
    CHECK(res->body.find("\"id\"") == std::string::npos);

    CHECK(h.group_count() == before);
    CHECK_FALSE(h.group_exists("audit-down"));
    CHECK(h.create_rows() == 0);
}

TEST_CASE("POST /management-groups: refusals that need no write burn no audit row",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;

    SECTION("an empty name is a 400 and no row") {
        auto res = h.create(R"({"name":""})");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("group name cannot be empty") != std::string::npos);
        CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
    }
    SECTION("a missing name is a 400 and no row") {
        auto res = h.create(R"({"description":"x"})");
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    SECTION("an unknown parent is a 400 and no row") {
        auto res = h.create(R"({"name":"orphan","parent_id":"deadbeef0000"})");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("parent group not found") != std::string::npos);
        CHECK_FALSE(h.group_exists("orphan"));
    }
    SECTION("a hierarchy deeper than the cap is a 400 and no row") {
        // Grow a chain through the store until it refuses; the last accepted group is the deepest.
        std::string parent = make_group(h, "depth-1");
        for (int i = 2; i < 12; ++i) {
            ManagementGroup g;
            g.name = "depth-" + std::to_string(i);
            g.parent_id = parent;
            g.membership_type = "static";
            auto next = h.mgmt_bundle->create_group(g);
            if (!next)
                break;
            parent = *next;
        }
        auto res = h.create(R"({"name":"too-deep","parent_id":")" + parent + R"("})");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("maximum hierarchy depth (5) exceeded") != std::string::npos);
        CHECK_FALSE(h.group_exists("too-deep"));
    }
    SECTION("a caller without ManagementGroup:Write is a 403 and no row") {
        h.perm_override = [](const std::string& type, const std::string& op) {
            return !(type == "ManagementGroup" && op == "Write");
        };
        auto res = h.create(R"({"name":"no-perm"})");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_FALSE(h.group_exists("no-perm"));
    }
    SECTION("malformed JSON is a 400 and no row") {
        auto res = h.create("{not json");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("invalid JSON") != std::string::npos);
    }

    // None of the above burned a row of any result for the create verb.
    CHECK(h.create_rows() == 0);
}

TEST_CASE("POST /management-groups: a duplicate name writes attempted then a name_conflict "
          "failure row and answers 400",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    make_group(h, "dup-name");
    const auto before = h.group_count();

    auto res = h.create(R"({"name":"dup-name"})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->body.find("a group with that name already exists") != std::string::npos);
    CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
    CHECK(h.group_count() == before);

    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == kCreate);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[0].target_type == "ManagementGroup");
    CHECK(h.audits[0].target_id.empty());
    CHECK(h.audits[0].detail == "dup-name");
    CHECK(h.audits[1].action == kCreate);
    CHECK(h.audits[1].result == "failure");
    CHECK(h.audits[1].target_id.empty());
    CHECK(h.audits[1].detail == "name_conflict");
}

TEST_CASE("POST /management-groups: success writes attempted then success with the new id",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;

    auto res = h.create(R"({"name":"fresh group","description":"d"})");
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
    auto body = nlohmann::json::parse(res->body);
    const std::string id = body["data"]["id"].get<std::string>();
    REQUIRE_FALSE(id.empty());
    CHECK(h.group_exists("fresh group"));

    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == kCreate);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[0].target_type == "ManagementGroup");
    CHECK(h.audits[0].target_id.empty());
    CHECK(h.audits[0].detail == "fresh group"); // the raw name, the existing contract
    CHECK(h.audits[1].action == kCreate);
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].target_type == "ManagementGroup");
    CHECK(h.audits[1].target_id == id);
    CHECK(h.audits[1].detail == "fresh group");
}

TEST_CASE("POST /management-groups: a lost outcome row keeps the 201 and marks the response "
          "Sec-Audit-Failed",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    h.fail_audit.insert(std::string(kCreate) + "|success");

    auto res = h.create(R"({"name":"outcome-lost"})");
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(res->has_header("Sec-Audit-Failed"));
    CHECK(h.group_exists("outcome-lost"));

    // The attempted row stands alone: "started, outcome unknown".
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "attempted");
}

TEST_CASE("POST /management-groups: a store fault on create answers 503 with a fixed message and "
          "a store_error failure row, never the database text",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    // No parent, so validate_new_group reads nothing and passes; the INSERT then fails.
    drop_mgmt_table(h, "management_group_store.management_groups");

    auto res = h.create(R"({"name":"store-fault"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["retry_after_ms"].is_number());
    CHECK(res->body.find("management group store unavailable") != std::string::npos);
    // No libpq text: the relation name, the SQLSTATE wording and the store's own prefix.
    CHECK(res->body.find("management_groups") == std::string::npos);
    CHECK(res->body.find("does not exist") == std::string::npos);
    CHECK(res->body.find("failed to create group") == std::string::npos);
    CHECK(res->body.find("ERROR") == std::string::npos);

    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].action == kCreate);
    CHECK(h.audits[1].result == "failure");
    CHECK(h.audits[1].target_id.empty());
    CHECK(h.audits[1].detail == "store_error");
    CHECK(h.audit_count(kCreate, "success") == 0);
}

TEST_CASE("POST /management-groups: a session gone after the attempted row creates nothing and "
          "writes a session_revoked failure row",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    h.session_gone_after_attempted = true;
    const auto before = h.group_count();

    auto res = h.create(R"({"name":"session-gone"})");
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(h.group_count() == before);
    CHECK_FALSE(h.group_exists("session-gone"));

    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].action == kCreate);
    CHECK(h.audits[1].result == "failure");
    CHECK(h.audits[1].detail == "session_revoked");
}

TEST_CASE("POST /management-groups: a permission revoked after the attempted row creates nothing "
          "and writes a permission_revoked failure row",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    h.perm_revoked_after_attempted = true;
    const auto before = h.group_count();

    auto res = h.create(R"({"name":"perm-gone"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.group_count() == before);
    CHECK_FALSE(h.group_exists("perm-gone"));

    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].action == kCreate);
    CHECK(h.audits[1].result == "failure");
    CHECK(h.audits[1].detail == "permission_revoked");
}
