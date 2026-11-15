/**
 * test_rest_mgmt_group_audit_first.cpp: #7074: `POST /api/v1/management-groups` is audit-first
 * (ADR-0033 section 9, "no audit row, no mutation").
 *
 * The route stores an `attempted` row BEFORE it creates the group and refuses (503 +
 * `Sec-Audit-Failed`) when that row cannot be stored. A refusal that needs no write to decide
 * (permission, malformed body, `ManagementGroupStore::validate_new_group`) answers first and
 * burns no row. The session and the permission are decided again after the `attempted` row
 * (it can wait on the audit pool). A store fault on create answers 503 with a fixed message and
 * a `store_error` failure row; the store's database error text is never returned.
 *
 * Add member (POST .../members) and remove member (DELETE .../members/{agent}) follow the same
 * order: perm, store, body and field checks (and, for add, the group-exists 404) answer first and
 * burn no row; then the `attempted` row; then the session and permission again; then the write;
 * then the outcome row.
 *
 * PG-gated: ManagementGroupStore is a Postgres store (ADR-0042), so every case SKIPs when
 * YUZU_TEST_POSTGRES_DSN is unset and FAILs when it is set but broken.
 */

#include "management_group_store.hpp"
#include "mgmt_group_error.hpp"
#include "rest_api_v1.hpp"
#include "test_auth_db_pg_helper.hpp" // AuthDbPg: a real AuthDB for the agent-known flag
#include "test_mgmt_group_pg_helper.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstddef>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

constexpr const char* kCreate = "management_group.create";
constexpr const char* kAdd = "management_group.add_member";
constexpr const char* kRemove = "management_group.remove_member";

struct AuditFirstHarness {
    // Declared FIRST: the store borrows it via set_metrics(), so it must outlive the store.
    yuzu::MetricsRegistry metrics;
    yuzu::test::ManagementGroupStorePg mgmt_bundle; // SKIPs without a PG DSN
    /// A real AuthDB (its own database), wired as `auth_db` only when the harness is built with
    /// `with_auth_db`; otherwise `auth_db` is null (the "no lookup source" case).
    std::optional<yuzu::test::AuthDbPg> auth_db_pg;
    RestApiV1 api;
    yuzu::server::test::TestRouteSink sink;

    struct AuditRow {
        std::string action;
        std::string result;
        std::string target_type;
        std::string target_id;
        std::string detail;
        /// Who the row names. The re-resolving `audit_fn` models production (the principal comes
        /// from the request's CURRENT session, so it is empty once the session is gone); the
        /// session-bound writer stamps the session handed to it.
        std::string principal;
        /// True when the row went through the session-bound writer
        /// (`RestApiV1::set_audit_as_session_fn`) rather than the re-resolving `audit_fn`.
        bool bound = false;
    };
    /// Rows the sink STORED, in order (a row the sink refused is not here).
    std::vector<AuditRow> audits;
    /// "action|result" pairs the sink refuses (returns false for), to model an unavailable store.
    std::set<std::string> fail_audit;
    /// Deny a (securable, operation) when this returns false. perm_fn consults it on EVERY check,
    /// so the denial also applies to the re-check made after the `attempted` row.
    std::function<bool(const std::string&, const std::string&)> perm_override{};
    /// After an `attempted` row of ANY management-group verb is stored (`attempted_stored()`
    /// does not look at the action): the session is gone / the permission is revoked, that is,
    /// every auth_fn / perm_fn call from then on answers that way.
    bool session_gone_after_attempted = false;
    bool perm_revoked_after_attempted = false;
    /// The session is gone only AFTER the route's post-attempted re-check has passed (the
    /// re-check is the first auth_fn call once an attempted row is stored): the window in which
    /// the outcome row is written. A row the re-resolving `audit_fn` stamps from then on names
    /// nobody, so a row that names the session was written through the session-bound writer.
    bool session_gone_after_recheck = false;
    /// The session is already gone when the `attempted` row itself is written (it lapsed in the
    /// window after the route resolved it, e.g. across a pool wait): the re-resolving `audit_fn`
    /// names nobody on an `attempted` row, so a row that names the session went through the
    /// session-bound writer. Pair it with `session_gone_after_attempted` for a route that then
    /// refuses at the re-check.
    bool session_gone_at_attempted = false;
    std::size_t post_attempted_auth_calls = 0;
    /// Runs ONCE, between the `attempted` row and the membership write (the first auth_fn call
    /// after the attempted row is stored): the deterministic injection point for a change that
    /// lands between the route's checks and its write, e.g. deleting the group.
    std::function<void()> after_attempted_hook{};

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
    /// An `attempted` row of ANY management-group verb has been stored (the re-check after the
    /// attempted row is what the session / permission switches below model).
    [[nodiscard]] bool attempted_stored() const {
        for (const auto& a : audits)
            if (a.result == "attempted")
                return true;
        return false;
    }

    [[nodiscard]] std::size_t group_count() const { return mgmt_bundle->list_groups().size(); }
    [[nodiscard]] bool group_exists(const std::string& name) const {
        for (const auto& g : mgmt_bundle->list_groups())
            if (g.name == name)
                return true;
        return false;
    }

    explicit AuditFirstHarness(bool with_auth_db = false) {
        mgmt_bundle->set_metrics(&metrics);
        if (with_auth_db)
            auth_db_pg.emplace();

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            if (after_attempted_hook && attempted_stored()) {
                auto hook = std::move(after_attempted_hook);
                after_attempted_hook = nullptr;
                hook();
            }
            if (session_gone_after_attempted && attempted_stored())
                return std::nullopt; // writes no response of its own: the route covers the 401
            if (attempted_stored())
                ++post_attempted_auth_calls;
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
            // Production re-resolves the session from the request at write time: once it is
            // gone the row names nobody.
            const bool session_alive =
                !(session_gone_after_attempted && attempted_stored()) &&
                !(session_gone_after_recheck && post_attempted_auth_calls > 0) &&
                !(session_gone_at_attempted && result == "attempted");
            audits.push_back({action, result, target_type, target_id, detail,
                              session_alive ? "tester" : "", /*bound=*/false});
            return true;
        };
        // The session-bound writer, as `AuthRoutes::audit_as_session_fn()` is wired in
        // production: the row names the session it is handed, whatever the request resolves to.
        api.set_audit_as_session_fn(
            [this](const httplib::Request&, const auth::Session& session, const std::string&,
                   const std::string& action, const std::string& result,
                   const std::string& target_type, const std::string& target_id,
                   const std::string& detail) -> bool {
                if (fail_audit.contains(action + "|" + result))
                    return false;
                audits.push_back(
                    {action, result, target_type, target_id, detail, session.username, true});
                return true;
            });

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
                            /*auth_db=*/auth_db_pg ? auth_db_pg->get() : nullptr,
                            /*directory_sync=*/nullptr);
    }

    auto create(const std::string& body) { return sink.Post("/api/v1/management-groups", body); }
    auto add_member(const std::string& gid, const std::string& body) {
        return sink.Post("/api/v1/management-groups/" + gid + "/members", body);
    }
    auto remove_member(const std::string& gid, const std::string& agent_id) {
        return sink.Delete("/api/v1/management-groups/" + gid + "/members/" + agent_id);
    }
    /// Every stored row of one verb, whatever its result.
    [[nodiscard]] std::vector<AuditRow> rows_of(const std::string& action) const {
        std::vector<AuditRow> out;
        for (const auto& a : audits)
            if (a.action == action)
                out.push_back(a);
        return out;
    }
    [[nodiscard]] std::size_t member_count(const std::string& gid) const {
        return mgmt_bundle->get_members(gid).size();
    }
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

namespace {

/// The add-member answer is exactly `{"added":true}`: no field says whether the agent id is an
/// enrolled device (that is recorded on the success audit row only).
void expect_added_only(const httplib::Response& res) {
    CHECK(res.body.find("known") == std::string::npos);
    const auto body = nlohmann::json::parse(res.body);
    REQUIRE(body.contains("data"));
    CHECK(body.at("data") == nlohmann::json{{"added", true}});
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
    CHECK(h.audits[1].detail == "name_conflict dup-name");
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

    yuzu::test::LogCapture cap;
    auto res = h.create(R"({"name":"store-fault"})");
    cap.stop();
    REQUIRE(res);
    CHECK(res->status == 503);
    // The cause is recorded in the server log (not in the response or the audit rows).
    CHECK(cap.text().find("management_group.create store fault: failed to create group") !=
          std::string::npos);
    CHECK(cap.text().find("does not exist") != std::string::npos);
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
    CHECK(h.audits[1].detail == "store_error store-fault");
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
    CHECK(h.audits[1].detail == "session_revoked session-gone");
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
    CHECK(h.audits[1].detail == "permission_revoked perm-gone");
    CHECK(h.audits[1].bound);
}

// ---------------------------------------------------------------------------------------------
// Add member and remove member (#7074).
// ---------------------------------------------------------------------------------------------

TEST_CASE("POST /management-groups/{id}/members: an unstorable attempted row refuses the add "
          "(503 + Sec-Audit-Failed) and nothing is added",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    const std::string gid = make_group(h, "add-audit-down");
    h.fail_audit.insert(std::string(kAdd) + "|attempted");

    auto res = h.add_member(gid, R"({"agent_id":"agent-1"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->has_header("Sec-Audit-Failed"));
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["retry_after_ms"].is_number());
    CHECK(res->body.find("\"added\"") == std::string::npos);

    CHECK(h.member_count(gid) == 0);
    CHECK(h.rows_of(kAdd).empty()); // the refused attempt was not stored; no outcome row
}

TEST_CASE("POST /management-groups/{id}/members: refusals that need no write burn no attempted "
          "row",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    const std::string gid = make_group(h, "add-no-row");

    SECTION("a group id naming no group (confirmed absent) is a 404 and no row") {
        auto res = h.add_member("deadbeef0000", R"({"agent_id":"agent-1"})");
        REQUIRE(res);
        CHECK(res->status == 404);
        CHECK(res->body.find("group not found") != std::string::npos);
        CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
    }
    SECTION("a bad agent_id keeps its existing denied row and burns no attempted row") {
        auto res = h.add_member(gid, std::string(R"({"agent_id":"a)") + "\\u0001" + R"(b"})");
        REQUIRE(res);
        CHECK(res->status == 400);
        REQUIRE(h.rows_of(kAdd).size() == 1);
        CHECK(h.rows_of(kAdd)[0].result == "denied");
        CHECK(h.rows_of(kAdd)[0].detail == "invalid_agent_id");
        CHECK(h.audit_count(kAdd, "attempted") == 0);
        CHECK(h.member_count(gid) == 0);
    }
    SECTION("a missing agent_id is a 400 and no row") {
        auto res = h.add_member(gid, R"({"x":1})");
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    SECTION("malformed JSON is a 400 and no row") {
        auto res = h.add_member(gid, "{not json");
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    SECTION("a caller without ManagementGroup:Write is a 403 and no row") {
        h.perm_override = [](const std::string& type, const std::string& op) {
            return !(type == "ManagementGroup" && op == "Write");
        };
        auto res = h.add_member(gid, R"({"agent_id":"agent-1"})");
        REQUIRE(res);
        CHECK(res->status == 403);
    }
    SECTION("an unreadable group read is a retryable 503 and no row") {
        drop_mgmt_table(h, "management_group_store.management_groups");
        auto res = h.add_member(gid, R"({"agent_id":"agent-1"})");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->body.find("does not exist") == std::string::npos);
    }

    // None of the above burned an attempted or outcome row (the denied row is a refusal row).
    CHECK(h.audit_count(kAdd, "attempted") == 0);
    CHECK(h.audit_count(kAdd, "success") == 0);
    CHECK(h.audit_count(kAdd, "failure") == 0);
}

TEST_CASE("POST /management-groups/{id}/members: success writes attempted then success with the "
          "group id as target and the agent id as detail",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    const std::string gid = make_group(h, "add-ok");

    auto res = h.add_member(gid, R"({"agent_id":"agent-1"})");
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
    CHECK(res->body.find("\"added\":true") != std::string::npos);
    CHECK(h.member_count(gid) == 1);

    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == kAdd);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[0].target_type == "ManagementGroup");
    CHECK(h.audits[0].target_id == gid);
    CHECK(h.audits[0].detail == "agent-1"); // the attempted row keeps the bare raw id
    CHECK(h.audits[1].action == kAdd);
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].target_id == gid);
    // No AuthDB is wired here, so the lookup is unreadable (see the agent-known cases below).
    CHECK(h.audits[1].detail == "agent-1 agent_known=unreadable");
    expect_added_only(*res); // the response never carries the agent-known flag
}

TEST_CASE("POST /management-groups/{id}/members: a lost outcome row keeps the 201 and marks the "
          "response Sec-Audit-Failed",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    const std::string gid = make_group(h, "add-outcome-lost");
    h.fail_audit.insert(std::string(kAdd) + "|success");

    auto res = h.add_member(gid, R"({"agent_id":"agent-1"})");
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(res->has_header("Sec-Audit-Failed"));
    CHECK(h.member_count(gid) == 1);

    // The attempted row stands alone: "started, outcome unknown".
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "attempted");
}

TEST_CASE("POST /management-groups/{id}/members: a store fault on the insert answers 503 with a "
          "store_error failure row, never the database text",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    const std::string gid = make_group(h, "add-store-fault");
    drop_mgmt_table(h, "management_group_store.management_group_members");

    auto res = h.add_member(gid, R"({"agent_id":"agent-1"})");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["retry_after_ms"].is_number());
    CHECK(res->body.find("management group store unavailable") != std::string::npos);
    for (const char* leak : {"management_group_members", "does not exist", "ERROR", "failed"})
        CHECK(res->body.find(leak) == std::string::npos);

    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == kAdd);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].action == kAdd);
    CHECK(h.audits[1].result == "failure");
    CHECK(h.audits[1].target_id == gid);
    CHECK(h.audits[1].detail == "store_error agent-1");
    CHECK(h.audit_count(kAdd, "success") == 0);
}

TEST_CASE("POST /management-groups/{id}/members: a session or grant gone after the attempted row "
          "adds nothing and writes a revoked failure row",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    const std::string gid = make_group(h, "add-revoked");

    SECTION("session gone") {
        h.session_gone_after_attempted = true;
        auto res = h.add_member(gid, R"({"agent_id":"agent-1"})");
        REQUIRE(res);
        CHECK(res->status == 401);
        REQUIRE(h.audits.size() == 2);
        CHECK(h.audits[0].result == "attempted");
        CHECK(h.audits[1].action == kAdd);
        CHECK(h.audits[1].result == "failure");
        CHECK(h.audits[1].target_id == gid);
        CHECK(h.audits[1].detail == "session_revoked agent-1");
    }
    SECTION("permission revoked") {
        h.perm_revoked_after_attempted = true;
        auto res = h.add_member(gid, R"({"agent_id":"agent-1"})");
        REQUIRE(res);
        CHECK(res->status == 403);
        REQUIRE(h.audits.size() == 2);
        CHECK(h.audits[0].result == "attempted");
        CHECK(h.audits[1].action == kAdd);
        CHECK(h.audits[1].result == "failure");
        CHECK(h.audits[1].detail == "permission_revoked agent-1");
        CHECK(h.audits[1].bound);
    }
    CHECK(h.member_count(gid) == 0);
}

TEST_CASE("POST /management-groups/{id}/members: a group deleted between the check and the "
          "insert answers 404 and records a group_not_found failure row",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    const std::string gid = make_group(h, "add-vanishes");
    // Deterministic race: the group exists at the route's exists check, the `attempted` row is
    // stored, then the group is deleted before the membership insert (the first auth_fn call
    // after the attempted row is the post-attempted re-check, which runs before the insert).
    h.after_attempted_hook = [&h, &gid]() { CHECK(h.mgmt_bundle->delete_group(gid).has_value()); };

    SECTION("the outcome row is stored") {
        auto res = h.add_member(gid, R"({"agent_id":"agent-1"})");
        REQUIRE(res);
        CHECK(res->status == 404);
        CHECK(res->body.find("group not found") != std::string::npos);
        CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
        CHECK(h.audit_count(kAdd, "success") == 0);
        REQUIRE(h.audits.size() == 2);
        CHECK(h.audits[0].action == kAdd);
        CHECK(h.audits[0].result == "attempted");
        CHECK(h.audits[1].action == kAdd);
        CHECK(h.audits[1].result == "failure");
        CHECK(h.audits[1].target_id == gid);
        CHECK(h.audits[1].detail == "group_not_found agent-1"); // a fixed token and the agent id, never the store text
    }
    SECTION("a lost outcome row keeps the 404 and marks the response Sec-Audit-Failed") {
        h.fail_audit.insert(std::string(kAdd) + "|failure");
        auto res = h.add_member(gid, R"({"agent_id":"agent-1"})");
        REQUIRE(res);
        CHECK(res->status == 404);
        CHECK(res->body.find("group not found") != std::string::npos);
        CHECK(res->has_header("Sec-Audit-Failed"));
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].result == "attempted");
    }
}

TEST_CASE("DELETE /management-groups/{id}/members/{agent}: an unstorable attempted row refuses "
          "the remove (503 + Sec-Audit-Failed) and the member is kept",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    const std::string gid = make_group(h, "remove-audit-down");
    REQUIRE(h.mgmt_bundle->add_member(gid, "agent-1").has_value());
    h.fail_audit.insert(std::string(kRemove) + "|attempted");

    auto res = h.remove_member(gid, "agent-1");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->has_header("Sec-Audit-Failed"));
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["error"]["retry_after_ms"].is_number());
    CHECK(res->body.find("\"removed\"") == std::string::npos);

    CHECK(h.member_count(gid) == 1);
    CHECK(h.rows_of(kRemove).empty());
}

TEST_CASE("DELETE /management-groups/{id}/members/{agent}: refusals that need no write burn no "
          "attempted row",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    const std::string gid = make_group(h, "remove-no-row");
    REQUIRE(h.mgmt_bundle->add_member(gid, "agent-1").has_value());

    SECTION("a bad agent_id keeps its existing denied row and burns no attempted row") {
        auto res = h.remove_member(gid, std::string("agent") + '\x1b' + "1");
        REQUIRE(res);
        CHECK(res->status == 400);
        REQUIRE(h.rows_of(kRemove).size() == 1);
        CHECK(h.rows_of(kRemove)[0].result == "denied");
        CHECK(h.rows_of(kRemove)[0].detail == "invalid_agent_id");
        CHECK(h.audit_count(kRemove, "attempted") == 0);
        CHECK(h.member_count(gid) == 1);
    }
    SECTION("a caller without ManagementGroup:Write is a 403 and no row") {
        h.perm_override = [](const std::string& type, const std::string& op) {
            return !(type == "ManagementGroup" && op == "Write");
        };
        auto res = h.remove_member(gid, "agent-1");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.member_count(gid) == 1);
    }

    // None of the above burned an attempted or outcome row (the denied row is a refusal row).
    CHECK(h.audit_count(kRemove, "attempted") == 0);
    CHECK(h.audit_count(kRemove, "success") == 0);
    CHECK(h.audit_count(kRemove, "failure") == 0);
}

TEST_CASE("DELETE /management-groups/{id}/members/{agent}: success writes attempted then success "
          "with the group id as target and the agent id as detail",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    const std::string gid = make_group(h, "remove-ok");
    REQUIRE(h.mgmt_bundle->add_member(gid, "agent-1").has_value());

    auto res = h.remove_member(gid, "agent-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
    CHECK(res->body.find("\"removed\":true") != std::string::npos);
    CHECK(h.member_count(gid) == 0);

    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == kRemove);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[0].target_type == "ManagementGroup");
    CHECK(h.audits[0].target_id == gid);
    CHECK(h.audits[0].detail == "agent-1");
    CHECK(h.audits[1].action == kRemove);
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].target_id == gid);
    CHECK(h.audits[1].detail == "agent-1");
}

TEST_CASE("DELETE /management-groups/{id}/members/{agent}: a lost outcome row keeps the success "
          "and marks the response Sec-Audit-Failed",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    const std::string gid = make_group(h, "remove-outcome-lost");
    REQUIRE(h.mgmt_bundle->add_member(gid, "agent-1").has_value());
    h.fail_audit.insert(std::string(kRemove) + "|success");

    auto res = h.remove_member(gid, "agent-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->has_header("Sec-Audit-Failed"));
    CHECK(h.member_count(gid) == 0);

    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "attempted");
}

TEST_CASE("DELETE /management-groups/{id}/members/{agent}: a store fault answers 503 with a "
          "store_error failure row, never the database text",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    const std::string gid = make_group(h, "remove-store-fault");
    drop_mgmt_table(h, "management_group_store.management_group_members");

    auto res = h.remove_member(gid, "agent-1");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->body.find("management group store unavailable") != std::string::npos);
    for (const char* leak : {"management_group_members", "does not exist", "ERROR", "failed"})
        CHECK(res->body.find(leak) == std::string::npos);

    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == kRemove);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].action == kRemove);
    CHECK(h.audits[1].result == "failure");
    CHECK(h.audits[1].target_id == gid);
    CHECK(h.audits[1].detail == "store_error agent-1");
    CHECK(h.audit_count(kRemove, "success") == 0);
}

TEST_CASE("DELETE /management-groups/{id}/members/{agent}: a session or grant gone after the "
          "attempted row removes nothing and writes a revoked failure row",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    const std::string gid = make_group(h, "remove-revoked");
    REQUIRE(h.mgmt_bundle->add_member(gid, "agent-1").has_value());

    SECTION("session gone") {
        h.session_gone_after_attempted = true;
        auto res = h.remove_member(gid, "agent-1");
        REQUIRE(res);
        CHECK(res->status == 401);
        REQUIRE(h.audits.size() == 2);
        CHECK(h.audits[0].result == "attempted");
        CHECK(h.audits[1].action == kRemove);
        CHECK(h.audits[1].result == "failure");
        CHECK(h.audits[1].target_id == gid);
        CHECK(h.audits[1].detail == "session_revoked agent-1");
    }
    SECTION("permission revoked") {
        h.perm_revoked_after_attempted = true;
        auto res = h.remove_member(gid, "agent-1");
        REQUIRE(res);
        CHECK(res->status == 403);
        REQUIRE(h.audits.size() == 2);
        CHECK(h.audits[0].result == "attempted");
        CHECK(h.audits[1].action == kRemove);
        CHECK(h.audits[1].result == "failure");
        CHECK(h.audits[1].detail == "permission_revoked agent-1");
        CHECK(h.audits[1].bound);
    }
    CHECK(h.member_count(gid) == 1);
}

// ---------------------------------------------------------------------------------------------
// Add member records whether the agent id is a known device (#6967, #7074): accept and flag, in
// the success audit row ONLY. "Known" = a row in the durable enrolment table
// (`AuthDB::pending_status`). The flag never changes whether the add happens, is never returned in
// the response, and an unreadable lookup is never recorded as "unknown".
// ---------------------------------------------------------------------------------------------

namespace {

/// Put an enrolment row for `agent_id` in the harness's real AuthDB, in the given status.
void enrol(AuditFirstHarness& h, const std::string& agent_id, auth::PendingStatus status) {
    REQUIRE(h.auth_db_pg.has_value());
    auth::PendingAgent a;
    a.agent_id = agent_id;
    a.hostname = "host-1";
    a.os = "linux";
    a.arch = "x64";
    a.agent_version = "1.0.0";
    a.requested_at = std::chrono::system_clock::now();
    a.status = auth::PendingStatus::pending;
    auto added = h.auth_db_pg->get()->add_pending(a);
    REQUIRE(added.has_value());
    REQUIRE(*added);
    if (status == auth::PendingStatus::approved)
        REQUIRE(h.auth_db_pg->get()->approve_pending(agent_id, "admin").has_value());
    else if (status == auth::PendingStatus::denied)
        REQUIRE(h.auth_db_pg->get()->deny_pending(agent_id, "admin").has_value());
}

nlohmann::json add_body(const std::string& agent_id) {
    return nlohmann::json{{"agent_id", agent_id}};
}

} // namespace

TEST_CASE("POST /management-groups/{id}/members: a known device (any enrolment status) is "
          "recorded as agent_known=1 and the response carries no known field",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h(/*with_auth_db=*/true);
    const std::string gid = make_group(h, "known-ok");

    const auto status = GENERATE(auth::PendingStatus::pending, auth::PendingStatus::approved,
                                 auth::PendingStatus::denied);
    INFO("enrolment status " << static_cast<int>(status));
    enrol(h, "agent-known", status);

    auto res = h.add_member(gid, add_body("agent-known").dump());
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
    expect_added_only(*res);
    CHECK(h.member_count(gid) == 1);

    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[0].detail == "agent-known"); // the attempted row keeps the bare raw id
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].detail == "agent-known agent_known=1");
}

TEST_CASE("POST /management-groups/{id}/members: an unknown device is still added, recorded as "
          "agent_known=0, with no known field in the response",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h(/*with_auth_db=*/true);
    const std::string gid = make_group(h, "unknown-ok");
    enrol(h, "agent-known", auth::PendingStatus::approved); // a different id exists

    auto res = h.add_member(gid, add_body("agent-never-seen").dump());
    REQUIRE(res);
    CHECK(res->status == 201);
    expect_added_only(*res);

    // The member row exists: an unknown id is flagged, never refused.
    const auto members = h.mgmt_bundle->get_members(gid);
    REQUIRE(members.size() == 1);
    CHECK(members[0].agent_id == "agent-never-seen");

    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].detail == "agent-never-seen");
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].detail == "agent-never-seen agent_known=0");
}

TEST_CASE("POST /management-groups/{id}/members: matching is exact, a case-only mismatch of a "
          "known id is unknown and is not refused",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h(/*with_auth_db=*/true);
    const std::string gid = make_group(h, "case-only");
    enrol(h, "Agent-ABC", auth::PendingStatus::approved);

    auto res = h.add_member(gid, add_body("agent-abc").dump());
    REQUIRE(res);
    CHECK(res->status == 201);
    expect_added_only(*res);
    CHECK(h.member_count(gid) == 1);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].detail == "agent-abc agent_known=0");
}

TEST_CASE("POST /management-groups/{id}/members: an id the enrolment store cannot hold (a comma) "
          "is unknown, not unreadable, and is still added",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    // An id over 256 bytes is refused by the route before it reaches the lookup (the length
    // bound equals the enrolment store's own), so the comma is the one input the store refuses
    // that a member add can still carry.
    AuditFirstHarness h(/*with_auth_db=*/true);
    const std::string gid = make_group(h, "invalid-input");

    const std::string id = "web,01";

    auto res = h.add_member(gid, add_body(id).dump());
    REQUIRE(res);
    CHECK(res->status == 201);
    expect_added_only(*res);
    CHECK(h.member_count(gid) == 1);

    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].detail == id); // the attempted row keeps the bare raw id
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].detail == id + " agent_known=0");
}

TEST_CASE("POST /management-groups/{id}/members: no AuthDB wired records "
          "agent_known=unreadable and still adds, with no known field in the response",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h; // auth_db is null
    const std::string gid = make_group(h, "no-auth-db");

    auto res = h.add_member(gid, add_body("agent-1").dump());
    REQUIRE(res);
    CHECK(res->status == 201);
    expect_added_only(*res);
    CHECK(h.member_count(gid) == 1);

    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].detail == "agent-1 agent_known=unreadable");
}

TEST_CASE("POST /management-groups/{id}/members: a lookup store error records "
          "agent_known=unreadable and still adds, never recording unknown",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h(/*with_auth_db=*/true);
    const std::string gid = make_group(h, "lookup-error");
    enrol(h, "agent-1", auth::PendingStatus::approved); // would be known if the table were readable
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.auth_db_pg->dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{PQexec(conn.get(), "DROP TABLE auth.pending_agents CASCADE")};
        REQUIRE(d.ok());
    }

    auto res = h.add_member(gid, add_body("agent-1").dump());
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
    expect_added_only(*res);
    CHECK(res->body.find("auth.pending_agents") == std::string::npos); // no store text
    CHECK(h.member_count(gid) == 1);

    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].detail == "agent-1 agent_known=unreadable");
}

TEST_CASE("POST /management-groups/{id}/members: the last token of the success detail is the "
          "flag, even for an id that spells it",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h(/*with_auth_db=*/true);
    const std::string gid = make_group(h, "forged-suffix");
    const std::string id = "x agent_known=1"; // a space and the flag text inside the raw id

    auto res = h.add_member(gid, add_body(id).dump());
    REQUIRE(res);
    CHECK(res->status == 201);
    expect_added_only(*res);

    REQUIRE(h.audits.size() == 2);
    const auto& d = h.audits[1].detail;
    CHECK(d == id + " agent_known=0");
    CHECK(d.substr(d.rfind(' ') + 1) == "agent_known=0");
    CHECK(h.audits[0].detail == id); // the attempted row stays the bare raw id
}

TEST_CASE("POST /management-groups/{id}/members: the lookup never refuses, and a failed attempted "
          "row still refuses before any member is added",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h(/*with_auth_db=*/true);
    const std::string gid = make_group(h, "lookup-no-refuse");
    h.fail_audit.insert(std::string(kAdd) + "|attempted");

    auto res = h.add_member(gid, add_body("agent-never-seen").dump());
    REQUIRE(res);
    CHECK(res->status == 503); // the audit-first refusal, not a lookup refusal
    CHECK(res->has_header("Sec-Audit-Failed"));
    CHECK(res->body.find("known") == std::string::npos);
    CHECK(h.member_count(gid) == 0);
}

// ── F1 (Gate 7): over-long or unclean group names and agent ids are refused BEFORE any row ──────

namespace {

std::string json_body(const std::string& key, const std::string& value) {
    return nlohmann::json{{key, value}}.dump();
}

} // namespace

TEST_CASE("POST /management-groups: an over-long or unclean name is a 400 before any audit row "
          "and creates nothing",
          "[pg][rest][mgmt_group][mgmt-audit-first][security]") {
    AuditFirstHarness h;
    const auto groups_before = h.group_count();

    SECTION("a name one byte over the bound (257) is refused; exactly 256 is accepted") {
        auto over = h.create(json_body("name", std::string(257, 'n')));
        REQUIRE(over);
        CHECK(over->status == 400);
        CHECK(over->body.find("at most 256 bytes") != std::string::npos);
        CHECK(h.audits.empty());
        CHECK(h.group_count() == groups_before);

        auto at_bound = h.create(json_body("name", std::string(256, 'n')));
        REQUIRE(at_bound);
        CHECK(at_bound->status == 201);
        CHECK(h.audit_count(kCreate, "attempted") == 1);
        CHECK(h.audit_count(kCreate, "success") == 1);
    }
    SECTION("300 B, 3 KB and a ~3 MiB name") {
        for (const std::size_t n : {std::size_t{300}, std::size_t{3 * 1024},
                                    std::size_t{3 * 1024 * 1024}}) {
            auto res = h.create(json_body("name", std::string(n, 'x')));
            REQUIRE(res);
            CHECK(res->status == 400);
            CHECK(res->body.size() < 1024); // the value is never echoed
            CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
        }
        CHECK(h.audits.empty());
        CHECK(h.group_count() == groups_before);
    }
    SECTION("a retry loop of 20 over-long creates writes no row and never turns into a 503") {
        for (int i = 0; i < 20; ++i) {
            auto res = h.create(json_body("name", std::string(3 * 1024, 'r')));
            REQUIRE(res);
            CHECK(res->status == 400);
        }
        CHECK(h.audits.empty());
        CHECK(h.group_count() == groups_before);
    }
    SECTION("a newline, a NUL, a tab and a DEL in the name (invalid UTF-8 cannot reach this "
            "route: the JSON parser refuses it first)") {
        for (const auto& name :
             {std::string("line1\nline2"), std::string("nul\0byte", 8), std::string("tab\there"),
              std::string("del\x7f")}) {
            auto res = h.create(json_body("name", name));
            REQUIRE(res);
            CHECK(res->status == 400);
            CHECK(res->body.find("control characters") != std::string::npos);
        }
        auto raw = h.create(std::string("{\"name\":\"bad\xff\xfe\"}"));
        REQUIRE(raw);
        CHECK(raw->status == 400);
        CHECK(h.audits.empty());
        CHECK(h.group_count() == groups_before);
    }
    SECTION("an over-long or unclean parent id names no group: 400, no row") {
        for (const auto& pid : {std::string(300, 'a'), std::string(3 * 1024, 'b'),
                                std::string("ab\ncd")}) {
            auto res = h.create(
                nlohmann::json{{"name", "child"}, {"parent_id", pid}}.dump());
            REQUIRE(res);
            CHECK(res->status == 400);
            CHECK(res->body.find("parent group not found") != std::string::npos);
        }
        CHECK(h.audits.empty());
        CHECK_FALSE(h.group_exists("child"));
    }
}

TEST_CASE("POST /management-groups/{id}/members: an over-long agent id is a 400 with no row, 256 is "
          "accepted",
          "[pg][rest][mgmt_group][mgmt-audit-first][security]") {
    AuditFirstHarness h;
    const std::string gid = make_group(h, "limits-add");

    SECTION("257 B, 3 KB and a ~3 MiB agent id: no row of any kind") {
        for (const std::size_t n : {std::size_t{257}, std::size_t{3 * 1024},
                                    std::size_t{3 * 1024 * 1024}}) {
            auto res = h.add_member(gid, json_body("agent_id", std::string(n, 'a')));
            REQUIRE(res);
            CHECK(res->status == 400);
            CHECK(res->body.find("at most 256 bytes") != std::string::npos);
        }
        CHECK(h.audits.empty());
        CHECK(h.member_count(gid) == 0);
    }
    SECTION("a 20-iteration retry loop writes no row") {
        for (int i = 0; i < 20; ++i) {
            auto res = h.add_member(gid, json_body("agent_id", std::string(3 * 1024, 'a')));
            REQUIRE(res);
            CHECK(res->status == 400);
        }
        CHECK(h.audits.empty());
    }
    SECTION("exactly 256 bytes is accepted") {
        auto res = h.add_member(gid, json_body("agent_id", std::string(256, 'a')));
        REQUIRE(res);
        CHECK(res->status == 201);
        CHECK(h.audit_count(kAdd, "attempted") == 1);
        CHECK(h.member_count(gid) == 1);
    }
    SECTION("a group id longer than the bound names no group: 404, no row") {
        auto res = h.add_member(std::string(3 * 1024, 'a'), R"({"agent_id":"agent-1"})");
        REQUIRE(res);
        CHECK(res->status == 404);
        CHECK(h.audits.empty());
    }
}

TEST_CASE("DELETE /management-groups/{id}/members/{agent}: an over-long agent id or group id is "
          "refused with no row, 256 is accepted",
          "[pg][rest][mgmt_group][mgmt-audit-first][security]") {
    AuditFirstHarness h;
    const std::string gid = make_group(h, "limits-remove");
    REQUIRE(h.mgmt_bundle->add_member(gid, std::string(256, 'a')).has_value());

    SECTION("257 B and 3 KB agent ids: 400, no row, member untouched") {
        for (const std::size_t n : {std::size_t{257}, std::size_t{3 * 1024}}) {
            auto res = h.remove_member(gid, std::string(n, 'a'));
            REQUIRE(res);
            CHECK(res->status == 400);
            CHECK(res->body.find("at most 256 bytes") != std::string::npos);
        }
        CHECK(h.audits.empty());
        CHECK(h.member_count(gid) == 1);
    }
    SECTION("a 20-iteration retry loop writes no row") {
        for (int i = 0; i < 20; ++i) {
            auto res = h.remove_member(gid, std::string(3 * 1024, 'a'));
            REQUIRE(res);
            CHECK(res->status == 400);
        }
        CHECK(h.audits.empty());
    }
    SECTION("exactly 256 bytes is accepted and removes the member") {
        auto res = h.remove_member(gid, std::string(256, 'a'));
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(h.audit_count(kRemove, "attempted") == 1);
        CHECK(h.member_count(gid) == 0);
    }
    SECTION("a group id longer than the bound names no group: 404, no row") {
        auto res = h.remove_member(std::string(3 * 1024, 'a'), "agent-1");
        REQUIRE(res);
        CHECK(res->status == 404);
        CHECK(h.audits.empty());
    }
}

// ── F3 (Gate 7): one name-conflict predicate, a checked parent read, validation_refused ──────────

TEST_CASE("create_failure_token: the fixed audit token for each class of create failure",
          "[mgmt-audit-first][mgmt_group_error]") {
    CHECK(create_failure_token(kMgmtGroupNameConflict) == "name_conflict");
    CHECK(create_failure_token("a group with that name already exists") == "name_conflict");
    // Only the exact text is a conflict: the same words inside a longer message are not.
    CHECK(create_failure_token("a group with that name already exists (x)") ==
          "validation_refused");
    for (const char* fault : {"database not open", "pool acquire timed out",
                              "failed to create group: ERROR: boom",
                              "failed to resolve ancestor chain (store degraded)"})
        CHECK(create_failure_token(fault) == "store_error");
    for (const char* refusal : {"parent group not found", "maximum hierarchy depth (5) exceeded",
                                "group name cannot be empty", "group cannot be its own parent", ""})
        CHECK(create_failure_token(refusal) == "validation_refused");
}

TEST_CASE("the store's duplicate-name answer is exactly kMgmtGroupNameConflict",
          "[pg][mgmt_group][mgmt-audit-first][mgmt_group_error]") {
    AuditFirstHarness h;
    ManagementGroup g;
    g.name = "twice";
    g.membership_type = "static";
    REQUIRE(h.mgmt_bundle->create_group(g).has_value());
    auto again = h.mgmt_bundle->create_group(g);
    REQUIRE_FALSE(again.has_value());
    // A rewording in management_group_store.cpp would turn name_conflict into validation_refused
    // on all three create surfaces: this pins the constant to the store's literal.
    CHECK(again.error() == kMgmtGroupNameConflict);
    CHECK(create_failure_token(again.error()) == "name_conflict");
}

TEST_CASE("validate_new_group: a parent read that FAILED is a store fault, not parent group not "
          "found; a confirmed-absent parent still is",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    ManagementGroup child;
    child.name = "child-of-unknown";
    child.parent_id = "deadbeef0000";
    child.membership_type = "static";

    SECTION("a confirmed-absent parent") {
        auto v = h.mgmt_bundle->validate_new_group(child);
        REQUIRE_FALSE(v.has_value());
        CHECK(v.error() == "parent group not found");
        CHECK_FALSE(mgmt_group_error_is_store_fault(v.error()));
        auto res = h.create(R"({"name":"child-of-unknown","parent_id":"deadbeef0000"})");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("parent group not found") != std::string::npos);
    }
    SECTION("an unreadable group table") {
        drop_mgmt_table(h, "management_group_store.management_groups");
        auto v = h.mgmt_bundle->validate_new_group(child);
        REQUIRE_FALSE(v.has_value());
        CHECK(v.error() == "failed to resolve ancestor chain (store degraded)");
        CHECK(mgmt_group_error_is_store_fault(v.error()));

        auto res = h.create(R"({"name":"child-of-unknown","parent_id":"deadbeef0000"})");
        REQUIRE(res);
        CHECK(res->status == 503); // a store fault, never a 400 "parent group not found"
        CHECK(res->body.find("parent group not found") == std::string::npos);
        CHECK(h.audits.empty()); // refused before any row
    }
}

TEST_CASE("POST /management-groups: a parent deleted between the check and the insert is a 400 "
          "with attempted then failure/validation_refused and no group",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    bool deleted = false; // before `h`: the hook below captures it and `h` is destroyed first
    AuditFirstHarness h;
    const std::string parent = make_group(h, "vanishing-parent");
    const auto groups_before = h.group_count();
    // Deterministic race: the parent exists at the route's pre-check; it is deleted while the
    // `attempted` row is stored, so create_group's own validation refuses.
    h.after_attempted_hook = [&]() { deleted = h.mgmt_bundle->delete_group(parent).has_value(); };

    auto res = h.create(nlohmann::json{{"name", "orphaned-child"}, {"parent_id", parent}}.dump());
    REQUIRE(res);
    REQUIRE(deleted);
    CHECK(res->status == 400);
    CHECK(res->body.find("parent group not found") != std::string::npos);
    CHECK_FALSE(res->has_header("Sec-Audit-Failed"));

    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == kCreate);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].action == kCreate);
    CHECK(h.audits[1].result == "failure");
    CHECK(h.audits[1].target_id.empty());
    CHECK(h.audits[1].detail == "validation_refused orphaned-child");
    CHECK_FALSE(h.group_exists("orphaned-child"));
    CHECK(h.group_count() == groups_before - 1); // only the parent's deletion changed the count
}

// ── UP-2 (Gate 7): the `*_revoked` failure rows name the principal the attempted row names ──────

TEST_CASE("POST /management-groups: the session_revoked and permission_revoked failure rows name "
          "the principal of the attempted row",
          "[pg][rest][mgmt_group][mgmt-audit-first][security]") {
    AuditFirstHarness h;

    SECTION("session revoked while the attempted row was stored") {
        h.session_gone_after_attempted = true;
        auto res = h.create(R"({"name":"revoked-session"})");
        REQUIRE(res);
        REQUIRE(h.audits.size() == 2);
        CHECK(h.audits[0].result == "attempted");
        CHECK(h.audits[0].principal == "tester");
        CHECK(h.audits[1].result == "failure");
        CHECK(h.audits[1].detail == "session_revoked revoked-session");
        CHECK(h.audits[1].bound); // not re-resolved: a re-resolved row would name nobody here
        CHECK(h.audits[1].principal == "tester");
        CHECK(h.audits[1].principal == h.audits[0].principal);
        CHECK(h.audits[1].target_id == h.audits[0].target_id);
    }
    SECTION("permission revoked while the attempted row was stored") {
        h.perm_revoked_after_attempted = true;
        auto res = h.create(R"({"name":"revoked-perm"})");
        REQUIRE(res);
        REQUIRE(h.audits.size() == 2);
        CHECK(h.audits[1].detail == "permission_revoked revoked-perm");
        CHECK(h.audits[1].bound);
        CHECK(h.audits[1].principal == "tester");
        CHECK(h.audits[1].principal == h.audits[0].principal);
    }
    CHECK_FALSE(h.group_exists("revoked-session"));
    CHECK_FALSE(h.group_exists("revoked-perm"));
}

TEST_CASE("POST and DELETE members: the session_revoked failure row names the principal of the "
          "attempted row",
          "[pg][rest][mgmt_group][mgmt-audit-first][security]") {
    AuditFirstHarness h;
    const std::string gid = make_group(h, "revoked-members");
    REQUIRE(h.mgmt_bundle->add_member(gid, "agent-1").has_value());
    h.session_gone_after_attempted = true;

    SECTION("add member") {
        auto res = h.add_member(gid, R"({"agent_id":"agent-2"})");
        REQUIRE(res);
        const auto rows = h.rows_of(kAdd);
        REQUIRE(rows.size() == 2);
        CHECK(rows[1].detail == "session_revoked agent-2");
        CHECK(rows[1].bound);
        CHECK(rows[1].principal == "tester");
        CHECK(rows[1].principal == rows[0].principal);
        CHECK(rows[1].target_id == gid);
        CHECK(h.member_count(gid) == 1);
    }
    SECTION("remove member") {
        auto res = h.remove_member(gid, "agent-1");
        REQUIRE(res);
        const auto rows = h.rows_of(kRemove);
        REQUIRE(rows.size() == 2);
        CHECK(rows[1].detail == "session_revoked agent-1");
        CHECK(rows[1].bound);
        CHECK(rows[1].principal == "tester");
        CHECK(rows[1].principal == rows[0].principal);
        CHECK(h.member_count(gid) == 1);
    }
}

// ── Every row after the attempted row is written through the session-bound writer ───────────────
// The re-check passes, then the session lapses (create_group and add_member can wait up to 4 s on
// the pool): an outcome row stamped by the re-resolving `audit_fn` would name nobody. The harness's
// `audit_fn` models that (principal "" once `session_gone_after_recheck`), so these cases fail on a
// route that writes any outcome row through it.

TEST_CASE("POST /management-groups: the success and failure outcome rows are session-bound and "
          "name the attempted row's principal",
          "[pg][rest][mgmt_group][mgmt-audit-first][security]") {
    AuditFirstHarness h;
    h.session_gone_after_recheck = true;

    SECTION("success row") {
        auto res = h.create(R"({"name":"bound-success"})");
        REQUIRE(res);
        CHECK(res->status == 201);
        REQUIRE(h.audits.size() == 2);
        CHECK(h.audits[0].result == "attempted");
        CHECK(h.audits[0].principal == "tester");
        CHECK(h.audits[1].result == "success");
        CHECK(h.audits[1].bound);
        CHECK(h.audits[1].principal == "tester");
        CHECK(h.audits[1].principal == h.audits[0].principal);
    }
    SECTION("name_conflict failure row") {
        make_group(h, "bound-dup");
        auto res = h.create(R"({"name":"bound-dup"})");
        REQUIRE(res);
        REQUIRE(h.create_rows() == 2);
        const auto rows = h.rows_of(kCreate);
        CHECK(rows[1].result == "failure");
        CHECK(rows[1].bound);
        CHECK(rows[1].principal == "tester");
        CHECK(rows[1].principal == rows[0].principal);
    }
    SECTION("store_error failure row") {
        drop_mgmt_table(h, "management_group_store.management_groups");
        auto res = h.create(R"({"name":"bound-fault"})");
        REQUIRE(res);
        const auto rows = h.rows_of(kCreate);
        REQUIRE(rows.size() == 2);
        CHECK(rows[1].result == "failure");
        CHECK(rows[1].bound);
        CHECK(rows[1].principal == rows[0].principal);
    }
}

TEST_CASE("POST /management-groups/{id}/members: the success and group_not_found rows are "
          "session-bound and name the attempted row's principal",
          "[pg][rest][mgmt_group][mgmt-audit-first][security]") {
    AuditFirstHarness h;
    h.session_gone_after_recheck = true;
    const std::string gid = make_group(h, "bound-add");

    SECTION("success row") {
        auto res = h.add_member(gid, R"({"agent_id":"agent-b1"})");
        REQUIRE(res);
        CHECK(res->status == 201);
        const auto rows = h.rows_of(kAdd);
        REQUIRE(rows.size() == 2);
        CHECK(rows[1].result == "success");
        CHECK(rows[1].bound);
        CHECK(rows[1].principal == "tester");
        CHECK(rows[1].principal == rows[0].principal);
    }
    SECTION("group_not_found failure row") {
        h.after_attempted_hook = [&h, &gid]() { CHECK(h.mgmt_bundle->delete_group(gid).has_value()); };
        auto res = h.add_member(gid, R"({"agent_id":"agent-b2"})");
        REQUIRE(res);
        CHECK(res->status == 404);
        const auto rows = h.rows_of(kAdd);
        REQUIRE(rows.size() == 2);
        CHECK(rows[1].detail == "group_not_found agent-b2");
        CHECK(rows[1].bound);
        CHECK(rows[1].principal == rows[0].principal);
    }
}

TEST_CASE("DELETE /management-groups/{id}/members/{agent}: the success and store_error rows are "
          "session-bound and name the attempted row's principal",
          "[pg][rest][mgmt_group][mgmt-audit-first][security]") {
    AuditFirstHarness h;
    h.session_gone_after_recheck = true;
    const std::string gid = make_group(h, "bound-remove");
    REQUIRE(h.mgmt_bundle->add_member(gid, "agent-b3").has_value());

    SECTION("success row") {
        auto res = h.remove_member(gid, "agent-b3");
        REQUIRE(res);
        const auto rows = h.rows_of(kRemove);
        REQUIRE(rows.size() == 2);
        CHECK(rows[1].result == "success");
        CHECK(rows[1].bound);
        CHECK(rows[1].principal == "tester");
        CHECK(rows[1].principal == rows[0].principal);
    }
    SECTION("store_error failure row") {
        drop_mgmt_table(h, "management_group_store.management_group_members");
        auto res = h.remove_member(gid, "agent-b3");
        REQUIRE(res);
        const auto rows = h.rows_of(kRemove);
        REQUIRE(rows.size() == 2);
        CHECK(rows[1].detail == "store_error agent-b3");
        CHECK(rows[1].bound);
        CHECK(rows[1].principal == rows[0].principal);
    }
}

// ── The attempted row is session-bound too ──────────────────────────────────────────────────────
// The route resolves the session before the `attempted` row, and the row can wait on the audit
// pool, so the session can lapse in between. The re-resolving `audit_fn` would then stamp an empty
// principal on the `attempted` row while every later row names the user, which breaks pairing the
// rows by principal. The harness's `audit_fn` models that (principal "" for an `attempted` row
// once `session_gone_at_attempted`), so these cases fail on a route that writes it through
// `audit_fn`.

TEST_CASE("POST /management-groups: the attempted row is written through the session-bound writer "
          "and names the principal when the session lapsed before it",
          "[pg][rest][mgmt_group][mgmt-audit-first][security]") {
    AuditFirstHarness h;
    h.session_gone_at_attempted = true;
    h.session_gone_after_attempted = true; // the re-check then refuses
    auto res = h.create(R"({"name":"attempt-bound"})");
    REQUIRE(res);
    CHECK(res->status == 401);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[0].bound);
    CHECK(h.audits[0].principal == "tester");
    CHECK(h.audits[1].result == "failure");
    CHECK(h.audits[1].bound);
    CHECK(h.audits[1].principal == h.audits[0].principal);
    CHECK_FALSE(h.group_exists("attempt-bound"));
}

TEST_CASE("POST and DELETE members: the attempted row is written through the session-bound writer "
          "and names the principal when the session lapsed before it",
          "[pg][rest][mgmt_group][mgmt-audit-first][security]") {
    AuditFirstHarness h;
    const std::string gid = make_group(h, "attempt-bound-members");
    REQUIRE(h.mgmt_bundle->add_member(gid, "agent-1").has_value());
    h.session_gone_at_attempted = true;
    h.session_gone_after_attempted = true;

    SECTION("add member") {
        auto res = h.add_member(gid, R"({"agent_id":"agent-2"})");
        REQUIRE(res);
        const auto rows = h.rows_of(kAdd);
        REQUIRE(rows.size() == 2);
        CHECK(rows[0].result == "attempted");
        CHECK(rows[0].bound);
        CHECK(rows[0].principal == "tester");
        CHECK(rows[1].principal == rows[0].principal);
        CHECK(h.member_count(gid) == 1);
    }
    SECTION("remove member") {
        auto res = h.remove_member(gid, "agent-1");
        REQUIRE(res);
        const auto rows = h.rows_of(kRemove);
        REQUIRE(rows.size() == 2);
        CHECK(rows[0].result == "attempted");
        CHECK(rows[0].bound);
        CHECK(rows[0].principal == "tester");
        CHECK(rows[1].principal == rows[0].principal);
        CHECK(h.member_count(gid) == 1);
    }
}

// ── Every failure row pairs with its attempted row: detail is "<token> <key>" ───────────────────
// A create's target_id is empty on both rows, and the add/remove rows name the group but not the
// agent, so the key (the group name for create, the agent id for add and remove) is what a reader
// pairs on. The key is already bounded and clean before any row, so it holds no control byte.

namespace {

bool detail_is_clean_text(const std::string& d) {
    for (const unsigned char c : d)
        if (c <= 0x1F || c == 0x7F)
            return false;
    return true;
}

} // namespace

TEST_CASE("POST /management-groups: a failure row's detail is the token, a space and the group "
          "name the attempted row carries",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    make_group(h, "pair-a");
    make_group(h, "pair-b");
    const std::string longest(256, 'n'); // the bound: accepted, and carried whole
    make_group(h, longest);

    std::set<std::string> details;
    for (const std::string name : {std::string("pair-a"), std::string("pair-b"), longest}) {
        h.audits.clear();
        auto res = h.create(nlohmann::json{{"name", name}}.dump());
        REQUIRE(res);
        REQUIRE(h.audits.size() == 2);
        CHECK(h.audits[0].result == "attempted");
        CHECK(h.audits[1].result == "failure");
        CHECK(h.audits[1].detail == "name_conflict " + name);
        CHECK(h.audits[1].detail == "name_conflict " + h.audits[0].detail);
        CHECK(detail_is_clean_text(h.audits[1].detail));
        details.insert(h.audits[1].detail);
    }
    CHECK(details.size() == 3); // three keys, three different details
}

TEST_CASE("POST and DELETE members: a failure row's detail is the token, a space and the agent id "
          "the attempted row carries",
          "[pg][rest][mgmt_group][mgmt-audit-first]") {
    AuditFirstHarness h;
    const std::string gid = make_group(h, "pair-members");
    drop_mgmt_table(h, "management_group_store.management_group_members");

    std::set<std::string> add_details;
    std::set<std::string> remove_details;
    for (const std::string agent : {std::string("agent-a"), std::string("agent-b")}) {
        h.audits.clear();
        auto added = h.add_member(gid, nlohmann::json{{"agent_id", agent}}.dump());
        REQUIRE(added);
        auto add_rows = h.rows_of(kAdd);
        REQUIRE(add_rows.size() == 2);
        CHECK(add_rows[1].detail == "store_error " + agent);
        CHECK(add_rows[1].detail == "store_error " + add_rows[0].detail);
        CHECK(add_rows[1].target_id == gid);
        CHECK(detail_is_clean_text(add_rows[1].detail));
        add_details.insert(add_rows[1].detail);

        h.audits.clear();
        auto removed = h.remove_member(gid, agent);
        REQUIRE(removed);
        auto remove_rows = h.rows_of(kRemove);
        REQUIRE(remove_rows.size() == 2);
        CHECK(remove_rows[1].detail == "store_error " + agent);
        CHECK(remove_rows[1].detail == "store_error " + remove_rows[0].detail);
        CHECK(detail_is_clean_text(remove_rows[1].detail));
        remove_details.insert(remove_rows[1].detail);
    }
    CHECK(add_details.size() == 2); // two keys, two different details
    CHECK(remove_details.size() == 2);
}

// ── The group-read failure log line neutralises the store's text ────────────────────────────────

TEST_CASE("POST /management-groups/{id}/members: the group read failure log line holds the store "
          "text on one physical line",
          "[pg][rest][mgmt_group][mgmt-audit-first][security]") {
    AuditFirstHarness h;
    const std::string gid = make_group(h, "read-fails");
    // PQerrorMessage text ends in a newline (and a failed statement adds a second line), so an
    // unsanitised argument would leave stray lines in the log.
    drop_mgmt_table(h, "management_group_store.management_groups");

    yuzu::test::LogCapture cap;
    auto res = h.add_member(gid, R"({"agent_id":"agent-1"})");
    cap.stop();
    REQUIRE(res);
    CHECK(res->status == 503);
    const auto text = cap.text();
    const auto at = text.find("management_group.add_member group read failure: query failed");
    REQUIRE(at != std::string::npos);
    // Only the route's OWN record is checked. The capture also holds the store's own
    // "get_group_checked: query failed" warn (logged once per degrade episode, then sampled;
    // process-wide), which this route does not control. PQerrorMessage text ends in a newline
    // (and a failed statement adds a second line), so an unsanitised argument leaves a stray
    // physical line after the first line of the route's record: the next line must be empty or
    // begin with its own timestamp.
    const auto eol = text.find('\n', at);
    REQUIRE(eol != std::string::npos); // spdlog ends every record with a newline
    const auto next_line = text.substr(eol + 1, text.find('\n', eol + 1) - (eol + 1));
    CHECK((next_line.empty() || next_line.front() == '['));
    CHECK(h.audits.empty()); // refused before any row
}
