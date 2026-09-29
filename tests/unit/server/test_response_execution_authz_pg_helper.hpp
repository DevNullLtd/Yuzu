#pragma once

#include "api_token_store.hpp"
#include "auth_routes.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "pg/pg_pool.hpp"
#include "rbac_store.hpp"
#include "test_api_token_pg_helper.hpp"
#include "test_mgmt_group_pg_helper.hpp"

#include "../test_helpers.hpp"

#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace yuzu::test {

inline PgTestTemplate response_execution_authz_tpl{
    "resp_exec_scope_1634", [](const std::string& dsn) {
        server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        server::RbacStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("response/execution authz template failed to migrate");
    }};

/// Real AuthRoutes fleet-read rig shared by the #1634/#3789 route tests. Bob
/// has Response:Read and Execution:Read only through Bob's management
/// group; Alice's agent is deliberately outside that subtree. Bob ALSO
/// holds Execution:Execute — GLOBALLY (`RbacStore::assign_role`, not
/// `ManagementGroupStore::assign_role`) — for the #3789 mutation-rule
/// tests: `require_permission` resolves grants ONLY via
/// `RbacStore::collect_roles`'s `rbac_store.principal_roles` union, which
/// never joins management-group assignments (verified against
/// `rbac_store.cpp`'s `authorize_list_read` vs `check_permission` split —
/// only the former reads groups). A group-scoped Execute role would 403 at
/// `require_permission` before a mutation test ever reached the
/// confinement rule under test.
struct ResponseExecutionAuthzPgRig {
    using FleetReadFn = std::function<server::authz::FleetReadGate(
        const httplib::Request&, httplib::Response&, const std::string&, const std::string&)>;
    using AuthFn = std::function<std::optional<server::auth::Session>(
        const httplib::Request&, httplib::Response&)>;

    server::Config cfg{};
    server::auth::AuthManager auth_mgr{};
    server::pg::PgPool pool;
    server::RbacStore rbac;
    ManagementGroupStorePg mgmt_bundle;
    server::ManagementGroupStore& mgmt = *mgmt_bundle;
    ApiTokenStorePg api_tokens;
    std::shared_mutex oidc_mu;
    std::unique_ptr<server::oidc::OidcProvider> oidc_provider;
    std::unique_ptr<server::AuthRoutes> auth_routes;
    std::string bob_group;
    std::string alice_group;

    explicit ResponseExecutionAuthzPgRig(const std::string& dsn)
        : pool{{.conninfo = dsn, .size = 4}}, rbac{pool} {
        REQUIRE(pool.valid());
        REQUIRE(rbac.is_open());
        rbac.set_rbac_enabled(true);

        REQUIRE(rbac.create_role({"ResponseReader1634", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"ResponseReader1634", "Response", "Read", "allow"})
                    .has_value());
        REQUIRE(rbac.create_role({"ExecutionReader1634", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"ExecutionReader1634", "Execution", "Read", "allow"})
                    .has_value());
        // #3789: mutation-rule coverage needs Execute — assigned GLOBALLY
        // below (RbacStore::assign_role), never via ManagementGroupStore —
        // see this struct's doc comment.
        REQUIRE(rbac.create_role({"ExecutionExecutor3789", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"ExecutionExecutor3789", "Execution", "Execute", "allow"})
                    .has_value());
        REQUIRE(rbac.assign_role({"user", "bob", "ExecutionExecutor3789"}).has_value());

        bob_group = make_group("Bob-1634");
        alice_group = make_group("Alice-1634");
        REQUIRE(mgmt.add_member(bob_group, "bob-agent").has_value());
        REQUIRE(mgmt.add_member(alice_group, "alice-agent").has_value());
        REQUIRE(mgmt.assign_role({bob_group, "user", "bob", "ResponseReader1634"})
                    .has_value());
        REQUIRE(mgmt.assign_role({bob_group, "user", "bob", "ExecutionReader1634"})
                    .has_value());

        REQUIRE(auth_mgr.upsert_user("bob", "correct-horse-battery-staple",
                                     server::auth::Role::admin));
        auth_routes = std::make_unique<server::AuthRoutes>(
            cfg, auth_mgr, &rbac, api_tokens.get(), /*audit_store=*/nullptr, &mgmt,
            /*tag_store=*/nullptr, /*analytics_store=*/nullptr, oidc_mu, oidc_provider);
    }

    std::string make_group(const std::string& name) {
        server::ManagementGroup group;
        group.name = name;
        group.membership_type = "static";
        auto id = mgmt.create_group(group);
        REQUIRE(id.has_value());
        return *id;
    }

    std::string mint_bob() {
        const auto expires = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count() +
                             3600;
        auto token = api_tokens->create_token("scope-1634", "bob", expires);
        REQUIRE(token.has_value());
        return *token;
    }

    FleetReadFn fleet_read_fn() {
        return [this](const httplib::Request& req, httplib::Response& res,
                      const std::string& type,
                      const std::string& operation) -> server::authz::FleetReadGate {
            auto result = auth_routes->require_fleet_read(req, res, type, operation);
            if (!result)
                return {};
            return {true, result->visible_for_query()};
        };
    }

    AuthFn auth_fn() {
        return [this](const httplib::Request& req,
                      httplib::Response& res) -> std::optional<server::auth::Session> {
            return auth_routes->require_auth(req, res);
        };
    }

    static std::unordered_map<std::string, std::string> bearer(const std::string& token) {
        return {{"Authorization", "Bearer " + token}};
    }
};

} // namespace yuzu::test
