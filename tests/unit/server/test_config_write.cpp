/**
 * test_config_write.cpp — the transport-free core of the Runtime Configuration API
 * (config_write.hpp), exercised without any route, session store or Postgres.
 *
 * The route and MCP suites (test_config_routes.cpp, test_mcp_server.cpp) prove each surface calls
 * the core; these cases prove the core's own decisions, so a surface cannot be right only because
 * its test happens to use a key the core gets right. Everything here is driven from
 * `RuntimeConfigStore::allowed_keys()` and `write_class()`, so a new key is covered the moment it
 * is added to the table.
 */

#include "config_write.hpp"

#include "runtime_config_store.hpp"

#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

auth::Session session(auth::Role role, std::string mcp_tier = {}, std::string scope = {},
                      bool elevated = false) {
    auth::Session s;
    s.username = "alice";
    s.role = role;
    s.mcp_tier = std::move(mcp_tier);
    s.token_scope_service = std::move(scope);
    if (elevated)
        s.steady_elevated_until = std::chrono::steady_clock::now() + std::chrono::hours(1);
    return s;
}

std::vector<std::string> keys_of(ConfigWriteClass cls) {
    std::vector<std::string> keys;
    for (const auto& k : RuntimeConfigStore::allowed_keys())
        if (RuntimeConfigStore::write_class(k) == cls)
            keys.push_back(k);
    return keys;
}

} // namespace

TEST_CASE("config_write: a general key is admitted for every caller shape",
          "[server][config_write]") {
    const auto general = keys_of(ConfigWriteClass::General);
    REQUIRE_FALSE(general.empty());
    const auth::Session callers[] = {
        session(auth::Role::admin),
        session(auth::Role::user),
        session(auth::Role::admin, "supervised"),
        session(auth::Role::user, "", "", /*elevated=*/true),
    };
    for (const auto& key : general)
        for (const auto& s : callers) {
            INFO(key);
            CHECK_FALSE(config::write_refusal(key, s).has_value());
        }
}

TEST_CASE("config_write: an administrator-route key needs an effective admin, never a token",
          "[server][config_write][elevation]") {
    const auto keys = keys_of(ConfigWriteClass::AdminRoute);
    REQUIRE(keys.size() == 7);
    for (const auto& key : keys) {
        INFO(key);
        // Admitted: an admin account, and a JIT elevation (it counts, as on the Settings routes).
        CHECK_FALSE(config::write_refusal(key, session(auth::Role::admin)).has_value());
        CHECK_FALSE(
            config::write_refusal(key, session(auth::Role::user, "", "", /*elevated=*/true))
                .has_value());

        // Refused: a token whatever its creator's role, then a plain non-administrator.
        for (const auto& s : {session(auth::Role::admin, "supervised"),
                              session(auth::Role::admin, "", "svc-a")}) {
            auto r = config::write_refusal(key, s);
            REQUIRE(r.has_value());
            CHECK(r->kind == config::WriteRefusal::Kind::Denied);
            CHECK(r->audit_detail == "token_session_admin_setting_blocked");
            CHECK_FALSE(r->remediation.empty());
        }
        auto r = config::write_refusal(key, session(auth::Role::user));
        REQUIRE(r.has_value());
        CHECK(r->audit_detail == "admin_role_required_setting_blocked");
    }
}

TEST_CASE("config_write: the oidc keys need the caller's own admin role, so an elevation is "
          "refused",
          "[server][config_write][elevation]") {
    const auto keys = keys_of(ConfigWriteClass::AdminRouteInteractiveOnly);
    REQUIRE_FALSE(keys.empty());
    for (const auto& key : keys) {
        INFO(key);
        CHECK_FALSE(config::write_refusal(key, session(auth::Role::admin)).has_value());

        auto elevated = config::write_refusal(key, session(auth::Role::user, "", "", true));
        REQUIRE(elevated.has_value());
        CHECK(elevated->audit_detail == "elevated_session_oidc_setting_blocked");

        auto plain = config::write_refusal(key, session(auth::Role::user));
        REQUIRE(plain.has_value());
        CHECK(plain->audit_detail == "admin_role_required_oidc_setting_blocked");

        for (const auto& s :
             {session(auth::Role::admin, "supervised"), session(auth::Role::admin, "", "svc-a")}) {
            auto token = config::write_refusal(key, s);
            REQUIRE(token.has_value());
            CHECK(token->audit_detail == "token_session_oidc_setting_blocked");
        }
    }
}

TEST_CASE("config_write: a route-owned key is refused for everyone, with no audit detail",
          "[server][config_write]") {
    const auto keys = keys_of(ConfigWriteClass::RouteOwned);
    REQUIRE_FALSE(keys.empty());
    for (const auto& key : keys) {
        INFO(key);
        auto r = config::write_refusal(key, session(auth::Role::admin));
        REQUIRE(r.has_value());
        CHECK(r->kind == config::WriteRefusal::Kind::RouteOwned);
        CHECK(r->audit_detail.empty());
        CHECK_FALSE(r->message.empty());
        CHECK_FALSE(r->remediation.empty());
    }
}

TEST_CASE("config_write: an unknown key has no class and is left to the caller's key check",
          "[server][config_write]") {
    CHECK_FALSE(config::write_refusal("not_a_setting", session(auth::Role::user)).has_value());
    CHECK_FALSE(RuntimeConfigStore::is_allowed_key("not_a_setting"));
}

TEST_CASE("config_write: every allowed key is classified, so the caller rule cannot skip one",
          "[server][config_write]") {
    for (const auto& k : RuntimeConfigStore::allowed_keys()) {
        INFO(k);
        CHECK(RuntimeConfigStore::write_class(k).has_value());
    }
}

TEST_CASE("config_write: integer keys must be non-negative whole numbers; other keys pass through",
          "[server][config_write]") {
    for (const char* key : {"heartbeat_timeout", "response_retention_days", "audit_retention_days",
                            "guardian_event_retention_days"}) {
        INFO(key);
        CHECK(config::validate_value(key, "0").value() == 0);
        CHECK(config::validate_value(key, "90").value() == 90);
        for (const char* bad : {"", "-1", "abc", "9x", " 9", "1.5", "99999999999"}) {
            INFO(bad);
            auto r = config::validate_value(key, bad);
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error() == "value must be a non-negative integer");
        }
    }
    // A non-integer key is not parsed here (the store validates the rest).
    CHECK(config::validate_value("log_level", "abc").value() == 0);
    CHECK(config::validate_value("plugin_signing_required", "-1").value() == 0);
}

TEST_CASE("config_write: a secret key's value is never in the audit detail or the response",
          "[server][config_write]") {
    for (const auto& key : RuntimeConfigStore::allowed_keys()) {
        INFO(key);
        const auto detail = config::success_audit_detail(key, "hunter2");
        const auto body = config::applied_json(key, "hunter2");
        CHECK(body["key"] == key);
        CHECK(body["applied"] == true);
        if (RuntimeConfigStore::is_secret_key(key)) {
            CHECK(detail.find("hunter2") == std::string::npos);
            CHECK_FALSE(body.contains("value"));
        } else {
            CHECK(detail == "value=hunter2");
            CHECK(body["value"] == "hunter2");
        }
    }
}

TEST_CASE("config_write: with no store the view is a fault, never an empty configuration",
          "[server][config_write]") {
    config::Backing none{};
    CHECK_FALSE(config::store_ready(none));
    CHECK_FALSE(config::build_config_view(none).has_value());
}
