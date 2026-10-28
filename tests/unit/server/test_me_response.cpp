/**
 * test_me_response.cpp - the shared GET /api/v1/me + GET /api/me + MCP get_me builder.
 *
 * Pure: the RBAC read is injected through RbacView::read_roles, so the principal
 * namespace choice and every degrade arm run without Postgres.
 */
#include "me_response.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <expected>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;
using nlohmann::json;
namespace chr = std::chrono;

namespace {

auth::Session human(auth::Role role = auth::Role::user, std::string name = "alice") {
    auth::Session s;
    s.username = std::move(name);
    s.role = role;
    return s;
}

auth::Session engine(std::string name = "engine:indexer") {
    auth::Session s;
    s.username = std::move(name);
    s.role = auth::Role::user;
    s.principal_kind = "engine";
    s.auth_source = "engine_token";
    return s;
}

struct Recorder {
    std::vector<std::pair<std::string, std::string>> calls;
    std::expected<std::vector<std::string>, std::string> answer{std::vector<std::string>{}};

    me_response::RbacView view(bool enabled = true) {
        me_response::RbacView v;
        v.enabled = enabled;
        v.read_roles = [this](std::string_view type, std::string_view id)
            -> std::expected<std::vector<std::string>, std::string> {
            calls.emplace_back(std::string(type), std::string(id));
            return answer;
        };
        return v;
    }
};

json build(const auth::Session& s, const me_response::RbacView& v) {
    return json::parse(me_response::build_me_body(s, v));
}

} // namespace

TEST_CASE("me_response: human admin with RBAC off keeps every legacy key", "[server][me_response]") {
    const auto j = build(human(auth::Role::admin), {});
    CHECK(j["username"] == "alice");
    CHECK(j["display_name"] == "alice"); // falls back to username
    CHECK(j["role"] == "admin");
    CHECK(j["rbac_enabled"] == false);
    CHECK(j["rbac_role"] == "Administrator");
    CHECK(j["effective_role"] == "admin");
    CHECK(j["elevated"] == false);
    CHECK_FALSE(j.contains("elevated_until"));
    CHECK(j["can_access_settings"] == true);
    // New keys, with their documented defaults.
    CHECK(j["principal_kind"] == "human");
    CHECK(j["auth_source"] == "local");
    CHECK(j["mcp_tier"] == "");
    CHECK(j["scope_service"] == "");
    CHECK(j["rbac_roles"].is_array());
    CHECK(j["rbac_roles"].empty());
    CHECK(j["rbac_roles_resolved"] == true);
}

TEST_CASE("me_response: display_name is reported when set", "[server][me_response]") {
    auto s = human();
    s.display_name = "Alice A";
    CHECK(build(s, {})["display_name"] == "Alice A");
}

TEST_CASE("me_response: human with RBAC on and no roles keeps the legacy fallback",
          "[server][me_response]") {
    Recorder r;
    SECTION("user session -> Viewer") {
        const auto j = build(human(auth::Role::user), r.view());
        CHECK(j["rbac_enabled"] == true);
        CHECK(j["rbac_role"] == "Viewer");
        CHECK(j["rbac_roles"].empty());
        CHECK(j["rbac_roles_resolved"] == true);
    }
    SECTION("admin session -> Administrator") {
        const auto j = build(human(auth::Role::admin), r.view());
        CHECK(j["rbac_role"] == "Administrator");
        CHECK(j["rbac_roles_resolved"] == true);
    }
}

TEST_CASE("me_response: human with direct roles reports them; rbac_role is the first",
          "[server][me_response]") {
    Recorder r;
    r.answer = std::vector<std::string>{"Operator", "Viewer"};
    const auto j = build(human(), r.view());
    CHECK(j["rbac_role"] == "Operator");
    CHECK(j["rbac_roles"] == json::array({"Operator", "Viewer"}));
    CHECK(j["rbac_roles_resolved"] == true);
}

TEST_CASE("me_response: a failed checked read reports unresolved and invents no role",
          "[server][me_response]") {
    Recorder r;
    r.answer = std::unexpected(std::string("pool acquire timeout"));
    SECTION("human") {
        const auto j = build(human(auth::Role::admin), r.view());
        CHECK(j["rbac_enabled"] == true);
        CHECK(j["rbac_roles_resolved"] == false);
        CHECK_FALSE(j.contains("rbac_role"));
        CHECK_FALSE(j.contains("rbac_roles"));
        // The rest of the self-description is unaffected by the RBAC fault.
        CHECK(j["role"] == "admin");
        CHECK(j["effective_role"] == "admin");
    }
    SECTION("engine") {
        const auto j = build(engine(), r.view());
        CHECK(j["rbac_roles_resolved"] == false);
        CHECK_FALSE(j.contains("rbac_role"));
        CHECK_FALSE(j.contains("rbac_roles"));
    }
}

TEST_CASE("me_response: RBAC enabled but no roles reader is unresolved, never empty",
          "[server][me_response]") {
    me_response::RbacView v;
    v.enabled = true; // read_roles deliberately unset
    const auto j = build(human(), v);
    CHECK(j["rbac_roles_resolved"] == false);
    CHECK_FALSE(j.contains("rbac_role"));
    CHECK_FALSE(j.contains("rbac_roles"));
}

TEST_CASE("me_response: an engine principal never gets a fabricated role", "[server][me_response]") {
    Recorder r;
    SECTION("RBAC off omits rbac_role and does not read the store") {
        const auto j = build(engine(), r.view(/*enabled=*/false));
        CHECK(j["principal_kind"] == "engine");
        CHECK(j["auth_source"] == "engine_token");
        CHECK(j["rbac_enabled"] == false);
        CHECK_FALSE(j.contains("rbac_role"));
        CHECK(j["rbac_roles"].is_array());
        CHECK(j["rbac_roles"].empty());
        CHECK(j["rbac_roles_resolved"] == true);
        CHECK(r.calls.empty());
    }
    SECTION("RBAC on with no engine grant omits rbac_role (never Viewer)") {
        const auto j = build(engine(), r.view());
        CHECK(j["rbac_enabled"] == true);
        CHECK_FALSE(j.contains("rbac_role"));
        CHECK(j["rbac_roles"].empty());
        CHECK(j["rbac_roles_resolved"] == true);
    }
    SECTION("an engine session on a legacy admin role is still not Administrator") {
        auto s = engine();
        s.role = auth::Role::admin;
        const auto j = build(s, r.view());
        CHECK_FALSE(j.contains("rbac_role"));
    }
    SECTION("RBAC on with an engine grant reports it") {
        r.answer = std::vector<std::string>{"Operator"};
        const auto j = build(engine(), r.view());
        CHECK(j["rbac_role"] == "Operator");
        CHECK(j["rbac_roles"] == json::array({"Operator"}));
        CHECK(j["rbac_roles_resolved"] == true);
    }
}

TEST_CASE("me_response: the principal namespace comes from the session kind, never the username",
          "[server][me_response]") {
    Recorder r;
    SECTION("an engine is read under principal type engine, keyed by the full engine:<slug>") {
        (void)build(engine("engine:indexer"), r.view());
        REQUIRE(r.calls.size() == 1);
        CHECK(r.calls[0].first == "engine");
        CHECK(r.calls[0].second == "engine:indexer");
    }
    SECTION("a human whose username starts with engine: is still looked up as a user") {
        (void)build(human(auth::Role::user, "engine:lookalike"), r.view());
        REQUIRE(r.calls.size() == 1);
        CHECK(r.calls[0].first == "user");
        CHECK(r.calls[0].second == "engine:lookalike");
    }
    SECTION("an ordinary human is a user lookup") {
        (void)build(human(), r.view());
        REQUIRE(r.calls.size() == 1);
        CHECK(r.calls[0].first == "user");
        CHECK(r.calls[0].second == "alice");
    }
    SECTION("principal_kind alone marks an engine") {
        auto s = human(auth::Role::user, "engine:solo");
        s.principal_kind = "engine"; // auth_source left at its default
        (void)build(s, r.view());
        REQUIRE(r.calls.size() == 1);
        CHECK(r.calls[0].first == "engine");
    }
    SECTION("auth_source alone marks an engine (the converse)") {
        auto s = human(auth::Role::user, "engine:solo");
        s.auth_source = "engine_token"; // principal_kind left at its default ("human")
        const auto j = build(s, r.view());
        REQUIRE(r.calls.size() == 1);
        CHECK(r.calls[0].first == "engine");
        CHECK(r.calls[0].second == "engine:solo");
        CHECK(j["principal_kind"] == "engine"); // the classification applied, not the stored field
        CHECK_FALSE(j.contains("rbac_role"));  // no grant: never a fabricated Viewer
    }
}

TEST_CASE("me_response: engine RBAC matrix records (type, id) on every read",
          "[server][me_response]") {
    // A reader that counts calls and answers per call number, so the matrix can include a
    // grant revoked between two requests.
    struct Counting {
        std::vector<std::pair<std::string, std::string>> calls;
        std::vector<std::expected<std::vector<std::string>, std::string>> answers;
        me_response::RbacView view(bool enabled) {
            me_response::RbacView v;
            v.enabled = enabled;
            v.read_roles = [this](std::string_view type, std::string_view id)
                -> std::expected<std::vector<std::string>, std::string> {
                calls.emplace_back(std::string(type), std::string(id));
                const std::size_t n = calls.size() - 1;
                return n < answers.size() ? answers[n] : std::vector<std::string>{};
            };
            return v;
        }
    };
    const auto session = engine("engine:matrix");
    Counting c;

    SECTION("RBAC off: no read, no rbac_role") {
        const auto j = build(session, c.view(false));
        CHECK(c.calls.empty());
        CHECK_FALSE(j.contains("rbac_role"));
        CHECK(j["rbac_roles_resolved"] == true);
    }
    SECTION("RBAC on, no grant: read once, no rbac_role") {
        const auto j = build(session, c.view(true));
        REQUIRE(c.calls.size() == 1);
        CHECK(c.calls[0] == std::pair<std::string, std::string>{"engine", "engine:matrix"});
        CHECK_FALSE(j.contains("rbac_role"));
        CHECK(j["rbac_roles"].empty());
    }
    SECTION("RBAC on, grant: rbac_role is the grant") {
        c.answers = {std::vector<std::string>{"EngineReader"}};
        const auto j = build(session, c.view(true));
        REQUIRE(c.calls.size() == 1);
        CHECK(j["rbac_role"] == "EngineReader");
    }
    SECTION("a grant revoked between two calls: the second call omits rbac_role") {
        c.answers = {std::vector<std::string>{"EngineReader"}, std::vector<std::string>{}};
        const auto v = c.view(true);
        const auto first = build(session, v);
        const auto second = build(session, v);
        REQUIRE(c.calls.size() == 2);
        for (const auto& call : c.calls)
            CHECK(call == std::pair<std::string, std::string>{"engine", "engine:matrix"});
        CHECK(first["rbac_role"] == "EngineReader");
        CHECK_FALSE(second.contains("rbac_role"));
        CHECK(second["rbac_roles"].empty());
        CHECK(second["rbac_roles_resolved"] == true);
    }
}

TEST_CASE("me_response: invalid UTF-8 in username / display_name is replaced, never thrown",
          "[server][me_response]") {
    auto s = human(auth::Role::user, std::string("ab\xC3\x28"));
    s.display_name = std::string("\xFF\xFE");
    std::string body;
    REQUIRE_NOTHROW(body = me_response::build_me_body(s, me_response::RbacView{}));
    const auto j = json::parse(body); // the output itself is valid JSON/UTF-8
    // U+FFFD is EF BF BD. "ab\xC3(" -> "ab" + U+FFFD + "(" ; "\xFF\xFE" -> two U+FFFD.
    CHECK(j["username"].get<std::string>() == "ab\xEF\xBF\xBD(");
    CHECK(j["display_name"].get<std::string>() == "\xEF\xBF\xBD\xEF\xBF\xBD");
    // The sibling overload and the shared dump helper agree.
    CHECK(me_response::build_me_body(s, static_cast<RbacStore*>(nullptr)) == body);
    REQUIRE_NOTHROW((void)me_response::dump_me_json(me_response::build_me_json(s, {})));
}

TEST_CASE("me_response: valid UTF-8 is byte-identical to a plain dump", "[server][me_response]") {
    auto s = human(auth::Role::user, "alice");
    s.display_name = "Zo\xC3\xAB \xE2\x9C\x93"; // "Zoe" with diaeresis, check mark
    const auto j = me_response::build_me_json(s, {});
    CHECK(me_response::dump_me_json(j) == j.dump());
}

TEST_CASE("me_response: session self-description keys per persona", "[server][me_response]") {
    SECTION("MCP tier token") {
        auto s = human(auth::Role::admin);
        s.auth_source = "mcp_token";
        s.mcp_tier = "operator";
        const auto j = build(s, {});
        CHECK(j["mcp_tier"] == "operator");
        CHECK(j["auth_source"] == "mcp_token");
        CHECK(j["can_access_settings"] == false);
        CHECK(j["effective_role"] == "admin");
    }
    SECTION("service-scoped token") {
        auto s = human();
        s.token_scope_service = "finance";
        const auto j = build(s, {});
        CHECK(j["scope_service"] == "finance");
        CHECK(j["can_access_settings"] == false);
    }
    SECTION("elevated user") {
        auto s = human(auth::Role::user);
        s.steady_elevated_until = chr::steady_clock::now() + chr::hours(1);
        s.elevated_until = chr::system_clock::now() + chr::hours(1);
        const auto j = build(s, {});
        CHECK(j["role"] == "user");
        CHECK(j["effective_role"] == "admin");
        CHECK(j["elevated"] == true);
        REQUIRE(j.contains("elevated_until"));
        CHECK(j["elevated_until"].get<std::string>().size() == 20); // YYYY-MM-DDTHH:MM:SSZ
        CHECK(j["can_access_settings"] == true);
    }
}

TEST_CASE("me_response: a null store is RBAC off and the string overload matches the view overload",
          "[server][me_response]") {
    CHECK_FALSE(me_response::rbac_view(nullptr).enabled);
    for (const auto& s : {human(), human(auth::Role::admin), engine()}) {
        CHECK(me_response::build_me_body(s, static_cast<RbacStore*>(nullptr)) ==
              me_response::build_me_body(s, me_response::RbacView{}));
    }
}
