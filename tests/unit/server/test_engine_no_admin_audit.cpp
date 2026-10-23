/**
 * test_engine_no_admin_audit.cpp - the pure half of the shared engine-principal
 * "no admin" auditor (engine_no_admin_audit.hpp). No Postgres: `evaluate` and
 * `audit_detail` are functions over vectors. The degraded-read behaviour of the
 * REST route and the MCP tool (read_inputs failing closed) is covered by the
 * [pg] cases in test_engine_principal_lifecycle.cpp and test_mcp_server.cpp.
 */

#include "engine_no_admin_audit.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
namespace audit = yuzu::server::engine_no_admin_audit;

namespace {

// A 2 x 2 grid keeps every case readable.
const std::vector<std::string> kSecurables{"Inventory", "Security"};
const std::vector<std::string> kOperations{"Read", "Write"};

std::vector<Permission> full_grid(const std::string& role, const std::string& effect = "allow") {
    std::vector<Permission> out;
    for (const auto& s : kSecurables)
        for (const auto& o : kOperations)
            out.push_back({role, s, o, effect});
    return out;
}

audit::Inputs inputs_with(std::vector<PrincipalRole> grants, std::vector<RbacRole> roles,
                          std::vector<Permission> perms) {
    audit::Inputs in;
    in.grants = std::move(grants);
    in.roles = std::move(roles);
    in.role_permissions = std::move(perms);
    return in;
}

} // namespace

TEST_CASE("no-admin audit: a clean principal produces no violation",
          "[engine_principal][no_admin][pure]") {
    auto in = inputs_with({{"engine", "engine:clean", "Reader"}}, {{.name = "Reader"}},
                          {{"Reader", "Inventory", "Read", "allow"}});
    CHECK(audit::evaluate(in, kSecurables, kOperations).empty());
}

TEST_CASE("no-admin audit: the admin and Administrator role names are reported",
          "[engine_principal][no_admin][pure]") {
    auto in = inputs_with({{"engine", "engine:a", "admin"}, {"engine", "engine:b", "Administrator"}},
                          {}, {});
    const auto v = audit::evaluate(in, kSecurables, kOperations);
    REQUIRE(v.size() == 2);
    CHECK(v[0].principal_id == "engine:a");
    CHECK(v[0].role == "admin");
    CHECK(v[0].reason == "admin_role");
    CHECK(v[1].principal_id == "engine:b");
    CHECK(v[1].reason == "admin_role");
}

TEST_CASE("no-admin audit: a built-in (is_system) role is reported as system_role",
          "[engine_principal][no_admin][pure]") {
    auto in = inputs_with({{"engine", "engine:s", "Operator"}},
                          {{.name = "Operator", .is_system = true}}, {});
    const auto v = audit::evaluate(in, kSecurables, kOperations);
    REQUIRE(v.size() == 1);
    CHECK(v[0].role == "Operator");
    CHECK(v[0].reason == "system_role");
}

TEST_CASE("no-admin audit: a custom role covering the whole grid is reported BY ROLE NAME",
          "[engine_principal][no_admin][pure]") {
    auto in = inputs_with({{"engine", "engine:w", "EverythingRole"}}, {{.name = "EverythingRole"}},
                          full_grid("EverythingRole"));
    const auto v = audit::evaluate(in, kSecurables, kOperations);
    REQUIRE(v.size() == 1);
    CHECK(v[0].principal_id == "engine:w");
    CHECK(v[0].role == "EverythingRole"); // not "": triage can see which role
    CHECK(v[0].reason == "wildcard_grant");
}

TEST_CASE("no-admin audit: two roles that together cover the grid are one union wildcard_grant",
          "[engine_principal][no_admin][pure]") {
    auto perms = std::vector<Permission>{{"Half1", "Inventory", "Read", "allow"},
                                         {"Half1", "Inventory", "Write", "allow"},
                                         {"Half2", "Security", "Read", "allow"},
                                         {"Half2", "Security", "Write", "allow"}};
    auto in = inputs_with({{"engine", "engine:u", "Half1"}, {"engine", "engine:u", "Half2"}},
                          {{.name = "Half1"}, {.name = "Half2"}}, std::move(perms));
    const auto v = audit::evaluate(in, kSecurables, kOperations);
    REQUIRE(v.size() == 1);
    CHECK(v[0].role.empty());
    CHECK(v[0].reason == "wildcard_grant");
}

TEST_CASE("no-admin audit: a role granting every pair but one is NOT reported (documented limit)",
          "[engine_principal][no_admin][pure]") {
    auto perms = full_grid("AlmostAll");
    perms.pop_back(); // drop Security:Write
    auto in = inputs_with({{"engine", "engine:almost", "AlmostAll"}}, {{.name = "AlmostAll"}},
                          std::move(perms));
    CHECK(audit::evaluate(in, kSecurables, kOperations).empty());
}

TEST_CASE("no-admin audit: deny rows grant nothing, and are ignored rather than subtracted",
          "[engine_principal][no_admin][pure]") {
    SECTION("an all-deny role is not a wildcard") {
        auto in = inputs_with({{"engine", "engine:d", "Denier"}}, {{.name = "Denier"}},
                              full_grid("Denier", "deny"));
        CHECK(audit::evaluate(in, kSecurables, kOperations).empty());
    }
    SECTION("a full allow grid with one extra deny row is still reported (over-report is safe)") {
        auto perms = full_grid("Mixed");
        perms.push_back({"Mixed", "Security", "Write", "deny"});
        auto in = inputs_with({{"engine", "engine:m", "Mixed"}}, {{.name = "Mixed"}},
                              std::move(perms));
        const auto v = audit::evaluate(in, kSecurables, kOperations);
        REQUIRE(v.size() == 1);
        CHECK(v[0].role == "Mixed");
    }
}

TEST_CASE("no-admin audit: a grant outside the current grid does not count toward coverage",
          "[engine_principal][no_admin][pure]") {
    // The grid grew (an upgrade seeded a new securable): the same role now misses a pair.
    auto in = inputs_with({{"engine", "engine:g", "OldFull"}}, {{.name = "OldFull"}},
                          full_grid("OldFull"));
    auto bigger = kSecurables;
    bigger.push_back("NewSecurable");
    CHECK(audit::evaluate(in, bigger, kOperations).empty());
}

TEST_CASE("no-admin audit: a shadow ('user', 'engine:x') grant row is caught",
          "[engine_principal][no_admin][pure]") {
    auto in = inputs_with({{"user", "engine:shadow", "Administrator"}}, {}, {});
    const auto v = audit::evaluate(in, kSecurables, kOperations);
    REQUIRE(v.size() == 1);
    CHECK(v[0].principal_id == "engine:shadow");
    CHECK(v[0].reason == "admin_role");
}

TEST_CASE("no-admin audit: human principals are not audited",
          "[engine_principal][no_admin][pure]") {
    auto in = inputs_with({{"user", "alice", "Administrator"}, {"group", "ops", "Administrator"}},
                          {}, {});
    CHECK(audit::evaluate(in, kSecurables, kOperations).empty());
}

TEST_CASE("no-admin audit: an empty grid is never a wildcard", "[engine_principal][no_admin][pure]") {
    auto in = inputs_with({{"engine", "engine:e", "Anything"}}, {{.name = "Anything"}}, {});
    CHECK(audit::evaluate(in, {}, {}).empty());
}

TEST_CASE("no-admin audit: only_principals narrows the report to the named ids",
          "[engine_principal][no_admin][pure]") {
    auto in = inputs_with({{"engine", "engine:live", "admin"}, {"engine", "engine:gone", "admin"}},
                          {}, {});
    const std::unordered_set<std::string> active{"engine:live"};
    const auto v = audit::evaluate(in, kSecurables, kOperations, &active);
    REQUIRE(v.size() == 1);
    CHECK(v[0].principal_id == "engine:live");
}

TEST_CASE("no-admin audit: the success detail carries a bounded, neutralised sample",
          "[engine_principal][no_admin][pure]") {
    CHECK(audit::audit_detail({}) == "violations=0");

    std::vector<audit::Violation> many;
    for (int i = 0; i < 12; ++i)
        many.push_back({"engine:p" + std::to_string(i), "admin", "admin_role"});
    const auto d = audit::audit_detail(many);
    CHECK(d.starts_with("violations=12 sample=engine:p0:admin_role,"));
    CHECK(d.find("engine:p9:admin_role") != std::string::npos);
    CHECK(d.find("engine:p10") == std::string::npos); // capped at ten

    // CWE-117: a hostile id cannot forge an adjacent audit field or split the line.
    const auto hostile =
        audit::audit_detail({{"engine:x result=success\r\nforged", "r", "admin_role"}});
    CHECK(hostile.find('\r') == std::string::npos);
    CHECK(hostile.find('\n') == std::string::npos);
    CHECK(hostile.find("result=success") == std::string::npos);
}
