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

TEST_CASE("no-admin audit: the active scope skips a REVOKED principal but never drops a grant "
          "with no roster row (orphan_grant)",
          "[engine_principal][no_admin][pure]") {
    auto in = inputs_with({{"engine", "engine:live", "admin"},
                           {"engine", "engine:revoked", "admin"},
                           {"user", "engine:shadow", "Administrator"},
                           {"engine", "engine:orphan", "Reader"}},
                          {{.name = "Reader"}}, {{"Reader", "Inventory", "Read", "allow"}});
    audit::ActiveScope scope;
    scope.active = {"engine:live"};
    scope.revoked = {"engine:revoked"};
    const auto v = audit::evaluate(in, kSecurables, kOperations, &scope);

    auto reasons_for = [&](const std::string& id) {
        std::vector<std::string> out;
        for (const auto& x : v)
            if (x.principal_id == id)
                out.push_back(x.reason);
        return out;
    };
    CHECK(reasons_for("engine:live") == std::vector<std::string>{"admin_role"});
    CHECK(reasons_for("engine:revoked").empty()); // narrowed out on request
    // No roster row at all: evaluated normally AND flagged, so a roster walk cannot hide it.
    CHECK(reasons_for("engine:shadow") == std::vector<std::string>{"admin_role", "orphan_grant"});
    // A harmless role on an orphan is still reported: the missing principal is the finding.
    CHECK(reasons_for("engine:orphan") == std::vector<std::string>{"orphan_grant"});
    // Without a scope, nothing is an orphan and the revoked principal is audited.
    const auto full = audit::evaluate(in, kSecurables, kOperations);
    for (const auto& x : full)
        CHECK(x.reason != "orphan_grant");
    CHECK(full.size() == 3); // live, revoked, shadow (admin roles); engine:orphan is clean
}

TEST_CASE("no-admin audit: a principal listed as neither active nor revoked is an orphan, not "
          "silently narrowed away",
          "[engine_principal][no_admin][pure]") {
    // The race the narrowing must survive: the roster was read AFTER the grants, so a principal
    // created in between has a grant and no roster row.
    auto in = inputs_with({{"engine", "engine:newborn", "admin"}}, {}, {});
    audit::ActiveScope scope; // empty roster
    const auto v = audit::evaluate(in, kSecurables, kOperations, &scope);
    REQUIRE(v.size() == 2);
    CHECK(v[0].reason == "admin_role");
    CHECK(v[1].reason == "orphan_grant");
    CHECK(v[1].role.empty());
}

TEST_CASE("no-admin audit: the success detail carries a bounded, neutralised sample",
          "[engine_principal][no_admin][pure]") {
    CHECK(audit::audit_detail({}) == "violations=0 scope=all");
    // A run narrowed to active principals says so, so its zero is not read as a full-fleet zero.
    CHECK(audit::audit_detail({}, /*narrowed_to_active=*/true) == "violations=0 scope=active");

    std::vector<audit::Violation> many;
    for (int i = 0; i < 12; ++i)
        many.push_back({"engine:p" + std::to_string(i), "admin", "admin_role"});
    const auto d = audit::audit_detail(many);
    CHECK(d.starts_with("violations=12 scope=all sample=engine:p0:admin_role,"));
    CHECK(d.find("engine:p9:admin_role") != std::string::npos);
    CHECK(d.find("engine:p10") == std::string::npos); // capped at ten

    // CWE-117: a hostile id cannot forge an adjacent audit field or split the line.
    const auto hostile =
        audit::audit_detail({{"engine:x result=success\r\nforged", "r", "admin_role"}});
    CHECK(hostile.find('\r') == std::string::npos);
    CHECK(hostile.find('\n') == std::string::npos);
    CHECK(hostile.find("result=success") == std::string::npos);
}

TEST_CASE("no-admin audit: the audited principal id is cut at a UTF-8 character boundary",
          "[engine_principal][no_admin][pure]") {
    // 98 ASCII bytes then a 3-byte character straddling the 100-byte cap: the cut must back up to
    // 98, never leave a lone lead byte in the audit detail.
    const std::string id = "engine:" + std::string(91, 'a') + "\xE2\x82\xAC" + "tail";
    REQUIRE(id.size() > audit::kAuditIdMax);
    const auto cut = audit::utf8_prefix(id, audit::kAuditIdMax);
    CHECK(cut.size() == 98);
    CHECK(cut.find('\xE2') == std::string_view::npos);
    // At a boundary the full budget is used; a short id is untouched.
    const std::string ascii(150, 'b');
    CHECK(audit::utf8_prefix(ascii, audit::kAuditIdMax).size() == audit::kAuditIdMax);
    CHECK(audit::utf8_prefix("short", audit::kAuditIdMax) == "short");
    // End to end through the audit detail.
    const auto d = audit::audit_detail({{id, "r", "admin_role"}});
    CHECK(d.find('\xE2') == std::string::npos);
}
