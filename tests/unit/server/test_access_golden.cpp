/**
 * @file test_access_golden.cpp
 * @brief Golden files for the Access fragments: one rendered HTML file per cell under
 *        tests/unit/server/golden/access/. A renderer edit shows up as a reviewable diff.
 *
 * The fixture accounts are constructed from the Users handler's own shapes (not a capture);
 * there is no timestamp in these fragments, so no normalisation is needed.
 *
 * Regeneration: `YUZU_UPDATE_GOLDEN=1 <server-tests> "[access][golden]"` rewrites the files
 * and the run FAILS on purpose; re-run without the variable to confirm they now match.
 */

#include "access_render.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

using namespace yuzu::server;
using namespace yuzu::server::access;

namespace {

std::filesystem::path golden_dir() {
    return std::filesystem::path(YUZU_TEST_GOLDEN_DIR) / "access";
}

void check_golden(const std::string& cell, const std::string& actual) {
    const auto path = golden_dir() / (cell + ".html");
    if (std::getenv("YUZU_UPDATE_GOLDEN") != nullptr) {
        std::error_code ec;
        std::filesystem::create_directories(golden_dir(), ec);
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        REQUIRE(out.good());
        out << actual;
        out.close();
        REQUIRE(out.good());
        FAIL_CHECK("YUZU_UPDATE_GOLDEN=1: (re)wrote " << path.string()
                   << " -- re-run WITHOUT YUZU_UPDATE_GOLDEN to verify it now matches.");
        return;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in.good()) {
        FAIL_CHECK("golden file missing: " << path.string()
                   << " -- run with YUZU_UPDATE_GOLDEN=1 to create it, then re-run to verify.");
        return;
    }
    const std::string expected((std::istreambuf_iterator<char>(in)),
                               std::istreambuf_iterator<char>());
    INFO("golden mismatch for '" << cell << "' (" << path.string() << ")");
    CHECK(expected == actual);
}

auth::UserEntry user(std::string name, std::string source, auth::Role role) {
    auth::UserEntry u;
    u.username = std::move(name);
    u.identity_source = std::move(source);
    u.role = role;
    return u;
}

} // namespace

TEST_CASE("access golden: users list populated", "[access][golden]") {
    check_golden("users-list__populated",
                 render_users_list(UsersList{{user("alice", "local", auth::Role::admin),
                                              user("bob", "local", auth::Role::user),
                                              user("oidc:https://idp.example/realm#7f3a", "oidc",
                                                   auth::Role::user)},
                                             "alice"}));
}

TEST_CASE("access golden: users list unavailable", "[access][golden]") {
    check_golden("users-list__unavailable", render_users_list(Unavailable{}));
}

TEST_CASE("access golden: user detail local", "[access][golden]") {
    check_golden("user-detail__local",
                 render_user_detail(UserDetail{user("bob", "local", auth::Role::user), false}));
}

TEST_CASE("access golden: user detail not found", "[access][golden]") {
    check_golden("user-detail__not-found", render_user_detail(NotFound{}));
}

TEST_CASE("access golden: roles list", "[access][golden]") {
    RbacRole admin;
    admin.name = "Administrator";
    admin.description = "Full access to all operations";
    admin.is_system = true;
    RbacRole custom;
    custom.name = "Auditor.eu";
    custom.description = "Read audit evidence";
    check_golden("roles-list__populated", render_roles_list(RolesList{{admin, custom}}));
    check_golden("roles-list__unavailable", render_roles_list(Unavailable{}));
}

TEST_CASE("access golden: role permissions", "[access][golden]") {
    auto perm = [](const char* type, const char* op, const char* effect) {
        Permission p;
        p.securable_type = type;
        p.operation = op;
        p.effect = effect;
        return p;
    };
    check_golden("role-permissions__populated",
                 render_role_permissions(RolePerms{"Operator",
                                                   {perm("Tag", "Read", "allow"),
                                                    perm("Tag", "Write", "allow"),
                                                    perm("Execution", "Execute", "allow"),
                                                    perm("Tag", "Delete", "deny")}}));
    check_golden("role-permissions__empty", render_role_permissions(RolePerms{"Empty", {}}));
    check_golden("role-permissions__not-found", render_role_permissions(NotFound{}));
    check_golden("role-permissions__unavailable",
                 render_role_permissions(Unavailable{}, "/fragments/access/roles/permissions?role=Operator"));
}
