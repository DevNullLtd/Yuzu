// sg10: the schedule/outbox arming check judges the parameter-escalated securable
// (windows_updates.patch_connectivity + `targets` -> Infrastructure:Read), through the same
// `effective_securable` rule the send chokepoint uses. A scheduled or queued command fires as the
// arming principal's re-resolved caller; the arming check stops an operator holding only
// SoftwareDeployment:Read at fire and at delivery, before any send.

#include "capability_decls/plugin_action_catalogue_d.hpp"
#include "command_capability.hpp"
#include "pg/pg_pool.hpp"
#include "rbac_store.hpp"
#include "schedule_arming_check.hpp"
#include "schedule_arming_params.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <stdexcept>
#include <string>
#include <unordered_map>

using yuzu::server::CommandCapabilityRegistry;
using yuzu::server::Permission;
using yuzu::server::PrincipalRole;
using yuzu::server::RbacRole;
using yuzu::server::RbacStore;

namespace {
yuzu::test::PgTestTemplate arm_param_rbac_tpl{"armparamrbac", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    RbacStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("arm param rbac template: store failed to migrate");
}};
} // namespace

TEST_CASE("arming: patch_connectivity targets need Infrastructure:Read at arming",
          "[server][routes][pg][sg10][schedule][outbox]") {
    CommandCapabilityRegistry registry{yuzu::server::capdecls::plugin_action_catalogue_d()};
    YUZU_REQUIRE_PG_DB_TPL(db_fx, arm_param_rbac_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db_fx.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    RbacStore rbac{pool};
    REQUIRE(rbac.is_open());
    rbac.set_rbac_enabled(true);
    REQUIRE(rbac.create_role(RbacRole{.name = "sd_only", .description = "t"}).has_value());
    REQUIRE(rbac.set_permission(Permission{"sd_only", "SoftwareDeployment", "Read", "allow"})
                .has_value());
    REQUIRE(rbac.assign_role(PrincipalRole{"user", "sd", "sd_only"}).has_value());
    REQUIRE(rbac.create_role(RbacRole{.name = "sd_infra", .description = "t"}).has_value());
    REQUIRE(rbac.set_permission(Permission{"sd_infra", "SoftwareDeployment", "Read", "allow"})
                .has_value());
    REQUIRE(rbac.set_permission(Permission{"sd_infra", "Infrastructure", "Read", "allow"})
                .has_value());
    REQUIRE(rbac.assign_role(PrincipalRole{"user", "both", "sd_infra"}).has_value());

    using P = std::unordered_map<std::string, std::string>;
    const P none, empty{{"targets", ""}}, supplied{{"targets", "https://wsus.example.test/"}},
        blank{{"targets", "  "}};
    const auto arm = [&](const char* who, const P& p) {
        return yuzu::server::schedule_arming_permitted(registry, &rbac, who, "windows_updates",
                                                       "patch_connectivity", p);
    };
    // Default targets: SoftwareDeployment:Read is enough (an empty value is the default branch).
    CHECK(arm("sd", none));
    CHECK(arm("sd", empty));
    // Supplied targets (whitespace counts as supplied, like the send gate): refused without
    // Infrastructure:Read, admitted with it.
    CHECK_FALSE(arm("sd", supplied));
    CHECK_FALSE(arm("sd", blank));
    CHECK(arm("both", supplied));
    CHECK(arm("both", none));
    // The stored-text path: a non-string `targets` decodes to a supplied value.
    const auto listy = yuzu::server::decode_arming_parameters(R"({"targets":["h"]})");
    REQUIRE(listy.has_value());
    CHECK_FALSE(arm("sd", *listy));
    CHECK(arm("both", *listy));
    // UP-1: a NUL-suffixed key is never armed, whatever grants the principal holds.
    const P evil{{std::string("targets\0x", 9), "10.0.0.1"}};
    CHECK_FALSE(arm("sd", evil));
    CHECK_FALSE(arm("both", evil));
}
