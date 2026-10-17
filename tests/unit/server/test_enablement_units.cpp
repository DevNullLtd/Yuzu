/**
 * test_enablement_units.cpp — invariants of the switchable-unit overlay
 * (enablement_units.hpp, ADR-3006) over the REAL capability catalogue,
 * composed from all 28 fragments exactly as test_capability_catalogue.cpp does
 * (test_real_capability_registry.hpp omits two fragments, #5131).
 *
 * Pure: constexpr tables only, no I/O, no clock, no process.
 */

#include "capability_decls/core_dispatch_capabilities.hpp"
#include "capability_decls/plugin_action_catalogue_a.hpp"
#include "capability_decls/plugin_action_catalogue_b.hpp"
#include "capability_decls/plugin_action_catalogue_c.hpp"
#include "capability_decls/plugin_action_catalogue_content_dist.hpp"
#include "capability_decls/plugin_action_catalogue_d.hpp"
#include "capability_decls/plugin_action_catalogue_disk_actions.hpp"
#include "capability_decls/plugin_action_catalogue_filesystem_posture.hpp"
#include "capability_decls/plugin_action_catalogue_power_health.hpp"
#include "capability_decls/plugin_action_catalogue_autoruns.hpp"
#include "capability_decls/plugin_action_catalogue_app_usage.hpp"
#include "capability_decls/plugin_action_catalogue_execution_artifacts.hpp"
#include "capability_decls/plugin_action_catalogue_windows_optional_features.hpp"
#include "capability_decls/plugin_action_catalogue_peripherals.hpp"
#include "capability_decls/plugin_action_catalogue_printing.hpp"
#include "capability_decls/plugin_action_catalogue_browser_policy.hpp"
#include "capability_decls/plugin_action_catalogue_update_source_trust.hpp"
#include "capability_decls/plugin_action_catalogue_app_control.hpp"
#include "capability_decls/plugin_action_catalogue_firmware_posture.hpp"
#include "capability_decls/plugin_action_catalogue_runtimes.hpp"
#include "capability_decls/plugin_action_catalogue_platform_security.hpp"
#include "capability_decls/plugin_action_catalogue_browser_inventory.hpp"
#include "capability_decls/plugin_action_catalogue_local_security_policy.hpp"
#include "capability_decls/plugin_action_catalogue_privacy_permissions.hpp"
#include "capability_decls/plugin_action_catalogue_system_hardening.hpp"
#include "capability_decls/plugin_action_catalogue_pkg_inventory.hpp"
#include "capability_decls/plugin_action_catalogue_mgmt_posture.hpp"
#include "capability_decls/plugin_action_catalogue_shares.hpp"
#include "dispatch_confined_arms.hpp"
#include "enablement_resolver.hpp"
#include "enablement_units.hpp"

#include <yuzu/agent/plugin_loader.hpp> // kReservedPluginNames (cross-check)
#include <yuzu/protective_actions.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::enablement;

namespace {

// The 28 real fragments, spelled once. A macro because the registry-style
// constructor only takes a brace-enclosed initializer_list.
#define YUZU_REAL_FRAGMENTS \
    capdecls::plugin_action_catalogue_a(),\
    capdecls::plugin_action_catalogue_b(),\
    capdecls::plugin_action_catalogue_c(),\
    capdecls::plugin_action_catalogue_content_dist(),\
    capdecls::plugin_action_catalogue_d(),\
    capdecls::plugin_action_catalogue_disk_actions(),\
    capdecls::plugin_action_catalogue_filesystem_posture(),\
    capdecls::plugin_action_catalogue_power_health(),\
    capdecls::plugin_action_catalogue_autoruns(),\
    capdecls::plugin_action_catalogue_app_usage(),\
    capdecls::plugin_action_catalogue_execution_artifacts(),\
    capdecls::plugin_action_catalogue_windows_optional_features(),\
    capdecls::plugin_action_catalogue_peripherals(),\
    capdecls::plugin_action_catalogue_printing(),\
    capdecls::plugin_action_catalogue_browser_policy(),\
    capdecls::plugin_action_catalogue_update_source_trust(),\
    capdecls::plugin_action_catalogue_app_control(),\
    capdecls::plugin_action_catalogue_firmware_posture(),\
    capdecls::plugin_action_catalogue_runtimes(),\
    capdecls::plugin_action_catalogue_platform_security(),\
    capdecls::plugin_action_catalogue_browser_inventory(),\
    capdecls::plugin_action_catalogue_local_security_policy(),\
    capdecls::plugin_action_catalogue_privacy_permissions(),\
    capdecls::plugin_action_catalogue_system_hardening(),\
    capdecls::plugin_action_catalogue_pkg_inventory(),\
    capdecls::plugin_action_catalogue_mgmt_posture(),\
    capdecls::plugin_action_catalogue_shares(),\
    capdecls::core_dispatch_capabilities()

UnitOverlay real_overlay() {
    auto r = build_unit_overlay({YUZU_REAL_FRAGMENTS}, kProtectivePredicate);
    REQUIRE(r.has_value());
    return std::move(*r);
}

std::vector<std::string> off_names(const Resolution& r) {
    std::vector<std::string> out;
    for (const auto& o : r.off)
        out.push_back(o.unit);
    return out;
}

bool contains(const std::vector<std::string>& v, std::string_view s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

Resolution resolve_all_for(const UnitOverlay& ov, std::string unit) {
    auto rule = make_rule("r", {std::move(unit)}, "__all__", Provenance::Operator, ov, {});
    REQUIRE(rule.has_value());
    std::vector<Rule> rules;
    rules.push_back(std::move(*rule));
    auto res = resolve(rules, ov, "linux", [](std::string_view) { return std::string{}; });
    REQUIRE(res.has_value());
    return std::move(*res);
}

// A predicate that is not the quarantine one: every `zz` action is protective.
bool zz_is_protective(std::string_view plugin, std::string_view) { return plugin == "zz"; }

constexpr CommandCapability cap(std::string_view plugin, std::string_view action) {
    return CommandCapability{.plugin = plugin, .action = action,
                             .execute_gate = ExecuteGate::None};
}

} // namespace

TEST_CASE("enablement units: the real catalogue builds with no missing or stale os row",
          "[enablement][catalogue]") {
    auto r = build_unit_overlay({YUZU_REAL_FRAGMENTS}, kProtectivePredicate);
    INFO(std::string(r.has_value() ? "" : r.error()));
    REQUIRE(r.has_value());
}

TEST_CASE("enablement units: the injected predicate is the canonical protective one",
          "[enablement][catalogue]") {
    // The real catalogue cannot tell the canonical set from the narrow quarantine one
    // (its only addition, __guard__.push_rules, is already a reserved name), so the
    // choice is pinned by identity. A swap back to the quarantine predicate fails here.
    CHECK(kProtectivePredicate == &yuzu::protective::is_protective_action);
    CHECK(kProtectivePredicate("__guard__", "push_rules"));
    CHECK(kProtectivePredicate("quarantine", "whitelist"));
    CHECK_FALSE(kProtectivePredicate("tar", "fleet_snapshot"));
}

TEST_CASE("enablement units: every catalogue pair follows the canonical protective predicate",
          "[enablement][catalogue]") {
    // Compared per pair against yuzu::protective::is_protective_action rather than a
    // hand-spelled list, so widening the canonical set turns the new action into a
    // non-unit here without an edit, and a unit that ought to be protective fails.
    const auto ov = real_overlay();
    std::size_t pairs = 0;
    for (const auto& src : std::initializer_list<std::span<const CommandCapability>>{
             YUZU_REAL_FRAGMENTS}) {
        for (const auto& row : src) {
            ++pairs;
            const std::string name = std::string(row.plugin) + "." + std::string(row.action);
            const bool non_unit = yuzu::protective::is_protective_action(row.plugin, row.action) ||
                                  plugin_config::is_reserved_plugin_name(row.plugin);
            INFO(name);
            CHECK((ov.find_non_unit(name) != nullptr) == non_unit);
            CHECK((ov.find(name) != nullptr) == !non_unit);
            // The agent's own reserved list agrees with the server's.
            CHECK(yuzu::agent::is_reserved_plugin_name(row.plugin) ==
                  plugin_config::is_reserved_plugin_name(row.plugin));
        }
    }
    CHECK(pairs > 100);
}

TEST_CASE("enablement units: the non-unit set is exactly the protective and reserved rows",
          "[enablement][catalogue]") {
    const auto ov = real_overlay();
    using R = NonUnitReason;
    const std::vector<std::pair<std::string, R>> expected{
        {"__guard__", R::ReservedName},
        {"__guard__.push_rules", R::ReservedName},
        {"__sync__", R::ReservedName},
        {"__sync__.now", R::ReservedName},
        {"quarantine", R::Protective},
        {"quarantine.quarantine", R::Protective},
        {"quarantine.status", R::Protective},
        {"quarantine.unquarantine", R::Protective},
        {"quarantine.whitelist", R::Protective},
    };
    REQUIRE(ov.non_units.size() == expected.size());
    for (const auto& [name, reason] : expected) {
        INFO(name);
        const auto* n = ov.find_non_unit(name);
        REQUIRE(n != nullptr);
        CHECK(n->reason == reason);
        CHECK(ov.find(name) == nullptr);
    }
}

TEST_CASE("enablement units: system_reserved rows with D3 work are ordinary units",
          "[enablement][catalogue]") {
    const auto ov = real_overlay();
    for (const auto* name : {"tar.fleet_snapshot", "asset_tags.sync"}) {
        INFO(name);
        const auto* u = ov.find(name);
        REQUIRE(u != nullptr);
        CHECK(u->kind == UnitKind::Action);
    }
    CHECK(ov.find("tar") != nullptr);
    CHECK(ov.find("asset_tags") != nullptr);
    CHECK(ov.find("quarantine") == nullptr);

    CHECK(contains(off_names(resolve_all_for(ov, "tar")), "tar.fleet_snapshot"));
    CHECK(contains(off_names(resolve_all_for(ov, "asset_tags")), "asset_tags.sync"));
}

TEST_CASE("enablement units: structural invariants", "[enablement][catalogue]") {
    const auto ov = real_overlay();
    CHECK(std::is_sorted(ov.units.begin(), ov.units.end(),
                         [](const Unit& a, const Unit& b) { return a.name < b.name; }));
    for (std::size_t i = 1; i < ov.units.size(); ++i)
        CHECK(ov.units[i - 1].name != ov.units[i].name);
    for (const auto& u : ov.units) {
        INFO(u.name);
        CHECK(u.os != 0);
        CHECK((u.os & ~kAllOs) == 0);
        if (u.kind == UnitKind::Action) {
            const auto* p = ov.find(u.plugin);
            REQUIRE(p != nullptr);
            CHECK(p->kind == UnitKind::Plugin);
        } else {
            std::uint8_t acc = 0;
            for (const auto* a : ov.actions_of(u.name))
                acc |= a->os;
            CHECK(u.os == acc);
        }
    }
}

TEST_CASE("enablement units: requirement edges", "[enablement][catalogue]") {
    const auto ov = real_overlay();
    const std::vector<std::pair<std::string, std::string>> expected{
        {"app_usage.summary", "tar"}, {"app_usage.last_used", "tar"}};
    CHECK(ov.requirements == expected);
    CHECK(ov.find("app_usage.foreground") != nullptr);
    for (const auto& [u, req] : ov.requirements) {
        CHECK(ov.find(u) != nullptr);
        CHECK(ov.find(req) != nullptr);
    }
}

TEST_CASE("enablement units: a catalogue row with no os row fails the build - naming it",
          "[enablement][catalogue]") {
    static constexpr std::array<CommandCapability, 1> extra{CommandCapability{
        .plugin = "zz", .action = "new", .execute_gate = ExecuteGate::None}};
    auto r = build_unit_overlay({YUZU_REAL_FRAGMENTS, std::span<const CommandCapability>{extra}},
                                kProtectivePredicate);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("zz.new") != std::string::npos);
    CHECK(r.error().find("enablement_units.hpp") != std::string::npos);
}

TEST_CASE("enablement units: a stale os row fails the build - naming it",
          "[enablement][catalogue]") {
    std::vector<UnitOsRow> rows(kUnitOs.begin(), kUnitOs.end());
    rows.push_back({"zz", "gone", kAllOs});
    auto r = build_unit_overlay({YUZU_REAL_FRAGMENTS}, kProtectivePredicate, rows);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("zz.gone") != std::string::npos);
}

TEST_CASE("enablement units: the protective predicate is the caller's and not a hard-coded set",
          "[enablement][catalogue]") {
    const std::array<CommandCapability, 2> frag{cap("zz", "a"), cap("zz", "b")};
    const std::array<UnitOsRow, 2> os{{{"zz", "a", kAllOs}, {"zz", "b", kWin}}};
    const std::span<const CommandCapability> src{frag};

    SECTION("a predicate marking zz protective records actions and plugin as non-units") {
        auto r = build_unit_overlay({src}, &zz_is_protective, os, {});
        REQUIRE(r.has_value());
        CHECK(r->units.empty());
        for (const auto* name : {"zz", "zz.a", "zz.b"}) {
            INFO(name);
            const auto* n = r->find_non_unit(name);
            REQUIRE(n != nullptr);
            CHECK(n->reason == NonUnitReason::Protective);
            CHECK(r->find(name) == nullptr);
        }
    }
    SECTION("the canonical protective predicate leaves the same fragment switchable") {
        auto r = build_unit_overlay({src}, kProtectivePredicate, os, {});
        REQUIRE(r.has_value());
        CHECK(r->non_units.empty());
        for (const auto* name : {"zz", "zz.a", "zz.b"})
            CHECK(r->find(name) != nullptr);
    }
}

TEST_CASE("enablement units: build_unit_overlay refuses malformed inputs - naming them",
          "[enablement][catalogue]") {
    struct Case {
        const char* what;
        std::vector<CommandCapability> rows;
        std::vector<UnitOsRow> os;
        std::vector<RequirementEdge> edges;
        ProtectivePredicate protective;
        std::string needle;
    };
    const auto ok_rows = std::vector<CommandCapability>{cap("zz", "a"), cap("zz", "b")};
    const std::vector<UnitOsRow> ok_os{{"zz", "a", kAllOs}, {"zz", "b", kAllOs}};
    auto pred = kProtectivePredicate;
    const std::vector<Case> cases{
        {"duplicate catalogue pair",
         {cap("zz", "a"), cap("zz", "a")},
         {{"zz", "a", kAllOs}},
         {},
         pred,
         "duplicate catalogue pair: zz.a"},
        {"duplicate os row for an existing pair",
         ok_rows,
         {{"zz", "a", kAllOs}, {"zz", "b", kAllOs}, {"zz", "a", kAllOs}},
         {},
         pred,
         "zz.a"},
        {"edge whose unit end is unknown", ok_rows, ok_os, {{"zz.nope", "zz.a"}}, pred, "zz.nope"},
        {"edge whose required end is unknown", ok_rows, ok_os, {{"zz.a", "zz.nope"}}, pred,
         "zz.nope"},
        {"null protective predicate", ok_rows, ok_os, {}, nullptr, "protective predicate required"},
        {"os row with mask 0",
         ok_rows,
         {{"zz", "a", 0}, {"zz", "b", kAllOs}},
         {},
         pred,
         "zz.a"},
        {"os row with mask 0 on a protective (non-unit) pair",
         ok_rows,
         {{"zz", "a", 0}, {"zz", "b", kAllOs}},
         {},
         &zz_is_protective,
         "zz.a"},
        {"a dotted plugin name would make the unit name ambiguous",
         {cap("z.z", "a")},
         {{"z.z", "a", kAllOs}},
         {},
         pred,
         "not a legal unit name: z.z.a"},
        {"a dotted action name would make the unit name ambiguous",
         {cap("zz", "a.b")},
         {{"zz", "a.b", kAllOs}},
         {},
         pred,
         "not a legal unit name: zz.a.b"},
        {"os row with bits above kAllOs",
         ok_rows,
         {{"zz", "a", kAllOs}, {"zz", "b", static_cast<std::uint8_t>(kWin | 0x80)}},
         {},
         pred,
         "zz.b"},
    };
    for (const auto& c : cases) {
        INFO(c.what);
        auto r = build_unit_overlay({std::span<const CommandCapability>{c.rows}}, c.protective,
                                    c.os, c.edges);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find(c.needle) != std::string::npos);
    }
    // The table's base rows are valid: only the named defect fails each case.
    CHECK(build_unit_overlay({std::span<const CommandCapability>{ok_rows}}, pred, ok_os, {})
              .has_value());
}
