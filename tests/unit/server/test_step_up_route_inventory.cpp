/**
 * test_step_up_route_inventory.cpp — the step-up policy table
 * (server/core/src/step_up_policy.hpp) against the routes the server REGISTERS.
 *
 * A mutating route nobody classified is the defect this file exists to fail on: the chokepoint
 * (step_up_gate.cpp) keys on the exact registered pattern, so a route absent from the table is
 * never evaluated and nothing else notices. Three layers, each with a different blind spot:
 *
 * L1 (compiled, exact keys). `register_every_constructible_owner()` constructs the route owners
 *    that can be built with null/empty dependencies, registers each on a `TestRouteSink`, and reads
 *    `registered_routes()`. The strings it sees are the COMPILED pattern strings, the very bytes
 *    httplib stores and reports as `Request::matched_route` and the table must equal. A source scan
 *    cannot see this: a table row typed from source can differ by one escape and never match in
 *    production while a lexical test says "covered". Blind spot: an owner registers a route only
 *    behind a non-null store (`if (store)`) shows up here only if this harness wires that store, and
 *    several owners are not constructible without a database. L1 therefore sees a SUBSET.
 * L3 (lexical, honestly). `route_inventory_scan.hpp` regex-scans the route sources for
 *    `sink.`/`svr.`/`web_server_->` calls. It sees registrations no harness can construct, but only
 *    as source text (see that header for what it cannot see). It checks that every scanned
 *    mutating route has a row, that every row is accounted for by L1 or L3 (no stale row after a
 *    rename or removal), and that L1 never sees a route the scan misses (a receiver spelling the scan
 *    does not know).
 * L4 is not a test: server.cpp refuses to start when the boot sweep finds a mutating registration
 *    without a row (`step_up_unclassified_registrations`). The refusal decision is exercised here
 *    against a synthetic unclassified route and a real `HttplibRouteSink`.
 *
 * No Postgres, no sockets. A change that adds a mutating route and does not classify it fails
 * here; the fix is a row in step_up_policy.hpp, never an entry in this file.
 */

#include "../../../server/core/src/step_up_gate.hpp"
#include "../../../server/core/src/step_up_policy.hpp"
#include "route_inventory_scan.hpp"
#include "test_route_sink.hpp"

#include "../../../server/core/src/approval_routes.hpp"
#include "../../../server/core/src/auth_routes.hpp"
#include "../../../server/core/src/ca_routes.hpp"
#include "../../../server/core/src/command_routes.hpp"
#include "../../../server/core/src/config_routes.hpp"
#include "../../../server/core/src/custom_properties_routes.hpp"
#include "../../../server/core/src/dashboard_api_routes.hpp"
#include "../../../server/core/src/dashboard_routes.hpp"
#include "../../../server/core/src/data_inventory_routes.hpp"
#include "../../../server/core/src/deployment_routes.hpp"
#include "../../../server/core/src/diagnostics_routes.hpp"
#include "../../../server/core/src/discovery_routes.hpp"
#include "../../../server/core/src/execution_routes.hpp"
#include "../../../server/core/src/file_retrieval_routes.hpp"
#include "../../../server/core/src/guardian_routes.hpp"
#include "../../../server/core/src/hardware_routes.hpp"
#include "../../../server/core/src/http_route_sink.hpp"
#include "../../../server/core/src/instruction_fragment_routes.hpp"
#include "../../../server/core/src/instruction_routes.hpp"
#include "../../../server/core/src/kek_routes.hpp"
#include "../../../server/core/src/mcp_disabled_routes.hpp"
#include "../../../server/core/src/mcp_server.hpp"
#include "../../../server/core/src/notification_routes.hpp"
#include "../../../server/core/src/nvd_routes.hpp"
#include "../../../server/core/src/offload_routes.hpp"
#include "../../../server/core/src/plugin_config_routes.hpp"
#include "../../../server/core/src/policy_admin_routes.hpp"
#include "../../../server/core/src/preflight_routes.hpp"
#include "../../../server/core/src/rest_api_v1.hpp"
#include "../../../server/core/src/result_set_routes.hpp"
#include "../../../server/core/src/schedule_routes.hpp"
#include "../../../server/core/src/scim_routes.hpp"
#include "../../../server/core/src/settings_routes.hpp"
#include "../../../server/core/src/sle_routes.hpp"
#include "../../../server/core/src/tag_routes.hpp"
#include "../../../server/core/src/tar_tree_routes.hpp"
#include "../../../server/core/src/webhook_routes.hpp"
#include "../../../server/core/src/workflow_routes.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <map>
#include <optional>
#include <memory>
#include <set>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace yuzu::server;
namespace scan = yuzu::server::test::route_scan;

namespace {

using Key = std::pair<std::string, std::string>; // (method, pattern)

bool is_mutating(const std::string& method) {
    return method == "POST" || method == "PUT" || method == "DELETE" || method == "PATCH";
}

/// One owner's registrations on a TestRouteSink, mutating verbs only.
struct OwnerRoutes {
    std::string owner;
    std::vector<Key> routes;
    std::string error; // non-empty when registration threw (an unbound REQUIRED dependency)
};

template <class Register>
OwnerRoutes register_owner(std::string name, Register&& reg) {
    // `reg` constructs the owner and registers it; the handlers capture raw `this`/store pointers
    // and are never invoked, so the owner may be destroyed before the sink.
    yuzu::server::test::TestRouteSink sink;
    OwnerRoutes out{std::move(name), {}, {}};
    try {
        reg(sink);
    } catch (const std::exception& e) {
        out.error = e.what();
    }
    for (auto& k : sink.registered_routes())
        if (is_mutating(k.first))
            out.routes.push_back(std::move(k));
    return out;
}

/// Every route owner that can be constructed with null/empty dependencies, registered once.
/// Memoised: registration is deterministic and the owners are throwaway.
const std::vector<OwnerRoutes>& register_every_constructible_owner() {
    static const std::vector<OwnerRoutes> cached = [] {
        std::vector<OwnerRoutes> v;

        // -- Deps-struct owners: a value-initialised Deps registers its routes (handlers capture the
        //    empty functors and are never invoked here).
        v.push_back(register_owner("approval", [](auto& s) {
            approval::register_approval_routes(s, approval::Deps{});
        }));
        v.push_back(register_owner("command", [](auto& s) {
            command::register_command_routes(s, command::Deps{});
        }));
        v.push_back(register_owner("config", [](auto& s) {
            config::register_config_routes(s, config::Deps{});
        }));
        v.push_back(register_owner("custom_properties", [](auto& s) {
            custom_properties::register_custom_properties_routes(s, custom_properties::Deps{});
        }));
        v.push_back(register_owner("dashboard_api", [](auto& s) {
            dashboard_api::Deps deps;
            deps.visible_agents_json_fn = [](const std::string&) {
                return nlohmann::json::array();
            };
            register_dashboard_api_routes(s, std::move(deps));
        }));
        v.push_back(register_owner("data_inventory", [](auto& s) {
            data_inventory::register_data_inventory_routes(s, data_inventory::Deps{});
        }));
        v.push_back(register_owner("diagnostics", [](auto& s) {
            diagnostics::register_diagnostics_routes(s, diagnostics::Deps{});
        }));
        v.push_back(register_owner("execution", [](auto& s) {
            execution::register_execution_routes(s, execution::Deps{});
        }));
        v.push_back(register_owner("file_retrieval", [](auto& s) {
            yuzu::server::Deps deps;
            deps.deny_service_scoped_fn = [](const httplib::Request&, httplib::Response&,
                                             const std::string&, const std::string&,
                                             const std::string&, const std::string&) {
                return true;
            };
            register_file_retrieval_routes(s, std::move(deps));
        }));
        v.push_back(register_owner("instruction_fragment", [](auto& s) {
            instruction_fragment::register_instruction_fragment_routes(
                s, instruction_fragment::Deps{});
        }));
        v.push_back(register_owner("instruction", [](auto& s) {
            instruction::register_instruction_routes(s, instruction::Deps{});
        }));
        v.push_back(register_owner("nvd", [](auto& s) {
            nvd::register_nvd_routes(s, nvd::Deps{});
        }));
        v.push_back(register_owner("plugin_config", [](auto& s) {
            plugin_config::register_plugin_config_routes(s, plugin_config::Deps{});
        }));
        v.push_back(register_owner("result_set", [](auto& s) {
            result_set::register_result_set_routes(s, result_set::Deps{});
        }));
        v.push_back(register_owner("schedule", [](auto& s) {
            schedule::register_schedule_routes(s, schedule::Deps{});
        }));
        v.push_back(register_owner("tag", [](auto& s) {
            tag::register_tag_routes(s, tag::Deps{});
        }));
        // -- Class owners: every callback `{}` and every store null. An owner that registers a
        //    route only behind a non-null store contributes less here; L3 covers the remainder.
        Config cfg{};
        cfg.https_enabled = false;
        auth::AuthManager auth_mgr{};
        std::shared_mutex oidc_mu;
        std::unique_ptr<oidc::OidcProvider> oidc_provider;
        auth::AutoApproveEngine auto_approve;

        v.push_back(register_owner("auth", [&](auto& s) {
            AuthRoutes r(cfg, auth_mgr, /*rbac_store=*/nullptr, /*api_token_store=*/nullptr,
                         /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr,
                         /*tag_store=*/nullptr, /*analytics_store=*/nullptr, oidc_mu,
                         oidc_provider);
            r.register_routes(s);
        }));
        v.push_back(register_owner("ca", [](auto& s) {
            CaRoutes r;
            r.register_routes(s, {}, {}, {}, /*ca_store=*/nullptr, /*publish_crl_fn=*/{});
        }));
        v.push_back(register_owner("dashboard", [](auto& s) {
            DashboardRoutes r;
            r.register_routes(s, {}, {}, {}, nullptr, nullptr, nullptr, nullptr, nullptr, {}, {},
                              {}, {});
        }));
        v.push_back(register_owner("deployment", [](auto& s) {
            DeploymentRoutes r;
            r.register_routes(s, {}, {}, {}, {}, {}, {}, /*preflight_store=*/nullptr,
                              /*deploy_store=*/nullptr);
        }));
        v.push_back(register_owner("discovery", [](auto& s) {
            DiscoveryRoutes r;
            r.register_routes(s, {}, {}, {}, nullptr, nullptr, nullptr, nullptr);
        }));
        v.push_back(register_owner("guardian", [](auto& s) {
            GuardianRoutes r;
            r.register_routes(s, {}, {}, {}, {}, /*store=*/nullptr, /*baseline_store=*/nullptr,
                              {}, {});
        }));
        v.push_back(register_owner("hardware", [](auto& s) {
            HardwareRoutes r;
            r.register_routes(s, HardwareRoutes::Deps{});
        }));
        v.push_back(register_owner("kek", [](auto& s) {
            KekRoutes r;
            r.register_routes(s, {}, {}, KekOps{});
        }));
        v.push_back(register_owner("notification", [](auto& s) {
            NotificationRoutes r;
            r.register_routes(s, {}, {}, {}, /*notification_store=*/nullptr);
        }));
        v.push_back(register_owner("offload", [](auto& s) {
            OffloadRoutes r;
            r.register_routes(s, {}, {}, {}, /*offload_store=*/nullptr);
        }));
        v.push_back(register_owner("policy_admin", [](auto& s) {
            PolicyAdminRoutes r;
            r.register_routes(s, {}, {}, {}, {}, /*policy_store=*/nullptr);
        }));
        v.push_back(register_owner("preflight", [](auto& s) {
            PreflightRoutes r;
            r.register_routes(s, {}, {}, {}, {}, {}, {}, {}, {}, /*run_store=*/nullptr);
        }));
        v.push_back(register_owner("rest_api_v1", [](auto& s) {
            RestApiV1 r;
            RestApiV1::AuthFn auth_fn = [](const httplib::Request&,
                                           httplib::Response&) -> std::optional<auth::Session> {
                return std::nullopt;
            };
            RestApiV1::PermFn perm_fn = [](const httplib::Request&, httplib::Response&,
                                           const std::string&, const std::string&) {
                return true;
            };
            RestApiV1::AuditFn audit_fn = [](const httplib::Request&, const std::string&,
                                             const std::string&, const std::string&,
                                             const std::string&, const std::string&) {
                return true;
            };
            r.register_routes(s, auth_fn, perm_fn, audit_fn, nullptr, nullptr, nullptr, nullptr,
                              nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
        }));
        v.push_back(register_owner("scim", [&](auto& s) {
            ScimRoutes r;
            r.register_routes(s, /*scim_store=*/nullptr, &auth_mgr, /*audit_store=*/nullptr);
        }));
        v.push_back(register_owner("settings", [&](auto& s) {
            SettingsRoutes r;
            r.register_routes(s, {}, {}, {}, {}, cfg, auth_mgr, auto_approve, nullptr, nullptr,
                              nullptr, nullptr, nullptr, nullptr, /*gateway_enabled=*/false, {},
                              {}, oidc_mu, oidc_provider);
        }));
        v.push_back(register_owner("sle", [](auto& s) {
            SleRoutes r;
            r.register_routes(s, {}, {}, {});
        }));
        v.push_back(register_owner("tar_tree", [](auto& s) {
            TarTreeRoutes r;
            r.register_routes(s, {}, {}, {}, {}, {}, {}, {}, {}, {});
        }));
        v.push_back(register_owner("webhook", [](auto& s) {
            WebhookRoutes r;
            r.register_routes(s, {}, {}, {}, {}, /*webhook_store=*/nullptr);
        }));
        v.push_back(register_owner("workflow", [](auto& s) {
            WorkflowRoutes r;
            r.register_routes(s, WorkflowRoutes::Deps{});
        }));

        v.push_back(register_owner("mcp", [](auto& s) {
            const bool read_only_mode = false;
            const bool mcp_disabled = false;
            mcp::McpServer r;
            r.register_routes(s, {}, {}, {}, {}, nullptr, nullptr, nullptr, nullptr, nullptr,
                              nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, read_only_mode,
                              mcp_disabled);
        }));
        v.push_back(register_owner("mcp_disabled", [](auto& s) {
            mcp_disabled::register_mcp_disabled_routes(s);
        }));
        return v;
    }();
    return cached;
}

/// Every (method, pattern) the L1 harness saw, over every owner.
std::set<Key> l1_registered() {
    std::set<Key> out;
    for (const auto& o : register_every_constructible_owner())
        out.insert(o.routes.begin(), o.routes.end());
    return out;
}

/// Every mutating (method, pattern) the lexical scan found.
std::set<Key> l3_scanned() {
    std::set<Key> out;
    for (const auto& r : scan::discover_mutating_routes())
        out.emplace(r.method, r.raw_path);
    return out;
}

std::string join(const std::vector<std::string>& v) {
    std::string s;
    for (const auto& x : v)
        s += "  " + x + "\n";
    return s;
}

} // namespace

// -- L1 ----------------------------------------------------------------------------------------

TEST_CASE("step-up route inventory L1: the harness registers a meaningful subset",
          "[stepup][inventory][l1]") {
    const auto& owners = register_every_constructible_owner();
    std::size_t total = 0;
    std::string per_owner;
    for (const auto& o : owners) {
        total += o.routes.size();
        per_owner += "  " + o.owner + ": " + std::to_string(o.routes.size()) + "\n";
    }
    std::string failed;
    for (const auto& o : owners) {
        if (!o.error.empty())
            failed += "  " + o.owner + ": " + o.error + "\n";
    }
    INFO("mutating registrations per owner:\n" << per_owner);
    INFO("owners whose registration threw (bind the REQUIRED dependency in the harness):\n"
         << failed);
    CHECK(failed.empty());
    // A floor that catches a wholesale collapse (an owner now gated behind a store this harness does
    // not wire registers nothing), measured with margin, not pinned to the exact count.
    CHECK(total >= 100);
    CHECK(l1_registered().size() >= 100);
}

TEST_CASE("step-up route inventory L1: every compiled mutating registration has a table row",
          "[stepup][inventory][l1]") {
    std::vector<std::string> missing;
    for (const auto& o : register_every_constructible_owner()) {
        for (const auto& [method, pattern] : o.routes) {
            if (step_up_policy_for(method, pattern) == nullptr)
                missing.push_back(o.owner + ": " + method + " " + pattern);
        }
    }
    INFO("Mutating registrations with no row in step_up_policy.hpp (add a row, with a class "
         "reason or a real class; the pattern must equal the registered string byte for byte):\n"
         << join(missing));
    CHECK(missing.empty());
}

TEST_CASE("step-up route inventory L1: each owner registers a pattern exactly once per verb",
          "[stepup][inventory][l1]") {
    // Two registrations of one (method, pattern) on one owner would make the second unreachable in
    // httplib (first match wins) and the table, keyed on the pair, could not describe both.
    for (const auto& o : register_every_constructible_owner()) {
        std::set<Key> seen;
        for (const auto& k : o.routes) {
            INFO(o.owner << ": " << k.first << " " << k.second);
            CHECK(seen.insert(k).second);
        }
    }
}

// -- L3 ----------------------------------------------------------------------------------------

TEST_CASE("step-up route inventory L3 (lexical): every scanned mutating route has a table row",
          "[stepup][inventory][l3]") {
    std::vector<std::string> missing;
    for (const auto& r : scan::discover_mutating_routes()) {
        if (step_up_policy_for(r.method, r.raw_path) == nullptr)
            missing.push_back(r.file + ":" + std::to_string(r.line) + " " + r.method + " " +
                              r.raw_path);
    }
    INFO("Scanned mutating registrations with no row in step_up_policy.hpp:\n" << join(missing));
    CHECK(missing.empty());
}

TEST_CASE("step-up route inventory L3 (lexical): L1 never sees a route the scan misses",
          "[stepup][inventory][l3]") {
    // The scan is the broader, lexical net. A compiled registration it cannot find means a receiver
    // spelling, a computed pattern or a helper the scan does not know about, i.e. a blind spot the
    // L3 checks above silently inherit.
    const auto scanned = l3_scanned();
    std::vector<std::string> unseen;
    for (const auto& k : l1_registered()) {
        if (!scanned.contains(k))
            unseen.push_back(k.first + " " + k.second);
    }
    INFO("Compiled mutating registrations the lexical scan does not find:\n" << join(unseen));
    CHECK(unseen.empty());
    CHECK(scanned.size() >= l1_registered().size());
}

TEST_CASE("step-up route inventory: no server source registers a route directly on web_server_",
          "[stepup][inventory][l3]") {
    // Every mutating route must register through HttpRouteSink so HttplibRouteSink records it for
    // the boot sweep. A direct `web_server_->Post(...)` would be served but never swept. Plain
    // substring searches: a regex pass over the whole tree costs seconds for a fixed four strings.
    std::size_t files_checked = 0;
    for (const auto& [file, text] : scan::read_all_cpp_files(YUZU_SERVER_SRC_DIR)) {
        ++files_checked;
        for (const char* verb : {"Post", "Put", "Delete", "Patch"}) {
            INFO(file << ": web_server_->" << verb << "(");
            CHECK(text.find(std::string("web_server_->") + verb + "(") == std::string::npos);
        }
    }
    CHECK(files_checked > 50);
}

// -- stale rows and exemption classes ----------------------------------------------------------

TEST_CASE("step-up route inventory: every table row names a route that is registered",
          "[stepup][inventory][l3]") {
    // A rename or removal that leaves its row behind would leave a dead row, and a row at the OLD
    // pattern is exactly what lets the renamed route go unclassified in a table nobody re-reads.
    std::set<Key> registered = l1_registered();
    for (const auto& k : l3_scanned())
        registered.insert(k);
    std::vector<std::string> stale;
    for (const auto& e : kStepUpPolicy) {
        if (!registered.contains({std::string(e.method), std::string(e.pattern)}))
            stale.push_back(std::string(e.method) + " " + std::string(e.pattern));
    }
    INFO("Table rows that no registration matches (remove or re-key them):\n" << join(stale));
    CHECK(stale.empty());
}

TEST_CASE("step-up route inventory: each exemption class holds only registered, ungated routes",
          "[stepup][inventory]") {
    std::set<Key> registered = l1_registered();
    for (const auto& k : l3_scanned())
        registered.insert(k);

    // One section per DISTINCT reason, generated from the table, so a class that loses its last
    // route (or gains a route that is registered nowhere) fails by name.
    std::map<std::string_view, std::vector<const StepUpPolicyEntry*>> by_reason;
    for (const auto& e : kStepUpPolicy) {
        if (e.cls == StepUpClass::kExempt)
            by_reason[e.reason].push_back(&e);
    }
    REQUIRE_FALSE(by_reason.empty());
    for (const auto& [reason, rows] : by_reason) {
        DYNAMIC_SECTION("exempt class: " << reason) {
            CHECK_FALSE(rows.empty());
            for (const auto* e : rows) {
                INFO(std::string(e->method) << " " << std::string(e->pattern));
                CHECK(registered.contains({std::string(e->method), std::string(e->pattern)}));
                CHECK(e->action_label.empty()); // an exempt row is never audited as a refusal
                CHECK(e->cls == StepUpClass::kExempt);
            }
        }
    }
}

TEST_CASE("step-up route inventory: every kRequired row is registered (its handler gate is real)",
          "[stepup][inventory]") {
    std::set<Key> registered = l1_registered();
    for (const auto& k : l3_scanned())
        registered.insert(k);
    for (const auto& e : kStepUpPolicy) {
        if (e.cls != StepUpClass::kRequired && e.cls != StepUpClass::kOwnGate)
            continue;
        INFO(std::string(e.method) << " " << std::string(e.pattern));
        CHECK(registered.contains({std::string(e.method), std::string(e.pattern)}));
    }
}

// -- L4: the boot sweep's refusal decision -----------------------------------------------------

TEST_CASE("step-up boot sweep: a synthetic unclassified mutating route is named and refuses the boot",
          "[stepup][inventory][boot]") {
    httplib::Server svr; // never listens: no port, no thread (#438)
    RouteInventory::instance().forget(&svr);
    HttplibRouteSink sink(svr);
    const httplib::Server::Handler noop = [](const httplib::Request&, httplib::Response&) {};

    SECTION("a classified route and read-only verbs pass") {
        sink.Post("/api/v1/tokens", noop);                    // kRequired
        sink.Post("/login", noop);                            // kExempt
        sink.Get("/yuzu_test_read_only_unclassified", noop);  // not a table verb
        sink.Options("/yuzu_test_options_unclassified", noop);
        CHECK(step_up_unclassified_registrations(&svr).empty());
    }
    SECTION("an unclassified POST, PUT, DELETE and PATCH are each reported with their verb") {
        sink.Post("/yuzu_test_unclassified", noop);
        sink.Put("/yuzu_test_unclassified", noop);
        sink.Delete("/yuzu_test_unclassified", noop);
        sink.Patch("/yuzu_test_unclassified", noop);
        sink.Post("/api/v1/tokens", noop);
        const auto missing = step_up_unclassified_registrations(&svr);
        REQUIRE(missing.size() == 4);
        const std::set<std::string> got(missing.begin(), missing.end());
        CHECK(got.contains("POST /yuzu_test_unclassified"));
        CHECK(got.contains("PUT /yuzu_test_unclassified"));
        CHECK(got.contains("DELETE /yuzu_test_unclassified"));
        CHECK(got.contains("PATCH /yuzu_test_unclassified"));
    }
    SECTION("a classified pattern under the wrong verb is unclassified") {
        sink.Put("/api/v1/tokens", noop); // only POST is registered in the table
        const auto missing = step_up_unclassified_registrations(&svr);
        REQUIRE(missing.size() == 1);
        CHECK(missing[0] == "PUT /api/v1/tokens");
    }
    SECTION("another server's registrations are not this server's") {
        httplib::Server other;
        RouteInventory::instance().forget(&other);
        HttplibRouteSink other_sink(other);
        other_sink.Post("/yuzu_test_on_the_other_server", noop);
        CHECK(step_up_unclassified_registrations(&svr).empty());
        CHECK(step_up_unclassified_registrations(&other).size() == 1);
        RouteInventory::instance().forget(&other);
    }
    SECTION("the pure overload reports exactly what it is given") {
        const std::vector<RouteInventory::Route> routes = {
            {"POST", "/api/v1/tokens"}, {"POST", "/yuzu_test_pure_unclassified"}, {"GET", "/x"}};
        const auto missing = step_up_unclassified_registrations(routes);
        REQUIRE(missing.size() == 1);
        CHECK(missing[0] == "POST /yuzu_test_pure_unclassified");
    }
    RouteInventory::instance().forget(&svr);
}
