#pragma once

// test_execution_owner_engine.hpp -- #5557: engine credentials on the shared execution-owner rig,
// for the service-scoped unrestricted-authority refusal tests on the list gates.
//
// Minting refuses a service-scoped engine token, so the only way to reach the gates with one is
// a CORRUPTED row: mint a valid engine token, then set its stored `scope_service` by direct SQL
// (technique: test_engine_principal_integration.cpp, section 6c). The rig header deliberately
// does not own this setup.
//
// Lifetime: `AuthManager` keeps a raw pointer to the metrics registry, so declare the
// `yuzu::MetricsRegistry` BEFORE the rig in the test body (it is destroyed after it).

#include "engine_principal_store.hpp"
#include "test_execution_owner_scope_rig.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <chrono>
#include <functional>
#include <string>
#include <vector>

namespace yuzu::test {

/// The audit detail the refusal writes for a corrupted engine session, on either gate.
inline constexpr const char* kCorruptedEngineAuditRow =
    "denied|engine principal denied: corrupted scope_service on engine session";

class OwnerEngineCreds {
public:
    OwnerEngineCreds(ExecutionOwnerRig& rig, yuzu::MetricsRegistry& metrics)
        : r_(rig), store_(rig.pool) {
        REQUIRE(store_.is_open());
        rig.auth_mgr.set_metrics_registry(&metrics);
        rig.auth->set_engine_principal_store(&store_);
        rig.api_tokens->set_engine_referent_check(
            [this](const std::string& id) { return store_.get_for_auth(id).status; });
        metrics_ = &metrics;
    }
    ~OwnerEngineCreds() {
        // The rig outlives this and `metrics` outlives the rig, but do not leave a registry
        // pointer in the shared AuthManager that this object installed.
        r_.auth_mgr.set_metrics_registry(nullptr);
        r_.api_tokens->set_engine_referent_check({});
        r_.auth->set_engine_principal_store(nullptr);
    }
    OwnerEngineCreds(const OwnerEngineCreds&) = delete;
    OwnerEngineCreds& operator=(const OwnerEngineCreds&) = delete;

    /// Mint an Active engine `principal` and an MCP-tier ("readonly") engine token for it
    /// (valid on REST, legacy, dashboard and MCP). `role` non-empty assigns that role to the
    /// engine; `corrupt_scope` non-empty then sets the stored `scope_service` of its token.
    std::string mint(const std::string& principal, const std::string& role = {},
                     const std::string& corrupt_scope = {}) {
        REQUIRE(store_.create("Rig Engine", "mina", "execution owner rig", "internal", "admin",
                              principal)
                    .has_value());
        const auto expires = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count() +
                             3600;
        auto token = r_.api_tokens->create_token("engine-token", principal, expires, "",
                                                 "readonly", "engine");
        REQUIRE(token.has_value());
        if (!role.empty())
            REQUIRE(r_.rbac.assign_role({"engine", principal, role}).has_value());
        if (!corrupt_scope.empty())
            corrupt_scope_service(principal, corrupt_scope);
        return *token;
    }

    /// The counter series' value (creates it at 0 when absent).
    double refused(const char* gate, const char* site) {
        return metrics_
            ->counter("yuzu_server_authz_service_scope_unrestricted_refused_total",
                      {{"gate", gate}, {"site", site}})
            .value();
    }
    /// Sum of the four closed series: "nothing was refused" is exactly 0.
    double refused_total() {
        double t = 0;
        for (const char* gate : {"fleet_read", "list_read"})
            for (const char* site : {"engine_entry", "postcondition"})
                t += refused(gate, site);
        return t;
    }

private:
    /// The token store lives in its own database (`api_tokens.dsn()`), not the rig's, so this
    /// opens its own side connection to it. Exactly one token row must change.
    void corrupt_scope_service(const std::string& principal, const std::string& scope) {
        server::pg::PgConn c{PQconnectdb(r_.api_tokens.dsn().c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        auto res = server::pg::exec_params(
            c.get(),
            "UPDATE api_token_store.api_tokens SET scope_service = $1 WHERE principal_id = $2",
            std::vector<std::string>{scope, principal});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
        REQUIRE(std::string(PQcmdTuples(res.get())) == "1");
    }

    ExecutionOwnerRig& r_;
    server::EnginePrincipalStore store_;
    yuzu::MetricsRegistry* metrics_{nullptr};
};

/// What one execution LIST surface answered: the HTTP status, the raw body and the execution ids
/// it listed (empty unless it answered 200).
struct EngineListResult {
    int status{0};
    std::string body;
    std::vector<std::string> ids;
};

/// The corrupted-engine cases for ONE execution list surface, RBAC on or off. `list(token)` is the surface's
/// list route as `token`. The LEGIT engine runs first as the control (RBAC on: 200 and every
/// seeded id; RBAC off: the engine-is-RBAC-only refusal as today), so a 403 for a corrupted row
/// proves the entry refusal and not a broken rig. A refusal is told from the ordinary deny by
/// the audit detail and the counter, never by status alone.
inline void
check_engine_fleet_read_scenario(ExecutionOwnerRig& r, OwnerEngineCreds& e, bool rbac_on,
                                 const std::function<EngineListResult(const std::string&)>& list) {
    r.rbac.set_rbac_enabled(rbac_on);
    const auto ctl = e.mint("engine:ctl", "ExecutionReader5557");
    const auto bad = e.mint("engine:bad", "ExecutionReader5557", "A");
    const auto bad_no_grant = e.mint("engine:badnogrant", {}, "A");
    auto corrupted_rows = [&] {
        const auto rows = r.audit("auth.fleet_read_required");
        return std::count(rows.begin(), rows.end(), std::string(kCorruptedEngineAuditRow));
    };

    const auto control = list(ctl);
    if (rbac_on) {
        CHECK(control.status == 200);
        CHECK(control.ids == r.all_seeded_ids());
    } else {
        CHECK(control.status == 403);
        CHECK(control.ids.empty());
    }
    CHECK(e.refused_total() == 0.0);
    CHECK(corrupted_rows() == 0);

    int expected = 0;
    for (const auto& token : {bad, bad_no_grant}) {
        const auto got = list(token);
        ++expected;
        INFO("refusal " << expected << ", rbac_on=" << rbac_on);
        CHECK(got.status == 403);
        CHECK(got.ids.empty());
        // No `permission` field (no grant would admit this caller) and none of the fleet data.
        CHECK(got.body.find("\"permission\"") == std::string::npos);
        for (const auto& id : r.all_seeded_ids())
            CHECK(got.body.find(id) == std::string::npos);
        CHECK(corrupted_rows() == expected);
        CHECK(e.refused("fleet_read", "engine_entry") == static_cast<double>(expected));
        CHECK(e.refused_total() == static_cast<double>(expected));
    }
    // The control credential is unaffected by the refusals.
    CHECK(list(ctl).status == control.status);
}

} // namespace yuzu::test
