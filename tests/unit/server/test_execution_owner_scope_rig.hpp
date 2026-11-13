#pragma once

// test_execution_owner_scope_rig.hpp -- #5557: the shared REAL-GATE rig for execution
// visibility under service-scoped credentials.
//
// ONE production-shaped `AuthRoutes` (real RbacStore, ManagementGroupStore, ApiTokenStore,
// TagStore and AuditStore; the same wiring `ServerImpl` builds) is the single session source for
// authentication, permission and fleet-read authorization, so an exact-id-set assertion matches
// what production admits. Nothing in here is a fake gate. The hooks it hands out
// (`auth_fn`, `perm_fn`, `fleet_read_fn`, `list_read_fn`, `resolve_session_fn`) are the same
// conversions server.cpp applies around `AuthRoutes`.
//
// The rig is a SEED and a WIRING HARNESS only. It asserts no behaviour; the per-surface
// assertions live in the test files that use it. It deliberately does not use or depend on any
// refusal added to the fleet-read or list-read gates (the engine-session refusal): those tests
// own their own corrupted-credential setup.
//
// Seed (see `ExecutionOwnerRig::ids`):
//   agents   a1, a2 tagged service=A; b1 tagged service=B; z1 untagged
//   people   mina  GLOBAL Execution:Read   (mints every service-scoped credential below)
//            bob   Execution:Read through a management group holding only {a1}
//            carol dispatcher only (no grant)       dan   authenticated, NO Execution:Read
//   scope    service A = {a1,a2}, service B = {b1}, service C = {} (no tagged agent:
//            ADMITTED with an empty scope, which is not the same as a refusal)
//
// Child, starvation and cap fixtures are seeded on demand (`seed_children()` and friends) so a
// test that asserts an exact LIST set is not polluted by rows it did not ask for.
//
// Each distinct database is salted per test by `YUZU_REQUIRE_PG_DB_TPL` (never a fixed name).

#include "audit_store.hpp"
#include "auth_routes.hpp"
#include "execution_tracker.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rbac_store.hpp"
#include "tag_store.hpp"
#include "test_api_token_pg_helper.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "test_response_execution_authz_pg_helper.hpp" // response_execution_authz_tpl only

#include "../test_helpers.hpp"

#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::test {

/// The tracker's per-parent children cap is `kExecutionChildrenCap` (100, a file-local constant
/// in execution_tracker.cpp, so it cannot be read from here). The cap fixture seeds this many
/// NEWER out-of-scope children; the rig smoke test proves the number really exceeds the cap
/// (`ExecutionChildrenResult::truncated`), so a future cap increase fails loudly there.
inline constexpr int kRigChildrenOverCap = 105;

/// Ids of the always-seeded executions. All are dispatched with a fixed epoch so list ordering
/// is deterministic (newest first, ties broken by the tracker).
struct ExecutionOwnerIds {
    std::string in_a;           // carol, a1 success                   -> in scope, foreign dispatcher
    std::string a2;             // carol, a2 success                   -> a2-ONLY: separates {a1} from {a1,a2}
    std::string mixed;          // carol, a1 success + b1 failure SECRET-B-ERR
    std::string run;            // carol, a1 running + a2 success + b1 running (running is not responded)
    std::string foreign;        // carol, z1 success                   -> out of every service
    std::string empty_pending;  // carol, no rows, pending             -> zero status rows, foreign
    std::string minter_out;     // mina,  z1 success                   -> THE LEAK ROW (minter-keyed)
    std::string minter_in_a;    // mina,  a1 success                   -> minter dispatch, in scope
    std::string minter_pending; // mina,  no rows, running             -> minter's pending row
    std::string bob_out;        // bob,   z1 success                   -> non-service owner control
    std::string bob_pending;    // bob,   no rows, running             -> non-service owner control
};

/// Children fixtures. `parent_in` has four children; `parent_minter_out` is hidden to a
/// service-A credential but has one visible child; `parent_cap` has `kRigChildrenOverCap` newer
/// out-of-scope children and ONE older visible child.
struct ExecutionOwnerChildren {
    std::string parent_in, c_in, c_minter_out, c_minter_pending, c_b;
    std::string parent_minter_out, c_x;
    std::string parent_cap, c_old_in;
};

/// Bearer tokens. The un-prefixed set is TIERLESS (valid on REST, legacy and dashboard
/// surfaces); `mcp_*` are the same principals with an explicit `readonly` MCP tier, because
/// production MCP admission refuses every tierless credential with 403 before any tool runs.
struct ExecutionOwnerCreds {
    std::string svc_a, svc_b, svc_none, svc_bob_a; // service-scoped (minters: mina, mina, mina, bob)
    std::string mina, bob, dan;                    // non-service
    std::string mcp_svc_a, mcp_svc_b, mcp_svc_none, mcp_svc_bob_a;
    std::string mcp_mina, mcp_bob, mcp_dan;
};

struct ExecutionOwnerRig {
    using FleetReadFn = std::function<server::authz::FleetReadGate(
        const httplib::Request&, httplib::Response&, const std::string&, const std::string&)>;
    using ListReadFn = std::function<server::ListReadGate(
        const httplib::Request&, httplib::Response&, const std::string&, const std::string&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string&, const std::string&)>;
    using AuthFn = std::function<std::optional<server::auth::Session>(const httplib::Request&,
                                                                      httplib::Response&)>;
    using ResolveSessionFn =
        std::function<std::optional<server::auth::Session>(const httplib::Request&)>;
    using Headers = std::unordered_map<std::string, std::string>;

    /// What a credential's fleet-read admission resolves to. `agents` is nullopt for an
    /// UNFILTERED admit (the whole fleet) and a sorted, possibly empty, list for an engaged scope.
    struct ScopeOutcome {
        bool admitted{false};
        int status{0}; // the response status the gate wrote when it refused (0 when admitted)
        std::optional<std::vector<std::string>> agents;
    };

    server::Config cfg{};
    server::auth::AuthManager auth_mgr{};
    server::pg::PgPool pool;
    server::RbacStore rbac;
    ManagementGroupStorePg mgmt_bundle;
    server::ManagementGroupStore& mgmt = *mgmt_bundle;
    ApiTokenStorePg api_tokens;
    server::ExecutionTracker tracker;
    server::TagStore tags;
    // A real AuditStore on a second pool over the same database (its own schema), wired into
    // `auth`, so a gate's denial row is observable through `audit()`.
    server::pg::PgPool audit_pool;
    server::AuditStore audit_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<server::oidc::OidcProvider> oidc_provider;
    std::unique_ptr<server::AuthRoutes> auth; // THE session source for every hook below

    std::string dsn_;
    std::string bob_group;
    ExecutionOwnerIds ids;
    ExecutionOwnerCreds creds;

    explicit ExecutionOwnerRig(const std::string& dsn)
        : pool{{.conninfo = dsn, .size = 4}}, rbac{pool}, tracker{pool}, tags{pool},
          audit_pool{{.conninfo = dsn, .size = 2}}, audit_store{audit_pool}, dsn_{dsn} {
        REQUIRE(pool.valid());
        REQUIRE(rbac.is_open());
        REQUIRE(tracker.is_open());
        REQUIRE(tags.is_open());
        REQUIRE(audit_store.is_open());
        rbac.set_rbac_enabled(true);

        REQUIRE(rbac.create_role({"ExecutionReader5557", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"ExecutionReader5557", "Execution", "Read", "allow"})
                    .has_value());
        for (const char* user : {"mina", "bob", "carol", "dan"})
            REQUIRE(auth_mgr.upsert_user(user, "correct-horse-battery-staple",
                                         server::auth::Role::user));
        // mina: GLOBAL Execution:Read. bob: the same role through a group holding only a1.
        REQUIRE(rbac.assign_role({"user", "mina", "ExecutionReader5557"}).has_value());
        {
            server::ManagementGroup group;
            group.name = "Bob-5557";
            group.membership_type = "static";
            auto gid = mgmt.create_group(group);
            REQUIRE(gid.has_value());
            bob_group = *gid;
        }
        REQUIRE(mgmt.add_member(bob_group, "a1").has_value());
        REQUIRE(mgmt.assign_role({bob_group, "user", "bob", "ExecutionReader5557"}).has_value());

        REQUIRE(tags.set_tag("a1", "service", "A").has_value());
        REQUIRE(tags.set_tag("a2", "service", "A").has_value());
        REQUIRE(tags.set_tag("b1", "service", "B").has_value());

        auth = std::make_unique<server::AuthRoutes>(cfg, auth_mgr, &rbac, api_tokens.get(),
                                                    &audit_store, &mgmt, &tags,
                                                    /*analytics_store=*/nullptr, oidc_mu,
                                                    oidc_provider);

        creds.svc_a = mint("mina", "A");
        creds.svc_b = mint("mina", "B");
        creds.svc_none = mint("mina", "C");
        creds.svc_bob_a = mint("bob", "A");
        creds.mina = mint("mina");
        creds.bob = mint("bob");
        creds.dan = mint("dan");
        creds.mcp_svc_a = mint("mina", "A", "readonly");
        creds.mcp_svc_b = mint("mina", "B", "readonly");
        creds.mcp_svc_none = mint("mina", "C", "readonly");
        creds.mcp_svc_bob_a = mint("bob", "A", "readonly");
        creds.mcp_mina = mint("mina", {}, "readonly");
        creds.mcp_bob = mint("bob", {}, "readonly");
        creds.mcp_dan = mint("dan", {}, "readonly");

        seed();
    }

    // ── credentials ────────────────────────────────────────────────────────────

    /// Mint an API token for `user` (an hour of life). `service` non-empty makes it
    /// service-scoped; `mcp_tier` non-empty makes it an MCP-tier token.
    std::string mint(const std::string& user, const std::string& service = {},
                     const std::string& mcp_tier = {}) {
        const auto expires = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count() +
                             3600;
        auto t = api_tokens->create_token("owner-rig", user, expires, service, mcp_tier);
        REQUIRE(t.has_value());
        return *t;
    }

    /// A local COOKIE session for `user` (no password was verified; a test seam). Valid on
    /// REST, legacy and dashboard surfaces; refused by production MCP admission.
    std::string cookie_session(const std::string& user,
                               server::auth::Role role = server::auth::Role::user) {
        return auth_mgr.create_local_session_for_test(user, role, /*mfa_verified=*/true);
    }
    static Headers bearer(const std::string& token) {
        return {{"Authorization", "Bearer " + token}};
    }
    static Headers cookie(const std::string& session_token) {
        return {{"Cookie", "yuzu_session=" + session_token}};
    }

    // ── the single real session source ─────────────────────────────────────────

    AuthFn auth_fn() {
        return [this](const httplib::Request& req,
                      httplib::Response& res) -> std::optional<server::auth::Session> {
            return auth->require_auth(req, res);
        };
    }
    PermFn perm_fn() {
        return [this](const httplib::Request& req, httplib::Response& res, const std::string& t,
                      const std::string& o) -> bool {
            return auth->require_permission(req, res, t, o);
        };
    }
    /// server.cpp's `require_fleet_read` conversion, byte for byte: a refusal is the
    /// default-constructed (not admitted) gate; an admit carries `visible_for_query()`.
    FleetReadFn fleet_read_fn() {
        return [this](const httplib::Request& req, httplib::Response& res, const std::string& t,
                      const std::string& o) -> server::authz::FleetReadGate {
            auto result = auth->require_fleet_read(req, res, t, o);
            if (!result)
                return {};
            return {true, result->visible_for_query()};
        };
    }
    ListReadFn list_read_fn() {
        return [this](const httplib::Request& req, httplib::Response& res, const std::string& t,
                      const std::string& o) -> server::ListReadGate {
            return auth->require_list_read(req, res, t, o);
        };
    }
    /// The non-blocking resolver the legacy execution routes take (`AuthRoutes::resolve_session`).
    ResolveSessionFn resolve_session_fn() {
        return [this](const httplib::Request& req) { return auth->resolve_session(req); };
    }

    /// Wire the real session into an MCP test server in ONE call: authentication (the fixture
    /// wraps it in the PRODUCTION admission, `mcp::make_admission_auth_fn`), permission,
    /// fleet-read and list-read all come from `auth`, so the MCP surface and the REST surfaces
    /// see the same session. `McpTestServerT` is test_mcp_server.cpp's file-local fixture; the
    /// two `*_for_test` seams it exposes for this are documented there. Call BEFORE `ts.start()`.
    template <class McpTestServerT>
    void wire_mcp(McpTestServerT& ts) {
        ts.real_session_auth_for_test = auth_fn();
        ts.real_perm_fn_for_test = perm_fn();
        ts.fleet_read_fn_for_test = fleet_read_fn();
        ts.list_read_fn_for_test = list_read_fn();
        ts.execution_tracker_for_test = &tracker;
    }

    // ── observation helpers ────────────────────────────────────────────────────

    /// The session `token` authenticates as (nullopt when the gate refuses).
    std::optional<server::auth::Session> session_of(const Headers& headers) {
        httplib::Request req;
        for (const auto& [k, v] : headers)
            req.set_header(k, v);
        httplib::Response res;
        return auth->require_auth(req, res);
    }
    std::optional<server::auth::Session> session_of_token(const std::string& token) {
        return session_of(bearer(token));
    }

    /// `require_fleet_read` for `headers` on (type, op), reduced to a comparable outcome.
    ScopeOutcome fleet_scope(const Headers& headers, const std::string& type = "Execution",
                             const std::string& op = "Read") {
        httplib::Request req;
        for (const auto& [k, v] : headers)
            req.set_header(k, v);
        httplib::Response res;
        res.status = 0;
        auto gate = fleet_read_fn()(req, res, type, op);
        ScopeOutcome out;
        out.admitted = gate.admitted;
        out.status = gate.admitted ? 0 : res.status;
        if (gate.admitted && gate.scope) {
            std::vector<std::string> v(gate.scope->begin(), gate.scope->end());
            std::sort(v.begin(), v.end());
            out.agents = std::move(v);
        }
        return out;
    }

    /// The durable audit rows with this action, as "result|detail".
    std::vector<std::string> audit(const std::string& action) {
        std::vector<std::string> out;
        server::AuditQuery q;
        q.action = action;
        q.limit = 1000;
        auto rows = audit_store.query(q);
        REQUIRE(rows.has_value());
        for (const auto& row : *rows)
            if (row.action == action)
                out.push_back(row.result + "|" + row.detail);
        return out;
    }

    static std::vector<std::string> sorted(std::vector<std::string> v) {
        std::sort(v.begin(), v.end());
        return v;
    }

    /// Run one statement over a fresh side connection (never the rig's pools), for fault injection
    /// such as renaming the executions table to make the tracker's reads degrade.
    void exec_sql(const std::string& sql) const {
        server::pg::PgConn conn{PQconnectdb(dsn_.c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        server::pg::PgResult r{PQexec(conn.get(), sql.c_str())};
        INFO(PQresultErrorMessage(r.get()));
        REQUIRE(r.ok());
    }

    // ── seed ───────────────────────────────────────────────────────────────────

    static constexpr int64_t kBaseAt = 1735689600; // 2025-01-01T00:00:00Z

    std::string make_exec(const std::string& dispatched_by, int64_t at, int targeted,
                          const std::string& status = "completed",
                          const std::string& parent_id = {}) {
        server::Execution e;
        e.definition_id = "def-owner-rig";
        e.dispatched_by = dispatched_by;
        e.status = status;
        e.dispatched_at = at;
        e.agents_targeted = targeted;
        e.parent_id = parent_id;
        auto id = tracker.create_execution(e);
        REQUIRE(id.has_value());
        return *id;
    }
    void put_status(const std::string& exec, const std::string& agent, const std::string& st,
                    const std::string& err = {}, int64_t done = kBaseAt + 60) {
        server::AgentExecStatus a;
        a.agent_id = agent;
        a.status = st;
        a.completed_at = (st == "running") ? 0 : done;
        a.error_detail = err;
        REQUIRE(tracker.update_agent_status(exec, a));
    }

    void seed() {
        ids.in_a = make_exec("carol", kBaseAt + 1, 1);
        put_status(ids.in_a, "a1", "success");
        ids.a2 = make_exec("carol", kBaseAt + 2, 1);
        put_status(ids.a2, "a2", "success");
        ids.mixed = make_exec("carol", kBaseAt + 3, 2);
        put_status(ids.mixed, "a1", "success");
        put_status(ids.mixed, "b1", "failure", "SECRET-B-ERR", kBaseAt + 90);
        ids.run = make_exec("carol", kBaseAt + 4, 3, "running");
        put_status(ids.run, "a1", "running");
        put_status(ids.run, "a2", "success");
        put_status(ids.run, "b1", "running");
        ids.foreign = make_exec("carol", kBaseAt + 5, 1);
        put_status(ids.foreign, "z1", "success");
        ids.empty_pending = make_exec("carol", kBaseAt + 6, 1, "pending");
        ids.minter_out = make_exec("mina", kBaseAt + 7, 1);
        put_status(ids.minter_out, "z1", "success");
        ids.minter_in_a = make_exec("mina", kBaseAt + 8, 1);
        put_status(ids.minter_in_a, "a1", "success");
        ids.minter_pending = make_exec("mina", kBaseAt + 9, 1, "running");
        ids.bob_out = make_exec("bob", kBaseAt + 10, 1);
        put_status(ids.bob_out, "z1", "success");
        ids.bob_pending = make_exec("bob", kBaseAt + 11, 1, "running");
    }

    /// The five ids a service-A credential is expected to see once minter-keyed visibility is
    /// gone, as a convenience for later assertions. Exported as data, not asserted here.
    std::vector<std::string> service_a_ids() const {
        return sorted({ids.in_a, ids.a2, ids.mixed, ids.run, ids.minter_in_a});
    }
    /// Every always-seeded id.
    std::vector<std::string> all_seeded_ids() const {
        return sorted({ids.in_a, ids.a2, ids.mixed, ids.run, ids.foreign, ids.empty_pending,
                       ids.minter_out, ids.minter_in_a, ids.minter_pending, ids.bob_out,
                       ids.bob_pending});
    }

    /// `n` NEWER mina executions on z1 (a page of out-of-scope minter rows), so a service-scoped
    /// list proves the owner key is dropped in SQL BEFORE the page LIMIT, not only per row.
    std::vector<std::string> seed_starvation(int n = 60) {
        std::vector<std::string> out;
        for (int i = 0; i < n; ++i) {
            auto id = make_exec("mina", kBaseAt + 1000 + i, 1);
            put_status(id, "z1", "success");
            out.push_back(id);
        }
        return out;
    }

    ExecutionOwnerChildren seed_children() {
        ExecutionOwnerChildren c;
        c.parent_in = make_exec("carol", kBaseAt + 100, 1);
        put_status(c.parent_in, "a1", "success");
        c.c_in = make_exec("carol", kBaseAt + 101, 1, "completed", c.parent_in);
        put_status(c.c_in, "a1", "success");
        c.c_minter_out = make_exec("mina", kBaseAt + 102, 1, "completed", c.parent_in);
        put_status(c.c_minter_out, "z1", "success");
        c.c_minter_pending = make_exec("mina", kBaseAt + 103, 1, "running", c.parent_in);
        c.c_b = make_exec("carol", kBaseAt + 104, 1, "completed", c.parent_in);
        put_status(c.c_b, "b1", "success");

        c.parent_minter_out = make_exec("mina", kBaseAt + 110, 1);
        put_status(c.parent_minter_out, "z1", "success");
        c.c_x = make_exec("carol", kBaseAt + 111, 1, "completed", c.parent_minter_out);
        put_status(c.c_x, "a1", "success");
        return c;
    }

    /// The children-cap fixture: `kRigChildrenOverCap` NEWER minter children on z1, then ONE older
    /// carol child on a1. Only the scope clause BEFORE `ORDER BY ... LIMIT cap+1` lets a
    /// service-A credential see `c_old_in`; the field values of `c` other than the cap pair are
    /// left empty.
    ExecutionOwnerChildren seed_children_cap() {
        ExecutionOwnerChildren c;
        c.parent_cap = make_exec("carol", kBaseAt + 200, 1);
        put_status(c.parent_cap, "a1", "success");
        c.c_old_in = make_exec("carol", kBaseAt + 201, 1, "completed", c.parent_cap);
        put_status(c.c_old_in, "a1", "success");
        for (int i = 0; i < kRigChildrenOverCap; ++i) {
            auto id = make_exec("mina", kBaseAt + 2000 + i, 1, "completed", c.parent_cap);
            put_status(id, "z1", "success");
        }
        return c;
    }
};

} // namespace yuzu::test
