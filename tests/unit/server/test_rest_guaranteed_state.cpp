/**
 * test_rest_guaranteed_state.cpp — HTTP-level coverage for the
 * /api/v1/guaranteed-state/ surface added in Guardian PR 2.
 *
 * Pattern matches test_rest_api_tokens.cpp: register RestApiV1 routes
 * against an in-process TestRouteSink and dispatch synthesised
 * httplib::Request objects through the captured handlers. No real HTTP
 * server, no acceptor thread, no #438 TSan trap.
 *
 * Coverage focuses on the wire contract that downstream tooling
 * (dashboard, MCP, CLI) will exercise:
 *   - 201 on create, with rule_id echoed in `data.rule_id`
 *   - 409 (kConflictPrefix mapping) on duplicate name / rule_id
 *   - 200 round-trip GET / list / PUT / DELETE
 *   - 202 on push (PR 2 placeholder; real fan-out is PR 3)
 *   - audit_fn fires for every mutating endpoint
 *
 * Not covered here: agent-side dispatch (test_guardian_engine.cpp), the
 * scope expansion that PR 3 wires into /push.
 */

#include "auth_routes.hpp"
#include "baseline_store.hpp"
#include "dex_app_perf_model.hpp" // the app-perf read types (slice-2)
#include "guaranteed_state_store.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rbac_store.hpp"
#include "response_store.hpp"
#include "dex_api_local.hpp" // ADR-0031 WS-A4: wire the real DexApi seam so the DEX REST cases exercise it
#include "guardian_api_local.hpp" // ADR-0031 WS-A4 (ninth family): wire the real GuardianApi seam
#include "rest_api_v1.hpp"
#include "test_dex_perf_api_double.hpp"
#include "test_guardian_api_double.hpp" // ADR-0031 WS-A4 (ninth family): FnGuardianApi
#include "test_network_api_double.hpp"
#include "test_route_sink.hpp"
#include "test_verify_api_double.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp> // Config's full definition (auth_routes.hpp only forward-declares it)

#include "../test_helpers.hpp"
#include "test_api_token_pg_helper.hpp" // ApiTokenStorePg — real tokens for the ADR-0017 list-read gate ladder
#include "test_mgmt_group_pg_helper.hpp"
#include "test_rbac_store_pg_helper.hpp" // RbacStorePg — RbacStore is PG-only (ADR-0041)

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <memory>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

// ResponseStore is now a migrated Postgres store (ADR-0039) — shares the
// "responsestore" template key with test_response_store.cpp (identical setup).
yuzu::test::PgTestTemplate responsestore_tpl{"responsestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResponseStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("responsestore template: store failed to migrate");
}};

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
};

std::int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every
// RestGsHarness below constructs its own GuaranteedStateStore against a clone
// of this schema (ADR-0038 migration). Shared key "guardianstate" — SAME
// spelling as every other GuaranteedStateStore test file's template, so the
// shared-key REPLAY verification (test_helpers.hpp) passes rather than
// failing on a divergent setup callback for the same key.
yuzu::test::PgTestTemplate guardianstate_tpl{"guardianstate", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    GuaranteedStateStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("guardianstate template: store failed to migrate");
}};

// Shared key "baselinestore" — SAME setup-callback shape as
// test_baseline_store.cpp's own template (ADR-0055 migration), so the
// shared-key replay verification (test_helpers.hpp) passes.
yuzu::test::PgTestTemplate baselinestore_tpl{"baselinestore", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    BaselineStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("baselinestore template: store failed to migrate");
}};

struct RestGsHarness {
    // Each TempDbFile sits ABOVE its store unique_ptr: members destruct in
    // reverse order, so the store closes its SQLite handle before the backing
    // file (+ -wal/-shm) is removed. RAII replaces the old manual dtor and
    // also covers a ctor REQUIRE throwing mid-construction, which previously
    // leaked all three DBs (#486 / qe-B1).
    //
    // GuaranteedStateStore is migrated to Postgres (ADR-0038): `gs_db_pg` /
    // `gs_pool` replace the old TempDbFile for this store specifically and
    // sit ABOVE `store` for the same reverse-destruction-order reason. Mirrors
    // AuthDbPg's shape (test_auth_db_pg_helper.hpp) — `gs_db_pg` stays
    // `std::optional` and is `.emplace()`d only after the ctor's own SKIP
    // check, so PostgresTestDb is never touched when PG isn't configured.
    std::optional<yuzu::test::PostgresTestDb> gs_db_pg;
    std::optional<yuzu::server::pg::PgPool> gs_pool;
    std::unique_ptr<GuaranteedStateStore> store;

    // Live-info dispatch/poll deps. resp_store is a real ResponseStore (ADR-0039:
    // Postgres-backed) the live endpoint polls, constructed only when the caller
    // supplies a pool (see the constructor's `resp_pool` param); the dispatch stub
    // returns a deterministic command_id so a test can pre-insert the matching
    // response row. live_sent toggles the offline path.
    std::unique_ptr<ResponseStore> resp_store;
    int live_sent{1};
    std::string last_live_plugin, last_live_action;
    /// #1788: the confinement set the /live handler derived and threaded into
    /// dispatch. The per-device scoped_perm_fn gate remains this route's
    /// PRIMARY authorization; this is the second, independent check.
    yuzu::server::authz::VisibleSet last_live_exec_visible;
    /// What the wired derivation answers; nullopt = unfiltered.
    yuzu::server::authz::VisibleSet exec_visible_override{};

    // BaselineStore for the baseline-anchored per-device status route.
    // Migrated to Postgres (ADR-0055) — separate clone/pool from gs_db_pg/
    // gs_pool above (its own "baselinestore" template; independent schema).
    std::optional<yuzu::test::PostgresTestDb> bl_db_pg;
    std::optional<yuzu::server::pg::PgPool> bl_pool;
    std::unique_ptr<BaselineStore> baseline_store;

    // ADR-0017 authorize_list_read confinement for the fleet /guaranteed-state/status
    // route. `rbac_` is a FRESH store with RBAC left disabled (the
    // constructor default, never toggled unless a test calls set_rbac_enabled(true)) —
    // rbac_enforcement_in_effect() then reads legacy-open, so authorize_list_read
    // unconditionally returns AdmitAll and every EXISTING test's happy-path behavior is
    // unchanged by this pair existing. RbacStore is PG-only (ADR-0041) and
    // mgmt_bundle_ is PG-backed (ADR-0042), but this harness already
    // unconditionally requires Postgres for GuaranteedStateStore (the ctor's
    // own SKIP check above), so adding either introduces no new skip condition.
    yuzu::test::RbacStorePg rbac_bundle_;
    RbacStore& rbac_ = *rbac_bundle_;
    yuzu::test::ManagementGroupStorePg mgmt_bundle_;
    ManagementGroupStore& mgmt_ = *mgmt_bundle_;

    // Real AuthRoutes for the fleet /status route's SOLE gate
    // (AuthRoutes::require_list_read, ADR-0017/#3038 fix) — the composition
    // bug this replaces shipped BECAUSE the stub auth_fn/perm_fn below
    // unconditionally granted, so it never exercised the real
    // require_permission/authorize_list_read interaction. Every OTHER route
    // in this harness still uses the stub auth_fn/perm_fn/scoped_perm_fn —
    // this pair is additional, not a replacement. ApiTokenStorePg mints real
    // service-scoped/MCP-tier tokens for the fleet route's ladder tests; this
    // harness already unconditionally requires Postgres (the ctor's own SKIP
    // check above), so this introduces no new skip condition. Declared AFTER
    // rbac_/mgmt_bundle_/api_tokens_ (destroyed BEFORE them, in reverse
    // declaration order) since auth_routes_ holds raw pointers into them.
    Config auth_cfg_{};
    auth::AuthManager auth_mgr_{};
    yuzu::test::ApiTokenStorePg api_tokens_;
    std::shared_mutex oidc_mu_;
    std::unique_ptr<oidc::OidcProvider> oidc_provider_; // empty
    std::unique_ptr<AuthRoutes> auth_routes_;

    std::string session_user{"alice"};
    auth::Role session_role{auth::Role::admin};
    // Non-empty simulates a service-scoped API token session (SEC-3: the
    // fleet-wide /guaranteed-state/events branch denies these outright, since
    // require_permission's service-token branch checks only the ITServiceOwner
    // role and never the token's own service-tag scope). Default empty
    // preserves every other test's ordinary-operator session. NOT dead code:
    // still live and used by many tests below (the events-route tests, and —
    // before the fleet /status route migrated to real tokens via
    // service_scoped_token_headers() — its own service-token-denial test).
    std::string session_token_scope_service;

    // When false, perm_fn denies (403) — lets a test prove the permission gate
    // runs BEFORE any audit emission on the DEX read surface (default grants,
    // preserving every other test's behaviour).
    bool grant_perms{true};

    // When non-empty, the scoped per-device gate denies (403) this agent_id — lets a
    // test prove the per-device scope is enforced on /api/v1/dex/devices/{id}.
    std::string deny_scoped_agent;

    // When non-empty, the scoped gate denies (403) only this operation (e.g.
    // "Execute") — lets a test isolate the Execute floor on /live from the Read
    // floor (#1549 review LOW: the gaps didn't isolate Execute-denied-but-Read-OK).
    std::string deny_scoped_op;

    // When false, audit_fn returns false (simulating a dropped evidence row) so a
    // test can prove audit-on-open fails CLOSED on the REST PII / dispatch surface
    // (#1549 review HIGH). Default true preserves every other test's behaviour.
    bool audit_succeeds{true};

    // When true, audit_fn THROWS (a bad_alloc-class failure) so a test can prove
    // the shared #1647 helper catches it (the throw arm was previously silent) and
    // still fails closed with Sec-Audit-Failed rather than letting it escape.
    bool audit_throws{false};

    // When false, the live deps (response_store + command_dispatch_fn) are left
    // unwired so a test can prove /live → 503 when the substrate is unavailable.
    bool wire_live_deps{true};

    // Per-device scoped-permission simulation for the baseline-anchored route.
    // scoped_deny_agent (when non-empty) is treated as OUT OF SCOPE → 403; every
    // other agent is in scope. last_scoped_agent_id records the agent_id the route
    // handed the scoped check (proves the route scopes by the right device).
    std::string scoped_deny_agent;
    std::string last_scoped_agent_id;

    // When true, a "GuaranteedState" scoped_perm_fn call delegates to the real
    // AuthRoutes::require_scoped_permission instead of the local stand-in above —
    // see scoped_perm_fn's own comment. Default false: every pre-existing test in
    // this file is unaffected.
    bool wire_real_gs_scoped_perm_{false};

    std::vector<AuditRecord> audit_log;

    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    // Slice-2 DEX app-perf read seams. Wired with present-but-empty doubles by
    // default (so the audit/scope/render paths are reachable); left empty when
    // wire_app_perf is false so a test can prove the provider-absent → 503 branch.
    yuzu::server::test::FnDexPerfApi::Providers app_perf_providers_;
    // ADR-0031 WS-A4 #4250: the shared VerifyApi seam backing GET
    // /api/v1/dex/perf/compare (replaces the retired AppPerfCohortFn-in-
    // AppPerfProviders ad-hoc cohort provider). Left null when wire_app_perf is
    // false — same "provider absent → 503" branch every other app-perf seam
    // above exercises.
    std::shared_ptr<const yuzu::server::VerifyApi> verify_api_;
    // Rows the wired fleet provider returns (default empty). A test sets this before
    // calling /perf/app to drive the suppression-serialization path (the wired fleet
    // lambda reads it lazily at request time).
    std::vector<yuzu::server::AppPerfFleetRow> fleet_rows_;
    // Rows the wired tag-cohort provider returns (default empty), same lazy-read
    // pattern as fleet_rows_ above — lets a test drive GET /dex/perf/tag's
    // suppression-serialization path (sub-floor cohort) without a harness rebuild.
    std::vector<yuzu::server::AppPerfFleetRow> tag_cohort_rows_;

    // GET /dex/perf/devices and GET /network/devices read seams — always wired
    // present-but-empty (unlike app_perf_providers_ above, no test here needs
    // the provider-absent → 503 branch for these two routes, so no toggle).
    // Reaches these routes' audit/deny paths without seeding fleet rows.
    yuzu::server::DexPerfFn dex_perf_fn_ = [](const std::string&) {
        return yuzu::server::DexPerfSnapshot{};
    };
    std::shared_ptr<const yuzu::server::NetworkApi> net_perf_fn_ =
        std::make_shared<yuzu::server::test::FnNetworkApi>(
            [](const std::string&) { return yuzu::server::NetPerfSnapshot{}; });

    // #4035: the DexFleet provider for GET /dex/{health,trends,overview,
    // catalogue/group}. Default DexFleet{} (all-zero: no online agents) so
    // every EXISTING test in this file is unaffected; a test targeting these
    // 4 new routes' fleet-dependent shape sets dex_fleet_override_ before
    // constructing the harness is not possible (register_routes captures the
    // lambda at construction) — so instead the lambda reads this field LIVE
    // at request time, letting a test mutate it after construction.
    yuzu::server::DexFleet dex_fleet_override_;

    // #4035 hardening (governance): the visible-agent-set resolver for GET
    // /api/v1/dex/app and GET /api/v1/dex/overview (ADR-0017 World A
    // confinement — ind. of the service-scoped-token deny belt above).
    // nullopt (default) = unfiltered, matching every EXISTING test in this
    // file (and matching an unwired dex_visible_fn / RBAC-off / global-read
    // production posture). A test proving confinement sets this to a
    // specific agent set before issuing the request.
    std::optional<std::set<std::string>> dex_visible_override_;

    // What the wired VERIFY cohort provider returns (default = present-but-empty
    // CohortRead → the compare reads "insufficient"). A test sets member_count +
    // rows to drive the paired-compare path, or sets it to nullopt to prove the
    // AUTHORITATIVE degrade → 503 branch.
    std::optional<yuzu::server::CohortRead> cohort_read_{yuzu::server::CohortRead{}};

    // live_deps=false leaves the live substrate (response_store + command_dispatch_fn)
    // unwired so a test can prove /live → 503. wire_scoped_perm=false registers the
    // device-compliance route with an EMPTY ScopedPermFn, exercising its fail-closed-503
    // path. Both default true so every existing test is unchanged.
    /// false → register with an EMPTY `exec_visible_fn`, modelling a deployment
    /// that never wired the #1788 derivation. Not a synonym for
    /// `exec_visible_override` being nullopt: that is a callback ANSWERING
    /// "unfiltered".
    bool wire_exec_visible{true};

    /// false → register the fleet /status route with an EMPTY ListReadFn,
    /// exercising its fail-closed-503 path (mirrors wire_scoped_perm above).
    bool wire_list_read_fn_{true};

    // Declared LAST (was first): sink's registered handlers capture `this` and
    // dereference owner members (auth_routes_, rbac_/mgmt_ bundles, api, ...)
    // declared above — CLAUDE.md's test-conventions rule ("fixtures must
    // declare the sink AFTER the route owner it registers") means sink must be
    // destroyed FIRST, before any of those owners. Moved here per cpp-safety
    // scoped review during the PR #3175 review-response round (verified: no
    // member's construction depends on sink already existing, and no
    // registered handler is ever invoked outside a live harness's own
    // synchronous sink.Get/Post calls, so this was latent, not a live UAF).
    yuzu::server::test::TestRouteSink sink;

    // ADR-0039: ResponseStore is now a migrated Postgres store, so it needs a
    // live `pg::PgPool&` — but only the handful of `/live`-exercising
    // TEST_CASEs in this file actually touch it. `resp_pool` is nullable
    // (default nullptr) so the ~100 other RestGsHarness call sites in this
    // file (Guard rule CRUD / DEX aggregations / …) stay PG-independent and
    // untagged; only callers that pass a real pool get a real (open)
    // resp_store — everyone else gets the same "substrate absent" shape the
    // explicit `live_deps=false` case already exercised.
    explicit RestGsHarness(bool live_deps = true, bool wire_scoped_perm = true,
                           bool wire_app_perf = true, bool with_exec_visible = true,
                           pg::PgPool* resp_pool = nullptr, bool wire_list_read_fn = true,
                           // ADR-0031 WS-A4 (ninth family), seam-bypass tripwire: when
                           // set, this DISTINGUISHING GuardianApi double is wired
                           // INSTEAD of the seam this harness otherwise derives from its
                           // own live store/baseline_store below — the real stores are
                           // still constructed and REQUIRE'd open either way, so a
                           // revert-to-raw-store still finds a live, answerable store at
                           // the SAME id but a DIFFERENT answer than the double gives.
                           std::shared_ptr<yuzu::server::GuardianApi> guardian_api_override = nullptr)
        : wire_live_deps(live_deps), wire_exec_visible(with_exec_visible),
          wire_list_read_fn_(wire_list_read_fn) {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        gs_db_pg.emplace(guardianstate_tpl);
        INFO("[RestGsHarness] guaranteed-state fixture status (blank == database came up OK): "
             << gs_db_pg->error());
        REQUIRE(gs_db_pg->available());
        gs_pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = gs_db_pg->dsn(), .size = 4});
        REQUIRE(gs_pool->valid());
        // retention=0 keeps the reaper out of the way for ingest tests (reap_expired()
        // is now called on-demand from the maintenance tick, not a background thread —
        // retention_days=0 makes compute_ttl_epoch() return the "never expire" sentinel).
        store = std::make_unique<GuaranteedStateStore>(*gs_pool, /*retention_days=*/0);
        REQUIRE(store->is_open());
        bl_db_pg.emplace(baselinestore_tpl);
        INFO("[RestGsHarness] baseline fixture status (blank == database came up OK): "
             << bl_db_pg->error());
        REQUIRE(bl_db_pg->available());
        bl_pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = bl_db_pg->dsn(), .size = 4});
        REQUIRE(bl_pool->valid());
        baseline_store = std::make_unique<BaselineStore>(*bl_pool);
        REQUIRE(baseline_store->is_open());

        auth_routes_ =
            std::make_unique<AuthRoutes>(auth_cfg_, auth_mgr_, &rbac_, api_tokens_.get(),
                                         /*audit_store=*/nullptr, &mgmt_, /*tag_store=*/nullptr,
                                         /*analytics_store=*/nullptr, oidc_mu_, oidc_provider_);

        if (wire_live_deps && resp_pool) {
            resp_store = std::make_unique<ResponseStore>(*resp_pool, /*retention_days=*/0);
            REQUIRE(resp_store->is_open());
        }

        // Deterministic dispatch stub: command_id = "<plugin>-live" so a test can
        // pre-insert the matching response row; live_sent toggles offline (0).
        auto command_dispatch_fn =
            [this](const std::string& plugin, const std::string& action,
                   const std::vector<std::string>& ids, const std::string&,
                   const std::unordered_map<std::string, std::string>&, const std::string&,
                   const yuzu::server::DispatchCaller& caller)
            -> yuzu::server::ConfinedDispatchOutcome {
            last_live_plugin = plugin;
            last_live_action = action;
            last_live_exec_visible = caller.exec_visible;
            // Model what the production seam does to the Ids arm rather than
            // ignoring the set the route just derived — otherwise this fake
            // reports a successful dispatch whatever confinement decided, which
            // is how the handoff went unasserted. nullopt admits everything, so
            // every pre-existing case here is unaffected.
            const bool admitted =
                std::all_of(ids.begin(), ids.end(), [&](const std::string& id) {
                    return yuzu::server::authz::in_scope(caller.exec_visible, id);
                });
            return {.sent = admitted ? live_sent : 0, .command_id = plugin + "-live"};
        };
        // When wire_live_deps is off, leave the dispatch closure empty so the /live
        // handler hits its "substrate unavailable → 503" branch.
        RestApiV1::CommandDispatchFn dispatch_arg =
            wire_live_deps ? RestApiV1::CommandDispatchFn{command_dispatch_fn}
                           : RestApiV1::CommandDispatchFn{};

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            if (session_user.empty())
                return std::nullopt;
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            s.token_scope_service = session_token_scope_service;
            return s;
        };

        // perm_fn grants unless grant_perms is flipped off (then 403, mirroring
        // the production perm_fn) — RBAC proper is exercised in test_rbac_store.cpp.
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) -> bool {
            if (grant_perms)
                return true;
            res.status = 403;
            return false;
        };

        // Scoped per-device permission (require_scoped_permission stand-in): records
        // the agent_id, then denies (403) when grant_perms is off OR the agent matches
        // either deny knob (deny_scoped_agent / dev's scoped_deny_agent) OR the
        // operation matches deny_scoped_op (Execute-vs-Read isolation, #1549). Mirrors
        // require_scoped_permission's contract (global passes; otherwise in-scope);
        // last_scoped_agent_id proves the route scopes by the right device.
        //
        // wire_real_gs_scoped_perm_ (default false, every existing test unaffected):
        // when a test flips it on, a GuaranteedState-securable call delegates to the
        // REAL AuthRoutes::require_scoped_permission (same auth_routes_ instance the
        // fleet route's list_read_fn already uses) instead of this stand-in — closes
        // the gap a review on PR #3175 raised: the per-agent status route's cross-
        // management-group denial test previously only proved THIS local string-match
        // stub denies, never that the real RBAC/ManagementGroupStore composition does.
        // Scoped to "GuaranteedState" only (that securable is shared by 5 routes in
        // this file — /status/{agent_id}, /device-compliance, /events, /dex/devices/*
        // — so a test using this toggle must call only the one route it means to
        // exercise; every other route's tests never flip the toggle, so they are
        // unaffected regardless).
        auto scoped_perm_fn = [this](const httplib::Request& req, httplib::Response& res,
                                     const std::string& securable_type,
                                     const std::string& operation,
                                     const std::string& agent_id) -> bool {
            last_scoped_agent_id = agent_id;
            if (wire_real_gs_scoped_perm_ && securable_type == "GuaranteedState")
                return auth_routes_->require_scoped_permission(req, res, securable_type, operation,
                                                                agent_id);
            if (!grant_perms || (!deny_scoped_agent.empty() && agent_id == deny_scoped_agent) ||
                (!scoped_deny_agent.empty() && agent_id == scoped_deny_agent) ||
                (!deny_scoped_op.empty() && operation == deny_scoped_op)) {
                res.status = 403;
                return false;
            }
            return true;
        };

        // ADR-0017: the fleet /status route's SOLE gate — a REAL
        // AuthRoutes::require_list_read call, not a stub (see the
        // auth_routes_ member comment above for why).
        auto list_read_fn = [this](const httplib::Request& req, httplib::Response& res,
                                   const std::string& type,
                                   const std::string& op) -> yuzu::server::ListReadGate {
            return auth_routes_->require_list_read(req, res, type, op);
        };

        // PR W1.1 UP-H1: AuditFn typedef → std::function<bool(...)>. Returns
        // audit_succeeds so a test can simulate a dropped evidence row (#1549).
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            // Throw BEFORE recording, so a throwing audit_fn leaves audit_log empty —
            // a test can then assert audit_log.empty() to prove the handler's catch arm
            // (not the return-false arm) fired. (The merge that adopted #1647's harness
            // left a second, unreachable post-push_back throw here; removed — qe-1.)
            if (audit_throws)
                throw std::runtime_error("audit store unavailable (test)");
            audit_log.push_back({action, result, target_type, target_id, detail});
            return audit_succeeds;
        };

        // Present-but-empty app-perf doubles (reach the audit/scope/render paths
        // without seeding rows). Left empty when wire_app_perf is false so a test
        // can hit the provider-absent → 503 branch.
        if (wire_app_perf) {
            app_perf_providers_.fleet =
                [this](std::string_view, std::string_view)
                -> std::optional<std::vector<yuzu::server::AppPerfFleetRow>> {
                return fleet_rows_; // settable by a test (default empty)
            };
            app_perf_providers_.apps =
                [](bool& truncated) -> std::optional<std::vector<yuzu::server::AppPerfAppSummary>> {
                truncated = false;
                return std::vector<yuzu::server::AppPerfAppSummary>{};
            };
            app_perf_providers_.device =
                [](std::string_view)
                -> std::optional<std::vector<yuzu::server::AppPerfDailyRow>> {
                return std::vector<yuzu::server::AppPerfDailyRow>{};
            };
            app_perf_providers_.group =
                [](std::string_view, std::string_view, std::string_view)
                -> std::optional<std::vector<yuzu::server::AppPerfFleetRow>> {
                return std::vector<yuzu::server::AppPerfFleetRow>{};
            };
            app_perf_providers_.tag_cohort =
                [this](std::string_view, std::string_view, std::string_view, std::string_view)
                -> std::optional<std::vector<yuzu::server::AppPerfFleetRow>> {
                return tag_cohort_rows_; // settable by a test (default empty)
            };
            // ADR-0031 WS-A4 #4250: the shared VerifyApi seam (replaces the
            // retired AppPerfCohortFn-in-AppPerfProviders ad-hoc cohort
            // provider) — a FnVerifyApi wraps the SAME `cohort_read_` fixture
            // so every existing test in this file keeps its meaning
            // unchanged. Left null (see the member's doc comment) when
            // wire_app_perf is false, same "provider absent → 503" branch.
            verify_api_ = std::make_shared<yuzu::server::test::FnVerifyApi>(
                [this](std::string_view, std::string_view, std::string_view, std::string_view,
                      int) -> std::optional<yuzu::server::CohortRead> { return cohort_read_; });
        }

        // ADR-0031 WS-A4: the REAL DexApi seam over this harness's live
        // GuaranteedStateStore + fleet override, so the DEX signal REST cases
        // exercise the SEAM path (production wires it identically). Gated on
        // store presence exactly like server.cpp — null store → null api → 503.
        std::shared_ptr<yuzu::server::DexApi> dex_api_local;
        if (store)
            dex_api_local = yuzu::server::make_local_dex_api(
                store.get(), [this]() { return dex_fleet_override_; });

        // ADR-0031 WS-A4 (sixth family): the REAL DexPerfApi seam wrapping
        // this harness's existing dex_perf_fn_/app_perf_providers_ function
        // doubles (FnDexPerfApi — mirrors FnVerifyApi's own "wrap the
        // pre-seam fn-shaped test double" pattern) — always wired, since
        // dex_perf_fn_ is always present-but-empty here (see its own doc
        // comment) and every over-time method individually degrades to
        // nullopt when its own app_perf_providers_ field is unset, exactly
        // matching this file's pre-rewire per-route provider-absent checks.
        auto dex_perf_api_local =
            std::make_shared<yuzu::server::test::FnDexPerfApi>(dex_perf_fn_, app_perf_providers_);

        // ADR-0031 WS-A4 (ninth family): the REAL GuardianApi seam over this
        // harness's live GuaranteedStateStore + BaselineStore, so the
        // guaranteed-state REST cases exercise the SEAM path (production
        // wires it identically). Constructed unconditionally, mirroring
        // server.cpp — this harness's constructor already REQUIREs both
        // stores open before reaching here, so both pointers are always
        // non-null in practice; each method still degrades individually if
        // either were absent (guardian_api.cpp). guardian_api_override (an
        // injected test double) takes precedence when set — see the
        // constructor param's own doc comment (seam-bypass tripwire testing).
        std::shared_ptr<yuzu::server::GuardianApi> guardian_api_local =
            guardian_api_override ? guardian_api_override
                                  : yuzu::server::make_local_guardian_api(store.get(),
                                                                           baseline_store.get());

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/&rbac_,
                            /*mgmt_store=*/&mgmt_,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr,
                            resp_store.get(), // null unless wire_live_deps && a pool was supplied
                            /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr,
                            /*service_group_fn=*/{},
                            /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr, store.get(),
                            /*metrics_registry=*/&metrics,
                            /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr,
                            dispatch_arg,
                            /*step_up_fn=*/{},
                            /*guardian_push_fn=*/{},
                            dex_perf_fn_,
                            net_perf_fn_,
                            /*lockout_clear_fn=*/{},
                            baseline_store.get(),
                            wire_scoped_perm ? RestApiV1::ScopedPermFn{scoped_perm_fn}
                                             : RestApiV1::ScopedPermFn{},
                            /*software_inventory_store=*/nullptr,
                            /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr, /*access_review_store=*/nullptr,
                            /*auth_db=*/nullptr, /*directory_sync=*/nullptr,
                            /*stream_budget=*/nullptr,
                            // #1788: by default a derivation that ANSWERS
                            // (nullopt = unfiltered), so this file's existing
                            // /live dispatch assertions keep their meaning;
                            // `wire_exec_visible=false` models the genuinely
                            // unwired deployment, which fails closed.
                            wire_exec_visible
                                ? RestApiV1::ExecVisibleFn{[this](const auth::Session&)
                                                               -> yuzu::server::authz::VisibleSet {
                                      return exec_visible_override;
                                  }}
                                : RestApiV1::ExecVisibleFn{},
                            wire_list_read_fn_ ? RestApiV1::ListReadFn{list_read_fn}
                                               : RestApiV1::ListReadFn{},
                            /*fleet_read_fn=*/{},
                            // #4033: this harness doesn't exercise GET
                            // /api/v1/devices or the agent-count preview —
                            // unwired defaults (fail-closed / legacy-open
                            // respectively) are correct no-ops here.
                            /*agents_fn=*/{}, /*response_visible_set_fn=*/{},
                            // ADR-0031 WS-A4 (fifth family): the dex_fleet_fn
                            // register_routes param is retired — the DEX handlers
                            // get the fleet via the DexApi seam (dex_api_local
                            // above, wired with dex_fleet_override_).
                            // #4035 hardening (governance): reads
                            // dex_visible_override_ LIVE at request time
                            // (ignores `username` — this stub doesn't model
                            // per-username resolution, only whether the
                            // caller's set is engaged).
                            RestApiV1::DexVisibleFn{
                                [this](const std::string&) { return dex_visible_override_; }},
                            // ADR-0031 WS-A4 #4250: the shared VerifyApi seam backing
                            // GET /api/v1/dex/perf/compare (see verify_api_'s doc
                            // comment above).
                            verify_api_,
                            // ADR-0031 WS-A4: device_api unused by this harness;
                            // dex_api_local is the real DEX signals seam (above).
                            /*device_api=*/nullptr, dex_api_local, dex_perf_api_local,
                            // ADR-0031 WS-A4 (ninth family): the real Guardian-read
                            // seam (guardian_api_local above).
                            guardian_api_local);
    }

    // The fleet /status route's real AuthRoutes::require_list_read gate needs
    // an actual authenticated request — unlike every other route in this
    // harness, still gated by the stub auth_fn/perm_fn above (the
    // session_user stub field does NOT reach this route). Mints a cookie
    // session for the CURRENT session_user/session_role and returns headers
    // carrying it; a test that reassigns session_user before calling this
    // (the DenyAll/AdmitAll/AdmitScoped [adr0017] cases) gets a session for
    // the new principal.
    std::unordered_map<std::string, std::string> status_route_headers() {
        REQUIRE(!session_user.empty());
        REQUIRE(auth_mgr_.upsert_user(session_user, "password1234", session_role));
        auto token =
            auth_mgr_.create_local_session(session_user, session_role, /*mfa_verified=*/true);
        return {{"Cookie", "yuzu_session=" + token}};
    }

    // A JIT-elevated session (mirrors the production /api/v1/elevate route)
    // for the route-level elevated-admits-unfiltered regression test — pins
    // the SEC-7 regression (an elevated session with zero RBAC grants
    // getting denied) at the surface where it actually shipped.
    std::unordered_map<std::string, std::string> elevated_status_route_headers() {
        REQUIRE(!session_user.empty());
        REQUIRE(auth_mgr_.upsert_user(session_user, "password1234", auth::Role::user));
        auto token = auth_mgr_.create_local_session(session_user, auth::Role::user,
                                                     /*mfa_verified=*/true);
        REQUIRE(auth_mgr_.elevate_session(token, std::chrono::seconds(300)).has_value());
        return {{"Cookie", "yuzu_session=" + token}};
    }

    // A real service-scoped API token (Bearer) for the fleet route's
    // service-scoped-token denial test — this route resolves its own
    // session from headers via list_read_fn, so a stub session has no way
    // to carry a service scope onto it.
    std::unordered_map<std::string, std::string>
    service_scoped_token_headers(const std::string& service) {
        REQUIRE(!session_user.empty());
        REQUIRE(auth_mgr_.upsert_user(session_user, "password1234", session_role));
        auto raw = api_tokens_->create_token("svc-token-" + service, session_user,
                                             now_epoch() + 3600, service, "");
        REQUIRE(raw.has_value());
        return {{"Authorization", "Bearer " + *raw}};
    }

    // Seed a Guard rule (name resolves in the route's list_rules() lookup).
    void seed_rule(const std::string& rule_id, const std::string& name) {
        GuaranteedStateRuleRow r;
        r.rule_id = rule_id;
        r.name = name;
        REQUIRE(store->create_rule(r).has_value());
    }

    // Seed one device's reported verdict for a Guard via the status feed
    // (insert_event → upsert_rule_status). event_type maps to state per
    // event_state_from_type: guard.compliant→compliant, drift.detected→drifted,
    // guard.unhealthy→errored. NOTE: the upsert keeps the row only when
    // excluded.updated_at >= the existing updated_at, so re-seeding the same
    // (agent, rule_id) with an EARLIER (or equal-then-different-state) timestamp
    // is silently dropped — use strictly increasing ts when overwriting a verdict.
    void seed_status(const std::string& event_id, const std::string& agent,
                     const std::string& rule_id, const std::string& event_type,
                     const std::string& ts) {
        GuaranteedStateEventRow e;
        e.event_id = event_id;
        e.rule_id = rule_id;
        e.agent_id = agent;
        e.event_type = event_type;
        e.severity = "info";
        e.timestamp = ts;
        REQUIRE(store->insert_event(e).has_value());
    }

    // Write a RAW guardian_agent_rule_status row (arbitrary `state`) directly via
    // a second Postgres connection — the public ingest path (insert_event →
    // event_state_from_type) can only ever write "compliant"/"drifted"/"errored",
    // so this is the only way to exercise the handler's defensive "unrecognized
    // state → pending" fallthrough (e.g. a corrupt DB or a future state token).
    // Ported from a raw sqlite3 connection (ADR-0038): unconditional
    // INSERT ... ON CONFLICT DO UPDATE (no updated_at guard) — this helper
    // wants to FORCE the state regardless, unlike the store's own
    // upsert_rule_status, which only advances on a newer timestamp.
    void seed_raw_status(const std::string& agent, const std::string& rule_id,
                         const std::string& state, const std::string& ts) {
        yuzu::server::pg::PgConn conn{PQconnectdb(gs_db_pg->dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult res = yuzu::server::pg::exec_params(
            conn.get(),
            "INSERT INTO guaranteed_state_store.guardian_agent_rule_status "
            "(agent_id, rule_id, state, updated_at) VALUES ($1,$2,$3,$4) "
            "ON CONFLICT (agent_id, rule_id) DO UPDATE SET state = EXCLUDED.state, "
            "updated_at = EXCLUDED.updated_at",
            std::vector<std::string>{agent, rule_id, state, ts});
        INFO(PQresultErrorMessage(res.get()));
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    // Create + deploy a Baseline with the given member Guards (snapshot = members,
    // lifecycle = deployed). Returns the generated baseline_id.
    std::string seed_deployed_baseline(const std::string& name,
                                       const std::vector<std::string>& member_rule_ids) {
        Baseline b;
        b.name = name;
        auto bid = baseline_store->create_baseline(b);
        REQUIRE(bid.has_value());
        REQUIRE(baseline_store->set_members(*bid, member_rule_ids).has_value());
        Baseline deployed = *baseline_store->get_baseline(*bid);
        deployed.deployed_snapshot = nlohmann::json(member_rule_ids).dump();
        deployed.lifecycle = kBaselineDeployed;
        REQUIRE(baseline_store->update_baseline(deployed).has_value());
        return *bid;
    }

    // Seed one ruleless DEX observation (the __observation__ projection the DEX
    // aggregations read — matches seed_signal in test_dex_routes.cpp). subject +
    // platform land in detail_json so dex_signal_subjects / _by_os pick them up.
    void seed_obs(const std::string& id, const std::string& agent, const std::string& obs_type,
                  const std::string& subject, const std::string& platform, const std::string& ts) {
        GuaranteedStateEventRow e;
        e.event_id = id;
        e.rule_id = "__observation__";
        e.agent_id = agent;
        e.event_type = obs_type;
        e.severity = "info";
        e.detail_json =
            "{\"subject\":\"" + subject + "\",\"platform\":\"" + platform + "\"}";
        e.timestamp = ts;
        REQUIRE(store->insert_event(e).has_value());
    }

    static std::string make_rule_body(const std::string& rule_id, const std::string& name,
                                      const std::string& yaml = "name: example\n") {
        nlohmann::json j;
        j["rule_id"] = rule_id;
        j["name"] = name;
        j["yaml_source"] = yaml;
        j["enabled"] = true;
        j["enforcement_mode"] = "enforce";
        j["severity"] = "high";
        j["os_target"] = "windows";
        j["scope_expr"] = "tag:env=prod";
        return j.dump();
    }
};

} // namespace

TEST_CASE("REST gs.rules: create returns 201 and echoes rule_id",
          "[pg][rest][guaranteed_state][create]") {
    RestGsHarness h;
    auto res = h.sink.Post("/api/v1/guaranteed-state/rules",
                           RestGsHarness::make_rule_body("r-001", "block-rdp"));
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(res->body.find("\"rule_id\":\"r-001\"") != std::string::npos);

    // get_rule is three-state (ADR-0038): REQUIRE the outer expected (not
    // degraded), then the inner optional (genuinely found).
    auto stored = h.store->get_rule("r-001");
    REQUIRE(stored.has_value());
    REQUIRE(stored->has_value());
    CHECK((*stored)->name == "block-rdp");
    CHECK((*stored)->severity == "high");
    CHECK((*stored)->os_target == "windows");
    CHECK((*stored)->created_by == "alice");
    CHECK((*stored)->updated_by == "alice");

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "guaranteed_state.rule.create");
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].target_id == "r-001");
}

TEST_CASE("REST gs.rules: missing required fields → 400",
          "[pg][rest][guaranteed_state][create][validation]") {
    RestGsHarness h;
    nlohmann::json bad;
    bad["rule_id"] = "r-bad";
    // name + yaml_source missing
    auto res = h.sink.Post("/api/v1/guaranteed-state/rules", bad.dump());
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->body.find("required") != std::string::npos);
    // #4665: this combined validation reject now audits (previously it was the
    // one create-reject branch that didn't, an asymmetric-audit-coverage gap
    // matching the UP-R1 PUT-malformed-body precedent above).
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "guaranteed_state.rule.create");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].target_id == "r-bad");
}

TEST_CASE("REST gs.rules: charset-invalid rule_id → 400 with the updated error message (#4665)",
          "[pg][rest][guaranteed_state][create][validation]") {
    RestGsHarness h;
    for (const std::string& bad_id :
         {std::string("has space"), std::string("has=eq"), std::string("has\nnewline"),
          std::string("has\xC3\xA9" "byte")}) {
        INFO("bad_id = " << bad_id);
        auto res = h.sink.Post("/api/v1/guaranteed-state/rules",
                               RestGsHarness::make_rule_body(bad_id, "n"));
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(res->body.find("[A-Za-z0-9._-]+") != std::string::npos);
    }
    REQUIRE(h.audit_log.size() == 4);
    for (const auto& rec : h.audit_log)
        CHECK(rec.result == "denied");
}

TEST_CASE("REST gs.rules: rule_id at the 256-byte boundary (#4665)",
          "[pg][rest][guaranteed_state][create][validation]") {
    RestGsHarness h;
    const std::string id256(256, 'a');
    auto ok = h.sink.Post("/api/v1/guaranteed-state/rules",
                          RestGsHarness::make_rule_body(id256, "n256"));
    REQUIRE(ok);
    CHECK(ok->status == 201);
    CHECK(ok->body.find("\"rule_id\":\"" + id256 + "\"") != std::string::npos);

    const std::string id257(257, 'a');
    auto bad = h.sink.Post("/api/v1/guaranteed-state/rules",
                           RestGsHarness::make_rule_body(id257, "n257"));
    REQUIRE(bad);
    CHECK(bad->status == 400);
}

TEST_CASE("REST gs.rules: duplicate name → 409 via kConflictPrefix",
          "[pg][rest][guaranteed_state][conflict]") {
    RestGsHarness h;
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      RestGsHarness::make_rule_body("r-001", "dup-name"))
                ->status == 201);
    auto res = h.sink.Post("/api/v1/guaranteed-state/rules",
                           RestGsHarness::make_rule_body("r-002", "dup-name"));
    REQUIRE(res);
    CHECK(res->status == 409);
    // Body must NOT carry the kConflictPrefix marker — that's an internal
    // wire convention; the operator-facing message is the cleaned form.
    CHECK(res->body.find("conflict:") == std::string::npos);
    CHECK(res->body.find("dup-name") != std::string::npos);

    REQUIRE(h.audit_log.size() == 2);
    CHECK(h.audit_log[1].result == "denied");
}

TEST_CASE("REST gs.rules: list, get, update, delete round-trip", "[pg][rest][guaranteed_state][crud]") {
    RestGsHarness h;
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      RestGsHarness::make_rule_body("r-001", "rule-a"))
                ->status == 201);
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      RestGsHarness::make_rule_body("r-002", "rule-b"))
                ->status == 201);

    auto list = h.sink.Get("/api/v1/guaranteed-state/rules");
    REQUIRE(list);
    CHECK(list->status == 200);
    auto list_json = nlohmann::json::parse(list->body);
    REQUIRE(list_json["data"].is_array());
    CHECK(list_json["data"].size() == 2);
    CHECK(list_json["pagination"]["total"].get<int>() == 2);

    auto got = h.sink.Get("/api/v1/guaranteed-state/rules/r-001");
    REQUIRE(got);
    CHECK(got->status == 200);
    auto got_json = nlohmann::json::parse(got->body);
    CHECK(got_json["data"]["name"].get<std::string>() == "rule-a");
    CHECK(got_json["data"]["version"].get<int>() == 1);

    nlohmann::json patch;
    patch["enabled"] = false;
    patch["severity"] = "critical";
    auto upd = h.sink.Put("/api/v1/guaranteed-state/rules/r-001", patch.dump());
    REQUIRE(upd);
    CHECK(upd->status == 200);

    auto refetched = h.store->get_rule("r-001");
    REQUIRE(refetched.has_value());
    REQUIRE(refetched->has_value());
    CHECK_FALSE((*refetched)->enabled);
    CHECK((*refetched)->severity == "critical");
    CHECK((*refetched)->version == 2); // bumped by handler

    auto del = h.sink.Delete("/api/v1/guaranteed-state/rules/r-001");
    REQUIRE(del);
    CHECK(del->status == 200);
    // Three-state (ADR-0038): the outer expected still has_value() (the read
    // itself succeeded) — genuinely-absent is the INNER optional being empty.
    auto after_delete = h.store->get_rule("r-001");
    REQUIRE(after_delete.has_value());
    CHECK_FALSE(after_delete->has_value());
}

TEST_CASE("REST gs.rules: get unknown id → 404", "[pg][rest][guaranteed_state][not_found]") {
    RestGsHarness h;
    auto got = h.sink.Get("/api/v1/guaranteed-state/rules/nope");
    REQUIRE(got);
    CHECK(got->status == 404);
}

TEST_CASE("REST gs.rules: PUT with malformed body → 400 + denied audit",
          "[pg][rest][guaranteed_state][crud]") {
    // UP-R1 regression guard. The PUT invalid-body 400 branch must emit a
    // denied audit, matching the sibling /push 400 branch. Asymmetric audit
    // coverage across sibling rejection paths was the original finding.
    RestGsHarness h;
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      RestGsHarness::make_rule_body("r-001", "rule-a"))
                ->status == 201);
    // Non-object body (top-level array) — body.is_object() is false.
    auto upd = h.sink.Put("/api/v1/guaranteed-state/rules/r-001", "[1,2,3]");
    REQUIRE(upd);
    CHECK(upd->status == 400);

    // Audit log: [0] create, [1] denied update.
    REQUIRE(h.audit_log.size() == 2);
    const auto& denied = h.audit_log[1];
    CHECK(denied.action == "guaranteed_state.rule.update");
    CHECK(denied.result == "denied");
    CHECK(denied.target_type == "GuaranteedState");
    CHECK(denied.target_id == "r-001");
    CHECK(denied.detail.find("invalid JSON") != std::string::npos);
}

TEST_CASE("REST gs.rules: delete unknown id → 404 + denied audit",
          "[pg][rest][guaranteed_state][not_found]") {
    RestGsHarness h;
    auto del = h.sink.Delete("/api/v1/guaranteed-state/rules/nope");
    REQUIRE(del);
    CHECK(del->status == 404);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].result == "denied");
}

TEST_CASE("REST gs.push: returns 202 + audits the operator action",
          "[pg][rest][guaranteed_state][push]") {
    RestGsHarness h;
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      RestGsHarness::make_rule_body("r-001", "rule-a"))
                ->status == 201);
    nlohmann::json push;
    push["scope"] = "tag:env=prod";
    push["full_sync"] = true;
    auto res = h.sink.Post("/api/v1/guaranteed-state/push", push.dump());
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(res->body.find("\"queued\":true") != std::string::npos);
    // Real fan-out landed: the body reports the rule count and the number of
    // in-scope agents the push was dispatched to (direct + gateway transports).
    // The old "agent delivery is asynchronous / deferred" phrasing is gone —
    // see docs/user-manual/guaranteed-state.md.
    CHECK(res->body.find("\"rules\":1") != std::string::npos);
    CHECK(res->body.find("\"agents\":") != std::string::npos);

    REQUIRE(h.audit_log.size() == 2); // create + push
    const auto& push_audit = h.audit_log[1];
    CHECK(push_audit.action == "guaranteed_state.push");
    // Vocabulary matches sibling handlers: "success" (not the prior novel
    // "accepted"), target_id is empty because a push is fleet-level rather
    // than per-entity, and the scope expression lives in detail alongside the
    // agents=<count> fan-out result so SIEM correlation rules can filter on it.
    CHECK(push_audit.result == "success");
    CHECK(push_audit.target_id == "");
    CHECK(push_audit.target_type == "GuaranteedState");
    CHECK(push_audit.detail.find("rules=1") != std::string::npos);
    CHECK(push_audit.detail.find("full_sync=true") != std::string::npos);
    CHECK(push_audit.detail.find("scope=\"tag:env=prod\"") != std::string::npos);
    // Audit detail records the dispatched agent count, not the retired
    // fan_out_deferred_pr3 marker (push now actually delivers).
    CHECK(push_audit.detail.find("agents=") != std::string::npos);
}

TEST_CASE("REST gs.push: sanitizes scope before embedding in audit detail",
          "[pg][rest][guaranteed_state][push][security]") {
    // UP-R3 regression guard. A scope containing raw quotes, control bytes,
    // or backslashes must not corrupt the audit detail string that SIEM
    // parsers consume. Attacker with GuaranteedState:Push could otherwise
    // forge audit fragments by injecting `" result="denied" fake="`.
    RestGsHarness h;
    nlohmann::json push;
    // Adversarial scope: embedded quote + CR + LF + NUL + backslash + tab.
    // Built by append so there is no risk of buffer-size mismatch with
    // std::string(const char*, size_t) and the embedded NUL.
    std::string adversarial;
    adversarial += "evil\" result=\"denied\" injected=\"yes\"";
    adversarial += "\r\n\t";
    adversarial += "foo";
    adversarial.push_back('\0');
    adversarial += "bar\\";
    push["scope"] = adversarial;
    push["full_sync"] = false;
    auto res = h.sink.Post("/api/v1/guaranteed-state/push", push.dump());
    REQUIRE(res);
    CHECK(res->status == 202);

    REQUIRE(h.audit_log.size() == 1);
    const auto& push_audit = h.audit_log[0];
    CHECK(push_audit.action == "guaranteed_state.push");
    CHECK(push_audit.result == "success");
    // Control bytes (CR/LF/NUL/TAB and the rest of C0) are dropped entirely
    // so no visual line-split survives the round-trip.
    const auto& d = push_audit.detail;
    CHECK(d.find("\r") == std::string::npos);
    CHECK(d.find("\n") == std::string::npos);
    CHECK(d.find("\t") == std::string::npos);
    CHECK(d.find('\0') == std::string::npos);
    // Quotes inside the attacker-controlled value are backslash-escaped so
    // SIEM parsers that tokenise on quoted strings see them inside the
    // scope value, not as delimiters.
    CHECK(d.find("\\\"") != std::string::npos);
    // Backslashes are doubled so they cannot escape the closing scope
    // delimiter.
    CHECK(d.find("bar\\\\") != std::string::npos);
    // The original adversarial payload's injected fields do not appear as
    // unescaped top-level tokens in the detail string.
    CHECK(d.find(" result=\"denied\"") == std::string::npos);
    CHECK(d.find(" injected=\"yes\"") == std::string::npos);
    // The structural frame of the detail is intact.
    CHECK(d.find("rules=0") != std::string::npos);
    CHECK(d.find("full_sync=false") != std::string::npos);
    CHECK(d.find("agents=") != std::string::npos);
}

TEST_CASE("REST gs.events: filter + limit pagination", "[pg][rest][guaranteed_state][events]") {
    RestGsHarness h;
    GuaranteedStateEventRow ev;
    ev.event_id = "e-1";
    ev.rule_id = "r-001";
    ev.agent_id = "agent-A";
    ev.event_type = "drift.detected";
    ev.severity = "high";
    ev.guard_type = "registry";
    ev.guard_category = "event";
    ev.detected_value = "0";
    ev.expected_value = "1";
    ev.timestamp = "2026-04-21T00:00:00Z";
    REQUIRE(h.store->insert_event(ev).has_value());

    auto res = h.sink.Get("/api/v1/guaranteed-state/events?rule_id=r-001&limit=10");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    CHECK(j["data"].size() == 1);
    CHECK(j["data"][0]["event_id"].get<std::string>() == "e-1");
}

TEST_CASE("REST gs.events: invalid limit → 400", "[pg][rest][guaranteed_state][events][validation]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/guaranteed-state/events?limit=-7");
    REQUIRE(res);
    CHECK(res->status == 400);
}

// ── SEC-3 regression coverage: agent_id present → scoped_perm_fn, agent_id
// absent → global perm_fn + explicit service-token deny, always audited. ──

TEST_CASE("REST gs.events: agent_id present routes through scoped_perm_fn (right agent, "
          "out-of-scope → 403)",
          "[pg][rest][guaranteed_state][events][rbac]") {
    RestGsHarness h;
    h.deny_scoped_agent = "WS-9";
    auto res = h.sink.Get("/api/v1/guaranteed-state/events?agent_id=WS-9");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.last_scoped_agent_id == "WS-9"); // scoped by the queried device
    CHECK(h.audit_log.empty());              // denied before any audit
}

TEST_CASE("REST gs.events: agent_id present + in-scope → 200, audited dex.device.view",
          "[pg][rest][guaranteed_state][events]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/guaranteed-state/events?agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.last_scoped_agent_id == "WS-1");
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "dex.device.view");
    CHECK(h.audit_log[0].target_type == "Agent"); // unchanged from before this fix
    CHECK(h.audit_log[0].target_id == "WS-1");
}

TEST_CASE("REST gs.events: unwired scoped_perm_fn on an agent_id query → fail-closed 503 (A4)",
          "[pg][rest][guaranteed_state][events][rbac]") {
    RestGsHarness h{/*live_deps=*/true, /*wire_scoped_perm=*/false};
    auto res = h.sink.Get("/api/v1/guaranteed-state/events?agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
    CHECK(j["error"].contains("correlation_id"));
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST gs.events: agent_id too long (>256) → 400, no gate reached",
          "[pg][rest][guaranteed_state][events][validation]") {
    RestGsHarness h;
    const std::string long_id(300, 'a');
    auto res = h.sink.Get("/api/v1/guaranteed-state/events?agent_id=" + long_id);
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.last_scoped_agent_id.empty());
}

TEST_CASE("REST gs.events: agent_id with a control character → 400",
          "[pg][rest][guaranteed_state][events][validation]") {
    RestGsHarness h;
    // %0D%0A → CR LF, closes the audit-log-line-forging hazard the
    // device-compliance route already guards against.
    auto res = h.sink.Get("/api/v1/guaranteed-state/events?agent_id=WS-1%0D%0Aforged");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.last_scoped_agent_id.empty()); // rejected before the gate, like the too-long case
}

TEST_CASE("REST gs.events: NO agent_id (fleet) → 200 for an ordinary global session, NOW audited "
          "(previously silently un-audited — the disclosure-adjacent SEC-3 gap)",
          "[pg][rest][guaranteed_state][events]") {
    RestGsHarness h;
    GuaranteedStateEventRow ev;
    ev.event_id = "e-fleet-1";
    ev.rule_id = "r-001";
    ev.agent_id = "agent-A";
    ev.event_type = "drift.detected";
    ev.severity = "high";
    ev.timestamp = "2026-04-21T00:00:00Z";
    REQUIRE(h.store->insert_event(ev).has_value());

    auto res = h.sink.Get("/api/v1/guaranteed-state/events");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    CHECK(j["data"].size() == 1); // global session still sees the fleet-wide fan-out
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "dex.device.view");
    CHECK(h.audit_log[0].target_type == "GuaranteedState"); // fleet shape, not "Agent"
    CHECK(h.audit_log[0].target_id.empty()); // no single agent — fleet-shaped audit
}

TEST_CASE("REST gs.events: NO agent_id + service-scoped token → 403, no data, not reached the "
          "global perm_fn (SEC-3: require_permission's service branch checks only the "
          "ITServiceOwner role, never the token's own service-tag scope)",
          "[pg][rest][guaranteed_state][events][rbac]") {
    RestGsHarness h;
    h.session_token_scope_service = "printers"; // any non-empty service scope
    GuaranteedStateEventRow ev;
    ev.event_id = "e-fleet-2";
    ev.rule_id = "r-001";
    ev.agent_id = "agent-A";
    ev.event_type = "drift.detected";
    ev.severity = "high";
    ev.timestamp = "2026-04-21T00:00:00Z";
    REQUIRE(h.store->insert_event(ev).has_value());

    auto res = h.sink.Get("/api/v1/guaranteed-state/events");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("agent-A") == std::string::npos); // no PII in the denial body
    CHECK(res->body.find("e-fleet-2") == std::string::npos);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 403);
    // No PII was served, but the denial itself IS recorded — a probing service
    // token leaves a trace, not silence (this deny bypasses perm_fn, which
    // would otherwise leave its own auth.permission_required denial row).
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "dex.device.view");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].target_type == "GuaranteedState");
    // This route sets its own X-Correlation-Id before the deny check runs;
    // deny_fleet_wide_service_scoped mints and sets its own on the deny path
    // too. Gate 8 finding (guardian-confinement-2298 branch): confirm the
    // shared helper's erase-then-set actually closes this instance, not just
    // the one that surfaced it.
    CHECK(res->headers.count("X-Correlation-Id") == 1);
}

TEST_CASE("REST gs.events: a service-scoped token MAY still read its own agent via agent_id "
          "(scoped_perm_fn, not the fleet deny, gates the per-device branch)",
          "[pg][rest][guaranteed_state][events]") {
    RestGsHarness h;
    h.session_token_scope_service = "printers";
    auto res = h.sink.Get("/api/v1/guaranteed-state/events?agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 200); // the test double's scoped_perm_fn grants; real
                                // confinement (tag match) is auth_routes' own contract
    CHECK(h.last_scoped_agent_id == "WS-1");
}

// ── Sibling-gap coverage: same vulnerability class as SEC-3, found by
// governance on this branch — /dex/signals/{obs_type}, /dex/perf/devices, and
// /network/devices all served fleet-wide identity-linked per-agent rows under
// a bare global gate, confining nothing for a service-scoped token. ──────────

TEST_CASE("REST dex/signals/{obs_type}: service-scoped token → 403, denial audited",
          "[pg][rest][dex][signals][rbac]") {
    RestGsHarness h;
    h.session_token_scope_service = "printers";
    auto res = h.sink.Get("/api/v1/dex/signals/process.crashed");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "dex.signal.view");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].target_id.empty()); // unvalidated obs_type never embedded
}

TEST_CASE("REST dex/signals/{obs_type}: ordinary session still reaches the route",
          "[pg][rest][dex][signals]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/dex/signals/process.crashed");
    REQUIRE(res);
    CHECK(res->status == 200);
}

TEST_CASE("REST dex/perf/devices: service-scoped token → 403, denial audited",
          "[pg][rest][dex][perf][rbac]") {
    RestGsHarness h;
    h.session_token_scope_service = "printers";
    auto res = h.sink.Get("/api/v1/dex/perf/devices");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "dex.perf.device.view");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].target_type == "GuaranteedState");
    // Same shared-helper erase-then-set fix as gs.events above — this route
    // also pre-sets its own X-Correlation-Id before reaching the deny.
    CHECK(res->headers.count("X-Correlation-Id") == 1);
}

TEST_CASE("REST dex/perf/devices: ordinary session reaches the route, audited success",
          "[pg][rest][dex][perf]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/dex/perf/devices");
    REQUIRE(res);
    CHECK(res->status == 200);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "dex.perf.device.view");
    CHECK(h.audit_log[0].result == "success");
}

TEST_CASE("REST dex/perf/devices: audit-persist failure → 503, no data",
          "[pg][rest][dex][perf]") {
    RestGsHarness h;
    h.audit_succeeds = false;
    auto res = h.sink.Get("/api/v1/dex/perf/devices");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->has_header("Sec-Audit-Failed"));
}

TEST_CASE("REST network/devices: service-scoped token → 403, denial audited",
          "[pg][rest][network][rbac]") {
    RestGsHarness h;
    h.session_token_scope_service = "printers";
    auto res = h.sink.Get("/api/v1/network/devices");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "network.device.view");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].target_type == "GuaranteedState");
}

TEST_CASE("REST network/devices: ordinary session reaches the route, audited success",
          "[pg][rest][network]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/network/devices");
    REQUIRE(res);
    CHECK(res->status == 200);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "network.device.view");
    CHECK(h.audit_log[0].result == "success");
}

TEST_CASE("REST network/devices: audit-persist failure → 503, no data",
          "[pg][rest][network]") {
    RestGsHarness h;
    h.audit_succeeds = false;
    auto res = h.sink.Get("/api/v1/network/devices");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->has_header("Sec-Audit-Failed"));
}

// ── BLOCKING finding, external review (PR #3156): Guardian rule CRUD +
// push carried no service-scoped deny at all - ITServiceOwner holds full
// CRUD on GuaranteedState plus an explicit Push grant, so a service-scoped
// token could read/author/delete rules and push the active rule set
// (full_sync) fleet-wide, outside its own service. Push is the single most
// severe instance of the guardian-confinement-2298 class: it mutates what
// every OTHER service's agents enforce. ──────────────────────────────────

TEST_CASE("REST gs.rules list: service-scoped token → 403, denial audited",
          "[pg][rest][guaranteed_state][rules][rbac]") {
    RestGsHarness h;
    h.session_token_scope_service = "printers";
    auto res = h.sink.Get("/api/v1/guaranteed-state/rules");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "guaranteed_state.rule.read");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].target_type == "GuaranteedState");
    CHECK(h.audit_log[0].target_id.empty());
}

TEST_CASE("REST gs.rules list: ordinary session still reaches the route",
          "[pg][rest][guaranteed_state][rules]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/guaranteed-state/rules");
    REQUIRE(res);
    CHECK(res->status == 200);
}

TEST_CASE("REST gs.rules detail: service-scoped token → 403, denial audited with the rule id",
          "[pg][rest][guaranteed_state][rules][rbac]") {
    RestGsHarness h;
    h.session_token_scope_service = "printers";
    auto res = h.sink.Get("/api/v1/guaranteed-state/rules/r-001");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "guaranteed_state.rule.read");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].target_id == "r-001");
}

TEST_CASE("REST gs.rules create: service-scoped token → 403, .permission names Write",
          "[pg][rest][guaranteed_state][rules][rbac]") {
    RestGsHarness h;
    h.session_token_scope_service = "printers";
    auto res = h.sink.Post("/api/v1/guaranteed-state/rules",
                           R"({"rule_id":"r-svc","name":"svc"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["permission"] == "GuaranteedState:Write");
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "guaranteed_state.rule.create");
    CHECK(h.audit_log[0].result == "denied");
}

TEST_CASE("REST gs.rules update: service-scoped token → 403, .permission names Write, "
          "target_id is the rule",
          "[pg][rest][guaranteed_state][rules][rbac]") {
    RestGsHarness h;
    h.session_token_scope_service = "printers";
    auto res = h.sink.Put("/api/v1/guaranteed-state/rules/r-001", R"({"name":"x"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["permission"] == "GuaranteedState:Write");
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "guaranteed_state.rule.update");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].target_id == "r-001");
}

TEST_CASE("REST gs.rules delete: service-scoped token → 403, .permission names Delete",
          "[pg][rest][guaranteed_state][rules][rbac]") {
    RestGsHarness h;
    h.session_token_scope_service = "printers";
    auto res = h.sink.Delete("/api/v1/guaranteed-state/rules/r-001");
    REQUIRE(res);
    CHECK(res->status == 403);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["permission"] == "GuaranteedState:Delete");
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "guaranteed_state.rule.delete");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].target_id == "r-001");
}

TEST_CASE("REST gs.push: service-scoped token → 403, .permission names Push (the most severe "
          "instance of this class - a fleet-wide full_sync push)",
          "[pg][rest][guaranteed_state][push][rbac]") {
    RestGsHarness h;
    h.session_token_scope_service = "printers";
    auto res = h.sink.Post("/api/v1/guaranteed-state/push", R"({})");
    REQUIRE(res);
    CHECK(res->status == 403);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["permission"] == "GuaranteedState:Push");
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "guaranteed_state.push");
    CHECK(h.audit_log[0].result == "denied");
}

TEST_CASE("REST gs.status: returns store rule_count rollup", "[pg][rest][guaranteed_state][status]") {
    RestGsHarness h;
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      RestGsHarness::make_rule_body("r-001", "rule-a"))
                ->status == 201);

    auto res = h.sink.Get("/api/v1/guaranteed-state/status", h.status_route_headers());
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["total_rules"].get<int>() == 1);
    // Field names match the agent-side proto GuaranteedStateStatus so REST and
    // proto schemas don't diverge when PR 4 wires real aggregation (BL-7 /
    // consistency-auditor F1). Previously emitted `compliant`/`drifted`/`errored`.
    CHECK(j["data"].contains("compliant_rules"));
    CHECK(j["data"].contains("drifted_rules"));
    CHECK(j["data"].contains("errored_rules"));
    CHECK_FALSE(j["data"].contains("compliant"));
    CHECK_FALSE(j["data"].contains("drifted"));
    CHECK_FALSE(j["data"].contains("errored"));
    // No census rows yet — the M1 census-derived count (#2298 item 6d) is honestly 0,
    // not a placeholder 0.
    CHECK(j["data"]["errored_rules"].get<int>() == 0);
}

TEST_CASE("REST gs.status: errored_rules is real, census-derived and DISTINCT-rule counted",
          "[pg][rest][guaranteed_state][status]") {
    // #2298 item 6d. Two agents share one errored rule (counted ONCE — distinct
    // rule_ids, not devices/rows); a second rule is errored on only one agent; a
    // third rule is compliant and must not contribute. compliant_rules/drifted_rules
    // stay the documented placeholder 0. Rules seeded first — errored_rules is
    // intersected against the live catalogue (adversarial-review finding).
    RestGsHarness h;
    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules", RestGsHarness::make_rule_body("r1", "rule-1"))
                ->status == 201);
    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules", RestGsHarness::make_rule_body("r2", "rule-2"))
                ->status == 201);
    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules", RestGsHarness::make_rule_body("r3", "rule-3"))
                ->status == 201);
    h.seed_status("e1", "WS-1", "r1", "guard.unhealthy", "2026-06-20T10:00:00Z");
    h.seed_status("e2", "WS-2", "r1", "guard.unhealthy", "2026-06-20T10:00:00Z");
    h.seed_status("e3", "WS-1", "r2", "guard.unhealthy", "2026-06-20T10:00:00Z");
    h.seed_status("e4", "WS-1", "r3", "guard.compliant", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/status", h.status_route_headers());
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["errored_rules"].get<int>() == 2); // r1 (once) + r2
    CHECK(j["data"]["compliant_rules"].get<int>() == 0);
    CHECK(j["data"]["drifted_rules"].get<int>() == 0);
    CHECK(j["data"]["total_rules"].get<int>() == 3);
}

TEST_CASE("REST gs.status: an errored census row for a DELETED rule is excluded (not counted)",
          "[pg][rest][guaranteed_state][status]") {
    // Adversarial-review finding: delete_rule's own status-table cleanup is
    // explicitly best-effort (no changes-count check, warn-only on failure) with no
    // FK — so a census row can outlive its rule. errored_rules must intersect
    // against the live catalogue, or a deleted rule inflates the count forever.
    RestGsHarness h;
    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules", RestGsHarness::make_rule_body("r-live", "live"))
                ->status == 201);
    h.seed_status("e1", "WS-1", "r-live", "guard.unhealthy", "2026-06-20T10:00:00Z");
    // r-orphan has a census row but was NEVER created as a rule (models the
    // best-effort-cleanup-failed / late-event-after-delete case without needing to
    // race the actual delete path).
    h.seed_status("e2", "WS-1", "r-orphan", "guard.unhealthy", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/status", h.status_route_headers());
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["errored_rules"].get<int>() == 1); // r-live only
    CHECK(j["data"]["total_rules"].get<int>() == 1);
}

TEST_CASE("REST gs.status: an unwired list_read_fn fails closed (503, mirrors "
          "wire_scoped_perm=false on the per-device route)",
          "[pg][rest][guaranteed_state][status]") {
    RestGsHarness h(/*live_deps=*/true, /*wire_scoped_perm=*/true, /*wire_app_perf=*/true,
                    /*with_exec_visible=*/true, /*resp_pool=*/nullptr,
                    /*wire_list_read_fn=*/false);
    auto res = h.sink.Get("/api/v1/guaranteed-state/status", h.status_route_headers());
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("REST gs.status: a service-scoped token is denied outright (World-A / ADR-0017)",
          "[pg][rest][guaranteed_state][status]") {
    // Adversarial-review finding: require_permission's service-scoped-token branch
    // checks only the ITServiceOwner role, never the token's own service tag scope —
    // so a bare perm_fn pass alone would let a token scoped to one service read the
    // fleet-wide aggregate. require_list_read (the route's SOLE gate since the #3038
    // fix) denies a service-scoped token outright, regardless of role. A REAL token
    // now — this route resolves its own session from headers via list_read_fn, so a
    // stub session has no way to carry a service scope onto it.
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/guaranteed-state/status",
                          h.service_scoped_token_headers("printers"));
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("errored_rules") == std::string::npos);
    // KNOWN GAP, stated honestly rather than cited against coverage that
    // doesn't exist: this test does NOT assert on require_list_read's own
    // audit row (AuthRoutes::audit_log, action "auth.permission_required")
    // — this harness's audit_log vector is fed by a SEPARATE stub audit_fn
    // used by every OTHER route, which the fleet route no longer calls.
    // test_auth_list_read_gate.cpp's ladder tests ALSO don't assert audit
    // content (they construct AuthRoutes with audit_store=nullptr, a no-op
    // audit sink) — asserting real audit-row content here would need a
    // real PG-backed AuditStore wired into this harness's auth_routes_
    // (mirrors test_authz_topology_floor.cpp's FloorFixture), not yet done.
}

// ── ADR-0017 authorize_list_read confinement on the fleet route (adversarial-
// review + second-opinion finding: this was previously a bare perm_fn gate, a
// policy-floor violation of the routed-concern MUST/never clause, independent
// of exploitability — CLAUDE.md severity rule 2). Rewritten (#3038 correction)
// to route through the REAL AuthRoutes::require_list_read gate via
// list_read_fn — the composition bug in the first fix attempt (perm_fn
// stacked with a direct authorize_list_read call) shipped BECAUSE the stub
// perm_fn used elsewhere in this harness unconditionally granted, so it never
// exercised the actual require_permission/authorize_list_read interaction.
// See status_route_headers()'s doc comment. ─────────────────────────────────

TEST_CASE("REST gs.status: no GuaranteedState:Read grant anywhere denies with 403 (DenyAll)",
          "[pg][rest][guaranteed_state][status][adr0017]") {
    RestGsHarness h;
    h.rbac_.set_rbac_enabled(true); // enforcement in effect; no roles/grants created
    h.session_user = "nobody";

    auto res = h.sink.Get("/api/v1/guaranteed-state/status", h.status_route_headers());
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("errored_rules") == std::string::npos);
}

TEST_CASE("REST gs.status: an elevated session is admitted unfiltered without any RBAC grant "
          "(SEC-7 regression pinned at the route surface where it shipped)",
          "[pg][rest][guaranteed_state][status][adr0017]") {
    RestGsHarness h;
    h.rbac_.set_rbac_enabled(true); // enforcement in effect; no roles/grants created
    h.session_user = "elevated_user";

    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules", RestGsHarness::make_rule_body("r1", "rule-1"))
                ->status == 201);
    h.seed_status("e1", "WS-1", "r1", "guard.unhealthy", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/status", h.elevated_status_route_headers());
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    // Elevation is unfiltered fleet-wide, despite zero RBAC grants.
    CHECK(j["data"]["errored_rules"].get<int>() == 1);
    CHECK(j["data"]["total_rules"].get<int>() == 1);
}

TEST_CASE("REST gs.status: a global GuaranteedState:Read grant sees the unfiltered fleet count "
          "(AdmitAll)",
          "[pg][rest][guaranteed_state][status][adr0017]") {
    RestGsHarness h;
    h.rbac_.set_rbac_enabled(true);
    REQUIRE(h.rbac_.create_role({"GsReader", "", false, 0}).has_value());
    REQUIRE(h.rbac_.set_permission({"GsReader", "GuaranteedState", "Read", "allow"}).has_value());
    REQUIRE(h.rbac_.assign_role({"user", "alice", "GsReader"}).has_value()); // GLOBAL grant
    h.session_user = "alice";

    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules", RestGsHarness::make_rule_body("r1", "rule-1"))
                ->status == 201);
    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules", RestGsHarness::make_rule_body("r2", "rule-2"))
                ->status == 201);
    h.seed_status("e1", "WS-1", "r1", "guard.unhealthy", "2026-06-20T10:00:00Z");
    h.seed_status("e2", "WS-2", "r2", "guard.unhealthy", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/status", h.status_route_headers());
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    // A global grant is unfiltered fleet-wide - both agents' errored rules count.
    CHECK(j["data"]["errored_rules"].get<int>() == 2);
    CHECK(j["data"]["total_rules"].get<int>() == 2);
}

TEST_CASE("REST gs.status: a management-group-confined grant scopes errored_rules to visible "
          "agents only (AdmitScoped) — proves the two gates now COMPOSE, the exact bug the "
          "first #3038 fix attempt shipped (a confined caller was 403'd by perm_fn before "
          "authorize_list_read was ever reached)",
          "[pg][rest][guaranteed_state][status][adr0017]") {
    RestGsHarness h;
    h.rbac_.set_rbac_enabled(true);
    REQUIRE(h.rbac_.create_role({"GsReader", "", false, 0}).has_value());
    REQUIRE(h.rbac_.set_permission({"GsReader", "GuaranteedState", "Read", "allow"}).has_value());

    ManagementGroup g;
    g.name = "RegionA";
    g.membership_type = "static";
    auto gid = h.mgmt_.create_group(g);
    REQUIRE(gid.has_value());
    REQUIRE(h.mgmt_.add_member(*gid, "WS-1").has_value()); // WS-1 visible; WS-2 is not
    // Group-SCOPED grant, deliberately NOT a global RbacStore::assign_role - carol
    // can see only what RegionA can see. carol has NO global grant of any kind, so
    // the old (broken) perm_fn-stacked-with-authorize_list_read shape would have
    // denied her 403 before authorize_list_read ever ran.
    REQUIRE(h.mgmt_.assign_role({*gid, "user", "carol", "GsReader"}).has_value());
    h.session_user = "carol";

    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules", RestGsHarness::make_rule_body("r1", "rule-1"))
                ->status == 201);
    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules", RestGsHarness::make_rule_body("r2", "rule-2"))
                ->status == 201);
    h.seed_status("e1", "WS-1", "r1", "guard.unhealthy", "2026-06-20T10:00:00Z"); // visible
    h.seed_status("e2", "WS-2", "r2", "guard.unhealthy", "2026-06-20T10:00:00Z"); // NOT visible

    auto res = h.sink.Get("/api/v1/guaranteed-state/status", h.status_route_headers());
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    // Only r1 (reported by the visible agent WS-1) counts - WS-2's r2 is out of scope.
    CHECK(j["data"]["errored_rules"].get<int>() == 1);
    // total_rules is NEVER confined - it is the global rule-catalogue size, which has
    // no agent/management-group dimension (a rule isn't owned by a group).
    CHECK(j["data"]["total_rules"].get<int>() == 2);
}

TEST_CASE("REST gs.status: AdmitScoped with zero visible agents contributes nothing (INV-2)",
          "[pg][rest][guaranteed_state][status][adr0017]") {
    RestGsHarness h;
    h.rbac_.set_rbac_enabled(true);
    REQUIRE(h.rbac_.create_role({"GsReader", "", false, 0}).has_value());
    REQUIRE(h.rbac_.set_permission({"GsReader", "GuaranteedState", "Read", "allow"}).has_value());

    ManagementGroup g;
    g.name = "EmptyRegion";
    g.membership_type = "static";
    auto gid = h.mgmt_.create_group(g);
    REQUIRE(gid.has_value());
    // No members added - dana's group is real and her grant is real, but it contains
    // no agents.
    REQUIRE(h.mgmt_.assign_role({*gid, "user", "dana", "GsReader"}).has_value());
    h.session_user = "dana";

    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules", RestGsHarness::make_rule_body("r1", "rule-1"))
                ->status == 201);
    h.seed_status("e1", "WS-1", "r1", "guard.unhealthy", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/status", h.status_route_headers());
    REQUIRE(res);
    // AdmitScoped with an empty visible set is 200 + zero, not a 403 - the caller has a
    // real grant, it simply resolves to no visible agents (INV-2).
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["errored_rules"].get<int>() == 0);
    CHECK(j["data"]["total_rules"].get<int>() == 1); // unaffected - global catalogue size
}

// ── #2298 item 6d: per-agent status route (previously untested at REST level) ──

TEST_CASE("REST gs.status/{agent_id}: errored_rules is real, scoped to this agent's census",
          "[pg][rest][guaranteed_state][status]") {
    RestGsHarness h;
    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules", RestGsHarness::make_rule_body("r1", "rule-1"))
                ->status == 201);
    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules", RestGsHarness::make_rule_body("r2", "rule-2"))
                ->status == 201);
    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules", RestGsHarness::make_rule_body("r3", "rule-3"))
                ->status == 201);
    h.seed_status("e1", "WS-1", "r1", "guard.unhealthy", "2026-06-20T10:00:00Z");
    h.seed_status("e2", "WS-1", "r2", "guard.compliant", "2026-06-20T10:00:00Z");
    // A different agent's errored rule must NOT leak into WS-1's count.
    h.seed_status("e3", "WS-2", "r3", "guard.unhealthy", "2026-06-20T10:00:00Z");
    h.audit_log.clear(); // drop the 3 rule.create audit rows from setup above

    auto res = h.sink.Get("/api/v1/guaranteed-state/status/WS-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["agent_id"].get<std::string>() == "WS-1");
    // total_rules = census rows for THIS agent (r1 + r2), not the fleet catalogue.
    CHECK(j["data"]["total_rules"].get<int>() == 2);
    CHECK(j["data"]["errored_rules"].get<int>() == 1);
    CHECK(j["data"]["compliant_rules"].get<int>() == 0);
    CHECK(j["data"]["drifted_rules"].get<int>() == 0);
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    // Audited as guardian.device.view — same verb as GET /guaranteed-state/device-
    // compliance and GET /dex/devices/{id}, so a works-council evidence review finds
    // one verb per read pattern, not a fork.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "guardian.device.view");
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].target_id == "WS-1");
}

TEST_CASE("REST gs.status/{agent_id}: an errored census row for a DELETED rule is excluded",
          "[pg][rest][guaranteed_state][status]") {
    RestGsHarness h;
    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules", RestGsHarness::make_rule_body("r-live", "live"))
                ->status == 201);
    h.seed_status("e1", "WS-1", "r-live", "guard.unhealthy", "2026-06-20T10:00:00Z");
    h.seed_status("e2", "WS-1", "r-orphan", "guard.unhealthy", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/status/WS-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["total_rules"].get<int>() == 1);
    CHECK(j["data"]["errored_rules"].get<int>() == 1);
}

TEST_CASE("REST gs.status/{agent_id}: per-device scope denies an out-of-scope caller",
          "[pg][rest][guaranteed_state][status]") {
    // World-A / ADR-0017: this route now serves real per-agent data, so it must be
    // confined the same way GET /guaranteed-state/device-compliance is — a bare
    // global perm_fn would be exactly the confinement gap that concern forbids.
    // NOTE: this proves the ROUTE calls scoped_perm_fn with the right agent_id and
    // honors its denial — it does NOT exercise the real RBAC/ManagementGroupStore
    // composition (see the two [adr0017] tests below for that).
    RestGsHarness h;
    h.deny_scoped_agent = "WS-9";
    h.seed_status("e1", "WS-9", "r1", "guard.unhealthy", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/status/WS-9");
    REQUIRE(res);
    CHECK(res->status == 403);
    // The route scoped by the right device before denying.
    CHECK(h.last_scoped_agent_id == "WS-9");
    // No data leaked in a denial.
    CHECK(res->body.find("errored_rules") == std::string::npos);
}

TEST_CASE("REST gs.status/{agent_id}: a management-group-confined grant that does NOT cover "
          "the target device is denied by the REAL scoped gate (not a stand-in) — PR #3175 "
          "review gap: this route's cross-management-group denial was previously only proven "
          "against a local string-match stub, never AuthRoutes::require_scoped_permission",
          "[pg][rest][guaranteed_state][status][adr0017]") {
    // WS-9 is a member of a REAL group carol has no grant on (RegionB), not of
    // NO group at all — a security-guardian re-review of the original version
    // of this test (WS-9 in zero groups) found it denied via
    // check_scoped_permission's empty-membership early-return
    // (rbac_store.cpp's `reachable.empty()` short-circuit) WITHOUT ever
    // reaching the allow/deny-group intersection that is the actual
    // cross-group boundary this test exists to prove — a regression in that
    // intersection logic (e.g. an inverted contains() check) would have left
    // this test exactly as green. Giving WS-9 a real, resolvable, but
    // unauthorized group membership forces the denial through the
    // intersection path instead.
    RestGsHarness h;
    h.wire_real_gs_scoped_perm_ = true;
    // Ordinary (non-admin) role — the point is to prove the RBAC/management-
    // group grant itself is what's evaluated, not the harness's default
    // legacy-admin session_role (which would pass independently of RBAC).
    h.session_role = auth::Role::user;
    h.rbac_.set_rbac_enabled(true);
    REQUIRE(h.rbac_.create_role({"GsReader", "", false, 0}).has_value());
    REQUIRE(h.rbac_.set_permission({"GsReader", "GuaranteedState", "Read", "allow"}).has_value());

    ManagementGroup ga;
    ga.name = "RegionA";
    ga.membership_type = "static";
    auto gida = h.mgmt_.create_group(ga);
    REQUIRE(gida.has_value());
    REQUIRE(h.mgmt_.add_member(*gida, "WS-1").has_value());
    REQUIRE(h.mgmt_.assign_role({*gida, "user", "carol", "GsReader"}).has_value());

    ManagementGroup gb;
    gb.name = "RegionB";
    gb.membership_type = "static";
    auto gidb = h.mgmt_.create_group(gb);
    REQUIRE(gidb.has_value());
    REQUIRE(h.mgmt_.add_member(*gidb, "WS-9").has_value()); // real membership, no grant on it
    h.session_user = "carol";
    h.seed_status("e1", "WS-9", "r1", "guard.unhealthy", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/status/WS-9", h.status_route_headers());
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("errored_rules") == std::string::npos);
    // The route scoped by the right device before the real gate denied.
    CHECK(h.last_scoped_agent_id == "WS-9");
}

TEST_CASE("REST gs.status/{agent_id}: a management-group-confined grant that DOES cover the "
          "target device is admitted by the REAL scoped gate",
          "[pg][rest][guaranteed_state][status][adr0017]") {
    RestGsHarness h;
    h.wire_real_gs_scoped_perm_ = true;
    h.session_role = auth::Role::user; // see the negative test above for why
    h.rbac_.set_rbac_enabled(true);
    REQUIRE(h.rbac_.create_role({"GsReader", "", false, 0}).has_value());
    REQUIRE(h.rbac_.set_permission({"GsReader", "GuaranteedState", "Read", "allow"}).has_value());

    ManagementGroup g;
    g.name = "RegionA";
    g.membership_type = "static";
    auto gid = h.mgmt_.create_group(g);
    REQUIRE(gid.has_value());
    REQUIRE(h.mgmt_.add_member(*gid, "WS-1").has_value()); // WS-1 IS a member
    REQUIRE(h.mgmt_.assign_role({*gid, "user", "carol", "GsReader"}).has_value());
    h.session_user = "carol";
    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules", RestGsHarness::make_rule_body("r1", "rule-1"))
                ->status == 201);
    h.seed_status("e1", "WS-1", "r1", "guard.unhealthy", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/status/WS-1", h.status_route_headers());
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["errored_rules"].get<int>() == 1);
    CHECK(h.last_scoped_agent_id == "WS-1");
}

TEST_CASE("REST gs.status/{agent_id}: audit persistence failure -> 503, no data served, "
          "Sec-Audit-Failed",
          "[pg][rest][guaranteed_state][status][audit]") {
    RestGsHarness h;
    h.seed_status("e1", "WS-1", "r1", "guard.unhealthy", "2026-06-20T10:00:00Z");
    h.audit_succeeds = false; // the audit row cannot persist (DB locked/full/corrupt)

    auto res = h.sink.Get("/api/v1/guaranteed-state/status/WS-1");
    REQUIRE(res);
    // FAIL-CLOSED: per-device Guardian state must not be served when the evidence row
    // is known to have been lost (SOC 2 CC7.2 / works-council) — same posture as GET
    // /guaranteed-state/device-compliance and GET /dex/devices/{id}.
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    CHECK(res->body.find("errored_rules") == std::string::npos);
}

TEST_CASE("REST gs.alerts: empty list placeholder", "[pg][rest][guaranteed_state][alerts]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/guaranteed-state/alerts");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    CHECK(j["data"].empty());
}

// ── C3b: structured authoring + resilience validation + schema discovery ─────

namespace {
// A full structured Guard body (spark + assertion + remediation). `resilience`
// is the remediation.params object carrying the C3b resilience policy.
std::string make_structured_body(const std::string& rule_id, const std::string& name,
                                 const std::string& remediation_type, nlohmann::json resilience) {
    nlohmann::json j;
    j["rule_id"] = rule_id;
    j["name"] = name;
    j["enforcement_mode"] = "enforce";
    j["severity"] = "high";
    j["spark"] = {{"type", "registry-change"}, {"params", nlohmann::json::object()}};
    j["assertion"] = {{"type", "registry-value-equals"},
                      {"params",
                       {{"hive", "HKLM"},
                        {"key", "SOFTWARE\\YuzuTest"},
                        {"value_name", "Flag"},
                        {"value_type", "REG_DWORD"},
                        {"expected", "1"}}}};
    j["remediation"] = {{"type", remediation_type}, {"params", std::move(resilience)}};
    return j.dump();
}
} // namespace

TEST_CASE("REST gs.rules: structured create validates + canonicalises resilience params",
          "[pg][rest][guaranteed_state][create][resilience]") {
    RestGsHarness h;
    auto res = h.sink.Post(
        "/api/v1/guaranteed-state/rules",
        make_structured_body("r-res", "bounded-guard", "enforce",
                             {{"mode", "BOUNDED"}, {"max_attempts", 3}}));
    REQUIRE(res);
    CHECK(res->status == 201);

    auto stored = h.store->get_rule("r-res");
    REQUIRE(stored.has_value());
    REQUIRE(stored->has_value());
    REQUIRE_FALSE((*stored)->spec_json.empty());
    auto spec = nlohmann::json::parse((*stored)->spec_json);
    const auto& params = spec["remediation"]["params"];
    // Canonical-out: mode lowercased, numeric stored as a decimal string.
    CHECK(params["mode"].get<std::string>() == "bounded");
    CHECK(params["max_attempts"].get<std::string>() == "3");
}

TEST_CASE("REST gs.rules: invalid resilience params → 400 A4 envelope + denied audit",
          "[pg][rest][guaranteed_state][create][resilience][validation]") {
    RestGsHarness h;
    auto res = h.sink.Post(
        "/api/v1/guaranteed-state/rules",
        make_structured_body("r-bad", "bad-guard", "enforce",
                             {{"mode", "bounded"}, {"max_attempts", 0}})); // 0 invalid
    REQUIRE(res);
    CHECK(res->status == 400);
    auto j = nlohmann::json::parse(res->body);
    // A4 envelope shape (contract decision 3).
    REQUIRE(j.contains("error"));
    CHECK(j["error"]["code"].get<int>() == 400);
    CHECK(j["error"].contains("correlation_id"));
    CHECK(j["error"].contains("remediation"));
    CHECK(j["meta"]["api_version"].get<std::string>() == "v1");
    // Rule not persisted; reject audited. Three-state (ADR-0038): the outer
    // expected still has_value() (the read succeeded) — not-persisted is the
    // INNER optional being empty.
    auto not_persisted = h.store->get_rule("r-bad");
    REQUIRE(not_persisted.has_value());
    CHECK_FALSE(not_persisted->has_value());
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "guaranteed_state.rule.create");
    CHECK(h.audit_log[0].result == "denied");
}

TEST_CASE("REST gs.rules: PUT re-authors structured spec (no silent drop)",
          "[pg][rest][guaranteed_state][crud][resilience]") {
    RestGsHarness h;
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      make_structured_body("r-edit", "edit-guard", "enforce",
                                           {{"mode", "persist"}}))
                ->status == 201);

    // Tune the resilience policy via PUT — the pre-C3b PUT returned 200 but
    // silently dropped structured blocks. Now it must re-derive the spec.
    auto upd = h.sink.Put("/api/v1/guaranteed-state/rules/r-edit",
                          make_structured_body("r-edit", "edit-guard", "enforce",
                                               {{"mode", "bounded"}, {"max_attempts", 2}}));
    REQUIRE(upd);
    CHECK(upd->status == 200);

    auto stored = h.store->get_rule("r-edit");
    REQUIRE(stored.has_value());
    REQUIRE(stored->has_value());
    auto spec = nlohmann::json::parse((*stored)->spec_json);
    CHECK(spec["remediation"]["params"]["mode"].get<std::string>() == "bounded");
    CHECK(spec["remediation"]["params"]["max_attempts"].get<std::string>() == "2");
    CHECK((*stored)->version == 2);
}

TEST_CASE("REST gs.rules: PUT with an incomplete structured body → 400 (not silently dropped)",
          "[pg][rest][guaranteed_state][crud][resilience]") {
    RestGsHarness h;
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      RestGsHarness::make_rule_body("r-meta", "meta-guard"))
                ->status == 201);
    // A remediation block with no spark/assertion is an incomplete structured
    // edit — rejected explicitly rather than 200-and-drop.
    nlohmann::json partial;
    partial["remediation"] = {{"type", "enforce"}, {"params", {{"mode", "bounded"}}}};
    auto upd = h.sink.Put("/api/v1/guaranteed-state/rules/r-meta", partial.dump());
    REQUIRE(upd);
    CHECK(upd->status == 400);
    auto j = nlohmann::json::parse(upd->body);
    CHECK(j["error"]["message"].get<std::string>().find("spark") != std::string::npos);
}

TEST_CASE("REST gs.rules: metadata-only PUT preserves the existing structured spec",
          "[pg][rest][guaranteed_state][crud][resilience]") {
    RestGsHarness h;
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      make_structured_body("r-keep", "keep-guard", "enforce",
                                           {{"mode", "backoff"}, {"backoff_initial_ms", 500}}))
                ->status == 201);
    // Toggle enabled only — must not wipe spec_json.
    nlohmann::json meta;
    meta["enabled"] = false;
    auto upd = h.sink.Put("/api/v1/guaranteed-state/rules/r-keep", meta.dump());
    REQUIRE(upd);
    CHECK(upd->status == 200);
    auto stored = h.store->get_rule("r-keep");
    REQUIRE(stored.has_value());
    REQUIRE(stored->has_value());
    REQUIRE_FALSE((*stored)->spec_json.empty());
    auto spec = nlohmann::json::parse((*stored)->spec_json);
    CHECK(spec["remediation"]["params"]["mode"].get<std::string>() == "backoff");
}

// json-dump-depth-guard fix (#2437-class): derive_rule_spec's spec.dump() has
// no depth guard on the raw caller-supplied spark/assertion/remediation
// blocks it copies verbatim. Both the create and update handlers now check
// the raw request body text before any parse. A raw string, never
// materialised as a live nlohmann::json object at this depth: kMcpMaxJsonDepth
// is 32, the 35-deep bracket chain below is comfortably past it and still
// trivially safe to construct/parse directly in this test process, orders of
// magnitude short of the ~100,000-level depth that actually SIGSEGVs the real
// spec.dump() call this guard exists to prevent.
TEST_CASE("REST gs.rules: create rejects a request body nested past the depth "
          "guard, no row created",
          "[pg][rest][guaranteed_state][create][security][depth]") {
    RestGsHarness h;
    const std::string body =
        R"({"rule_id":"r-deep","name":"deep-guard","enforcement_mode":"enforce",)"
        R"("severity":"high","spark":{"type":"registry-change","params":{}},)"
        R"("assertion":{"type":"registry-value-equals","params":{"hive":"HKLM",)"
        R"("key":"SOFTWARE\\YuzuTest","value_name":"Flag","value_type":"REG_DWORD",)"
        R"("expected":"1","nested":)" +
        std::string(35, '[') + std::string(35, ']') +
        R"(}},"remediation":{"type":"alert-only","params":{}}})";
    auto res = h.sink.Post("/api/v1/guaranteed-state/rules", body);
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->body.find("nests too deeply") != std::string::npos);

    // Three-state (ADR-0038): the outer expected still has_value() (the read
    // succeeded); not-created is the INNER optional being empty.
    auto not_persisted = h.store->get_rule("r-deep");
    REQUIRE(not_persisted.has_value());
    CHECK_FALSE(not_persisted->has_value());
    // Pre-parse rejection: rule_id is not yet known, so this mirrors the
    // create handler's own "invalid JSON" sibling branch (no audit call),
    // not the enforcement_mode/spec.error branches (which do audit).
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST gs.rules: create with a normal, safely-nested structured body "
          "still succeeds (happy path unaffected)",
          "[pg][rest][guaranteed_state][create][security][depth]") {
    RestGsHarness h;
    auto res = h.sink.Post(
        "/api/v1/guaranteed-state/rules",
        make_structured_body("r-safe", "safe-guard", "enforce", {{"mode", "persist"}}));
    REQUIRE(res);
    CHECK(res->status == 201);
    auto stored = h.store->get_rule("r-safe");
    REQUIRE(stored.has_value());
    REQUIRE(stored->has_value());
    CHECK_FALSE((*stored)->spec_json.empty());
}

TEST_CASE("REST gs.rules: PUT rejects a request body nested past the depth "
          "guard, existing row unchanged",
          "[pg][rest][guaranteed_state][crud][security][depth]") {
    RestGsHarness h;
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      make_structured_body("r-edit-deep", "edit-deep-guard", "enforce",
                                           {{"mode", "persist"}}))
                ->status == 201);
    auto before = h.store->get_rule("r-edit-deep");
    REQUIRE(before.has_value());
    REQUIRE(before->has_value());
    const auto version_before = (*before)->version;
    const auto spec_before = (*before)->spec_json;

    const std::string body =
        R"({"name":"edit-deep-guard","spark":{"type":"registry-change","params":{}},)"
        R"("assertion":{"type":"registry-value-equals","params":{"hive":"HKLM",)"
        R"("key":"SOFTWARE\\YuzuTest","value_name":"Flag","value_type":"REG_DWORD",)"
        R"("expected":"1","nested":)" +
        std::string(35, '[') + std::string(35, ']') +
        R"(}},"remediation":{"type":"alert-only","params":{}}})";
    auto upd = h.sink.Put("/api/v1/guaranteed-state/rules/r-edit-deep", body);
    REQUIRE(upd);
    CHECK(upd->status == 400);
    CHECK(upd->body.find("nests too deeply") != std::string::npos);

    auto after = h.store->get_rule("r-edit-deep");
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK((*after)->version == version_before);
    CHECK((*after)->spec_json == spec_before);

    // Update's invalid-body sibling branch DOES audit (UP-R1 parity), so the
    // depth-guard rejection matches that, not the create handler's silent one.
    REQUIRE(h.audit_log.size() == 2); // create + denied update
    CHECK(h.audit_log[1].action == "guaranteed_state.rule.update");
    CHECK(h.audit_log[1].result == "denied");
    CHECK(h.audit_log[1].target_id == "r-edit-deep");
    CHECK(h.audit_log[1].detail.find("nests too deeply") != std::string::npos);
}

TEST_CASE("REST gs.rules: PUT with a normal, safely-nested structured body "
          "still succeeds (happy path unaffected)",
          "[pg][rest][guaranteed_state][crud][security][depth]") {
    RestGsHarness h;
    REQUIRE(h.sink
                .Post("/api/v1/guaranteed-state/rules",
                      make_structured_body("r-edit-safe", "edit-safe-guard", "enforce",
                                           {{"mode", "persist"}}))
                ->status == 201);
    auto upd = h.sink.Put("/api/v1/guaranteed-state/rules/r-edit-safe",
                          make_structured_body("r-edit-safe", "edit-safe-guard", "enforce",
                                               {{"mode", "bounded"}, {"max_attempts", 2}}));
    REQUIRE(upd);
    CHECK(upd->status == 200);
    auto stored = h.store->get_rule("r-edit-safe");
    REQUIRE(stored.has_value());
    REQUIRE(stored->has_value());
    CHECK((*stored)->version == 2);
}

TEST_CASE("REST gs.schemas: catalog + ETag revalidation", "[pg][rest][guaranteed_state][schemas]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/guaranteed-state/schemas");
    REQUIRE(res);
    CHECK(res->status == 200);
    const std::string etag = res->get_header_value("ETag");
    CHECK_FALSE(etag.empty());
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j.contains("schemas"));
    CHECK(j["schemas"].is_array());

    // Conditional GET with the matching ETag → 304 Not Modified.
    auto cached = h.sink.Get("/api/v1/guaranteed-state/schemas",
                             {{"If-None-Match", etag}});
    REQUIRE(cached);
    CHECK(cached->status == 304);
}

// ── DEX read-model aggregation surface (/api/v1/dex/*) — ar-S1 agentic parity ─
//
// The audit BOUNDARY is the load-bearing contract: the catalogue rollup and the
// per-OS scope are fleet aggregates and must NOT audit; the per-signal drill-down
// returns a most-affected DEVICES list (agent_ids — behavioral) and MUST emit the
// same dex.signal.view verb the dashboard fragment does. Both halves are asserted.

TEST_CASE("REST dex.signals: catalogue rollup returns seeded signals, NOT audited",
          "[pg][rest][dex][signals]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.seed_obs("o2", "WS-2", "process.crashed", "chrome.exe", "windows", "2026-06-10T11:00:00Z");
    h.seed_obs("o3", "WS-1", "os.boot", "boot", "windows", "2026-06-10T08:00:00Z");

    auto res = h.sink.Get("/api/v1/dex/signals?window=all");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());

    int64_t crashed_count = -1, crashed_devices = -1;
    bool saw_boot = false;
    for (const auto& row : j["data"]) {
        if (row["obs_type"].get<std::string>() == "process.crashed") {
            crashed_count = row["count"].get<int64_t>();
            crashed_devices = row["distinct_devices"].get<int64_t>();
        }
        if (row["obs_type"].get<std::string>() == "os.boot")
            saw_boot = true;
    }
    CHECK(crashed_count == 2);
    CHECK(crashed_devices == 2);
    CHECK(saw_boot);
    // Fleet aggregate — no individual-identifying access, so no audit.
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST dex.signals: os filter scopes the catalogue rollup to one OS (A1 parity)",
          "[pg][rest][dex][signals]") {
    RestGsHarness h;
    h.seed_obs("w1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.seed_obs("m1", "MAC-1", "storage.low", "disk", "macos", "2026-06-10T11:00:00Z");

    // macOS lens: only the macOS-sourced signal type.
    auto mac = h.sink.Get("/api/v1/dex/signals?window=all&os=macos");
    REQUIRE(mac);
    auto jm = nlohmann::json::parse(mac->body);
    bool mac_has_storage = false, mac_has_crashed = false;
    for (const auto& r : jm["data"]) {
        const auto t = r["obs_type"].get<std::string>();
        if (t == "storage.low") mac_has_storage = true;
        if (t == "process.crashed") mac_has_crashed = true;
    }
    CHECK(mac_has_storage);
    CHECK_FALSE(mac_has_crashed); // Windows-sourced signal scoped out

    // No os param = all-OS: both signals present.
    auto all = h.sink.Get("/api/v1/dex/signals?window=all");
    REQUIRE(all);
    auto ja = nlohmann::json::parse(all->body);
    bool all_has_storage = false, all_has_crashed = false;
    for (const auto& r : ja["data"]) {
        const auto t = r["obs_type"].get<std::string>();
        if (t == "storage.low") all_has_storage = true;
        if (t == "process.crashed") all_has_crashed = true;
    }
    CHECK(all_has_storage);
    CHECK(all_has_crashed);
}

TEST_CASE("REST dex/devices/{id}: per-device read model — score + THIS device's signals, audited",
          "[pg][rest][dex][device]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.seed_obs("o2", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T11:00:00Z");
    h.seed_obs("o3", "WS-2", "os.boot", "boot", "windows", "2026-06-10T08:00:00Z"); // other device

    auto res = h.sink.Get("/api/v1/dex/devices/WS-1?window=all");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["agent_id"].get<std::string>() == "WS-1");
    REQUIRE(j["data"]["signals"].is_array());
    bool saw_crashed = false, saw_other = false;
    int64_t crashed_count = -1;
    for (const auto& s : j["data"]["signals"]) {
        if (s["obs_type"].get<std::string>() == "process.crashed") {
            saw_crashed = true;
            crashed_count = s["count"].get<int64_t>();
        }
        if (s["obs_type"].get<std::string>() == "os.boot")
            saw_other = true; // belongs to WS-2
    }
    CHECK(saw_crashed);
    CHECK(crashed_count == 2);
    CHECK_FALSE(saw_other); // WS-2's signal must not leak into WS-1's per-device summary
    // Per-device behavioral read → audited dex.device.view (parity with the lens).
    bool audited = false;
    for (const auto& a : h.audit_log)
        if (a.action == "dex.device.view" && a.target_id == "WS-1")
            audited = true;
    CHECK(audited);
}

// #4855: a degraded signal-summary read must 503, never render a fabricated
// healthy score of 100 with no signals. DROP TABLE on a second connection
// forces a genuine query-level failure while the store stays open (same
// technique the guard/baseline degrade tests in test_guardian_routes.cpp
// use). The audit fires BEFORE the read (unchanged fail-closed ordering), so
// it still records "success" here.
TEST_CASE("REST dex/devices/{id}: a degraded signal-summary read → 503, never a fabricated "
          "healthy score",
          "[pg][rest][dex][device][degraded]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.gs_db_pg->dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE guaranteed_state_store.guardian_observations")};
        REQUIRE(d.ok());
    }

    auto res = h.sink.Get("/api/v1/dex/devices/WS-1?window=all");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->body.find("\"score\"") == std::string::npos); // never a score at all
    bool audited = false;
    for (const auto& a : h.audit_log)
        if (a.action == "dex.device.view" && a.target_id == "WS-1")
            audited = true;
    CHECK(audited);
}

TEST_CASE("OpenAPI lists /dex/devices/{id} and the whole spec still parses",
          "[pg][rest][dex][device][a2]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // A2 discovery: the per-device DEX endpoint is enumerable from the live server.
    REQUIRE(res->body.find(R"("/dex/devices/{id}":)") != std::string::npos);
    // And the embedded spec remains valid JSON after the insertion.
    REQUIRE_NOTHROW(nlohmann::json::parse(res->body));
}

// ═══ #4035 (api-parity #2146 Batch A): the 8 genuinely-new DEX REST twins ═══

TEST_CASE("REST dex/app: blast-radius drill, audited, service-scoped token denied",
          "[pg][rest][dex][app]") {
    RestGsHarness h;
    h.seed_obs("a1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.seed_obs("a2", "WS-2", "process.crashed", "chrome.exe", "windows", "2026-06-10T11:00:00Z");

    auto res = h.sink.Get("/api/v1/dex/app?name=chrome.exe&window=all");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["process_name"].get<std::string>() == "chrome.exe");
    CHECK(j["data"]["crashes"].get<int64_t>() == 2);
    CHECK(j["data"]["distinct_devices"].get<int64_t>() == 2);
    REQUIRE(j["data"]["devices"].is_array());
    CHECK(j["data"]["devices"].size() == 2);
    bool audited = false;
    for (const auto& a : h.audit_log)
        if (a.action == "dex.app.view" && a.result == "success")
            audited = true;
    CHECK(audited);

    // missing required name -> 400
    auto missing = h.sink.Get("/api/v1/dex/app?window=all");
    REQUIRE(missing);
    CHECK(missing->status == 400);

    // service-scoped token -> 403, denied audit only
    RestGsHarness h2;
    h2.session_token_scope_service = "printers";
    auto denied = h2.sink.Get("/api/v1/dex/app?name=chrome.exe");
    REQUIRE(denied);
    CHECK(denied->status == 403);
}

// #4035 hardening (governance): closure evidence for the ADR-0017 World A
// confinement gap — GET /api/v1/dex/app's devices[] list previously ALWAYS
// passed visible=nullptr to the shared builder regardless of the caller's
// management-group scope, unlike its own /fragments/dex/app dashboard
// fragment (which confines via resolve_visible). A management-group-confined
// operator could read affected agent_ids fleet-wide through this route even
// though the equivalent dashboard fragment would have hidden them.
TEST_CASE("REST dex/app: devices[] confined to the caller's visible set "
          "(ADR-0017 World A — regression coverage for the governance fix)",
          "[pg][rest][dex][app][scope]") {
    RestGsHarness h;
    h.seed_obs("s1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.seed_obs("s2", "WS-2", "process.crashed", "chrome.exe", "windows", "2026-06-10T11:00:00Z");

    // Unconfined (default, matches production RBAC-off / global-read): both
    // devices are visible.
    auto unconfined = h.sink.Get("/api/v1/dex/app?name=chrome.exe&window=all");
    REQUIRE(unconfined);
    CHECK(unconfined->status == 200);
    auto uj = nlohmann::json::parse(unconfined->body);
    CHECK(uj["data"]["devices"].size() == 2);

    // Confined to WS-1 only (simulating a management-group-scoped operator):
    // WS-2 must NEVER appear, even though the aggregate crash COUNT still
    // reflects the whole fleet (the SCOPING NOTE's tracked, separate,
    // aggregate-numerator follow-up — not this fix's scope).
    h.dex_visible_override_ = std::set<std::string>{"WS-1"};
    auto confined = h.sink.Get("/api/v1/dex/app?name=chrome.exe&window=all");
    REQUIRE(confined);
    CHECK(confined->status == 200);
    auto cj = nlohmann::json::parse(confined->body);
    REQUIRE(cj["data"]["devices"].is_array());
    CHECK(cj["data"]["devices"].size() == 1);
    CHECK(cj["data"]["devices"][0]["agent_id"].get<std::string>() == "WS-1");
    for (const auto& d : cj["data"]["devices"])
        CHECK(d["agent_id"].get<std::string>() != "WS-2");

    // Confined to a DISJOINT set (simulating an operator with no visibility
    // into either device): devices[] is empty, never a 403/404 — matching
    // the fragment's own admit-then-filter posture (ADR-0017 INV-2: engaged-
    // empty is a legitimate, distinct outcome from "unfiltered").
    h.dex_visible_override_ = std::set<std::string>{};
    auto empty_scope = h.sink.Get("/api/v1/dex/app?name=chrome.exe&window=all");
    REQUIRE(empty_scope);
    CHECK(empty_scope->status == 200);
    auto ej = nlohmann::json::parse(empty_scope->body);
    CHECK(ej["data"]["devices"].empty());
}

TEST_CASE("REST dex/apps: app-centric stability list, no audit (aggregate)",
          "[pg][rest][dex][apps]") {
    RestGsHarness h;
    h.seed_obs("b1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.seed_obs("b2", "WS-2", "process.hung", "notepad.exe", "windows", "2026-06-10T11:00:00Z");

    auto res = h.sink.Get("/api/v1/dex/apps?window=all");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"]["apps"].is_array());
    bool saw_chrome = false;
    for (const auto& a : j["data"]["apps"])
        if (a["subject"].get<std::string>() == "chrome.exe")
            saw_chrome = true;
    CHECK(saw_chrome);
    CHECK(h.audit_log.empty()); // fleet aggregate — no per-agent identity
}

TEST_CASE("REST dex/catalogue/group: family drill, unknown family -> 404, no audit",
          "[pg][rest][dex][catalogue][group]") {
    RestGsHarness h;
    h.seed_obs("c1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");

    auto res = h.sink.Get("/api/v1/dex/catalogue/group?name=" +
                          std::string("App%20reliability") + "&window=all");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["group_name"].get<std::string>() == "App reliability");
    CHECK(j["data"]["total_type_count"].get<int64_t>() > 0);
    CHECK(h.audit_log.empty());

    auto unknown = h.sink.Get("/api/v1/dex/catalogue/group?name=NoSuchFamily");
    REQUIRE(unknown);
    CHECK(unknown->status == 404);

    auto missing = h.sink.Get("/api/v1/dex/catalogue/group");
    REQUIRE(missing);
    CHECK(missing->status == 400);
}

TEST_CASE("REST dex/health: composite score suppressed with no reporting agents, no audit",
          "[pg][rest][dex][health]") {
    RestGsHarness h;
    h.seed_obs("d1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    // No dex_fleet_override_ set -> windows_online stays 0 -> suppressed.
    auto res = h.sink.Get("/api/v1/dex/health?window=all");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["score"].is_null());
    CHECK(j["data"]["reporting"].get<int64_t>() == 0);
    CHECK(h.audit_log.empty());

    // With a reporting fleet, the score is a real number.
    h.dex_fleet_override_.windows_online = 5;
    auto res2 = h.sink.Get("/api/v1/dex/health?window=all");
    REQUIRE(res2);
    auto j2 = nlohmann::json::parse(res2->body);
    CHECK_FALSE(j2["data"]["score"].is_null());
}

TEST_CASE("REST dex/trends: cross-OS + per-family day counts, no audit",
          "[pg][rest][dex][trends]") {
    RestGsHarness h;
    h.seed_obs("e1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    auto res = h.sink.Get("/api/v1/dex/trends?window=all");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"]["families"].is_array());
    REQUIRE(j["data"]["days"].is_array());
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST dex/overview: fleet summary, audited, service-scoped token denied",
          "[pg][rest][dex][overview]") {
    RestGsHarness h;
    h.seed_obs("f1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.seed_obs("f2", "WS-2", "process.crashed", "chrome.exe", "windows", "2026-06-10T11:00:00Z");

    auto res = h.sink.Get("/api/v1/dex/overview?window=all");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"]["top_apps"].is_array());
    bool saw_chrome = false;
    for (const auto& a : j["data"]["top_apps"])
        if (a["subject"].get<std::string>() == "chrome.exe")
            saw_chrome = true;
    CHECK(saw_chrome);
    bool audited = false;
    for (const auto& a : h.audit_log)
        if (a.action == "dex.overview.view" && a.result == "success")
            audited = true;
    CHECK(audited);

    RestGsHarness h2;
    h2.session_token_scope_service = "printers";
    auto denied = h2.sink.Get("/api/v1/dex/overview");
    REQUIRE(denied);
    CHECK(denied->status == 403);
}

// #4035 hardening (governance): closure evidence for the ADR-0017 World A
// confinement gap on GET /api/v1/dex/overview's top_devices[] — same defect
// class and same fix as GET /api/v1/dex/app above.
TEST_CASE("REST dex/overview: top_devices[] confined to the caller's visible set "
          "(ADR-0017 World A — regression coverage for the governance fix)",
          "[pg][rest][dex][overview][scope]") {
    RestGsHarness h;
    h.seed_obs("t1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.seed_obs("t2", "WS-2", "process.crashed", "chrome.exe", "windows", "2026-06-10T11:00:00Z");

    auto unconfined = h.sink.Get("/api/v1/dex/overview?window=all");
    REQUIRE(unconfined);
    CHECK(unconfined->status == 200);
    auto uj = nlohmann::json::parse(unconfined->body);
    REQUIRE(uj["data"]["top_devices"].is_array());
    CHECK(uj["data"]["top_devices"].size() == 2);

    h.dex_visible_override_ = std::set<std::string>{"WS-1"};
    auto confined = h.sink.Get("/api/v1/dex/overview?window=all");
    REQUIRE(confined);
    CHECK(confined->status == 200);
    auto cj = nlohmann::json::parse(confined->body);
    REQUIRE(cj["data"]["top_devices"].is_array());
    CHECK(cj["data"]["top_devices"].size() == 1);
    CHECK(cj["data"]["top_devices"][0]["agent_id"].get<std::string>() == "WS-1");
    for (const auto& d : cj["data"]["top_devices"])
        CHECK(d["agent_id"].get<std::string>() != "WS-2");
}

TEST_CASE("REST dex/devices/{id}/history: per-device signal history, audited dex.device.view "
          "(same verb the score-only route uses), out-of-scope device -> 403",
          "[pg][rest][dex][device][history]") {
    RestGsHarness h;
    h.seed_obs("g1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.seed_obs("g2", "WS-2", "os.boot", "boot", "windows", "2026-06-10T08:00:00Z");

    auto res = h.sink.Get("/api/v1/dex/devices/WS-1/history?window=all");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["agent_id"].get<std::string>() == "WS-1");
    REQUIRE(j["data"]["history"].is_array());
    bool saw_it = false, saw_other = false;
    for (const auto& r : j["data"]["history"]) {
        if (r["obs_type"].get<std::string>() == "process.crashed")
            saw_it = true;
        if (r["subject"].get<std::string>() == "boot")
            saw_other = true; // WS-2's row must never leak into WS-1's history
    }
    CHECK(saw_it);
    CHECK_FALSE(saw_other);
    bool audited = false;
    for (const auto& a : h.audit_log)
        if (a.action == "dex.device.view" && a.target_id == "WS-1")
            audited = true;
    CHECK(audited);

    h.deny_scoped_agent = "WS-9";
    auto denied = h.sink.Get("/api/v1/dex/devices/WS-9/history");
    REQUIRE(denied);
    CHECK(denied->status == 403);
}

TEST_CASE("REST dex/devices/{id}/observations/{event_id}: single-observation detail, audited, "
          "foreign event_id -> 404 (same as genuinely-absent, no oracle)",
          "[pg][rest][dex][device][observation]") {
    RestGsHarness h;
    h.seed_obs("h1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.seed_obs("h2", "WS-2", "os.boot", "boot", "windows", "2026-06-10T08:00:00Z");

    auto res = h.sink.Get("/api/v1/dex/devices/WS-1/observations/h1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["event_id"].get<std::string>() == "h1");
    CHECK(j["data"]["agent_id"].get<std::string>() == "WS-1");
    CHECK(j["data"]["obs_type"].get<std::string>() == "process.crashed");
    bool audited = false;
    for (const auto& a : h.audit_log)
        if (a.action == "dex.observation.view" && a.target_id == "WS-1")
            audited = true;
    CHECK(audited);

    // h2 belongs to WS-2, not WS-1 -- same 404 as a genuinely-absent event.
    auto foreign = h.sink.Get("/api/v1/dex/devices/WS-1/observations/h2");
    REQUIRE(foreign);
    CHECK(foreign->status == 404);
    auto absent = h.sink.Get("/api/v1/dex/devices/WS-1/observations/no-such-event");
    REQUIRE(absent);
    CHECK(absent->status == 404);
}

TEST_CASE("REST dex/devices/{id}: out-of-scope device → 403, no data leak, no audit",
          "[pg][rest][dex][device][scope]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-9", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.deny_scoped_agent = "WS-9"; // the per-device scope gate denies this agent
    auto res = h.sink.Get("/api/v1/dex/devices/WS-9?window=all");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.audit_log.empty()); // the scope gate runs BEFORE any audit emission
}

// ── #1788 per-device dispatch confinement on /live ───────────────────────
// The per-device `scoped_perm_fn` gate remains this route's PRIMARY
// authorization; the derived VisibleSet is a SECOND, independent check at the
// dispatch seam. These exist because the handoff was added with nothing reading
// it — a review confirmed empirically that forcing the route to pass `nullopt`
// left this whole suite green, so the layer could not be verified at all.

TEST_CASE("REST dex/devices/{id}/live: the caller's confined VisibleSet reaches dispatch",
          "[pg][rest][dex][device][live][scope][1788]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    h.exec_visible_override = std::unordered_set<std::string>{"WS-1"};
    StoredResponse r;
    r.instruction_id = "os_info-live";
    r.agent_id = "WS-1";
    r.status = 0;
    r.output = "uptime_seconds|1\nuptime_display|1s";
    h.resp_store->store(r);

    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 200);
    REQUIRE(h.last_live_exec_visible.has_value()); // CONFINED, not unfiltered
    CHECK(h.last_live_exec_visible->count("WS-1") == 1);
    CHECK(h.last_live_exec_visible->count("WS-9") == 0);
}

TEST_CASE("REST dex/devices/{id}/live: a device the caller cannot see is not reached, even though "
          "the per-device gate admitted it",
          "[pg][rest][dex][device][live][scope][1788]") {
    // The scope gate is left ADMITTING on purpose, so the confinement layer is
    // the only thing that can refuse this dispatch.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    h.exec_visible_override = std::unordered_set<std::string>{"WS-OTHER"};
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 503); // "device offline" — deliberately indistinguishable
    REQUIRE(h.last_live_exec_visible.has_value());
    CHECK(h.last_live_exec_visible->count("WS-1") == 0);
}

TEST_CASE("REST dex/devices/{id}/live: an UNWIRED ExecVisibleFn fails CLOSED (present-empty)",
          "[pg][rest][dex][device][live][scope][fail-closed][1788]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(/*live_deps=*/true, /*wire_scoped_perm=*/true, /*wire_app_perf=*/true,
                    /*with_exec_visible=*/false, /*resp_pool=*/&pool);
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 503);
    REQUIRE(h.last_live_exec_visible.has_value()); // PRESENT (deny-all), never nullopt
    CHECK(h.last_live_exec_visible->empty());
}

TEST_CASE("REST dex/devices/{id}/live uptime: dispatches + returns parsed JSON, audited",
          "[pg][rest][dex][device][live]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    // Pre-insert the agent's response for the deterministic command_id the stub mints.
    StoredResponse r;
    r.instruction_id = "os_info-live";
    r.agent_id = "WS-1";
    r.status = 0; // RUNNING row carries the output
    r.output = "uptime_seconds|181740\nuptime_display|2d 2h 29m";
    h.resp_store->store(r);

    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.last_live_plugin == "os_info");
    CHECK(h.last_live_action == "uptime");
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["kind"].get<std::string>() == "uptime");
    CHECK(j["data"]["uptime_display"].get<std::string>() == "2d 2h 29m");
    CHECK(j["data"]["uptime_seconds"].get<int64_t>() == 181740);
    // #1549 audit-on-open: the audit fires BEFORE dispatch with result "requested"
    // (the works-council event = operator asked for live data), not the old
    // post-dispatch "dispatched". Lock it so a revert to post-dispatch auditing
    // (which would dispatch before durable evidence) fails.
    bool audited = false;
    for (const auto& a : h.audit_log)
        if (a.action == "device.live.uptime" && a.result == "requested" && a.target_id == "WS-1")
            audited = true;
    CHECK(audited);
}

TEST_CASE("REST dex/devices/{id}/live processes: parses proc|pid|name|sha256|path rows",
          "[pg][rest][dex][device][live]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    StoredResponse r;
    r.instruction_id = "processes-live";
    r.agent_id = "WS-1";
    r.status = 0;
    r.output =
        "proc|0|[System Process]||\n"
        "proc|123|sh|deadbeefcafe0000111122223333444455556666777788889999aaaabbbbccccdddd|/bin/sh";
    h.resp_store->store(r);

    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=processes", "");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.last_live_action == "list_hashed"); // the hashed variant
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"]["processes"].is_array());
    REQUIRE(j["data"]["processes"].size() == 2);
    const auto& sh = j["data"]["processes"][1];
    CHECK(sh["pid"].get<int64_t>() == 123);
    CHECK(sh["name"].get<std::string>() == "sh");
    CHECK(sh["sha256"].get<std::string>().rfind("deadbeefcafe0000", 0) == 0);
    CHECK(sh["path"].get<std::string>() == "/bin/sh");
    bool audited = false; // #1549: pre-dispatch audit, result "requested"
    for (const auto& a : h.audit_log)
        if (a.action == "device.live.processes" && a.result == "requested")
            audited = true;
    CHECK(audited);
}

TEST_CASE("REST dex/devices/{id}/live: offline device (sent=0) → 503, audited requested",
          "[pg][rest][dex][device][live]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    h.live_sent = 0; // dispatch reaches no connected agent
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 503);
    // #1549: the audit fires "requested" BEFORE dispatch — the works-council event
    // is the operator's request, recorded regardless of whether an agent was reached
    // (the 503 carries the no-agent outcome). The dispatch still happened (audit
    // persisted), so the evidence row exists.
    bool audited = false;
    for (const auto& a : h.audit_log)
        if (a.action == "device.live.uptime" && a.result == "requested")
            audited = true;
    CHECK(audited);
}

TEST_CASE("REST dex/devices/{id}/live: unknown kind → 400, no dispatch",
          "[pg][rest][dex][device][live]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=bogus", "");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.last_live_plugin.empty()); // never dispatched
}

TEST_CASE("REST dex/devices/{id}/live: out-of-scope device → 403, no dispatch",
          "[pg][rest][dex][device][live][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    h.deny_scoped_agent = "WS-9";
    auto res = h.sink.Post("/api/v1/dex/devices/WS-9/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.last_live_plugin.empty()); // gate denied before any dispatch
}

// ── Governance hardening-round coverage (R1) ──────────────────────────────

namespace {
// StoredResponse::status mirrors CommandResponse::Status; name the values the /live
// poll branches on so a proto enum shuffle breaks these tests loudly (quality S4).
constexpr int kStatusPending = 0;
constexpr int kStatusSuccess = 1;
constexpr int kStatusFailure = 2;
constexpr int kStatusFatal = 3;

// Exception-safe save/restore for a process-global test-seam atomic: restores in the
// dtor so a throwing REQUIRE between mutate and restore can't poison later tests
// (quality S1 / cpp-safety SHOULD).
struct AtomicSave {
    std::atomic<int>& ref;
    int saved;
    explicit AtomicSave(std::atomic<int>& a) : ref(a), saved(a.load()) {}
    ~AtomicSave() { ref.store(saved); }
    AtomicSave(const AtomicSave&) = delete;
    AtomicSave& operator=(const AtomicSave&) = delete;
};
} // namespace


TEST_CASE("REST dex/devices/{id}: off-enum window → 400, no audit, no data",
          "[pg][rest][dex][device]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    auto res = h.sink.Get("/api/v1/dex/devices/WS-1?window=banana");
    REQUIRE(res);
    CHECK(res->status == 400);          // not a silent default to 7d
    CHECK(h.audit_log.empty());         // validated before any audit emission
}

TEST_CASE("REST dex/devices/{id}/live: terminal failure WINS over a partial-output row → 502",
          "[pg][rest][dex][device][live]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    // A single frame that carries BOTH partial output AND a failure status — the
    // pre-fix poll returned 200 with the partial data (UP-4). Failure must 502.
    StoredResponse r;
    r.instruction_id = "os_info-live";
    r.agent_id = "WS-1";
    r.status = kStatusFailure;
    r.output = "uptime_display|2d 2h"; // partial output present alongside the failure
    r.error_detail = "agent aborted";
    h.resp_store->store(r);
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 502);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 502);
    CHECK(j["error"]["message"].get<std::string>().find("device query failed") != std::string::npos);
}

TEST_CASE("REST dex/devices/{id}/live: device error| output → 502",
          "[pg][rest][dex][device][live]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    StoredResponse r;
    r.instruction_id = "os_info-live";
    r.agent_id = "WS-1";
    r.status = kStatusPending;
    r.output = "error|disk subsystem offline";
    h.resp_store->store(r);
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 502);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 502);
    CHECK(j["error"]["message"].get<std::string>().find("device reported an error") !=
          std::string::npos);
}

TEST_CASE("REST dex/devices/{id}/live: terminal failure, no output → 502",
          "[pg][rest][dex][device][live]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    StoredResponse r;
    r.instruction_id = "os_info-live";
    r.agent_id = "WS-1";
    r.status = kStatusFatal; // FAILURE, no output
    r.error_detail = "plugin crashed";
    h.resp_store->store(r);
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 502);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 502);
}

TEST_CASE("REST dex/devices/{id}/live: success terminal, no output → 200 empty (not a 504)",
          "[pg][rest][dex][device][live]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    StoredResponse r;
    r.instruction_id = "processes-live";
    r.agent_id = "WS-1";
    r.status = kStatusSuccess; // no output rows
    h.resp_store->store(r);
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=processes", "");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["kind"].get<std::string>() == "processes");
    REQUIRE(j["data"]["processes"].is_array());
    CHECK(j["data"]["processes"].empty());
}

TEST_CASE("REST dex/devices/{id}/live: over the concurrency cap → 429, no dispatch",
          "[pg][rest][dex][device][live]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    AtomicSave cap_save{yuzu::server::detail::live_max_inflight()};
    yuzu::server::detail::live_max_inflight().store(0); // any call is over budget
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 429);
    CHECK(h.last_live_plugin.empty()); // 429'd before dispatch — no command sent
}

TEST_CASE("REST dex/devices/{id}/live: agent never responds → 504",
          "[pg][rest][dex][device][live]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    AtomicSave mp_save{yuzu::server::detail::live_poll_max_polls()};
    AtomicSave iv_save{yuzu::server::detail::live_poll_interval_ms()};
    yuzu::server::detail::live_poll_max_polls().store(2);
    yuzu::server::detail::live_poll_interval_ms().store(1); // ~2ms not ~20s; no row inserted
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 504);
}

TEST_CASE("REST dex/devices/{id}/live: GET is not routed (POST-only side effect)",
          "[pg][rest][dex][device][live]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    // The endpoint is POST-only (it dispatches a command). A GET must NOT reach the
    // handler — the TestRouteSink returns nullptr when no route matches the method,
    // mirroring httplib's 404. Locks the GET->POST migration (architect B1).
    auto res = h.sink.Get("/api/v1/dex/devices/WS-1/live?kind=uptime");
    CHECK(res == nullptr);
    CHECK(h.last_live_plugin.empty()); // never dispatched
}

TEST_CASE("REST dex/devices/{id}/live: emits outcome counter + in-flight gauge",
          "[pg][rest][dex][device][live][metrics]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    StoredResponse r;
    r.instruction_id = "os_info-live";
    r.agent_id = "WS-1";
    r.status = kStatusSuccess;
    r.output = "uptime_display|1d";
    h.resp_store->store(r);

    auto ok = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    // One uptime/200 counted; the in-flight gauge returns to 0 after the call.
    CHECK(h.metrics
              .counter("yuzu_server_live_requests_total", {{"kind", "uptime"}, {"outcome", "200"}})
              .value() == 1.0);
    CHECK(h.metrics.gauge("yuzu_server_live_inflight").value() == 0.0);

    // A 429 (cap exhausted) is counted under its own outcome label, no dispatch.
    AtomicSave cap_save{yuzu::server::detail::live_max_inflight()};
    yuzu::server::detail::live_max_inflight().store(0);
    auto rej = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(rej);
    CHECK(rej->status == 429);
    CHECK(h.metrics
              .counter("yuzu_server_live_requests_total", {{"kind", "uptime"}, {"outcome", "429"}})
              .value() == 1.0);
}

// ── #1549 review hardening: audit-on-open fail-closed, A4 denials, headers ──

TEST_CASE("REST dex/devices/{id}: audit persistence failure → 503, no PII served, Sec-Audit-Failed",
          "[pg][rest][dex][device][audit]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.audit_succeeds = false; // the audit row cannot persist (DB locked/full/corrupt)
    auto res = h.sink.Get("/api/v1/dex/devices/WS-1?window=all");
    REQUIRE(res);
    // FAIL-CLOSED: behavioral PII must not be served when the evidence row is known
    // to have been lost (SOC 2 CC7.2 / works-council).
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty()); // echoed on the error path too
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
    // No device data leaked onto the body — assert the structural keys AND the actual
    // seeded PII content (an app-identity leak under a different key would harm the
    // works-council/SOC 2 evidence review).
    CHECK(res->body.find("\"signals\"") == std::string::npos);
    CHECK(res->body.find("\"score\"") == std::string::npos);
    CHECK(res->body.find("chrome.exe") == std::string::npos);
}

TEST_CASE("REST dex/devices/{id}: success echoes X-Correlation-Id header",
          "[pg][rest][dex][device][a3]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    auto res = h.sink.Get("/api/v1/dex/devices/WS-1?window=all");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
}

// ── Slice-2 DEX app-perf read surface: route-level control flow ──────────────
// Model math (test_dex_app_perf_model.cpp) + the group SQL (test_app_perf_group_
// reader.cpp) are covered separately; these pin the HANDLER control flow the
// dex-perf family already tests — the gate, the provider-absent degrade, the
// required-param 400s, and the security-relevant device audit-fail-closed.

TEST_CASE("REST dex/perf/apps: provider absent → 503 + A4 correlation id",
          "[pg][rest][dex][app_perf][route]") {
    RestGsHarness h(/*live_deps=*/true, /*wire_scoped_perm=*/true, /*wire_app_perf=*/false);
    auto res = h.sink.Get("/api/v1/dex/perf/apps");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
}

TEST_CASE("REST dex/perf/app: missing app → 400; provider absent → 503; present → 200",
          "[pg][rest][dex][app_perf][route]") {
    SECTION("missing required app → 400") {
        RestGsHarness h;
        auto res = h.sink.Get("/api/v1/dex/perf/app");
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    SECTION("provider absent → 503") {
        RestGsHarness h(true, true, false);
        auto res = h.sink.Get("/api/v1/dex/perf/app?app=chrome.exe");
        REQUIRE(res);
        CHECK(res->status == 503);
    }
    SECTION("present provider, valid app → 200 with the app echoed") {
        RestGsHarness h;
        auto res = h.sink.Get("/api/v1/dex/perf/app?app=chrome.exe");
        REQUIRE(res);
        CHECK(res->status == 200);
        auto j = nlohmann::json::parse(res->body);
        CHECK(j["data"]["app"].get<std::string>() == "chrome.exe");
        CHECK(j["data"]["points"].is_array());
    }
    SECTION("sub-floor fleet point serializes suppressed, stats omitted") {
        // The fleet path floors too now — a sub-floor (version,day) point must carry
        // suppressed=true with device_count only, never zeroed stats that read as
        // "3 devices @ 0% CPU" (security re-review of the suppressed-flag fix).
        RestGsHarness h;
        yuzu::server::AppPerfFleetRow r;
        r.app_name = "niche.exe";
        r.version = "1.0";
        r.day = 1'700'000'000;
        r.device_count = 3; // < kDexCohortFloor (10)
        r.cpu_sum = 30.0;
        r.cpu_max = 10.0;
        r.ws_sum = 300;
        r.ws_max = 100;
        r.hist_version = yuzu::server::kAppPerfHistVersion;
        r.cpu_hist.assign(yuzu::server::app_perf_cpu_buckets().size() + 1, 0);
        r.ws_hist.assign(yuzu::server::app_perf_ws_buckets().size() + 1, 0);
        h.fleet_rows_ = {r};
        auto res = h.sink.Get("/api/v1/dex/perf/app?app=niche.exe");
        REQUIRE(res);
        CHECK(res->status == 200);
        auto j = nlohmann::json::parse(res->body);
        REQUIRE(j["data"]["points"].size() == 1);
        const auto& pt = j["data"]["points"][0];
        CHECK(pt["suppressed"] == true);
        CHECK(pt["device_count"] == 3);
        CHECK_FALSE(pt.contains("cpu_mean")); // stats omitted when suppressed
    }
}

// ── CRITICAL finding, this branch's own governance review (PR #3156, while
// re-verifying the external review's separate findings on this same file):
// /dex/perf/group and /dex/perf/compare gated only on the GLOBAL perm_fn -
// their own comments
// reasoned about RBAC management-group-scoped grants (a different axis) and
// never considered a service-scoped API token, which holds a GLOBAL
// GuaranteedState:Read via ITServiceOwner and so could supply any group_id/
// group, including one outside its own service. ──────────────────────────

TEST_CASE("REST dex/perf/group: service-scoped token → 403, denial audited",
          "[pg][rest][dex][app_perf][rbac]") {
    RestGsHarness h;
    h.session_token_scope_service = "printers";
    auto res = h.sink.Get("/api/v1/dex/perf/group?group_id=g1&app=chrome.exe");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "dex.perf.group.view");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].target_type == "GuaranteedState");
}

TEST_CASE("REST dex/perf/group: ordinary session still reaches the route",
          "[pg][rest][dex][app_perf]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/dex/perf/group?group_id=g1&app=chrome.exe");
    REQUIRE(res);
    CHECK(res->status != 403);
}

TEST_CASE("REST dex/perf/tag: service-scoped token → 403, denial audited",
          "[pg][rest][dex][app_perf][rbac]") {
    RestGsHarness h;
    h.session_token_scope_service = "printers";
    auto res = h.sink.Get("/api/v1/dex/perf/tag?value=Latitude+5420&app=chrome.exe");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "dex.perf.tag.view");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].target_type == "GuaranteedState");
}

TEST_CASE("REST dex/perf/tag: ordinary session still reaches the route",
          "[pg][rest][dex][app_perf]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/dex/perf/tag?value=Latitude+5420&app=chrome.exe");
    REQUIRE(res);
    CHECK(res->status != 403);
}

TEST_CASE("REST dex/perf/tag: missing params, invalid key, provider absent, floor "
          "echoed, key defaults to model",
          "[pg][rest][dex][app_perf][route]") {
    SECTION("missing value → 400") {
        RestGsHarness h;
        auto res = h.sink.Get("/api/v1/dex/perf/tag?app=chrome.exe");
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    SECTION("missing app → 400") {
        RestGsHarness h;
        auto res = h.sink.Get("/api/v1/dex/perf/tag?value=Latitude+5420");
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    SECTION("invalid key → 400") {
        RestGsHarness h;
        auto res =
            h.sink.Get("/api/v1/dex/perf/tag?key=bad%20key%21&value=x&app=chrome.exe");
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    SECTION("present-but-empty value → 400, not treated as 'every value' (sec-M1)") {
        RestGsHarness h;
        auto res = h.sink.Get("/api/v1/dex/perf/tag?value=&app=chrome.exe");
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    SECTION("present-but-empty key → 400, not silently defaulted (sec-M1)") {
        RestGsHarness h;
        auto res = h.sink.Get("/api/v1/dex/perf/tag?key=&value=Latitude+5420&app=chrome.exe");
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    SECTION("provider absent → 503") {
        RestGsHarness h(true, true, false);
        auto res = h.sink.Get("/api/v1/dex/perf/tag?value=Latitude+5420&app=chrome.exe");
        REQUIRE(res);
        CHECK(res->status == 503);
    }
    SECTION("present provider, key omitted → 200, floor echoed, key defaults to model") {
        RestGsHarness h;
        auto res = h.sink.Get("/api/v1/dex/perf/tag?value=Latitude+5420&app=chrome.exe");
        REQUIRE(res);
        CHECK(res->status == 200);
        auto j = nlohmann::json::parse(res->body);
        CHECK(j["data"]["floor"].get<int64_t>() == yuzu::server::kDexCohortFloor);
        CHECK(j["data"]["key"].get<std::string>() == "model");
        CHECK(j["data"]["value"].get<std::string>() == "Latitude 5420");
    }
    SECTION("sub-floor tag-cohort point serializes suppressed, stats omitted") {
        // Same wiring (app_perf_group_trend) and same floor as the fleet/group
        // routes' own sub-floor tests — this proves the ROUTE composes it
        // correctly for a tag-value cohort, not just that the shared model
        // function floors correctly in isolation (already covered at
        // test_dex_app_perf_model.cpp's "app_perf_group_trend: sub-floor points
        // suppress stats, keep device_count").
        RestGsHarness h;
        yuzu::server::AppPerfFleetRow r;
        r.app_name = "niche.exe";
        r.version = "1.0";
        r.day = 1'700'000'000;
        r.device_count = 3; // < kDexCohortFloor (10)
        r.cpu_sum = 30.0;
        r.cpu_max = 10.0;
        r.ws_sum = 300;
        r.ws_max = 100;
        r.hist_version = yuzu::server::kAppPerfHistVersion;
        r.cpu_hist.assign(yuzu::server::app_perf_cpu_buckets().size() + 1, 0);
        r.ws_hist.assign(yuzu::server::app_perf_ws_buckets().size() + 1, 0);
        h.tag_cohort_rows_ = {r};
        auto res =
            h.sink.Get("/api/v1/dex/perf/tag?value=RareModel&app=niche.exe");
        REQUIRE(res);
        CHECK(res->status == 200);
        auto j = nlohmann::json::parse(res->body);
        REQUIRE(j["data"]["points"].size() == 1);
        const auto& pt = j["data"]["points"][0];
        CHECK(pt["suppressed"] == true);
        CHECK(pt["device_count"] == 3);
        CHECK_FALSE(pt.contains("cpu_mean"));
    }
}

TEST_CASE("REST dex/perf/compare: service-scoped token → 403, denied under the "
          "existing dex.app_perf.compare verb",
          "[pg][rest][dex][app_perf][rbac]") {
    RestGsHarness h;
    h.session_token_scope_service = "printers";
    auto res = h.sink.Get(
        "/api/v1/dex/perf/compare?app=AcmeVPN.exe&group=g1&baseline=4.2.0.0&candidate=4.3.0.0");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "dex.app_perf.compare");
    CHECK(h.audit_log[0].result == "denied");
}

TEST_CASE("REST dex/perf/compare: ordinary session still reaches the route",
          "[pg][rest][dex][app_perf]") {
    RestGsHarness h;
    auto res = h.sink.Get(
        "/api/v1/dex/perf/compare?app=AcmeVPN.exe&group=g1&baseline=4.2.0.0&candidate=4.3.0.0");
    REQUIRE(res);
    CHECK(res->status != 403);
}

TEST_CASE("REST dex/perf/group: missing params → 400; provider absent → 503; floor echoed",
          "[pg][rest][dex][app_perf][route]") {
    SECTION("missing group_id → 400") {
        RestGsHarness h;
        auto res = h.sink.Get("/api/v1/dex/perf/group?app=chrome.exe");
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    SECTION("missing app → 400") {
        RestGsHarness h;
        auto res = h.sink.Get("/api/v1/dex/perf/group?group_id=g1");
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    SECTION("provider absent → 503") {
        RestGsHarness h(true, true, false);
        auto res = h.sink.Get("/api/v1/dex/perf/group?group_id=g1&app=chrome.exe");
        REQUIRE(res);
        CHECK(res->status == 503);
    }
    SECTION("present provider → 200 with the floor echoed") {
        RestGsHarness h;
        auto res = h.sink.Get("/api/v1/dex/perf/group?group_id=g1&app=chrome.exe");
        REQUIRE(res);
        CHECK(res->status == 200);
        auto j = nlohmann::json::parse(res->body);
        CHECK(j["data"]["floor"].get<int64_t>() == yuzu::server::kDexCohortFloor);
    }
}

TEST_CASE("REST dex/perf/compare: param + degrade + paired-compute paths",
          "[pg][rest][dex][app_perf][verify][route]") {
    SECTION("missing baseline/candidate → 400") {
        RestGsHarness h;
        auto res = h.sink.Get("/api/v1/dex/perf/compare?app=AcmeVPN.exe&group=g1");
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    SECTION("baseline == candidate → 400") {
        RestGsHarness h;
        auto res = h.sink.Get(
            "/api/v1/dex/perf/compare?app=AcmeVPN.exe&group=g1&baseline=4.2.0.0&candidate=4.2.0.0");
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    SECTION("provider absent → 503") {
        RestGsHarness h(true, true, /*wire_app_perf=*/false);
        auto res = h.sink.Get(
            "/api/v1/dex/perf/compare?app=AcmeVPN.exe&group=g1&baseline=4.2.0.0&candidate=4.3.0.0");
        REQUIRE(res);
        CHECK(res->status == 503);
    }
    SECTION("AUTHORITATIVE degrade (cohort read nullopt) → 503") {
        RestGsHarness h;
        h.cohort_read_ = std::nullopt;
        auto res = h.sink.Get(
            "/api/v1/dex/perf/compare?app=AcmeVPN.exe&group=g1&baseline=4.2.0.0&candidate=4.3.0.0");
        REQUIRE(res);
        CHECK(res->status == 503);
    }
    SECTION("paired cohort → 200 with the measured shift (no verdict field)") {
        RestGsHarness h;
        yuzu::server::CohortRead cr;
        cr.member_count = 2;
        // Two machines, each ran both versions; both heavier on the candidate.
        cr.rows = {
            {"m1", "4.2.0.0", 10, 100, 2.0, 1000}, {"m1", "4.3.0.0", 11, 100, 5.0, 1500},
            {"m2", "4.2.0.0", 10, 100, 3.0, 1000}, {"m2", "4.3.0.0", 11, 100, 4.0, 1100},
        };
        h.cohort_read_ = cr;
        auto res = h.sink.Get(
            "/api/v1/dex/perf/compare?app=AcmeVPN.exe&group=g1&baseline=4.2.0.0&candidate=4.3.0.0");
        REQUIRE(res);
        CHECK(res->status == 200);
        auto j = nlohmann::json::parse(res->body);
        CHECK(j["data"]["paired"].get<int64_t>() == 2);
        CHECK(j["data"]["cohort_size"].get<int64_t>() == 2);
        CHECK(j["data"]["small_cohort"].get<bool>() == true); // 2 < kDexCohortFloor
        CHECK(j["data"]["insufficient"].get<bool>() == false);
        CHECK(j["data"]["cpu"]["before_mean"].get<double>() == Catch::Approx(2.5));
        CHECK(j["data"]["cpu"]["after_mean"].get<double>() == Catch::Approx(4.5));
        CHECK(j["data"]["distribution"]["up"].get<int64_t>() == 2);
        // EVIDENTIAL — there must be NO verdict/pass/fail field.
        CHECK_FALSE(j["data"].contains("verdict"));
        CHECK_FALSE(j["data"].contains("pass"));
        // The read IS audited (the accountability that replaces the absent floor),
        // and the detail carries paired= (singleton-visible) + view=aggregate.
        REQUIRE(h.audit_log.size() == 1);
        CHECK(h.audit_log[0].action == "dex.app_perf.compare");
        CHECK(h.audit_log[0].detail.find("paired=2") != std::string::npos);
        CHECK(h.audit_log[0].detail.find("view=aggregate") != std::string::npos);
        CHECK_FALSE(j["data"]["truncated"].get<bool>());
    }
    SECTION("audit-field forgery — a spaced/=-laden app cannot forge paired=/cohort= (H1)") {
        RestGsHarness h;
        yuzu::server::CohortRead cr;
        cr.member_count = 2;
        cr.rows = {
            {"m1", "4.2.0.0", 10, 100, 2.0, 1000}, {"m1", "4.3.0.0", 11, 100, 5.0, 1500},
            {"m2", "4.2.0.0", 10, 100, 3.0, 1000}, {"m2", "4.3.0.0", 11, 100, 4.0, 1100},
        };
        h.cohort_read_ = cr;
        // app = "Acme.exe paired=99 cohort=99" (space + '=' pass app_perf_param_valid).
        auto res = h.sink.Get("/api/v1/dex/perf/compare?app=Acme.exe%20paired%3D99%20cohort%3D99"
                              "&group=g1&baseline=4.2.0.0&candidate=4.3.0.0");
        REQUIRE(res);
        CHECK(res->status == 200);
        REQUIRE(h.audit_log.size() == 1);
        const std::string& d = h.audit_log[0].detail;
        // audit_token neutralised the forgery (space/= → _); the REAL fields stand.
        CHECK(d.find("paired=2") != std::string::npos);
        CHECK(d.find("cohort=2") != std::string::npos);
        CHECK(d.find("paired=99") == std::string::npos);  // forged token defused
        CHECK(d.find("cohort=99") == std::string::npos);
        CHECK(d.find("Acme.exe_paired_99_cohort_99") != std::string::npos);
    }
    SECTION("truncated cohort → truncated:true in the response (loud, not silent)") {
        RestGsHarness h;
        yuzu::server::CohortRead cr;
        cr.member_count = 2;
        cr.truncated = true; // the read hit the row cap
        cr.rows = {
            {"m1", "4.2.0.0", 10, 100, 2.0, 1000}, {"m1", "4.3.0.0", 11, 100, 5.0, 1500},
        };
        h.cohort_read_ = cr;
        auto res = h.sink.Get(
            "/api/v1/dex/perf/compare?app=AcmeVPN.exe&group=g1&baseline=4.2.0.0&candidate=4.3.0.0");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(nlohmann::json::parse(res->body)["data"]["truncated"].get<bool>() == true);
    }
    SECTION("audit drop → 200 set-and-proceed + Sec-Audit-Failed (aggregate has no PII)") {
        RestGsHarness h;
        h.audit_succeeds = false; // simulate a lost evidence row
        yuzu::server::CohortRead cr;
        cr.member_count = 2;
        cr.rows = {
            {"m1", "4.2.0.0", 10, 100, 2.0, 1000}, {"m1", "4.3.0.0", 11, 100, 5.0, 1500},
            {"m2", "4.2.0.0", 10, 100, 3.0, 1000}, {"m2", "4.3.0.0", 11, 100, 4.0, 1100},
        };
        h.cohort_read_ = cr;
        auto res = h.sink.Get(
            "/api/v1/dex/perf/compare?app=AcmeVPN.exe&group=g1&baseline=4.2.0.0&candidate=4.3.0.0");
        REQUIRE(res);
        CHECK(res->status == 200); // operational set-and-proceed, NOT fail-closed
        CHECK(res->has_header("Sec-Audit-Failed"));
        CHECK(nlohmann::json::parse(res->body)["data"]["paired"].get<int64_t>() == 2);
    }
    SECTION("perm denied → 403 BEFORE the cohort read or audit") {
        RestGsHarness h;
        h.grant_perms = false;
        yuzu::server::CohortRead cr;
        cr.member_count = 2;
        h.cohort_read_ = cr;
        auto res = h.sink.Get(
            "/api/v1/dex/perf/compare?app=AcmeVPN.exe&group=g1&baseline=4.2.0.0&candidate=4.3.0.0");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.audit_log.empty()); // gate runs first — no read, no audit
    }
}

TEST_CASE("REST dex/devices/{id}/app-perf: audit failure → 503 + Sec-Audit-Failed, no rows",
          "[pg][rest][dex][device][app_perf][audit]") {
    RestGsHarness h;
    h.audit_succeeds = false; // the evidence row cannot persist
    auto res = h.sink.Get("/api/v1/dex/devices/WS-1/app-perf");
    REQUIRE(res);
    // FAIL-CLOSED: per-device behavioural data is not served without durable evidence.
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    CHECK(res->body.find("\"rows\"") == std::string::npos); // no behavioural data leaked
    bool saw_verb = false;
    for (const auto& a : h.audit_log)
        if (a.action == "dex.device.app_perf.view" && a.target_id == "WS-1")
            saw_verb = true;
    CHECK(saw_verb); // the right verb was attempted (cross-surface SIEM parity)
}

TEST_CASE("REST dex/devices/{id}/app-perf: out-of-scope device → 403, scoped by the path id",
          "[pg][rest][dex][device][app_perf][scope]") {
    RestGsHarness h;
    h.deny_scoped_agent = "WS-9";
    auto res = h.sink.Get("/api/v1/dex/devices/WS-9/app-perf");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.last_scoped_agent_id == "WS-9"); // scoped by the path device, not a default
}

TEST_CASE("REST dex/devices/{id}/app-perf: provider absent → 503 BEFORE audit",
          "[pg][rest][dex][device][app_perf][route]") {
    RestGsHarness h(true, true, false); // app-perf seam unwired
    auto res = h.sink.Get("/api/v1/dex/devices/WS-1/app-perf");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed").empty()); // provider check precedes audit
}

TEST_CASE("REST dex/devices/{id}/live: audit persistence failure → 503, NO dispatch, "
          "Sec-Audit-Failed",
          "[pg][rest][dex][device][live][audit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    h.audit_succeeds = false; // evidence row cannot persist
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    // The probe must NOT be dispatched without durable evidence.
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty()); // echoed on the error path too
    CHECK(h.last_live_plugin.empty()); // audit failed BEFORE dispatch → no command sent
}

TEST_CASE("REST dex/devices/{id}/live: success echoes X-Correlation-Id header",
          "[pg][rest][dex][device][live][a3]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    StoredResponse r;
    r.instruction_id = "os_info-live";
    r.agent_id = "WS-1";
    r.status = kStatusSuccess;
    r.output = "uptime_display|1d";
    h.resp_store->store(r);
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
}

TEST_CASE("REST dex/devices/{id}/live: Execute denied but Read allowed → 403, no dispatch",
          "[pg][rest][dex][device][live][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    h.deny_scoped_op = "Execute"; // Read floor passes; Execute floor denies
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.last_live_plugin.empty()); // the Execute gate denied before any dispatch
}

TEST_CASE("REST dex/devices/{id}/live: live substrate unavailable → 503",
          "[pg][rest][dex][device][live]") {
    RestGsHarness h{/*live_deps=*/false}; // no response_store + no command_dispatch_fn
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
}

TEST_CASE("REST dex/devices/{id}/live: device output over the cap → 502",
          "[pg][rest][dex][device][live]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    // Seeded via a raw connection, NOT ResponseStore::store() (#2691): store()
    // now truncates ingest at 2 MiB (Doomgoose finding #4, matching the
    // agent's own per-dispatch cap) — a real agent can never legitimately
    // reach this handler's own 4 MiB display-layer cap, so exercising it
    // means bypassing ingest entirely, the same way a corrupt/pre-migration
    // row could.
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult res = yuzu::server::pg::exec_params(
            conn.get(),
            "INSERT INTO response_store.responses (instruction_id, agent_id, timestamp, "
            "status, output) VALUES ($1,$2,$3::bigint,$4::integer,$5)",
            std::vector<std::string>{"processes-live", "WS-1", "1700000000",
                                     std::to_string(kStatusSuccess),
                                     std::string(5 * 1024 * 1024, 'x')}); // > 4 MiB cap
        INFO(PQresultErrorMessage(res.get()));
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=processes", "");
    REQUIRE(res);
    CHECK(res->status == 502);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["message"].get<std::string>().find("too large") != std::string::npos);
}

TEST_CASE("REST dex/devices/{id}/live: a different agent's response row is never rendered → 504",
          "[pg][rest][dex][device][live][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    AtomicSave mp_save{yuzu::server::detail::live_poll_max_polls()};
    AtomicSave iv_save{yuzu::server::detail::live_poll_interval_ms()};
    yuzu::server::detail::live_poll_max_polls().store(2);
    yuzu::server::detail::live_poll_interval_ms().store(1);
    // A row under the SAME command_id but for a DIFFERENT agent must be ignored —
    // never returned as WS-1's data. With no WS-1 row, the poll times out (504).
    StoredResponse other;
    other.instruction_id = "os_info-live";
    other.agent_id = "OTHER";
    other.status = kStatusSuccess;
    other.output = "uptime_display|99d";
    h.resp_store->store(other);
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 504);
    CHECK(res->body.find("99d") == std::string::npos); // OTHER's data never leaked
}

TEST_CASE("REST dex/devices/{id}/live uptime: success terminal, no output → 200 empty",
          "[pg][rest][dex][device][live]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    RestGsHarness h(true, true, true, true, &pool);
    StoredResponse r;
    r.instruction_id = "os_info-live";
    r.agent_id = "WS-1";
    r.status = kStatusSuccess; // no output rows
    h.resp_store->store(r);
    auto res = h.sink.Post("/api/v1/dex/devices/WS-1/live?kind=uptime", "");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["kind"].get<std::string>() == "uptime");
}

TEST_CASE("REST dex/devices/{id}: scoped denial carries the A4 envelope (correlation_id + "
          "permission)",
          "[pg][rest][dex][device][scope][a4]") {
    // The scoped gate is wired in production to require_scoped_permission, whose
    // denial now emits the A4 envelope. Here the harness's scoped_perm_fn stands in
    // for the gate and writes only a 403 status — so this test asserts the handler
    // surfaces the gate's status untouched (no data leak); the A4 *body* shape is
    // pinned at the helper level in test_auth_routes.cpp.
    // KNOWN GAP (governance #1549 QE-SHOULD): this test does NOT prove the
    // /api/v1/dex/devices/{id} handler is wired to the A4-emitting
    // require_scoped_permission — that binding is accepted as untested at this unit
    // boundary (the harness stub stands in for the gate).
    RestGsHarness h;
    h.deny_scoped_agent = "WS-9";
    auto res = h.sink.Get("/api/v1/dex/devices/WS-9?window=all");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.audit_log.empty());
}

// #1549 governance consistency-B1: the per-device PII REST siblings must fail closed
// on a dropped audit row, same as GET /dex/devices/{id}.

TEST_CASE("REST guaranteed-state/events: agent-scoped audit failure → 503, no PII, Sec-Audit-Failed",
          "[pg][rest][dex][events][audit]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.audit_succeeds = false;
    // agent_id filter = individual-identifying behavioral PII → audited + fail-closed.
    auto res = h.sink.Get("/api/v1/guaranteed-state/events?agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(res->body.find("chrome.exe") == std::string::npos); // no PII leaked
    // A4 envelope on the fail-closed body (#1651 review K2): correlation_id + retry_after_ms,
    // parity with the /dex/devices/{id} + baseline siblings.
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    auto j = nlohmann::json::parse(res->body);
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
    CHECK(j["error"]["retry_after_ms"].get<int>() == 5000);
}

// #1651 review K5: the converted route's catch arm (a throwing audit_fn) was only
// covered by the helper unit test, not end-to-end here. Pin it at the route level.
TEST_CASE("REST guaranteed-state/events: agent-scoped throwing audit → 503, A4, Sec-Audit-Failed",
          "[pg][rest][dex][events][audit]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.audit_throws = true; // bad_alloc-class throw — caught by the shared helper
    auto res = h.sink.Get("/api/v1/guaranteed-state/events?agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(res->body.find("chrome.exe") == std::string::npos);
}

// SEC-3: was "NO agent_id filter is a bulk query — not gated by audit" — that
// was the disclosure-adjacent gap (an un-audited fleet-wide fan-out of
// identity-linked agent_id + detail_json rows). The fleet shape is now
// audited and fails closed exactly like the agent-scoped shape above.
TEST_CASE("REST guaranteed-state/events: NO agent_id (fleet) query is now audited, fail-closed on "
          "a persist failure",
          "[pg][rest][dex][events][audit]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.audit_succeeds = false;
    auto res = h.sink.Get("/api/v1/guaranteed-state/events");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(res->body.find("chrome.exe") == std::string::npos);
}

TEST_CASE("REST dex/signals/{obs_type}: audit failure → 503, no device list, Sec-Audit-Failed",
          "[pg][rest][dex][signals][audit]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.audit_succeeds = false;
    auto res = h.sink.Get("/api/v1/dex/signals/process.crashed?window=all");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(res->body.find("WS-1") == std::string::npos); // the agent_id list must not leak
    // A4 envelope on the fail-closed body (#1651 review K2).
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    auto j = nlohmann::json::parse(res->body);
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
    CHECK(j["error"]["retry_after_ms"].get<int>() == 5000);
}

// #1651 review K5: route-level catch-arm coverage for the converted dex.signal route.
TEST_CASE("REST dex/signals/{obs_type}: throwing audit → 503, A4, Sec-Audit-Failed",
          "[pg][rest][dex][signals][audit]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.audit_throws = true; // caught by the shared helper, must still fail closed
    auto res = h.sink.Get("/api/v1/dex/signals/process.crashed?window=all");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(res->body.find("WS-1") == std::string::npos);
}

TEST_CASE("REST dex.scope: per-OS coverage returned, NOT audited", "[pg][rest][dex][scope]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.seed_obs("o2", "MB-1", "process.crashed", "Safari", "macos", "2026-06-10T11:00:00Z");
    h.seed_obs("o3", "MB-1", "storage.low", "disk", "macos", "2026-06-10T12:00:00Z");

    auto res = h.sink.Get("/api/v1/dex/scope?window=all");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());

    int64_t macos_types = -1;
    for (const auto& row : j["data"]) {
        if (row["platform"].get<std::string>() == "macos")
            macos_types = row["distinct_types"].get<int64_t>();
    }
    CHECK(macos_types == 2); // process.crashed + storage.low
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST dex.signals/{type}: drill-down fires dex.signal.view audit + returns the shape",
          "[pg][rest][dex][signals][audit]") {
    RestGsHarness h;
    h.seed_obs("o1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.seed_obs("o2", "WS-2", "process.crashed", "chrome.exe", "windows", "2026-06-10T11:00:00Z");

    auto res = h.sink.Get("/api/v1/dex/signals/process.crashed?window=all");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"]["obs_type"].get<std::string>() == "process.crashed");
    REQUIRE(j["data"]["subjects"].is_array());
    REQUIRE(j["data"]["by_os"].is_array());
    REQUIRE(j["data"]["devices"].is_array());
    REQUIRE(j["data"]["by_day"].is_array());
    CHECK(j["data"]["devices"].size() == 2); // WS-1 + WS-2
    CHECK(j["data"]["subjects"][0]["subject"].get<std::string>() == "chrome.exe");

    // Behavioral-PII access → exactly one dex.signal.view, same target shape as
    // the /fragments/dex/catalogue/signal route (governance B4).
    REQUIRE(h.audit_log.size() == 1);
    const auto& a = h.audit_log[0];
    CHECK(a.action == "dex.signal.view");
    CHECK(a.result == "success");
    CHECK(a.target_type == "ObsType");
    CHECK(a.target_id == "process.crashed");
}

TEST_CASE("REST dex.signals/{type}: os filter scopes subjects/devices/by_day (A1 parity)",
          "[pg][rest][dex][signals]") {
    RestGsHarness h;
    h.seed_obs("w1", "WS-1", "process.crashed", "chrome.exe", "windows", "2026-06-10T10:00:00Z");
    h.seed_obs("w2", "WS-2", "process.crashed", "outlook.exe", "windows", "2026-06-10T11:00:00Z");
    h.seed_obs("m1", "MAC-1", "process.crashed", "Safari", "macos", "2026-06-10T12:00:00Z");

    // Windows lens: subjects/devices/by_day all Windows-only, never MAC-1/Safari.
    auto win = h.sink.Get("/api/v1/dex/signals/process.crashed?window=all&os=windows");
    REQUIRE(win);
    CHECK(win->status == 200);
    auto jw = nlohmann::json::parse(win->body);
    CHECK(jw["data"]["os"].get<std::string>() == "windows");
    REQUIRE(jw["data"]["devices"].size() == 2);
    for (const auto& d : jw["data"]["devices"])
        CHECK(d["agent_id"].get<std::string>() != "MAC-1");
    bool win_has_safari = false;
    for (const auto& s : jw["data"]["subjects"])
        if (s["subject"].get<std::string>() == "Safari") win_has_safari = true;
    CHECK_FALSE(win_has_safari);                 // subjects scoped
    REQUIRE(jw["data"]["by_day"].size() == 1);   // all on 06-10
    CHECK(jw["data"]["by_day"][0]["count"].get<int64_t>() == 2); // 2 Windows events, not 3
    CHECK(jw["data"]["by_os"].size() == 2);      // by_os stays cross-OS even under a filter

    // macOS lens: subjects/devices/by_day all macOS-only.
    auto mac = h.sink.Get("/api/v1/dex/signals/process.crashed?window=all&os=macos");
    REQUIRE(mac);
    auto jm = nlohmann::json::parse(mac->body);
    CHECK(jm["data"]["os"].get<std::string>() == "macos");
    REQUIRE(jm["data"]["devices"].size() == 1);
    CHECK(jm["data"]["devices"][0]["agent_id"].get<std::string>() == "MAC-1");
    REQUIRE(jm["data"]["subjects"].size() == 1);
    CHECK(jm["data"]["subjects"][0]["subject"].get<std::string>() == "Safari");
    REQUIRE(jm["data"]["by_day"].size() == 1);
    CHECK(jm["data"]["by_day"][0]["count"].get<int64_t>() == 1);

    // No os param = all-OS (backward compatible).
    auto all = h.sink.Get("/api/v1/dex/signals/process.crashed?window=all");
    REQUIRE(all);
    auto ja = nlohmann::json::parse(all->body);
    CHECK(ja["data"]["os"].get<std::string>() == "all");
    CHECK(ja["data"]["devices"].size() == 3);
}

TEST_CASE("REST dex.signals/{type}: well-formed but absent type → 200 empty arrays (still audited)",
          "[pg][rest][dex][signals]") {
    RestGsHarness h; // empty store
    auto res = h.sink.Get("/api/v1/dex/signals/process.crashed?window=all");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["subjects"].empty());
    CHECK(j["data"]["devices"].empty());
    // The operator requested an individual-identifying view; audit the access
    // regardless of whether the read-model happened to hold matching rows.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "dex.signal.view");
}

TEST_CASE("REST dex.signals/{type}: malformed obs_type → 400, no audit", "[pg][rest][dex][signals]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/dex/signals/foo!bar?window=all");
    REQUIRE(res);
    CHECK(res->status == 400);
    // Validation precedes audit — a rejected malformed request leaves no trace
    // of a behavioral-view access that never happened.
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST dex.signals/{type}: invalid limit → 400", "[pg][rest][dex][signals]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/dex/signals/process.crashed?limit=-3");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST dex: permission gate runs before audit on the per-signal view",
          "[pg][rest][dex][rbac]") {
    RestGsHarness h;
    h.grant_perms = false; // perm_fn denies → 403
    auto res = h.sink.Get("/api/v1/dex/signals/process.crashed?window=all");
    REQUIRE(res);
    CHECK(res->status == 403);
    // No audit emission on a denied request — the permission check is the first
    // statement in the handler, before the dex.signal.view audit.
    CHECK(h.audit_log.empty());
}

// ── Name-anchored, device-applicable Guardian compliance ─────────────────────
// GET /api/v1/guaranteed-state/device-compliance?baseline={name}&agent_id={id}

TEST_CASE("REST gs.device-compliance: applicable subset — only reported guards, keyed by name",
          "[pg][rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    h.seed_rule("r1", "Firewall on");
    h.seed_rule("r2", "RDP NLA");
    h.seed_rule("r3", "BitLocker");
    // One shared "ServiceNow Compliance" Baseline carrying a SUPERSET of 3 guards.
    h.seed_deployed_baseline("ServiceNow Compliance", {"r1", "r2", "r3"});
    // WS-1 only ever armed/reported r1 + r2 (r3's scope_expr excludes WS-1) — so r3
    // is out of scope for WS-1 and must be ABSENT, not pending.
    h.seed_status("e1", "WS-1", "r1", "guard.compliant", "2026-06-20T10:00:00Z");
    h.seed_status("e2", "WS-1", "r2", "drift.detected", "2026-06-20T11:00:00Z");

    // Name keyed via query param; the space is percent-encoded (parse_query_text decodes).
    auto res = h.sink.Get("/api/v1/guaranteed-state/device-compliance"
                          "?baseline=ServiceNow%20Compliance&agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    // A1 envelope: ok_json() wraps the payload as {data:..., meta:...}.
    CHECK(j.contains("data"));
    CHECK(j.contains("meta"));
    auto& d = j["data"];
    CHECK(d["baseline"]["name"].get<std::string>() == "ServiceNow Compliance");
    CHECK(d["deployed"].get<bool>() == true);
    CHECK(d["agent_id"].get<std::string>() == "WS-1");
    // Applicable subset = the 2 guards WS-1 reported; r3 (out of scope) is absent.
    CHECK(d["total_guards"].get<int>() == 2);
    CHECK(d["compliant"].get<int>() == 1);
    CHECK(d["drifted"].get<int>() == 1);
    CHECK(d["errored"].get<int>() == 0);
    CHECK(d["pending"].get<int>() == 0);
    CHECK(d["total_guards"].get<int>() == d["compliant"].get<int>() + d["drifted"].get<int>()
                                             + d["errored"].get<int>() + d["pending"].get<int>());
    CHECK(d["last_updated"].get<std::string>() == "2026-06-20T11:00:00Z");
    REQUIRE(d["guards"].is_array());
    CHECK(d["guards"].size() == 2);
    bool saw_r3 = false, saw_named = false;
    for (auto& g : d["guards"]) {
        if (g["rule_id"].get<std::string>() == "r3")
            saw_r3 = true;
        if (g["rule_id"].get<std::string>() == "r1")
            saw_named = g["name"].get<std::string>() == "Firewall on"
                        && g["status"].get<std::string>() == "compliant"
                        && !g["updated_at"].is_null();
    }
    CHECK_FALSE(saw_r3); // out-of-scope guard absent (not pending)
    CHECK(saw_named);
    bool audited = false;
    for (auto& a : h.audit_log)
        if (a.action == "guardian.device.view" && a.target_id == "WS-1")
            audited = true;
    CHECK(audited);
}

TEST_CASE("REST gs.device-compliance: per-machine variation from one shared baseline",
          "[pg][rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    h.seed_rule("r1", "G1");
    h.seed_rule("r2", "G2");
    h.seed_rule("r3", "G3");
    // Same Baseline, same NAME; each device armed a DIFFERENT subset (per-guard scope_expr)
    // and so reported a different subset — the heart of "different machines, different guards".
    h.seed_deployed_baseline("ServiceNow Compliance", {"r1", "r2", "r3"});
    h.seed_status("a1", "WS-1", "r1", "guard.compliant", "2026-06-20T10:00:00Z");
    h.seed_status("b1", "WS-2", "r1", "guard.compliant", "2026-06-20T10:00:00Z");
    h.seed_status("b2", "WS-2", "r2", "guard.compliant", "2026-06-20T10:00:00Z");
    h.seed_status("b3", "WS-2", "r3", "drift.detected", "2026-06-20T10:00:00Z");

    auto j1 = nlohmann::json::parse(
        h.sink
            .Get("/api/v1/guaranteed-state/device-compliance"
                 "?baseline=ServiceNow%20Compliance&agent_id=WS-1")
            ->body);
    CHECK(j1["data"]["total_guards"].get<int>() == 1); // only r1 applies to WS-1
    // Identity, not just count: WS-1's applicable set is EXACTLY {r1} — a route that
    // returned the wrong guard (r2/r3) would pass a count-only check.
    {
        bool ws1_r1 = false, ws1_other = false;
        for (auto& g : j1["data"]["guards"]) {
            if (g["rule_id"].get<std::string>() == "r1") ws1_r1 = true;
            else ws1_other = true;
        }
        CHECK(ws1_r1);
        CHECK_FALSE(ws1_other);
    }

    auto j2 = nlohmann::json::parse(
        h.sink
            .Get("/api/v1/guaranteed-state/device-compliance"
                 "?baseline=ServiceNow%20Compliance&agent_id=WS-2")
            ->body);
    CHECK(j2["data"]["total_guards"].get<int>() == 3); // all three apply to WS-2
    CHECK(j2["data"]["drifted"].get<int>() == 1);
    // Identity: WS-2 sees {r1,r2,r3} and r3 specifically is the drifted one.
    {
        std::string s_r1, s_r2, s_r3;
        for (auto& g : j2["data"]["guards"]) {
            const auto id = g["rule_id"].get<std::string>();
            if (id == "r1") s_r1 = g["status"].get<std::string>();
            else if (id == "r2") s_r2 = g["status"].get<std::string>();
            else if (id == "r3") s_r3 = g["status"].get<std::string>();
        }
        CHECK(s_r1 == "compliant");
        CHECK(s_r2 == "compliant");
        CHECK(s_r3 == "drifted");
    }
}

TEST_CASE("REST gs.device-compliance: verdicts are isolated per agent (WHERE agent_id)",
          "[pg][rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    h.seed_rule("r1", "G1");
    h.seed_rule("r2", "G2");
    h.seed_deployed_baseline("B", {"r1", "r2"});
    // WS-1 all compliant; WS-2 all errored — the WS-2 rows must not bleed into WS-1.
    h.seed_status("a1", "WS-1", "r1", "guard.compliant", "2026-06-20T10:00:00Z");
    h.seed_status("a2", "WS-1", "r2", "guard.compliant", "2026-06-20T10:00:00Z");
    h.seed_status("b1", "WS-2", "r1", "guard.unhealthy", "2026-06-20T10:00:00Z");
    h.seed_status("b2", "WS-2", "r2", "guard.unhealthy", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=B&agent_id=WS-1");
    REQUIRE(res);
    auto j = nlohmann::json::parse(res->body);
    auto& d = j["data"];
    CHECK(d["compliant"].get<int>() == 2);
    CHECK(d["errored"].get<int>() == 0); // WS-2's errored verdicts must not leak here
    CHECK(d["pending"].get<int>() == 0);

    // The same data, queried for WS-2, positively exercises the errored bucket
    // (guard.unhealthy -> "errored" via event_state_from_type) and confirms the
    // counts are isolated in both directions.
    auto res2 = h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=B&agent_id=WS-2");
    REQUIRE(res2);
    auto j2 = nlohmann::json::parse(res2->body);
    auto& d2 = j2["data"];
    CHECK(d2["errored"].get<int>() == 2);
    CHECK(d2["compliant"].get<int>() == 0);
    CHECK(d2["pending"].get<int>() == 0);
}

TEST_CASE("REST gs.device-compliance: a reported guard NOT in the deployed snapshot is excluded",
          "[pg][rest][guaranteed_state][baseline]") {
    // The denominator is deployed_snapshot ∩ reported. This exercises the OTHER side
    // of the intersection: a guard the device REPORTED but that is NOT a member of the
    // deployed Baseline (left over from a prior Baseline, or retired post-deploy) must
    // be excluded. An implementation that filtered only by agent_id — forgetting the
    // snapshot filter — would wrongly include r-extra and pass every other test here.
    RestGsHarness h;
    h.seed_rule("r1", "In snapshot");
    h.seed_rule("r-extra", "Reported but not a member");
    h.seed_deployed_baseline("B", {"r1"}); // snapshot = {r1} ONLY
    h.seed_status("a1", "WS-1", "r1", "guard.compliant", "2026-06-20T10:00:00Z");
    h.seed_status("a2", "WS-1", "r-extra", "guard.compliant", "2026-06-20T11:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=B&agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    auto& d = j["data"];
    CHECK(d["total_guards"].get<int>() == 1); // only r1 — the snapshot bounds it
    CHECK(d["compliant"].get<int>() == 1);
    bool saw_extra = false;
    for (auto& g : d["guards"])
        if (g["rule_id"].get<std::string>() == "r-extra")
            saw_extra = true;
    CHECK_FALSE(saw_extra); // reported-but-not-a-member guard is excluded
}

TEST_CASE("REST gs.device-compliance: unknown agent on a deployed baseline → empty applicable set",
          "[pg][rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    h.seed_rule("r1", "G1");
    h.seed_rule("r2", "G2");
    h.seed_deployed_baseline("B", {"r1", "r2"});
    // A device that has reported nothing has no applicable guards (report-driven):
    // existence-oracle-safe — 200 with an empty set, never a per-guard enumeration.
    auto res = h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=B&agent_id=ghost");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    auto& d = j["data"];
    CHECK(d["deployed"].get<bool>() == true);
    CHECK(d["total_guards"].get<int>() == 0);
    CHECK(d["pending"].get<int>() == 0);
    REQUIRE(d["guards"].is_array());
    CHECK(d["guards"].empty());
    CHECK(d["last_updated"].is_null());
}

TEST_CASE("REST gs.device-compliance: draft baseline → deployed:false, no guards",
          "[pg][rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    h.seed_rule("r1", "G1");
    // Members set but never deployed → empty deployed_snapshot.
    Baseline b;
    b.name = "Draft B";
    auto bid = h.baseline_store->create_baseline(b);
    REQUIRE(bid.has_value());
    REQUIRE(h.baseline_store->set_members(*bid, {"r1"}).has_value());

    auto res = h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=Draft%20B&agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    auto& d = j["data"];
    CHECK(d["deployed"].get<bool>() == false);
    CHECK(d["total_guards"].get<int>() == 0);
    REQUIRE(d["guards"].is_array());
    CHECK(d["guards"].empty());
}

TEST_CASE("REST gs.device-compliance: unknown baseline name → 404 + not_found audit",
          "[pg][rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    auto res = h.sink.Get(
        "/api/v1/guaranteed-state/device-compliance?baseline=NoSuchBaseline&agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 404);
    // The attempt is still audited (enumeration trail), but result reflects the
    // miss — not "success" — so a 404 probe stream stays distinguishable.
    bool not_found_audited = false;
    for (auto& a : h.audit_log)
        if (a.action == "guardian.device.view" && a.target_id == "WS-1" &&
            a.result == "not_found")
            not_found_audited = true;
    CHECK(not_found_audited);
}

// #2146 Batch B1 review fix, REST-side symmetry - mirrors the two MCP
// fault-injection tests pinning guardian_device_compliance_rollup's
// pii_access_began split (test_mcp_server.cpp, "MCP Guardian:
// get_guardian_device_compliance leaves NO audit row.../audits FAILURE...")
// - this route calls the SAME shared model function, and a symmetric REST-
// side regression test was missing (Gate 4/6 finding).

TEST_CASE("REST gs.device-compliance: leaves NO audit row on a pre-PII "
          "baseline-lookup degrade",
          "[pg][rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    // Degrade BEFORE any lookup - the baseline itself can never be found.
    {
        auto lease = h.bl_pool->try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        yuzu::server::pg::PgResult drop = yuzu::server::pg::exec_params(
            lease.get(), "DROP SCHEMA baseline_store CASCADE", std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
    }
    auto res = h.sink.Get(
        "/api/v1/guaranteed-state/device-compliance?baseline=ServiceNow%20Compliance&agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(h.audit_log.empty()); // no PII was looked up - no audit row owed
}

TEST_CASE("REST gs.device-compliance: audits FAILURE on a post-baseline-found "
          "degrade (PII already touched)",
          "[pg][rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    h.seed_rule("r1", "guard-one");
    h.seed_deployed_baseline("ServiceNow Compliance", {"r1"});

    // Degrade AFTER the baseline is real and deployed - the baseline lookup
    // and deployed_member_rule_ids (both BaselineStore) still succeed;
    // rule_names_for/agent_rule_statuses_for_agent (GuaranteedStateStore) fail.
    {
        auto lease = h.gs_pool->try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        yuzu::server::pg::PgResult drop = yuzu::server::pg::exec_params(
            lease.get(), "DROP SCHEMA guaranteed_state_store CASCADE",
            std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
    }
    auto res = h.sink.Get(
        "/api/v1/guaranteed-state/device-compliance?baseline=ServiceNow%20Compliance&agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 503);
    bool failure_audited = false;
    for (auto& a : h.audit_log)
        if (a.action == "guardian.device.view" && a.target_id == "WS-1" &&
            a.result == "failure")
            failure_audited = true;
    CHECK(failure_audited);
}

TEST_CASE("REST gs.device-compliance: deployed-but-empty baseline → deployed:true, no guards",
          "[pg][rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    // A genuinely deployed Baseline with zero members (snapshot "[]") — distinct
    // from a draft (deployed:false). A consumer must branch on `deployed`, not on
    // total_guards, to decide "No Baseline Deployed".
    h.seed_deployed_baseline("Empty Deployed", {});
    auto res = h.sink.Get(
        "/api/v1/guaranteed-state/device-compliance?baseline=Empty%20Deployed&agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    auto& d = j["data"];
    CHECK(d["deployed"].get<bool>() == true);
    CHECK(d["total_guards"].get<int>() == 0);
    REQUIRE(d["guards"].is_array());
    CHECK(d["guards"].empty());
    // UP-2/comp-1/er-1: deployed but zero applicable Guards reported → NOT assessable.
    // A consumer MUST read assessable:false and refuse to compute a 0/0 compliance %
    // (the green-wash this flag exists to prevent). snapshot_total is the deployed
    // member count (0 here).
    CHECK(d["assessable"].get<bool>() == false);
    CHECK(d["snapshot_total"].get<int>() == 0);
}

TEST_CASE("REST gs.device-compliance: permission gate runs before audit",
          "[pg][rest][guaranteed_state][baseline][rbac]") {
    RestGsHarness h;
    h.seed_rule("r1", "G1");
    h.seed_deployed_baseline("B", {"r1"});
    h.grant_perms = false; // scoped_perm_fn denies → 403
    auto res = h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=B&agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST gs.device-compliance: per-device scope — out-of-scope agent 403, in-scope 200",
          "[pg][rest][guaranteed_state][baseline][rbac]") {
    RestGsHarness h;
    h.seed_rule("r1", "G1");
    h.seed_deployed_baseline("B", {"r1"});
    h.seed_status("e1", "WS-1", "r1", "guard.compliant", "2026-06-20T10:00:00Z");
    h.seed_status("e2", "WS-2", "r1", "guard.compliant", "2026-06-20T10:00:00Z");

    // WS-1 is outside the caller's management-group scope → 403, and the gate runs
    // before the store read + audit (no leak, no audit row). Also proves the route
    // hands the scoped check the RIGHT device id (regression net vs flat perm_fn).
    h.scoped_deny_agent = "WS-1";
    auto denied =
        h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=B&agent_id=WS-1");
    REQUIRE(denied);
    CHECK(denied->status == 403);
    CHECK(h.last_scoped_agent_id == "WS-1");
    CHECK(h.audit_log.empty());

    // WS-2 is in scope → 200.
    auto ok = h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=B&agent_id=WS-2");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(h.last_scoped_agent_id == "WS-2");
}

TEST_CASE("REST gs.device-compliance: unwired scoped_perm_fn → fail-closed 503 (A4)",
          "[pg][rest][guaranteed_state][baseline][rbac]") {
    RestGsHarness h{/*live_deps=*/true, /*wire_scoped_perm=*/false};
    h.seed_rule("r1", "G1");
    h.seed_deployed_baseline("B", {"r1"});
    // With no scoped_perm_fn wired the route MUST fail closed (503) — never silently
    // fall back to the flat gate that would re-introduce the group-scoped lockout.
    auto res = h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=B&agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
    CHECK(j["error"].contains("correlation_id"));
    CHECK(j["meta"]["api_version"] == "v1");
    CHECK(h.audit_log.empty()); // fail-closed before any audit
}

TEST_CASE("REST gs.device-compliance: query-param validation — required + length cap (256)",
          "[pg][rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    h.seed_rule("r1", "G1");
    h.seed_deployed_baseline("B", {"r1"});

    // Missing baseline → 400 A4.
    auto miss_b = h.sink.Get("/api/v1/guaranteed-state/device-compliance?agent_id=WS-1");
    REQUIRE(miss_b);
    CHECK(miss_b->status == 400);
    // Missing agent_id → 400 A4.
    auto miss_a = h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=B");
    REQUIRE(miss_a);
    CHECK(miss_a->status == 400);

    // 256-char baseline name is AT the cap → passes length → reaches the store →
    // 404 (unknown name), proving the cap did not bite a valid-length value.
    const std::string n256(256, 'x');
    auto ok_b = h.sink.Get(
        "/api/v1/guaranteed-state/device-compliance?baseline=" + n256 + "&agent_id=WS-1");
    REQUIRE(ok_b);
    CHECK(ok_b->status == 404);

    // 257-char baseline name is past the cap → 400 A4.
    const std::string n257(257, 'x');
    auto bad_b = h.sink.Get(
        "/api/v1/guaranteed-state/device-compliance?baseline=" + n257 + "&agent_id=WS-1");
    REQUIRE(bad_b);
    CHECK(bad_b->status == 400);
    auto jb = nlohmann::json::parse(bad_b->body);
    CHECK(jb["error"]["code"].get<int>() == 400);
    CHECK(jb["error"].contains("correlation_id"));

    // 257-char agent_id is independently capped → 400 A4 (baseline is a valid name).
    const std::string a257(257, 'a');
    auto bad_a =
        h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=B&agent_id=" + a257);
    REQUIRE(bad_a);
    CHECK(bad_a->status == 400);
    CHECK(nlohmann::json::parse(bad_a->body)["error"].contains("correlation_id"));

    // 256-char agent_id is AT the cap → passes → deployed baseline → 200 (empty set).
    const std::string a256(256, 'a');
    auto ok_a =
        h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=B&agent_id=" + a256);
    REQUIRE(ok_a);
    CHECK(ok_a->status == 200);
}

TEST_CASE("REST gs.device-compliance: control characters in a param → 400, no audit",
          "[pg][rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    h.seed_rule("r1", "G1");
    h.seed_deployed_baseline("B", {"r1"});

    // A newline (%0A) in the name would forge lines in the guardian.device.view audit
    // detail; the route swapped a charset-restricted path regex for arbitrary query
    // bytes, so control bytes (< 0x20) are re-rejected before the scope gate / store.
    auto crlf = h.sink.Get(
        "/api/v1/guaranteed-state/device-compliance?baseline=ok%0Aevil&agent_id=WS-1");
    REQUIRE(crlf);
    CHECK(crlf->status == 400);
    auto j = nlohmann::json::parse(crlf->body);
    CHECK(j["error"]["code"].get<int>() == 400);
    CHECK(j["error"].contains("correlation_id"));
    // Rejected before the scoped-perm gate and the audit emit → no audit row.
    CHECK(h.audit_log.empty());

    // A NUL (%00) in agent_id — would truncate the SQL bind while the audit logged the
    // full string; also rejected.
    auto nul = h.sink.Get(
        "/api/v1/guaranteed-state/device-compliance?baseline=B&agent_id=WS%00x");
    REQUIRE(nul);
    CHECK(nul->status == 400);
}

TEST_CASE("REST gs.device-compliance: audit-persist failure → 503 fail-closed, withholds data",
          "[pg][rest][guaranteed_state][baseline][audit]") {
    RestGsHarness h;
    h.seed_rule("r1", "G1");
    h.seed_deployed_baseline("B", {"r1"});
    h.seed_status("e1", "WS-1", "r1", "guard.compliant", "2026-06-20T10:00:00Z");
    h.audit_succeeds = false; // guardian.device.view row fails to persist

    auto res = h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=B&agent_id=WS-1");
    REQUIRE(res);
    // FAIL-CLOSED (parity with GET /dex/devices/{id}, governance #1549): a behavioral-PII
    // read refuses to serve when the evidence row is known-lost — 503 + Sec-Audit-Failed,
    // the compliance body is WITHHELD (A4 envelope, no `data`), with a retry hint.
    CHECK(res->status == 503);
    REQUIRE(res->has_header("Sec-Audit-Failed"));
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
    CHECK(j["error"].contains("correlation_id"));
    CHECK_FALSE(j.contains("data")); // PII withheld, not served with a degraded flag
    CHECK(h.audit_log.size() == 1);  // the access attempt fired (then failed to persist)
    // cons-1: X-Correlation-Id is set on EVERY path and equals the A4 body cid (the
    // header and body never diverge — parity with the dex.device.view sibling).
    REQUIRE(res->has_header("X-Correlation-Id"));
    CHECK(res->get_header_value("X-Correlation-Id") ==
          j["error"]["correlation_id"].get<std::string>());
}

TEST_CASE("REST gs.device-compliance: a throwing audit_fn → 503 fail-closed, not 500",
          "[pg][rest][guaranteed_state][baseline][audit]") {
    RestGsHarness h;
    h.seed_rule("r1", "G1");
    h.seed_deployed_baseline("B", {"r1"});
    h.seed_status("e1", "WS-1", "r1", "guard.compliant", "2026-06-20T10:00:00Z");
    h.audit_throws = true; // audit store raises mid-call

    auto res = h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=B&agent_id=WS-1");
    REQUIRE(res);
    // A throw is mapped to a persist failure (try/catch) → 503, NOT an uncaught 500
    // (the bare #1549 template would 500; our try/catch closes that).
    CHECK(res->status == 503);
    REQUIRE(res->has_header("Sec-Audit-Failed"));
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
    CHECK_FALSE(j.contains("data")); // qe-2: PII withheld on the throw path too
    CHECK(h.audit_log.empty()); // throw exits before the record → proves the catch arm
    REQUIRE(res->has_header("X-Correlation-Id")); // cons-1
    CHECK(res->get_header_value("X-Correlation-Id") ==
          j["error"]["correlation_id"].get<std::string>());
}

TEST_CASE("REST gs.device-compliance: audit success → 200, no header, serves compliance",
          "[pg][rest][guaranteed_state][baseline][audit]") {
    RestGsHarness h; // default audit_succeeds == true
    h.seed_rule("r1", "G1");
    h.seed_deployed_baseline("B", {"r1"});
    h.seed_status("e1", "WS-1", "r1", "guard.compliant", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=B&agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
    CHECK(res->has_header("X-Correlation-Id")); // cons-1: set on the success path too
    // Data is served only when the audit row landed.
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["total_guards"].get<int>() == 1);
    // assessable + snapshot_total are on the wire (UP-2/comp-1/er-1): a deployed
    // Baseline with a reported applicable Guard is assessable; snapshot_total is the
    // deployed-member count.
    CHECK(j["data"]["assessable"].get<bool>() == true);
    CHECK(j["data"]["snapshot_total"].get<int>() == 1);
}

TEST_CASE("REST gs.device-compliance: audit-fail + unknown baseline → 503 (fail-closed precedes 404)",
          "[pg][rest][guaranteed_state][baseline][audit]") {
    // The audit-fail 503 returns BEFORE the 404 branch, so an audit outage never reveals
    // baseline existence without durable evidence (anti-enumeration — deliberate).
    RestGsHarness h;
    h.audit_succeeds = false;
    auto res =
        h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=NoSuch&agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 503); // NOT 404 — audit-fail wins
    REQUIRE(res->has_header("Sec-Audit-Failed"));
    CHECK(h.audit_log.size() == 1); // the not_found audit attempt fired
}

TEST_CASE("GuaranteedStateStore::rule_names_for resolves ONLY the requested ids",
          "[pg][guaranteed_state][store][rule_names]") {
    // Backs the perf fix: the device-compliance handler resolves guard names with
    // rule_names_for(guard_ids) instead of the full-catalogue rule_names(). Confirm
    // the bounded WHERE rule_id IN (...) returns names for exactly the requested ids.
    RestGsHarness h;
    h.seed_rule("r1", "Name One");
    h.seed_rule("r2", "Name Two");
    h.seed_rule("r3", "Name Three");

    // rule_names_for is now type-distinguishable (ADR-0038 catastrophic-read
    // set): std::expected<unordered_map<...>, std::string>. Not double-wrapped
    // like get_rule (the value type here IS the map, not an optional-of-map),
    // so a single REQUIRE(...has_value()) + arrow/deref suffices.
    auto m = h.store->rule_names_for({"r1", "r3"});
    REQUIRE(m.has_value());
    CHECK(m->size() == 2);
    CHECK((*m)["r1"] == "Name One");
    CHECK((*m)["r3"] == "Name Three");
    CHECK(m->find("r2") == m->end()); // r2 not requested → absent (scoped, not full read)

    auto empty_result = h.store->rule_names_for({});
    REQUIRE(empty_result.has_value());
    CHECK(empty_result->empty()); // empty input → empty map (success, not degrade), no query

    // An unknown id simply has no row — the map omits it (the handler then falls
    // back to rendering the rule_id).
    auto m2 = h.store->rule_names_for({"r1", "nope"});
    REQUIRE(m2.has_value());
    CHECK(m2->size() == 1);
    CHECK((*m2)["r1"] == "Name One");
}

TEST_CASE("REST gs.device-compliance: 404 uses the A4 envelope (code + correlation_id)",
          "[pg][rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    auto res = h.sink.Get(
        "/api/v1/guaranteed-state/device-compliance?baseline=does-not-exist&agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 404);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 404);
    CHECK(j["error"].contains("correlation_id"));
    CHECK(j["error"]["message"].get<std::string>() == "baseline not found");
    CHECK(j["meta"]["api_version"] == "v1");
}

TEST_CASE("REST gs.device-compliance: route + schema are in the OpenAPI spec (A1 discoverability)",
          "[pg][rest][guaranteed_state][baseline][discovery]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    CHECK(res->status == 200);
    nlohmann::json spec;
    // Parsing validates the spec survived the C2026 string-literal split.
    REQUIRE_NOTHROW(spec = nlohmann::json::parse(res->body));
    REQUIRE(spec.contains("paths"));
    CHECK(spec["paths"].contains("/guaranteed-state/device-compliance"));
    REQUIRE(spec.contains("components"));
    REQUIRE(spec["components"].contains("schemas"));
    CHECK(spec["components"]["schemas"].contains("GuaranteedStateDeviceComplianceStatus"));
}

TEST_CASE("REST gs.device-compliance: unrecognized stored state folds into pending (invariant holds)",
          "[pg][rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    h.seed_rule("r1", "G1");
    h.seed_deployed_baseline("B", {"r1"});
    // A corrupt/future state token the public ingest path can never write. The device
    // DID report r1 (so it is applicable), just with an unrecognized verdict.
    h.seed_raw_status("WS-1", "r1", "weird-future-state", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=B&agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    auto& d = j["data"];
    CHECK(d["total_guards"].get<int>() == 1);
    CHECK(d["compliant"].get<int>() == 0);
    CHECK(d["drifted"].get<int>() == 0);
    CHECK(d["errored"].get<int>() == 0);
    CHECK(d["pending"].get<int>() == 1); // unrecognized state -> pending LABEL
    CHECK(d["total_guards"].get<int>() == d["compliant"].get<int>() + d["drifted"].get<int>()
                                             + d["errored"].get<int>() + d["pending"].get<int>());
    // hp-1: the device DID report (the row exists with a real timestamp), so the
    // timestamp is preserved INDEPENDENT of the unrecognized status label — both the
    // per-guard updated_at and the rolled-up last_updated carry it. (Previously these
    // were suppressed to null, conflating "reported, unknown token" with "never
    // reported" — a consumer watching last_updated could not tell them apart.)
    CHECK(d["last_updated"].get<std::string>() == "2026-06-20T10:00:00Z");
    REQUIRE(d["guards"].is_array());
    CHECK(d["guards"].size() == 1);
    CHECK(d["guards"][0]["status"].get<std::string>() == "pending");
    CHECK(d["guards"][0]["updated_at"].get<std::string>() == "2026-06-20T10:00:00Z");
}

TEST_CASE("REST gs.device-compliance: snapshot guard with no rule row falls back to rule_id name",
          "[pg][rest][guaranteed_state][baseline]") {
    RestGsHarness h;
    h.seed_rule("r1", "Real Guard");
    // r-gone is in the deployed snapshot but its rule row was never created (e.g. the
    // Guard was deleted after deploy) -> name falls back to the rule_id. The device
    // reported BOTH guards, so both are applicable.
    h.seed_deployed_baseline("B", {"r1", "r-gone"});
    h.seed_status("e1", "WS-1", "r1", "guard.compliant", "2026-06-20T10:00:00Z");
    h.seed_status("e2", "WS-1", "r-gone", "drift.detected", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=B&agent_id=WS-1");
    REQUIRE(res);
    auto j = nlohmann::json::parse(res->body);
    auto& d = j["data"];
    CHECK(d["total_guards"].get<int>() == 2);
    bool saw_fallback = false;
    for (auto& g : d["guards"]) {
        if (g["rule_id"].get<std::string>() == "r-gone") {
            CHECK(g["name"].get<std::string>() == "r-gone"); // fallback to rule_id
            CHECK(g["status"].get<std::string>() == "drifted");
            saw_fallback = true;
        }
    }
    CHECK(saw_fallback);
}

TEST_CASE("REST gs.device-compliance: rule_names_for chunks the IN-list past 500 (perf-2/UP-6)",
          "[pg][rest][guaranteed_state][baseline]") {
    // A Baseline whose deployed snapshot exceeds the 500-id chunk (and a pre-3.32
    // SQLite's SQLITE_MAX_VARIABLE_NUMBER of 999) must STILL resolve every guard name.
    // An un-chunked IN-list would prepare-fail past the limit and silently drop ALL
    // names to the rule_id fallback fleet-wide; chunking at 500 keeps every name
    // resolved. 600 crosses the boundary (chunk 1 = r0..r499, chunk 2 = r500..r599).
    RestGsHarness h;
    std::vector<std::string> ids;
    for (int i = 0; i < 600; ++i) {
        const std::string rid = "r" + std::to_string(i);
        ids.push_back(rid);
        h.seed_rule(rid, "G" + std::to_string(i));
        h.seed_status("e" + std::to_string(i), "WS-1", rid, "guard.compliant",
                      "2026-06-20T10:00:00Z");
    }
    h.seed_deployed_baseline("Big", ids);

    auto res = h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=Big&agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    auto& d = j["data"];
    CHECK(d["total_guards"].get<int>() == 600);
    CHECK(d["snapshot_total"].get<int>() == 600);
    CHECK(d["compliant"].get<int>() == 600);
    // Every name resolved (name "G<n>" matches rule_id "r<n>"), across BOTH chunks —
    // none fell back to the rule_id, which is what a prepare-fail would have caused.
    int resolved = 0;
    for (auto& g : d["guards"]) {
        const auto rid = g["rule_id"].get<std::string>();
        CHECK(g["name"].get<std::string>() == "G" + rid.substr(1));
        ++resolved;
    }
    CHECK(resolved == 600);
}

// ═════════════════════════════════════════════════════════════════════════
// #4037 — per-guard fleet-wide agent-status drilldown
// (GET /api/v1/guaranteed-state/rules/{rule_id}/status)
// ═════════════════════════════════════════════════════════════════════════

TEST_CASE("REST gs.rule-status: returns agent_id/state/updated_at for every reporting agent",
          "[pg][rest][guaranteed_state][rule_status]") {
    RestGsHarness h;
    h.seed_rule("r1", "rule-one");
    h.seed_status("e1", "WS-1", "r1", "guard.unhealthy", "2026-06-20T10:00:00Z");
    h.seed_status("e2", "WS-2", "r1", "guard.compliant", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/rules/r1/status", h.status_route_headers());
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    CHECK(j["data"].size() == 2);
    CHECK(j["pagination"]["total"].get<int>() == 2);
    std::unordered_map<std::string, std::string> by_agent;
    for (auto& row : j["data"])
        by_agent[row["agent_id"].get<std::string>()] = row["state"].get<std::string>();
    CHECK(by_agent["WS-1"] == "errored");
    CHECK(by_agent["WS-2"] == "compliant");
}

TEST_CASE("REST gs.rule-status: unknown rule_id → 404 (not a store degrade)",
          "[pg][rest][guaranteed_state][rule_status]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/guaranteed-state/rules/no-such-rule/status",
                          h.status_route_headers());
    REQUIRE(res);
    CHECK(res->status == 404);
}

TEST_CASE("REST gs.rule-status: an unwired list_read_fn fails closed (503)",
          "[pg][rest][guaranteed_state][rule_status]") {
    RestGsHarness h(/*live_deps=*/true, /*wire_scoped_perm=*/true, /*wire_app_perf=*/true,
                    /*with_exec_visible=*/true, /*resp_pool=*/nullptr,
                    /*wire_list_read_fn=*/false);
    h.seed_rule("r1", "rule-one");
    auto res = h.sink.Get("/api/v1/guaranteed-state/rules/r1/status");
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("REST gs.rule-status: a service-scoped token is denied outright (same posture as "
          "the fleet /status route)",
          "[pg][rest][guaranteed_state][rule_status]") {
    RestGsHarness h;
    h.seed_rule("r1", "rule-one");
    auto res = h.sink.Get("/api/v1/guaranteed-state/rules/r1/status",
                          h.service_scoped_token_headers("printers"));
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("REST gs.rule-status: a management-group-confined grant sees only visible agents "
          "(AdmitScoped) — same require_list_read composition proof as the fleet /status "
          "route's own [adr0017] test above, pinned here because this route's C++ post-filter "
          "(agent_rule_statuses(rule_id) has no scope parameter of its own) is a genuinely "
          "different code path from /status's SQL-pushed errored_rule_count(agent_scope)",
          "[pg][rest][guaranteed_state][rule_status][adr0017]") {
    RestGsHarness h;
    h.rbac_.set_rbac_enabled(true);
    REQUIRE(h.rbac_.create_role({"GsReader", "", false, 0}).has_value());
    REQUIRE(h.rbac_.set_permission({"GsReader", "GuaranteedState", "Read", "allow"}).has_value());

    ManagementGroup g;
    g.name = "RegionA";
    g.membership_type = "static";
    auto gid = h.mgmt_.create_group(g);
    REQUIRE(gid.has_value());
    REQUIRE(h.mgmt_.add_member(*gid, "WS-1").has_value()); // WS-1 visible; WS-2 is not
    // Group-SCOPED grant, deliberately NOT a global RbacStore::assign_role — carol
    // can see only what RegionA can see, exactly the AdmitScoped fixture shape used
    // by the fleet /status route's own [adr0017] tests above.
    REQUIRE(h.mgmt_.assign_role({*gid, "user", "carol", "GsReader"}).has_value());
    h.session_user = "carol";

    h.seed_rule("r1", "rule-one");
    h.seed_status("e1", "WS-1", "r1", "guard.unhealthy", "2026-06-20T10:00:00Z"); // visible
    h.seed_status("e2", "WS-2", "r1", "guard.compliant", "2026-06-20T10:00:00Z"); // NOT visible

    auto res = h.sink.Get("/api/v1/guaranteed-state/rules/r1/status", h.status_route_headers());
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    // Only WS-1's row is returned — WS-2 is out of carol's management-group scope.
    CHECK(j["data"].size() == 1);
    CHECK(j["data"][0]["agent_id"].get<std::string>() == "WS-1");
    CHECK(j["pagination"]["total"].get<int>() == 1);
}

TEST_CASE("REST gs.rule-status: AdmitScoped with zero visible agents returns an empty list, "
          "not a 403 (INV-2) — the caller has a real grant, it simply resolves to no visible "
          "agents",
          "[pg][rest][guaranteed_state][rule_status][adr0017]") {
    RestGsHarness h;
    h.rbac_.set_rbac_enabled(true);
    REQUIRE(h.rbac_.create_role({"GsReader", "", false, 0}).has_value());
    REQUIRE(h.rbac_.set_permission({"GsReader", "GuaranteedState", "Read", "allow"}).has_value());

    ManagementGroup g;
    g.name = "EmptyRegion";
    g.membership_type = "static";
    auto gid = h.mgmt_.create_group(g);
    REQUIRE(gid.has_value());
    // No members added — dana's group is real and her grant is real, but it
    // contains no agents.
    REQUIRE(h.mgmt_.assign_role({*gid, "user", "dana", "GsReader"}).has_value());
    h.session_user = "dana";

    h.seed_rule("r1", "rule-one");
    h.seed_status("e1", "WS-1", "r1", "guard.unhealthy", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/rules/r1/status", h.status_route_headers());
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    CHECK(j["data"].empty());
    CHECK(j["pagination"]["total"].get<int>() == 0);
}

// ═════════════════════════════════════════════════════════════════════════
// #4037 — per-device all-guards view
// (GET /api/v1/guaranteed-state/agents/{agent_id}/rules)
// ═════════════════════════════════════════════════════════════════════════

TEST_CASE("REST gs.device-all-guards: every guard's state for one device, unscoped to any "
          "Baseline",
          "[pg][rest][guaranteed_state][device_guards]") {
    RestGsHarness h;
    h.seed_rule("r1", "guard-one");
    h.seed_rule("r2", "guard-two");
    h.seed_status("e1", "WS-1", "r1", "guard.unhealthy", "2026-06-20T10:00:00Z");
    h.seed_status("e2", "WS-1", "r2", "guard.compliant", "2026-06-20T10:00:00Z");
    // Different device — must NOT appear in WS-1's response.
    h.seed_status("e3", "WS-2", "r1", "guard.compliant", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/agents/WS-1/rules");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["agent_id"].get<std::string>() == "WS-1");
    CHECK(j["data"]["total_guards"].get<int>() == 2);
    REQUIRE(j["data"]["guards"].is_array());
    CHECK(j["data"]["guards"].size() == 2);
    std::unordered_map<std::string, std::string> by_rule;
    for (auto& g : j["data"]["guards"])
        by_rule[g["rule_id"].get<std::string>()] = g["state"].get<std::string>();
    CHECK(by_rule["r1"] == "errored");
    CHECK(by_rule["r2"] == "compliant");
}

TEST_CASE("REST gs.device-all-guards: a device with no reported guards returns an empty list, "
          "not an error",
          "[pg][rest][guaranteed_state][device_guards]") {
    RestGsHarness h;
    auto res = h.sink.Get("/api/v1/guaranteed-state/agents/never-seen/rules");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["total_guards"].get<int>() == 0);
    CHECK(j["data"]["guards"].empty());
}

TEST_CASE("REST gs.device-all-guards: scoped_perm_fn denies the queried device → 403",
          "[pg][rest][guaranteed_state][device_guards]") {
    RestGsHarness h;
    h.deny_scoped_agent = "WS-9";
    auto res = h.sink.Get("/api/v1/guaranteed-state/agents/WS-9/rules");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.last_scoped_agent_id == "WS-9"); // scoped by the queried device
}

TEST_CASE("REST gs.device-all-guards: an unwired scoped_perm_fn fails closed (503)",
          "[pg][rest][guaranteed_state][device_guards]") {
    RestGsHarness h(/*live_deps=*/true, /*wire_scoped_perm=*/false);
    auto res = h.sink.Get("/api/v1/guaranteed-state/agents/WS-1/rules");
    REQUIRE(res);
    CHECK(res->status == 503);
}

// ── ADR-0031 WS-A4 (ninth family) — seam-bypass tripwires ───────────────────
//
// Gate 3 quality-engineer finding on this seam's own governance round: every
// prior WS-A4 family (network/verify/device/compliance/dex_perf/schedule/
// workflow) shipped a positive, non-crashing tripwire proving each rewired
// handler answers via the family's *Api seam and not a silently-reverted raw
// store call — `rest_api_v1.cpp`/`mcp_server.cpp` are INSPECTED-NOT-ENFORCED
// by check-seam-closure.py (both already #include guaranteed_state_store.hpp
// for the mutators this seam doesn't cover), so a revert compiles clean and
// the static check stays green; only a DYNAMIC test with a real store AND a
// DISTINGUISHING FnGuardianApi double wired at once can catch it (the two
// doors must answer DIFFERENTLY, so a revert flips the test from pass to
// fail). `guardian` shipped with none; these eight close that gap, one per
// rewired REST resource (`test_mcp_server.cpp` carries the MCP-side twins).
//
// Each test seeds REAL, separately-answerable data via the harness's normal
// (mutator, unaffected by this seam) helpers, then wires a `guardian_api_override`
// double that answers the SAME query differently — so a revert-to-raw-store
// would show the REAL data, not the double's.

TEST_CASE("REST gs.rules (seam-bypass tripwire): answers via GuardianApi, not the raw store",
          "[pg][rest][guaranteed_state][twins]") {
    auto seam_api = std::make_shared<yuzu::server::test::FnGuardianApi>(
        []() -> std::expected<std::vector<GuaranteedStateRuleRow>, std::string> {
            GuaranteedStateRuleRow r;
            r.rule_id = "seam-only-id";
            r.name = "seam-only-name";
            return std::vector<GuaranteedStateRuleRow>{r};
        });
    RestGsHarness h(true, true, true, true, nullptr, true, seam_api);
    REQUIRE(h.sink.Post("/api/v1/guaranteed-state/rules",
                        RestGsHarness::make_rule_body("real-id", "real-name"))
                ->status == 201);

    auto res = h.sink.Get("/api/v1/guaranteed-state/rules");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    REQUIRE(j["data"].size() == 1);
    CHECK(j["data"][0]["name"] == "seam-only-name");
    CHECK(j["pagination"]["total"].get<int>() == 1);
}

TEST_CASE("REST gs.rules/{id} (seam-bypass tripwire): answers via GuardianApi, not the raw store",
          "[pg][rest][guaranteed_state][twins]") {
    // Nothing seeded in the real store at "seam-id" — a revert to the raw
    // store would 404; the double answers 200 with a distinguishing name.
    GuaranteedStateRuleRow seam_row;
    seam_row.rule_id = "seam-id";
    seam_row.name = "seam-only-detail";
    auto seam_api = std::make_shared<yuzu::server::test::FnGuardianApi>(
        yuzu::server::test::FnGuardianApi::ListRulesFn{},
        [seam_row](const std::string& id)
            -> std::expected<std::optional<GuaranteedStateRuleRow>, GuaranteedStateReadError> {
            if (id != "seam-id")
                return std::optional<GuaranteedStateRuleRow>{};
            return std::optional<GuaranteedStateRuleRow>{seam_row};
        });
    RestGsHarness h(true, true, true, true, nullptr, true, seam_api);

    auto res = h.sink.Get("/api/v1/guaranteed-state/rules/seam-id");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["name"] == "seam-only-detail");
}

TEST_CASE("REST gs.status (fleet, seam-bypass tripwire): answers via GuardianApi, not the raw "
          "store",
          "[pg][rest][guaranteed_state][twins]") {
    GuardianStatusRollup seam_rollup;
    seam_rollup.total_rules = 999;
    seam_rollup.errored_rules = 888;
    auto seam_api = std::make_shared<yuzu::server::test::FnGuardianApi>(
        yuzu::server::test::FnGuardianApi::ListRulesFn{},
        yuzu::server::test::FnGuardianApi::GetRuleFn{},
        [seam_rollup](const std::optional<std::vector<std::string>>&)
            -> std::optional<GuardianStatusRollup> { return seam_rollup; });
    RestGsHarness h(true, true, true, true, nullptr, true, seam_api);
    // Real store has genuinely different (small) data, proving the response
    // is NOT derived from it.
    h.seed_rule("r1", "real-rule");

    auto res = h.sink.Get("/api/v1/guaranteed-state/status", h.status_route_headers());
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["total_rules"].get<int>() == 999);
    CHECK(j["data"]["errored_rules"].get<int>() == 888);
}

TEST_CASE("REST gs.status/{agent_id} (seam-bypass tripwire): answers via GuardianApi, not the "
          "raw store",
          "[pg][rest][guaranteed_state][twins]") {
    GuardianAgentStatusRollup seam_rollup;
    seam_rollup.total_rules = 777;
    seam_rollup.errored_rules = 666;
    auto seam_api = std::make_shared<yuzu::server::test::FnGuardianApi>(
        yuzu::server::test::FnGuardianApi::ListRulesFn{},
        yuzu::server::test::FnGuardianApi::GetRuleFn{},
        yuzu::server::test::FnGuardianApi::StatusFn{},
        [seam_rollup](const std::string&) -> std::optional<GuardianAgentStatusRollup> {
            return seam_rollup;
        });
    RestGsHarness h(true, true, true, true, nullptr, true, seam_api);
    h.seed_rule("r1", "real-rule");
    h.seed_status("e1", "WS-1", "r1", "guard.unhealthy", "2026-06-20T10:00:00Z");

    auto res = h.sink.Get("/api/v1/guaranteed-state/status/WS-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["total_rules"].get<int>() == 777);
    CHECK(j["data"]["errored_rules"].get<int>() == 666);
}

TEST_CASE("REST gs.rules/{id}/status (seam-bypass tripwire): answers via GuardianApi, not the "
          "raw store",
          "[pg][rest][guaranteed_state][twins]") {
    // The handler makes TWO seam calls — the get_rule() existence pre-check,
    // then rule_status() — and each must be independently revert-sensitive.
    // "seam-rule" exists ONLY in the double: reverting the pre-check to the
    // raw store 404s; reverting rule_status() answers no WS-SEAM row. The
    // real store's r1 is noise that must not surface.
    GuaranteedStateRuleRow found;
    found.rule_id = "seam-rule";
    found.name = "seam-rule-name";
    GuardianRuleAgentStatusRow seam_row;
    seam_row.agent_id = "WS-SEAM";
    seam_row.state = "drifted";
    seam_row.updated_at = "2026-06-20T10:00:00Z";
    auto seam_api = std::make_shared<yuzu::server::test::FnGuardianApi>(
        yuzu::server::test::FnGuardianApi::ListRulesFn{},
        [found](const std::string& id)
            -> std::expected<std::optional<GuaranteedStateRuleRow>, GuaranteedStateReadError> {
            if (id != "seam-rule")
                return std::optional<GuaranteedStateRuleRow>{};
            return std::optional<GuaranteedStateRuleRow>{found};
        },
        yuzu::server::test::FnGuardianApi::StatusFn{},
        yuzu::server::test::FnGuardianApi::AgentStatusFn{},
        [seam_row](const std::string&) -> std::optional<std::vector<GuardianRuleAgentStatusRow>> {
            return std::vector<GuardianRuleAgentStatusRow>{seam_row};
        });
    RestGsHarness h(true, true, true, true, nullptr, true, seam_api);
    h.seed_rule("r1", "rule-one");

    auto res =
        h.sink.Get("/api/v1/guaranteed-state/rules/seam-rule/status", h.status_route_headers());
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    REQUIRE(j["data"].size() == 1);
    CHECK(j["data"][0]["agent_id"] == "WS-SEAM");
}

TEST_CASE("REST gs.agents/{id}/rules (seam-bypass tripwire): answers via GuardianApi, not the "
          "raw store",
          "[pg][rest][guaranteed_state][twins]") {
    GuardianDeviceGuardRow seam_row;
    seam_row.rule_id = "r-seam";
    seam_row.name = "seam-guard";
    seam_row.state = "compliant";
    seam_row.updated_at = "2026-06-20T10:00:00Z";
    auto seam_api = std::make_shared<yuzu::server::test::FnGuardianApi>(
        yuzu::server::test::FnGuardianApi::ListRulesFn{},
        yuzu::server::test::FnGuardianApi::GetRuleFn{},
        yuzu::server::test::FnGuardianApi::StatusFn{},
        yuzu::server::test::FnGuardianApi::AgentStatusFn{},
        yuzu::server::test::FnGuardianApi::RuleStatusFn{},
        [seam_row](const std::string&) -> std::optional<std::vector<GuardianDeviceGuardRow>> {
            return std::vector<GuardianDeviceGuardRow>{seam_row};
        });
    RestGsHarness h(true, true, true, true, nullptr, true, seam_api);
    // Real store has NO guards reported for WS-1 — a revert would answer an
    // empty list.

    auto res = h.sink.Get("/api/v1/guaranteed-state/agents/WS-1/rules");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"]["guards"].is_array());
    REQUIRE(j["data"]["guards"].size() == 1);
    CHECK(j["data"]["guards"][0]["name"] == "seam-guard");
}

TEST_CASE("REST gs.device-compliance (seam-bypass tripwire): answers via GuardianApi, not the "
          "raw store",
          "[pg][rest][guaranteed_state][twins]") {
    GuardianDeviceComplianceRollup seam_rollup;
    seam_rollup.baseline_id = "seam-baseline-id";
    seam_rollup.baseline_name = "SEAM-BASELINE";
    seam_rollup.baseline_lifecycle = "deployed";
    seam_rollup.deployed = true;
    seam_rollup.total_guards = 1;
    auto seam_api = std::make_shared<yuzu::server::test::FnGuardianApi>(
        yuzu::server::test::FnGuardianApi::ListRulesFn{},
        yuzu::server::test::FnGuardianApi::GetRuleFn{},
        yuzu::server::test::FnGuardianApi::StatusFn{},
        yuzu::server::test::FnGuardianApi::AgentStatusFn{},
        yuzu::server::test::FnGuardianApi::RuleStatusFn{},
        yuzu::server::test::FnGuardianApi::DeviceGuardsFn{},
        [seam_rollup](const std::string&, const std::string&, bool* store_degraded,
                     bool* pii_access_began) -> std::optional<GuardianDeviceComplianceRollup> {
            *store_degraded = false;
            *pii_access_began = true;
            return seam_rollup;
        });
    RestGsHarness h(true, true, true, true, nullptr, true, seam_api);
    // No real Baseline named "B" exists — a revert to the raw store would
    // answer 404 (baseline name not found).

    auto res = h.sink.Get("/api/v1/guaranteed-state/device-compliance?baseline=B&agent_id=WS-1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["baseline"]["name"] == "SEAM-BASELINE");
}

TEST_CASE("REST gs.events (seam-bypass tripwire): answers via GuardianApi, not the raw store",
          "[pg][rest][guaranteed_state][twins]") {
    GuaranteedStateEventRow seam_event;
    seam_event.event_id = "seam-event";
    seam_event.rule_id = "r-seam";
    seam_event.agent_id = "WS-SEAM";
    seam_event.event_type = "drift.detected";
    seam_event.severity = "high";
    seam_event.timestamp = "2026-06-20T10:00:00Z";
    auto seam_api = std::make_shared<yuzu::server::test::FnGuardianApi>(
        yuzu::server::test::FnGuardianApi::ListRulesFn{},
        yuzu::server::test::FnGuardianApi::GetRuleFn{},
        yuzu::server::test::FnGuardianApi::StatusFn{},
        yuzu::server::test::FnGuardianApi::AgentStatusFn{},
        yuzu::server::test::FnGuardianApi::RuleStatusFn{},
        yuzu::server::test::FnGuardianApi::DeviceGuardsFn{},
        yuzu::server::test::FnGuardianApi::DeviceComplianceFn{},
        [seam_event](const GuaranteedStateEventQuery&) -> std::vector<GuaranteedStateEventRow> {
            return {seam_event};
        });
    RestGsHarness h(true, true, true, true, nullptr, true, seam_api);
    // No real events exist — a revert to the raw store would answer an
    // empty list.

    auto res = h.sink.Get("/api/v1/guaranteed-state/events");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    REQUIRE(j["data"].size() == 1);
    CHECK(j["data"][0]["event_id"] == "seam-event");
}
