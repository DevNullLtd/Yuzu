/**
 * test_dashboard_group_from_results.cpp — route-handler coverage for
 *   POST /api/dashboard/group-from-results
 *
 * exercised end-to-end through the TestRouteSink seam (#438/#1786), covering
 * the Response:Read confinement the dashboard's group-from-filtered-results
 * flow now applies (D2/D3): the raw `facet_agent_ids` match set is
 * intersected against the caller's visible-agent scope BEFORE the group is
 * materialised, a dropped intersection audits a `response.read`/`denied`
 * row, an all-dropped intersection falls into the PRE-EXISTING 422 ("No
 * agents match the current filters.") with no new oracle, and a partial
 * `add_member` failure is reported honestly (the group is left existing with
 * whatever subset actually landed — no rollback) rather than silently
 * hidden behind the success path.
 *
 * Pinned, ground-truthed against the store (never the HTTP response body
 * alone — a response body assertion cannot tell "the store has {A}" from "the
 * store has {A,B} and the toast just says 1"):
 *   - CONFINED MATERIALISATION: a present, narrower visible set drops the
 *     out-of-scope agent before the group is created; the final membership
 *     read back from ManagementGroupStore is EXACTLY the visible subset.
 *   - ALL-DROPPED: every match is out of scope → the existing 422 "No agents
 *     match the current filters." body, byte-identical to the genuine-empty
 *     case (no new distinguishable error), but the server-side denied audit
 *     still records the drop.
 *   - DEGRADE: a response store that cannot be read 503s with the existing
 *     "could not be read" body BEFORE any scope resolution runs (no denied
 *     audit, no group).
 *   - ADD_MEMBER PARTIAL FAILURE: one member insert is forced to fail (a
 *     BEFORE INSERT trigger on the real management-group membership table —
 *     `add_member`'s own INSERT is `ON CONFLICT (group_id, agent_id) DO
 *     NOTHING`, per management_group_store.cpp, so a duplicate-row
 *     precondition would silently no-op rather than produce a genuine SQL
 *     error; a trigger is the only store-level seam that actually errors).
 *     The group ends up existing with the honest partial membership, a
 *     `group.create_from_results`/`failure` audit row records
 *     added/failed counts, and the HTTP response is a 500 naming the group.
 *   - UNFILTERED (nullopt scope): the legacy-open/global-Response:Read case
 *     — both matching agents materialise, no denied audit fires.
 *
 * Model + conventions borrowed from FragmentHarness
 * (test_dashboard_tar_fragments.cpp:106-180): member order is LOAD-BEARING
 * — `sink` is declared LAST so it is destroyed FIRST, while the
 * DashboardRoutes whose `this` its handlers captured is still alive — and
 * the auth_fn/perm_fn/audit_fn capture lambdas follow the same shape. Unlike
 * that file, this harness wires a REAL Postgres ResponseStore (facets are a
 * Postgres-only feature) alongside the real ManagementGroupStorePg bundle,
 * plus a settable DashboardRoutes::VisibleSetFn passed as register_routes'
 * trailing argument.
 *
 * POST bodies are application/x-www-form-urlencoded (group_name, command_id,
 * plugin, f_* filter params) — the #1786 trap: routes are registered on the
 * sink BEFORE any request is issued, and TestRouteSink's own form parsing
 * (not `extract_form_value`'s raw-body fallback) is what's under test here,
 * exactly as test_dashboard_tar_fragments.cpp:563-582 documents.
 */

#include "dashboard_routes.hpp"
#include "management_group_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "response_store.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <initializer_list>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

constexpr const char* kUser = "grp-op";
constexpr const char* kHost = "yuzu.example:8080";
constexpr const char* kPath = "/api/dashboard/group-from-results";
constexpr const char* kPlugin = "vuln_scan"; // columns: Agent,Severity,Category,Title,Detail
constexpr const char* kCommandId = "cmd-grp-facet-1";

// Shared "responsestore" PgTestTemplate — same key as
// test_response_store.cpp / test_dashboard_results_columns.cpp (one
// migration run across the suite); the callback just needs to produce the
// same schema, not the same source text (shared-key setups are verified by
// structural replay, not textual comparison).
yuzu::test::PgTestTemplate responsestore_tpl{"responsestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResponseStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("responsestore template: store failed to migrate");
}};

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

bool contains(const std::string& hay, std::string_view needle) {
    return hay.find(needle) != std::string::npos;
}

std::set<std::string> member_ids_of(ManagementGroupStore& mg, const std::string& group_id) {
    std::set<std::string> ids;
    for (const auto& m : mg.get_members(group_id))
        ids.insert(m.agent_id);
    return ids;
}

/// Seed a matching facet row (col_idx=1 "Category" = "cat-a") for each of
/// `agents`, all under the same command_id, so a filter of f_category=cat-a
/// matches every one of them.
void seed_matching_responses(ResponseStore& rs, std::initializer_list<std::string> agents) {
    for (const auto& agent : agents) {
        StoredResponse r;
        r.instruction_id = kCommandId;
        r.agent_id = agent;
        r.status = 1;
        r.plugin = kPlugin;
        r.output = "high|cat-a|title|detail\n";
        rs.store(r);
    }
}

struct GroupFromResultsHarness {
    // MEMBER ORDER IS LOAD-BEARING (mirrors FragmentHarness,
    // test_dashboard_tar_fragments.cpp:106-114): `sink` is declared AFTER
    // `routes` so it is destroyed FIRST, while the `DashboardRoutes` whose
    // `this` its handlers captured is still alive. `rs_*`/`mg_bundle` precede
    // `routes` because `routes` borrows both via raw pointers. The members
    // below `sink` (`audits`, `visible_set_fn`, etc.) are read by value
    // through `this` at request-handling time, not by `sink`'s own
    // destructor, so their position relative to `sink` isn't load-bearing.
    std::optional<yuzu::test::PostgresTestDb> rs_db_;
    std::optional<PgPool> rs_pool_;
    std::unique_ptr<ResponseStore> rs_;
    yuzu::test::ManagementGroupStorePg mg_bundle;
    ManagementGroupStore& mg = *mg_bundle;
    DashboardRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    std::vector<AuditRow> audits;

    /// Live-read via `this` (same pattern as FragmentHarness::caller_fn) so a
    /// test can reassign it AFTER construction, before issuing a request.
    /// Default nullopt == unfiltered (legacy-open), matching the production
    /// unwired-VisibleSetFn posture.
    DashboardRoutes::VisibleSetFn visible_set_fn{
        [](const std::string&) -> std::optional<std::set<std::string>> { return std::nullopt; }};

    /// Reassignable AFTER construction, same live-read pattern as
    /// `visible_set_fn` above. Set true to simulate a JIT-elevated session
    /// (CDX-FV-02): `auth_fn` below stamps `elevated_until` in the future
    /// whenever this is true, at the moment each request is authenticated.
    bool elevated_session{false};

    /// Counts invocations of `visible_set_fn` regardless of what it
    /// returns (CDX-FV-04) -- lets a degrade-path test prove the scope
    /// resolver was never even CALLED, not merely that its result was
    /// unobservable in the response.
    int visible_set_fn_calls{0};

    /// @param degrade_response_store true → wire a ResponseStore pointed at
    ///        an unreachable pool (never open), so the 503-before-scope-logic
    ///        path is reachable. `mg` (the confinement substrate the group
    ///        actually gets created in) stays healthy either way — only the
    ///        response store degrades.
    /// @param csrf_trusted_origins forwarded to `set_csrf_trusted_origins`
    ///        BEFORE `register_routes` runs below, per that setter's own
    ///        documented contract (dashboard_routes.hpp) -- CDX-FV-05 needs
    ///        this to actually prove the route reads a configured allowlist,
    ///        which a post-construction call would not exercise correctly.
    explicit GroupFromResultsHarness(bool degrade_response_store = false,
                                     std::vector<std::string> csrf_trusted_origins = {}) {
        // ManagementGroupStorePg's own constructor already SKIPs the whole
        // TEST_CASE when YUZU_TEST_POSTGRES_DSN is unset (before this body
        // runs, per member-initialization order) — REQUIRE here is a
        // documentation-only sanity check, not a first line of defense.
        REQUIRE(mg.is_open());

        if (degrade_response_store) {
            rs_pool_.emplace(
                PgPool::Options{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1});
            rs_ = std::make_unique<ResponseStore>(*rs_pool_);
            REQUIRE_FALSE(rs_->is_open());
        } else {
            rs_db_.emplace(responsestore_tpl);
            INFO("[GroupFromResultsHarness] responsestore fixture status (blank == OK): "
                 << rs_db_->error());
            REQUIRE(rs_db_->available());
            rs_pool_.emplace(PgPool::Options{.conninfo = rs_db_->dsn(), .size = 4});
            rs_ = std::make_unique<ResponseStore>(*rs_pool_);
            REQUIRE(rs_->is_open());
        }

        auto auth_fn = [this](const httplib::Request&,
                             httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = kUser;
            s.role = auth::Role::admin;
            if (elevated_session) {
                // Since HA WS-1/1a DB-clock authority (ADR-2002 §4), is_elevated
                // adjudicates against the local monotonic steady_elevated_until
                // derived by AuthManager::derive_session_deadlines -- hand-
                // stamping elevated_until/elevation_issued_at alone no longer
                // elevates (those wall fields are now only a suspend backstop).
                const std::int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                std::chrono::system_clock::now().time_since_epoch())
                                                .count();
                const std::int64_t life_ms = now_ms + 8LL * 3600 * 1000;
                REQUIRE(auth::AuthManager::derive_session_deadlines(
                    s, now_ms, life_ms, now_ms, /*mfa_verified_ms=*/0,
                    /*elevated_until_ms=*/now_ms + 5 * 60'000, /*elevation_issued_ms=*/now_ms,
                    now_ms));
            }
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& a,
                               const std::string& r, const std::string& tt,
                               const std::string& tid, const std::string& d) {
            audits.push_back({a, r, tt, tid, d});
        };

        if (!csrf_trusted_origins.empty())
            routes.set_csrf_trusted_origins(std::move(csrf_trusted_origins));

        routes.register_routes(
            sink, auth_fn, perm_fn, audit_fn, rs_.get(), &mg,
            /*registry=*/nullptr, /*tag_store=*/nullptr, /*event_bus=*/nullptr,
            /*agents_json_fn=*/[] { return std::string{"[]"}; },
            /*dispatch_fn=*/DashboardRoutes::DispatchFn{},
            /*caller_fn=*/DashboardRoutes::CallerFn{},
            /*resolve_fn=*/DashboardRoutes::ResolveFn{},
            /*metrics=*/nullptr, /*instruction_store=*/nullptr,
            /*visible_set_fn=*/
            [this](const std::string& username) -> std::optional<std::set<std::string>> {
                ++visible_set_fn_calls;
                return visible_set_fn ? visible_set_fn(username) : std::nullopt;
            });
    }

    ResponseStore& rs() const { return *rs_; }

    static std::unordered_map<std::string, std::string> same_site_headers() {
        return {{"Host", kHost}, {"Origin", std::string{"https://"} + kHost}};
    }

    static std::string form_body(const std::string& group_name) {
        return "group_name=" + group_name + "&command_id=" + kCommandId +
               "&plugin=" + kPlugin + "&f_category=cat-a";
    }

    std::unique_ptr<httplib::Response>
    post(const std::string& body,
         const std::unordered_map<std::string, std::string>& headers = same_site_headers()) {
        auto res = sink.dispatch("POST", kPath, body, "application/x-www-form-urlencoded", headers);
        REQUIRE(res != nullptr);
        return res;
    }

    int audits_for(const std::string& action, const std::string& result) const {
        int n = 0;
        for (const auto& a : audits)
            if (a.action == action && a.result == result)
                ++n;
        return n;
    }
    std::string audit_detail(const std::string& action, const std::string& result) const {
        for (const auto& a : audits)
            if (a.action == action && a.result == result)
                return a.detail;
        return {};
    }
    /// Full row lookup (CDX-FV-03): action/result/detail alone don't prove
    /// the documented SIEM taxonomy (target_type="Execution", target_id=
    /// command_id) survived -- a regression there would pass every existing
    /// assertion that only checks detail.
    const AuditRow* audit_row(const std::string& action, const std::string& result) const {
        for (const auto& a : audits)
            if (a.action == action && a.result == result)
                return &a;
        return nullptr;
    }
};

} // namespace

// ── (1) Confined materialisation — store ground truth ──────────────────────

TEST_CASE("group-from-results: a confined visible set materialises only the "
          "visible agent (ground-truthed against the store, not the HTTP body)",
          "[pg][server][dashboard][group_from_results][scope]") {
    GroupFromResultsHarness h;
    seed_matching_responses(h.rs(), {"agent-A", "agent-B"});
    h.visible_set_fn = [](const std::string&) -> std::optional<std::set<std::string>> {
        return std::set<std::string>{"agent-A"};
    };

    auto res = h.post(GroupFromResultsHarness::form_body("confined-group"));
    CHECK(res->status == 200);
    // The success toast reports the CONFINED count (1), not the raw match
    // count (2).
    CHECK(contains(res->get_header_value("HX-Trigger"), "created with 1 agents"));

    // Ground truth: query ManagementGroupStore DIRECTLY. A response-body-only
    // assertion could not tell "the store really has {agent-A}" from "the
    // store has {agent-A,agent-B} and the toast text just lied".
    auto group = h.mg.find_group_by_name("confined-group");
    REQUIRE(group.has_value());
    CHECK(member_ids_of(h.mg, group->id) == std::set<std::string>{"agent-A"});

    REQUIRE(h.audits_for("response.read", "denied") == 1);
    CHECK(h.audit_detail("response.read", "denied") ==
          "scope_dropped=1 surface=group_from_results");
    // CDX-FV-03: the documented SIEM taxonomy (target_type="Execution",
    // target_id=command_id) is part of the contract, not just the detail
    // string -- a regression there would pass the two checks above alone.
    auto row = h.audit_row("response.read", "denied");
    REQUIRE(row != nullptr);
    CHECK(row->target_type == "Execution");
    CHECK(row->target_id == kCommandId);
}

// ── (2) All-dropped → the EXISTING 422, no new oracle ───────────────────────

TEST_CASE("group-from-results: an all-dropped scope falls into the existing "
          "422 (byte-identical to the genuine-empty message)",
          "[pg][server][dashboard][group_from_results][scope]") {
    GroupFromResultsHarness h;
    seed_matching_responses(h.rs(), {"agent-A", "agent-B"});
    h.visible_set_fn = [](const std::string&) -> std::optional<std::set<std::string>> {
        return std::set<std::string>{"agent-Z"}; // disjoint from the match set
    };

    auto res = h.post(GroupFromResultsHarness::form_body("alldropped-group"));
    CHECK(res->status == 422);
    // Exact-equal, not merely `contains` — the boundary is that NO new
    // distinguishable string may appear for the confinement-caused empty
    // case; this is the same body the genuine-zero-match case renders.
    CHECK(res->body ==
          "<span class=\"feedback-error\">No agents match the current filters.</span>");

    // The drop still audits server-side even though the caller sees the
    // ordinary empty-match response.
    REQUIRE(h.audits_for("response.read", "denied") == 1);
    CHECK(h.audit_detail("response.read", "denied") ==
          "scope_dropped=2 surface=group_from_results");

    CHECK_FALSE(h.mg.find_group_by_name("alldropped-group").has_value());
}

// ── (3) Degrade 503 unchanged, before any scope logic ───────────────────────

TEST_CASE("group-from-results: a degraded response store 503s with the "
          "existing body BEFORE any scope resolution runs",
          "[pg][server][dashboard][group_from_results][degrade]") {
    GroupFromResultsHarness h{/*degrade_response_store=*/true};
    // A visible set that, if scope logic ran at all, would matter — proving
    // via its absence from the audit trail that the 503 branch returns
    // before scope is ever resolved.
    h.visible_set_fn = [](const std::string&) -> std::optional<std::set<std::string>> {
        return std::set<std::string>{"agent-A"};
    };

    auto res = h.post(GroupFromResultsHarness::form_body("degrade-group"));
    CHECK(res->status == 503);
    CHECK(contains(res->body, "could not be read"));

    CHECK(h.audits_for("response.read", "denied") == 0);
    CHECK_FALSE(h.mg.find_group_by_name("degrade-group").has_value());
    // CDX-FV-04: prove the ordering claim in this test's own name -- the
    // scope resolver was never even CALLED, not merely that its result
    // never reached the response. Without this, a mutant that resolves
    // scope BEFORE the failing response-store read (reversing the
    // documented ordering) would still pass every assertion above.
    CHECK(h.visible_set_fn_calls == 0);
}

// ── (4) add_member partial failure — honest partial state, no rollback ─────

TEST_CASE("group-from-results: an add_member partial failure is reported "
          "honestly — the group exists with only the members that actually "
          "landed",
          "[pg][server][dashboard][group_from_results][add_member]") {
    GroupFromResultsHarness h;
    seed_matching_responses(h.rs(), {"agent-A", "agent-B"});
    // Default visible_set_fn (nullopt/unfiltered) — both agents match scope;
    // the failure under test is at add_member, not at confinement.

    // management_group_store.cpp's add_member INSERTs with `ON CONFLICT
    // (group_id, agent_id) DO NOTHING` — a duplicate-row precondition would
    // silently no-op (PGRES_COMMAND_OK, 0 rows touched), not error. The only
    // store-level seam that produces a genuine add_member failure is a
    // BEFORE INSERT trigger, scoped to this test's own cloned database
    // (ManagementGroupStorePg's ephemeral clone), that raises only for
    // agent_id='agent-B'.
    {
        PgConn conn{PQconnectdb(h.mg_bundle.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string fn_sql =
            "CREATE OR REPLACE FUNCTION management_group_store.block_agent_b() "
            "RETURNS trigger AS $$ BEGIN IF NEW.agent_id = 'agent-B' THEN "
            "RAISE EXCEPTION 'test: forced add_member failure for agent-B'; "
            "END IF; RETURN NEW; END; $$ LANGUAGE plpgsql;";
        PgResult fn_res{PQexec(conn.get(), fn_sql.c_str())};
        REQUIRE(fn_res.ok());
        PgResult trig_res{PQexec(
            conn.get(),
            "CREATE TRIGGER block_agent_b BEFORE INSERT ON "
            "management_group_store.management_group_members "
            "FOR EACH ROW EXECUTE FUNCTION management_group_store.block_agent_b();")};
        REQUIRE(trig_res.ok());
    }

    auto res = h.post(GroupFromResultsHarness::form_body("partial-group"));
    CHECK(res->status == 500);
    CHECK(contains(res->body, "partial-group"));
    CHECK(contains(res->body, "1 of 2"));

    REQUIRE(h.audits_for("group.create_from_results", "failure") == 1);
    CHECK(h.audit_detail("group.create_from_results", "failure") ==
          "partial_materialisation added=1 failed=1");
    CHECK(h.audits_for("group.create_from_results", "success") == 0);

    // The group HONESTLY exists with the partial membership — no rollback.
    auto group = h.mg.find_group_by_name("partial-group");
    REQUIRE(group.has_value());
    CHECK(member_ids_of(h.mg, group->id) == std::set<std::string>{"agent-A"});
}

// ── (5) Unfiltered nullopt — full materialisation, no denied audit ─────────

TEST_CASE("group-from-results: an unfiltered (nullopt) scope materialises "
          "every matching agent with zero denied audit rows",
          "[pg][server][dashboard][group_from_results][scope]") {
    GroupFromResultsHarness h;
    seed_matching_responses(h.rs(), {"agent-A", "agent-B"});
    // Default visible_set_fn already returns nullopt — no override.

    auto res = h.post(GroupFromResultsHarness::form_body("unfiltered-group"));
    CHECK(res->status == 200);
    CHECK(contains(res->get_header_value("HX-Trigger"), "created with 2 agents"));

    auto group = h.mg.find_group_by_name("unfiltered-group");
    REQUIRE(group.has_value());
    CHECK(member_ids_of(h.mg, group->id) == (std::set<std::string>{"agent-A", "agent-B"}));

    CHECK(h.audits_for("response.read", "denied") == 0);
}

// Branch-review finding (Functional CDX-FV-02, MEDIUM): the elevation bypass
// existed for the POST route (dashboard_routes.cpp) but had no test -- the
// nullopt case above exercises the SAME code path a deny-all-plus-elevated
// caller would (both resolve to "materialise everything"), so it cannot
// distinguish "elevation genuinely bypasses the resolver" from "elevation
// does nothing and the resolver happened to return nullopt anyway".
TEST_CASE("group-from-results: a JIT-elevated session materialises every "
          "matching agent despite a deny-all visible scope",
          "[pg][server][dashboard][group_from_results][elevation]") {
    GroupFromResultsHarness h;
    h.elevated_session = true;
    seed_matching_responses(h.rs(), {"agent-A", "agent-B"});
    // Deny-all for every username -- an elevated caller must bypass this
    // entirely, not resolve to an empty set.
    h.visible_set_fn = [](const std::string&) -> std::optional<std::set<std::string>> {
        return std::set<std::string>{};
    };

    auto res = h.post(GroupFromResultsHarness::form_body("elevated-group"));
    CHECK(res->status == 200);
    CHECK(contains(res->get_header_value("HX-Trigger"), "created with 2 agents"));

    auto group = h.mg.find_group_by_name("elevated-group");
    REQUIRE(group.has_value());
    CHECK(member_ids_of(h.mg, group->id) == (std::set<std::string>{"agent-A", "agent-B"}));
    CHECK(h.audits_for("response.read", "denied") == 0);
    // Elevation must BYPASS the resolver, not merely happen to agree with
    // its (deny-all) answer.
    CHECK(h.visible_set_fn_calls == 0);
}

// ── (6) CSRF same-site gate — branch-review BR-001 ─────────────────────────
// This route materialises management-group membership and, before this fix,
// had no origin check at all (a pre-existing gap, unrelated to the scope
// confinement above, closed in the same round it was found). Mirrors
// test_dashboard_tar_fragments.cpp's coverage of the identical gate on the
// TAR re-enable/purge fragments.

TEST_CASE("group-from-results: CSRF same-site gate rejects cross-origin and "
          "header-less POSTs, never creates a group, before any scope logic",
          "[pg][server][dashboard][group_from_results][csrf]") {
    GroupFromResultsHarness h;
    seed_matching_responses(h.rs(), {"agent-A", "agent-B"});

    SECTION("cross-origin Origin") {
        auto res = h.post(GroupFromResultsHarness::form_body("csrf-group"),
                          {{"Host", kHost}, {"Origin", "https://evil.example"}});
        CHECK(res->status == 403);
        CHECK(h.audit_detail("group.create_from_results", "denied") == "csrf_cross_origin");
        CHECK_FALSE(h.mg.find_group_by_name("csrf-group").has_value());
        // CDX-FV-05: the UI contract (refusal body + HX-Retarget), not just
        // the status code and audit row, is part of what this gate promises
        // -- a broken feedback/retarget would pass every check above.
        CHECK(res->body == "<span class=\"feedback-error\">Cross-origin request refused.</span>");
        CHECK(res->get_header_value("HX-Retarget") == "#group-form-slot");
    }

    SECTION("neither Origin nor Referer — stricter than origin_is_same_site's default") {
        auto res = h.post(GroupFromResultsHarness::form_body("csrf-group"), {{"Host", kHost}});
        CHECK(res->status == 403);
        CHECK(h.audit_detail("group.create_from_results", "denied") == "csrf_cross_origin");
        CHECK_FALSE(h.mg.find_group_by_name("csrf-group").has_value());
    }

    SECTION("same-site Origin is accepted (the default headers every other case in this file uses)") {
        auto res = h.post(GroupFromResultsHarness::form_body("csrf-group"));
        CHECK(res->status == 200);
        CHECK(h.mg.find_group_by_name("csrf-group").has_value());
    }

    // CDX-FV-05: same-site Referer (no Origin at all) must ALSO be accepted
    // -- a strict Origin-only check would silently break every browser
    // request that omits Origin per the standard privacy-sensitive
    // referrer-policy cases, none of which are CSRF.
    SECTION("same-site Referer with no Origin is accepted") {
        auto res = h.post(GroupFromResultsHarness::form_body("csrf-referer-group"),
                          {{"Host", kHost},
                           {"Referer", std::string{"https://"} + kHost + "/dashboard/results"}});
        CHECK(res->status == 200);
        CHECK(h.mg.find_group_by_name("csrf-referer-group").has_value());
    }

    // CDX-FV-05: a configured trusted origin (e.g. a reverse proxy on a
    // different host) must be accepted even though it is cross-host by the
    // bare Host comparison -- proving THIS ROUTE actually reads and passes
    // its configured `csrf_trusted_origins_`, not just that the underlying
    // helper supports the parameter in isolation (test_web_utils.cpp proves
    // that; it can't prove this route wires it through).
}

TEST_CASE("group-from-results: a configured trusted origin is accepted "
          "despite a different Host",
          "[pg][server][dashboard][group_from_results][csrf]") {
    GroupFromResultsHarness h{/*degrade_response_store=*/false,
                              /*csrf_trusted_origins=*/{"https://proxy.example"}};
    seed_matching_responses(h.rs(), {"agent-A", "agent-B"});

    auto res = h.post(GroupFromResultsHarness::form_body("csrf-trusted-group"),
                      {{"Host", kHost}, {"Origin", "https://proxy.example"}});
    CHECK(res->status == 200);
    CHECK(h.mg.find_group_by_name("csrf-trusted-group").has_value());
}
