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
 * (test_dashboard_echo_fragments.cpp:106-180): member order is LOAD-BEARING
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
 * exactly as test_dashboard_echo_fragments.cpp:563-582 documents.
 */

#include "agent_registry.hpp"
#include "audit_store.hpp"
#include "dashboard_routes.hpp"
#include "event_bus.hpp"
#include "management_group_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "response_store.hpp"
#include "test_export_cap_guard.hpp"
#include "test_forensics_tier_fixture.hpp"
#include "test_mgmt_group_pg_helper.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <libpq-fe.h>

#include "agent.pb.h"

#include <cstdint>
#include <ctime>
#include <functional>
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
namespace agent_pb = ::yuzu::agent::v1;

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

/// One frame for `agent` with an explicit category and title (the Search term matches the title).
/// @p plugin is the plugin the row is stored under (the Forensics tier keys on it).
void seed_titled_response(ResponseStore& rs, const std::string& agent, const std::string& category,
                          const std::string& title, const char* plugin = kPlugin) {
    StoredResponse r;
    r.instruction_id = kCommandId;
    r.agent_id = agent;
    r.status = 1;
    r.plugin = plugin;
    r.output = "high|" + category + "|" + title + "|detail\n";
    rs.store(r);
}

std::string q_form_body(const std::string& group_name, const std::string& extra) {
    return "group_name=" + group_name + "&command_id=" + kCommandId + "&plugin=" + kPlugin + extra;
}

/// Makes `add_member` fail for @p agent_id in this test's own cloned database.
/// management_group_store.cpp's add_member INSERTs with `ON CONFLICT (group_id, agent_id) DO
/// NOTHING`, so a duplicate row silently no-ops rather than erroring; a BEFORE INSERT trigger
/// is the only store-level seam that produces a genuine add_member failure.
void block_add_member_for(yuzu::test::ManagementGroupStorePg& bundle, const std::string& agent_id) {
    PgConn conn{PQconnectdb(bundle.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    const std::string fn_sql =
        "CREATE OR REPLACE FUNCTION management_group_store.block_agent_b() "
        "RETURNS trigger AS $$ BEGIN IF NEW.agent_id = '" + agent_id + "' THEN "
        "RAISE EXCEPTION 'test: forced add_member failure'; "
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

// Same key and schema as test_plugin_result_audit.cpp's audit-only template (one migration run).
yuzu::test::PgTestTemplate group_audit_tpl{"agentaudit", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    AuditStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("agentaudit template: store failed to migrate");
}};

struct GroupFromResultsHarness {
    // MEMBER ORDER IS LOAD-BEARING (mirrors FragmentHarness,
    // test_dashboard_echo_fragments.cpp:106-114): `sink` is declared AFTER
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
    // #4990: the caller's Forensics visibility (admin by default so the cases that are not about
    // the tier keep their meaning). Declared before `routes`: the resolver borrows it.
    yuzu::server::test::ForensicsCaller forensics;
    // The Search term also matches an agent's registry display name. Unwired (nullptr) unless the
    // case asks for it; declared before `routes`, which borrows the registry by raw pointer.
    yuzu::MetricsRegistry metrics;
    yuzu::server::detail::EventBus bus;
    std::unique_ptr<yuzu::server::detail::AgentRegistry> registry;
    DashboardRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    std::vector<AuditRow> audits;

    /// #3619: whether the audit store persists a given row. Read live per row, so a case can
    /// fail exactly one (action, result) and leave the rest stored. Default: every row persists.
    std::function<bool(const AuditRow&)> audit_persists{[](const AuditRow&) { return true; }};
    /// #3619: when set, every row is written to this REAL AuditStore and its persist outcome is
    /// the store's own (the last step of production's AuthRoutes::audit_log), instead of
    /// `audit_persists`. Lets a case assert the store's emit-failure counter, the value
    /// published as yuzu_server_audit_emit_failed_total.
    AuditStore* real_audit{nullptr};
    /// #3619: whether `group_name_probe` already existed when the `attempted` row was written.
    /// Proves the row precedes the mutation, not merely that both happened.
    std::string group_name_probe;
    std::optional<bool> group_existed_at_attempted;

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

    /// The Response:Read admission a Search term needs (#5700: it matches stored output content).
    /// Admits by default (unconfined: scope nullopt); a case sets `fleet_read_admit = false` to
    /// deny, or `fleet_read_wired = false` for the unwired fail-closed contract. Both are read live
    /// per request; `fleet_read_calls` proves whether the gate ran at all.
    bool fleet_read_admit{true};
    int fleet_read_calls{0};
    std::string fleet_read_securable;
    std::string fleet_read_operation;

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
    /// @param with_registry true → wire an AgentRegistry (see @ref register_host).
    explicit GroupFromResultsHarness(bool degrade_response_store = false,
                                     std::vector<std::string> csrf_trusted_origins = {},
                                     bool with_registry = false) {
        if (with_registry)
            registry = std::make_unique<yuzu::server::detail::AgentRegistry>(bus, metrics);
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
        // ONE recording sink behind both callbacks, as production wires ONE `audit_log` behind
        // both (server.cpp): the persist-reporting `set_persist_audit_fn` sink the `attempted`
        // row goes through, and `audit_fn` for the outcome, refusal and scope-drop rows. Each
        // returns the store's verdict for that row (#3619).
        auto record = [this](const std::string& a, const std::string& r, const std::string& tt,
                             const std::string& tid, const std::string& d) -> bool {
            AuditRow row{a, r, tt, tid, d};
            if (r == "attempted" && !group_name_probe.empty())
                group_existed_at_attempted = mg.find_group_by_name(group_name_probe).has_value();
            bool ok = false;
            if (real_audit) {
                AuditEvent ev;
                ev.timestamp = static_cast<std::int64_t>(std::time(nullptr));
                ev.principal = kUser;
                ev.action = a;
                ev.result = r;
                ev.target_type = tt;
                ev.target_id = tid;
                ev.detail = d;
                ok = real_audit->log(ev);
            } else {
                ok = audit_persists(row);
            }
            audits.push_back(std::move(row));
            return ok;
        };
        auto audit_fn = [record](const httplib::Request&, const std::string& a,
                                 const std::string& r, const std::string& tt,
                                 const std::string& tid, const std::string& d) {
            return record(a, r, tt, tid, d);
        };
        routes.set_persist_audit_fn(audit_fn);

        if (!csrf_trusted_origins.empty())
            routes.set_csrf_trusted_origins(std::move(csrf_trusted_origins));
        yuzu::server::test::wire_forensics(routes, forensics);
        routes.set_fleet_read_fn([this](const httplib::Request&, httplib::Response& res,
                                        const std::string& securable, const std::string& op)
                                     -> authz::FleetReadGate {
            ++fleet_read_calls;
            fleet_read_securable = securable;
            fleet_read_operation = op;
            if (!fleet_read_admit) {
                res.status = 403;
                res.set_content(R"({"error":"permission denied"})", "application/json");
                return {false, authz::deny_all()};
            }
            return {true, std::nullopt};
        });

        routes.register_routes(
            sink, auth_fn, perm_fn, audit_fn, rs_.get(), &mg,
            registry.get(), /*tag_store=*/nullptr, /*event_bus=*/nullptr,
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

    /// Registers @p agent_id under @p hostname (the registry's display name for it). Needs the
    /// harness built with `with_registry`.
    void register_host(const std::string& agent_id, const std::string& hostname) {
        REQUIRE(registry != nullptr);
        agent_pb::AgentInfo info;
        info.set_agent_id(agent_id);
        info.set_hostname(hostname);
        info.mutable_platform()->set_os("linux");
        info.mutable_platform()->set_arch("x86_64");
        info.set_agent_version("0.13.0");
        (void)registry->register_agent(info);
    }

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

// ── (2a) #4990: the Forensics tier narrows the membership this materializes ───────────────────────

TEST_CASE("group-from-results: agents matched only through Forensics rows the caller may not read "
          "are not materialized, and look like no match",
          "[pg][server][dashboard][group_from_results][security][forensics]") {
    GroupFromResultsHarness h;
    // agent-A and agent-B match through a Forensics plugin; agent-C through an ordinary one.
    for (const char* agent : {"agent-A", "agent-B"}) {
        StoredResponse r;
        r.instruction_id = kCommandId;
        r.agent_id = agent;
        r.status = 1;
        r.plugin = yuzu::server::test::kForensicsPlugin;
        r.output = "high|cat-a|title|detail\n";
        h.rs().store(r);
    }
    {
        StoredResponse r;
        r.instruction_id = kCommandId;
        r.agent_id = "agent-C";
        r.status = 1;
        r.plugin = yuzu::server::test::kOrdinaryPlugin;
        r.output = "high|cat-a|title|detail\n";
        h.rs().store(r);
    }

    SECTION("without Forensics:Read the membership is exactly the ordinary match") {
        h.forensics.viewer();
        auto res = h.post(GroupFromResultsHarness::form_body("tier-viewer-group"));
        CHECK(res->status == 200);
        auto group = h.mg.find_group_by_name("tier-viewer-group");
        REQUIRE(group.has_value());
        CHECK(member_ids_of(h.mg, group->id) == std::set<std::string>{"agent-C"});
    }
    SECTION("a global Forensics:Read materializes every match") {
        h.forensics.admin();
        auto res = h.post(GroupFromResultsHarness::form_body("tier-admin-group"));
        CHECK(res->status == 200);
        auto group = h.mg.find_group_by_name("tier-admin-group");
        REQUIRE(group.has_value());
        CHECK(member_ids_of(h.mg, group->id) ==
              std::set<std::string>{"agent-A", "agent-B", "agent-C"});
    }
    SECTION("a per-agent subset is unsupported and fails closed: no Forensics match is materialized") {
        h.forensics.unsupported_subset({"agent-B"});
        auto res = h.post(GroupFromResultsHarness::form_body("tier-subset-group"));
        CHECK(res->status == 200);
        auto group = h.mg.find_group_by_name("tier-subset-group");
        REQUIRE(group.has_value());
        CHECK(member_ids_of(h.mg, group->id) == std::set<std::string>{"agent-C"});
    }
}

TEST_CASE("group-from-results: when every match is a Forensics row the caller may not read, the "
          "answer is the ordinary 422 and no group exists",
          "[pg][server][dashboard][group_from_results][security][forensics]") {
    GroupFromResultsHarness h;
    StoredResponse r;
    r.instruction_id = kCommandId;
    r.agent_id = "agent-A";
    r.status = 1;
    r.plugin = yuzu::server::test::kForensicsPlugin;
    r.output = "high|cat-a|title|detail\n";
    h.rs().store(r);

    h.forensics.viewer();
    auto res = h.post(GroupFromResultsHarness::form_body("tier-none-group"));
    CHECK(res->status == 422);
    // Byte-identical to the genuine-empty body: nothing distinguishes a filtered match.
    CHECK(res->body ==
          "<span class=\"feedback-error\">No agents match the current filters.</span>");
    CHECK_FALSE(h.mg.find_group_by_name("tier-none-group").has_value());
    // The filtered row leaves no scope-drop trace either.
    CHECK(h.audits_for("response.read", "denied") == 0);
}

TEST_CASE("group-from-results: an Unknown Forensics decision shows a visible notice (200) and creates "
          "no group",
          "[pg][server][dashboard][group_from_results][security][forensics]") {
    GroupFromResultsHarness h;
    StoredResponse r;
    r.instruction_id = kCommandId;
    r.agent_id = "agent-A";
    r.status = 1;
    r.plugin = yuzu::server::test::kOrdinaryPlugin;
    r.output = "high|cat-a|title|detail\n";
    h.rs().store(r);

    h.forensics.unknown();
    auto res = h.post(GroupFromResultsHarness::form_body("tier-unknown-group"));
    // 200, not 503: htmx drops a 4xx/5xx body, and the notice below is the operator's only signal.
    CHECK(res->status == 200);
    CHECK(res->body.find("class=\"feedback-error\"") != std::string::npos);
    CHECK(res->body.find("could not be completed") != std::string::npos);
    CHECK(res->body.find("Nothing was created") != std::string::npos);
    // The form is hx-swap="none": the body and HX-Retarget are never displayed. The operator sees
    // the refusal through the page's toast channel (the HX-Trigger showToast event every other
    // handler of this page uses), carrying exactly this constant message at the error level.
    CHECK(res->get_header_value("HX-Trigger") ==
          R"({"showToast":{"message":"The permission check for this action could not be completed. )"
          R"(Nothing was created. Retry shortly.","level":"error"}})");
    CHECK(res->get_header_value("HX-Retarget").empty());
    // This action materializes membership: an Unknown answer must create nothing, not a group from
    // the ordinary rows alone.
    CHECK_FALSE(h.mg.find_group_by_name("tier-unknown-group").has_value());

    // Control: a Denied decision still creates the group from the ordinary row.
    h.forensics.viewer();
    auto ok = h.post(GroupFromResultsHarness::form_body("tier-denied-group"));
    CHECK(ok->status != 503);
    CHECK(ok->body.find("Nothing was created") == std::string::npos);
    CHECK(ok->get_header_value("HX-Trigger").find("could not be completed") == std::string::npos);
    CHECK(h.mg.find_group_by_name("tier-denied-group").has_value());
}

// -- (2b) #5623: an empty match with a filter over the ingest bound says so --

TEST_CASE("group-from-results: a 422 for an over-bound filter value explains the undercount, "
          "status and no-group unchanged",
          "[pg][server][dashboard][group_from_results][facets]") {
    GroupFromResultsHarness h;
    seed_matching_responses(h.rs(), {"agent-A"});

    const std::string plain =
        "<span class=\"feedback-error\">No agents match the current filters.</span>";
    const std::string over_bound = "<span class=\"feedback-error\">No agents match the current "
                                   "filters. A filter value is longer than " +
                                   std::to_string(kMaxFacetValueBytes) +
                                   " bytes; values that long are not indexed in newly stored "
                                   "responses, so this may be an undercount.</span>";
    auto body_with = [](const std::string& name, const std::string& category) {
        return "group_name=" + name + "&command_id=" + kCommandId + "&plugin=" + kPlugin +
               "&f_category=" + category;
    };

    SECTION("one byte over the bound: 422, the explanatory body, no value echo, no group") {
        const std::string value(kMaxFacetValueBytes + 1, 'z');
        auto res = h.post(body_with("overbound-group", value));
        CHECK(res->status == 422);
        CHECK(res->body == over_bound);
        CHECK_FALSE(contains(res->body, "zzzz"));
        CHECK_FALSE(h.mg.find_group_by_name("overbound-group").has_value());
    }

    SECTION("a value that is short raw but over the bound once stored: 422 with the explanation") {
        // NOTE: an undecoded "%00" is also 3 bytes, so this reads the same if the request decoder
        // stopped producing real NUL bytes; the real-byte helper case in
        // test_group_agent_count_preview.cpp pins the rule itself.
        // 683 NUL bytes (%00) are 2049 stored bytes: each becomes a 3-byte U+FFFD at ingest.
        std::string nuls;
        for (std::size_t i = 0; i < 683; ++i)
            nuls += "%00";
        auto res = h.post(body_with("nul-overbound-group", nuls));
        CHECK(res->status == 422);
        CHECK(res->body == over_bound);
        CHECK_FALSE(h.mg.find_group_by_name("nul-overbound-group").has_value());
    }

    SECTION("exactly the bound: the plain body (nothing changed for a value that is indexed)") {
        const std::string value(kMaxFacetValueBytes, 'z');
        auto res = h.post(body_with("atbound-group", value));
        CHECK(res->status == 422);
        CHECK(res->body == plain);
    }

    SECTION("a short filter that matches nothing: the plain body") {
        auto res = h.post(body_with("nomatch-group", "no-such-category"));
        CHECK(res->status == 422);
        CHECK(res->body == plain);
    }

    SECTION("a short matching filter still creates the group") {
        auto res = h.post(GroupFromResultsHarness::form_body("match-group"));
        CHECK(res->status != 422);
        CHECK(h.mg.find_group_by_name("match-group").has_value());
    }
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
    // The form never swaps a body (hx-swap="none"), so the refusal also travels on the toast
    // channel: exactly this constant message, at the error level.
    CHECK(res->get_header_value("HX-Trigger") ==
          R"({"showToast":{"message":"Agent count unavailable. The response store could not be read. )"
          R"(Nothing was created. Retry shortly.","level":"error"}})");
    CHECK(res->get_header_value("HX-Retarget").empty());

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

    // A trigger in this test's own cloned database (see block_add_member_for).
    block_add_member_for(h.mg_bundle, "agent-B");

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
// test_dashboard_echo_fragments.cpp's coverage of the identical gate on the
// Echo re-enable/purge fragments.

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

// ── Success toast: the HX-Trigger header is always valid, single-line, ASCII JSON ───────────

namespace {

/// Percent-encode every byte that is not an unreserved URL character, so a test can put any
/// byte (quote, backslash, CR/LF, tab, UTF-8) into the urlencoded `group_name` field.
std::string percent_encode(std::string_view in) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    for (const unsigned char c : in) {
        const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
        if (unreserved) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 0x0F]);
        }
    }
    return out;
}

} // namespace

TEST_CASE("group-from-results: the success toast is valid single-line ASCII JSON whatever the "
          "group name holds",
          "[pg][server][dashboard][group_from_results][toast]") {
    GroupFromResultsHarness h;
    seed_matching_responses(h.rs(), {"agent-A"});

    const auto run = [&](const std::string& name) {
        auto res = h.post(GroupFromResultsHarness::form_body(percent_encode(name)));
        REQUIRE(res->status == 200);
        const std::string trigger = res->get_header_value("HX-Trigger");
        // A header dropped by the transport (CR/LF in the value) leaves the operator with no
        // confirmation and no list refresh, so its absence is itself the failure.
        REQUIRE_FALSE(trigger.empty());
        for (const unsigned char c : trigger) {
            INFO("byte " << static_cast<int>(c) << " in the HX-Trigger header");
            REQUIRE((c >= 0x20 && c < 0x7F));
        }
        const auto j = nlohmann::json::parse(trigger, nullptr, /*allow_exceptions=*/false);
        REQUIRE_FALSE(j.is_discarded());
        REQUIRE(j.is_object());
        // Event structure is unchanged: the toast plus the list-refresh trigger, nothing else.
        CHECK(j.size() == 2);
        REQUIRE(j.contains("showToast"));
        REQUIRE(j["showToast"].is_object());
        CHECK(j["showToast"].size() == 2);
        CHECK(j["showToast"].value("level", "") == "success");
        REQUIRE(j.contains("agentChanged"));
        CHECK(j["agentChanged"] == true);
        // The message round-trips the name byte for byte.
        CHECK(j["showToast"].value("message", "") == "Group '" + name + "' created with 1 agents");
    };

    SECTION("an ordinary name is unchanged") {
        run("plain-group");
        CHECK(h.mg.find_group_by_name("plain-group").has_value());
    }
    SECTION("a double quote") {
        run("say \"hi\"");
    }
    SECTION("a backslash") {
        run("a\\b");
    }
    SECTION("a newline") {
        run("line1\nline2");
    }
    SECTION("a carriage return and line feed") {
        run("line1\r\nline2");
    }
    SECTION("a tab") {
        run("col1\tcol2");
    }
    SECTION("a non-ASCII name") {
        run("Gr\xC3\xBC" "ppe \xE2\x9C\x93 \xE6\x97\xA5\xE6\x9C\xAC");
    }
    SECTION("markup characters travel as text, not HTML entities") {
        run("R&D <team> 'north'");
    }
    SECTION("a long name is cut in the toast so the header stays small, and the group keeps it whole") {
        // 60 three-byte characters = 180 bytes of name, which would escape to 360 bytes.
        std::string name;
        for (int i = 0; i < 60; ++i)
            name += "\xE6\x97\xA5";
        auto res = h.post(GroupFromResultsHarness::form_body(percent_encode(name)));
        REQUIRE(res->status == 200);
        const std::string trigger = res->get_header_value("HX-Trigger");
        REQUIRE_FALSE(trigger.empty());
        CHECK(trigger.size() < 400);
        const auto j = nlohmann::json::parse(trigger, nullptr, /*allow_exceptions=*/false);
        REQUIRE_FALSE(j.is_discarded());
        const std::string msg = j["showToast"].value("message", "");
        CHECK(msg.find("...' created with 1 agents") != std::string::npos);
        CHECK(h.mg.find_group_by_name(name).has_value()); // the store keeps the full name
    }
}

// ── #5700: the results page's Search term is part of the group ──────────────

TEST_CASE("group-from-results: the Search term alone defines the group (ground-truthed against "
          "the store), and with a column filter the two intersect",
          "[pg][server][dashboard][group_from_results][search]") {
    GroupFromResultsHarness h;
    seed_titled_response(h.rs(), "agent-A", "cat-a", "alpha");
    seed_titled_response(h.rs(), "agent-B", "cat-a", "beta");
    seed_titled_response(h.rs(), "agent-C", "cat-b", "alpha2");

    SECTION("q alone: exactly the agents with a matching line, whatever their category") {
        auto res = h.post(q_form_body("q-only", "&q=alp"));
        CHECK(res->status == 200);
        CHECK(contains(res->get_header_value("HX-Trigger"), "created with 2 agents"));
        auto group = h.mg.find_group_by_name("q-only");
        REQUIRE(group.has_value());
        CHECK(member_ids_of(h.mg, group->id) == std::set<std::string>{"agent-A", "agent-C"});
        // The audit row records that a Search term shaped the set, never the term itself.
        CHECK(contains(h.audit_detail("group.create_from_results", "success"), "text_query=1"));
        CHECK_FALSE(contains(h.audit_detail("group.create_from_results", "success"), "alp"));
    }
    SECTION("q with a column filter: the intersection, not either alone") {
        auto res = h.post(q_form_body("q-and-filter", "&f_category=cat-a&q=alp"));
        CHECK(res->status == 200);
        auto group = h.mg.find_group_by_name("q-and-filter");
        REQUIRE(group.has_value());
        CHECK(member_ids_of(h.mg, group->id) == std::set<std::string>{"agent-A"});
    }
    SECTION("no q: the filter-only path is unchanged and carries no marker") {
        auto res = h.post(q_form_body("filter-only", "&f_category=cat-a"));
        CHECK(res->status == 200);
        auto group = h.mg.find_group_by_name("filter-only");
        REQUIRE(group.has_value());
        CHECK(member_ids_of(h.mg, group->id) == std::set<std::string>{"agent-A", "agent-B"});
        CHECK_FALSE(contains(h.audit_detail("group.create_from_results", "success"), "text_query"));
    }
    SECTION("a q that matches nothing: the existing 422, now with a toast, and no group row") {
        auto res = h.post(q_form_body("q-none", "&q=zzznomatch"));
        CHECK(res->status == 422);
        CHECK(contains(res->body, "No agents match the current filters."));
        CHECK(res->get_header_value("HX-Retarget") == "#group-form-slot");
        CHECK(contains(res->get_header_value("HX-Trigger"), "showToast"));
        CHECK_FALSE(h.mg.find_group_by_name("q-none").has_value());
    }
}

TEST_CASE("create-group-form: previews the Search-term count and carries q as a hidden field",
          "[pg][server][dashboard][group_from_results][search]") {
    GroupFromResultsHarness h;
    seed_titled_response(h.rs(), "agent-A", "cat-a", "alpha");
    seed_titled_response(h.rs(), "agent-B", "cat-a", "beta");
    seed_titled_response(h.rs(), "agent-C", "cat-b", "alpha2");
    const std::string base = std::string{"/fragments/create-group-form?command_id="} + kCommandId +
                             "&plugin=" + kPlugin;

    auto res = h.sink.Get(base + "&q=alp");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);
    CHECK(contains(res->body, "2 agents will be added"));
    CHECK(contains(res->body, "<input type=\"hidden\" name=\"q\" value=\"alp\">"));
    CHECK_FALSE(contains(res->body, "disabled"));

    // A quote in the term is HTML-escaped once, never raw and never double-escaped.
    auto quoted = h.sink.Get(base + "&q=a%22b");
    REQUIRE(quoted != nullptr);
    CHECK(contains(quoted->body, "name=\"q\" value=\"a&quot;b\""));
    CHECK_FALSE(contains(quoted->body, "a\"b"));
    CHECK_FALSE(contains(quoted->body, "&amp;quot;"));

    // No q: no hidden q field (the filter-only form is byte-compatible with before).
    auto plain = h.sink.Get(base + "&f_category=cat-a");
    REQUIRE(plain != nullptr);
    CHECK_FALSE(contains(plain->body, "name=\"q\""));
}

// A Search set is still confined to the caller's visible scope: the preview and the persisted
// membership both drop an agent the caller may not read, even though its lines match the term.
TEST_CASE("group-from-results: a Search set is confined to the visible scope, in the preview and "
          "in the persisted membership",
          "[pg][server][dashboard][group_from_results][search][scope]") {
    GroupFromResultsHarness h;
    seed_titled_response(h.rs(), "agent-A", "cat-a", "alpha");
    seed_titled_response(h.rs(), "agent-B", "cat-a", "alpha2"); // matches q, out of scope
    seed_titled_response(h.rs(), "agent-C", "cat-a", "beta");   // in scope, not a match
    h.visible_set_fn = [](const std::string&) -> std::optional<std::set<std::string>> {
        return std::set<std::string>{"agent-A", "agent-C"};
    };
    const std::string base = std::string{"/fragments/create-group-form?command_id="} + kCommandId +
                             "&plugin=" + kPlugin;

    SECTION("the preview counts, and the group holds, only the visible match") {
        auto form = h.sink.Get(base + "&q=alp");
        REQUIRE(form != nullptr);
        CHECK(contains(form->body, "1 agent will be added"));
        CHECK_FALSE(contains(form->body, "2 agents will be added"));

        auto res = h.post(q_form_body("q-confined", "&q=alp"));
        CHECK(res->status == 200);
        auto group = h.mg.find_group_by_name("q-confined");
        REQUIRE(group.has_value());
        CHECK(member_ids_of(h.mg, group->id) == std::set<std::string>{"agent-A"});
        REQUIRE(h.audits_for("response.read", "denied") == 1);
        CHECK(h.audit_detail("response.read", "denied") ==
              "scope_dropped=1 surface=group_from_results");
    }
    SECTION("every match out of scope: the existing 422, and no group") {
        auto res = h.post(q_form_body("q-all-dropped", "&q=alpha2"));
        CHECK(res->status == 422);
        CHECK(res->body ==
              "<span class=\"feedback-error\">No agents match the current filters.</span>");
        CHECK_FALSE(h.mg.find_group_by_name("q-all-dropped").has_value());
        CHECK(h.audit_detail("response.read", "denied") ==
              "scope_dropped=1 surface=group_from_results");
    }
}

// The Search term also matches the agent's registry display name (the same predicate the results
// table renders), so an agent whose stored lines do not contain the term still joins the group.
TEST_CASE("group-from-results: a Search term matching only an agent's registry display name "
          "includes that agent, in the preview and in the persisted membership",
          "[pg][server][dashboard][group_from_results][search]") {
    GroupFromResultsHarness h(/*degrade_response_store=*/false, /*csrf_trusted_origins=*/{},
                              /*with_registry=*/true);
    h.register_host("agent-D", "zeta-box");
    h.register_host("agent-E", "plain-box");
    seed_titled_response(h.rs(), "agent-D", "cat-a", "alpha"); // no "zeta" in any stored field
    seed_titled_response(h.rs(), "agent-E", "cat-a", "alpha");
    const std::string base = std::string{"/fragments/create-group-form?command_id="} + kCommandId +
                             "&plugin=" + kPlugin;

    auto form = h.sink.Get(base + "&q=zeta");
    REQUIRE(form != nullptr);
    CHECK(contains(form->body, "1 agent will be added"));

    auto res = h.post(q_form_body("q-by-host", "&q=zeta"));
    CHECK(res->status == 200);
    auto group = h.mg.find_group_by_name("q-by-host");
    REQUIRE(group.has_value());
    CHECK(member_ids_of(h.mg, group->id) == std::set<std::string>{"agent-D"});
}

// #4990: the Forensics tier narrows a Search set exactly as it narrows a column-filter set. Every
// tier case above posts without `q` (the facet branch), so the tier inside agents_matching_text is
// pinned only here. agent-A and agent-B hold Forensics rows, agent-C and agent-D ordinary ones;
// agent-D does not match the term, agent-B is outside the category the column filter picks.
TEST_CASE("create-group-form: a Search preview counts only the rows the caller's Forensics tier "
          "may read",
          "[pg][server][dashboard][group_from_results][search][forensics]") {
    GroupFromResultsHarness h;
    const char* const forensics = yuzu::server::test::kForensicsPlugin;
    seed_titled_response(h.rs(), "agent-A", "cat-a", "alpha", forensics);
    seed_titled_response(h.rs(), "agent-B", "cat-b", "alpha2", forensics);
    seed_titled_response(h.rs(), "agent-C", "cat-a", "alpha3", yuzu::server::test::kOrdinaryPlugin);
    seed_titled_response(h.rs(), "agent-D", "cat-a", "beta", yuzu::server::test::kOrdinaryPlugin);
    const std::string base = std::string{"/fragments/create-group-form?command_id="} + kCommandId +
                             "&plugin=" + kPlugin;

    SECTION("without Forensics:Read, q alone previews exactly the ordinary match") {
        h.forensics.viewer();
        auto res = h.sink.Get(base + "&q=alp");
        REQUIRE(res != nullptr);
        CHECK(contains(res->body, "1 agent will be added"));
        CHECK_FALSE(contains(res->body, "3 agents will be added"));
    }
    SECTION("without Forensics:Read, q plus a column filter previews exactly the ordinary match") {
        h.forensics.viewer();
        auto res = h.sink.Get(base + "&f_category=cat-a&q=alp");
        REQUIRE(res != nullptr);
        CHECK(contains(res->body, "1 agent will be added"));
        CHECK_FALSE(contains(res->body, "2 agents will be added"));
    }
    SECTION("a global Forensics:Read previews every match") {
        h.forensics.admin();
        auto alone = h.sink.Get(base + "&q=alp");
        REQUIRE(alone != nullptr);
        CHECK(contains(alone->body, "3 agents will be added"));
        auto both = h.sink.Get(base + "&f_category=cat-a&q=alp");
        REQUIRE(both != nullptr);
        CHECK(contains(both->body, "2 agents will be added"));
    }
    SECTION("an Unknown decision shows no count, never a number from a partial row set") {
        h.forensics.unknown();
        auto res = h.sink.Get(base + "&q=alp");
        REQUIRE(res != nullptr);
        CHECK(contains(res->body, "agent count unavailable"));
        CHECK_FALSE(contains(res->body, "will be added"));
    }
}

TEST_CASE("group-from-results: a Search set is narrowed by the caller's Forensics tier, and an "
          "Unknown decision creates nothing",
          "[pg][server][dashboard][group_from_results][search][forensics]") {
    GroupFromResultsHarness h;
    const char* const forensics = yuzu::server::test::kForensicsPlugin;
    seed_titled_response(h.rs(), "agent-A", "cat-a", "alpha", forensics);
    seed_titled_response(h.rs(), "agent-B", "cat-b", "alpha2", forensics);
    seed_titled_response(h.rs(), "agent-C", "cat-a", "alpha3", yuzu::server::test::kOrdinaryPlugin);
    seed_titled_response(h.rs(), "agent-D", "cat-a", "beta", yuzu::server::test::kOrdinaryPlugin);

    SECTION("without Forensics:Read, q alone materialises exactly the ordinary match") {
        h.forensics.viewer();
        auto res = h.post(q_form_body("tier-q-viewer", "&q=alp"));
        CHECK(res->status == 200);
        auto group = h.mg.find_group_by_name("tier-q-viewer");
        REQUIRE(group.has_value());
        CHECK(member_ids_of(h.mg, group->id) == std::set<std::string>{"agent-C"});
    }
    SECTION("without Forensics:Read, q plus a column filter materialises exactly the ordinary "
            "match") {
        h.forensics.viewer();
        auto res = h.post(q_form_body("tier-qf-viewer", "&f_category=cat-a&q=alp"));
        CHECK(res->status == 200);
        auto group = h.mg.find_group_by_name("tier-qf-viewer");
        REQUIRE(group.has_value());
        CHECK(member_ids_of(h.mg, group->id) == std::set<std::string>{"agent-C"});
    }
    SECTION("a global Forensics:Read materialises every match") {
        h.forensics.admin();
        auto alone = h.post(q_form_body("tier-q-admin", "&q=alp"));
        CHECK(alone->status == 200);
        auto g1 = h.mg.find_group_by_name("tier-q-admin");
        REQUIRE(g1.has_value());
        CHECK(member_ids_of(h.mg, g1->id) ==
              std::set<std::string>{"agent-A", "agent-B", "agent-C"});

        auto both = h.post(q_form_body("tier-qf-admin", "&f_category=cat-a&q=alp"));
        CHECK(both->status == 200);
        auto g2 = h.mg.find_group_by_name("tier-qf-admin");
        REQUIRE(g2.has_value());
        CHECK(member_ids_of(h.mg, g2->id) == std::set<std::string>{"agent-A", "agent-C"});
    }
    SECTION("an Unknown decision answers the notice and creates no group") {
        h.forensics.unknown();
        auto res = h.post(q_form_body("tier-q-unknown", "&q=alp"));
        CHECK(res->status == 200);
        CHECK(contains(res->body, "could not be completed"));
        CHECK(contains(res->body, "Nothing was created"));
        CHECK(contains(res->get_header_value("HX-Trigger"), "showToast"));
        CHECK(res->get_header_value("HX-Retarget").empty());
        CHECK_FALSE(h.mg.find_group_by_name("tier-q-unknown").has_value());
    }
}

// A set cut by a read cap is partial; a group is never materialised from it.
TEST_CASE("group-from-results: a Search over a read cut by the byte cap is refused with a toast",
          "[pg][server][dashboard][group_from_results][search][truncation]") {
    GroupFromResultsHarness h;
    seed_titled_response(h.rs(), "agent-A", "cat-a", "alpha");
    seed_titled_response(h.rs(), "agent-B", "cat-a", "alpha");
    seed_titled_response(h.rs(), "agent-C", "cat-a", "alpha");
    yuzu::test::ExportByteCapGuard cap{1}; // every row past the first is cut
    const std::string base = std::string{"/fragments/create-group-form?command_id="} + kCommandId +
                             "&plugin=" + kPlugin;

    auto form = h.sink.Get(base + "&q=alp");
    REQUIRE(form != nullptr);
    CHECK(contains(form->body, "agent count is partial"));
    CHECK(contains(form->body, "<button type=\"submit\" disabled>"));
    CHECK_FALSE(contains(form->body, "agents will be added"));

    auto res = h.post(q_form_body("cut-by-bytes", "&q=alp"));
    CHECK(res->status == 422);
    // The toast and the body say the same sentence, byte for byte (the 422 body is never swapped,
    // so the toast is the operator's only signal).
    CHECK(res->get_header_value("HX-Trigger") ==
          R"({"showToast":{"message":"The result set was cut by the read cap, so the agent list is )"
          R"(partial. Nothing was created. Narrow the filters or the Search term and try again.")"
          R"(,"level":"error"}})");
    CHECK(res->body == "<span class=\"feedback-error\">The result set was cut by the read cap, so "
                       "the agent list is partial. Nothing was created. Narrow the filters or the "
                       "Search term and try again.</span>");
    CHECK_FALSE(h.mg.find_group_by_name("cut-by-bytes").has_value());
}

TEST_CASE("group-from-results: a Search plus a column filter over a read cut by the row cap is "
          "refused, not materialised as a smaller group",
          "[pg][server][dashboard][group_from_results][search][truncation]") {
    GroupFromResultsHarness h;
    seed_titled_response(h.rs(), "agent-A", "cat-a", "alpha");
    seed_titled_response(h.rs(), "agent-B", "cat-a", "alpha");
    seed_titled_response(h.rs(), "agent-C", "cat-a", "alpha");
    yuzu::test::ResultsRowCapGuard cap{2};
    const std::string base = std::string{"/fragments/create-group-form?command_id="} + kCommandId +
                             "&plugin=" + kPlugin + "&f_category=cat-a&q=alp";

    auto form = h.sink.Get(base);
    REQUIRE(form != nullptr);
    CHECK(contains(form->body, "agent count is partial"));
    CHECK(contains(form->body, "<button type=\"submit\" disabled>"));

    auto res = h.post(q_form_body("cut-by-rows", "&f_category=cat-a&q=alp"));
    CHECK(res->status == 422);
    CHECK(contains(res->get_header_value("HX-Trigger"), "showToast"));
    CHECK(contains(res->get_header_value("HX-Trigger"),
                   "Narrow the filters or the Search term and try again."));
    CHECK_FALSE(h.mg.find_group_by_name("cut-by-rows").has_value());

    // Control: a cap that holds every match lets the same request through.
    yuzu::test::ResultsRowCapGuard roomy{3};
    auto ok = h.post(q_form_body("not-cut", "&f_category=cat-a&q=alp"));
    CHECK(ok->status == 200);
    auto group = h.mg.find_group_by_name("not-cut");
    REQUIRE(group.has_value());
    CHECK(member_ids_of(h.mg, group->id) ==
          std::set<std::string>{"agent-A", "agent-B", "agent-C"});
}

TEST_CASE("group-from-results: a duplicate group name is refused with the same toast channel",
          "[pg][server][dashboard][group_from_results]") {
    GroupFromResultsHarness h;
    seed_matching_responses(h.rs(), {"agent-A"});
    REQUIRE(h.post(GroupFromResultsHarness::form_body("dup-name"))->status == 200);

    auto res = h.post(GroupFromResultsHarness::form_body("dup-name"));
    CHECK(res->status == 400);
    CHECK(res->get_header_value("HX-Retarget") == "#group-form-slot");
    CHECK(contains(res->body, "A group with that name already exists."));
    CHECK(contains(res->get_header_value("HX-Trigger"), "showToast"));
}

// A degraded store never reads as "no agents match" on the Search path either: the POST refuses
// before the visible scope is even resolved, and the preview says the count is unavailable.
TEST_CASE("group-from-results: a Search-only request on a degraded store 503s before any scope "
          "resolution, and the preview says the count is unavailable",
          "[pg][server][dashboard][group_from_results][search][degrade]") {
    GroupFromResultsHarness h{/*degrade_response_store=*/true};
    h.visible_set_fn = [](const std::string&) -> std::optional<std::set<std::string>> {
        return std::set<std::string>{"agent-A"};
    };

    auto res = h.post(q_form_body("q-degrade", "&q=alp"));
    CHECK(res->status == 503);
    CHECK(res->get_header_value("HX-Trigger") ==
          R"({"showToast":{"message":"Agent count unavailable. The response store could not be read. )"
          R"(Nothing was created. Retry shortly.","level":"error"}})");
    CHECK(h.visible_set_fn_calls == 0);
    CHECK(h.audits_for("response.read", "denied") == 0);
    CHECK_FALSE(h.mg.find_group_by_name("q-degrade").has_value());

    const std::string preview_url = std::string{"/fragments/create-group-form?command_id="} +
                                    kCommandId + "&plugin=" + kPlugin + "&q=alp";
    auto form = h.sink.Get(preview_url);
    REQUIRE(form != nullptr);
    CHECK(form->status == 200);
    CHECK(contains(form->body, "agent count unavailable"));
    CHECK_FALSE(contains(form->body, "agents will be added"));
    CHECK_FALSE(contains(form->body, "0 agents"));
}

// A urlencoded body is read by key, not by substring: a column named `seq` posts `f_seq=`, which
// must never be taken for the Search term `q`. With no real `q` the request is a filters-only one
// (no Response:Read admission, no marker); with a real `q` the real term wins.
TEST_CASE("group-from-results: a form key that merely ends in q is never the Search term",
          "[pg][server][dashboard][group_from_results][search]") {
    GroupFromResultsHarness h;
    seed_titled_response(h.rs(), "agent-A", "cat-a", "alpha");
    seed_titled_response(h.rs(), "agent-B", "cat-b", "beta");
    h.fleet_read_admit = false; // a Search term would be refused; filters alone are not

    SECTION("no real q: the filters-only path runs and records no Search marker") {
        auto res = h.post(q_form_body("seq-key", "&f_category=cat-a&f_seq=5"));
        CHECK(res->status == 200);
        CHECK(h.fleet_read_calls == 0);
        auto group = h.mg.find_group_by_name("seq-key");
        REQUIRE(group.has_value());
        CHECK(member_ids_of(h.mg, group->id) == std::set<std::string>{"agent-A"});
        CHECK_FALSE(contains(h.audit_detail("group.create_from_results", "success"), "text_query"));
    }
    SECTION("a real q after it is the Search term") {
        h.fleet_read_admit = true;
        auto res = h.post(q_form_body("seq-and-q", "&f_seq=5&q=bet"));
        CHECK(res->status == 200);
        auto group = h.mg.find_group_by_name("seq-and-q");
        REQUIRE(group.has_value());
        CHECK(member_ids_of(h.mg, group->id) == std::set<std::string>{"agent-B"});
    }
}

// R2: a Search term substring-matches stored output, so the preview and the POST that carry one
// run the results table's own Response:Read admission after ManagementGroup:Write; a filters-only
// request keeps ManagementGroup:Write alone, exactly as before.
namespace {
// The constant toast a refused Search admission answers (JSON as refusal_toast_header builds it).
const std::string kSearchRefusalToast =
    R"({"showToast":{"message":"The Search term could not be used: reading responses is not )"
    R"(permitted or the permission check is unavailable.","level":"error"}})";
} // namespace

TEST_CASE("group-from-results: a Search term needs the results table's Response:Read admission, in "
          "the preview and the POST; filters alone do not",
          "[pg][server][dashboard][group_from_results][search][auth]") {
    GroupFromResultsHarness h;
    seed_titled_response(h.rs(), "agent-A", "cat-a", "alpha");
    seed_titled_response(h.rs(), "agent-B", "cat-a", "beta");
    const std::string base = std::string{"/fragments/create-group-form?command_id="} + kCommandId +
                             "&plugin=" + kPlugin;

    SECTION("denied: the preview and the POST answer the gate's refusal and touch nothing") {
        h.fleet_read_admit = false;

        auto form = h.sink.Get(base + "&q=alp");
        REQUIRE(form != nullptr);
        CHECK(form->status == 403);
        CHECK(contains(form->body, "permission denied"));
        CHECK_FALSE(contains(form->body, "agents will be added"));
        // The form never swaps a 4xx body: the toast is the operator's signal.
        CHECK(form->get_header_value("HX-Trigger") == kSearchRefusalToast);
        CHECK(h.fleet_read_securable == "Response");
        CHECK(h.fleet_read_operation == "Read");

        auto res = h.post(q_form_body("q-denied", "&q=alp"));
        CHECK(res->status == 403);
        CHECK(contains(res->body, "permission denied"));
        CHECK(res->get_header_value("HX-Trigger") == kSearchRefusalToast);
        CHECK(h.fleet_read_calls == 2);
        CHECK_FALSE(h.mg.find_group_by_name("q-denied").has_value());
        // The refusal precedes every store read and the visible-scope resolve.
        CHECK(h.visible_set_fn_calls == 0);
        CHECK(h.audits_for("group.create_from_results", "success") == 0);
        CHECK(h.audits_for("response.read", "denied") == 0);
    }
    SECTION("filters alone never reach the gate, whatever it would answer") {
        h.fleet_read_admit = false;

        auto form = h.sink.Get(base + "&f_category=cat-a");
        REQUIRE(form != nullptr);
        CHECK(form->status == 200);
        CHECK(contains(form->body, "2 agents will be added"));

        auto res = h.post(GroupFromResultsHarness::form_body("filters-only"));
        CHECK(res->status == 200);
        CHECK(h.mg.find_group_by_name("filters-only").has_value());
        CHECK(h.fleet_read_calls == 0);
    }
    SECTION("unwired: the Search path fails closed with a 503, never an open read") {
        h.routes.set_fleet_read_fn(DashboardRoutes::FleetReadFn{});

        auto form = h.sink.Get(base + "&q=alp");
        REQUIRE(form != nullptr);
        CHECK(form->status == 503);
        CHECK_FALSE(contains(form->body, "agents will be added"));
        CHECK(form->get_header_value("HX-Trigger") == kSearchRefusalToast);

        auto res = h.post(q_form_body("q-unwired", "&q=alp"));
        CHECK(res->status == 503);
        CHECK(res->get_header_value("HX-Trigger") == kSearchRefusalToast);
        CHECK_FALSE(h.mg.find_group_by_name("q-unwired").has_value());
        CHECK(h.visible_set_fn_calls == 0);

        // Filters alone are unaffected by the missing gate.
        CHECK(h.post(GroupFromResultsHarness::form_body("unwired-filters"))->status == 200);
    }
    SECTION("admitted: the gate runs once per request on the Search path, and scoping still applies") {
        h.visible_set_fn = [](const std::string&) -> std::optional<std::set<std::string>> {
            return std::set<std::string>{"agent-A"};
        };
        auto form = h.sink.Get(base + "&q=a");
        REQUIRE(form != nullptr);
        CHECK(form->status == 200);
        CHECK(contains(form->body, "1 agent will be added")); // agent-B's match is out of scope
        CHECK(h.fleet_read_calls == 1);

        auto res = h.post(q_form_body("q-admitted", "&q=a"));
        CHECK(res->status == 200);
        CHECK(h.fleet_read_calls == 2);
        auto group = h.mg.find_group_by_name("q-admitted");
        REQUIRE(group.has_value());
        CHECK(member_ids_of(h.mg, group->id) == std::set<std::string>{"agent-A"});
    }
}

// ── (#3619) Audit-failure posture: no audit row, no mutation (ADR-0033 §9) ──
//
// Group materialisation is a mutation. Its `attempted` row is written BEFORE `create_group`, and a
// row the store does not persist refuses the request with nothing created. Every other row this
// route writes (the scope-drop `response.read`/denied row, the partial-failure row, the success
// row) proceeds and marks the response `Sec-Audit-Failed: true`, so the caller can tell an
// audited answer from an unaudited one.

namespace {
/// The group route's audit refusal, verbatim (dashboard_routes.cpp kGroupAuditRefusal).
constexpr const char* kGroupAuditRefusalText =
    "The audit record could not be stored. Nothing was created. Retry once the audit store "
    "recovers.";

/// The showToast message carried in a response's HX-Trigger header ("" if absent/unparsable).
std::string toast_message(const httplib::Response& res) {
    const auto j = nlohmann::json::parse(res.get_header_value("HX-Trigger"), nullptr,
                                         /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object() || !j.contains("showToast") ||
        !j["showToast"].is_object() || !j["showToast"].contains("message") ||
        !j["showToast"]["message"].is_string())
        return {};
    return j["showToast"]["message"].get<std::string>();
}

/// Fails exactly the rows matching (action, result); every other row persists.
std::function<bool(const AuditRow&)> fail_only(std::string action, std::string result) {
    return [action = std::move(action), result = std::move(result)](const AuditRow& r) {
        return !(r.action == action && r.result == result);
    };
}
} // namespace

TEST_CASE("group-from-results audit: the attempted row is stored BEFORE the group is created",
          "[pg][server][dashboard][group_from_results][audit][3619]") {
    GroupFromResultsHarness h;
    seed_matching_responses(h.rs(), {"agent-A"});
    h.group_name_probe = "attempted-first";

    auto res = h.post(GroupFromResultsHarness::form_body("attempted-first"));
    CHECK(res->status == 200);
    REQUIRE(h.audits_for("group.create_from_results", "attempted") == 1);
    REQUIRE(h.group_existed_at_attempted.has_value());
    CHECK_FALSE(*h.group_existed_at_attempted);
    CHECK(h.audits_for("group.create_from_results", "success") == 1);
    CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
}

TEST_CASE("group-from-results audit: an attempted row the store does not persist creates NO group",
          "[pg][server][dashboard][group_from_results][audit][security][3619]") {
    GroupFromResultsHarness h;
    seed_matching_responses(h.rs(), {"agent-A", "agent-B"});
    h.audit_persists = fail_only("group.create_from_results", "attempted");

    auto res = h.post(GroupFromResultsHarness::form_body("unaudited-group"));
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    // The form is hx-swap="none": the toast is the operator's only signal. Pinned exactly:
    // five sibling refusals on this route also say "Nothing was created" (#3619 C-4).
    CHECK(toast_message(*res) == kGroupAuditRefusalText);
    CHECK(contains(res->body, "data-reason=\"audit_unavailable\""));
    CHECK_FALSE(h.mg.find_group_by_name("unaudited-group").has_value());
    CHECK(h.audits_for("group.create_from_results", "success") == 0);
    CHECK(h.audits_for("group.create_from_results", "failure") == 0);
}

TEST_CASE("group-from-results audit: a refused request writes no attempted row",
          "[pg][server][dashboard][group_from_results][audit][3619]") {
    GroupFromResultsHarness h;
    seed_matching_responses(h.rs(), {"agent-A"});

    // A duplicate name, a set that matches nothing, a missing name, and a cross-site POST.
    REQUIRE(h.post(GroupFromResultsHarness::form_body("dup"))->status == 200);
    const int attempted_after_first = h.audits_for("group.create_from_results", "attempted");
    CHECK(h.post(GroupFromResultsHarness::form_body("dup"))->status == 400);
    CHECK(h.post("group_name=empty&command_id=" + std::string(kCommandId) + "&plugin=" + kPlugin +
                 "&f_category=no-such-category")
              ->status == 422);
    CHECK(h.post("group_name=&command_id=" + std::string(kCommandId))->status == 400);
    CHECK(h.post(GroupFromResultsHarness::form_body("xsite"),
                 {{"Host", kHost}, {"Origin", "https://evil.example"}})
              ->status == 403);
    CHECK(h.audits_for("group.create_from_results", "attempted") == attempted_after_first);
}

TEST_CASE("group-from-results audit: a scope-drop row that is not persisted is flagged on the "
          "response, and the narrowed group is still created",
          "[pg][server][dashboard][group_from_results][audit][3619]") {
    GroupFromResultsHarness h;
    seed_matching_responses(h.rs(), {"agent-A", "agent-B"});
    h.visible_set_fn = [](const std::string&) -> std::optional<std::set<std::string>> {
        return std::set<std::string>{"agent-A"};
    };
    h.audit_persists = fail_only("response.read", "denied");

    auto res = h.post(GroupFromResultsHarness::form_body("narrowed"));
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    REQUIRE(h.audits_for("response.read", "denied") == 1);
    auto group = h.mg.find_group_by_name("narrowed");
    REQUIRE(group.has_value());
    CHECK(member_ids_of(h.mg, group->id) == std::set<std::string>{"agent-A"});
}

TEST_CASE("group-from-results audit: a success row that is not persisted keeps the 200 and is "
          "flagged on the response",
          "[pg][server][dashboard][group_from_results][audit][3619]") {
    GroupFromResultsHarness h;
    seed_matching_responses(h.rs(), {"agent-A"});
    h.audit_persists = fail_only("group.create_from_results", "success");

    auto res = h.post(GroupFromResultsHarness::form_body("success-unrecorded"));
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(h.mg.find_group_by_name("success-unrecorded").has_value());
    // The attempted row stands, so the trail reads "started, outcome unknown", never nothing.
    CHECK(h.audits_for("group.create_from_results", "attempted") == 1);
}

TEST_CASE("group-from-results audit: a partial add_member failure whose failure row is not "
          "persisted keeps the 500 and is flagged on the response",
          "[pg][server][dashboard][group_from_results][audit][add_member][3619]") {
    GroupFromResultsHarness h;
    seed_matching_responses(h.rs(), {"agent-A", "agent-B"});
    block_add_member_for(h.mg_bundle, "agent-B");
    h.audit_persists = fail_only("group.create_from_results", "failure");

    auto res = h.post(GroupFromResultsHarness::form_body("partial-unrecorded"));
    CHECK(res->status == 500);
    CHECK(contains(res->body, "1 of 2"));
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    REQUIRE(h.audits_for("group.create_from_results", "failure") == 1);
    CHECK(h.audits_for("group.create_from_results", "attempted") == 1);
}

TEST_CASE("group-from-results audit: a REAL audit-store failure on the scope-drop row and on a "
          "partial add_member failure is counted by the store and flagged on the response",
          "[pg][server][dashboard][group_from_results][audit][add_member][3619]") {
    // Criterion 2 of #3619: the failure is forced in the audit STORE (a Postgres trigger rejects
    // exactly the two rows), concurrent with a scope drop and a partial add_member failure, and
    // the assertion is the store's emit-failure counter -- the value /metrics publishes as
    // yuzu_server_audit_emit_failed_total, which the shipped YuzuAuditPersistFailures alert reads.
    YUZU_REQUIRE_PG_DB_TPL(adb, group_audit_tpl);
    PgPool apool{{.conninfo = adb.dsn(), .size = 2}};
    AuditStore store{apool};
    REQUIRE(store.is_open());
    {
        PgConn conn{PQconnectdb(adb.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult fn_res{PQexec(
            conn.get(),
            "CREATE OR REPLACE FUNCTION audit_store.reject_3619() RETURNS trigger AS $$ BEGIN "
            "IF (NEW.action = 'response.read' AND NEW.result = 'denied') OR "
            "(NEW.action = 'group.create_from_results' AND NEW.result = 'failure') THEN "
            "RAISE EXCEPTION 'test: forced audit write failure'; END IF; RETURN NEW; END; $$ "
            "LANGUAGE plpgsql;")};
        REQUIRE(fn_res.ok());
        PgResult trig_res{PQexec(conn.get(),
                                 "CREATE TRIGGER reject_3619 BEFORE INSERT ON "
                                 "audit_store.audit_events FOR EACH ROW EXECUTE FUNCTION "
                                 "audit_store.reject_3619();")};
        REQUIRE(trig_res.ok());
    }

    GroupFromResultsHarness h;
    seed_matching_responses(h.rs(), {"agent-A", "agent-B", "agent-C"});
    h.visible_set_fn = [](const std::string&) -> std::optional<std::set<std::string>> {
        return std::set<std::string>{"agent-A", "agent-B"}; // agent-C is dropped by scope
    };
    block_add_member_for(h.mg_bundle, "agent-B"); // agent-B fails to land
    h.real_audit = &store;

    const auto before = store.emit_failed_count();
    auto res = h.post(GroupFromResultsHarness::form_body("store-fault"));

    CHECK(res->status == 500);
    CHECK(contains(res->body, "1 of 2"));
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    // Exactly the two rejected rows: the scope-drop row and the partial-failure row.
    CHECK(store.emit_failed_count() - before == 2);

    // The attempted row DID persist (the trigger passes it), so the trail reads "started,
    // outcome unknown" rather than nothing; the two rejected rows are absent.
    AuditQuery attempted;
    attempted.action = "group.create_from_results";
    const auto rows = store.query(attempted);
    REQUIRE(rows.has_value());
    int n_attempted = 0, n_failure = 0;
    for (const auto& r : *rows) {
        if (r.result == "attempted")
            ++n_attempted;
        if (r.result == "failure")
            ++n_failure;
    }
    CHECK(n_attempted == 1);
    CHECK(n_failure == 0);
    AuditQuery dropped;
    dropped.action = "response.read";
    const auto drop_rows = store.query(dropped);
    REQUIRE(drop_rows.has_value());
    CHECK(drop_rows->empty());
}

TEST_CASE("group-from-results audit: a create_group failure records a failure outcome for its "
          "attempted row",
          "[pg][server][dashboard][group_from_results][audit][3619]") {
    // sec-3: a store error inside create_group must not leave the attempted row without an
    // outcome. A BEFORE INSERT trigger on this test's own cloned database forces the failure.
    GroupFromResultsHarness h;
    seed_matching_responses(h.rs(), {"agent-A"});
    {
        PgConn conn{PQconnectdb(h.mg_bundle.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult fn_res{PQexec(
            conn.get(),
            "CREATE OR REPLACE FUNCTION management_group_store.block_group_3619() RETURNS "
            "trigger AS $$ BEGIN RAISE EXCEPTION 'test: forced create_group failure'; END; $$ "
            "LANGUAGE plpgsql;")};
        REQUIRE(fn_res.ok());
        PgResult trig_res{PQexec(conn.get(),
                                 "CREATE TRIGGER block_group_3619 BEFORE INSERT ON "
                                 "management_group_store.management_groups FOR EACH ROW "
                                 "EXECUTE FUNCTION management_group_store.block_group_3619();")};
        REQUIRE(trig_res.ok());
    }

    auto res = h.post(GroupFromResultsHarness::form_body("create-fails"));
    CHECK(res->status == 500);
    CHECK_FALSE(h.mg.find_group_by_name("create-fails").has_value());
    REQUIRE(h.audits_for("group.create_from_results", "attempted") == 1);
    REQUIRE(h.audits_for("group.create_from_results", "failure") == 1);
    CHECK(h.audit_detail("group.create_from_results", "failure") ==
          "create_failed name=create-fails");
    // The form is hx-swap="none": the toast is the only thing the operator sees (Gate 8 UP-1).
    CHECK(toast_message(*res) ==
          "The group could not be created. Nothing was created. Retry shortly.");
    CHECK(h.audits_for("group.create_from_results", "success") == 0);
}

TEST_CASE("group-from-results audit: two unstored rows in one request yield exactly ONE "
          "Sec-Audit-Failed header",
          "[pg][server][dashboard][group_from_results][audit][3619]") {
    // sec-4 / CH-6: the scope-drop row and the attempted row both fail to persist.
    GroupFromResultsHarness h;
    seed_matching_responses(h.rs(), {"agent-A", "agent-B"});
    h.visible_set_fn = [](const std::string&) -> std::optional<std::set<std::string>> {
        return std::set<std::string>{"agent-A"};
    };
    h.audit_persists = [](const AuditRow& r) {
        return !((r.action == "response.read" && r.result == "denied") ||
                 (r.action == "group.create_from_results" && r.result == "attempted"));
    };

    auto res = h.post(GroupFromResultsHarness::form_body("double-fault"));
    CHECK(res->status == 503);
    CHECK(res->get_header_value_count("Sec-Audit-Failed") == 1);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK_FALSE(h.mg.find_group_by_name("double-fault").has_value());
}

TEST_CASE("group-from-results audit: an unwired or throwing persist sink refuses, never acts",
          "[pg][server][dashboard][group_from_results][audit][security][3619]") {
    // CH-4: unwired = fail CLOSED (never "audit-off, proceed"); a throwing sink is caught by
    // the shared kernel and refuses the same way, with no exception escaping the handler.
    SECTION("unwired") {
        GroupFromResultsHarness h;
        seed_matching_responses(h.rs(), {"agent-A"});
        h.routes.set_persist_audit_fn({});
        auto res = h.post(GroupFromResultsHarness::form_body("unwired-sink"));
        CHECK(res->status == 503);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        CHECK_FALSE(h.mg.find_group_by_name("unwired-sink").has_value());
    }
    SECTION("throwing") {
        GroupFromResultsHarness h;
        seed_matching_responses(h.rs(), {"agent-A"});
        h.routes.set_persist_audit_fn(
            [](const httplib::Request&, const std::string&, const std::string&,
               const std::string&, const std::string&, const std::string&) -> bool {
                throw std::runtime_error("test: audit sink threw");
            });
        auto res = h.post(GroupFromResultsHarness::form_body("throwing-sink"));
        CHECK(res->status == 503);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        CHECK_FALSE(h.mg.find_group_by_name("throwing-sink").has_value());
    }
}

TEST_CASE("group-from-results audit: a REAL audit-store rejection of the attempted row creates "
          "no group and shows the exact refusal",
          "[pg][server][dashboard][group_from_results][audit][security][3619]") {
    // CH-8: the failure is in the store (a trigger rejects every `attempted` row), not in a
    // test predicate, and the refusal text is pinned exactly rather than by substring.
    YUZU_REQUIRE_PG_DB_TPL(adb, group_audit_tpl);
    PgPool apool{{.conninfo = adb.dsn(), .size = 2}};
    AuditStore store{apool};
    REQUIRE(store.is_open());
    {
        PgConn conn{PQconnectdb(adb.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult fn_res{PQexec(
            conn.get(),
            "CREATE OR REPLACE FUNCTION audit_store.reject_attempted_3619() RETURNS trigger AS "
            "$$ BEGIN IF NEW.result = 'attempted' THEN RAISE EXCEPTION 'test: forced'; END IF; "
            "RETURN NEW; END; $$ LANGUAGE plpgsql;")};
        REQUIRE(fn_res.ok());
        PgResult trig_res{PQexec(conn.get(),
                                 "CREATE TRIGGER reject_attempted_3619 BEFORE INSERT ON "
                                 "audit_store.audit_events FOR EACH ROW EXECUTE FUNCTION "
                                 "audit_store.reject_attempted_3619();")};
        REQUIRE(trig_res.ok());
    }

    GroupFromResultsHarness h;
    seed_matching_responses(h.rs(), {"agent-A"});
    h.real_audit = &store;
    const auto before = store.emit_failed_count();

    auto res = h.post(GroupFromResultsHarness::form_body("store-rejects-attempted"));
    CHECK(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(toast_message(*res) == kGroupAuditRefusalText);
    CHECK(res->body == std::string("<span class=\"feedback-error\" "
                                   "data-reason=\"audit_unavailable\">") +
                           kGroupAuditRefusalText + "</span>");
    CHECK(store.emit_failed_count() - before == 1);
    CHECK_FALSE(h.mg.find_group_by_name("store-rejects-attempted").has_value());
}
