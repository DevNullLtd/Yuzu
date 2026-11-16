/**
 * test_execution_mutation_owner_key.cpp -- #5557: the execution MUTATIONS (cancel / rerun) keep
 * the OWNERSHIP key apart from the audit principal.
 *
 * `ExecutionMutationRequest::username` is the REAL principal (audit attribution, `mark_cancelled`
 * / `create_rerun`); `ExecutionMutationRequest::owner` is the key admission compares against
 * `Execution::dispatched_by`, derived by `execution_owner_key(session)`. For a service-scoped
 * session the key is empty, so a minter-dispatched execution is admitted only on COMPLETE cohort
 * visibility, never because the credential's `username` (the minting account) matches.
 *
 * A service-scoped token cannot reach these routes today: the Execution:Execute gate (REST,
 * legacy) and the C8 default-deny (MCP) refuse it first. The conversion is defence in depth and
 * changes no reachable behaviour. These cases pin both halves:
 *   - the real gate still refuses a service-scoped token, with no effect;
 *   - with ONLY the Execute permission check bypassed (a test seam; authentication, fleet-read
 *     admission and the mutation sequence stay real) a service-scoped session still cannot be
 *     admitted by ownership.
 *
 * Part 1 is pure (a counting fake store). Part 2 drives the REST v1 and legacy routes through the
 * shared real-gate rig (test_execution_owner_scope_rig.hpp) and needs Postgres.
 */

#include "execution_mutation.hpp"
#include "execution_routes.hpp"
#include "execution_scope_rules.hpp"
#include "rest_api_v1.hpp"
#include "test_execution_owner_scope_rig.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using yuzu::test::ExecutionOwnerRig;
using Hdrs = ExecutionOwnerRig::Headers;

namespace {

// ── part 1: the sequence against a counting fake store ──────────────────────────────────────

/// A mutation request built the way every production construction site builds it: the real
/// principal in `username`, the ownership key from `execution_owner_key(session)`.
ExecutionMutationRequest request_for(const auth::Session& s, ExecutionMutation what,
                                     authz::VisibleSet scope) {
    ExecutionMutationRequest r;
    r.what = what;
    r.execution_id = "exec-1";
    r.username = s.username;
    r.owner = execution_owner_key(s);
    r.scope = std::move(scope);
    r.audit_context = "surface=test";
    return r;
}

auth::Session session_of(const std::string& user, const std::string& service = {}) {
    auth::Session s;
    s.username = user;
    s.token_scope_service = service;
    return s;
}

authz::VisibleSet scope_of(std::initializer_list<const char*> agents) {
    std::unordered_set<std::string> s;
    for (auto* a : agents)
        s.emplace(a);
    return authz::VisibleSet{std::move(s)};
}

Execution exec_by(const std::string& by, int targeted) {
    Execution e;
    e.id = "exec-1";
    e.dispatched_by = by;
    e.agents_targeted = targeted;
    e.status = "running";
    return e;
}

AgentExecStatus status_of(const std::string& agent) {
    AgentExecStatus a;
    a.agent_id = agent;
    a.status = "running";
    return a;
}

/// Counts every port call, so "a refusal invokes NO mutation port" is an exact assertion, and
/// records the user each mutation port receives (the real principal).
struct CountingStore {
    std::optional<Execution> exec;
    std::vector<AgentExecStatus> statuses;
    int exec_reads{0}, status_reads{0}, cancel_calls{0}, rerun_calls{0};
    std::string cancel_user, rerun_user;

    ExecutionMutationPorts ports() {
        ExecutionMutationPorts p;
        p.get_execution =
            [this](const std::string&) -> std::expected<std::optional<Execution>, std::string> {
            ++exec_reads;
            return exec;
        };
        p.get_statuses = [this](const std::string&) -> std::optional<std::vector<AgentExecStatus>> {
            ++status_reads;
            return statuses;
        };
        p.mark_cancelled = [this](const std::string&, const std::string& user) {
            ++cancel_calls;
            cancel_user = user;
            return ExecutionTracker::MarkCancelledOutcome::kCancelled;
        };
        p.create_rerun = [this](const std::string&, const std::string& user,
                                bool) -> std::expected<std::string, ExecutionTracker::RerunError> {
            ++rerun_calls;
            rerun_user = user;
            return std::string("rerun-new-1");
        };
        return p;
    }
    int effects() const { return cancel_calls + rerun_calls; }
};

struct AuditRow {
    std::string action, result, target, detail;
};

ExecutionMutationAuditFn record_into(std::vector<AuditRow>& rows) {
    return [&rows](const std::string& action, const std::string& result, const std::string& target,
                   const std::string& detail) {
        rows.push_back({action, result, target, detail});
        return true;
    };
}

constexpr ExecutionMutation kBoth[] = {ExecutionMutation::kCancel, ExecutionMutation::kRerun};

const char* name_of(ExecutionMutation m) {
    return m == ExecutionMutation::kCancel ? "cancel" : "rerun";
}

using S = ExecutionMutationStatus;

} // namespace

TEST_CASE("mutation owner key: a service-scoped session keeps the minter as username and an empty "
          "key",
          "[execution][mutation][owner_key][5557]") {
    const auto svc = session_of("mina", "A");
    const auto req = request_for(svc, ExecutionMutation::kCancel, scope_of({"a1"}));
    // (f) username is still the minting human's, the real principal; the key owns nothing.
    CHECK(req.username == "mina");
    CHECK(req.owner.empty());
    Execution minters;
    minters.dispatched_by = "mina";
    CHECK_FALSE(req.owner.owns(minters));
    // The same human without a service scope: the key is the username.
    const auto plain =
        request_for(session_of("mina"), ExecutionMutation::kCancel, scope_of({"a1"}));
    CHECK(plain.username == "mina");
    CHECK_FALSE(plain.owner.empty());
    CHECK(plain.owner.owns(minters));
    // A request nobody set a key on owns nothing (fails closed).
    CHECK(ExecutionMutationRequest{}.owner.empty());
}

TEST_CASE("mutation owner key: a service-scoped session is never admitted by the minter's "
          "dispatch, and a refusal calls no mutation port",
          "[execution][mutation][owner_key][security][5557]") {
    for (const auto what : kBoth) {
        INFO(name_of(what));
        SECTION(std::string(name_of(what)) + ": zero status rows, dispatched by the minter") {
            CountingStore fs;
            fs.exec = exec_by("mina", 1);
            std::vector<AuditRow> audit;
            const auto out = apply_execution_mutation(
                fs.ports(), request_for(session_of("mina", "A"), what, scope_of({"a1", "a2"})),
                record_into(audit));
            CHECK(out.status == S::kNotFound);
            CHECK(out.audit_persisted);
            // The reads happened (a nonexistent id and a hidden id cost the same); no effect port
            // did.
            CHECK(fs.exec_reads == 1);
            CHECK(fs.status_reads == 1);
            CHECK(fs.cancel_calls == 0);
            CHECK(fs.rerun_calls == 0);
            // ONE `denied` row, and no `attempted` row.
            REQUIRE(audit.size() == 1);
            CHECK(audit[0].result == "denied");
            CHECK(audit[0].action == execution_mutation_audit_action(what));
            CHECK(audit[0].target == "exec-1");
        }
        SECTION(std::string(name_of(what)) +
                ": the same human WITHOUT a service scope is admitted") {
            CountingStore fs;
            fs.exec = exec_by("mina", 1);
            std::vector<AuditRow> audit;
            const auto out = apply_execution_mutation(
                fs.ports(), request_for(session_of("mina"), what, scope_of({"a1", "a2"})),
                record_into(audit));
            CHECK(out.status == S::kDone);
            CHECK(fs.effects() == 1);
            REQUIRE(audit.size() == 2);
            CHECK(audit[0].result == "attempted");
            CHECK(audit[1].result == "success");
        }
        SECTION(std::string(name_of(what)) +
                ": another non-service user on a stranger's zero-row execution is refused") {
            CountingStore fs;
            fs.exec = exec_by("mina", 1);
            const auto out = apply_execution_mutation(
                fs.ports(), request_for(session_of("bob"), what, scope_of({"a1"})), {});
            CHECK(out.status == S::kNotFound);
            CHECK(fs.effects() == 0);
        }
        SECTION(std::string(name_of(what)) + ": a request whose key was never set fails closed") {
            CountingStore fs;
            fs.exec = exec_by("mina", 1);
            auto req = request_for(session_of("mina"), what, scope_of({"a1"}));
            req.owner = ExecutionOwnerKey{};
            const auto out = apply_execution_mutation(fs.ports(), req, {});
            CHECK(out.status == S::kNotFound);
            CHECK(fs.effects() == 0);
        }
    }
}

TEST_CASE("mutation owner key: a service-scoped session is admitted only on complete cohort "
          "visibility, and the port gets the REAL principal",
          "[execution][mutation][owner_key][5557]") {
    for (const auto what : kBoth) {
        INFO(name_of(what));
        // Complete cohort, every row in scope: admitted although the key owns nothing. The
        // execution is dispatched by someone else, so ownership is not what admits it.
        SECTION(std::string(name_of(what)) + ": complete cohort in the visible set") {
            CountingStore fs;
            fs.exec = exec_by("carol", 2);
            fs.statuses = {status_of("a1"), status_of("a2")};
            std::vector<AuditRow> audit;
            const auto out = apply_execution_mutation(
                fs.ports(), request_for(session_of("mina", "A"), what, scope_of({"a1", "a2"})),
                record_into(audit));
            CHECK(out.status == S::kDone);
            CHECK(fs.effects() == 1);
            // (d) the effect is attributed to the real principal, never the (empty) key.
            CHECK((what == ExecutionMutation::kCancel ? fs.cancel_user : fs.rerun_user) == "mina");
            REQUIRE(audit.size() == 2);
            CHECK(audit[0].result == "attempted");
            CHECK(audit[1].result == "success");
        }
        // Dispatched by the minter AND the cohort is complete and in scope: admitted by the
        // cohort rule, exactly as a stranger's execution would be.
        SECTION(std::string(name_of(what)) + ": the minter's own complete in-scope cohort") {
            CountingStore fs;
            fs.exec = exec_by("mina", 1);
            fs.statuses = {status_of("a1")};
            const auto out = apply_execution_mutation(
                fs.ports(), request_for(session_of("mina", "A"), what, scope_of({"a1"})), {});
            CHECK(out.status == S::kDone);
            CHECK(fs.effects() == 1);
        }
        // One cohort row outside the visible set: refused even though the minter dispatched it.
        SECTION(std::string(name_of(what)) + ": a partially visible cohort") {
            CountingStore fs;
            fs.exec = exec_by("mina", 2);
            fs.statuses = {status_of("a1"), status_of("z1")};
            const auto out = apply_execution_mutation(
                fs.ports(), request_for(session_of("mina", "A"), what, scope_of({"a1", "a2"})), {});
            CHECK(out.status == S::kNotFound);
            CHECK(fs.effects() == 0);
        }
        // Fewer rows than agents_targeted: the cohort is not proven complete.
        SECTION(std::string(name_of(what)) + ": an incomplete cohort") {
            CountingStore fs;
            fs.exec = exec_by("mina", 2);
            fs.statuses = {status_of("a1")};
            const auto out = apply_execution_mutation(
                fs.ports(), request_for(session_of("mina", "A"), what, scope_of({"a1", "a2"})), {});
            CHECK(out.status == S::kNotFound);
            CHECK(fs.effects() == 0);
        }
    }
}

TEST_CASE("mutation owner key: a non-service session keeps the owner disjunct for the zero-row "
          "window only",
          "[execution][mutation][owner_key][5557]") {
    for (const auto what : kBoth) {
        INFO(name_of(what));
        SECTION(std::string(name_of(what)) + ": the dispatcher, no status rows yet") {
            CountingStore fs;
            fs.exec = exec_by("bob", 1);
            const auto out = apply_execution_mutation(
                fs.ports(), request_for(session_of("bob"), what, scope_of({"a1"})), {});
            CHECK(out.status == S::kDone);
            CHECK(fs.effects() == 1);
            CHECK((what == ExecutionMutation::kCancel ? fs.cancel_user : fs.rerun_user) == "bob");
        }
        // The complete-cohort rule is unchanged: once rows exist, ownership is not a bypass.
        SECTION(std::string(name_of(what)) + ": the dispatcher of a partially visible cohort") {
            CountingStore fs;
            fs.exec = exec_by("bob", 2);
            fs.statuses = {status_of("a1"), status_of("z1")};
            const auto out = apply_execution_mutation(
                fs.ports(), request_for(session_of("bob"), what, scope_of({"a1"})), {});
            CHECK(out.status == S::kNotFound);
            CHECK(fs.effects() == 0);
        }
    }
}

TEST_CASE("mutation owner key: an unrestricted scope admits whatever the key is",
          "[execution][mutation][owner_key][5557]") {
    for (const auto what : kBoth) {
        CountingStore fs;
        fs.exec = exec_by("carol", 1);
        const auto out = apply_execution_mutation(
            fs.ports(), request_for(session_of("mina", "A"), what, std::nullopt), {});
        CHECK(out.status == S::kDone);
        CHECK(fs.effects() == 1);
        CHECK((what == ExecutionMutation::kCancel ? fs.cancel_user : fs.rerun_user) == "mina");
    }
}

TEST_CASE("mutation owner key: an empty principal is refused before any port, key or not",
          "[execution][mutation][owner_key][5557]") {
    for (const auto what : kBoth) {
        CountingStore fs;
        fs.exec = exec_by("", 1);
        std::vector<AuditRow> audit;
        const auto out = apply_execution_mutation(
            fs.ports(), request_for(session_of(""), what, scope_of({"a1"})), record_into(audit));
        CHECK(out.status == S::kNoPrincipal);
        CHECK(fs.exec_reads == 0);
        CHECK(fs.effects() == 0);
        CHECK(audit.empty());
    }
}

// ── part 2: the REST v1 and legacy routes, real gates, Execute check bypassed ────────────────

namespace {

struct Call {
    int status{0};
    nlohmann::json body;
};

/// One audit row as the route's `audit_fn` saw it. The principal is deliberately not recorded:
/// resolving it from the request here would only re-test the harness, not the handler. The
/// attribution evidence is the mutation ports' `cancel_users` / `rerun_users` and the rerun
/// records' `dispatched_by`.
struct SeenAudit {
    std::string action, result, target;
};

/// Wraps the real tracker ports; counts and records every MUTATION port call.
struct CountingPorts {
    ExecutionMutationPorts inner;
    int cancels{0}, reruns{0};
    std::vector<std::string> cancel_users, rerun_users;

    explicit CountingPorts(ExecutionTracker& t) : inner(make_tracker_mutation_ports(&t)) {}

    ExecutionMutationPorts ports() {
        ExecutionMutationPorts p = inner;
        p.mark_cancelled = [this](const std::string& id, const std::string& user) {
            ++cancels;
            cancel_users.push_back(user);
            return inner.mark_cancelled(id, user);
        };
        p.create_rerun = [this](const std::string& id, const std::string& user, bool failed_only) {
            ++reruns;
            rerun_users.push_back(user);
            return inner.create_rerun(id, user, failed_only);
        };
        return p;
    }
    int effects() const { return cancels + reruns; }
};

/// The Execution:Execute check is the first thing a service-scoped token meets, so the rest of
/// the handler is unreachable for one. This stands in for it ONLY (defence-in-depth tests).
ExecutionOwnerRig::PermFn permit_all() {
    return [](const httplib::Request&, httplib::Response&, const std::string&, const std::string&) {
        return true;
    };
}

/// The REST v1 mutation routes wired the way server.cpp wires them, with `perm_fn` injectable.
struct RestV1Mutations {
    ExecutionOwnerRig& r;
    CountingPorts counting;
    yuzu::MetricsRegistry metrics;
    yuzu::server::test::TestRouteSink sink;
    RestApiV1 api;
    std::vector<SeenAudit> audits;

    RestV1Mutations(ExecutionOwnerRig& rig, ExecutionOwnerRig::PermFn perm)
        : r(rig), counting(rig.tracker) {
        api.set_execution_mutation_ports_for_test(counting.ports());
        auto audit_fn = [this](const httplib::Request&, const std::string& a,
                               const std::string& res, const std::string&,
                               const std::string& target, const std::string&) -> bool {
            audits.push_back({a, res, target});
            return true;
        };
        api.register_routes(sink, r.auth_fn(), std::move(perm), audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr, &r.tracker,
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
                            /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/&metrics,
                            /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{},
                            /*step_up_fn=*/{},
                            /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{},
                            /*network_api=*/{},
                            /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr,
                            /*scoped_perm_fn=*/{},
                            /*software_inventory_store=*/nullptr,
                            /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr,
                            /*access_review_store=*/nullptr, /*auth_db=*/nullptr,
                            /*directory_sync=*/nullptr, /*stream_budget=*/nullptr,
                            /*exec_visible_fn=*/{}, /*list_read_fn=*/{}, r.fleet_read_fn());
    }

    Call post(const std::string& id, const char* verb, const Hdrs& headers) {
        auto res = sink.dispatch("POST", "/api/v1/executions/" + id + "/" + verb, "{}",
                                 "application/json", headers);
        REQUIRE(res);
        return {res->status, nlohmann::json::parse(res->body, nullptr, false)};
    }
    Call cancel(const std::string& id, const Hdrs& h) { return post(id, "cancel", h); }
    Call rerun(const std::string& id, const Hdrs& h) { return post(id, "rerun", h); }
};

/// The legacy /api/executions/{id}/{cancel,rerun} routes, `perm_fn` injectable. They call the
/// tracker directly, so the effect is observed on the tracker, not through ports.
struct LegacyMutations {
    ExecutionOwnerRig& r;
    yuzu::server::test::TestRouteSink sink;
    std::vector<SeenAudit> audits;

    LegacyMutations(ExecutionOwnerRig& rig, ExecutionOwnerRig::PermFn perm) : r(rig) {
        execution::Deps d;
        d.perm_fn = std::move(perm);
        d.fleet_read_fn = r.fleet_read_fn();
        d.resolve_session_fn = r.resolve_session_fn();
        d.audit_fn = [this](const httplib::Request&, const std::string& a,
                            const std::string& res, const std::string&, const std::string& target,
                            const std::string&) {
            audits.push_back({a, res, target});
            return true;
        };
        d.emit_event_fn = [](const std::string&, const httplib::Request&, const nlohmann::json&,
                             const nlohmann::json&) {
        };
        d.execution_tracker = &r.tracker;
        execution::register_execution_routes(sink, std::move(d));
    }

    Call post(const std::string& id, const char* verb, const Hdrs& headers) {
        auto res = sink.dispatch("POST", "/api/executions/" + id + "/" + verb, "{}",
                                 "application/json", headers);
        REQUIRE(res);
        return {res->status, nlohmann::json::parse(res->body, nullptr, false)};
    }
    Call cancel(const std::string& id, const Hdrs& h) { return post(id, "cancel", h); }
    Call rerun(const std::string& id, const Hdrs& h) { return post(id, "rerun", h); }
};

std::string tracker_status(ExecutionOwnerRig& r, const std::string& id) {
    auto e = r.tracker.get_execution(id);
    REQUIRE(e.has_value());
    return e->status;
}

/// `dispatched_by` of every rerun record created from `id`.
std::vector<std::string> rerun_dispatchers(ExecutionOwnerRig& r, const std::string& id) {
    auto kids = r.tracker.get_children_checked(id, std::nullopt);
    REQUIRE(kids.has_value());
    std::vector<std::string> out;
    for (const auto& c : kids->children)
        if (c.rerun_of == id)
            out.push_back(c.dispatched_by);
    return out;
}

bool is_2xx(int status) {
    return status >= 200 && status < 300;
}

} // namespace

TEST_CASE("mutation owner key REST v1: a service-scoped session cannot mutate by minter ownership",
          "[pg][execution][mutation][owner_rig][owner_rest][owner_key][security][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionOwnerRig r{db.dsn()};
    RestV1Mutations api{r, permit_all()};
    const auto svc = ExecutionOwnerRig::bearer(r.creds.svc_a);
    // The minter's own pending execution (zero status rows): admitted by the old owner compare.
    // The minter's z1 execution: out of every service-A scope. Both refused, with no effect.
    for (const auto& id : {r.ids.minter_pending, r.ids.minter_out, r.ids.empty_pending}) {
        INFO(id);
        const auto before = tracker_status(r, id);
        CHECK(api.cancel(id, svc).status == 404);
        CHECK(api.rerun(id, svc).status == 404);
        CHECK(tracker_status(r, id) == before);
        CHECK(rerun_dispatchers(r, id).empty());
    }
    CHECK(api.counting.effects() == 0); // the refusals never reached a mutation port
    // Every refusal is audited as denied. (Attribution to the real principal is asserted where
    // it is observable: the mutation ports' `cancel_users` / `rerun_users` and the rerun
    // records' `dispatched_by`; the sink's own principal resolution is the harness's.)
    REQUIRE(api.audits.size() == 6);
    for (const auto& a : api.audits)
        CHECK(a.result == "denied");
    CHECK(api.audits[0].action == "execution.cancel");
    CHECK(api.audits[1].action == "execution.rerun");
}

TEST_CASE("mutation owner key REST v1: a service-scoped session mutates a complete in-scope "
          "cohort, attributed to the real principal",
          "[pg][execution][mutation][owner_rig][owner_rest][owner_key][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionOwnerRig r{db.dsn()};
    RestV1Mutations api{r, permit_all()};
    const auto svc = ExecutionOwnerRig::bearer(r.creds.svc_a);

    // carol's execution, one a1 row, running: complete and in scope for service A.
    const auto live = r.make_exec("carol", ExecutionOwnerRig::kBaseAt + 300, 1, "running");
    r.put_status(live, "a1", "running");
    const auto cancelled = api.cancel(live, svc);
    CHECK(cancelled.status == 200);
    CHECK(tracker_status(r, live) == "cancelled");
    // The principal, not the (empty) key.
    CHECK(api.counting.cancel_users == std::vector<std::string>{"mina"});

    const auto rerun = api.rerun(r.ids.in_a, svc);
    CHECK(is_2xx(rerun.status));
    CHECK(api.counting.rerun_users == std::vector<std::string>{"mina"});
    CHECK(rerun_dispatchers(r, r.ids.in_a) == std::vector<std::string>{"mina"});

    // Every mutation wrote its audit row (the real principal is asserted on the port users above).
    REQUIRE_FALSE(api.audits.empty());
}

TEST_CASE("mutation owner key REST v1: a non-service session of the same human keeps the owner "
          "disjunct",
          "[pg][execution][mutation][owner_rig][owner_rest][owner_key][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionOwnerRig r{db.dsn()};
    RestV1Mutations api{r, permit_all()};
    const auto bob = ExecutionOwnerRig::bearer(r.creds.bob);

    // bob (a1 only): his own zero-row execution is admitted by ownership.
    CHECK(api.cancel(r.ids.bob_pending, bob).status == 200);
    CHECK(tracker_status(r, r.ids.bob_pending) == "cancelled");
    CHECK(api.counting.cancel_users == std::vector<std::string>{"bob"});
    // ...the complete-cohort rule still applies once rows exist: his z1 execution is refused...
    CHECK(api.cancel(r.ids.bob_out, bob).status == 404);
    CHECK(api.rerun(r.ids.bob_out, bob).status == 404);
    // ...and so is a stranger's zero-row execution.
    CHECK(api.rerun(r.ids.empty_pending, bob).status == 404);
    CHECK(api.counting.cancels == 1);
    CHECK(api.counting.reruns == 0);
    // Rerun of his own zero-row execution is attributed to bob.
    CHECK(is_2xx(api.rerun(r.ids.bob_pending, bob).status));
    CHECK(rerun_dispatchers(r, r.ids.bob_pending) == std::vector<std::string>{"bob"});
}

TEST_CASE("mutation owner key REST v1: the real Execute gate still refuses a service-scoped token",
          "[pg][execution][mutation][owner_rig][owner_rest][owner_key][security][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionOwnerRig r{db.dsn()};
    // mina's role may Execute, so only the service scope can be what refuses her minted token.
    REQUIRE(r.rbac.set_permission({"ExecutionReader5557", "Execution", "Execute", "allow"})
                .has_value());
    RestV1Mutations api{r, r.perm_fn()};
    const auto before = tracker_status(r, r.ids.minter_pending);

    CHECK(api.cancel(r.ids.minter_pending, ExecutionOwnerRig::bearer(r.creds.svc_a)).status == 403);
    CHECK(api.rerun(r.ids.minter_pending, ExecutionOwnerRig::bearer(r.creds.svc_a)).status == 403);
    CHECK(api.counting.effects() == 0);
    CHECK(tracker_status(r, r.ids.minter_pending) == before);
    // The same human's non-service token is not refused there (global grant: unconfined).
    CHECK(api.cancel(r.ids.minter_pending, ExecutionOwnerRig::bearer(r.creds.mina)).status == 200);
    CHECK(api.counting.cancels == 1);
}

TEST_CASE("mutation owner key REST v1: RBAC off refuses a service-scoped session and leaves a "
          "non-service one unconfined",
          "[pg][execution][mutation][owner_rig][owner_rest][owner_key][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionOwnerRig r{db.dsn()};
    r.rbac.set_rbac_enabled(false);
    RestV1Mutations api{r, permit_all()};

    CHECK(api.cancel(r.ids.minter_pending, ExecutionOwnerRig::bearer(r.creds.svc_a)).status == 403);
    CHECK(api.rerun(r.ids.minter_pending, ExecutionOwnerRig::bearer(r.creds.svc_a)).status == 403);
    CHECK(api.counting.effects() == 0);
    // Non-service: unconfined, so even a stranger's zero-row execution is mutable (unchanged).
    CHECK(api.cancel(r.ids.empty_pending, ExecutionOwnerRig::bearer(r.creds.bob)).status == 200);
    CHECK(tracker_status(r, r.ids.empty_pending) == "cancelled");
    CHECK(api.counting.cancel_users == std::vector<std::string>{"bob"});
}

TEST_CASE("mutation owner key legacy: a service-scoped session cannot mutate by minter ownership",
          "[pg][execution][mutation][owner_rig][owner_legacy][owner_key][security][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionOwnerRig r{db.dsn()};
    LegacyMutations api{r, permit_all()};
    const auto svc = ExecutionOwnerRig::bearer(r.creds.svc_a);

    for (const auto& id : {r.ids.minter_pending, r.ids.minter_out, r.ids.empty_pending}) {
        INFO(id);
        const auto before = tracker_status(r, id);
        CHECK(api.cancel(id, svc).status == 404);
        CHECK(api.rerun(id, svc).status == 404);
        CHECK(tracker_status(r, id) == before);
        CHECK(rerun_dispatchers(r, id).empty());
    }
    REQUIRE(api.audits.size() == 6);
    for (const auto& a : api.audits)
        CHECK(a.result == "denied");
    CHECK(api.audits[0].action == "execution.cancel");
    CHECK(api.audits[1].action == "execution.rerun");

    // A complete in-scope cohort is admitted by the cohort rule; the rerun is attributed to the
    // real principal (`user`), which the key never replaced.
    const auto live = r.make_exec("carol", ExecutionOwnerRig::kBaseAt + 300, 1, "running");
    r.put_status(live, "a1", "running");
    CHECK(api.cancel(live, svc).status == 200);
    CHECK(tracker_status(r, live) == "cancelled");
    CHECK(is_2xx(api.rerun(r.ids.in_a, svc).status));
    CHECK(rerun_dispatchers(r, r.ids.in_a) == std::vector<std::string>{"mina"});
}

TEST_CASE("mutation owner key legacy: a non-service session of the same human keeps the owner "
          "disjunct",
          "[pg][execution][mutation][owner_rig][owner_legacy][owner_key][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionOwnerRig r{db.dsn()};
    LegacyMutations api{r, permit_all()};
    const auto bob = ExecutionOwnerRig::bearer(r.creds.bob);

    CHECK(api.cancel(r.ids.bob_pending, bob).status == 200);
    CHECK(tracker_status(r, r.ids.bob_pending) == "cancelled");
    CHECK(api.cancel(r.ids.bob_out, bob).status == 404);
    CHECK(api.rerun(r.ids.bob_out, bob).status == 404);
    CHECK(api.rerun(r.ids.empty_pending, bob).status == 404);
    CHECK(is_2xx(api.rerun(r.ids.bob_pending, bob).status));
    CHECK(rerun_dispatchers(r, r.ids.bob_pending) == std::vector<std::string>{"bob"});
    REQUIRE_FALSE(api.audits.empty());
}

TEST_CASE("mutation owner key legacy: RBAC off refuses a service-scoped session",
          "[pg][execution][mutation][owner_rig][owner_legacy][owner_key][5557]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    ExecutionOwnerRig r{db.dsn()};
    r.rbac.set_rbac_enabled(false);
    LegacyMutations api{r, permit_all()};
    const auto before = tracker_status(r, r.ids.minter_pending);

    CHECK(api.cancel(r.ids.minter_pending, ExecutionOwnerRig::bearer(r.creds.svc_a)).status == 403);
    CHECK(api.rerun(r.ids.minter_pending, ExecutionOwnerRig::bearer(r.creds.svc_a)).status == 403);
    CHECK(tracker_status(r, r.ids.minter_pending) == before);
    CHECK(rerun_dispatchers(r, r.ids.minter_pending).empty());
    // Non-service, RBAC off: unconfined (unchanged).
    CHECK(api.cancel(r.ids.empty_pending, ExecutionOwnerRig::bearer(r.creds.bob)).status == 200);
    CHECK(tracker_status(r, r.ids.empty_pending) == "cancelled");
}
