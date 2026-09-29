#include "execution_routes.hpp"

#include "execution_model.hpp" // #2146 A2-R1: shared execution_child_row_json builder
#include "execution_scope_rules.hpp"
#include "execution_tracker.hpp"
#include "http_route_sink.hpp"
#include "json_extract.hpp"
#include "rest_a4_envelope_http.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace yuzu::server::execution {

void register_execution_routes(HttpRouteSink& sink, Deps deps) {
    // -- Execution API ------------------------------------------------------
    //
    // #3789: every route below is gated on `require_fleet_read(...,
    // "Read")` (mutations additionally keep their pre-existing
    // `require_permission(..., "Execute")` ahead of it — the fleet gate
    // structurally rejects any operation but "Read", see
    // authz_gates.cpp). `gate.scope` engaged means a confined caller;
    // visibility/count/mutation-admission decisions are delegated to
    // execution_scope_rules.hpp so every route (and its tests) share ONE
    // implementation of each rule. See docs/auth-architecture.md's
    // "Fourth migration (#3789)" note for the full design rationale.

    // GET /api/executions
    sink.Get("/api/executions", [deps](const httplib::Request& req, httplib::Response& res) {
        // No correlation-id capture here. Unlike the `/api/responses/*`
        // family (server.cpp aggregate/export/get routes), which
        // computes a `scope_dropped=N` audit count because it filters
        // rows in C++ AFTER the query, this route's confinement is a
        // SQL EXISTS pushdown (execution_tracker.cpp's
        // append_execution_scope_clause) — dropped rows never reach
        // this handler, so N is not observable here without a second,
        // unfiltered COUNT(*) query per confined LIST call (real cost
        // on the exact route already flagged for scan-depth amplification,
        // consistency-auditor #3789 Finding 1 / chaos-injector CH-6).
        // Deliberately deferred, not an oversight — tracked as
        // follow-up #3832 rather than blocking this migration. a4_error
        // mints a correlation id lazily on any 503/400 branch below.
        auto gate = deps.fleet_read_fn(req, res, "Execution", "Read");
        if (!gate.admitted)
            return; // gate already wrote the response.
        if (!deps.execution_tracker) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "service unavailable"), "application/json");
            return;
        }

        ExecutionQuery q;
        if (req.has_param("definition_id"))
            q.definition_id = req.get_param_value("definition_id");
        if (req.has_param("status"))
            q.status = req.get_param_value("status");
        try {
            if (req.has_param("limit"))
                q.limit = std::stoi(req.get_param_value("limit"));
        } catch (const std::exception&) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "invalid numeric query parameter"),
                            "application/json");
            return;
        }
        // #3789: the legacy route previously had no upper bound; cap
        // matches MCP list_executions (mcp_server.cpp).
        if (q.limit < 1)
            q.limit = 1;
        if (q.limit > 500)
            q.limit = 500;

        yuzu::server::ExecutionScope scope_arg; // nullopt = unrestricted
        std::string username;
        if (gate.scope) {
            auto session = deps.resolve_session_fn(req);
            username = session ? session->username : std::string{};
            // #3789 (mcp_server.cpp list_executions CH-5 precedent): an
            // empty username must never silently widen the owner
            // disjunct to "no owner filter" for a confined caller.
            if (username.empty()) {
                res.status = 503;
                res.set_content(
                    detail::a4_error(res,
                                    "unable to resolve caller identity for a confined read",
                                    {.retry_after_ms = 5000}),
                    "application/json");
                return;
            }
            yuzu::server::ExecutionListScope s;
            s.owner = username;
            s.visible_agents.assign(gate.scope->begin(), gate.scope->end());
            scope_arg = std::move(s);
        }

        auto execs_opt = deps.execution_tracker->query_executions_checked(q, scope_arg);
        if (!execs_opt) {
            res.status = 503;
            res.set_content(
                detail::a4_error(res, "execution tracker degraded", {.retry_after_ms = 5000}),
                "application/json");
            return;
        }
        const auto& execs = *execs_opt;

        nlohmann::json arr = nlohmann::json::array();
        if (gate.scope) {
            // #3789: batched per-row visibility + confined counts, one
            // round trip (ADR-0017 INV-10) — the SQL scope pushdown
            // above already restricted `execs` to visible rows; this
            // re-check is defense-in-depth plus how the per-row confined
            // counts get derived.
            std::vector<std::string> ids;
            ids.reserve(execs.size());
            for (const auto& e : execs)
                ids.push_back(e.id);
            auto statuses_opt =
                deps.execution_tracker->get_agent_statuses_for_executions_checked(ids);
            if (!statuses_opt) {
                res.status = 503;
                res.set_content(detail::a4_error(res, "execution tracker degraded",
                                                {.retry_after_ms = 5000}),
                                "application/json");
                return;
            }
            static const std::vector<AgentExecStatus> kEmptyStatuses;
            for (const auto& e : execs) {
                auto it = statuses_opt->find(e.id);
                const auto& statuses =
                    it != statuses_opt->end() ? it->second : kEmptyStatuses;
                if (!execution_visible(e, statuses, gate.scope, username))
                    continue;
                auto counts = confined_projection(statuses, gate.scope);
                arr.push_back({{"id", e.id},
                               {"definition_id", e.definition_id},
                               {"status", e.status},
                               {"dispatched_by", e.dispatched_by},
                               {"dispatched_at", e.dispatched_at},
                               {"agents_targeted", counts.agents_targeted},
                               {"agents_responded", counts.agents_responded},
                               {"agents_success", counts.agents_success},
                               {"agents_failure", counts.agents_failure},
                               {"completed_at", e.completed_at},
                               {"rerun_of", e.rerun_of}});
            }
        } else {
            for (const auto& e : execs) {
                arr.push_back({{"id", e.id},
                               {"definition_id", e.definition_id},
                               {"status", e.status},
                               {"dispatched_by", e.dispatched_by},
                               {"dispatched_at", e.dispatched_at},
                               {"agents_targeted", e.agents_targeted},
                               {"agents_responded", e.agents_responded},
                               {"agents_success", e.agents_success},
                               {"agents_failure", e.agents_failure},
                               {"completed_at", e.completed_at},
                               {"rerun_of", e.rerun_of}});
            }
        }
        res.set_content(nlohmann::json({{"executions", arr}, {"count", arr.size()}}).dump(),
                        "application/json");
    });

    // GET /api/executions/:id
    sink.Get(R"(/api/executions/([^/]+))", [deps](const httplib::Request& req,
                                                   httplib::Response& res) {
        const auto cid = detail::ensure_correlation_id(res);
        auto gate = deps.fleet_read_fn(req, res, "Execution", "Read");
        if (!gate.admitted)
            return;
        if (!deps.execution_tracker) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "service unavailable"), "application/json");
            return;
        }

        auto id = req.matches[1].str();
        std::string username;
        if (gate.scope) {
            auto session = deps.resolve_session_fn(req);
            username = session ? session->username : std::string{};
            // #3789: an empty username under an engaged scope means
            // session resolution failed after require_fleet_read
            // already admitted the request — fail closed with an
            // honest 503 rather than silently falling through to
            // agent-only visibility, which could otherwise 404 a
            // dispatcher's own execution under a misleading "denied"
            // audit row (matches the LIST route's identical guard).
            if (username.empty()) {
                res.status = 503;
                res.set_content(
                    detail::a4_error(res,
                                    "unable to resolve caller identity for a confined read",
                                    {.retry_after_ms = 5000}),
                    "application/json");
                return;
            }
        }

        auto exec_r = deps.execution_tracker->get_execution_checked(id);
        if (!exec_r) {
            res.status = 503;
            res.set_content(
                detail::a4_error(res, "execution tracker degraded", {.retry_after_ms = 5000}),
                "application/json");
            return;
        }
        const auto& exec_opt = *exec_r;

        std::vector<AgentExecStatus> statuses;
        if (gate.scope) {
            // #1634 perf precedent: only fetch/scan agent statuses when
            // confined — an unrestricted caller is always visible
            // regardless, so this indexed lookup would be pure waste.
            auto statuses_opt = deps.execution_tracker->get_agent_statuses_checked(id);
            if (!statuses_opt) {
                res.status = 503;
                res.set_content(detail::a4_error(res, "execution tracker degraded",
                                                {.retry_after_ms = 5000}),
                                "application/json");
                return;
            }
            statuses = std::move(*statuses_opt);
        }

        const bool visible =
            exec_opt.has_value() && execution_visible(*exec_opt, statuses, gate.scope, username);
        if (!exec_opt || !visible) {
            // #3789: audit ONLY when a confinement decision actually
            // happened (gate.scope engaged) — a suppressed
            // cross-operator read attempt is CC7.2-evidence-worthy the
            // same way the #1634 v1 detail route treats it. An
            // unconfined caller's genuinely-nonexistent id is ordinary
            // "not found", not a security event; auditing it as
            // "denied" would inflate the confinement-denial metric with
            // routine 404s (compliance-officer #3789 F2). The
            // caller-visible response stays identical either way (no
            // oracle) — only the server-side audit trail differs.
            if (gate.scope) {
                (void)deps.audit_fn(req, "execution.read", "denied", "Execution", id,
                                    "not found or outside caller's fleet-read scope surface=detail "
                                    "cid=" +
                                        cid);
            }
            res.status = 404;
            res.set_content(detail::a4_error(res, "not found"), "application/json");
            return;
        }

        const auto& exec = *exec_opt;
        std::string scope_expression = exec.scope_expression;
        std::string parameter_values = exec.parameter_values;
        int agents_targeted = exec.agents_targeted;
        int agents_responded = exec.agents_responded;
        int agents_success = exec.agents_success;
        int agents_failure = exec.agents_failure;
        // #3789: `owns_execution` above exists only to admit a
        // dispatcher to a just-dispatched, zero-status-row execution —
        // it must never also bypass this projection (#1634 precedent,
        // rest_api_v1.cpp). Apply confinement whenever `gate.scope` is
        // engaged, dispatcher or not.
        if (gate.scope) {
            auto counts = confined_projection(statuses, gate.scope);
            agents_targeted = counts.agents_targeted;
            agents_responded = counts.agents_responded;
            agents_success = counts.agents_success;
            agents_failure = counts.agents_failure;
            scope_expression = "(redacted - confined view)";
            parameter_values = "(redacted - confined view)";
        }
        // Deliberately keep status, completion time, dispatcher, and
        // lineage truthful (#1634 precedent) — none directly names
        // another agent. Deliberately NOT adding last_error_detail:
        // this legacy payload never carried it, and it is
        // PII-adjacent (agent stderr) — do not introduce a new
        // unconfined exposure while closing this gap.
        res.set_content(nlohmann::json({{"id", exec.id},
                                        {"definition_id", exec.definition_id},
                                        {"status", exec.status},
                                        {"scope_expression", scope_expression},
                                        {"parameter_values", parameter_values},
                                        {"dispatched_by", exec.dispatched_by},
                                        {"dispatched_at", exec.dispatched_at},
                                        {"agents_targeted", agents_targeted},
                                        {"agents_responded", agents_responded},
                                        {"agents_success", agents_success},
                                        {"agents_failure", agents_failure},
                                        {"completed_at", exec.completed_at},
                                        {"parent_id", exec.parent_id},
                                        {"rerun_of", exec.rerun_of}})
                            .dump(),
                        "application/json");
    });

    // GET /api/executions/:id/summary
    sink.Get(R"(/api/executions/([^/]+)/summary)", [deps](const httplib::Request& req,
                                                           httplib::Response& res) {
        const auto cid = detail::ensure_correlation_id(res);
        auto gate = deps.fleet_read_fn(req, res, "Execution", "Read");
        if (!gate.admitted)
            return;
        if (!deps.execution_tracker) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "service unavailable"), "application/json");
            return;
        }

        auto id = req.matches[1].str();
        std::string username;
        if (gate.scope) {
            auto session = deps.resolve_session_fn(req);
            username = session ? session->username : std::string{};
            // #3789: an empty username under an engaged scope means
            // session resolution failed after require_fleet_read
            // already admitted the request — fail closed with an
            // honest 503 rather than silently falling through to
            // agent-only visibility, which could otherwise 404 a
            // dispatcher's own execution under a misleading "denied"
            // audit row (matches the LIST route's identical guard).
            if (username.empty()) {
                res.status = 503;
                res.set_content(
                    detail::a4_error(res,
                                    "unable to resolve caller identity for a confined read",
                                    {.retry_after_ms = 5000}),
                    "application/json");
                return;
            }
        }

        auto exec_r = deps.execution_tracker->get_execution_checked(id);
        if (!exec_r) {
            res.status = 503;
            res.set_content(
                detail::a4_error(res, "execution tracker degraded", {.retry_after_ms = 5000}),
                "application/json");
            return;
        }
        const auto& exec_opt = *exec_r;

        std::vector<AgentExecStatus> statuses;
        if (gate.scope) {
            auto statuses_opt = deps.execution_tracker->get_agent_statuses_checked(id);
            if (!statuses_opt) {
                res.status = 503;
                res.set_content(detail::a4_error(res, "execution tracker degraded",
                                                {.retry_after_ms = 5000}),
                                "application/json");
                return;
            }
            statuses = std::move(*statuses_opt);
        }

        const bool visible =
            exec_opt.has_value() && execution_visible(*exec_opt, statuses, gate.scope, username);
        if (!exec_opt || !visible) {
            // #3789: unknown-id and invisible now collapse to the SAME
            // 404 for EVERY caller — the legacy route previously
            // returned a zero-filled 200 for an unknown id even to an
            // unconfined caller (behavior change; docs/user-manual/
            // upgrading.md). Audit ONLY under an engaged scope — see
            // the detail route's identical rationale.
            if (gate.scope) {
                (void)deps.audit_fn(req, "execution.read", "denied", "Execution", id,
                                    "not found or outside caller's fleet-read scope surface=summary "
                                    "cid=" +
                                        cid);
            }
            res.status = 404;
            res.set_content(detail::a4_error(res, "not found"), "application/json");
            return;
        }

        const auto& exec = *exec_opt;
        int agents_targeted = exec.agents_targeted;
        int agents_responded = exec.agents_responded;
        int agents_success = exec.agents_success;
        int agents_failure = exec.agents_failure;
        if (gate.scope) {
            auto counts = confined_projection(statuses, gate.scope);
            agents_targeted = counts.agents_targeted;
            agents_responded = counts.agents_responded;
            agents_success = counts.agents_success;
            agents_failure = counts.agents_failure;
        }
        const int progress_pct =
            agents_targeted > 0 ? (agents_responded * 100 / agents_targeted) : 0;

        res.set_content(nlohmann::json({{"id", exec.id},
                                        {"status", exec.status},
                                        {"agents_targeted", agents_targeted},
                                        {"agents_responded", agents_responded},
                                        {"agents_success", agents_success},
                                        {"agents_failure", agents_failure},
                                        {"progress_pct", progress_pct}})
                            .dump(),
                        "application/json");
    });

    // GET /api/executions/:id/agents
    sink.Get(R"(/api/executions/([^/]+)/agents)", [deps](const httplib::Request& req,
                                                          httplib::Response& res) {
        const auto cid = detail::ensure_correlation_id(res);
        auto gate = deps.fleet_read_fn(req, res, "Execution", "Read");
        if (!gate.admitted)
            return;
        if (!deps.execution_tracker) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "service unavailable"), "application/json");
            return;
        }

        auto id = req.matches[1].str();
        std::string username;
        if (gate.scope) {
            auto session = deps.resolve_session_fn(req);
            username = session ? session->username : std::string{};
            // #3789: an empty username under an engaged scope means
            // session resolution failed after require_fleet_read
            // already admitted the request — fail closed with an
            // honest 503 rather than silently falling through to
            // agent-only visibility, which could otherwise 404 a
            // dispatcher's own execution under a misleading "denied"
            // audit row (matches the LIST route's identical guard).
            if (username.empty()) {
                res.status = 503;
                res.set_content(
                    detail::a4_error(res,
                                    "unable to resolve caller identity for a confined read",
                                    {.retry_after_ms = 5000}),
                    "application/json");
                return;
            }
        }

        auto exec_r = deps.execution_tracker->get_execution_checked(id);
        if (!exec_r) {
            res.status = 503;
            res.set_content(
                detail::a4_error(res, "execution tracker degraded", {.retry_after_ms = 5000}),
                "application/json");
            return;
        }
        const auto& exec_opt = *exec_r;

        auto statuses_opt = deps.execution_tracker->get_agent_statuses_checked(id);
        if (!statuses_opt) {
            res.status = 503;
            res.set_content(
                detail::a4_error(res, "execution tracker degraded", {.retry_after_ms = 5000}),
                "application/json");
            return;
        }
        const auto& statuses = *statuses_opt;

        const bool visible =
            exec_opt.has_value() && execution_visible(*exec_opt, statuses, gate.scope, username);
        if (!exec_opt || !visible) {
            // #3789: audit ONLY under an engaged scope — see the detail
            // route's identical rationale (compliance-officer F2).
            if (gate.scope) {
                (void)deps.audit_fn(req, "execution.read", "denied", "Execution", id,
                                    "not found or outside caller's fleet-read scope surface=agents "
                                    "cid=" +
                                        cid);
            }
            res.status = 404;
            res.set_content(detail::a4_error(res, "not found"), "application/json");
            return;
        }

        // #3789: this route returns raw agent identities — the worst
        // leak of the seven pre-migration routes. Filter to in-scope
        // agents; the projection applies to the dispatcher too, same as
        // the detail route.
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& a : statuses) {
            if (!authz::in_scope(gate.scope, a.agent_id))
                continue;
            arr.push_back({{"agent_id", a.agent_id},
                           {"status", a.status},
                           {"dispatched_at", a.dispatched_at},
                           {"first_response_at", a.first_response_at},
                           {"completed_at", a.completed_at},
                           {"exit_code", a.exit_code},
                           {"error_detail", a.error_detail}});
        }
        res.set_content(nlohmann::json({{"agents", arr}}).dump(), "application/json");
    });

    // POST /api/executions/:id/rerun
    sink.Post(R"(/api/executions/([^/]+)/rerun)", [deps](const httplib::Request& req,
                                                          httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Execution", "Execute"))
            return;
        const auto cid = detail::ensure_correlation_id(res);
        auto gate = deps.fleet_read_fn(req, res, "Execution", "Read");
        if (!gate.admitted)
            return;
        if (!deps.execution_tracker) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "service unavailable"), "application/json");
            return;
        }

        auto id = req.matches[1].str();
        auto scope_filter = extract_json_string(req.body, "scope");
        bool failed_only = (scope_filter == "failed_only");

        auto session = deps.resolve_session_fn(req);
        auto user = session ? session->username : "unknown";
        const std::string username = session ? session->username : std::string{};

        if (gate.scope) {
            // #3789: an empty username under an engaged scope means
            // session resolution failed after require_fleet_read
            // already admitted the request — fail closed with an
            // honest 503 (matches the GET routes' identical guard).
            if (username.empty()) {
                res.status = 503;
                res.set_content(
                    detail::a4_error(res,
                                    "unable to resolve caller identity for a confined read",
                                    {.retry_after_ms = 5000}),
                    "application/json");
                return;
            }
            auto exec_r = deps.execution_tracker->get_execution_checked(id);
            if (!exec_r) {
                res.status = 503;
                res.set_content(detail::a4_error(res, "execution tracker degraded",
                                                {.retry_after_ms = 5000}),
                                "application/json");
                return;
            }
            const auto& exec_opt = *exec_r;
            // #3789 (adversarial review, Kimi+Codex): fetch statuses
            // UNCONDITIONALLY here, not only when exec_opt exists — an
            // id-conditional second query is a timing/work oracle that
            // lets a confined caller distinguish "nonexistent" from
            // "exists but hidden" by DB round-trip count, even though
            // the HTTP response is identical. The GET routes already
            // fetch unconditionally under gate.scope for the same
            // reason; mirror that shape here.
            auto statuses_opt = deps.execution_tracker->get_agent_statuses_checked(id);
            if (!statuses_opt) {
                res.status = 503;
                res.set_content(detail::a4_error(res, "execution tracker degraded",
                                                {.retry_after_ms = 5000}),
                                "application/json");
                return;
            }
            const bool admitted = exec_opt.has_value() &&
                                 admit_confined_mutation(*exec_opt, *statuses_opt, gate.scope,
                                                        username);
            if (!admitted) {
                // #3789: uniform deny shape — nonexistent, zero-visible,
                // partial, and incomplete-target-ledger all collapse to
                // the SAME 404 + non-distinguishing audit detail (a
                // distinct status for "partial visibility" would be a
                // hidden-cohort oracle, Sol/gpt-5.6-sol adversarial
                // review).
                (void)deps.audit_fn(req, "execution.rerun", "denied", "execution", id,
                                    "not found or outside caller's fleet-read scope cid=" + cid);
                res.status = 404;
                res.set_content(detail::a4_error(res, "not found"), "application/json");
                return;
            }
        }
        // Unconfined callers (and confined-and-admitted ones) fall
        // through to create_rerun, which performs its own
        // (degrade-collapsing) existence check internally — unchanged
        // from pre-#3789 behavior for an unconfined caller hitting an
        // unknown id (400 "original execution not found").

        auto result = deps.execution_tracker->create_rerun(id, user, failed_only);
        if (!result) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                            "application/json");
            return;
        }
        (void)deps.audit_fn(req, "execution.rerun", "success", "execution", *result,
                            "rerun of " + id);
        deps.emit_event_fn("execution.created", req, {},
                           {{"execution_id", *result}, {"parent_id", id}, {"trigger", "rerun"}});
        res.set_header(
            "HX-Trigger",
            R"({"showToast":{"message":"Execution rerun initiated","level":"success"}})");
        res.set_content(nlohmann::json({{"id", *result}}).dump(), "application/json");
    });

    // POST /api/executions/:id/cancel
    sink.Post(R"(/api/executions/([^/]+)/cancel)", [deps](const httplib::Request& req,
                                                           httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Execution", "Execute"))
            return;
        const auto cid = detail::ensure_correlation_id(res);
        auto gate = deps.fleet_read_fn(req, res, "Execution", "Read");
        if (!gate.admitted)
            return;
        if (!deps.execution_tracker) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "service unavailable"), "application/json");
            return;
        }

        auto id = req.matches[1].str();
        auto session = deps.resolve_session_fn(req);
        auto user = session ? session->username : "unknown";
        const std::string username = session ? session->username : std::string{};

        auto exec_r = deps.execution_tracker->get_execution_checked(id);
        if (!exec_r) {
            res.status = 503;
            res.set_content(
                detail::a4_error(res, "execution tracker degraded", {.retry_after_ms = 5000}),
                "application/json");
            return;
        }
        const auto& exec_opt = *exec_r;

        if (gate.scope) {
            // #3789: an empty username under an engaged scope means
            // session resolution failed after require_fleet_read
            // already admitted the request — fail closed with an
            // honest 503 (matches the GET routes' identical guard).
            if (username.empty()) {
                res.status = 503;
                res.set_content(
                    detail::a4_error(res,
                                    "unable to resolve caller identity for a confined read",
                                    {.retry_after_ms = 5000}),
                    "application/json");
                return;
            }
            // #3789 (adversarial review, Kimi+Codex): fetch statuses and
            // audit UNIFORMLY for a nonexistent id and a
            // hidden-but-existing/incomplete-cohort id — the earlier
            // shape short-circuited on `!exec_opt` before this fetch,
            // which was both a timing/work oracle (one DB round-trip
            // less for a nonexistent id) and an audit-trail asymmetry
            // (only the hidden-but-existing case wrote a `denied` row) —
            // breaking the documented "identical 404 + non-distinguishing
            // audit detail" guarantee for the two cases a caller sees as
            // the same response.
            auto statuses_opt = deps.execution_tracker->get_agent_statuses_checked(id);
            if (!statuses_opt) {
                res.status = 503;
                res.set_content(detail::a4_error(res, "execution tracker degraded",
                                                {.retry_after_ms = 5000}),
                                "application/json");
                return;
            }
            const bool admitted = exec_opt.has_value() &&
                                 admit_confined_mutation(*exec_opt, *statuses_opt, gate.scope,
                                                        username);
            if (!admitted) {
                (void)deps.audit_fn(req, "execution.cancel", "denied", "execution", id,
                                    "not found or outside caller's fleet-read scope cid=" + cid);
                res.status = 404;
                res.set_content(detail::a4_error(res, "not found"), "application/json");
                return;
            }
        } else if (!exec_opt) {
            // #3789 + PR #3842: this existence check gives an unknown id a
            // clean 404. It was originally load-bearing because
            // `mark_cancelled` reported PGRES_COMMAND_OK (a false "cancelled"
            // 200) on an UPDATE matching zero rows (Sol/gpt-5.6-sol review);
            // PR #3842's `RETURNING id` + terminal-status guard now makes
            // mark_cancelled return FALSE for an unknown OR already-terminal
            // execution, so this check is now defense-in-depth — it keeps the
            // common unknown-id case a 404 rather than the 503 a bare
            // mark_cancelled-false would produce below (a not-found/terminal-
            // vs-degrade refinement of that 503 is tracked in #3845). A
            // confined caller's existence check is folded into the branch above.
            res.status = 404;
            res.set_content(detail::a4_error(res, "not found"), "application/json");
            return;
        }

        // governance PR review (2026-08-31): mark_cancelled now reports
        // whether the update actually happened — do not tell the
        // operator "cancelled" (HTTP 200 + a "success" audit row) when
        // it didn't.
        if (!deps.execution_tracker->mark_cancelled(id, user)) {
            (void)deps.audit_fn(req, "execution.cancel", "failure", "execution", id, "");
            res.status = 503;
            res.set_content(detail::a4_error(res, "cancel failed - execution store degraded"),
                            "application/json");
            return;
        }
        (void)deps.audit_fn(req, "execution.cancel", "success", "execution", id, "");
        deps.emit_event_fn("execution.completed", req, {{"status", "cancelled"}},
                           {{"execution_id", id}});
        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"Execution cancelled","level":"success"}})");
        res.set_content(R"({"status":"cancelled"})", "application/json");
    });

    // GET /api/executions/:id/children
    sink.Get(R"(/api/executions/([^/]+)/children)", [deps](const httplib::Request& req,
                                                            httplib::Response& res) {
        const auto cid = detail::ensure_correlation_id(res);
        auto gate = deps.fleet_read_fn(req, res, "Execution", "Read");
        if (!gate.admitted)
            return;
        if (!deps.execution_tracker) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "service unavailable"), "application/json");
            return;
        }

        auto id = req.matches[1].str();
        std::string username;
        yuzu::server::ExecutionScope scope_arg; // nullopt = unrestricted
        if (gate.scope) {
            auto session = deps.resolve_session_fn(req);
            username = session ? session->username : std::string{};
            // #3789: an empty username under an engaged scope means
            // session resolution failed after require_fleet_read
            // already admitted the request — fail closed with an
            // honest 503 rather than silently falling through to
            // agent-only visibility, which could otherwise 404 a
            // dispatcher's own execution under a misleading "denied"
            // audit row (matches the LIST route's identical guard).
            if (username.empty()) {
                res.status = 503;
                res.set_content(
                    detail::a4_error(res,
                                    "unable to resolve caller identity for a confined read",
                                    {.retry_after_ms = 5000}),
                    "application/json");
                return;
            }
            // #2146 A2-R1 Gate 8 fix: threads the SAME owner-or-visible-agent
            // admission predicate into get_children_checked's SQL below (this
            // file's own LIST handler precedent above) -- closes the
            // cap-before-scope defect where an invisible sibling could
            // displace this caller's own visible children out of the capped
            // window.
            yuzu::server::ExecutionListScope s;
            s.owner = username;
            s.visible_agents.assign(gate.scope->begin(), gate.scope->end());
            scope_arg = std::move(s);
        }

        auto exec_r = deps.execution_tracker->get_execution_checked(id);
        if (!exec_r) {
            res.status = 503;
            res.set_content(
                detail::a4_error(res, "execution tracker degraded", {.retry_after_ms = 5000}),
                "application/json");
            return;
        }
        const auto& exec_opt = *exec_r;

        std::vector<AgentExecStatus> parent_statuses;
        if (gate.scope) {
            auto statuses_opt = deps.execution_tracker->get_agent_statuses_checked(id);
            if (!statuses_opt) {
                res.status = 503;
                res.set_content(detail::a4_error(res, "execution tracker degraded",
                                                {.retry_after_ms = 5000}),
                                "application/json");
                return;
            }
            parent_statuses = std::move(*statuses_opt);
        }

        const bool parent_visible =
            exec_opt.has_value() &&
            execution_visible(*exec_opt, parent_statuses, gate.scope, username);
        if (!exec_opt || !parent_visible) {
            // #3789: audit ONLY under an engaged scope — see the detail
            // route's identical rationale (compliance-officer F2).
            if (gate.scope) {
                (void)deps.audit_fn(req, "execution.read", "denied", "Execution", id,
                                    "not found or outside caller's fleet-read scope surface=children "
                                    "cid=" +
                                        cid);
            }
            res.status = 404;
            res.set_content(detail::a4_error(res, "not found"), "application/json");
            return;
        }

        auto children_opt = deps.execution_tracker->get_children_checked(id, scope_arg);
        if (!children_opt) {
            res.status = 503;
            res.set_content(
                detail::a4_error(res, "execution tracker degraded", {.retry_after_ms = 5000}),
                "application/json");
            return;
        }

        nlohmann::json arr = nlohmann::json::array();
        if (gate.scope) {
            // #3789 (Sol/gpt-5.6-sol adversarial review, overriding an
            // earlier "truthful lineage" reading of the #1634 detail
            // precedent): parent visibility does NOT authorize
            // enumerating separate child execution records — each
            // child passes the same owner-or-visible-agent predicate
            // independently. One batched statuses call, not N+1.
            std::vector<std::string> child_ids;
            child_ids.reserve(children_opt->children.size());
            for (const auto& c : children_opt->children)
                child_ids.push_back(c.id);
            auto child_statuses_opt =
                deps.execution_tracker->get_agent_statuses_for_executions_checked(child_ids);
            if (!child_statuses_opt) {
                res.status = 503;
                res.set_content(detail::a4_error(res, "execution tracker degraded",
                                                {.retry_after_ms = 5000}),
                                "application/json");
                return;
            }
            static const std::vector<AgentExecStatus> kEmptyStatuses;
            for (const auto& c : children_opt->children) {
                auto it = child_statuses_opt->find(c.id);
                const auto& c_statuses =
                    it != child_statuses_opt->end() ? it->second : kEmptyStatuses;
                if (!execution_visible(c, c_statuses, gate.scope, username))
                    continue;
                // #2146 A2-R1: shared builder (execution_model.hpp) - REST v1's
                // new GET /api/v1/executions/{id}/children and MCP's new
                // get_execution_children call the SAME function, so this row
                // shape cannot drift from theirs (docs/api-twin-recipe.md Rule 1).
                arr.push_back(execution_child_row_json(c));
            }
        } else {
            for (const auto& c : children_opt->children) {
                arr.push_back(execution_child_row_json(c));
            }
        }
        nlohmann::json body{{"children", arr}};
        // #2146 A2-R1 (governance re-review, blocking): get_children_checked
        // is now hard-capped (execution_tracker.cpp's kExecutionChildrenCap)
        // -- previously unbounded. Present-only-when-true, matching MCP
        // list_schedules/query_responses' result_truncated_by_cap
        // convention -- this route has no `pagination` envelope object to
        // nest it under (unlike GET /api/v1/schedules), so it sits
        // top-level next to `children`. #2146 A2-R1 Gate 8 fix: scope_arg
        // above is now pushed into the SQL BEFORE the cap
        // (ExecutionChildrenResult's doc comment), so for a confined caller
        // this reports THEIR OWN visible row set exceeding the cap, not the
        // fleet-wide one -- the per-child confinement filter above is now
        // redundant-but-safe defense in depth over an already-scoped result,
        // never the primary admission decision.
        if (children_opt->truncated)
            body["result_truncated_by_cap"] = true;
        res.set_content(body.dump(), "application/json");
    });
}

} // namespace yuzu::server::execution
