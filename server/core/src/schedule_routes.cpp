#include "schedule_routes.hpp"

#include "http_route_sink.hpp"
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard
#include "schedule_engine.hpp"
#include "schedule_params_parsers.hpp"

#include <nlohmann/json.hpp>

namespace yuzu::server::schedule {

void register_schedule_routes(HttpRouteSink& sink, Deps deps) {
    // -- Schedule API -----------------------------------------------------

    sink.Get("/api/schedules", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Schedule", "Read"))
            return;
        // guardian-confinement-2298 hardening sweep originally added an
        // explicit deny_service_scoped_schedule() call here (ITServiceOwner
        // grants full CRUD on Schedule, and query_schedules has no owner/
        // service filter at all — a bare Schedule:Read gate would let a
        // service-scoped token enumerate every schedule from every other
        // service). guardian-confinement-2298 PR 3 ("the flip") made it
        // provably dead: require_permission above already denies any
        // service-scoped token outright for (Schedule, Read)
        // (kServiceScopeGlobalSafe is compile-time-empty), so a
        // service-scoped session can never reach this point at all.
        // Retired #3290 Phase 2 bucket 1a — see
        // docs/security-reviews/service-scope-phase2-migrations-2026-08.md.
        if (!deps.schedule_engine) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        ScheduleQuery q;
        if (req.has_param("definition_id"))
            q.definition_id = req.get_param_value("definition_id");
        if (req.has_param("enabled_only"))
            q.enabled_only = true;

        auto scheds = deps.schedule_engine->query_schedules(q);
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& s : scheds) {
            arr.push_back({{"id", s.id},
                           {"name", s.name},
                           {"definition_id", s.definition_id},
                           {"enabled", s.enabled},
                           {"frequency_type", s.frequency_type},
                           {"next_execution_at", s.next_execution_at},
                           {"last_executed_at", s.last_executed_at},
                           {"execution_count", s.execution_count}});
        }
        res.set_content(nlohmann::json({{"schedules", arr}}).dump(), "application/json");
    });

    sink.Post("/api/schedules", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Schedule", "Write"))
            return;
        // H-01 (#1806): Schedule:Write alone must not reach fleet-wide
        // command dispatch — a created schedule fires unattended through
        // ScheduleRunner::tick() with NO per-fire permission check (there
        // is no operator session on that background-thread path), and an
        // empty scope_expression means send-to-all with no approval gate
        // by default. Every other execution-producing route in server.cpp
        // (POST /api/command, the instruction-execute routes) gates
        // Execution:Execute; schedule creation must match.
        if (!deps.perm_fn(req, res, "Execution", "Execute"))
            return;
        // The interim deny_service_scoped_schedule() call that used to sit
        // here was retired (#3290 Phase 2, bucket 1a): guardian-
        // confinement-2298 PR 3 ("the flip") made it provably dead —
        // require_permission's own service-scoped branch above already
        // denies any service-scoped token outright for (Schedule, Write)
        // (kServiceScopeGlobalSafe is compile-time-empty), so a
        // service-scoped session can never reach this point at all. See
        // docs/security-reviews/service-scope-phase2-migrations-2026-08.md's
        // "Bucket 1a" section.
        if (!deps.schedule_engine) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        try {
            // #2437-class guard: raw-text depth check before parse -
            // "parameters" is dumped a few lines below
            // (params_raw = j["parameters"].dump()), so the check has to run
            // on the raw text before any allocation.
            if (mcp::json_exceeds_depth(req.body, mcp::kMcpMaxJsonDepth)) {
                res.status = 400;
                res.set_content(
                    nlohmann::json({{"error", "request body nests too deeply"}}).dump(),
                    "application/json");
                return;
            }
            auto j = nlohmann::json::parse(req.body);
            InstructionSchedule sched;
            sched.name = j.value("name", "");
            sched.definition_id = j.value("definition_id", "");
            sched.frequency_type = j.value("frequency_type", "once");
            sched.interval_minutes = j.value("interval_minutes", 60);
            sched.time_of_day = j.value("time_of_day", "00:00");
            sched.day_of_week = j.value("day_of_week", 0);
            sched.day_of_month = j.value("day_of_month", 1);
            sched.scope_expression = j.value("scope_expression", "");
            sched.requires_approval = j.value("requires_approval", false);

            // Typed schedule parameters (PR1.5a). `parameters` is OPTIONAL —
            // an omitted field dumps to the empty string, which the
            // validator treats identically to an explicit "{}". Validating
            // here (rather than deferring entirely to create_schedule's
            // backstop) gives the caller a specific, typed 400 instead of a
            // generic insert failure.
            std::string params_raw;
            if (j.contains("parameters"))
                params_raw = j["parameters"].dump();
            auto canon_params = validate_and_canonicalize_schedule_params(params_raw);
            if (!canon_params) {
                res.status = 400;
                res.set_content(
                    nlohmann::json({{"error", std::string(to_string(canon_params.error()))}})
                        .dump(),
                    "application/json");
                return;
            }
            sched.parameter_values = *canon_params;

            // KNOWN GAP (#4131, pre-existing, not introduced by this extraction —
            // verified byte-identical against origin/dev's pre-extraction inline
            // code): this is a SECOND, non-atomic resolve_session call, independent
            // of the Schedule:Write/Execution:Execute perm_fn gates' own internal
            // session resolution above. If THIS call returns nullopt (a concurrent
            // session eviction, or a Postgres session-store brownout past the 30s
            // stale-serve bound) while the gates above already succeeded,
            // `created_by` silently stays "" rather than failing the request
            // closed — and "" can never match a real username, so the schedule
            // becomes permanently un-deletable/un-disableable via the owner-scoped
            // API, and (under RBAC legacy-open) still arms and fires unattended
            // forever with no kill switch. Do not silently fix this here; see
            // #4131 for the real remedy (reuse the identity the gate already
            // validated instead of re-resolving).
            if (auto session = deps.resolve_session_fn(req))
                sched.created_by = session->username;

            auto result = deps.schedule_engine->create_schedule(sched);
            if (!result) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                                "application/json");
                return;
            }
            (void)deps.audit_fn(req, "schedule.create", "success", "schedule", *result,
                                sched.name);
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"Schedule created","level":"success"}})");
            res.set_content(nlohmann::json({{"id", *result}}).dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    sink.Delete(R"(/api/schedules/([^/]+))",
               [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Schedule", "Delete"))
            return;
        if (!deps.schedule_engine) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto id = req.matches[1].str();
        // An interim deny_service_scoped_schedule() call used to sit here
        // (delete_schedule is username-owner-scoped below, and a
        // service-scoped token shares its creating principal's username —
        // without a deny it could delete a fleet-wide schedule its own
        // principal created interactively). guardian-confinement-2298 PR 3
        // ("the flip") made it provably dead: require_permission above
        // already denies any service-scoped token outright for
        // (Schedule, Delete). Retired #3290 Phase 2 bucket 1a.
        // M-01 (#1806): owner-scoped delete — a Schedule:Delete grant
        // deletes only schedules the caller created, not the whole
        // fleet's. deps.resolve_session_fn, not require_permission's
        // session (already consumed) — a SECOND, non-atomic resolution
        // (#4131), same shape as the create route's own known gap above.
        // Here the failure mode is benign: a nullopt yields an empty `user`
        // that matches no real owner, so the delete is a harmless no-op
        // rather than a wrong deletion.
        auto session = deps.resolve_session_fn(req);
        auto user = session ? session->username : std::string();
        bool deleted = deps.schedule_engine->delete_schedule(id, user);
        if (deleted) {
            (void)deps.audit_fn(req, "schedule.delete", "success", "schedule", id, "");
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"Schedule deleted","level":"success"}})");
        }
        res.set_content(nlohmann::json({{"deleted", deleted}}).dump(), "application/json");
    });

    sink.Post(R"(/api/schedules/([^/]+)/enable)",
             [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Schedule", "Write"))
            return;
        if (!deps.schedule_engine) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto id = req.matches[1].str();
        // guardian-confinement-2298: parse_schedule_enabled (schedule_routes.hpp)
        // — extract_json_string only matches a JSON *string*, so a real
        // JSON boolean {"enabled":false} used to silently fall through
        // to the "absent" default (true), inverting the request and
        // defeating the disable-always-reachable kill switch (H-01).
        bool enabled = parse_schedule_enabled(req.body);
        // H-01 (#1806): re-enabling arms the schedule to fire unattended
        // through ScheduleRunner — the same fleet-wide-dispatch concern
        // as create, so it needs the same Execution:Execute gate.
        // Disabling only ever stops a schedule, so it stays gated on
        // Schedule:Write alone — an operator must be able to kill a
        // runaway schedule even without Execution:Execute.
        if (enabled && !deps.perm_fn(req, res, "Execution", "Execute"))
            return;
        // An interim deny_service_scoped_schedule() call used to sit here,
        // enable(true) only — deliberately built to leave disable
        // reachable for a service-scoped token as its kill switch (H-01).
        // guardian-confinement-2298 PR 3 ("the flip") made the deny itself
        // provably dead (require_permission above already denies any
        // service-scoped token outright for (Schedule, Write), enabled or
        // not) — retired here, #3290 Phase 2 bucket 1a. NOTE: the flip's
        // unconditional Schedule:Write gate ALSO means the documented
        // kill-switch guarantee (disable stays reachable) does not
        // currently hold for a service-scoped token, since it never gets
        // past `require_permission` above regardless of `enabled`'s
        // value — a real, pre-existing, NOT-yet-fixed gap this retirement
        // discovered but does not resolve; see #3378.

        // M-01 (#1806): owner-scoped enable/disable, same as delete above.
        auto session = deps.resolve_session_fn(req);
        auto user = session ? session->username : std::string();
        bool changed = deps.schedule_engine->set_enabled(id, enabled, user);
        if (changed) {
            // L-04 (#1806): enable/disable had no audit trail at all.
            (void)deps.audit_fn(req, enabled ? "schedule.enable" : "schedule.disable", "success",
                                "schedule", id, "");
        }
        res.set_content(nlohmann::json({{"enabled", enabled}}).dump(), "application/json");
    });
}

bool parse_schedule_enabled(const std::string& body) {
    try {
        auto j = nlohmann::json::parse(body);
        if (j.contains("enabled")) {
            if (j["enabled"].is_boolean())
                return j["enabled"].get<bool>();
            if (j["enabled"].is_string())
                return j["enabled"].get<std::string>() != "false";
        }
    } catch (...) {
    }
    return true; // missing key / malformed body — pre-existing default
}

} // namespace yuzu::server::schedule
