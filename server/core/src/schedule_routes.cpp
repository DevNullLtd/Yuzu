#include "schedule_routes.hpp"

#include "http_route_sink.hpp"
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard
#include "mcp_retry.hpp"   // mcp::kMcpStoreFaultRetryMs: the shared transient-fault retry floor
#include "query_int_parse.hpp"
#include "rbac_text.hpp" // rbac_text_is_clean: the shared clean-identifier predicate
#include "schedule_engine.hpp"
#include "schedule_params_parsers.hpp"
#include "utf8_sanitize.hpp" // sanitize_utf8_strict: keeps error bodies serialisable

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server::schedule {

namespace {

/// Upper bound of `interval_minutes`: the engine's own create-time ceiling
/// (`kMaxScheduleIntervalMinutes`, floor(INT32_MAX / 60)), so the route 400s before the engine
/// would refuse the same value.
constexpr std::int64_t kMaxIntervalMinutes = kMaxScheduleIntervalMinutes;

/// Strict schedule integer (#4644): ABSENT keeps `def`; a PRESENT key must be one JSON integer
/// inside [lo, hi]. `body.value(k, int)` is a plain static_cast, so 4294967297 became 1 (an
/// every-minute interval) and 5.5 became 5; a string or null threw and leaked nlohmann's text.
/// Returns the 400 message, or nullopt when accepted (`out` then holds the value).
std::optional<std::string> read_schedule_int(const nlohmann::json& j, const char* key, int def,
                                             std::int64_t lo, std::int64_t hi, int& out) {
    const auto v = read_json_int_strict(j, key, def);
    if (!v)
        return std::string(key) + " must be a JSON integer";
    if (*v < lo || *v > hi)
        return std::string(key) + " must be between " + std::to_string(lo) + " and " +
               std::to_string(hi);
    out = static_cast<int>(*v);
    return std::nullopt;
}

/// Writes the file's A4-style error envelope (the same shape as the 503 "service unavailable"
/// answers below) with the given status and message.
void send_error(httplib::Response& res, int status, std::string_view message) {
    res.status = status;
    res.set_content(
        nlohmann::json({{"error", {{"code", status}, {"message", std::string(message)}}},
                        {"meta", {{"api_version", "v1"}}}})
            .dump(),
        "application/json");
}

/// A path id is an identifier: a NUL, other control byte or DEL is refused before any store call.
[[nodiscard]] bool schedule_id_is_clean(const std::string& id) noexcept {
    return rbac_text_is_clean(id);
}

/// Why an owner-scoped write (`delete_schedule`, `set_enabled`) reported "no row changed".
enum class MissCause {
    NotFound,   ///< the store answered and the caller owns no such schedule
    StoreFault, ///< the store could not answer, or the caller's own row exists but was not written
};

/// The engine's write methods return a bare bool, so a store fault and an absent row look the
/// same. Classify a false result with one owner-filtered point read by (id, owner), independent
/// of any listing cap: an unreadable store, or a row that exists and belongs to `user`, is a
/// store fault (the write did not apply to a row it should have matched). Only an answered read
/// that shows no such owned row is NotFound (a row owned by someone else is deliberately the
/// same answer, so ids cannot be probed across owners).
[[nodiscard]] MissCause classify_write_miss(const ScheduleEngine& engine, const std::string& id,
                                            const std::string& user) {
    switch (engine.owned_schedule_exists_checked(id, user)) {
    case OwnedScheduleLookup::Absent:
        return MissCause::NotFound;
    case OwnedScheduleLookup::Exists:
    case OwnedScheduleLookup::Unreadable:
        break;
    }
    return MissCause::StoreFault;
}

/// True when `create_schedule` failed because the store could not take the write (not the
/// request). `kScheduleCreateValueRefusedError` (a field value the store refused as invalid text
/// or as violating a constraint) and every request-validation text are answered 400 instead.
[[nodiscard]] bool create_error_is_store_fault(const std::string& err) {
    return err == kScheduleCreateNotOpenError || err == kScheduleCreateInsertFailedError;
}

/// A NUL byte in a free-text create field (the store cannot hold one).
[[nodiscard]] bool contains_nul(const std::string& s) noexcept {
    return s.find('\0') != std::string::npos;
}

/// The 503 for a store fault: the same A4 envelope as `send_error` plus the shared transient-fault
/// `retry_after_ms` hint.
void send_store_fault(httplib::Response& res) {
    res.status = 503;
    res.set_content(
        nlohmann::json({{"error",
                         {{"code", 503},
                          {"message", "schedule store unavailable"},
                          {"retry_after_ms", mcp::kMcpStoreFaultRetryMs}}},
                        {"meta", {{"api_version", "v1"}}}})
            .dump(),
        "application/json");
}

} // namespace

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
            sched.time_of_day = j.value("time_of_day", "00:00");
            sched.scope_expression = j.value("scope_expression", "");
            sched.requires_approval = j.value("requires_approval", false);
            // A NUL byte cannot be stored in a text column: refuse it here, before the engine,
            // so the answer is a client error with a denied row rather than a store fault.
            for (const std::string* field :
                 {&sched.name, &sched.definition_id, &sched.frequency_type, &sched.time_of_day,
                  &sched.scope_expression}) {
                if (contains_nul(*field)) {
                    (void)deps.audit_fn(req, "schedule.create", "denied", "schedule", "",
                                        "field_contains_nul");
                    res.status = 400;
                    res.set_content(
                        nlohmann::json({{"error", "a schedule field must not contain a NUL byte"}})
                            .dump(),
                        "application/json");
                    return;
                }
            }
            // Strict integers with the documented ranges (#4644): a wrapped or fractional value
            // used to become a different, valid-looking schedule, and nothing is created on a 400.
            for (const auto& err :
                 {read_schedule_int(j, "interval_minutes", 60, 1, kMaxIntervalMinutes,
                                    sched.interval_minutes),
                  read_schedule_int(j, "day_of_week", 0, 0, 6, sched.day_of_week),
                  read_schedule_int(j, "day_of_month", 1, 1, 28, sched.day_of_month)}) {
                if (err) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", *err}}).dump(), "application/json");
                    return;
                }
            }

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
                if (create_error_is_store_fault(result.error())) {
                    (void)deps.audit_fn(req, "schedule.create", "failure", "schedule", "",
                                        "store_error");
                    send_store_fault(res);
                    return;
                }
                if (result.error() == kScheduleCreateValueRefusedError)
                    (void)deps.audit_fn(req, "schedule.create", "denied", "schedule", "",
                                        "invalid_field_value");
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
        } catch (const nlohmann::json::parse_error&) {
            // A fixed text: the parser's own message can quote the offending input, including a
            // byte that is not valid UTF-8, which `dump()` would then refuse to serialise.
            res.status = 400;
            res.set_content(nlohmann::json({{"error", "invalid JSON in request body"}}).dump(),
                            "application/json");
        } catch (const std::exception& e) {
            // Scrubbed to valid UTF-8 so the error body can always be serialised.
            res.status = 400;
            res.set_content(
                nlohmann::json({{"error", sanitize_utf8_strict(e.what())}}).dump(),
                "application/json");
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
        if (!schedule_id_is_clean(id)) {
            (void)deps.audit_fn(req, "schedule.delete", "denied", "schedule", "",
                                "invalid_schedule_id");
            send_error(res, 400, "invalid schedule id");
            return;
        }
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
        } else if (classify_write_miss(*deps.schedule_engine, id, user) ==
                   MissCause::StoreFault) {
            (void)deps.audit_fn(req, "schedule.delete", "failure", "schedule", id, "store_error");
            send_store_fault(res);
            return;
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
        const auto parsed_enabled = parse_schedule_enabled(req.body);
        if (!parsed_enabled) {
            // #4644: nothing is armed or changed on a value that is not an unambiguous boolean.
            res.status = 400;
            res.set_content(
                nlohmann::json({{"error", "enabled must be a JSON boolean, the integer 0 or 1, or the string \"true\" or \"false\""}})
                    .dump(),
                "application/json");
            return;
        }
        const bool enabled = *parsed_enabled;
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

        const char* const audit_action = enabled ? "schedule.enable" : "schedule.disable";
        if (!schedule_id_is_clean(id)) {
            (void)deps.audit_fn(req, audit_action, "denied", "schedule", "",
                                "invalid_schedule_id");
            send_error(res, 400, "invalid schedule id");
            return;
        }

        // M-01 (#1806): owner-scoped enable/disable, same as delete above.
        auto session = deps.resolve_session_fn(req);
        auto user = session ? session->username : std::string();
        const bool changed = deps.schedule_engine->set_enabled(id, enabled, user);
        if (!changed) {
            // No row changed: answer what actually happened, never the requested state.
            if (classify_write_miss(*deps.schedule_engine, id, user) == MissCause::StoreFault) {
                (void)deps.audit_fn(req, audit_action, "failure", "schedule", id, "store_error");
                send_store_fault(res);
                return;
            }
            send_error(res, 404, "schedule not found");
            return;
        }
        // L-04 (#1806): enable/disable had no audit trail at all.
        (void)deps.audit_fn(req, audit_action, "success", "schedule", id, "");
        res.set_content(nlohmann::json({{"enabled", enabled}}).dump(), "application/json");
    });
}

std::optional<bool> parse_schedule_enabled(const std::string& body) {
    // A blank (empty or whitespace-only) body is "no body" -- the same rule as the credential-
    // rotate and enrollment-batch readers.
    if (std::all_of(body.begin(), body.end(),
                    [](unsigned char c) { return std::isspace(c) != 0; }))
        return true; // no body -- pre-existing default: enabling is the bare action
    const auto j = nlohmann::json::parse(body, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object())
        return std::nullopt; // truncated or non-object body: never inferred as "arm"
    if (!j.contains("enabled"))
        return true; // missing key -- pre-existing default (disable is an explicit opt-in)
    const auto& v = j["enabled"];
    if (v.is_boolean())
        return v.get<bool>();
    // 0 and 1 are the only integers with an unambiguous boolean meaning; `{"enabled":0}` used to
    // ARM the schedule (only the exact string "false" disarmed). Floats, strings, null, arrays
    // and objects are refused.
    if (v.is_number_integer()) {
        if (v == 0)
            return false;
        if (v == 1)
            return true;
    }
    // The exact strings "true" and "false" keep the documented kill switch reachable for older
    // clients that send the value as text: `{"enabled":"false"}` must still disable a runaway
    // schedule. Case variants and every other string stay refused.
    if (v.is_string()) {
        const auto& t = v.get_ref<const std::string&>();
        if (t == "false")
            return false;
        if (t == "true")
            return true;
    }
    return std::nullopt;
}

} // namespace yuzu::server::schedule
