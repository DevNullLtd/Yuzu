#include "command_routes.hpp"

#include "agent_registry.hpp"            // AgentRegistry, ClassifiedCommand, DispatchDenial(Reason)
#include "authz_model.hpp"                // yuzu::server::authz::to_string(Operation)
#include "command_capability.hpp"         // CommandCapabilityRegistry (full definition — classify())
#include "dispatch_destructive_gate.hpp"  // evaluate_destructive_targeting / confine_destructive_targets
#include "dispatch_scope_ladder.hpp"      // ScopeLadderAudit / resolve_scope_targets
#include "dispatch_target_shape.hpp"      // check_targeting_shape / targeting_supplied / classify_dispatch_arm
#include "json_extract.hpp"               // extract_json_string / _array / _map / _int
#include "mcp_jsonrpc.hpp"                 // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard
#include "on_behalf_guard.hpp"            // onbehalf::sanitize_for_log
#include "rest_audit.hpp"                 // yuzu::server::detail::emit_behavioral_audit

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstddef>
#include <exception>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

/// @file command_routes.cpp
/// The extraction body. Every fix below is numbered against the review of the
/// prior (unmerged) extraction attempt that found them; the numbering is not
/// contiguous because two pairs of fixes are two facets of one underlying
/// defect (#2/#4 are both the send-time leak; #3/#6 are both the audit
/// exception-unsafety) — six defects, eight fix sites.

namespace {

/// #2557 fix #7: the ORIGINAL `bad_ident` used `std::isalnum(c)`, which is
/// LOCALE-DEPENDENT — in a "C" locale it behaves as intended, but a process
/// that has called `std::setlocale(LC_ALL, "")` (or any locale other than
/// "C"/"POSIX") can have `std::isalnum` accept bytes outside `[A-Za-z0-9]`
/// (a Latin-1 'é' reads as alphanumeric under several locales), silently
/// widening what this route accepts as a "safe identifier" — undermining the
/// exact audit-forgery closure this check exists for. Explicit ASCII
/// range checks are never locale-sensitive. Char-class widened only in
/// mechanism, not in the actual accepted set or the length limit — both
/// verified against the pre-extraction original before this file was
/// written: `kIdentMax == 128`, `_`/`.`/`-` legal.
[[nodiscard]] bool bad_ident(std::string_view v) {
    constexpr std::size_t kIdentMax = 128;
    if (v.size() > kIdentMax)
        return true;
    return std::any_of(v.begin(), v.end(), [](unsigned char c) {
        return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                 c == '_' || c == '.' || c == '-');
    });
}

/// Governance round 1 (UP-1b): the counterpart to the local `audit_fn`
/// wrapper's own throw-counting (below) — a throwing `guarded()` site
/// deserves the SAME `yuzu_server_dispatch_fanout_throw_total{route,phase}`
/// observability, not just a log line. `phase` is the call site's own
/// `what` label, reused directly rather than mapped through a second
/// taxonomy. Wrapped in its own try/catch, empty on purpose (matches the
/// `audit_fn` wrapper's pattern at :131-152 below) so a metrics-registry
/// failure can never itself escape `guarded()`'s catch block.
void record_fanout_throw(yuzu::MetricsRegistry* metrics, const char* phase) {
    if (!metrics)
        return;
    try {
        metrics->counter("yuzu_server_dispatch_fanout_throw_total",
                         {{"route", "command"}, {"phase", phase}})
            .increment();
    } catch (...) { // NOLINT(bugprone-empty-catch)
    }
}

/// #2557 fix #3/#6: a post-dispatch side effect (an audit helper that isn't
/// `AuditFn`-shaped, an event emission, a gateway forward) that throws must
/// not take the whole `/api/command` response down with it — the dispatch
/// already SUCCEEDED (agents were sent the command) by the time any of these
/// run, so an exception here must degrade the response, never turn a real
/// success into an uncaught-exception 500. Logged at ERROR (not silently
/// swallowed) so the failure is still observable in the server log even
/// though the caller gets a clean 200, and counted via `record_fanout_throw`
/// above (governance round 1, UP-1b) so it is also observable without
/// grepping the log.
void guarded(const std::string& command_id, const char* what, yuzu::MetricsRegistry* metrics,
            const std::function<void()>& fn) {
    try {
        fn();
    } catch (const std::exception& e) {
        spdlog::error("post-dispatch {} threw for command {}: {}", what, command_id, e.what());
        record_fanout_throw(metrics, what);
    } catch (...) {
        spdlog::error("post-dispatch {} threw for command {}", what, command_id);
        record_fanout_throw(metrics, what);
    }
}

} // namespace

namespace yuzu::server::command {

void register_command_routes(HttpRouteSink& sink, Deps deps) {
    sink.Post("/api/command", [deps = std::move(deps)](const httplib::Request& req,
                                                        httplib::Response& res) {
        // #2437-class guard: raw-text depth check before ANY parse of this
        // body. One check here covers every extraction below, including the
        // helper-hidden ones (extract_json_string/_map both parse the body
        // internally) and the later explicit nlohmann::json::parse, in
        // particular extract_json_string_map's own `v.dump()` on a non-string
        // "params" value, the actual crash site this guard closes.
        if (mcp::json_exceeds_depth(req.body, mcp::kMcpMaxJsonDepth)) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"request body nests too deeply"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        // Parse JSON body: { "plugin": "...", "action": "...", "agent_ids": [...] }
        auto plugin = extract_json_string(req.body, "plugin");
        auto action = extract_json_string(req.body, "action");

        if (plugin.empty() || action.empty()) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"plugin and action are required"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        // plugin/action are IDENTIFIERS. Bounding them here is what actually
        // closes the audit-detail forgery that a previous round only half
        // fixed: `sanitize_for_log` normalises control bytes, but leaves
        // space, `=`, `:` and `-` alone, so a caller could still plant
        //     plugin = "noop reason=agent_ids_empty"
        //     action = "noop → 4000 agent(s)"
        // and produce a durable denial row that mimics the SUCCESS format
        // (`reason=<r> <plugin>:<action>` vs `plugin:action → N agent(s)`).
        // Byte-shape safety is not field-structure safety. Validating the
        // input is also what bounds the row size and keeps the column
        // well-formed, which is three problems closed at one gate instead of
        // three sanitisers at three sinks.
        //
        // Charset matches what shipped content actually uses - every
        // `plugin`/`action` in content/definitions/*.yaml fits this, and
        // dotted server actions (`workflow.list`) are live content, so `.`
        // must stay legal. Length matches MCP's kExecInstrIdentMaxLen so the
        // two execute surfaces agree on what an identifier is. See the
        // anonymous-namespace `bad_ident` above for fix #7 (ASCII, not
        // locale-dependent `std::isalnum`).
        if (bad_ident(plugin) || bad_ident(action)) {
            res.status = 400;
            res.set_content(
                R"j({"error":{"code":400,"message":"plugin and action must be identifiers ([A-Za-z0-9_.-], max 128 bytes)"},"meta":{"api_version":"v1"}})j",
                "application/json");
            return;
        }

        // #2557 fix #3/#6: every audit_fn(...) call in this handler goes
        // through this wrapper, never `deps.audit_fn` directly. It counts
        // (and re-throws) a THROWING audit sink separately from a clean
        // `false` return — `rest_audit.hpp`'s `try_persist_audit` already
        // catches the rethrow and returns `false`/logs a warning, so the
        // response shape is unaffected; this only adds the ability to tell
        // "the sink threw" apart from "the sink cleanly declined" in
        // `yuzu_server_dispatch_fanout_throw_total`, which a plain `false`
        // return never distinguished before.
        // CPPX-3 (governance round 1): `raw` is a REFERENCE to `deps.audit_fn`,
        // not a copy — `deps` is a member of the OUTER persistent route
        // lambda (captured once at `sink.Post(...)` registration, alive for
        // the server's lifetime), and this inner wrapper never outlives a
        // single request's handler invocation, which is always shorter. A
        // by-value capture here copied the whole wrapped `std::function`
        // object on every request for no reason.
        const Deps::AuditFn audit_fn = [&raw = deps.audit_fn, metrics = deps.metrics](
                                           const httplib::Request& r, const std::string& action_,
                                           const std::string& result,
                                           const std::string& target_type,
                                           const std::string& target_id,
                                           const std::string& detail) -> bool {
            try {
                return raw ? raw(r, action_, result, target_type, target_id, detail) : true;
            } catch (...) {
                if (metrics) {
                    try {
                        metrics
                            ->counter("yuzu_server_dispatch_fanout_throw_total",
                                     {{"route", "command"},
                                      {"phase", result == "success" ? "success" : "denial"}})
                            .increment();
                    } catch (...) { // NOLINT(bugprone-empty-catch)
                    }
                }
                throw; // rest_audit.hpp's try_persist_audit still logs + returns false
            }
        };

        // All commands require Execution:Execute permission
        if (!deps.perm_fn(req, res, "Execution", "Execute"))
            return;

        // ── Targeting shape: supplied-but-names-nothing is an ERROR (#2500) ──
        // Run on the PARSED BODY, never on a separately re-parsed agent_ids
        // extraction (that second parse WAS the pre-extraction bug fixed
        // here as #2557 fix #8 — see the `agent_ids` derivation below, after
        // this check passes).
        //
        // Placed AFTER require_permission so a refusal is attributable to a
        // principal and can carry an audit row; before any dispatch-shaped work.
        // The `plugin`/`action` emptiness check above deliberately stays where it
        // is rather than being subsumed the way `ident_empty` subsumed MCP's: it
        // currently runs BEFORE require_permission, and moving an auth-adjacent
        // check is not something to do silently inside a targeting fix.
        // Parsed with allow_exceptions=false rather than a try/catch that falls
        // through. The earlier form set "named no target" in its catch and
        // CONTINUED, arguing the catch was unreachable because a body that does
        // not parse yields an empty `plugin`. That holds for parse errors — but
        // not for std::bad_alloc: under memory pressure a body of
        // {"agent_ids":[]} would have landed in the catch and proceeded to
        // broadcast. A fail-OPEN catch inside the fix for a widening defect
        // (governance, cpp-safety). A discarded value yields contains()==false
        // on every query below, so an unparseable body is refused here rather
        // than continuing with unknown targeting.
        const auto body = nlohmann::json::parse(req.body, nullptr, /*allow_exceptions=*/false);
        // `check_targeting_shape` requires an OBJECT: contains() is false for an
        // array or scalar, so `["dev-1"]` would read as "named no target" and
        // broadcast — the very shape this route is being fixed for. Three Gate-3
        // reviewers found this independently; the precondition is enforced here
        // and pinned by a route test, not left as a comment on the header.
        if (!body.is_object()) {
            // Counted and audited like every other refusal in this family.
            // The fold's own argument against an uncounted refusal applies
            // here: an invisible one cannot reach the alert this change
            // ships, and this is the shape three reviewers had to find by
            // reading rather than by watching a dashboard.
            //
            // Governance round 1 (UP-4a): this increment previously had NO
            // try/catch at all — a throw here (metrics-registry exhaustion,
            // an allocation failure inside Counter/MetricFamily) propagated
            // uncaught, skipping the `emit_behavioral_audit` call immediately
            // below entirely. `command_id` is not generated until AFTER
            // classification succeeds, well past this point, so the request
            // is identified by `plugin`/`action` instead.
            try {
                deps.metrics
                    ->counter("yuzu_server_dispatch_target_rejected_total",
                             {{"route", "command"}, {"reason", std::string(kReasonBodyType)}})
                    .increment();
            } catch (const std::exception& e) {
                spdlog::error("dispatch_target_rejected_total counter threw for {}:{} "
                             "(reason={}): {}",
                             plugin, action, kReasonBodyType, e.what());
            } catch (...) {
                spdlog::error("dispatch_target_rejected_total counter threw for {}:{} "
                             "(reason={})",
                             plugin, action, kReasonBodyType);
            }
            // #2557 fix #3/#6: emit_behavioral_audit (rest_audit.hpp) rather
            // than a raw AuditFn call + manual Sec-Audit-Failed header — the
            // helper sets that header itself on a persist failure, and the
            // local `audit_fn` wrapper above makes a THROWING sink
            // separately countable. The status stays 400 — the request WAS
            // invalid, and answering 503 because we could not record that
            // would trade a correct refusal for an outage.
            const bool audit_ok = yuzu::server::detail::emit_behavioral_audit(
                audit_fn, req, res, "command.dispatch", "denied", "command", "",
                std::string("reason=") + std::string(kReasonBodyType));
            res.status = 400;
            // `audit_emitted` is omitted entirely when no audit store is
            // configured: the AuditFn contract returns true in that case, so
            // reporting `true` would assert a row landed on a deployment
            // that keeps none. Absent means "no claim", not "false".
            nlohmann::json err{{"error",
                                {{"code", 400},
                                 {"message", "request body must be a JSON object"}}},
                               {"meta", {{"api_version", "v1"}}}};
            if (deps.audit_store_configured_fn())
                err["audit_emitted"] = audit_ok;
            res.set_content(err.dump(), "application/json");
            return;
        }
        if (auto bv = yuzu::server::check_targeting_shape(body)) {
            // Governance round 1 (UP-4a): same fix as the body-type counter
            // above — no try/catch meant a throw here skipped the audit call
            // below entirely. `command_id` does not exist yet at this point
            // either, so the log line identifies the request by
            // `plugin`/`action` instead.
            try {
                deps.metrics
                    ->counter("yuzu_server_dispatch_target_rejected_total",
                             {{"route", "command"}, {"reason", bv->reason}})
                    .increment();
            } catch (const std::exception& e) {
                spdlog::error("dispatch_target_rejected_total counter threw for {}:{} "
                             "(reason={}): {}",
                             plugin, action, bv->reason, e.what());
            } catch (...) {
                spdlog::error("dispatch_target_rejected_total counter threw for {}:{} "
                             "(reason={})",
                             plugin, action, bv->reason);
            }
            // The detail carries WHAT was being attempted, not just why it
            // was refused. The success row records `plugin:action -> N
            // agent(s)`; a denial that records only `reason=` lets an
            // auditor show that an operator was blocked but not what they
            // were trying to run — on a control whose whole purpose is
            // reconstructing near-miss blast radius (governance, compliance).
            // `plugin`/`action` are CALLER-SUPPLIED and this route bounds
            // neither length nor charset (unlike MCP's kExecInstrIdentMaxLen).
            // Concatenating them raw into an evidence field let a caller
            // forge a row that mimics the success format
            // (`plugin:action -> N agent(s)`) and write an arbitrarily large
            // durable row before any dispatch — turning the field this fold
            // added FOR blast-radius reconstruction into the thing an
            // attacker writes. Sanitised through the same helper the
            // on-behalf-of guard uses for untrusted log text: control chars
            // and CR/LF become '?', length capped (governance, security).
            const bool audit_ok = yuzu::server::detail::emit_behavioral_audit(
                audit_fn, req, res, "command.dispatch", "denied", "command", "",
                std::string("reason=") + bv->reason + " " +
                    onbehalf::sanitize_for_log(plugin, 128) + ":" +
                    onbehalf::sanitize_for_log(action, 128));
            res.status = 400;
            nlohmann::json err{{"error", {{"code", 400}, {"message", bv->message}}},
                               {"meta", {{"api_version", "v1"}}}};
            if (deps.audit_store_configured_fn())
                err["audit_emitted"] = audit_ok;
            res.set_content(err.dump(), "application/json");
            return;
        }
        const bool named_target = yuzu::server::targeting_supplied(body);

        // #2557 fix #8 (targeting erasure): `agent_ids` is read straight off
        // THIS validated `body` object, never from a second, independent
        // `nlohmann::json::parse` of the same raw bytes. The pre-extraction
        // code parsed `req.body` a second time here (via
        // `extract_json_string_array`), before `check_targeting_shape` ran
        // on the FIRST parse — that helper swallows every parse exception
        // and collapses to `{}` on failure, so a transient `std::bad_alloc`
        // on the SECOND parse could silently erase a caller's non-empty
        // `agent_ids` list to empty AFTER the first parse's validation had
        // already confirmed a real, non-empty list was present. That
        // mismatch — validated non-empty, then silently re-read as empty —
        // is exactly what let a named-device dispatch fall through to a
        // fleet-wide broadcast (#2500). `check_targeting_shape` returning no
        // violation guarantees `agent_ids`, if present, is a non-empty array
        // whose every element `is_string()` — so `.get<std::string>()` below
        // cannot throw.
        std::vector<std::string> agent_ids;
        if (body.contains("agent_ids"))
            for (const auto& v : body["agent_ids"])
                agent_ids.push_back(v.get<std::string>());

        // Resolved ONCE for the whole handler (was resolved a second time,
        // redundantly, inside the destructive-action block below, and a
        // third time implicitly via derive_exec_visible's need for a
        // Session — PR1.9c consolidates to the one call every other path
        // in this file already treats as the rule: "require_auth writes an
        // error response on failure, so calling it twice could emit two"
        // (forward_legacy_command's own comment, server.cpp). Placed AFTER
        // require_permission(Execution,Execute) so a bare-unauthenticated
        // caller was already turned away by that coarser gate first.
        auto sess = deps.auth_fn(req, res);
        if (!sess)
            return; // auth_fn already wrote the response

        // Per-action securable elevation + scope confinement for DESTRUCTIVE
        // generic-dispatch actions (governance HIGH #2). /api/command otherwise
        // base-gates only Execution:Execute and applies NO per-device visibility to
        // explicit agent_ids — a systemic property of this escape hatch tracked
        // separately (Tr3kkR/Yuzu#1788). An irreversible action (e.g.
        // tar.purge_source) must NOT inherit that: require its real securable AND
        // confine the targets to the operator's visible agents, refusing untargeted
        // broadcast/scope fan-out. The dedicated POST /api/v1/tar/retention-paused/
        // purge is the first-class structured surface; this keeps the generic path
        // from being a weaker one on AUTHZ.
        //
        // #3685: routed through the pure `evaluate_destructive_targeting` /
        // `confine_destructive_targets` (`dispatch_destructive_gate.hpp`).
        // `ClassifyMiss` is an explicit switch arm (Policy B: fall through to
        // `build_classified_command`, which denies a real miss unconditionally
        // with its own taxonomy/metric/audit shape).
        {
            const auto gate = yuzu::server::evaluate_destructive_targeting(
                deps.capability_registry->classify(plugin, action),
                /*valid_nonempty_agent_ids=*/!agent_ids.empty(),
                /*scope_key_present=*/!extract_json_string(body, "scope").empty(),
                /*agent_id_count=*/agent_ids.size());
            switch (gate.verdict) {
            case yuzu::server::DestructiveTargetingVerdict::NotDestructive:
                break;
            case yuzu::server::DestructiveTargetingVerdict::ClassifyMiss:
                // Policy B (#3685 decision, revised after external review):
                // explicit fall-through, not a new denial site. The SAME
                // registry/classifier `build_classified_command` consults
                // below denies a real miss unconditionally with its own
                // taxonomy/metric/audit shape — an independent early denial
                // here would only duplicate, and risk drifting from, that
                // evidence.
                break;
            case yuzu::server::DestructiveTargetingVerdict::Targeted:
            case yuzu::server::DestructiveTargetingVerdict::RefuseUntargeted: {
                const auto& cap = *gate.capability;
                // Elevation FIRST — preserves the pre-#3685 403-before-400
                // ordering.
                if (!deps.perm_fn(req, res, std::string(cap.securable),
                                 std::string(yuzu::server::authz::to_string(cap.operation))))
                    return;
                if (gate.verdict == yuzu::server::DestructiveTargetingVerdict::RefuseUntargeted) {
                    // #3685: counted like every other refusal in this
                    // family (#2500 precedent above) — an uncounted
                    // refusal on a P1 security control cannot reach the
                    // dashboard/alert this observability commit ships.
                    try {
                        deps.metrics
                            ->counter("yuzu_server_dispatch_target_rejected_total",
                                     {{"route", "command"},
                                      {"reason", std::string(gate.refusal_reason)}})
                            .increment();
                    } catch (const std::exception& e) {
                        // Governance round 1 (UP-4b): every empty catch in
                        // this file except this pre-existing one and its
                        // DestructiveNoVisibleTarget sibling below already
                        // logs — this one silently swallowed.
                        spdlog::error("dispatch_target_rejected_total counter threw for {}:{} "
                                     "(reason={}): {}",
                                     plugin, action, gate.refusal_reason, e.what());
                    } catch (...) {
                        spdlog::error("dispatch_target_rejected_total counter threw for {}:{} "
                                     "(reason={})",
                                     plugin, action, gate.refusal_reason);
                    }
                    // #3685 fix round (adversarial review F2): audited like
                    // the check_targeting_shape refusal above in this same
                    // function — an incident review of a near-miss
                    // broadcast-Destructive attempt must find a row here,
                    // not just a counter increment. Wave 7 PR7.2: the same
                    // audit shape now also covers a broadcast/fan-out
                    // Forensics refusal (reason=forensic_untargeted).
                    const bool audit_ok = yuzu::server::detail::emit_behavioral_audit(
                        audit_fn, req, res, "command.dispatch", "denied", "command", "",
                        std::string("reason=") + std::string(gate.refusal_reason) + " " +
                            onbehalf::sanitize_for_log(plugin, 128) + ":" +
                            onbehalf::sanitize_for_log(action, 128));
                    res.status = 400;
                    nlohmann::json err{
                        {"error",
                         {{"code", 400}, {"message", std::string(gate.refusal_message)}}},
                        {"meta", {{"api_version", "v1"}}}};
                    if (deps.audit_store_configured_fn())
                        err["audit_emitted"] = audit_ok;
                    res.set_content(err.dump(), "application/json");
                    return;
                }
                // Confine to the operator's visible agents (fail-closed: an
                // absent or degraded mgmt-group read → empty → 404, same
                // posture as the dashboard fragment). Out-of-scope ids are
                // silently dropped. `DestructiveVisibleAgents`'s nullopt
                // means fail-closed-empty — the OPPOSITE of
                // `authz::VisibleSet`'s nullopt (unfiltered) — see that
                // type's doc comment (`dispatch_destructive_gate.hpp`).
                std::optional<std::vector<std::string>> vis;
                if (deps.mgmt_group_store)
                    vis = deps.mgmt_group_store->get_visible_agents(
                        sess->username); // ADR-0042: nullopt (degraded) → fail-closed
                agent_ids = yuzu::server::confine_destructive_targets(
                    agent_ids, yuzu::server::DestructiveVisibleAgents{std::move(vis)});
                if (agent_ids.empty()) {
                    // #2557 fix #5: this arm previously answered 404 with NO
                    // metric increment and NO audit row — an incident review
                    // of "dispatch a Destructive action at devices the
                    // operator cannot see" found nothing at all. Mirrors the
                    // RefuseUntargeted arm immediately above, byte-for-byte,
                    // except the reason/status/message: a non-empty
                    // `agent_ids` list WAS explicitly supplied here (this is
                    // NOT `kReasonDestructiveUntargeted`'s "named nothing at
                    // all") — every named id simply fell outside the
                    // caller's visible-agent confinement.
                    try {
                        deps.metrics
                            ->counter(
                                "yuzu_server_dispatch_target_rejected_total",
                                {{"route", "command"},
                                 {"reason",
                                  std::string(
                                      yuzu::server::kReasonDestructiveNoVisibleTarget)}})
                            .increment();
                    } catch (const std::exception& e) {
                        // Governance round 1 (UP-4c): same fix as the
                        // RefuseUntargeted sibling above.
                        spdlog::error("dispatch_target_rejected_total counter threw for {}:{} "
                                     "(reason=destructive_no_visible_target): {}",
                                     plugin, action, e.what());
                    } catch (...) {
                        spdlog::error("dispatch_target_rejected_total counter threw for {}:{} "
                                     "(reason=destructive_no_visible_target)",
                                     plugin, action);
                    }
                    const bool audit_ok = yuzu::server::detail::emit_behavioral_audit(
                        audit_fn, req, res, "command.dispatch", "denied", "command", "",
                        std::string("reason=") +
                            std::string(yuzu::server::kReasonDestructiveNoVisibleTarget) + " " +
                            onbehalf::sanitize_for_log(plugin, 128) + ":" +
                            onbehalf::sanitize_for_log(action, 128));
                    res.status = 404;
                    nlohmann::json err{
                        {"error",
                         {{"code", 404},
                          {"message",
                           std::string(yuzu::server::kDestructiveNoVisibleAgentMessage)}}},
                        {"meta", {{"api_version", "v1"}}}};
                    if (deps.audit_store_configured_fn())
                        err["audit_emitted"] = audit_ok;
                    res.set_content(err.dump(), "application/json");
                    return;
                }
                break;
            }
            }
        }

        // ── #1788: per-device visibility on EVERY dispatch arm ──────────────
        // Everything above gates a possibly-GLOBAL Execution:Execute (or the
        // destructive-action securable) and, for the destructive list only,
        // narrows `agent_ids` to a coarser ManagementGroupStore visibility.
        // Nothing narrowed the actual send set on ANY of the four dispatch
        // arms below (explicit agent_ids, broadcast, Group, Scope) to the
        // operator's own Execution:Execute visibility. Derive ONE
        // permission-specific visible set here and intersect every arm
        // against it before send_to.
        //
        // D3: the no-agent 503 short-circuit sits BEFORE deriving
        // exec_visible — that derivation runs an RBAC/tag-store lookup
        // that is wasted work on the (common, cheap-to-detect) no-agent
        // path, which never reaches a dispatch decision anyway.
        //
        // HA WS-5 governance hardening (external review finding, 2026-09-22):
        // has_any() alone is LOCAL-ONLY — on a replica holding zero local
        // sessions but a healthy presence-visible fleet (the ordinary HA
        // topology this slice exists to support), the plain check rejected
        // EVERY dispatch here before all_ids()/evaluate_scope() or any
        // presence lookup ever ran. has_any_reachable() checks presence too.
        if (!deps.registry->has_any_reachable()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"no agent connected"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        // PLAN-006: the caller's IDENTITY, not merely their visibility
        // filter — `caller.exec_visible` is byte-identical to the
        // `exec_visible` this handler derived directly before PR1.9c, kept
        // as a reference alias so every arm-dispatch use of `exec_visible`
        // below is unchanged.
        const auto caller = deps.derive_dispatch_caller_fn(*sess);
        const auto& exec_visible = caller.exec_visible;

        auto command_id =
            plugin + "-" + auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(8));

        // Parameters: pass-through key-value pairs to the agent plugin.
        auto parameters = extract_json_string_map(body, "params");

        // Stagger/delay: prevent thundering herd on large-fleet dispatch.
        auto stagger = extract_json_int(body, "stagger", 0);
        auto delay = extract_json_int(body, "delay", 0);

        // Check for scope-based targeting. Reuses the parsed body like the
        // other post-auth reads. Computed here because PR1.9c's builder
        // needs `arm` for its plan-hash `target_arm` before any dispatch
        // decision is made.
        auto scope_expr = extract_json_string(body, "scope");
        const auto arm = yuzu::server::classify_dispatch_arm(!agent_ids.empty(), scope_expr);

        // PR1.9c (spec item 1): the ONE builder — the only place a
        // `detail::pb::CommandRequest` is constructed. A denial (unknown/
        // ambiguous plugin.action, or `caller` not authorized for the
        // resolved securable/operation) is answered here — unlike the
        // background dispatch seams, this route has a `res` to write to.
        // Already counted (`yuzu_server_dispatch_denied_total{reason=}`)
        // and logged by build_classified_command; this block only shapes
        // the HTTP response and the route-local audit row.
        auto classified = deps.build_classified_command_fn(
            caller, plugin, action, command_id, parameters, /*payload=*/{}, stagger, delay,
            std::string(yuzu::server::dispatch_arm_label(arm)), /*execution_id=*/{});
        if (!classified) {
            const auto& denial = classified.error();
            const bool is_classification_error =
                denial.reason == yuzu::server::detail::DispatchDenialReason::Unclassified ||
                denial.reason == yuzu::server::detail::DispatchDenialReason::Ambiguous;
            // #1398: a gated-but-unapproved pair gets its own message,
            // naming the gate and pointing at the governed alternative —
            // distinct from a bare RBAC "permission denied" (Decision 7,
            // deny+redirect, no new ticket-mint surface on this route).
            const bool is_approval_required =
                denial.reason == yuzu::server::detail::DispatchDenialReason::ApprovalRequired;
            const int status = is_classification_error ? 400 : 403;
            const std::string message =
                is_classification_error
                    ? std::string{"unknown or ambiguous plugin.action"}
                    : is_approval_required
                          ? "approval required for " + plugin + "." + action +
                                " — this action requires either an admin caller or an "
                                "approved request; dispatch it via "
                                "POST /api/instructions/{id}/execute instead, which "
                                "supports the approval workflow"
                          : "permission denied: " + denial.securable + ":" +
                                std::string(yuzu::server::authz::to_string(denial.operation));
            // #1398 (governance security-guardian F3): the SPECIFIC denial
            // reason, not a flat "dispatch_denied" — an incident review
            // needs to tell `forbidden` apart from `approval_required`
            // from the audit trail alone, the same way the metric label
            // already does.
            const bool audit_ok = yuzu::server::detail::emit_behavioral_audit(
                audit_fn, req, res, "command.dispatch", "denied", "command", "",
                std::string("reason=") +
                    std::string(yuzu::server::detail::to_string(denial.reason)) + " " +
                    onbehalf::sanitize_for_log(plugin, 128) + ":" +
                    onbehalf::sanitize_for_log(action, 128));
            res.status = status;
            nlohmann::json err{{"error", {{"code", status}, {"message", message}}},
                               {"meta", {{"api_version", "v1"}}}};
            if (deps.audit_store_configured_fn())
                err["audit_emitted"] = audit_ok;
            res.set_content(err.dump(), "application/json");
            return;
        }

        // #2557 fix #2/#4 (send-time leak): `record_send_time_fn` below
        // inserts an entry keyed on `command_id` into
        // `AgentServiceImpl::cmd_send_times_`, which is normally erased when
        // a LATER agent response for this exact command_id arrives. A
        // dispatch that reaches zero agents (sent == 0) or that throws
        // before any response can ever arrive leaves that entry behind
        // forever — nothing else ever revisits it. `sent` is declared and
        // the guard constructed HERE, immediately BEFORE the one
        // unconditional `record_send_time_fn` call.
        //
        // Governance round 1 (SAFE-1/UP-2): an earlier revision constructed
        // the guard AFTER this call, reasoning it only needed to cover what
        // came below. That left a window where a throw INSIDE
        // `record_send_time_fn` itself — including its own internal
        // `AgentServiceImpl::publish_send_times_gauge_locked` step — would
        // already have inserted the `cmd_send_times_` entry with no guard
        // yet in scope to clean it up: an uncaught 500 for an
        // already-classified/authorized command, AND a permanently leaked
        // entry. Constructing the guard FIRST means every exit from this
        // point on — a throw inside `record_send_time_fn` itself, the
        // containment-gate store read, the registry plugin-presence query,
        // the confined-dispatch sink, and the ordinary sent==0 -> 503 path
        // far below — is covered by the SAME mechanism.
        // `AgentServiceImpl::discard_send_time`'s own find()-on-a-
        // not-yet-inserted-key path is a safe no-op (returns `false`, and
        // throws only on a mutex-lock failure, which the guard's own
        // `catch` below already absorbs), so constructing the guard before
        // the entry exists is not itself a hazard.
        int sent = 0;
        struct SendTimeGuard {
            const Deps::DiscardSendTimeFn& discard;
            const std::string& command_id;
            const int& sent;
            ~SendTimeGuard() {
                if (sent > 0)
                    return;
                try {
                    (void)discard(command_id);
                } catch (const std::exception& e) {
                    // SAFE-4 (governance round 1): every other guarded()
                    // catch site in this file logs at ERROR — this one used
                    // to swallow silently, the one asymmetry in the file.
                    spdlog::error("discard_send_time threw for command {}: {}", command_id,
                                 e.what());
                } catch (...) {
                    spdlog::error("discard_send_time threw for command {}", command_id);
                }
            }
        } send_time_guard{deps.discard_send_time_fn, command_id, sent};

        deps.record_send_time_fn(command_id);

        // #881: the ONE store read for this whole request (never per
        // arm, never per agent) — computed once here, AFTER every early
        // return above (no-agent 503, classification 403/400), so a
        // request that will be refused for an unrelated reason does not
        // also cost a Postgres round trip. Still shared by all four arm
        // branches below.
        const auto containment_gate = deps.make_containment_gate_fn(plugin, action);
        // #3424/#3511: same lifecycle as containment_gate — one registry
        // read for the whole request, shared by every arm branch below.
        // BR-009: `classified->wire().plugin()`, NOT the raw `plugin`
        // local — `classify()` is case-insensitive and
        // `finalize_classified_command` builds the wire command from the
        // catalogue-resolved spelling, so a caller who dispatches with
        // valid-but-non-canonical casing (e.g. "TAR") must be checked
        // against the SAME spelling every agent's self-reported inventory
        // uses, or every agent that genuinely has the plugin is spuriously
        // flagged absent.
        const auto plugin_missing = deps.registry->ids_missing_plugin(classified->wire().plugin());

        // #881: filled by whichever arm branch below actually ran, then
        // audited once — BEFORE the sent==0 -> 503 branch further down —
        // so a deliberate policy denial correlates with the transport
        // error it is knowingly reported as.
        std::vector<std::string> denied_quarantined;
        // Separate from the vector: under fail-closed the ids are
        // deliberately not collected (a fleet-sized allocation on the
        // dispatch thread, per refused dispatch), so .size() is not the
        // denial count. See ArmDispatchResult.
        std::size_t denied_quarantined_count = 0;
        // #3511: mirrors denied_quarantined_count for the plugin-presence
        // filter — see ArmDispatchResult::unknown_plugin_count.
        std::size_t unknown_plugin_count = 0;
        // WS-4 4.2b Task D: mirrors the two counts above — ArmDispatchResult
        // has no aggregation of its own (each arm branch below runs the walk
        // once), so this is simply whatever the arm that ran reported.
        bool route_unreadable = false;
        // `__all__` is the PUBLISHED ground scope kind, handled here as "no
        // scope expression" so the ordering matches the shared closure and
        // the MCP one exactly: an explicit agent_ids list still wins.
        // #1788: the injected sink shared with `ServerImpl::dispatch_confined`
        // (dispatch_confined_arms.hpp / A-3's make_confined_dispatch_sink).
        // This route keeps its own target resolution, audit rows and HTTP
        // shaping — which is why it is not simply absorbed by that seam —
        // but the DECISION OF WHO IS REACHED is the shared one, so the two
        // can no longer drift.
        const auto confined_sink = deps.make_confined_dispatch_sink_fn(*classified);
        const auto dispatch_broadcast = [&]() -> yuzu::server::ArmDispatchResult {
            return yuzu::server::dispatch_confined_arms(
                yuzu::server::DispatchArm::Broadcast, {}, exec_visible,
                /*broadcast_on_none=*/true, containment_gate, confined_sink, plugin_missing);
        };

        if (arm == yuzu::server::DispatchArm::Group) {
            // Group-based dispatch — resolve group members here, then let the
            // shared seam intersect (#1788): a management group is a targeting
            // mechanism, not an authz exemption from it.
            auto group_id = scope_expr.substr(6);
            std::vector<std::string> members;
            if (deps.mgmt_group_store)
                for (const auto& m : deps.mgmt_group_store->get_members(group_id))
                    members.push_back(m.agent_id);
            yuzu::server::ConfinedDispatchTargets t;
            t.group_members = &members;
            const auto result = yuzu::server::dispatch_confined_arms(
                arm, t, exec_visible, /*broadcast_on_none=*/true, containment_gate, confined_sink,
                plugin_missing);
            sent = result.sent;
            denied_quarantined = result.denied_quarantined;
            denied_quarantined_count = result.denied_quarantined_count;
            unknown_plugin_count = result.unknown_plugin_count;
            route_unreadable = result.route_unreadable;
        } else if (arm == yuzu::server::DispatchArm::Scope) {
            // Scope expression dispatch.
            //
            // #2557 fix #1 (stale re-auth): this arm used to call
            // `require_auth`/`deps.auth_fn` a SECOND time here, purely to
            // re-derive the exact same session's username/role that
            // `caller` (derived once, above) already carries — the very
            // pattern this file's own comment on `sess`'s single
            // resolution warns against ("require_auth writes an error
            // response on failure, so calling it twice could emit two").
            // `caller.principal`/`caller.principal_role` are
            // byte-identical to what that second call would have
            // produced: both derive from the same `*sess`. No return
            // guard is added — there is nothing left to guard once the
            // redundant call is gone.
            const std::string& principal = caller.principal;
            const std::string& principal_role = caller.principal_role;
            // A-3: the ladder itself (alias resolution -> owner-check gate
            // -> parse -> registry evaluation, each step fail-closed per
            // ADR-0036) is shared via `resolve_scope_targets`
            // (dispatch_scope_ladder.hpp). A DB error or failed owner check
            // at any step ABORTS (nullopt), `sent` stays 0, and the shared
            // "sent == 0 -> 503" fallback below fires. This route ALONE
            // reacts to a parse failure with its own 400 (no `res` to write
            // to on the dispatch_confined side), which is why it is not
            // simply absorbed by that seam.
            yuzu::server::ScopeLadderAudit audit;
            audit.resolution_failed = [&deps, &principal, &principal_role,
                                       &command_id](const std::string& ref) {
                deps.audit_scope_resolution_failed_fn(principal, principal_role, command_id, ref);
            };
            audit.evaluation_aborted = [&deps, &principal, &principal_role,
                                        &command_id](const std::string& reason) {
                deps.audit_scope_evaluation_aborted_fn(principal, principal_role, command_id,
                                                       reason);
            };
            auto ladder = yuzu::server::resolve_scope_targets(
                scope_expr, principal, deps.result_set_store,
                [&deps, &principal](const yuzu::scope::Expression& parsed) {
                    return deps.registry->evaluate_scope(parsed, deps.tag_store,
                                                         deps.custom_properties_store,
                                                         deps.result_set_store, principal);
                },
                audit);
            if (ladder.parse_error) {
                res.status = 400;
                res.set_content(
                    nlohmann::json({{"error", "invalid scope: " + *ladder.parse_error}}).dump(),
                    "application/json");
                return;
            }
            if (ladder.matched) {
                // #1788: a scope match is a targeting mechanism, not an
                // authz exemption — the shared seam intersects it against
                // the operator's Execution:Execute visible set before
                // dispatch.
                yuzu::server::ConfinedDispatchTargets t;
                t.scope_matched = &*ladder.matched;
                const auto result = yuzu::server::dispatch_confined_arms(
                    arm, t, exec_visible, /*broadcast_on_none=*/true, containment_gate,
                    confined_sink, plugin_missing);
                sent = result.sent;
                denied_quarantined = result.denied_quarantined;
                denied_quarantined_count = result.denied_quarantined_count;
                unknown_plugin_count = result.unknown_plugin_count;
                route_unreadable = result.route_unreadable;
            }
            // else: the ladder already audited the abort (db_degraded /
            // owner_check_failed / principal_unresolved) — sent stays 0.
        } else if (arm == yuzu::server::DispatchArm::Ids) {
            // #1788: an explicit id list is the arm #1788 named directly —
            // the shared seam intersects it against the operator's
            // Execution:Execute visible set before dispatch; a hidden id is
            // silently dropped, not an error.
            yuzu::server::ConfinedDispatchTargets t;
            t.agent_ids = &agent_ids;
            const auto result = yuzu::server::dispatch_confined_arms(
                arm, t, exec_visible, /*broadcast_on_none=*/true, containment_gate, confined_sink,
                plugin_missing);
            sent = result.sent;
            denied_quarantined = result.denied_quarantined;
            denied_quarantined_count = result.denied_quarantined_count;
            unknown_plugin_count = result.unknown_plugin_count;
            route_unreadable = result.route_unreadable;
        } else if (arm == yuzu::server::DispatchArm::Broadcast) {
            // Explicitly asked for the fleet by its published name — #1788
            // still narrows delivery to the operator's visible set; the
            // NAME `__all__` is preserved (never rejected, never reread as
            // "no target"), only the SEND SET composes with visibility.
            const auto result = dispatch_broadcast();
            sent = result.sent;
            denied_quarantined = result.denied_quarantined;
            denied_quarantined_count = result.denied_quarantined_count;
            unknown_plugin_count = result.unknown_plugin_count;
            route_unreadable = result.route_unreadable;
        } else {
            // Broadcast ONLY when the caller named no target at all (#2500).
            // The shape check above already refuses a supplied-but-empty
            // body, so this branch is second line of defence, not the fix.
            if (named_target) {
                // Derive the label from which field was actually supplied,
                // as the MCP sink does. Hardcoding `agent_ids_empty` would
                // mislabel a `scope`-only violation if this arm ever became
                // reachable, and a wrong reason on a fleet-safety refusal is
                // worse than no reason.
                const auto sink_reason = body.contains("agent_ids")
                                             ? yuzu::server::kReasonAgentIdsEmpty
                                             : yuzu::server::kReasonScopeEmpty;
                // Governance round 1 (UP-4a): same fix as the two counters
                // above — no try/catch meant a throw here skipped the audit
                // call below entirely. `command_id` IS in scope by this
                // point (generated above, before the arm dispatch), so it is
                // included here even though the audit row below deliberately
                // omits it (see that call's own comment).
                try {
                    deps.metrics
                        ->counter("yuzu_server_dispatch_target_rejected_total",
                                 {{"route", "command"}, {"reason", std::string(sink_reason)}})
                        .increment();
                } catch (const std::exception& e) {
                    spdlog::error("dispatch_target_rejected_total counter threw for command {} "
                                 "({}:{}, reason={}): {}",
                                 command_id, plugin, action, sink_reason, e.what());
                } catch (...) {
                    spdlog::error("dispatch_target_rejected_total counter threw for command {} "
                                 "({}:{}, reason={})",
                                 command_id, plugin, action, sink_reason);
                }
                // Empty target_id, matching the source-side denial above: the
                // same verb must not carry two different target shapes, and a
                // command_id for a command that was never dispatched reads in
                // the audit trail as though one was.
                const bool audit_ok = yuzu::server::detail::emit_behavioral_audit(
                    audit_fn, req, res, "command.dispatch", "denied", "command", "",
                    "reason=" + std::string(sink_reason) + " " +
                        onbehalf::sanitize_for_log(plugin, 128) + ":" +
                        onbehalf::sanitize_for_log(action, 128));
                res.status = 400;
                nlohmann::json err{
                    {"error",
                     {{"code", 400},
                      {"message", "a targeting argument was supplied but resolved to no "
                                  "target; omit it entirely to target all agents"}}},
                    {"meta", {{"api_version", "v1"}}}};
                if (deps.audit_store_configured_fn())
                    err["audit_emitted"] = audit_ok;
                res.set_content(err.dump(), "application/json");
                return;
            }
            // #1788: an omitted target means "the whole fleet" (#2500) —
            // still narrowed to the operator's visible set, same as the
            // named Broadcast arm above.
            const auto result = dispatch_broadcast();
            sent = result.sent;
            denied_quarantined = result.denied_quarantined;
            denied_quarantined_count = result.denied_quarantined_count;
            // #3511: this arm (the omitted-target -> whole-fleet default,
            // #2500) needs this copy too, or a plugin-absence withholding on
            // THIS arm silently falls through to the generic "failed to send
            // command to any agent" 503 instead of the specific
            // `plugin_not_found` one below.
            unknown_plugin_count = result.unknown_plugin_count;
            route_unreadable = result.route_unreadable;
        }

        // #881: emitted BEFORE the sent==0 -> 503 branch below, so a
        // deliberate quarantine denial is correlated with the transport
        // error it is knowingly reported as. Fail-closed denies every
        // connected agent, so it gets ONE aggregate row rather than N.
        //
        // #2557 fix #3/#6: each of these four post-dispatch side effects is
        // wrapped INDIVIDUALLY in `guarded()` — a throw from one must not
        // skip the others, and none of them may turn an already-successful
        // dispatch into an uncaught-exception 500.
        if (containment_gate.fail_closed) {
            guarded(command_id, "audit_quarantine_dispatch_fail_closed", deps.metrics, [&] {
                deps.audit_quarantine_dispatch_fail_closed_fn(
                    "command", caller.principal, caller.principal_role, command_id,
                    denied_quarantined_count);
            });
        } else {
            guarded(command_id, "audit_quarantine_dispatch_denied_batch", deps.metrics, [&] {
                deps.audit_quarantine_dispatch_denied_batch_fn(
                    "command", caller.principal, caller.principal_role, command_id,
                    denied_quarantined);
            });
        }
        guarded(command_id, "audit_unknown_plugin_dispatch", deps.metrics, [&] {
            deps.audit_unknown_plugin_dispatch_fn("command", caller.principal,
                                                  caller.principal_role, command_id, plugin,
                                                  unknown_plugin_count);
        });

        // Forward commands queued for gateway agents
        guarded(command_id, "forward_gateway_pending", deps.metrics,
               [&] { deps.forward_gateway_pending_fn(); });

        if (sent == 0) {
            // #881/#3511: say WHICH kind of nothing. All five of these answered
            // "failed to send command to any agent", which reads as an
            // agent-connectivity outage — so a fail-closed containment
            // gate, which denies EVERY agent on EVERY dispatch fleet-wide,
            // sent an operator diagnosing a transport problem while the
            // real cause (the quarantine store is unreadable) appeared
            // only in an audit row and a metric. ADR-0033 §2 names that
            // shape — a silent deny-all reported as an empty fleet —
            // as a gate violation.
            res.status = 503;
            if (containment_gate.fail_closed) {
                res.set_content(
                    R"({"error":{"code":503,"message":"containment state is unreadable — dispatch is failing closed and reaching no agent; check the quarantine store","reason":"containment_unreadable","retry_after_ms":5000},"meta":{"api_version":"v1"}})",
                    "application/json");
            } else if (route_unreadable) {
                // WS-4 4.2b Task D: the exact sibling of the containment
                // branch above — a degraded read of the gateway routing
                // directory (not a per-target fact), so this must not be
                // reported as the generic connectivity catch-all below.
                // Checked right after containment_unreadable, same
                // "gate/directory itself could not answer" tier.
                res.set_content(
                    R"({"error":{"code":503,"message":"the gateway routing directory could not be read for one or more targets — dispatch is failing closed rather than guessing where to route","reason":"route_unreadable","retry_after_ms":5000},"meta":{"api_version":"v1"}})",
                    "application/json");
            } else if (denied_quarantined_count > 0) {
                res.set_content(
                    R"({"error":{"code":503,"message":"every target is quarantined — dispatch was withheld, not attempted","reason":"quarantined","retry_after_ms":null},"meta":{"api_version":"v1"}})",
                    "application/json");
            } else if (unknown_plugin_count > 0) {
                // #3511: the dispatched plugin is absent from every target's
                // reported inventory — a command guaranteed to fail, withheld
                // before dispatch rather than reported as a false success.
                res.set_content(
                    R"({"error":{"code":503,"message":"the dispatched plugin is not in any target's reported inventory — dispatch was withheld, not attempted","reason":"plugin_not_found","retry_after_ms":null},"meta":{"api_version":"v1"}})",
                    "application/json");
            } else {
                res.set_content(
                    R"({"error":{"code":503,"message":"failed to send command to any agent"},"meta":{"api_version":"v1"}})",
                    "application/json");
            }
            return;
        }

        deps.metrics->counter("yuzu_commands_dispatched_total").increment();
        guarded(command_id, "publish(command-status)", deps.metrics, [&] {
            deps.publish_fn("command-status",
                            "<span id=\"status-badge\" class=\"badge-running\""
                            " hx-swap-oob=\"outerHTML\">RUNNING</span>");
        });
        spdlog::info("Command dispatched: {}:{} → {} agent(s)", plugin, action, sent);
        // #2557 fix #3/#6: the success path is audited through the SAME
        // `emit_behavioral_audit` + local `audit_fn` wrapper as every denial
        // arm above — previously this was a bare, discarded `(void)audit_log(
        // ...)` call with no exception safety and no `audit_emitted` field on
        // the success response, unlike every denial arm's response.
        const bool audit_ok = yuzu::server::detail::emit_behavioral_audit(
            audit_fn, req, res, "command.dispatch", "success", "command", command_id,
            plugin + ":" + action + " → " + std::to_string(sent) + " agent(s)");
        guarded(command_id, "emit_event(command.dispatched)", deps.metrics, [&] {
            deps.emit_event_fn("command.dispatched", req, {{"target_count", sent}},
                               {{"plugin", plugin},
                                {"action", action},
                                {"command_id", command_id},
                                {"scope", scope_expr}});
        });
        // #3424/#3511 (governance Gate 4 finding, independently raised by
        // consistency-auditor and unhappy-path): a MIXED partial dispatch
        // -- some reached, some withheld for plugin absence -- must be as
        // visible as a mixed quarantine withholding already is.
        std::string toast_suffix;
        if (denied_quarantined_count > 0)
            toast_suffix +=
                "; " + std::to_string(denied_quarantined_count) + " withheld (quarantined)";
        if (unknown_plugin_count > 0)
            toast_suffix += "; " + std::to_string(unknown_plugin_count) +
                            " withheld (plugin not found)";
        res.set_header("HX-Trigger", "{\"showToast\":{\"message\":\"Command sent to " +
                                         std::to_string(sent) + " agent(s)" + toast_suffix +
                                         "\",\"level\":\"success\"}}");
        // #2557 fix #3/#6: a throwing `thead_for_plugin_fn` degrades to an
        // empty string (cosmetic rendering only) rather than aborting an
        // otherwise-successful response.
        std::string thead_html;
        guarded(command_id, "thead_for_plugin", deps.metrics,
               [&] { thead_html = deps.thead_for_plugin_fn(plugin); });
        // #881: a PARTIAL dispatch must say so. Without this an operator
        // targeting a 100-device group with 3 contained devices reads
        // "Command sent to 97 agent(s)" and has no signal that 3 were
        // deliberately withheld — the count alone is indistinguishable
        // from three devices being offline. Always present (0 on a clean
        // dispatch) rather than conditionally added, so a client can read
        // the field unconditionally.
        nlohmann::json resp_body({{"status", "sent"},
                                  {"command_id", command_id},
                                  {"agents_reached", sent},
                                  {"withheld_quarantined", denied_quarantined_count},
                                  {"withheld_unknown_plugin", unknown_plugin_count},
                                  {"thead_html", thead_html}});
        // #2557 fix #6: `audit_emitted` on the SUCCESS response too, matching
        // every denial arm's convention — previously only the denial arms
        // carried this field, so a caller could not tell a throwing/failing
        // audit sink apart from a clean one on the one response shape most
        // likely to be read as "everything is fine".
        if (deps.audit_store_configured_fn())
            resp_body["audit_emitted"] = audit_ok;
        res.set_content(resp_body.dump(), "application/json");
    });
}

} // namespace yuzu::server::command
