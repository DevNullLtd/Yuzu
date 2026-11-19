/// @file policy_admin_routes.cpp
/// Policy/fragment mutator + dispatch route registration. Moved verbatim out
/// of `compliance_routes.cpp` by ADR-0031 WS-A4 Task B — see
/// policy_admin_routes.hpp's file banner for why this stays outside the
/// compliance family's seam-closure enforcement (no public REST/MCP twin).

#include "policy_admin_routes.hpp"

#include "dispatch_target_shape.hpp" // check_targeting_shape (#2500)
#include "policy_evaluator.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_error (the refusal 409)
#include "store_errors.hpp"
#include "web_utils.hpp" // audit_token

#include <nlohmann/json.hpp>
#include <cstdint>

#include <string>
#include <vector>

namespace yuzu::server {

namespace {

// Detail for the policy.create audit row: the targeting AS STORED, so what a
// policy actually acts on can be reconstructed after the fact (CC6.1/CC6.3;
// #2123 governance G6-CO-1 — an empty detail is why silently-broadened scopes
// left no trace). Read back from the store, not re-derived from the request, so
// it records what evaluation will use. Every caller-influenced value goes
// through audit_token (CWE-117). The row is bounded: at most 32 ids, each id
// and the scope cut to a fixed byte budget with a trailing `~`.
std::string policy_targeting_audit_detail(const PolicyStore& store, const std::string& policy_id) {
    auto pol = store.get_policy(policy_id);
    if (!pol || !pol->has_value())
        return "scope=unreadable groups=unreadable";
    const auto& p = **pol;
    constexpr std::size_t kMaxScopeBytes = 1024;
    constexpr std::size_t kMaxIdBytes = 64;
    constexpr std::size_t kMaxListedGroups = 32;
    auto capped = [](std::string v, std::size_t max) {
        if (v.size() > max) {
            v.resize(max);
            v += '~';
        }
        return v;
    };
    std::string out = "scope=";
    out += p.scope_expression.empty() ? std::string{"-"}
                                      : capped(audit_token(p.scope_expression), kMaxScopeBytes);
    out += " groups=" + std::to_string(p.management_groups.size());
    for (std::size_t i = 0; i < p.management_groups.size() && i < kMaxListedGroups; ++i)
        out += (i == 0 ? ":" : ",") + capped(audit_token(p.management_groups[i]), kMaxIdBytes);
    if (p.management_groups.size() > kMaxListedGroups)
        out += ",~";
    return out;
}

} // namespace

void PolicyAdminRoutes::register_routes(httplib::Server& svr,
                                        AuthFn auth_fn,
                                        PermFn perm_fn,
                                        AuditFn audit_fn,
                                        EmitEventFn emit_event_fn,
                                        PolicyStore* policy_store,
                                        PolicyEvaluator* policy_evaluator,
                                        yuzu::MetricsRegistry* metrics) {
    // Production shim — wrap the real server in an HttplibRouteSink and
    // delegate to the sink-based overload. Same handlers, same lambdas,
    // same observable behaviour.
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(audit_fn),
                    std::move(emit_event_fn), policy_store, policy_evaluator, metrics);
}

namespace {

/// The remediation text of a refused dispatch or a refused authoring request: the closed
/// reason token first (it is how a client tells these bodies from the string-error 400s on the
/// same routes), then what to do. `unwired` is not the instruction's fault: the server could
/// not check the pair at all, so changing the instruction would not help.
std::string refusal_remediation(PolicyDispatchDenialReason reason, bool authoring) {
    std::string out = "policy_dispatch_refused: " + std::string(to_string(reason)) + ". ";
    if (reason == PolicyDispatchDenialReason::Unwired)
        return out + "Policy evaluation cannot check this action now, because the server's "
                     "capability registry is not available. Try again later, and tell the "
                     "administrator if it persists.";
    if (authoring)
        return out + "The instruction names an action that policy evaluation does not "
                     "dispatch. Use a different instruction.";
    return out + "The policy's check or fix names an action that policy evaluation does not "
                 "dispatch. Change the instruction the policy uses.";
}

// The lookup could not be answered, so the request is neither accepted nor refused: a retry
// may answer it.
constexpr std::int64_t kInstructionLookupRetryMs = 5000;

} // namespace

void PolicyAdminRoutes::answer_dispatch_refused(httplib::Response& res,
                                                PolicyDispatchDenialReason reason) {
    // A refusal is its own 409: the shared A4 builder gives it a correlation id and the
    // retry field, and the remediation text names the reason token. The existing 409 on these
    // routes ("nothing to dispatch", "already in flight") is a different body, so a client
    // can tell them apart.
    res.status = 409;
    detail::A4ErrorOpts opts;
    const std::string remediation = refusal_remediation(reason, /*authoring=*/false);
    opts.remediation = remediation;
    res.set_content(detail::a4_error(res, "policy dispatch refused", opts), "application/json");
}

bool PolicyAdminRoutes::refuse_unusable_instructions(
    const httplib::Request& req, httplib::Response& res,
    const std::vector<std::string>& instruction_ids, const char* audit_verb,
    const char* target_type, const std::string& target_id) {
    if (!policy_evaluator_)
        return false;
    for (const auto& id : instruction_ids) {
        const auto check = policy_evaluator_->authorize_instruction(id);
        if (check.kind == PolicyEvaluator::InstructionCheck::Kind::Allowed)
            continue;
        if (check.kind == PolicyEvaluator::InstructionCheck::Kind::Degraded) {
            // Never an accept and never a refusal: the lookup could not be answered.
            res.status = 503;
            detail::A4ErrorOpts opts;
            // A hint only when a retry can help: a store failure may clear, an unwired
            // evaluator will not.
            if (check.transient)
                opts.retry_after_ms = kInstructionLookupRetryMs;
            res.set_content(detail::a4_error(res, "instruction lookup unavailable, try again", opts),
                            "application/json");
            return true;
        }
        const std::string token(to_string(check.denial->reason));
        audit_fn_(req, audit_verb, "denied", target_type, target_id,
                  "reason=" + token + " instruction=" + audit_token(id));
        res.status = 400;
        detail::A4ErrorOpts opts;
        const std::string remediation = refusal_remediation(check.denial->reason, /*authoring=*/true);
        opts.remediation = remediation;
        res.set_content(detail::a4_error(res,
                                         "instruction " + id +
                                             " names an action that policy evaluation does not "
                                             "dispatch (" + token + ")",
                                         opts),
                        "application/json");
        return true;
    }
    return false;
}

void PolicyAdminRoutes::register_routes(HttpRouteSink& sink,
                                        AuthFn auth_fn,
                                        PermFn perm_fn,
                                        AuditFn audit_fn,
                                        EmitEventFn emit_event_fn,
                                        PolicyStore* policy_store,
                                        PolicyEvaluator* policy_evaluator,
                                        yuzu::MetricsRegistry* metrics) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    audit_fn_ = std::move(audit_fn);
    emit_event_fn_ = std::move(emit_event_fn);
    policy_store_ = policy_store;
    policy_evaluator_ = policy_evaluator;
    metrics_ = metrics;

    // POST /api/policy-fragments -- create fragment from YAML
    sink.Post("/api/policy-fragments",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Write"))
                return;
            if (!policy_store_ || !policy_store_->is_open()) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store not available"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            std::string yaml_source;
            // Accept raw YAML body or JSON with yaml_source field
            if (req.get_header_value("Content-Type").find("application/json") != std::string::npos) {
                try {
                    auto j = nlohmann::json::parse(req.body);
                    yaml_source = j.value("yaml_source", "");
                } catch (const std::exception& e) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
                    return;
                }
            } else {
                yaml_source = req.body;
            }

            // G01: refuse early a fragment that names an instruction policy evaluation will not
            // dispatch. Advisory: the dispatch check is the control.
            if (refuse_unusable_instructions(req, res,
                                             PolicyStore::peek_fragment_instructions(yaml_source),
                                             "policy_fragment.create", "policy_fragment",
                                             PolicyStore::peek_fragment_name(yaml_source)))
                return;

            auto result = policy_store_->create_fragment(yaml_source);
            if (!result) {
                // #396: store-level kConflictPrefix maps to HTTP 409. Strip
                // the internal prefix from the operator-facing JSON body
                // (governance enterprise-N1) and emit a denied audit so
                // name-enumeration leaves a trace (governance compliance-1,
                // up-18). The fragment name is recovered from the error
                // string when audit needs it — the parsed YAML name isn't
                // available here without re-extracting.
                bool is_conflict = is_conflict_error(result.error());
                bool is_degraded = is_db_error(result.error());
                res.status = is_conflict ? 409 : (is_degraded ? 503 : 400);
                if (is_conflict) {
                    // iter-M1: target_id is the fragment name (parsed from
                    // YAML) so SOC 2 audit reviewers can answer "duplicate
                    // of which fragment?" without re-correlating timestamps.
                    auto attempted_name = PolicyStore::peek_fragment_name(yaml_source);
                    audit_fn_(req, "policy_fragment.create", "denied",
                              "policy_fragment", attempted_name, "duplicate_name");
                }
                if (is_degraded) {
                    res.set_content(
                        nlohmann::json({{"error", {{"code", 503},
                                                    {"message", std::string(strip_db_error_prefix(result.error()))}}},
                                        {"meta", {{"api_version", "v1"}}}})
                            .dump(),
                        "application/json");
                } else {
                    std::string body_msg = is_conflict ? std::string(strip_conflict_prefix(result.error()))
                                                        : result.error();
                    res.set_content(nlohmann::json({{"error", body_msg}}).dump(), "application/json");
                }
                return;
            }
            audit_fn_(req, "policy_fragment.create", "success", "policy_fragment", *result, "");
            emit_event_fn_("policy_fragment.created", req, {}, {{"fragment_id", *result}});
            res.status = 201;
            res.set_content(nlohmann::json({{"id", *result}, {"status", "created"}}).dump(),
                            "application/json");
        });

    // DELETE /api/policy-fragments/:id
    sink.Delete(R"(/api/policy-fragments/([^/]+))",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Delete"))
                return;
            if (!policy_store_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            bool deleted = policy_store_->delete_fragment(id);
            if (deleted) {
                audit_fn_(req, "policy_fragment.delete", "success", "policy_fragment", id, "");
                emit_event_fn_("policy_fragment.deleted", req, {}, {{"fragment_id", id}});
            }
            res.set_content(nlohmann::json({{"deleted", deleted}}).dump(), "application/json");
        });

    // POST /api/policies -- create policy from YAML
    sink.Post("/api/policies",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Write"))
                return;
            if (!policy_store_ || !policy_store_->is_open()) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store not available"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            std::string yaml_source;
            if (req.get_header_value("Content-Type").find("application/json") != std::string::npos) {
                try {
                    auto j = nlohmann::json::parse(req.body);
                    yaml_source = j.value("yaml_source", "");
                } catch (const std::exception& e) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
                    return;
                }
            } else {
                yaml_source = req.body;
            }

            // G01: the same advisory check through the policy's fragment. An unknown or
            // unreadable fragment is left to the store's own create below.
            if (const auto fragment_ref = PolicyStore::peek_policy_fragment(yaml_source);
                !fragment_ref.empty()) {
                auto frag = policy_store_->get_fragment(fragment_ref);
                if (frag && *frag) {
                    std::vector<std::string> ids;
                    for (const auto* instr : {&(*frag)->check_instruction, &(*frag)->fix_instruction,
                                              &(*frag)->post_check_instruction})
                        if (!instr->empty())
                            ids.push_back(*instr);
                    if (refuse_unusable_instructions(req, res, ids, "policy.create", "policy",
                                                     PolicyStore::peek_fragment_name(yaml_source)))
                        return;
                }
            }

            auto result = policy_store_->create_policy(yaml_source);
            if (!result) {
                bool is_degraded = is_db_error(result.error());
                res.status = is_degraded ? 503 : 400;
                if (is_degraded) {
                    res.set_content(
                        nlohmann::json({{"error", {{"code", 503},
                                                    {"message", std::string(strip_db_error_prefix(result.error()))}}},
                                        {"meta", {{"api_version", "v1"}}}})
                            .dump(),
                        "application/json");
                } else {
                    res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                }
                return;
            }
            audit_fn_(req, "policy.create", "success", "policy", *result,
                      policy_targeting_audit_detail(*policy_store_, *result));
            emit_event_fn_("policy.created", req, {}, {{"policy_id", *result}});
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"Policy created","level":"success"}})");
            res.status = 201;
            res.set_content(nlohmann::json({{"id", *result}, {"status", "created"}}).dump(),
                            "application/json");
        });

    // DELETE /api/policies/:id
    sink.Delete(R"(/api/policies/([^/]+))",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Delete"))
                return;
            if (!policy_store_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            bool deleted = policy_store_->delete_policy(id);
            if (deleted) {
                audit_fn_(req, "policy.delete", "success", "policy", id, "");
                emit_event_fn_("policy.deleted", req, {}, {{"policy_id", id}});
                res.set_header("HX-Trigger",
                    R"({"showToast":{"message":"Policy deleted","level":"success"}})");
            }
            res.set_content(nlohmann::json({{"deleted", deleted}}).dump(), "application/json");
        });

    // POST /api/policies/:id/enable
    sink.Post(R"(/api/policies/([^/]+)/enable)",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Write"))
                return;
            if (!policy_store_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            // G01: enabling is where a policy starts to run, so the advisory check runs here
            // too (a policy installed by a pack was never checked at install).
            if (auto pol = policy_store_->get_policy(id); pol && *pol) {
                auto frag = policy_store_->get_fragment((*pol)->fragment_id);
                if (frag && *frag) {
                    std::vector<std::string> ids;
                    for (const auto* instr : {&(*frag)->check_instruction, &(*frag)->fix_instruction,
                                              &(*frag)->post_check_instruction})
                        if (!instr->empty())
                            ids.push_back(*instr);
                    if (refuse_unusable_instructions(req, res, ids, "policy.enable", "policy", id))
                        return;
                }
            }
            auto result = policy_store_->enable_policy(id);
            if (!result) {
                bool is_degraded = is_db_error(result.error());
                res.status = is_degraded ? 503 : 400;
                if (is_degraded) {
                    res.set_content(
                        nlohmann::json({{"error", {{"code", 503},
                                                    {"message", std::string(strip_db_error_prefix(result.error()))}}},
                                        {"meta", {{"api_version", "v1"}}}})
                            .dump(),
                        "application/json");
                } else {
                    res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                }
                return;
            }
            audit_fn_(req, "policy.enable", "success", "policy", id, "");
            emit_event_fn_("policy.enabled", req, {}, {{"policy_id", id}});
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"Policy enabled","level":"success"}})");
            res.set_content(R"({"status":"ok"})", "application/json");
        });

    // POST /api/policies/:id/disable
    sink.Post(R"(/api/policies/([^/]+)/disable)",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Write"))
                return;
            if (!policy_store_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto result = policy_store_->disable_policy(id);
            if (!result) {
                bool is_degraded = is_db_error(result.error());
                res.status = is_degraded ? 503 : 400;
                if (is_degraded) {
                    res.set_content(
                        nlohmann::json({{"error", {{"code", 503},
                                                    {"message", std::string(strip_db_error_prefix(result.error()))}}},
                                        {"meta", {{"api_version", "v1"}}}})
                            .dump(),
                        "application/json");
                } else {
                    res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                }
                return;
            }
            audit_fn_(req, "policy.disable", "success", "policy", id, "");
            emit_event_fn_("policy.disabled", req, {}, {{"policy_id", id}});
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"Policy disabled","level":"warning"}})");
            res.set_content(R"({"status":"ok"})", "application/json");
        });

    // POST /api/policies/:id/invalidate -- invalidate cache for one policy
    sink.Post(R"(/api/policies/([^/]+)/invalidate)",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Execute"))
                return;
            if (!policy_store_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto result = policy_store_->invalidate_policy(id);
            if (!result) {
                bool is_degraded = is_db_error(result.error());
                res.status = is_degraded ? 503 : 400;
                if (is_degraded) {
                    res.set_content(
                        nlohmann::json({{"error", {{"code", 503},
                                                    {"message", std::string(strip_db_error_prefix(result.error()))}}},
                                        {"meta", {{"api_version", "v1"}}}})
                            .dump(),
                        "application/json");
                } else {
                    res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                }
                return;
            }
            audit_fn_(req, "policy.invalidate", "success", "policy", id, "");
            emit_event_fn_("policy.invalidated", req, {}, {{"policy_id", id}, {"agents_reset", std::to_string(*result)}});
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"Policy cache invalidated","level":"success"}})");
            res.set_content(
                nlohmann::json({{"status", "ok"}, {"agents_invalidated", *result}}).dump(),
                "application/json");
        });

    // POST /api/policies/invalidate-all -- invalidate cache for all policies
    sink.Post("/api/policies/invalidate-all",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Execute"))
                return;
            if (!policy_store_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto result = policy_store_->invalidate_all_policies();
            if (!result) {
                bool is_degraded = is_db_error(result.error());
                res.status = is_degraded ? 503 : 500;
                if (is_degraded) {
                    res.set_content(
                        nlohmann::json({{"error", {{"code", 503},
                                                    {"message", std::string(strip_db_error_prefix(result.error()))}}},
                                        {"meta", {{"api_version", "v1"}}}})
                            .dump(),
                        "application/json");
                } else {
                    res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                }
                return;
            }
            audit_fn_(req, "policy.invalidate_all", "success", "", "", "");
            emit_event_fn_("policy.invalidated_all", req, {}, {{"total_reset", std::to_string(*result)}});
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"All policy caches invalidated","level":"success"}})");
            res.set_content(
                nlohmann::json({{"status", "ok"}, {"total_invalidated", *result}}).dump(),
                "application/json");
        });

    // POST /api/policies/:id/evaluate -- force an immediate compliance check
    // (the background evaluator picks it up on its next collect cycle).
    sink.Post(R"(/api/policies/([^/]+)/evaluate)",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Execute"))
                return;
            if (!policy_store_ || !policy_store_->is_open() || !policy_evaluator_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy evaluation not available"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }
            auto id = req.matches[1].str();
            auto policy_check = policy_store_->get_policy(id);
            if (!policy_check) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store degraded"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }
            if (!*policy_check) {
                res.status = 404;
                res.set_content(R"({"error":{"code":404,"message":"policy not found"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }
            auto exec_res = policy_evaluator_->evaluate_now(id);
            if (!exec_res) {
                // ADR-0058 / gov Gate 6: this 503 covers a genuine InstructionStore DB/lease
                // failure (among the other internal-degrade causes evaluate_now can return) —
                // audited the same as every other denial branch on this route, re-applied here
                // in evaluate_now's new std::expected shape after ADR-0056's durable-claim
                // rework (governance ledger finding gov8r1-cas-timestamp-aba's re-verify).
                // "error", not "denied" (merge-time re-verify finding): an infra degrade is not
                // an operator denial — matches /remediate's own degraded ? "error" : "denied"
                // convention a few lines below, which this re-add had missed.
                //
                // #4981 PR-1 (gov Gate 6, enterprise-readiness): thread the real cause
                // (exec_res.error(), e.g. "kickoff_check degraded for <id>: scope
                // evaluation degraded: owner_check_failed") into both the message and
                // the audit detail, matching /remediate's own result.error convention
                // below and the rest-api.md contract this route is documented against —
                // the previous generic "policy evaluation degraded" literal discarded
                // the specific reason on this route while /remediate already surfaced it.
                audit_fn_(req, "policy.evaluate", "error", "policy", id, exec_res.error());
                res.status = 503;
                res.set_content(
                    nlohmann::json({{"error", {{"code", 503}, {"message", exec_res.error()}}},
                                    {"meta", {{"api_version", "v1"}}}})
                        .dump(),
                    "application/json");
                return;
            }
            // G01: a refused dispatch comes back as a value with `denial` set and no execution
            // id. It is its own 409, ahead of the "nothing to dispatch" 409 below, and is always
            // audited (an operator-triggered refusal is evidence of the attempt).
            if (exec_res->denial) {
                audit_fn_(req, "policy.evaluate", "denied", "policy", id,
                          "reason=" + std::string(to_string(exec_res->denial->reason)));
                answer_dispatch_refused(res, exec_res->denial->reason);
                return;
            }
            auto exec_id = exec_res->execution_id;
            if (exec_id.empty()) {
                res.status = 409;
                res.set_content(
                    nlohmann::json({{"error",
                                     {{"code", 409},
                                      {"message",
                                       "policy has no check instruction or matches no agents"}}},
                                    {"meta", {{"api_version", "v1"}}}})
                        .dump(),
                    "application/json");
                return;
            }
            audit_fn_(req, "policy.evaluate", "success", "policy", id, "execution_id=" + exec_id);
            emit_event_fn_("policy.evaluated", req, {},
                           {{"policy_id", id}, {"execution_id", exec_id}});
            res.status = 202;
            res.set_content(
                nlohmann::json({{"status", "dispatched"}, {"execution_id", exec_id}}).dump(),
                "application/json");
        });

    // POST /api/policies/:id/remediate -- manual, gated remediation. Requires
    // the bound fragment to define a fix_instruction. Optional body
    // {"agent_ids":[...]} scopes the fix; absent => all non_compliant agents.
    sink.Post(R"(/api/policies/([^/]+)/remediate)",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Execute"))
                return;
            if (!policy_store_ || !policy_store_->is_open() || !policy_evaluator_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy evaluation not available"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }
            auto id = req.matches[1].str();

            // ── #2500, FIFTH instance ────────────────────────────────────────
            // An empty vector means "every non-compliant agent in this policy"
            // (policy_evaluator.cpp, remediate()). The parse below used to drop
            // non-string entries and accept an empty/non-array/unparseable body
            // silently, so `{"agent_ids":[1,2,3]}` remediated the ENTIRE
            // non-compliant set, answered 202, and audited
            // `policy.remediate|success`. Identical to the /api/command defect
            // this issue is about, on a MUTATING remediation path, and missed by
            // every diff-focused review because the reviews cleared
            // PolicyEvaluator as a DISPATCH caller and never read this route's
            // own parsing.
            //
            // ABSENT body or ABSENT key still means "all non-compliant" - that
            // is the omitted case and it is legitimate. Everything supplied that
            // names nothing is refused.
            std::vector<std::string> agent_ids;
            if (!req.body.empty()) {
                auto j = nlohmann::json::parse(req.body, nullptr, false);
                const auto refuse = [&](std::string_view reason, const std::string& msg) {
                    if (metrics_)
                        metrics_
                            ->counter("yuzu_server_dispatch_target_rejected_total",
                                      {{"route", "policy_remediate"},
                                       {"reason", std::string(reason)}})
                            .increment();
                    if (audit_fn_)
                        audit_fn_(req, "policy.remediate", "denied", "policy", id,
                                  std::string("reason=") + std::string(reason));
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", {{"code", 400}, {"message", msg}}},
                                                    {"meta", {{"api_version", "v1"}}}})
                                        .dump(),
                                    "application/json");
                };
                if (j.is_discarded() || !j.is_object()) {
                    refuse(yuzu::server::kReasonBodyType,
                           "request body must be a JSON object");
                    return;
                }
                // `scope` is NOT honoured on this route: PolicyEvaluator::remediate
                // takes only (policy_id, agent_ids). Refuse it BEFORE the shared
                // shape check, which would otherwise type-check it, empty-check
                // it, and then let the route discard it — so `{"scope":"tag:x"}`
                // passed validation, left agent_ids empty, and empty here means
                // EVERY non-compliant agent in the policy. A narrowing selector
                // producing a wider MUTATING remediation: this PR's own defect
                // class, arriving through the guard added to prevent it.
                //
                // Worse than the silent drop it replaced, until now: the shared
                // check's `target_conflict` message tells a caller who sends both
                // fields to "supply exactly one", steering them straight into the
                // widening case. Refusing scope outright is the only honest
                // answer on a route that cannot act on it. (Review finding, #2548.)
                if (j.contains("scope")) {
                    refuse(yuzu::server::kReasonScopeUnsupported,
                           "scope is not supported on this route; remediation targets are "
                           "selected by agent_ids, or by omitting it to target every "
                           "non-compliant agent in the policy");
                    return;
                }
                if (auto bv = yuzu::server::check_targeting_shape(j)) {
                    refuse(bv->reason, bv->message);
                    return;
                }
                if (j.contains("agent_ids")) {
                    for (const auto& a : j["agent_ids"])
                        agent_ids.push_back(a.get<std::string>());
                }
            }
            auto result = policy_evaluator_->remediate(id, agent_ids);
            if (!result.ok && result.denial) {
                // G01: a refused fix is a 409 of its own, decided before any matching on the
                // error text (which would have made it a 400).
                audit_fn_(req, "policy.remediate", "denied", "policy", id,
                          "reason=" + std::string(to_string(result.denial->reason)));
                answer_dispatch_refused(res, result.denial->reason);
                return;
            }
            if (!result.ok) {
                // Governance (2026-08-24): a genuine store-degrade error
                // used to fall through to the 400/"denied" default below —
                // a false diagnosis (this isn't a malformed/rejected
                // request) AND a false audit entry (an infra failure is not
                // an operator denial). Classified via RemediateResult::degraded
                // (set explicitly by remediate() itself), not a string prefix
                // guess (consistency-auditor SHOULD-2: an unshared,
                // untested string contract on the route side).
                bool degraded = result.degraded;
                int code = 400;
                if (degraded)
                    code = 503;
                else if (result.error.find("not found") != std::string::npos)
                    code = 404;
                else if (result.error.find("remediation pathway") != std::string::npos ||
                         result.error.find("no non_compliant") != std::string::npos ||
                         result.error.find("no in-scope") != std::string::npos ||
                         result.error.find("already in flight") != std::string::npos)
                    code = 409;
                audit_fn_(req, "policy.remediate", degraded ? "error" : "denied", "policy", id,
                          result.error);
                res.status = code;
                // Nested A4 error envelope, matching /evaluate and the other
                // policy endpoints (gov consistency SHOULD-1).
                res.set_content(nlohmann::json({{"error", {{"code", code}, {"message", result.error}}},
                                                {"meta", {{"api_version", "v1"}}}})
                                    .dump(),
                                "application/json");
                return;
            }
            audit_fn_(req, "policy.remediate", "success", "policy", id,
                      "execution_id=" + result.execution_id +
                          " agents=" + std::to_string(result.agents));
            emit_event_fn_("policy.remediated", req, {},
                           {{"policy_id", id},
                            {"execution_id", result.execution_id},
                            {"agents", result.agents}});
            res.status = 202;
            res.set_content(nlohmann::json({{"status", "remediating"},
                                            {"execution_id", result.execution_id},
                                            {"agents", result.agents}})
                                .dump(),
                            "application/json");
        });
}

} // namespace yuzu::server
