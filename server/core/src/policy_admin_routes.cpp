/// @file policy_admin_routes.cpp
/// Policy/fragment mutator + dispatch route registration. Moved verbatim out
/// of `compliance_routes.cpp` by ADR-0031 WS-A4 Task B — see
/// policy_admin_routes.hpp's file banner for why this stays outside the
/// compliance family's seam-closure enforcement (no public REST/MCP twin).

#include "policy_admin_routes.hpp"

#include "dispatch_target_shape.hpp" // check_targeting_shape (#2500)
#include "policy_evaluator.hpp"
#include "store_errors.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace yuzu::server {

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
            audit_fn_(req, "policy.create", "success", "policy", *result, "");
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
            auto exec_id = *exec_res;
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
