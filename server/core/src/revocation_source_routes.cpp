/// @file revocation_source_routes.cpp
/// `/api/v1/crypto/revocation-sources` route registration - see revocation_source_routes.hpp for
/// the gate / audit contract. Validation, the egress check and the JSON views are the shared
/// `RevocationSourceService`'s; this file is the REST transport only.

#include "revocation_source_routes.hpp"

#include "body_cap_policy.hpp" // the pre-routing twin of kBodyMaxBytes (static_assert below)
#include "rest_a4_envelope_http.hpp"
#include "rest_audit.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <mutex>
#include <string>
#include <utility>

namespace yuzu::server {

namespace {

namespace rs = revocation_source;

// The handler's own body bound and the pre-routing cap table must agree (ca_revoke precedent):
// this assert IS the enforcement of the pair - a change to either fails the build.
static_assert(resolve_body_cap("POST", "/api/v1/crypto/revocation-sources").max_body_bytes ==
                  rs::kBodyMaxBytes,
              "body_cap_policy.hpp's /api/v1/crypto/revocation-sources row must mirror "
              "revocation_source::kBodyMaxBytes");
static_assert(resolve_body_cap("PUT", "/api/v1/crypto/revocation-sources/1").max_body_bytes ==
                  rs::kBodyMaxBytes,
              "the PUT must resolve to the same row");

constexpr std::int64_t kRetryAfterMs = 5000;
const std::string kTargetType = "RevocationSource";

std::string ok_json(nlohmann::json data) {
    nlohmann::json out;
    out["data"] = std::move(data);
    out["meta"] = nlohmann::json{{"api_version", "v1"}};
    return out.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

// Per-caller, never cached by a shared cache, keyed by any private one on every credential.
void set_private_no_store(httplib::Response& res) {
    res.set_header("Cache-Control", "no-store, private");
    res.set_header("Vary", "Authorization, Cookie, X-Yuzu-Token");
}

void rest_error(httplib::Response& res, int status, const std::string& message,
                bool retryable = false, const std::string& remediation = {},
                std::int64_t retry_after_ms = 0) {
    res.status = status;
    detail::A4ErrorOpts opts;
    if (retryable)
        opts.retry_after_ms = retry_after_ms > 0 ? retry_after_ms : kRetryAfterMs;
    opts.remediation = remediation;
    res.set_content(detail::a4_error(res, message, opts), "application/json");
}

/// A service error as the A4 envelope. A 409 names the existing source in its remediation; a 400
/// names the offending parameter.
void service_error(httplib::Response& res, const rs::ServiceError& e) {
    using K = rs::ServiceError::Kind;
    switch (e.kind) {
    case K::kInvalidParams:
        rest_error(res, 400, e.message, false,
                   e.param.empty() ? std::string{} : "fix the parameter " + e.param);
        return;
    case K::kNotFound:
        rest_error(res, 404, e.message);
        return;
    case K::kVersionConflict:
        rest_error(res, 409, e.message, false,
                   "read the source (GET /api/v1/crypto/revocation-sources/{id}) and resend with "
                   "expected_config_version=" + std::to_string(e.existing_id));
        return;
    case K::kConflict:
        rest_error(res, 409, e.message, false,
                   e.existing_id > 0
                       ? "update the existing source with PUT /api/v1/crypto/revocation-sources/" +
                             std::to_string(e.existing_id)
                       : "remove a source first with DELETE /api/v1/crypto/revocation-sources/{id}");
        return;
    case K::kUnavailable:
        rest_error(res, 503, e.message, true, {}, e.retry_after_ms);
        return;
    case K::kOutcomeUnknown:
        rest_error(res, 503, e.message, true,
                   "read the source (GET /api/v1/crypto/revocation-sources) to see whether the "
                   "change was applied");
        return;
    }
}

using rs::audit_result_for;

std::once_flag g_unwired_logged;

void unwired(httplib::Response& res) {
    std::call_once(g_unwired_logged, [] {
        spdlog::error("revocation source routes: a gate or the service is unwired - every route "
                      "answers 503");
    });
    // A wiring fault lasts until a restart: no retry hint.
    rest_error(res, 503, "service unavailable");
}

} // namespace

void RevocationSourceRoutes::register_routes(httplib::Server& svr, Deps deps) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(deps));
}

void RevocationSourceRoutes::register_routes(HttpRouteSink& sink, Deps deps) {
    deps_ = std::move(deps);

    // The shared prelude: authentication, the securable, then the durable administrator. Returns
    // the session when the request may proceed; otherwise the answer is already written. `verb`
    // is the audit verb of the route, `target_id` its target.
    const auto gate = [this](const httplib::Request& req, httplib::Response& res, bool is_write,
                             const std::string& verb,
                             const std::string& target_id) -> std::optional<auth::Session> {
        (void)detail::ensure_correlation_id(res);
        set_private_no_store(res);
        if (!deps_.auth_fn || !deps_.perm_fn || !deps_.admin_fn || deps_.service == nullptr) {
            unwired(res);
            return std::nullopt;
        }
        auto session = deps_.auth_fn(req, res);
        if (!session)
            return std::nullopt;
        if (!deps_.perm_fn(req, res, kTargetType, is_write ? "Write" : "Read"))
            return std::nullopt; // the gate wrote 401/403/503 and its own denial row
        const auto decision = deps_.admin_fn(*session, is_write);
        if (decision.outcome != rs::AdminDecision::Outcome::kAdmin) {
            const bool unavailable = decision.outcome == rs::AdminDecision::Outcome::kUnavailable;
            if (unavailable)
                spdlog::warn("{}: {} (user={})", verb, decision.audit_reason, session->username);
            (void)detail::emit_behavioral_audit(deps_.audit_fn, req, res, verb, "denied",
                                                kTargetType, target_id, decision.audit_reason);
            if (unavailable)
                rest_error(res, 503, decision.message, true);
            else
                rest_error(res, 403, decision.message);
            return std::nullopt;
        }
        if (is_write && deps_.write_gate.refuse_cross_site(deps_.audit_fn, req, res, verb))
            return std::nullopt;
        return session;
    };

    // The body of a mutation: size-bounded and strict JSON.
    const auto parse_body = [this](const httplib::Request& req, httplib::Response& res,
                                   const std::string& verb, const std::string& target_id,
                                   nlohmann::json& out) -> bool {
        if (req.body.size() > rs::kBodyMaxBytes) {
            rest_error(res, 413, "request body too large");
            return false;
        }
        out = nlohmann::json::parse(req.body, nullptr, /*allow_exceptions=*/false);
        if (out.is_discarded()) {
            (void)detail::emit_behavioral_audit(deps_.audit_fn, req, res, verb, "denied",
                                                kTargetType, target_id,
                                                "invalid request: body is not valid JSON");
            rest_error(res, 400, "invalid JSON");
            return false;
        }
        return true;
    };

    // Re-run the administrator decision AFTER name resolution and before the `attempted` row and
    // the commit: validation can take many seconds, and a demotion applied meanwhile (on this or
    // another replica) must not still commit a durable egress target.
    const auto recheck = [this](const httplib::Request& req, httplib::Response& res,
                                const auth::Session& session, const std::string& verb,
                                const std::string& target_id) -> bool {
        const auto d = deps_.admin_fn(session, /*is_write=*/true);
        if (d.outcome == rs::AdminDecision::Outcome::kAdmin)
            return true;
        (void)detail::emit_behavioral_audit(deps_.audit_fn, req, res, verb, "denied", kTargetType,
                                            target_id, d.audit_reason);
        if (d.outcome == rs::AdminDecision::Outcome::kUnavailable)
            rest_error(res, 503, d.message, true);
        else
            rest_error(res, 403, d.message);
        return false;
    };

    // -- GET /api/v1/crypto/revocation-sources - every registered source.
    sink.Get("/api/v1/crypto/revocation-sources", [this, gate](const httplib::Request& req,
                                                                httplib::Response& res) {
        const auto cid = detail::ensure_correlation_id(res);
        const std::string verb(rs::kAuditList);
        auto session = gate(req, res, false, verb, "all");
        if (!session)
            return;
        auto list = deps_.service->list();
        if (!list) {
            (void)detail::emit_behavioral_audit(deps_.audit_fn, req, res, verb,
                                                audit_result_for(list.error()), kTargetType, "all",
                                                rs::audit_detail_error(cid, list.error()));
            service_error(res, list.error());
            return;
        }
        // Fail closed: a row that does not persist answers 503 with no data.
        if (!detail::emit_behavioral_audit(deps_.audit_fn, req, res, verb, "success", kTargetType,
                                           "all", rs::audit_detail_list(cid, list->sources.size()))) {
            rest_error(res, 503, "audit log unavailable; the sources were not returned", true,
                       "retry once the audit log is available");
            return;
        }
        res.set_content(ok_json(rs::list_json(*list)), "application/json");
    });

    // -- GET /api/v1/crypto/revocation-sources/{id}
    sink.Get(R"(/api/v1/crypto/revocation-sources/([0-9]+))",
             [this, gate](const httplib::Request& req, httplib::Response& res) {
                 const auto cid = detail::ensure_correlation_id(res);
                 const std::string verb(rs::kAuditView);
                 const std::string raw = req.matches[1].str();
                 auto session = gate(req, res, false, verb, raw);
                 if (!session)
                     return;
                 const auto id = rs::parse_source_id(raw);
                 if (!id) {
                     rest_error(res, 404, "no such revocation source");
                     return;
                 }
                 auto src = deps_.service->get(*id);
                 if (!src) {
                     (void)detail::emit_behavioral_audit(
                         deps_.audit_fn, req, res, verb,
                         audit_result_for(src.error()),
                         kTargetType, raw, rs::audit_detail_error(cid, src.error()));
                     service_error(res, src.error());
                     return;
                 }
                 if (!detail::emit_behavioral_audit(deps_.audit_fn, req, res, verb, "success",
                                                    kTargetType, raw, rs::audit_detail_view(cid))) {
                     rest_error(res, 503, "audit log unavailable; the source was not returned",
                                true, "retry once the audit log is available");
                     return;
                 }
                 res.set_content(ok_json(rs::source_json(*src)), "application/json");
             });

    // -- POST /api/v1/crypto/revocation-sources - register a CA and its CRL URLs.
    sink.Post("/api/v1/crypto/revocation-sources", [this, gate, parse_body, recheck](
                                                        const httplib::Request& req,
                                                        httplib::Response& res) {
        const auto cid = detail::ensure_correlation_id(res);
        const std::string verb(rs::kAuditRegister);
        auto session = gate(req, res, true, verb, "new");
        if (!session)
            return;
        if (deps_.step_up_fn &&
            !deps_.step_up_fn(req, res, *session, "POST /api/v1/crypto/revocation-sources"))
            return;
        nlohmann::json body;
        if (!parse_body(req, res, verb, "new", body))
            return;
        // Judged before the attempted row: a refused body is never a mutation attempt.
        auto valid = deps_.service->validate_registration(
            body, rs::RevocationSourceService::BodyMode::kRegister);
        if (!valid) {
            (void)detail::emit_behavioral_audit(deps_.audit_fn, req, res, verb,
                                                audit_result_for(valid.error()), kTargetType, "new",
                                                rs::audit_detail_error(cid, valid.error()));
            service_error(res, valid.error());
            return;
        }
        if (!recheck(req, res, *session, verb, "new"))
            return;
        if (!detail::audit_attempted(deps_.audit_fn, req, res, verb, kTargetType, "new",
                                     rs::audit_detail_config(cid, *valid)))
            return;
        auto made = deps_.service->register_validated(*valid, session->username);
        if (!made) {
            (void)detail::emit_behavioral_audit(deps_.audit_fn, req, res, verb,
                                                audit_result_for(made.error()), kTargetType, "new",
                                                rs::audit_detail_error(cid, made.error()));
            service_error(res, made.error());
            return;
        }
        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, verb, "success", kTargetType, std::to_string(made->id),
            rs::audit_detail_source(cid, *made));
        auto data = rs::source_json(*made);
        if (!persisted)
            data["audit_persisted"] = false;
        res.status = 201;
        res.set_header("Location", "/api/v1/crypto/revocation-sources/" + std::to_string(made->id));
        res.set_content(ok_json(std::move(data)), "application/json");
    });

    // -- PUT /api/v1/crypto/revocation-sources/{id} - replace name, keys and URLs.
    sink.Put(R"(/api/v1/crypto/revocation-sources/([0-9]+))",
             [this, gate, parse_body, recheck](const httplib::Request& req, httplib::Response& res) {
                 const auto cid = detail::ensure_correlation_id(res);
                 const std::string verb(rs::kAuditUpdate);
                 const std::string raw = req.matches[1].str();
                 auto session = gate(req, res, true, verb, raw);
                 if (!session)
                     return;
                 if (deps_.step_up_fn &&
                     !deps_.step_up_fn(req, res, *session, "PUT /api/v1/crypto/revocation-sources/{id}"))
                     return;
                 const auto id = rs::parse_source_id(raw);
                 if (!id) {
                     rest_error(res, 404, "no such revocation source");
                     return;
                 }
                 nlohmann::json body;
                 if (!parse_body(req, res, verb, raw, body))
                     return;
                 auto valid = deps_.service->validate_registration(
                     body, rs::RevocationSourceService::BodyMode::kUpdate);
                 if (!valid) {
                     (void)detail::emit_behavioral_audit(
                         deps_.audit_fn, req, res, verb, audit_result_for(valid.error()),
                         kTargetType, raw, rs::audit_detail_error(cid, valid.error()));
                     service_error(res, valid.error());
                     return;
                 }
                 if (!recheck(req, res, *session, verb, raw))
                     return;
                 if (!detail::audit_attempted(deps_.audit_fn, req, res, verb, kTargetType, raw,
                                              rs::audit_detail_config(cid, *valid)))
                     return;
                 auto done = deps_.service->update_validated(*id, *valid);
                 if (!done) {
                     (void)detail::emit_behavioral_audit(
                         deps_.audit_fn, req, res, verb,
                         audit_result_for(done.error()),
                         kTargetType, raw, rs::audit_detail_error(cid, done.error()));
                     service_error(res, done.error());
                     return;
                 }
                 const bool persisted = detail::emit_behavioral_audit(
                     deps_.audit_fn, req, res, verb, "success", kTargetType, raw,
                     rs::audit_detail_update(cid, *done));
                 auto data = rs::update_json(*done);
                 if (!persisted)
                     data["audit_persisted"] = false;
                 res.set_content(ok_json(std::move(data)), "application/json");
             });

    // -- DELETE /api/v1/crypto/revocation-sources/{id} - remove a source (a Write, not a Delete).
    sink.Delete(R"(/api/v1/crypto/revocation-sources/([0-9]+))",
                [this, gate](const httplib::Request& req, httplib::Response& res) {
                    const auto cid = detail::ensure_correlation_id(res);
                    const std::string verb(rs::kAuditRemove);
                    const std::string raw = req.matches[1].str();
                    auto session = gate(req, res, true, verb, raw);
                    if (!session)
                        return;
                    if (deps_.step_up_fn &&
                        !deps_.step_up_fn(req, res, *session,
                                          "DELETE /api/v1/crypto/revocation-sources/{id}"))
                        return;
                    const auto id = rs::parse_source_id(raw);
                    if (!id) {
                        rest_error(res, 404, "no such revocation source");
                        return;
                    }
                    if (!detail::audit_attempted(deps_.audit_fn, req, res, verb, kTargetType, raw,
                                                 "cid=" + cid))
                        return;
                    auto removed = deps_.service->remove(*id);
                    if (!removed) {
                        (void)detail::emit_behavioral_audit(
                            deps_.audit_fn, req, res, verb,
                            audit_result_for(removed.error()),
                            kTargetType, raw, rs::audit_detail_error(cid, removed.error()));
                        service_error(res, removed.error());
                        return;
                    }
                    const bool persisted = detail::emit_behavioral_audit(
                        deps_.audit_fn, req, res, verb, "success", kTargetType, raw,
                        "cid=" + cid + " removed=true");
                    nlohmann::json data{{"id", *id}, {"removed", true}};
                    if (!persisted)
                        data["audit_persisted"] = false;
                    res.set_content(ok_json(std::move(data)), "application/json");
                });

    // -- POST /api/v1/crypto/revocation-sources/{id}/reset-high-water
    sink.Post(R"(/api/v1/crypto/revocation-sources/([0-9]+)/reset-high-water)",
              [this, gate, parse_body, recheck](const httplib::Request& req, httplib::Response& res) {
                  const auto cid = detail::ensure_correlation_id(res);
                  const std::string verb(rs::kAuditResetHighWater);
                  const std::string raw = req.matches[1].str();
                  auto session = gate(req, res, true, verb, raw);
                  if (!session)
                      return;
                  if (deps_.step_up_fn &&
                      !deps_.step_up_fn(req, res, *session,
                                        "POST /api/v1/crypto/revocation-sources/{id}/reset-high-water"))
                      return;
                  const auto id = rs::parse_source_id(raw);
                  if (!id) {
                      rest_error(res, 404, "no such revocation source");
                      return;
                  }
                  // An empty body is the same as `{}` (reset to now).
                  nlohmann::json body = nlohmann::json::object();
                  if (!req.body.empty() && !parse_body(req, res, verb, raw, body))
                      return;
                  // Judged before the attempted row, like register and update: a refused body is
                  // never a mutation attempt, and the refusal is audited.
                  if (const auto bad = deps_.service->validate_reset(body); !bad) {
                      (void)detail::emit_behavioral_audit(deps_.audit_fn, req, res, verb, "denied",
                                                          kTargetType, raw,
                                                          rs::audit_detail_error(cid, bad.error()));
                      service_error(res, bad.error());
                      return;
                  }
                  if (!recheck(req, res, *session, verb, raw))
                      return;
                  if (!detail::audit_attempted(deps_.audit_fn, req, res, verb, kTargetType, raw,
                                               rs::audit_detail_reset(cid, body)))
                      return;
                  auto done = deps_.service->reset_high_water(*id, body);
                  if (!done) {
                      (void)detail::emit_behavioral_audit(
                          deps_.audit_fn, req, res, verb, audit_result_for(done.error()),
                          kTargetType, raw, rs::audit_detail_error(cid, done.error()));
                      service_error(res, done.error());
                      return;
                  }
                  const bool persisted = detail::emit_behavioral_audit(
                      deps_.audit_fn, req, res, verb, "success", kTargetType, raw,
                      rs::audit_detail_reset_result(cid, *done));
                  auto data = rs::reset_json(*done);
                  if (!persisted)
                      data["audit_persisted"] = false;
                  res.set_content(ok_json(std::move(data)), "application/json");
              });
}

} // namespace yuzu::server
