#include "config_routes.hpp"

#include "admin_gate.hpp"           // authz::admin_gate_verdict
#include "dex_score_policy_json.hpp" // kDexScorePolicyKey
#include "http_route_sink.hpp"
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard
#include "rest_a4_envelope_http.hpp" // detail::a4_error
#include "rest_audit.hpp"        // detail::try_persist_audit / emit_behavioral_audit
#include "runtime_config_store.hpp"
#include "runtime_config_view.hpp" // build_overrides_json
#include "web_utils.hpp"          // browser_write_is_cross_site

#include <yuzu/log_token.hpp>
#include <yuzu/server/server.hpp> // struct Config (forward-declared in the header)

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <charconv>
#include <chrono>
#include <string>
#include <system_error>

namespace yuzu::server::config {

void register_config_routes(HttpRouteSink& sink, Deps deps) {
    // -- Runtime Configuration API (7.3) ------------------------------------
    sink.Get("/api/config", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Infrastructure", "Read"))
            return;

        nlohmann::json config_obj;
        // Current effective values (from cfg_ + overrides)
        config_obj["heartbeat_timeout"] = deps.cfg->session_timeout.count();
        config_obj["response_retention_days"] = deps.cfg->response_retention_days;
        config_obj["audit_retention_days"] = deps.cfg->audit_retention_days;
        config_obj["guardian_event_retention_days"] = deps.cfg->guardian_event_retention_days;
        config_obj["auto_approve_enabled"] = !deps.auto_approve->list_rules().empty();
        config_obj["log_level"] =
            spdlog::level::to_string_view(spdlog::default_logger()->level()).data();

        // Overrides from store. The omission rule lives in
        // build_overrides_json (runtime_config_view.hpp) so it was independently
        // unit-testable even while this route was still inline (the route itself is
        // also TestRouteSink-registered since #2542 PR-12), and it is one of the
        // sites the secret leaked from twice.
        // A degraded store must NOT read as "nothing is configured". This route no
        // longer returns a secret's value, so the PRESENCE of the key and its
        // `is_set` are the only way to answer "is the OIDC secret set here?" -- and
        // security-hardening.md tells operators to answer exactly that before
        // deciding whether to rotate a disclosed credential. Returning 200 with an
        // empty `overrides` would answer "never set, nothing to rotate". The PUT twin
        // below already 503s on this condition; this matches it.
        if (!deps.runtime_config_store || !deps.runtime_config_store->is_open()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"runtime config store unavailable"},)"
                R"("meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        auto overrides_result = deps.runtime_config_store->get_all();
        if (!overrides_result.has_value()) {
            spdlog::error("GET /api/config: read failed: {}",
                          ::yuzu::log_key_token(overrides_result.error()));
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"runtime config store unavailable"},)"
                R"("meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        nlohmann::json overrides = build_overrides_json(*overrides_result);

        nlohmann::json allowed = nlohmann::json::array();
        for (const auto& k : RuntimeConfigStore::allowed_keys())
            allowed.push_back(k);

        // Allowed keys that this route lists but does not write: the generic PUT refuses them
        // (they have their own route). Derived from the write class, so a second route-owned key
        // is listed here without a second edit.
        nlohmann::json read_only = nlohmann::json::array();
        for (const auto& k : RuntimeConfigStore::allowed_keys())
            if (RuntimeConfigStore::write_class(k) == ConfigWriteClass::RouteOwned)
                read_only.push_back(k);

        res.set_content(nlohmann::json({{"config", config_obj},
                                        {"overrides", overrides},
                                        {"allowed_keys", allowed},
                                        {"read_only_keys", read_only}})
                            .dump(),
                        "application/json");
    });

    sink.Put(R"(/api/config/([a-z_]+))", [deps](const httplib::Request& req,
                                                httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Infrastructure", "Write"))
            return;

        // Same-site gate for the cookie-authorised write the General page calls (API, MCP and
        // engine token callers are exempt). After the permission gate, so an unauthorised caller
        // still gets the 403 it always did, and before any refusal or the body is read, so a
        // cross-site write is audited as `csrf.denied` best effort (the row is attempted; the
        // refusal does not depend on its outcome). auth_fn writes its own 401 when there is no session.
        auto session = deps.auth_fn(req, res);
        if (!session)
            return;
        if (browser_write_is_cross_site(session->auth_source, req.get_header_value("Host"),
                                        req.get_header_value("Origin"),
                                        req.get_header_value("Referer"),
                                        deps.cfg->csrf_trusted_origins)) {
            (void)detail::try_persist_audit(deps.audit_fn, req, "csrf.denied", "denied", "Endpoint",
                                            "config", "cross-site or header-less browser write refused");
            res.status = 403;
            res.set_content(detail::a4_error(res, "cross-site request refused"), "application/json");
            return;
        }

        // One lookup decides both refusals below. Both run before the store gate: the answer
        // depends on the key and the caller, not on the store, and a denied caller must get the
        // same 403 whether or not the store is up. An unknown key has no class and is refused
        // further down, as before.
        auto key = req.matches[1].str();
        const auto write_class = RuntimeConfigStore::write_class(key);

        // A route-owned key (today only dex_score_policy: one document that will have its own
        // writer, which validates it whole; a generic single-value write could leave it
        // half-edited). Refused with no audit row, like the unknown-key refusal below.
        if (write_class == ConfigWriteClass::RouteOwned) {
            res.status = 400;
            res.set_content(
                detail::a4_error(res,
                                 key == kDexScorePolicyKey
                                     ? std::string("dex_score_policy is written only through "
                                                   "PUT /api/v1/dex/score-policy")
                                     : key + " is written only through its own route",
                                 detail::A4ErrorOpts{
                                     .remediation = key == kDexScorePolicyKey
                                                        ? "send the whole policy document to "
                                                          "PUT /api/v1/dex/score-policy with "
                                                          "If-Match (not yet available in this "
                                                          "release)"
                                                        : "use the route that owns this key"}),
                "application/json");
            return;
        }

        // A key whose own settings route is administrator-only is not writable here by a weaker
        // caller (RuntimeConfigStore::write_class). perm_fn admits a JIT-elevated session and an
        // MCP-tier token; the settings routes refuse an MCP-tier or service-scoped token through
        // require_admin, so this route must too. The oidc_* keys decide who becomes an
        // administrator at an SSO login (oidc_admin_group is read from the stored value at the
        // next start), so they additionally refuse an elevation: the caller's OWN role must be
        // admin. That is the one rule here that is not authz::admin_gate_verdict, on purpose.
        // Every other key stays writable under Infrastructure:Write. Refused before the
        // audit-first `attempted` row so a denial leaves one `denied` row, not a dangling
        // `attempted` (outcome unknown).
        const char* refusal_detail = nullptr;
        const char* refusal_message = "changing this setting needs your own administrator role";
        if (write_class == ConfigWriteClass::AdminRouteInteractiveOnly) {
            refusal_message = "changing sign-in provider settings needs your own administrator role";
            if (session->role != auth::Role::admin || !session->mcp_tier.empty() ||
                !session->token_scope_service.empty())
                refusal_detail = auth::is_elevated(*session)
                                     ? "elevated_session_oidc_setting_blocked"
                                     : "admin_role_required_oidc_setting_blocked";
        } else if (write_class == ConfigWriteClass::AdminRoute) {
            switch (authz::admin_gate_verdict(*session)) {
            case authz::AdminGate::Admit:
                break;
            case authz::AdminGate::ServiceScoped:
            case authz::AdminGate::McpTier:
                refusal_detail = "token_session_admin_setting_blocked";
                refusal_message = "an interactive administrator session is required; MCP-tier and "
                                  "service-scoped tokens cannot change this setting";
                break;
            case authz::AdminGate::NotAdmin:
                refusal_detail = "admin_role_required_setting_blocked";
                break;
            }
        }
        if (refusal_detail) {
            (void)deps.audit_fn(req, "config.update", "denied", "RuntimeConfig", key,
                                refusal_detail);
            res.status = 403;
            res.set_content(
                detail::a4_error(res, refusal_message,
                                 detail::A4ErrorOpts{
                                     .remediation = "change this setting from an interactive "
                                                    "administrator session (the Settings page)"}),
                "application/json");
            return;
        }

        if (!deps.runtime_config_store || !deps.runtime_config_store->is_open()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"runtime config store unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        std::string value;
        try {
            // #2437-class guard: raw-text depth check before parse - "value"
            // is dumped a few lines below (j["value"].dump() when it is not
            // a string), so the check has to run on the raw text before any
            // allocation.
            if (mcp::json_exceeds_depth(req.body, mcp::kMcpMaxJsonDepth)) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"request body nests too deeply"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            auto j = nlohmann::json::parse(req.body);
            if (j.contains("value"))
                value = j["value"].is_string() ? j["value"].get<std::string>() : j["value"].dump();
            else {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"missing 'value' in request body"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
        } catch (...) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"invalid JSON body"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        // Validate integer-typed keys BEFORE persisting so a
        // non-numeric or negative value does not silently land
        // in RuntimeConfigStore while leaving cfg_ at the old
        // value (the prior `try { stoi } catch (...) {}` path
        // was a ghost-write: store persists, cfg ignores,
        // operator sees 200 with no effect). UP-R5 from the
        // Guardian PR 2 governance re-run.
        const bool is_int_key =
            key == "heartbeat_timeout" || key == "response_retention_days" ||
            key == "audit_retention_days" || key == "guardian_event_retention_days";
        int parsed_int = 0;
        if (is_int_key) {
            auto first = value.data();
            auto last = value.data() + value.size();
            auto [ptr, ec] = std::from_chars(first, last, parsed_int);
            if (ec != std::errc{} || ptr != last || parsed_int < 0) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"value must be a non-negative integer"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
        }

        // An unknown key is refused here, before any audit row, so a junk key leaves no
        // attempted/failure pair. The store repeats the check as the authority.
        if (!RuntimeConfigStore::is_allowed_key(key)) {
            res.status = 400;
            res.set_content(
                nlohmann::json({{"error", "key '" + key + "' is not a configurable runtime setting"}})
                    .dump(),
                "application/json");
            return;
        }

        // ADR-0033 section 9, "no audit row, no mutation": an `attempted` row is written before
        // anything is changed, and a row that cannot be stored refuses the change. The outcome
        // row follows. The attempted row carries no value (a secret key's value never reaches an
        // audit detail; the outcome row below redacts it).
        if (!detail::emit_behavioral_audit(deps.audit_fn, req, res, "config.update", "attempted",
                                           "RuntimeConfig", key, "")) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "audit log unavailable; the change was not made",
                                             detail::A4ErrorOpts{.retry_after_ms = 5000,
                                                                 .remediation = "retry the request"}),
                            "application/json");
            return;
        }

        auto result = deps.runtime_config_store->set(key, value, session->username);
        if (!result) {
            // Best effort: the attempted row is already durable, and the response does not change.
            // A refusal of the value is operator-written text (no value, no secret); a database
            // failure may have committed before the acknowledgement was lost, so it is not
            // recorded as "not applied".
            const bool db_failure = result.error().starts_with(kRuntimeConfigDbErrorPrefix);
            (void)detail::try_persist_audit(deps.audit_fn, req, "config.update", "failure",
                                            "RuntimeConfig", key,
                                            db_failure ? "store error; outcome unknown"
                                                       : result.error());
            // A genuine DB/crypto failure (kRuntimeConfigDbErrorPrefix) is a
            // 503 with a generic message -- never echo the internal detail
            // to the caller; caller-input validation (unknown key, bad
            // value shape, the redaction-placeholder guard) is a 400 with
            // the store's own message, which is written for an operator.
            if (result.error().starts_with(kRuntimeConfigDbErrorPrefix)) {
                spdlog::error("PUT /api/config/{}: write failed: {}", ::yuzu::log_key_token(key),
                              ::yuzu::log_key_token(result.error()));
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"runtime config store unavailable"},)"
                    R"("meta":{"api_version":"v1"}})",
                    "application/json");
            } else {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                                "application/json");
            }
            return;
        }

        // Apply the change to in-memory config. Integer keys
        // parsed above; direct assignment here means no
        // second `try { stoi }` that could swallow errors.
        if (key == "heartbeat_timeout") {
            deps.cfg->session_timeout = std::chrono::seconds(parsed_int);
        } else if (key == "response_retention_days") {
            deps.cfg->response_retention_days = parsed_int;
        } else if (key == "audit_retention_days") {
            deps.cfg->audit_retention_days = parsed_int;
        } else if (key == "guardian_event_retention_days") {
            deps.cfg->guardian_event_retention_days = parsed_int;
        }
        // log_level is applied inside RuntimeConfigStore::set()

        // NOT the raw value. An audit detail is durable, retained by policy, and
        // readable by every role seeded AuditLog:Read (Operator among them) -- so
        // writing a credential here is a worse sink than the log and the API this
        // branch already fixed, and it is not rotatable away afterwards.
        // The attempted row already exists, so a lost outcome row does not undo the change; it is
        // surfaced the way the other audited routes do (Sec-Audit-Failed), so a caller can show it.
        (void)detail::emit_behavioral_audit(
            deps.audit_fn, req, res, "config.update", "success", "RuntimeConfig", key,
            "value=" + (RuntimeConfigStore::is_secret_key(key)
                            ? std::string(RuntimeConfigStore::redacted_placeholder())
                            : value));

        res.set_content(
            nlohmann::json(RuntimeConfigStore::is_secret_key(key)
                               ? nlohmann::json{{"key", key}, {"applied", true}}
                               : nlohmann::json{{"key", key}, {"value", value}, {"applied", true}})
                .dump(),
            "application/json");
    });
}

} // namespace yuzu::server::config
