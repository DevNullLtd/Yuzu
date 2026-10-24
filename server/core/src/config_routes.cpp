#include "config_routes.hpp"

#include "config_write.hpp"
#include "http_route_sink.hpp"
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard
#include "rest_a4_envelope_http.hpp" // detail::a4_error
#include "rest_audit.hpp"        // detail::try_persist_audit / emit_behavioral_audit
#include "runtime_config_store.hpp"
#include "web_utils.hpp" // browser_write_is_cross_site

#include <yuzu/server/server.hpp> // struct Config (forward-declared in the header)

#include <nlohmann/json.hpp>

#include <string>
#include <string_view>
#include <utility>

namespace yuzu::server::config {

namespace {

/// The body shapes the legacy routes answer in. A4 is the envelope every v1 refusal uses; Terse is
/// the original `{"error":{"code","message"},"meta":{"api_version"}}` form and Flat the original
/// `{"error": message}` form, both kept byte for byte (the Settings page and scripts parse them).
enum class Legacy { A4, Terse, Flat };

std::string terse_body(int code, std::string_view message) {
    // nlohmann sorts object keys, which is the order the literal bodies always had.
    return nlohmann::json({{"error", {{"code", code}, {"message", std::string(message)}}},
                           {"meta", {{"api_version", "v1"}}}})
        .dump();
}

/// A v1 success body: `{"data": ..., "meta": {"api_version": "v1"}}`.
std::string ok_json(nlohmann::json data) {
    return nlohmann::json({{"data", std::move(data)}, {"meta", {{"api_version", "v1"}}}}).dump();
}

/// The one PUT handler. `v1` selects the envelope only: the legacy route keeps its original
/// terse error bodies byte for byte (the Settings page and scripts parse them), the v1 twin
/// answers every refusal in the A4 envelope. The gate order, the checks and the audit rows are
/// identical, and every decision is `config_write.hpp`'s.
void handle_put(const Deps& deps, const httplib::Request& req, httplib::Response& res, bool v1) {
    // A refusal with `status`. The v1 route answers every refusal in the A4 envelope. The legacy
    // route answers in `legacy` shape where it always did, and in A4 where it always did.
    auto refuse = [&](int status, std::string_view message, Legacy legacy = Legacy::A4,
                      detail::A4ErrorOpts opts = {}) {
        res.status = status;
        if (!v1 && legacy == Legacy::Terse)
            res.set_content(terse_body(status, message), "application/json");
        else if (!v1 && legacy == Legacy::Flat)
            res.set_content(nlohmann::json({{"error", std::string(message)}}).dump(),
                            "application/json");
        else
            res.set_content(detail::a4_error(res, message, opts), "application/json");
    };

    // The permission gate (Infrastructure:Write) is called by the registering lambda, in the
    // handler body, where the api-parity gate-parity check reads it; it has already run.

    // Same-site gate for the cookie-authorised write the General page calls (API, MCP and engine
    // token callers are exempt). Defence in depth behind the central pre-routing gate, which
    // answers a cookie-session write first; this copy runs before the body is read, so a
    // cross-site write is audited as `csrf.denied` best effort (the row is attempted; the refusal
    // does not depend on its outcome). auth_fn writes its own 401 when there is no session.
    auto session = deps.auth_fn(req, res);
    if (!session)
        return;
    if (browser_write_is_cross_site(session->auth_source, req.get_header_value("Host"),
                                    req.get_header_value("Origin"), req.get_header_value("Referer"),
                                    deps.cfg->csrf_trusted_origins)) {
        (void)detail::try_persist_audit(deps.audit_fn, req, "csrf.denied", "denied", "Endpoint",
                                        "config", "cross-site or header-less browser write refused");
        refuse(403, "cross-site request refused");
        return;
    }

    // MFA step-up (kRequired for the v1 write only; the legacy route's row is pending). A
    // token caller and an un-enrolled user are skipped inside the closure; a cookie session
    // without a fresh proof is answered by the closure itself.
    if (v1 && deps.step_up_fn && !deps.step_up_fn(req, res, *session, "PUT /api/v1/config/{key}"))
        return;

    // Both refusals below run before the store gate: the answer depends on the key and the
    // caller, not on the store, and a denied caller must get the same 403 whether or not the
    // store is up. An unknown key has no class and is refused further down, as before.
    const auto key = req.matches[1].str();
    if (auto refusal = write_refusal(key, *session)) {
        if (refusal->kind == WriteRefusal::Kind::RouteOwned) {
            // Refused with no audit row, like the unknown-key refusal below.
            refuse(400, refusal->message, Legacy::A4,
                   detail::A4ErrorOpts{.remediation = refusal->remediation});
            return;
        }
        // Refused before the audit-first `attempted` row so a denial leaves one `denied` row, not
        // a dangling `attempted` (outcome unknown). try_persist_audit: a throwing or empty sink
        // must not turn the refusal into a 500.
        (void)detail::try_persist_audit(deps.audit_fn, req, "config.update", "denied",
                                        "RuntimeConfig", key, refusal->audit_detail);
        refuse(403, refusal->message, Legacy::A4,
               detail::A4ErrorOpts{.remediation = refusal->remediation});
        return;
    }

    const auto backing = deps.backing();
    if (!store_ready(backing)) {
        refuse(503, "runtime config store unavailable", Legacy::Terse,
               detail::A4ErrorOpts{.retry_after_ms = 5000,
                                   .remediation = "retry once the server reports ready"});
        return;
    }

    std::string value;
    try {
        // #2437-class guard: raw-text depth check before parse - "value" is dumped a few lines
        // below (j["value"].dump() when it is not a string), so the check has to run on the raw
        // text before any allocation.
        if (mcp::json_exceeds_depth(req.body, mcp::kMcpMaxJsonDepth)) {
            refuse(400, "request body nests too deeply", Legacy::Terse);
            return;
        }
        auto j = nlohmann::json::parse(req.body);
        if (j.contains("value")) {
            value = j["value"].is_string() ? j["value"].get<std::string>() : j["value"].dump();
        } else {
            refuse(400, "missing 'value' in request body", Legacy::Terse);
            return;
        }
    } catch (...) {
        refuse(400, "invalid JSON body", Legacy::Terse);
        return;
    }

    const auto parsed = validate_value(key, value);
    if (!parsed) {
        refuse(400, parsed.error(), Legacy::Terse);
        return;
    }

    // An unknown key is refused here, before any audit row, so a junk key leaves no
    // attempted/failure pair. The store repeats the check as the authority.
    if (!RuntimeConfigStore::is_allowed_key(key)) {
        refuse(400, "key '" + key + "' is not a configurable runtime setting", Legacy::Flat);
        return;
    }

    // ADR-0033 section 9, "no audit row, no mutation": an `attempted` row is written before
    // anything is changed, and a row that cannot be stored refuses the change. The outcome row
    // follows. The attempted row carries no value (a secret key's value never reaches an audit
    // detail; the outcome row redacts it).
    if (!detail::emit_behavioral_audit(deps.audit_fn, req, res, "config.update", "attempted",
                                       "RuntimeConfig", key, "")) {
        refuse(503, "audit log unavailable; the change was not made", Legacy::A4,
               detail::A4ErrorOpts{.retry_after_ms = 5000, .remediation = "retry the request"});
        return;
    }

    auto written = write_and_apply(backing, key, value, *parsed, session->username);
    if (!written) {
        // Best effort: the attempted row is already durable, and the response does not change.
        (void)detail::try_persist_audit(deps.audit_fn, req, "config.update", "failure",
                                        "RuntimeConfig", key, written.error().audit_detail);
        // A genuine DB/crypto failure is a 503 with a generic message, never the internal
        // detail; a refused value (unknown key, bad shape, the redaction-placeholder guard) is a
        // 400 with the store's own message, which is written for an operator.
        if (written.error().kind == WriteFault::Kind::StoreFault)
            refuse(503, written.error().message, Legacy::Terse,
                   detail::A4ErrorOpts{.retry_after_ms = 5000, .remediation = "retry the request"});
        else
            refuse(400, written.error().message, Legacy::Flat);
        return;
    }

    // The attempted row already exists, so a lost outcome row does not undo the change; it is
    // surfaced the way the other audited routes do (Sec-Audit-Failed), so a caller can show it.
    const bool persisted = detail::emit_behavioral_audit(deps.audit_fn, req, res, "config.update",
                                                         "success", "RuntimeConfig", key,
                                                         success_audit_detail(key, value));
    auto body = applied_json(key, value);
    if (!v1) {
        res.set_content(body.dump(), "application/json");
        return;
    }
    if (!persisted)
        body["audit_persisted"] = false;
    res.set_header("Cache-Control", "no-store");
    res.set_content(ok_json(std::move(body)), "application/json");
}

} // namespace

void register_config_routes(HttpRouteSink& sink, Deps deps) {
    // -- Runtime Configuration API (7.3) ------------------------------------
    sink.Get("/api/config", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Infrastructure", "Read"))
            return;
        // A degraded store must NOT read as "nothing is configured" (config_write.hpp,
        // ViewFault). The PUT twin answers 503 on the same condition.
        auto view = build_config_view(deps.backing());
        if (!view) {
            res.status = 503;
            res.set_content(terse_body(503, "runtime config store unavailable"), "application/json");
            return;
        }
        res.set_content(view->dump(), "application/json");
    });

    sink.Put(R"(/api/config/([a-z_]+))",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!deps.perm_fn(req, res, "Infrastructure", "Write"))
                     return;
                 handle_put(deps, req, res, /*v1=*/false);
             });

    // -- v1 twins: the same reads, writes, gates and audit rows in the A4 envelope. -----------
    sink.Get("/api/v1/config", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Infrastructure", "Read"))
            return;
        // The viewing session scopes what is shown (build_config_view): the legacy route above
        // shows every override to every reader; this route shows only what the caller could write.
        auto session = deps.auth_fn(req, res);
        if (!session)
            return;
        res.set_header("Cache-Control", "no-store");
        auto view = build_config_view(deps.backing(), &*session);
        if (!view) {
            res.status = 503;
            res.set_content(
                detail::a4_error(res, "runtime config store unavailable",
                                 detail::A4ErrorOpts{.retry_after_ms = 5000,
                                                     .remediation = "retry the request"}),
                "application/json");
            return;
        }
        res.set_content(ok_json(std::move(*view)), "application/json");
    });

    sink.Put(R"(/api/v1/config/([a-z_]+))",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!deps.perm_fn(req, res, "Infrastructure", "Write"))
                     return;
                 handle_put(deps, req, res, /*v1=*/true);
             });
}

} // namespace yuzu::server::config
