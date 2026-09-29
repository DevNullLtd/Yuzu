#include "plugin_config_routes.hpp"

#include "plugin_config_parsers.hpp"
#include "plugin_config_store.hpp"
#include "rbac_store.hpp" // RbacStore::authorize_list_read / ListReadDecision (ADR-0017)
#include "rest_a4_envelope.hpp"
#include "rest_audit.hpp" // detail::emit_behavioral_audit (Sec-Audit-Failed / 503-on-audit-failure, #1647)

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <cstddef>
#include <string>

namespace yuzu::server::plugin_config {

namespace {

using detail::error_json_a4;
using detail::make_correlation_id;

constexpr const char* kJson = "application/json";

// Defensive cap on a request body — generous enough for a secret value up to
// kMaxSecretValueBytes (64 KiB) plus JSON framing overhead, small enough
// that a multi-GB POST never reaches nlohmann::json::parse on this surface
// (mirrors kek_routes.cpp's kMaxKekBody / ca_routes.cpp's kMaxRevokeBody).
constexpr std::size_t kMaxBodyBytes = 128 * 1024;

/// Parse `req.body` as a JSON object. Writes an A4 error + returns false on
/// an oversized body, a parse failure, or a non-object body — callers must
/// `return` immediately on false.
bool parse_json_object_body(const httplib::Request& req, httplib::Response& res,
                            nlohmann::json& out) {
    if (req.body.size() > kMaxBodyBytes) {
        res.status = 413;
        res.set_content(error_json_a4(413, "request body too large", make_correlation_id()), kJson);
        return false;
    }
    // Hermes-style defensive parse (matches kek_routes.cpp / ca_routes.cpp):
    // allow_exceptions=false turns a parse error into a discarded value; the
    // try/catch also guards an impl-specific throw (e.g. bad_alloc).
    try {
        out = nlohmann::json::parse(req.body, nullptr, false);
    } catch (...) {
        res.status = 400;
        res.set_content(error_json_a4(400, "invalid JSON body", make_correlation_id()), kJson);
        return false;
    }
    if (out.is_discarded() || !out.is_object()) {
        res.status = 400;
        res.set_content(error_json_a4(400, "invalid JSON body", make_correlation_id()), kJson);
        return false;
    }
    return true;
}

/// Extracts a required string field. Writes an A4 400 + returns nullopt on a
/// missing/non-string field.
std::optional<std::string> require_string_field(const nlohmann::json& body, const char* field,
                                                 httplib::Response& res) {
    if (!body.contains(field) || !body.at(field).is_string()) {
        res.status = 400;
        res.set_content(
            error_json_a4(400, std::string("missing or non-string field: ") + field,
                          make_correlation_id()),
            kJson);
        return std::nullopt;
    }
    return body.at(field).get<std::string>();
}

void write_store_error(httplib::Response& res, PluginConfigStore::Error err) {
    switch (err) {
    case PluginConfigStore::Error::NotFound:
        res.status = 404;
        res.set_content(error_json_a4(404, "not found", make_correlation_id()), kJson);
        return;
    case PluginConfigStore::Error::InvalidInput:
        res.status = 400;
        res.set_content(error_json_a4(400, "invalid plugin/key/value/reason", make_correlation_id()),
                        kJson);
        return;
    case PluginConfigStore::Error::Unavailable:
        res.status = 503;
        res.set_content(error_json_a4(503, "plugin config store unavailable", make_correlation_id(),
                                      /*retry_after_ms=*/2000, "retry once the server reports ready"),
                        kJson);
        return;
    case PluginConfigStore::Error::WriteFailed:
        res.status = 500;
        res.set_content(error_json_a4(500, "write failed", make_correlation_id()), kJson);
        return;
    case PluginConfigStore::Error::SecretUnavailable:
        res.status = 503;
        res.set_content(error_json_a4(503, "secret encryption unavailable", make_correlation_id(),
                                      /*retry_after_ms=*/2000, "retry once the server reports ready"),
                        kJson);
        return;
    }
    res.status = 500;
    res.set_content(error_json_a4(500, "internal error", make_correlation_id()), kJson);
}

/// Emit the mutation audit row and — matching rest_audit.hpp's documented
/// REST-JSON posture exactly — fail CLOSED (503) when the audit row could
/// not be persisted, rather than the HTML-dashboard "set the header and
/// proceed" posture some fragment routes use.
///
/// Every mutation handler below calls this BEFORE invoking the store
/// mutation, never after (#PCP-01 fix): every field passed here is derived
/// from the REQUEST alone (plugin/key/action from the URL, value/reason
/// from the validated body) — never from the store's return value — so
/// gating on it first is possible, and doing so means an audit-store
/// degradation can never leave a mutation committed with no audit row at
/// all (the failure mode this posture exists to prevent). The residual
/// trade-off: each handler re-validates its input with the same
/// `plugin_config_parsers.hpp` grammar the store enforces internally
/// BEFORE calling this, so that a plain 400-shaped input rejection never
/// first burns an audit row it turns out not to need; a mutation can still
/// rarely fail AFTER a successful pre-mutation audit (a lease timeout, a
/// concurrent-delete race, an encrypt failure) — that residual gap is
/// narrow and infrastructure-shaped, not the routine "any audit hiccup
/// silently permits an unaudited write" gap this reordering closes.
/// Returns true iff the caller may proceed to attempt the mutation.
[[nodiscard]] bool audit_or_503(const Deps::AuditFn& audit_fn, const httplib::Request& req,
                                httplib::Response& res, const std::string& action,
                                const std::string& target_type, const std::string& target_id,
                                const std::string& detail_str) {
    // BR-006: the pre-mutation row records `attempted`, NOT `success`. It used
    // to claim success, which made the evidence chain lie in the exact window
    // it exists to cover: the audit insert lands, the store call then fails on
    // a lease timeout / encrypt error / concurrent delete, the caller correctly
    // gets a 503 — and the compliance log permanently asserts a configuration
    // or secret change that never happened. `emit_behavioral_audit` already
    // takes the result string, so honesty here costs nothing.
    //
    // The fail-closed property is unchanged and is the reason the row is
    // written FIRST: if the evidence cannot be persisted, the mutation is not
    // attempted at all. Callers pair this with `audit_outcome(...)` below to
    // record what actually happened once the store has answered.
    const bool persisted = detail::emit_behavioral_audit(audit_fn, req, res, action, "attempted",
                                                          target_type, target_id, detail_str);
    if (!persisted) {
        res.status = 503;
        res.set_content(
            error_json_a4(503, "the audit record could not be persisted, so the operation was "
                               "NOT performed; retry once the audit store recovers",
                          make_correlation_id()),
            kJson);
        return false;
    }
    return true;
}

/// BR-006 second half: record what the store ACTUALLY did, after it answered.
/// Pairs with `audit_or_503`'s pre-mutation `attempted` row — together they
/// give a reviewer an evidence chain that cannot assert a change which did not
/// occur, and cannot lose a change that did.
///
/// Deliberately NOT fail-closed and deliberately `[[nodiscard]]`-free: the
/// mutation has already happened by the time this runs, so refusing it is not
/// on the table, and 503-ing a completed write would be a worse lie than the
/// one BR-006 fixes. A dropped outcome row leaves the `attempted` row standing,
/// which reads as "started, outcome unknown" — the honest reading of exactly
/// that state. It is logged at warn so the gap is visible rather than silent.
void audit_outcome(const Deps::AuditFn& audit_fn, const httplib::Request& req,
                   httplib::Response& res, const std::string& action, bool ok,
                   const std::string& target_type, const std::string& target_id,
                   const std::string& detail_str) {
    if (!detail::emit_behavioral_audit(audit_fn, req, res, action, ok ? "success" : "failure",
                                       target_type, target_id, detail_str)) {
        spdlog::warn("plugin-config: {} outcome row ({}) could not be persisted for {}; the "
                     "'attempted' row stands and the outcome is unrecorded",
                     action, ok ? "success" : "failure", target_id);
    }
}

nlohmann::json config_json(const PluginConfigStore::ConfigEntry& e) {
    return {{"plugin", e.plugin},
           {"key", e.key},
           {"value", e.value},
           {"updated_at_ms", e.updated_at_ms},
           {"updated_by", e.updated_by}};
}

nlohmann::json secret_meta_json(const PluginConfigStore::SecretMeta& m) {
    return {{"plugin", m.plugin}, {"key", m.key}, {"updated_at_ms", m.updated_at_ms},
           {"updated_by", m.updated_by}};
}

nlohmann::json kill_switch_json(const PluginConfigStore::KillSwitchEntry& e) {
    return {{"plugin", e.plugin},
           {"action", e.action},
           {"enabled", e.enabled},
           {"reason", e.reason},
           {"set_by", e.set_by},
           {"updated_at_ms", e.updated_at_ms}};
}

/// "who" for updated_by/set_by columns — the authenticated session's stable
/// principal. `auth_fn` already wrote a 401 response and returned nullopt on
/// failure; every write handler bails out at that point, so this is only
/// ever called with a resolved session.
const std::string& actor(const auth::Session& session) { return session.username; }

} // namespace

void register_plugin_config_routes(HttpRouteSink& sink, Deps deps) {
    spdlog::info("plugin config routes: registering /api/v1/plugin-config/*");

    // ── GET /api/v1/plugin-config ── PluginConfig:Read, ADR-0017 list gate ──
    //
    // The ADR-0017 admit-then-filter chokepoint (RbacStore::authorize_list_read)
    // gates this route rather than a bare perm_fn check — required by this
    // package's spec regardless of the fact that plugin configuration is NOT
    // agent-scoped data. AdmitAll (global grant, or RBAC loaded-and-disabled)
    // serves the (optionally ?plugin=-filtered) list; DenyAll is a 403.
    // AdmitScoped — a management-group-CONFINED grant — is ALSO treated as a
    // 403 here: `visible_agents` names agent ids, which have no correspondence
    // to plugin/key rows, so there is no principled way to "filter" this list
    // by it. Serving it unfiltered under a confined grant would silently
    // widen a device-scoped grant to fleet-wide platform configuration;
    // refusing it is the only safe reading.
    sink.Get("/api/v1/plugin-config", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "PluginConfig", "Read"))
            return;
        auto session = deps.auth_fn(req, res);
        if (!session)
            return;
        if (!deps.rbac_store || !deps.rbac_store->is_open()) {
            res.status = 503;
            res.set_content(error_json_a4(503, "authorization store unavailable",
                                          make_correlation_id()),
                            kJson);
            return;
        }
        auto authz = deps.rbac_store->authorize_list_read(session->username, "PluginConfig",
                                                           "Read", deps.mgmt_store);
        if (authz.decision != ListReadDecision::AdmitAll) {
            res.status = 403;
            res.set_content(
                error_json_a4(403, "permission denied: PluginConfig:Read", make_correlation_id(),
                              detail::A4ErrorOpts{.permission = "PluginConfig:Read"}),
                kJson);
            return;
        }
        if (!deps.store || !deps.store->is_open()) {
            write_store_error(res, PluginConfigStore::Error::Unavailable);
            return;
        }
        const std::string plugin_filter = req.has_param("plugin") ? req.get_param_value("plugin") : "";
        bool truncated = false;
        auto rows = deps.store->list_config(plugin_filter, &truncated);
        if (!rows) {
            write_store_error(res, rows.error());
            return;
        }
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& e : *rows)
            arr.push_back(config_json(e));
        nlohmann::json out = {{"data", arr},
                              {"meta", {{"api_version", "v1"}, {"truncated", truncated}}}};
        res.set_content(out.dump(), kJson);
    });

    // ── GET/PUT /api/v1/plugin-config/:plugin/kill-switch ── (?action=) ─────
    // Registered BEFORE the generic :plugin/:key routes below — cpp-httplib
    // (and TestRouteSink) try patterns in REGISTRATION order and dispatch to
    // the first match, so this literal segment must win over the generic
    // key-shaped capture.
    sink.Get(R"(/api/v1/plugin-config/([^/]+)/kill-switch)",
            [deps](const httplib::Request& req, httplib::Response& res) {
                if (!deps.perm_fn(req, res, "PluginConfig", "Read"))
                    return;
                if (!deps.store || !deps.store->is_open()) {
                    write_store_error(res, PluginConfigStore::Error::Unavailable);
                    return;
                }
                const std::string plugin = req.matches[1].str();
                const std::string action = req.has_param("action") ? req.get_param_value("action") : "";
                auto entry = deps.store->get_kill_switch(plugin, action);
                if (!entry) {
                    write_store_error(res, entry.error());
                    return;
                }
                nlohmann::json out = {{"data", kill_switch_json(*entry)},
                                      {"meta", {{"api_version", "v1"}}}};
                res.set_content(out.dump(), kJson);
            });

    sink.Put(R"(/api/v1/plugin-config/([^/]+)/kill-switch)",
            [deps](const httplib::Request& req, httplib::Response& res) {
                if (!deps.perm_fn(req, res, "PluginConfig", "Write"))
                    return;
                auto session = deps.auth_fn(req, res);
                if (!session)
                    return;
                if (!deps.store || !deps.store->is_open()) {
                    write_store_error(res, PluginConfigStore::Error::Unavailable);
                    return;
                }
                nlohmann::json body;
                if (!parse_json_object_body(req, res, body))
                    return;
                if (!body.contains("enabled") || !body.at("enabled").is_boolean()) {
                    res.status = 400;
                    res.set_content(error_json_a4(400, "missing or non-boolean field: enabled",
                                                  make_correlation_id()),
                                    kJson);
                    return;
                }
                const bool enabled = body.at("enabled").get<bool>();
                std::string reason;
                if (body.contains("reason")) {
                    auto r = require_string_field(body, "reason", res);
                    if (!r)
                        return;
                    reason = *r;
                }

                const std::string plugin = req.matches[1].str();
                const std::string action = req.has_param("action") ? req.get_param_value("action") : "";
                // Pre-validate with the SAME grammar set_kill_switch enforces
                // internally, so the audit row emitted below (before the
                // mutation — see audit_or_503's doc comment) is never
                // recorded for an input the store would reject anyway.
                if (!plugin_config::parse_kill_switch_scope(plugin, action) ||
                    !plugin_config::is_valid_reason(reason) ||
                    !plugin_config::is_valid_actor(actor(*session))) {
                    write_store_error(res, PluginConfigStore::Error::InvalidInput);
                    return;
                }

                const std::string target_id =
                    action.empty() ? plugin : plugin + "." + action;
                const std::string detail_str =
                    std::string("enabled=") + (enabled ? "true" : "false");
                if (!audit_or_503(deps.audit_fn, req, res, "plugin_config.kill_switch.set",
                                  "PluginConfig", target_id, detail_str))
                    return;

                auto result =
                    deps.store->set_kill_switch(plugin, action, enabled, reason, actor(*session));
                if (!result) {
                    audit_outcome(deps.audit_fn, req, res, "plugin_config.kill_switch.set", /*ok=*/false,
                                  "PluginConfig", target_id, detail_str);
                    write_store_error(res, result.error());
                    return;
                }
                audit_outcome(deps.audit_fn, req, res, "plugin_config.kill_switch.set", /*ok=*/true, "PluginConfig",
                              target_id, detail_str);
                nlohmann::json out = {{"data", kill_switch_json(*result)},
                                      {"meta", {{"api_version", "v1"}}}};
                res.set_content(out.dump(), kJson);
            });

    // ── PUT/DELETE /api/v1/plugin-config/:plugin/:key/secret ── write-only ──
    // No GET/list route for secrets exists on this surface — deliberate; see
    // the file header and docs/adr/3005-plugin-config-store.md. `set`'s
    // response is `PluginConfigStore::SecretMeta` — metadata only, never the
    // value that was sealed.
    sink.Put(R"(/api/v1/plugin-config/([^/]+)/([^/]+)/secret)",
            [deps](const httplib::Request& req, httplib::Response& res) {
                if (!deps.perm_fn(req, res, "PluginSecret", "Write"))
                    return;
                auto session = deps.auth_fn(req, res);
                if (!session)
                    return;
                if (!deps.store || !deps.store->is_open()) {
                    write_store_error(res, PluginConfigStore::Error::Unavailable);
                    return;
                }
                nlohmann::json body;
                if (!parse_json_object_body(req, res, body))
                    return;
                auto value = require_string_field(body, "value", res);
                if (!value)
                    return;

                const std::string plugin = req.matches[1].str();
                const std::string key = req.matches[2].str();
                // Pre-validate with the SAME grammar set_secret enforces
                // internally, so the audit row emitted below (before the
                // mutation — see audit_or_503's doc comment) is never
                // recorded for an input the store would reject anyway.
                auto pk = parse_plugin_key(plugin, key);
                if (!pk || !plugin_config::is_valid_secret_value(*value) ||
                    !plugin_config::is_valid_actor(actor(*session))) {
                    write_store_error(res, PluginConfigStore::Error::InvalidInput);
                    return;
                }
                // Redact-by-construction: the audit detail is built from a
                // helper that has no plaintext parameter at all (never `*value`).
                const std::string detail_str = redact_secret_for_audit(*pk);
                const std::string target_id = plugin + "." + key;
                if (!audit_or_503(deps.audit_fn, req, res, "plugin_secret.set", "PluginSecret",
                                  target_id, detail_str))
                    return;

                auto result = deps.store->set_secret(plugin, key, *value, actor(*session));
                if (!result) {
                    audit_outcome(deps.audit_fn, req, res, "plugin_secret.set", /*ok=*/false,
                                  "PluginSecret", target_id, detail_str);
                    write_store_error(res, result.error());
                    return;
                }
                audit_outcome(deps.audit_fn, req, res, "plugin_secret.set", /*ok=*/true, "PluginSecret",
                              target_id, detail_str);
                nlohmann::json out = {{"data", secret_meta_json(*result)},
                                      {"meta", {{"api_version", "v1"}}}};
                res.set_content(out.dump(), kJson);
            });

    sink.Delete(R"(/api/v1/plugin-config/([^/]+)/([^/]+)/secret)",
               [deps](const httplib::Request& req, httplib::Response& res) {
                   if (!deps.perm_fn(req, res, "PluginSecret", "Delete"))
                       return;
                   if (!deps.store || !deps.store->is_open()) {
                       write_store_error(res, PluginConfigStore::Error::Unavailable);
                       return;
                   }
                   const std::string plugin = req.matches[1].str();
                   const std::string key = req.matches[2].str();
                   auto pk = parse_plugin_key(plugin, key);
                   if (!pk) {
                       write_store_error(res, PluginConfigStore::Error::InvalidInput);
                       return;
                   }
                   // No GET/existence check exists on the write-only secret
                   // plane (by design — see the file header), so unlike
                   // delete_config below this audit-before-mutate call
                   // cannot be preceded by a cheap existence pre-check: a
                   // delete of an already-absent secret still records this
                   // as an attempted deletion before discovering that, which
                   // is accepted as the same narrow, documented trade-off
                   // audit_or_503's doc comment describes for every mutation
                   // route here.
                   const std::string target_id = plugin + "." + key;
                   if (!audit_or_503(deps.audit_fn, req, res, "plugin_secret.delete", "PluginSecret",
                                     target_id, "deleted"))
                       return;

                   auto result = deps.store->delete_secret(plugin, key);
                   if (!result) {
                       audit_outcome(deps.audit_fn, req, res, "plugin_secret.delete", /*ok=*/false,
                                     "PluginSecret", target_id, "deleted");
                       write_store_error(res, result.error());
                       return;
                   }
                   audit_outcome(deps.audit_fn, req, res, "plugin_secret.delete", /*ok=*/true, "PluginSecret",
                                 target_id, "deleted");
                   nlohmann::json out = {{"deleted", true}, {"meta", {{"api_version", "v1"}}}};
                   res.set_content(out.dump(), kJson);
               });

    // ── GET/PUT/DELETE /api/v1/plugin-config/:plugin/:key ── plain config ──
    sink.Get(R"(/api/v1/plugin-config/([^/]+)/([^/]+))",
            [deps](const httplib::Request& req, httplib::Response& res) {
                if (!deps.perm_fn(req, res, "PluginConfig", "Read"))
                    return;
                if (!deps.store || !deps.store->is_open()) {
                    write_store_error(res, PluginConfigStore::Error::Unavailable);
                    return;
                }
                const std::string plugin = req.matches[1].str();
                const std::string key = req.matches[2].str();
                auto entry = deps.store->get_config(plugin, key);
                if (!entry) {
                    write_store_error(res, entry.error());
                    return;
                }
                nlohmann::json out = {{"data", config_json(*entry)}, {"meta", {{"api_version", "v1"}}}};
                res.set_content(out.dump(), kJson);
            });

    sink.Put(R"(/api/v1/plugin-config/([^/]+)/([^/]+))",
            [deps](const httplib::Request& req, httplib::Response& res) {
                if (!deps.perm_fn(req, res, "PluginConfig", "Write"))
                    return;
                auto session = deps.auth_fn(req, res);
                if (!session)
                    return;
                if (!deps.store || !deps.store->is_open()) {
                    write_store_error(res, PluginConfigStore::Error::Unavailable);
                    return;
                }
                nlohmann::json body;
                if (!parse_json_object_body(req, res, body))
                    return;
                auto value = require_string_field(body, "value", res);
                if (!value)
                    return;

                const std::string plugin = req.matches[1].str();
                const std::string key = req.matches[2].str();
                // Pre-validate with the SAME grammar set_config enforces
                // internally, so the audit row emitted below (before the
                // mutation — see audit_or_503's doc comment) is never
                // recorded for an input the store would reject anyway.
                auto pk = parse_plugin_key(plugin, key);
                if (!pk || !plugin_config::is_valid_config_value(*value) ||
                    !plugin_config::is_valid_actor(actor(*session))) {
                    write_store_error(res, PluginConfigStore::Error::InvalidInput);
                    return;
                }

                const std::string target_id = plugin + "." + key;
                const std::string detail_str = "len=" + std::to_string(value->size());
                if (!audit_or_503(deps.audit_fn, req, res, "plugin_config.set", "PluginConfig",
                                  target_id, detail_str))
                    return;

                auto result = deps.store->set_config(plugin, key, *value, actor(*session));
                if (!result) {
                    audit_outcome(deps.audit_fn, req, res, "plugin_config.set", /*ok=*/false,
                                  "PluginConfig", target_id, detail_str);
                    write_store_error(res, result.error());
                    return;
                }
                audit_outcome(deps.audit_fn, req, res, "plugin_config.set", /*ok=*/true, "PluginConfig",
                              target_id, detail_str);
                nlohmann::json out = {{"data", config_json(*result)}, {"meta", {{"api_version", "v1"}}}};
                res.set_content(out.dump(), kJson);
            });

    sink.Delete(R"(/api/v1/plugin-config/([^/]+)/([^/]+))",
               [deps](const httplib::Request& req, httplib::Response& res) {
                   if (!deps.perm_fn(req, res, "PluginConfig", "Delete"))
                       return;
                   if (!deps.store || !deps.store->is_open()) {
                       write_store_error(res, PluginConfigStore::Error::Unavailable);
                       return;
                   }
                   const std::string plugin = req.matches[1].str();
                   const std::string key = req.matches[2].str();
                   // Existence pre-check (a plain read, not a mutation) keeps
                   // the pre-mutation audit below accurate for the common
                   // double-delete/retry case: a 404 for an already-absent
                   // key answers here with NO audit row emitted at all,
                   // exactly matching the pre-reorder behaviour for that
                   // case (unlike plugin_secret's delete route, which has no
                   // existence-check method available — see its handler's
                   // comment).
                   auto existing = deps.store->get_config(plugin, key);
                   if (!existing) {
                       write_store_error(res, existing.error());
                       return;
                   }

                   const std::string target_id = plugin + "." + key;
                   if (!audit_or_503(deps.audit_fn, req, res, "plugin_config.delete", "PluginConfig",
                                     target_id, "deleted"))
                       return;

                   auto result = deps.store->delete_config(plugin, key);
                   if (!result) {
                       audit_outcome(deps.audit_fn, req, res, "plugin_config.delete", /*ok=*/false,
                                     "PluginConfig", target_id, "deleted");
                       write_store_error(res, result.error());
                       return;
                   }
                   audit_outcome(deps.audit_fn, req, res, "plugin_config.delete", /*ok=*/true, "PluginConfig",
                                 target_id, "deleted");
                   nlohmann::json out = {{"deleted", true}, {"meta", {{"api_version", "v1"}}}};
                   res.set_content(out.dump(), kJson);
               });
}

} // namespace yuzu::server::plugin_config
