/// @file software_lifecycle_routes.cpp
/// See software_lifecycle_routes.hpp.

#include "software_lifecycle_routes.hpp"

#include "rest_a4_envelope_http.hpp"
#include "body_cap_policy.hpp"
#include "rest_audit.hpp"
#include "software_lifecycle_import.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <string_view>
#include <vector>

namespace yuzu::server {

namespace li = lifecycle_import;
using json = nlohmann::json;

namespace {

constexpr const char* kVerbImport = "software_estate.lifecycle_rules.import";
constexpr const char* kVerbDelete = "software_estate.lifecycle_rules.delete";
constexpr const char* kVerbRead = "software_estate.lifecycle_rules.read"; // refusals only
constexpr const char* kTargetType = "Inventory";

// The pre-routing body cap and the parser's own bound are one number (body_cap_policy.hpp row).
static_assert(resolve_body_cap("POST", "/api/v1/inventory/software/lifecycle/rules")
                      .max_body_bytes == li::kImportMaxBytes,
              "the software_lifecycle_rules body cap must equal lifecycle_import::kImportMaxBytes");

std::string ok_body(json data) {
    return json{{"data", std::move(data)}, {"meta", {{"api_version", "v1"}}}}.dump(
        -1, ' ', false, json::error_handler_t::replace);
}

void fail(httplib::Response& res, int status, std::string_view message,
          detail::A4ErrorOpts opts = {}) {
    res.status = status;
    res.set_content(detail::a4_error(res, message, opts), "application/json");
}

void unavailable(httplib::Response& res, std::string_view message) {
    fail(res, 503, message, {.retry_after_ms = 2000, .remediation = "retry the request"});
}

// "csv or cle": the format tokens, spelled once (kLifecycleImportFormatTokens).
std::string format_list() {
    std::string out;
    for (std::size_t i = 0; i < kLifecycleImportFormatTokens.size(); ++i) {
        if (i != 0)
            out += i + 1 == kLifecycleImportFormatTokens.size() ? " or " : ", ";
        out += kLifecycleImportFormatTokens[i];
    }
    return out;
}

// "reason=count;..." for an audit detail; the reasons are the parser's fixed tokens.
std::string skipped_text(const std::vector<li::Skipped>& skipped) {
    if (skipped.empty())
        return "none";
    std::string out;
    for (const auto& s : skipped) {
        if (!out.empty())
            out += ';';
        out += audit_token(s.reason) + "=" + std::to_string(s.count);
    }
    return out;
}

json rule_json(const LifecycleRule& r) {
    return {{"product_key", r.product_key},
            {"version_prefix", r.version_prefix},
            {"event", std::string{to_string(r.event)}},
            {"date", r.date},
            {"source_reference", r.source_ref}};
}

} // namespace

void SoftwareLifecycleRoutes::register_routes(HttpRouteSink& sink, Deps deps) {
    // The gates must be wired: an unwired gate fails closed, it never admits.
    const auto gates_wired = [deps](httplib::Response& res) {
        detail::ensure_correlation_id(res);
        if (!deps.perm_fn || !deps.audit_fn) {
            spdlog::error("SoftwareLifecycleRoutes: permission/audit gate unwired; failing closed");
            fail(res, 503, "service unavailable");
            return false;
        }
        return true;
    };
    const auto store_ready = [deps](httplib::Response& res) {
        if (!deps.store || !deps.store->is_open()) {
            unavailable(res, "software lifecycle store not available");
            return false;
        }
        return true;
    };
    // A refused request: audited `denied` under `verb` (best effort, the refusal stands either way).
    const auto refuse = [deps](const httplib::Request& req, httplib::Response& res, int status,
                               const char* verb, const std::string& target_id,
                               const std::string& reason) {
        (void)detail::try_persist_audit(deps.audit_fn, req, verb, "denied", kTargetType, target_id,
                                        audit_token(reason));
        fail(res, status, reason);
    };
    // The `requested` row ahead of a write: fail closed, nothing written when it cannot be stored.
    const auto audit_first = [deps](const httplib::Request& req, httplib::Response& res,
                                    const char* verb, const std::string& target_id,
                                    const std::string& text) {
        if (detail::emit_behavioral_audit(deps.audit_fn, req, res, verb, "requested", kTargetType,
                                          target_id, text))
            return true;
        fail(res, 503, "audit subsystem unavailable - request not served",
             {.retry_after_ms = 5000});
        return false;
    };

    // -- POST: import (replaces the whole imported set) -------------------------------------
    sink.Post("/api/v1/inventory/software/lifecycle/rules",
              [deps, gates_wired, store_ready, refuse,
               audit_first](const httplib::Request& req, httplib::Response& res) {
        if (!gates_wired(res))
            return;
        // The gate runs ahead of the body, the format and the name are looked at.
        if (!deps.perm_fn(req, res, "Inventory", "Write"))
            return;
        // The content type is not read. httplib folds an application/x-www-form-urlencoded body
        // into the request parameters, and the exactly-once counts below refuse a repeated
        // `name` or `format`.
        const std::string name_raw =
            req.get_param_value_count("name") == 1 ? req.get_param_value("name") : std::string{};
        const std::string target = audit_token(name_raw.substr(0, kLifecycleImportNameMaxBytes));
        if (req.get_param_value_count("name") != 1) {
            refuse(req, res, 400, kVerbImport, "", "name is required exactly once");
            return;
        }
        if (const auto bad = lifecycle_import_name_defect(name_raw)) {
            refuse(req, res, 400, kVerbImport, target, std::string{*bad});
            return;
        }
        const auto format = req.get_param_value_count("format") == 1
                                ? li::parse_format(req.get_param_value("format"))
                                : std::nullopt;
        if (!format) {
            refuse(req, res, 400, kVerbImport, target, "format must be " + format_list());
            return;
        }
        auto parsed = li::parse(*format, req.body, name_raw);
        if (!parsed) {
            refuse(req, res, 400, kVerbImport, target, parsed.error().reason);
            return;
        }
        if (!store_ready(res))
            return;

        const std::string format_token{req.get_param_value("format")};
        if (!audit_first(req, res, kVerbImport, target,
                         "format=" + format_token + " bytes=" + std::to_string(req.body.size()) +
                             " rules=" + std::to_string(parsed->rules.size()) +
                             " skipped=" + skipped_text(parsed->skipped)))
            return;
        // The outcome row. A failed persist here cannot undo a landed write: the
        // Sec-Audit-Failed header carries the signal.
        const auto outcome = [&](const char* result, const std::string& text) {
            (void)detail::emit_behavioral_audit(deps.audit_fn, req, res, kVerbImport, result,
                                                kTargetType, target, text);
        };
        const auto stored = deps.store->replace_rules(LifecycleSource::imported, parsed->rules);
        if (!stored) {
            spdlog::warn("SoftwareLifecycleRoutes: import replace_rules failed: {}", stored.error());
            outcome("failure", "store write failed");
            unavailable(res, "software lifecycle store write failed");
            return;
        }
        outcome("success", "stored=" + std::to_string(*stored) +
                               " skipped=" + skipped_text(parsed->skipped));
        json skipped = json::array();
        for (const auto& s : parsed->skipped)
            skipped.push_back({{"reason", s.reason}, {"count", s.count}});
        res.set_content(ok_body({{"stored", *stored},
                                 {"replaced", true},
                                 {"format", format_token},
                                 {"spec_version", parsed->spec_version},
                                 {"source_reference", name_raw},
                                 {"skipped", std::move(skipped)}}),
                        "application/json");
    });

    // -- GET: list one source's rules -------------------------------------------------------
    sink.Get("/api/v1/inventory/software/lifecycle/rules",
             [deps, gates_wired, store_ready,
              refuse](const httplib::Request& req, httplib::Response& res) {
        if (!gates_wired(res))
            return;
        if (!deps.perm_fn(req, res, "Inventory", "Read"))
            return;
        const std::string token = req.has_param("source") ? req.get_param_value("source")
                                                          : std::string{"imported"};
        const auto source = req.get_param_value_count("source") <= 1
                                ? lifecycle_rules_listable_source(token)
                                : std::nullopt;
        if (!source) {
            refuse(req, res, 400, kVerbRead, "", "source must be imported, shipped or external");
            return;
        }
        if (!store_ready(res))
            return;
        const auto rules = deps.store->rules_of(*source);
        if (!rules) {
            unavailable(res, "software lifecycle rules read unavailable");
            return;
        }
        json arr = json::array();
        for (const auto& r : *rules)
            arr.push_back(rule_json(r));
        res.set_content(ok_body({{"source", std::string{to_string(*source)}},
                                 {"rules", std::move(arr)},
                                 {"count", rules->size()}}),
                        "application/json");
    });

    // -- DELETE: empty the imported set -----------------------------------------------------
    sink.Delete("/api/v1/inventory/software/lifecycle/rules",
                [deps, gates_wired, store_ready,
                 audit_first](const httplib::Request& req, httplib::Response& res) {
        if (!gates_wired(res))
            return;
        if (!deps.perm_fn(req, res, "Inventory", "Write"))
            return;
        if (!store_ready(res))
            return;
        // The count is read ahead of the audited write, so a concurrent import can make it
        // differ from the rows the delete clears; the audit rows record what this call saw.
        const auto current = deps.store->rules_of(LifecycleSource::imported);
        if (!current) {
            unavailable(res, "software lifecycle rules read unavailable");
            return;
        }
        const std::size_t removed = current->size();
        if (!audit_first(req, res, kVerbDelete, "imported", "removing=" + std::to_string(removed)))
            return;
        const auto outcome = [&](const char* result, const std::string& text) {
            (void)detail::emit_behavioral_audit(deps.audit_fn, req, res, kVerbDelete, result,
                                                kTargetType, "imported", text);
        };
        const auto cleared = deps.store->replace_rules(LifecycleSource::imported, {});
        if (!cleared) {
            spdlog::warn("SoftwareLifecycleRoutes: delete replace_rules failed: {}", cleared.error());
            outcome("failure", "store write failed");
            unavailable(res, "software lifecycle store write failed");
            return;
        }
        outcome("success", "removed=" + std::to_string(removed));
        res.set_content(ok_body({{"removed", removed}}), "application/json");
    });
}

} // namespace yuzu::server
