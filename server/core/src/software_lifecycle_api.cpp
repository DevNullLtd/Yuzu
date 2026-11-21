/// @file software_lifecycle_api.cpp
/// See software_lifecycle_api.hpp. The bodies moved here verbatim from
/// software_lifecycle_routes.cpp; the REST routes keep the gate and the HTTP mapping.

#include "software_lifecycle_api.hpp"

#include "software_lifecycle_import.hpp"
#include "software_lifecycle_routes.hpp" // the format tokens, the name bound, the two small parsers
#include "web_utils.hpp"                 // audit_token

#include <spdlog/spdlog.h>

#include <utility>
#include <vector>

namespace yuzu::server::software_lifecycle_api {

namespace li = lifecycle_import;
using json = nlohmann::json;
using Kind = Reply::Kind;

namespace {

Reply bad_request(std::string message) {
    return Reply{.kind = Kind::BadRequest, .message = std::move(message)};
}

Reply unavailable(std::string message) {
    return Reply{.kind = Kind::Unavailable,
                 .message = std::move(message),
                 .retry_after_ms = 2000,
                 .remediation = "retry the request"};
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

bool store_ready(const SoftwareLifecycleStore* store) {
    return store && store->is_open();
}

// A refused request: audited `denied` under `verb` (best effort, the refusal stands either way).
Reply refuse(const AuditSink& audit, const char* verb, const std::string& target,
             const std::string& reason) {
    (void)audit(verb, "denied", target, audit_token(reason), false);
    return bad_request(reason);
}

// The `requested` row ahead of a write: fail closed, nothing written when it cannot be stored.
// An empty optional means the row is stored and the write may go on.
std::optional<Reply> audit_first(const AuditSink& audit, const char* verb, const std::string& target,
                                 const std::string& text) {
    if (audit(verb, "requested", target, text, true))
        return std::nullopt;
    return Reply{.kind = Kind::Unavailable,
                 .message = "audit subsystem unavailable - request not served",
                 .retry_after_ms = 5000};
}

} // namespace

Reply import_rules(SoftwareLifecycleStore* store, const std::optional<std::string_view>& name,
                   const std::optional<std::string_view>& format_token, std::string_view content,
                   const AuditSink& audit) {
    const std::string name_raw = name ? std::string{*name} : std::string{};
    const std::string target = audit_token(name_raw.substr(0, kLifecycleImportNameMaxBytes));
    if (!name)
        return refuse(audit, kVerbImport, "", "name is required exactly once");
    if (const auto bad = lifecycle_import_name_defect(name_raw))
        return refuse(audit, kVerbImport, target, std::string{*bad});
    const auto format = format_token ? li::parse_format(*format_token) : std::nullopt;
    if (!format)
        return refuse(audit, kVerbImport, target, "format must be " + format_list());
    auto parsed = li::parse(*format, content, name_raw);
    if (!parsed)
        return refuse(audit, kVerbImport, target, parsed.error().reason);
    if (!store_ready(store))
        return unavailable("software lifecycle store not available");

    if (auto refused = audit_first(audit, kVerbImport, target,
                                   "format=" + std::string{*format_token} +
                                       " bytes=" + std::to_string(content.size()) +
                                       " rules=" + std::to_string(parsed->rules.size()) +
                                       " skipped=" + skipped_text(parsed->skipped)))
        return std::move(*refused);
    // The outcome row. A failed persist here cannot undo a landed write: the surface carries the
    // signal (the REST Sec-Audit-Failed header, the MCP audit_persisted field).
    bool outcome_persisted = true;
    const auto outcome = [&](const char* result, const std::string& text) {
        outcome_persisted = audit(kVerbImport, result, target, text, true);
    };
    const auto stored = store->replace_rules(LifecycleSource::imported, parsed->rules);
    if (!stored) {
        spdlog::warn("software_lifecycle_api: import replace_rules failed: {}", stored.error());
        outcome("failure", "store write failed");
        return unavailable("software lifecycle store write failed");
    }
    outcome("success", "stored=" + std::to_string(*stored) +
                           " skipped=" + skipped_text(parsed->skipped));
    json skipped = json::array();
    for (const auto& s : parsed->skipped)
        skipped.push_back({{"reason", s.reason}, {"count", s.count}});
    return Reply{.kind = Kind::Ok,
                 .body = {{"stored", *stored},
                          {"replaced", true},
                          {"format", std::string{*format_token}},
                          {"spec_version", parsed->spec_version},
                          {"source_reference", name_raw},
                          {"skipped", std::move(skipped)}},
                 .audit_persisted = outcome_persisted};
}

Reply list_rules(SoftwareLifecycleStore* store, std::string_view source_token,
                 const AuditSink& audit) {
    const auto source = lifecycle_rules_listable_source(source_token);
    if (!source)
        return refuse(audit, kVerbRead, "", "source must be imported, shipped or external");
    if (!store_ready(store))
        return unavailable("software lifecycle store not available");
    const auto rules = store->rules_of(*source);
    if (!rules)
        return unavailable("software lifecycle rules read unavailable");
    json arr = json::array();
    for (const auto& r : *rules)
        arr.push_back(rule_json(r));
    return Reply{.kind = Kind::Ok,
                 .body = {{"source", std::string{to_string(*source)}},
                          {"rules", std::move(arr)},
                          {"count", rules->size()}}};
}

Reply delete_rules(SoftwareLifecycleStore* store, const AuditSink& audit) {
    if (!store_ready(store))
        return unavailable("software lifecycle store not available");
    // The count is read ahead of the audited write, so a concurrent import can make it
    // differ from the rows the delete clears; the audit rows record what this call saw.
    const auto current = store->rules_of(LifecycleSource::imported);
    if (!current)
        return unavailable("software lifecycle rules read unavailable");
    const std::size_t removed = current->size();
    if (auto refused =
            audit_first(audit, kVerbDelete, "imported", "removing=" + std::to_string(removed)))
        return std::move(*refused);
    bool outcome_persisted = true;
    const auto outcome = [&](const char* result, const std::string& text) {
        outcome_persisted = audit(kVerbDelete, result, "imported", text, true);
    };
    const auto cleared = store->replace_rules(LifecycleSource::imported, {});
    if (!cleared) {
        spdlog::warn("software_lifecycle_api: delete replace_rules failed: {}", cleared.error());
        outcome("failure", "store write failed");
        return unavailable("software lifecycle store write failed");
    }
    outcome("success", "removed=" + std::to_string(removed));
    return Reply{.kind = Kind::Ok,
                 .body = {{"removed", removed}},
                 .audit_persisted = outcome_persisted};
}

} // namespace yuzu::server::software_lifecycle_api
