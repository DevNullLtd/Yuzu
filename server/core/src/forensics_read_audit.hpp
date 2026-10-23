#pragma once

/// #4990: the access-audit row for a read that SERVED Forensics-tier response rows.
///
/// Verb `response.forensics.read`, result `success`, written ONLY when the rows actually handed to
/// the caller include at least one row whose plugin is in the `ForensicsPluginSet`. The served rows
/// are inspected as they are (no second store query): a caller who was filtered out of the tier, or
/// whose result holds only ordinary-plugin rows, leaves no row. The point is a separately countable
/// usage-class read (works-council), exactly like the `device.live.<kind>` verbs.
///
/// Persist semantics follow `rest_audit.hpp` per surface and are decided by the CALLER, not here:
///   * REST (legacy + v1)  fail closed: `emit_forensics_read_audit` returns false and the route
///                         answers 503 + `Sec-Audit-Failed` before building any body.
///   * MCP                 set-and-proceed, the failure surfaces as `audit_persisted:false`.
///   * dashboard HTML      set-and-proceed, the failure surfaces as `Sec-Audit-Failed`.
/// Row-returning surfaces only: aggregate, facet and count reads emit nothing.
///
/// Detail is `forensics_rows=<n> plugins=<a,b>`. Every token goes through `audit_token` (CWE-117).

#include <httplib.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <set>
#include <string>
#include <string_view>

#include "response_tier_filter.hpp"
#include "rest_audit.hpp"
#include "web_utils.hpp" // audit_token

namespace yuzu::server {

/// The audit verb. One spelling for every surface.
inline constexpr const char* kForensicsReadVerb = "response.forensics.read";

/// What a surface served, with respect to the Forensics tier.
struct ForensicsServed {
    std::size_t rows{0};
    std::set<std::string> plugins; // lowercase, sorted: the stable audit spelling

    [[nodiscard]] bool any() const noexcept { return rows > 0; }

    /// Count one served row of `plugin` (ASCII case-insensitive, like the SQL predicate). Rows of
    /// any plugin outside the set are ignored. A null set (unwired; such a surface serves no row)
    /// counts nothing.
    void note(std::string_view plugin, const ForensicsPluginSet* set) {
        if (!set)
            return;
        std::string lower(plugin);
        for (auto& c : lower)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (!std::ranges::binary_search(set->names(), lower))
            return;
        ++rows;
        plugins.insert(std::move(lower));
    }

    /// `forensics_rows=<n> plugins=<a,b>` with every token neutralised.
    [[nodiscard]] std::string detail() const {
        std::string out = "forensics_rows=" + std::to_string(rows) + " plugins=";
        bool first = true;
        for (const auto& p : plugins) {
            if (!first)
                out += ',';
            out += audit_token(p);
            first = false;
        }
        return out;
    }
};

/// Summarise the served rows (anything iterable whose elements have a `.plugin` string).
template <class Rows>
[[nodiscard]] ForensicsServed summarize_forensics_served(const Rows& rows,
                                                         const ForensicsPluginSet* set) {
    ForensicsServed served;
    for (const auto& r : rows)
        served.note(r.plugin, set);
    return served;
}

/// REST/HTML helper: emit the `response.forensics.read` row for `served` through
/// `emit_behavioral_audit` (sets `Sec-Audit-Failed` on a persist failure). Returns true when there
/// is nothing to audit or the row persisted (or audit is off); false when it did not persist, and
/// the fail-closed REST caller must then refuse to serve. `target_id` is the id the neighbouring
/// `response.read` row names (instruction or execution id).
template <class AuditFn>
[[nodiscard]] bool emit_forensics_read_audit(const AuditFn& audit_fn, const httplib::Request& req,
                                             httplib::Response& res, const ForensicsServed& served,
                                             const std::string& target_id) {
    if (!served.any())
        return true;
    return detail::emit_behavioral_audit(audit_fn, req, res, kForensicsReadVerb, "success",
                                         "Execution", target_id, served.detail());
}

} // namespace yuzu::server
